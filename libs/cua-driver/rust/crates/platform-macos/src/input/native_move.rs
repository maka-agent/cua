//! A single PID-routed native mouse move after the Host's visual movement.

use core_foundation::base::CFRetain;
use core_graphics::{
    event::{CGEvent, CGEventFlags, EventField},
    geometry::{CGAffineTransform, CGPoint, CGRect, CGSize},
    sys::CGEventRef,
};
use foreign_types::ForeignType;
use mach2::mach_time::{mach_absolute_time, mach_timebase_info_data_t};
use objc2::{encode::RefEncode, Encoding};
use objc2_app_kit::{NSEvent, NSEventModifierFlags, NSEventType};
use objc2_foundation::NSPoint;
use std::{
    cell::RefCell,
    future::Future,
    sync::atomic::{AtomicI64, Ordering},
    time::Duration,
};

/// A native move could not be prepared or timestamped for PID delivery.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NativeMoveError {
    #[error("native move requires a finite exact-window point")]
    InvalidGeometry,
    #[error("native move local point cannot be represented")]
    UnrepresentableLocalPoint,
    #[error("native move boot uptime source is unavailable")]
    UptimeUnavailable,
    #[error("native move event number cannot be represented")]
    EventNumberExhausted,
    #[error("native mouse event factory returned no event")]
    EventUnavailable,
    #[error("native mouse event has no CGEvent")]
    CgEventUnavailable,
    #[error("native move window-location API is unavailable")]
    WindowLocationUnavailable,
    #[error("native move uptime timestamp cannot be represented")]
    UptimeOverflow,
}

/// Geometry selected for this move, independent of the later wheel target.
#[derive(Clone, Copy, Debug)]
pub struct NativeMoveRequest {
    pub pid: i32,
    pub window_id: u32,
    pub screen_point: CGPoint,
    pub window_bounds: CGRect,
    pub window_uses_flipped_coordinates: bool,
    pub native_window_pixels: [f64; 2],
}

tokio::task_local! {
    static NATIVE_MOVE: RefCell<Option<NativeMoveRequest>>;
}

/// Carry data with the original bound-session operation; this grants no input.
#[doc(hidden)]
pub async fn with_native_move<F: Future>(request: NativeMoveRequest, operation: F) -> F::Output {
    NATIVE_MOVE
        .scope(RefCell::new(Some(request)), operation)
        .await
}

pub(crate) fn take_native_move() -> Option<NativeMoveRequest> {
    NATIVE_MOVE
        .try_with(|request| request.borrow_mut().take())
        .ok()
        .flatten()
}

// One sequence for the native synthesizer, never one per target or session.
static NEXT_EVENT_NUMBER: AtomicI64 = AtomicI64::new(0);

fn allocate_event_number(counter: &AtomicI64) -> Result<i64, NativeMoveError> {
    counter
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |number| {
            number.checked_add(1)
        })
        .map_err(|_| NativeMoveError::EventNumberExhausted)
}

#[repr(C)]
struct OpaqueCGEvent {
    _private: [u8; 0],
}

// SAFETY: AppKit declares the getter as CGEventRef, an opaque __CGEvent pointer.
unsafe impl RefEncode for OpaqueCGEvent {
    const ENCODING_REF: Encoding = Encoding::Pointer(&Encoding::Struct("__CGEvent", &[]));
}

fn retained_cg_event(native: &NSEvent) -> Option<CGEvent> {
    // SAFETY: the getter's exact opaque-pointer encoding is supplied above;
    // `native` is live for the getter and until the borrowed value is retained.
    let raw: *mut OpaqueCGEvent = unsafe { objc2::msg_send![native, CGEvent] };
    if raw.is_null() {
        return None;
    }
    // SAFETY: raw is a nonnull borrowed CGEvent. Its +1 is owned by CGEvent's
    // Drop, independently of this NSEvent and the current autorelease pool.
    Some(unsafe {
        CFRetain(raw.cast());
        CGEvent::from_ptr(raw.cast::<std::ffi::c_void>() as CGEventRef)
    })
}

#[must_use = "preparing a native move does not send it"]
pub struct PreparedNativeMove {
    event: CGEvent,
    pid: i32,
    timebase: mach_timebase_info_data_t,
}

impl std::fmt::Debug for PreparedNativeMove {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedNativeMove")
            .field("pid", &self.pid)
            .finish_non_exhaustive()
    }
}

/// Create the NSEvent and retain its nullable, autoreleased CGEvent.
/// Call and consume this on one native worker inside its autorelease pool.
///
/// # Errors
/// Returns the failed geometry, native factory or platform-API preparation step.
pub fn prepare_native_move(
    request: NativeMoveRequest,
) -> Result<PreparedNativeMove, NativeMoveError> {
    let point = request.screen_point;
    let bounds = request.window_bounds;
    if request.pid <= 0
        || request.window_id == 0
        || ![
            point.x,
            point.y,
            bounds.origin.x,
            bounds.origin.y,
            bounds.size.width,
            bounds.size.height,
        ]
        .iter()
        .all(|value| value.is_finite())
    {
        return Err(NativeMoveError::InvalidGeometry);
    }
    let local_x = point.x - bounds.origin.x;
    let local_y = point.y - bounds.origin.y;
    let local_y = if request.window_uses_flipped_coordinates {
        bounds.size.height - local_y
    } else {
        local_y
    };
    if !local_x.is_finite() || !local_y.is_finite() {
        return Err(NativeMoveError::UnrepresentableLocalPoint);
    }
    let timebase =
        super::page_scroll::uptime_timebase().map_err(|_| NativeMoveError::UptimeUnavailable)?;
    let event_number = allocate_event_number(&NEXT_EVENT_NUMBER)?;
    // SAFETY: these are NSEvent's native mouse factory argument types. The
    // event and its conversion stay on this worker; no NSEvent crosses await.
    let native = unsafe {
        NSEvent::mouseEventWithType_location_modifierFlags_timestamp_windowNumber_context_eventNumber_clickCount_pressure(
            NSEventType::MouseMoved, NSPoint::new(point.x, point.y),
            NSEventModifierFlags::empty(), 0.0, request.window_id as isize,
            None, event_number as isize, 1, 1.0,
        )
    }.ok_or(NativeMoveError::EventUnavailable)?;
    let event = retained_cg_event(&native).ok_or(NativeMoveError::CgEventUnavailable)?;
    event.set_flags(CGEventFlags::empty());
    super::set_event_location(&event, point);
    event.set_integer_value_field(3, 0);
    event.set_integer_value_field(7, 3);
    event.set_integer_value_field(
        EventField::MOUSE_EVENT_WINDOW_UNDER_MOUSE_POINTER,
        i64::from(request.window_id),
    );
    event.set_integer_value_field(
        EventField::MOUSE_EVENT_WINDOW_UNDER_MOUSE_POINTER_THAT_CAN_HANDLE_THIS_EVENT,
        i64::from(request.window_id),
    );
    super::page_scroll::set_window_location(event.as_ptr(), CGPoint::new(local_x, local_y))
        .map_err(|_| NativeMoveError::WindowLocationUnavailable)?;
    Ok(PreparedNativeMove {
        event,
        pid: request.pid,
        timebase,
    })
}

impl PreparedNativeMove {
    /// Stamp boot uptime, post once to the selected PID, then wait 10 ms.
    ///
    /// # Errors
    /// Returns before posting if boot uptime does not fit the native timestamp.
    pub fn post(self) -> Result<(), NativeMoveError> {
        timestamp_and_post(&self.event, self.pid, &self.timebase)
            .map_err(|_| NativeMoveError::UptimeOverflow)?;
        std::thread::sleep(Duration::from_millis(10));
        Ok(())
    }
}

/// A native focus event could not be prepared or timestamped.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NativeEventError {
    #[error("native focus boot uptime source is unavailable")]
    UptimeUnavailable,
    #[error("native focus event factory returned no event")]
    EventUnavailable,
    #[error("native focus event has no CGEvent")]
    CgEventUnavailable,
    #[error("native focus uptime timestamp cannot be represented")]
    UptimeOverflow,
    #[error("native focus window-location API is unavailable")]
    WindowLocationUnavailable,
}

/// One retained native event; it carries no target authority or lifecycle lease.
#[must_use = "preparing a native event does not send it"]
pub struct PreparedNativeEvent {
    event: CGEvent,
    timebase: mach_timebase_info_data_t,
}

impl std::fmt::Debug for PreparedNativeEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedNativeEvent")
            .finish_non_exhaustive()
    }
}

/// Prepare one native-profile otherEvent with zero location, time and data words.
///
/// The focus caller selects the source event type (13 or 21), subtype and flags.
/// Call and consume this on one native worker inside its autorelease pool.
///
/// # Errors
/// Returns the failed native factory, CGEvent conversion or clock setup step.
pub fn prepare_other_event(
    event_type: u32,
    subtype: u16,
    flags: u64,
    window_id: u32,
) -> Result<PreparedNativeEvent, NativeEventError> {
    let timebase =
        super::page_scroll::uptime_timebase().map_err(|_| NativeEventError::UptimeUnavailable)?;
    // The original subtype is a 16-bit word, including 0x8000; AppKit takes
    // the same bits through its signed-short ABI.
    let subtype = i16::from_ne_bytes(subtype.to_ne_bytes());
    // SAFETY: these are the native otherEvent factory's argument types, with
    // no graphics context. The NSEvent and conversion stay on this worker.
    let native = unsafe {
        NSEvent::otherEventWithType_location_modifierFlags_timestamp_windowNumber_context_subtype_data1_data2(
            NSEventType(event_type as usize), NSPoint::new(0.0, 0.0),
            NSEventModifierFlags(flags as usize), 0.0,
            window_id as isize, None, subtype, 0, 0,
        )
    }.ok_or(NativeEventError::EventUnavailable)?;
    let event = retained_cg_event(&native).ok_or(NativeEventError::CgEventUnavailable)?;
    Ok(PreparedNativeEvent { event, timebase })
}

impl PreparedNativeEvent {
    /// Stamp fresh boot uptime and post once to `pid`, with no pause.
    ///
    /// This neither checks nor creates the caller's PID authority or lease.
    /// Prepare and send a pulse's first event before preparing its second event.
    ///
    /// # Errors
    /// Returns before posting if boot uptime does not fit the native timestamp.
    pub fn timestamp_and_post(self, pid: i32) -> Result<(), NativeEventError> {
        timestamp_and_post(&self.event, pid, &self.timebase)
            .map_err(|_| NativeEventError::UptimeOverflow)
    }
}

/// Retained window metadata; absence of the activation-point attribute differs
/// from an attribute whose value is explicitly absent.
#[derive(Clone, Copy, Debug)]
pub struct FocusActivationWindow {
    pub window_id: u32,
    pub bounds: Option<[f64; 4]>,
    pub activation_point: Option<Option<[f64; 2]>>,
}

/// Prepare the entire activation sequence before posting any event.
///
/// # Errors
/// Returns a native factory, CGEvent, clock or window-location API failure.
pub fn prepare_focus_activation(
    window: Option<FocusActivationWindow>,
) -> Result<Vec<PreparedNativeEvent>, NativeEventError> {
    let Some(window) = window.filter(|window| window.activation_point.is_some()) else {
        return Ok(vec![prepare_other_event(13, 1, 0, 0)?]);
    };
    let flags = if window.window_id == 0 { 0 } else { 0xc0000 };
    let activation = prepare_other_event(13, 1, flags, window.window_id)?;
    let (Some(bounds), Some(Some(point))) = (window.bounds, window.activation_point) else {
        return Ok(vec![activation]);
    };
    if window.window_id == 0 {
        return Ok(vec![activation]);
    }
    let down = prepare_activation_mouse(1, 1, window.window_id, bounds, point)?;
    let up = prepare_activation_mouse(2, 2, window.window_id, bounds, point)?;
    Ok(vec![activation, down, up])
}

fn prepare_activation_mouse(
    event_type: u32,
    event_number: isize,
    window_id: u32,
    bounds: [f64; 4],
    point: [f64; 2],
) -> Result<PreparedNativeEvent, NativeEventError> {
    let timebase =
        super::page_scroll::uptime_timebase().map_err(|_| NativeEventError::UptimeUnavailable)?;
    // SAFETY: these are AppKit's native mouse factory arguments. No event or
    // borrowed AppKit reference leaves this worker's autorelease pool.
    let native = unsafe {
        NSEvent::mouseEventWithType_location_modifierFlags_timestamp_windowNumber_context_eventNumber_clickCount_pressure(
            NSEventType(event_type as usize), NSPoint::new(point[0], point[1]),
            NSEventModifierFlags::empty(), 0.0, window_id as isize,
            None, event_number, 1, 1.0,
        )
    }.ok_or(NativeEventError::EventUnavailable)?;
    let event = retained_cg_event(&native).ok_or(NativeEventError::CgEventUnavailable)?;
    event.set_flags(CGEventFlags::empty());
    super::set_event_location(&event, CGPoint::new(point[0], point[1]));
    event.set_integer_value_field(3, 0);
    event.set_integer_value_field(7, 3);
    event.set_integer_value_field(91, i64::from(window_id));
    event.set_integer_value_field(92, i64::from(window_id));
    // Read the actual CG location after setting it, as the original builder
    // does. CGRectGetMinX/Y also handle negative rectangle dimensions.
    let actual = event.location();
    let rectangle = CGRect::new(
        &CGPoint::new(bounds[0], bounds[1]),
        &CGSize::new(bounds[2], bounds[3]),
    );
    // SAFETY: these native by-value CoreGraphics structs have their declared
    // ABI on both supported 64-bit macOS architectures.
    let local = unsafe {
        let min_x = CGRectGetMinX(rectangle);
        let min_y = CGRectGetMinY(rectangle);
        let transform = CGAffineTransformMakeTranslation(-min_x, -min_y);
        CGPointApplyAffineTransform(actual, transform)
    };
    super::page_scroll::set_window_location(event.as_ptr(), local)
        .map_err(|_| NativeEventError::WindowLocationUnavailable)?;
    Ok(PreparedNativeEvent { event, timebase })
}

fn timestamp_and_post(
    event: &CGEvent,
    pid: i32,
    timebase: &mach_timebase_info_data_t,
) -> Result<(), std::num::TryFromIntError> {
    // SAFETY: this is the read-only mach boot clock; both preparation paths
    // validate their timebase before storing it in the prepared event.
    let ticks = unsafe { mach_absolute_time() };
    let nanos = u128::from(ticks) * u128::from(timebase.numer) / u128::from(timebase.denom);
    let timestamp = u64::try_from(nanos)?;
    // SAFETY: the caller owns the retained event and timestamp has its ABI type.
    unsafe { CGEventSetTimestamp(event.as_ptr(), timestamp) };
    event.post_to_pid(pid);
    Ok(())
}

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    fn CGRectGetMinX(rectangle: CGRect) -> f64;
    fn CGRectGetMinY(rectangle: CGRect) -> f64;
    fn CGAffineTransformMakeTranslation(x: f64, y: f64) -> CGAffineTransform;
    fn CGPointApplyAffineTransform(point: CGPoint, transform: CGAffineTransform) -> CGPoint;
    fn CGEventSetTimestamp(event: CGEventRef, timestamp: u64);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_number_returns_the_old_value_and_never_wraps() {
        let numbers = AtomicI64::new(0);
        assert_eq!(allocate_event_number(&numbers).unwrap(), 0);
        assert_eq!(allocate_event_number(&numbers).unwrap(), 1);
        numbers.store(i64::MAX, Ordering::Relaxed);
        assert!(allocate_event_number(&numbers).is_err());
        assert_eq!(numbers.load(Ordering::Relaxed), i64::MAX);
    }

    #[tokio::test]
    async fn native_move_data_is_single_use_and_stays_with_its_future() {
        fn request(pid: i32) -> NativeMoveRequest {
            NativeMoveRequest {
                pid,
                window_id: 456,
                screen_point: CGPoint::new(-1.25, 42.5),
                window_bounds: Default::default(),
                window_uses_flipped_coordinates: true,
                native_window_pixels: [37.5, 25.0],
            }
        }
        assert!(take_native_move().is_none());
        let (first, second) = tokio::join!(
            with_native_move(request(11), async {
                tokio::task::yield_now().await;
                let request = take_native_move().unwrap();
                assert!(take_native_move().is_none());
                request.pid
            }),
            with_native_move(request(22), async {
                tokio::task::yield_now().await;
                let request = take_native_move().unwrap();
                assert_eq!(request.screen_point.x.to_bits(), (-1.25_f64).to_bits());
                request.pid
            }),
        );
        assert_eq!((first, second), (11, 22));
        assert!(take_native_move().is_none());
    }
}
