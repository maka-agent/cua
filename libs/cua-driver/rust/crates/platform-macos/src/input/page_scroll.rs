//! One native macOS page-scroll event, independent of Portable page input.
//!
//! The Host supplies an exact retained target and a point already resolved
//! against its observation. Preparing an event does not deliver native input;
//! the Host can recheck cancellation immediately before consuming `post()`.

mod math;

pub use math::{page_deltas, DeltaError, PageDirection};

use core_graphics::{
    event::{CGEvent, EventField, ScrollEventUnit},
    event_source::{CGEventSource, CGEventSourceStateID},
    geometry::{CGPoint, CGRect},
    sys::CGEventRef,
};
use foreign_types::ForeignType;
use mach2::mach_time::{mach_absolute_time, mach_timebase_info, mach_timebase_info_data_t};
use std::{cell::RefCell, future::Future, time::Duration};

#[derive(Clone, Copy, Debug)]
pub struct PageScrollRequest {
    pub pid: i32,
    pub window_id: u32,
    pub screen_point: CGPoint,
    pub window_bounds: CGRect,
    pub window_uses_flipped_coordinates: bool,
    pub direction: PageDirection,
    pub pages: f64,
    /// Selected element frame extent, or the cached visible frame extent.
    pub extent: f64,
}

/// Trusted Host data for one native page event. The two coordinate frames are
/// deliberately separate: only `native_window_pixels` describes the ordinary
/// SDK input record; the event consumes the original global logical point.
/// This request does not authorize input or resolve an application's helpers.
#[derive(Clone, Copy, Debug)]
pub struct NativePageScrollRequest {
    pub event: PageScrollRequest,
    pub native_window_pixels: [f64; 2],
}

tokio::task_local! {
    static NATIVE_PAGE_SCROLL: RefCell<Option<NativePageScrollRequest>>;
}

/// Attach request data to the same authorized bound-session scroll future.
/// Public JSON has no way to construct this scope.
#[doc(hidden)]
pub async fn with_native_page_scroll<F: Future>(
    request: NativePageScrollRequest,
    operation: F,
) -> F::Output {
    NATIVE_PAGE_SCROLL
        .scope(RefCell::new(Some(request)), operation)
        .await
}

pub(crate) fn take_native_page_scroll() -> Option<NativePageScrollRequest> {
    NATIVE_PAGE_SCROLL
        .try_with(|request| request.borrow_mut().take())
        .ok()
        .flatten()
}

#[must_use = "preparing a page scroll does not send it"]
pub struct PreparedPageScroll {
    event: CGEvent,
    pid: i32,
    timebase: mach_timebase_info_data_t,
}

/// Build exactly one PIXEL event without moving a cursor or posting input.
///
/// The wheel count deliberately remains one, including horizontal requests.
/// Its effect on horizontal delivery is a native macOS verification boundary.
pub fn prepare_page_scroll(request: PageScrollRequest) -> anyhow::Result<PreparedPageScroll> {
    let (delta_x, delta_y) = page_deltas(request.direction, request.pages, request.extent)?;
    let bounds = request.window_bounds;
    let point = request.screen_point;
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
        anyhow::bail!(
            "unsupported_native_geometry: page scroll requires a finite exact-window point"
        );
    }
    let local_x = point.x - bounds.origin.x;
    let local_y = point.y - bounds.origin.y;
    let local_y = if request.window_uses_flipped_coordinates {
        bounds.size.height - local_y
    } else {
        local_y
    };
    if !local_x.is_finite() || !local_y.is_finite() {
        anyhow::bail!("unsupported_native_geometry: page scroll local point cannot be represented");
    }
    let timebase = uptime_timebase()?;
    let source = CGEventSource::new(CGEventSourceStateID::HIDSystemState)
        .map_err(|_| anyhow::anyhow!("native page scroll event source unavailable"))?;
    let event = CGEvent::new_scroll_event(source, ScrollEventUnit::PIXEL, 1, delta_y, delta_x, 0)
        .map_err(|_| anyhow::anyhow!("native page scroll event creation failed"))?;
    super::set_event_location(&event, point);
    event.set_integer_value_field(51, i64::from(request.window_id));
    event.set_integer_value_field(
        EventField::MOUSE_EVENT_WINDOW_UNDER_MOUSE_POINTER,
        i64::from(request.window_id),
    );
    event.set_integer_value_field(
        EventField::MOUSE_EVENT_WINDOW_UNDER_MOUSE_POINTER_THAT_CAN_HANDLE_THIS_EVENT,
        i64::from(request.window_id),
    );
    set_window_location(event.as_ptr(), CGPoint::new(local_x, local_y))?;
    Ok(PreparedPageScroll {
        event,
        pid: request.pid,
        timebase,
    })
}

impl PreparedPageScroll {
    /// Consume this prepared event once, post to its PID, then wait 10 ms.
    /// The timestamp uses the current boot uptime rather than wall-clock time.
    pub fn post(self) -> anyhow::Result<()> {
        // SAFETY: mach_absolute_time is a read-only clock and `timebase` was
        // checked before preparation returned. The event stays retained here.
        let ticks = unsafe { mach_absolute_time() };
        let nanos =
            u128::from(ticks) * u128::from(self.timebase.numer) / u128::from(self.timebase.denom);
        let timestamp = u64::try_from(nanos)
            .map_err(|_| anyhow::anyhow!("native page scroll uptime cannot be represented"))?;
        // SAFETY: this event remains retained and the timestamp has the native ABI type.
        unsafe { CGEventSetTimestamp(self.event.as_ptr(), timestamp) };
        self.event.post_to_pid(self.pid);
        std::thread::sleep(Duration::from_millis(10));
        Ok(())
    }
}

pub(super) fn uptime_timebase() -> anyhow::Result<mach_timebase_info_data_t> {
    let mut info = mach_timebase_info_data_t { numer: 0, denom: 0 };
    // SAFETY: the system fills one correctly sized native timebase record.
    let result = unsafe { mach_timebase_info(&mut info) };
    if result != 0 || info.numer == 0 || info.denom == 0 {
        anyhow::bail!("native page scroll uptime source unavailable");
    }
    Ok(info)
}

pub(super) fn set_window_location(event: CGEventRef, point: CGPoint) -> anyhow::Result<()> {
    if !super::skylight::set_window_location(event.cast(), point.x, point.y) {
        anyhow::bail!("native page scroll window-location API unavailable");
    }
    Ok(())
}

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    fn CGEventSetTimestamp(event: CGEventRef, timestamp: u64);
}

#[cfg(test)]
mod request_tests {
    use super::*;
    use core_graphics::geometry::CGSize;

    fn request(pid: i32) -> NativePageScrollRequest {
        NativePageScrollRequest {
            event: PageScrollRequest {
                pid,
                window_id: pid as u32,
                screen_point: CGPoint::new(-1.25, 42.5),
                window_bounds: CGRect::new(&CGPoint::new(-20.0, 30.0), &CGSize::new(0.0, 0.0)),
                window_uses_flipped_coordinates: true,
                direction: PageDirection::Down,
                pages: 51.25,
                extent: 100.25,
            },
            native_window_pixels: [37.5, 25.0],
        }
    }

    #[test]
    fn prepared_page_scroll_accepts_fractional_window_coordinates_without_posting() {
        let event = prepare_page_scroll(PageScrollRequest {
            pid: std::process::id() as i32,
            window_id: 17,
            screen_point: CGPoint::new(100.25, 150.75),
            window_bounds: CGRect::new(&CGPoint::new(20.0, 30.0), &CGSize::new(300.0, 200.0)),
            window_uses_flipped_coordinates: true,
            direction: PageDirection::Down,
            pages: 1.0,
            extent: 200.0,
        })
        .expect("prepare the retained event without delivering input");
        assert_eq!(
            (event.event.location().x, event.event.location().y),
            (100.25, 150.75)
        );
    }

    #[tokio::test]
    async fn native_page_data_is_single_use_and_isolated_between_tasks() {
        assert!(take_native_page_scroll().is_none());
        let (first, second) = tokio::join!(
            with_native_page_scroll(request(11), async {
                tokio::task::yield_now().await;
                let request = take_native_page_scroll().unwrap();
                assert!(take_native_page_scroll().is_none());
                request
            }),
            with_native_page_scroll(request(22), async {
                tokio::task::yield_now().await;
                let request = take_native_page_scroll().unwrap();
                assert!(take_native_page_scroll().is_none());
                request
            }),
        );
        assert_eq!((first.event.pid, second.event.pid), (11, 22));
        assert_eq!(first.event.pages, 51.25);
        assert_eq!(first.event.screen_point.x.to_bits(), (-1.25_f64).to_bits());
        assert_eq!(first.event.screen_point.y.to_bits(), 42.5_f64.to_bits());
        assert_eq!(first.native_window_pixels, [37.5, 25.0]);
        assert!(take_native_page_scroll().is_none());
    }
}
