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
use std::{ffi::c_void, sync::OnceLock, time::Duration};

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

#[must_use = "preparing a page scroll does not send it"]
pub struct PreparedPageScroll {
    event: CGEvent,
    pid: i32,
    timebase: libc::mach_timebase_info_data_t,
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
        let ticks = unsafe { libc::mach_absolute_time() };
        let nanos =
            u128::from(ticks) * u128::from(self.timebase.numer) / u128::from(self.timebase.denom);
        let timestamp = u64::try_from(nanos)
            .map_err(|_| anyhow::anyhow!("native page scroll uptime cannot be represented"))?;
        unsafe { CGEventSetTimestamp(self.event.as_ptr(), timestamp) };
        self.event.post_to_pid(self.pid);
        std::thread::sleep(Duration::from_millis(10));
        Ok(())
    }
}

fn uptime_timebase() -> anyhow::Result<libc::mach_timebase_info_data_t> {
    let mut info = libc::mach_timebase_info_data_t { numer: 0, denom: 0 };
    // SAFETY: the system fills one correctly sized native timebase record.
    let result = unsafe { libc::mach_timebase_info(&mut info) };
    if result != 0 || info.numer == 0 || info.denom == 0 {
        anyhow::bail!("native page scroll uptime source unavailable");
    }
    Ok(info)
}

fn set_window_location(event: CGEventRef, point: CGPoint) -> anyhow::Result<()> {
    type SetWindowLocation = unsafe extern "C" fn(CGEventRef, CGPoint);
    static FUNCTION: OnceLock<Option<SetWindowLocation>> = OnceLock::new();
    let function = FUNCTION.get_or_init(|| {
        super::skylight::find_sym(b"_CGEventSetWindowLocation\0").map(|pointer| {
            // SAFETY: this exact symbol has the fixed CGEventRef + CGPoint ABI.
            unsafe { std::mem::transmute::<*mut c_void, SetWindowLocation>(pointer) }
        })
    });
    let function = function
        .ok_or_else(|| anyhow::anyhow!("native page scroll window-location API unavailable"))?;
    // SAFETY: preparation retains `event` and supplies finite local coordinates.
    unsafe { function(event, point) };
    Ok(())
}

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    fn CGEventSetTimestamp(event: CGEventRef, timestamp: u64);
}
