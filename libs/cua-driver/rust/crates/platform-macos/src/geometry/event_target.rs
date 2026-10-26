//! Read-only AppKit observations used at the native event-target boundary.

use core_foundation::{
    array::{CFArray, CFArrayRef},
    base::TCFType,
};
use objc2::runtime::Bool;
use objc2_app_kit::{NSRunningApplication, NSScreen, NSWindow};
use objc2_foundation::{MainThreadMarker, NSPoint, NSRect, NSString};
use serde::{Deserialize, Serialize};

/// A read-only event-target observation was unavailable or unrepresentable.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EventTargetError {
    #[error("WindowServer returned no on-screen window list")]
    WindowOrderUnavailable,
    #[error("native window ID cannot be represented")]
    WindowIdUnrepresentable,
    #[error("native event point is not finite")]
    NonfinitePoint,
    #[error("native window number cannot be represented")]
    WindowNumberUnrepresentable,
}

/// Facts from one exact NSRunningApplication, including background helpers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunningProcess {
    pub finished_launching: bool,
    pub activation_policy: i64,
    pub terminated: bool,
    pub bundle_identifier: Option<String>,
}

/// Preserve WindowServer's on-screen, non-desktop order on every layer.
///
/// # Errors
/// Refuses an unavailable native list or a window ID outside its native range.
pub fn ordered_window_ids_on_main_thread(
    _main: MainThreadMarker,
) -> Result<Vec<u32>, EventTargetError> {
    // SAFETY: this copied array contains raw uintptr-encoded CGWindowIDs,
    // not CFNumber objects. Only the array itself has CF ownership.
    let raw = unsafe { CGWindowListCreate(0x11, 0) };
    if raw.is_null() {
        return Err(EventTargetError::WindowOrderUnavailable);
    }
    let array: CFArray<*const std::ffi::c_void> = unsafe { CFArray::wrap_under_create_rule(raw) };
    array
        .iter()
        .map(|value| {
            u32::try_from(*value as usize).map_err(|_| EventTargetError::WindowIdUnrepresentable)
        })
        .collect()
}

/// Query exactly the requested PID, including non-regular helper applications.
pub fn running_process_on_main_thread(_main: MainThreadMarker, pid: i32) -> Option<RunningProcess> {
    // SAFETY: native read-only queries; the retained application stays local.
    unsafe {
        NSRunningApplication::runningApplicationWithProcessIdentifier(pid).map(|app| {
            RunningProcess {
                finished_launching: app.isFinishedLaunching(),
                activation_policy: app.activationPolicy().0 as i64,
                terminated: app.isTerminated(),
                bundle_identifier: app.bundleIdentifier().map(|value| value.to_string()),
            }
        })
    }
}

/// Return the first native process for the bundle, preserving AppKit order.
pub fn first_bundle_process_on_main_thread(_main: MainThreadMarker, bundle: &str) -> Option<i32> {
    let bundle = NSString::from_str(bundle);
    // SAFETY: the array is retained and index zero is read only when present.
    unsafe {
        let applications = NSRunningApplication::runningApplicationsWithBundleIdentifier(&bundle);
        (applications.count() > 0).then(|| applications.objectAtIndex(0).processIdentifier())
    }
}

/// Select the first AppKit screen containing the original global point, then
/// use its raw height for the original NSWindow point conversion.
///
/// # Errors
/// Refuses nonfinite coordinates or an unrepresentable native window number.
pub fn global_window_at_point_on_main_thread(
    main: MainThreadMarker,
    point: [f64; 2],
) -> Result<Option<u32>, EventTargetError> {
    if !point.iter().all(|value| value.is_finite()) {
        return Err(EventTargetError::NonfinitePoint);
    }
    let screens = NSScreen::screens(main);
    for index in 0..screens.count() {
        // SAFETY: the index is bounded by this retained immutable array.
        let frame = unsafe { screens.objectAtIndex(index) }.frame();
        let native_point = NSPoint::new(point[0], point[1]);
        if unsafe { NSMouseInRect(native_point, frame, Bool::NO) }.as_bool() {
            let converted = NSPoint::new(point[0], frame.size.height - point[1]);
            // SAFETY: the caller supplies the AppKit main-thread marker.
            let window = unsafe {
                NSWindow::windowNumberAtPoint_belowWindowWithWindowNumber(converted, 0, main)
            };
            return if window == 0 {
                Ok(None)
            } else {
                u32::try_from(window)
                    .map(Some)
                    .map_err(|_| EventTargetError::WindowNumberUnrepresentable)
            };
        }
    }
    Ok(None)
}

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    fn CGWindowListCreate(options: u32, relative_to: u32) -> CFArrayRef;
}

#[link(name = "Foundation", kind = "framework")]
unsafe extern "C" {
    fn NSMouseInRect(point: NSPoint, rectangle: NSRect, flipped: Bool) -> Bool;
}
