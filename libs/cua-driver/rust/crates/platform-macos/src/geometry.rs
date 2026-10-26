//! Read-only WindowServer geometry and the selected AppKit screen's scale.
//!
//! This metadata is independent of screenshot success and pixel dimensions.
//! The caller owns main-queue dispatch and target/process lifetime checks.

pub mod event_target;
mod selection;

use crate::windows::{self, WindowBounds};
use core_graphics::{
    base::CGFloat,
    geometry::{CGPoint, CGRect, CGSize},
};
use objc2_app_kit::NSScreen;
use serde::{Deserialize, Serialize};

// Embedders may use a different objc2 generation. Obtain this marker through
// this module so the token has the backend's exact type.
pub use objc2_foundation::MainThreadMarker;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeWindowGeometry {
    pub window_id: u32,
    pub pid: i32,
    pub layer: i32,
    pub bounds: WindowBounds,
    /// The selected NSScreen's backingScaleFactor, without capture inference.
    pub native_scale: f64,
}

/// Read one window record and choose its scale on the AppKit main thread.
///
/// PID, layer and raw bounds come from the same WindowServer enumeration.
/// Screens retain their AppKit order and raw `frame` coordinate system. Equal
/// intersection areas keep the first screen, including all-zero intersections.
/// An empty screen list uses 2.0; missing main-queue hosting is not that case.
/// This function does not capture, walk accessibility, focus or deliver input.
pub fn window_geometry_on_main_thread(
    main_thread: MainThreadMarker,
    expected_pid: i32,
    window_id: u32,
) -> anyhow::Result<NativeWindowGeometry> {
    let window = windows::window_info_by_id(window_id)
        .ok_or_else(|| anyhow::anyhow!("window_id_not_found: {window_id}"))?;
    if window.pid != expected_pid {
        anyhow::bail!(
            "window_owner_pid_mismatch: window {window_id} belongs to pid {}, expected {expected_pid}",
            window.pid
        );
    }

    let bounds = CGRect::new(
        &CGPoint::new(window.bounds.x, window.bounds.y),
        &CGSize::new(window.bounds.width, window.bounds.height),
    );
    let screens = NSScreen::screens(main_thread);
    let winner = selection::largest_area_index((0..screens.count()).map(|index| {
        // SAFETY: this range comes from the retained immutable array's count.
        let screen = unsafe { screens.objectAtIndex(index) };
        let frame = screen.frame();
        // Intentionally keep AppKit's raw frame here. Normalizing its Y axis
        // would change the screen chosen for WindowServer bounds.
        let frame = CGRect::new(
            &CGPoint::new(frame.origin.x, frame.origin.y),
            &CGSize::new(frame.size.width, frame.size.height),
        );
        // SAFETY: both values have CoreGraphics' CGRect C layout. Keeping the
        // native intersection/width/height operations also preserves its null
        // and degenerate-rectangle behavior.
        unsafe {
            let intersection = CGRectIntersection(frame, bounds);
            CGRectGetWidth(intersection) * CGRectGetHeight(intersection)
        }
    }));
    let native_scale = match winner {
        Some(index) => {
            // SAFETY: selection preserves an index from this retained,
            // immutable array's count range.
            unsafe { screens.objectAtIndex(index) }.backingScaleFactor()
        }
        None => 2.0,
    };
    Ok(NativeWindowGeometry {
        window_id: window.window_id,
        pid: window.pid,
        layer: window.layer,
        bounds: window.bounds,
        native_scale,
    })
}

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGRectIntersection(first: CGRect, second: CGRect) -> CGRect;
    fn CGRectGetWidth(rectangle: CGRect) -> CGFloat;
    fn CGRectGetHeight(rectangle: CGRect) -> CGFloat;
}
