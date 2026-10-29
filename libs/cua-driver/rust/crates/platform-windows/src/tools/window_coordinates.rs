//! Private physical-frame refinement supplied by the trusted SDK invocation.
//! Public tool arguments cannot supply this evidence; registry dispatch removes
//! all caller-owned reserved fields before applying its captured evidence.

use cua_driver_core::{protocol::ToolResult, tool::NativeWindowFrame};
use serde_json::json;
#[cfg(target_os = "windows")]
use serde_json::Value;

fn refused(message: impl Into<String>) -> ToolResult {
    ToolResult::error(message).with_structured(json!({
        "code":"window_coordinate_frame_mismatch", "effect":"refused"
    }))
}

fn validate(
    frame: NativeWindowFrame,
    pid: u32,
    hwnd: u64,
    live: [i32; 4],
) -> Result<NativeWindowFrame, ToolResult> {
    if frame.pid() != pid || frame.window_id() != hwnd || frame.bounds() != live {
        return Err(refused(
            "native window target or bounds changed before coordinate input",
        ));
    }
    Ok(frame)
}

/// Convert already-refined physical offsets into the exact full-window origin.
/// No screenshot crop inset or DPI multiplier belongs to this coordinate frame.
pub(super) fn screen_point(
    frame: NativeWindowFrame,
    x: f64,
    y: f64,
) -> Result<(i32, i32), ToolResult> {
    fn axis(point: f64, origin: i32, size: i32) -> Option<i32> {
        if !point.is_finite() || point.fract() != 0.0 || point < 0.0 || point >= f64::from(size) {
            return None;
        }
        origin.checked_add(point as i32)
    }
    let [ox, oy, width, height] = frame.bounds();
    axis(x, ox, width)
        .zip(axis(y, oy, height))
        .ok_or_else(|| refused("coordinate is outside the native window frame"))
}

#[derive(Debug)]
pub(super) struct NativeFrameRefused(&'static str);
impl std::fmt::Display for NativeFrameRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for NativeFrameRefused {}
impl NativeFrameRefused {
    pub(super) fn result(&self) -> ToolResult {
        refused(self.0)
    }
}

fn check_live(
    frame: NativeWindowFrame,
    live: Option<(u32, u64, [i32; 4])>,
) -> Result<(), NativeFrameRefused> {
    let Some((pid, hwnd, bounds)) = live else {
        return Err(NativeFrameRefused("native window is no longer available"));
    };
    if frame.pid() != pid || frame.window_id() != hwnd || frame.bounds() != bounds {
        return Err(NativeFrameRefused(
            "native window target or bounds changed before coordinate input",
        ));
    }
    Ok(())
}

/// The actual worker calls this immediately before the first native effect.
/// It does not freeze the desktop or confirm anything after dispatch.
#[cfg(target_os = "windows")]
pub(super) fn revalidate(frame: NativeWindowFrame) -> Result<(), NativeFrameRefused> {
    let live = crate::capture_admission::live_window_frame(
        crate::capture_admission::WindowsCaptureTarget::Window {
            pid: frame.pid(),
            window_id: frame.window_id(),
        },
    )
    .ok()
    .map(|live| (live.pid(), live.window_id(), live.bounds()));
    check_live(frame, live)
}

#[cfg(target_os = "windows")]
pub(super) fn admit(
    args: &Value,
    pid: u32,
    hwnd: u64,
) -> Result<Option<NativeWindowFrame>, ToolResult> {
    let Some(value) = args.get("_native_window_frame") else {
        return Ok(None);
    };
    if args.get("window_id").and_then(Value::as_u64) != Some(hwnd)
        || args.get("capture_id").is_some()
        || args
            .get("element_token")
            .is_some_and(|value| !value.is_null())
        || args.get("from_zoom").and_then(Value::as_bool) == Some(true)
    {
        return Err(refused(
            "native frame requires an exact coordinate window without capture, element or zoom",
        ));
    }
    if args.get("delivery_mode").and_then(Value::as_str) != Some("foreground") {
        return Err(refused(
            "trusted native frame refinement requires foreground coordinate delivery",
        ));
    }
    let frame: NativeWindowFrame = serde_json::from_value(value.clone())
        .map_err(|error| refused(format!("invalid trusted native frame: {error}")))?;
    let live = crate::capture_admission::live_window_frame(
        crate::capture_admission::WindowsCaptureTarget::Window {
            pid,
            window_id: hwnd,
        },
    )
    .map_err(|error| refused(error.to_string()))?;
    validate(frame, pid, hwnd, live.bounds()).map(Some)
}
