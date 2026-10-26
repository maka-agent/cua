use async_trait::async_trait;
use core_foundation::base::{CFRelease, CFTypeRef};
use cua_driver_contract::{ScrollDirection, ScrollInput};
use cua_driver_core::{
    protocol::ToolResult,
    tool::{Tool, ToolDef},
    tool_args::parse_typed_projection,
};
use serde_json::Value;
use std::sync::Arc;

use crate::apps;
use crate::ax::bindings::{
    copy_children, copy_element_attr, copy_string_attr, element_screen_center, kAXErrorSuccess,
    perform_action, AXUIElementRef,
};
use crate::focus_guard;
use crate::window_change_detector::WindowChangeDetector;

use super::ToolState;

/// Per-notch pixel step for the wheel path. `page` rolls a screenful-ish chunk,
/// `line` a few text lines — tuned to feel like a real wheel notch. Runtime
/// tuning deferred (host is screen-recording); centralized here for one-line edits.
const WHEEL_STEP_LINE_PX: i32 = 120;
const WHEEL_STEP_PAGE_PX: i32 = 600;

/// Resolved pixel-wheel target in screen space, plus optional window-local
/// stamp + window id for backgrounded delivery.
struct WheelTarget {
    screen_x: f64,
    screen_y: f64,
    win_local: Option<(f64, f64)>,
    wid: Option<u32>,
    /// Element screen rect `[x, y, w, h]` for the cursor glide; `None` for
    /// pixel targets.
    rect: Option<[f64; 4]>,
}

pub struct ScrollTool {
    state: Arc<ToolState>,
}

impl ScrollTool {
    pub fn new(state: Arc<ToolState>) -> Self {
        Self { state }
    }

    async fn invoke_native_pages(
        &self,
        args: Value,
        request: crate::input::page_scroll::NativePageScrollRequest,
    ) -> ToolResult {
        use crate::input::page_scroll::prepare_page_scroll;
        use cua_driver_core::background_input::BackgroundAction;

        if let Err(error) = native_page_arguments_match(&args, &request) {
            return error;
        }
        // This is the actual event target, not an app PID substituted for a
        // helper. A trusted Host must resolve that relationship separately.
        let lease = match super::gate_background_window_action(
            request.event.pid,
            request.event.window_id,
            None,
            BackgroundAction::WindowPointer,
        )
        .await
        {
            Ok(lease) => lease,
            Err(refusal) => return refusal,
        };
        let outcome = tokio::task::spawn_blocking(move || {
            // The native worker keeps its exact mutation lease even if a
            // consumer abandons the asynchronous reply observer.
            let _lease = lease;
            let prepared = prepare_page_scroll(request.event).map_err(|error| {
                native_page_refusal("native_page_preparation_failed", error.to_string())
            })?;
            prepared
                .post()
                .map_err(|error| native_page_refusal("input_outcome_unknown", error.to_string()))
        })
        .await;
        match outcome {
            Ok(Ok(())) => native_page_posted_result(&request),
            Ok(Err(refusal)) => refusal,
            Err(error) => native_page_refusal(
                "input_outcome_unknown",
                format!("native page worker did not complete normally: {error}"),
            ),
        }
    }
}

fn native_page_posted_result(
    request: &crate::input::page_scroll::NativePageScrollRequest,
) -> ToolResult {
    ToolResult::text("Native page event posted.").with_structured(serde_json::json!({
        "path":"cgevent","native_profile":"native_pages",
        "effect":"unverifiable","verified":false,
        "native_page_request":native_page_provenance(request),
    }))
}

fn native_page_refusal(code: &str, reason: String) -> ToolResult {
    ToolResult::error(reason).with_structured(serde_json::json!({"code":code}))
}

fn native_page_arguments_match(
    args: &Value,
    request: &crate::input::page_scroll::NativePageScrollRequest,
) -> Result<(), ToolResult> {
    use crate::input::page_scroll::{page_deltas, DeltaError, PageDirection};

    let event = &request.event;
    let direction = match event.direction {
        PageDirection::Up => "up",
        PageDirection::Down => "down",
        PageDirection::Left => "left",
        PageDirection::Right => "right",
    };
    if args.get("pid").and_then(Value::as_i64) != Some(i64::from(event.pid))
        || args.get("window_id").and_then(Value::as_u64) != Some(u64::from(event.window_id))
        || args.get("direction").and_then(Value::as_str) != Some(direction)
        || args.get("by").and_then(Value::as_str) != Some("page")
        || args.get("amount").and_then(Value::as_f64) != Some(event.pages)
        || args.get("scope").and_then(Value::as_str) != Some("window")
        || args.get("delivery_mode").and_then(Value::as_str) != Some("background")
        || args.get("x").and_then(Value::as_f64) != Some(request.native_window_pixels[0])
        || args.get("y").and_then(Value::as_f64) != Some(request.native_window_pixels[1])
        || !request
            .native_window_pixels
            .iter()
            .all(|value| value.is_finite())
    {
        return Err(native_page_refusal(
            "native_page_request_mismatch",
            "native page data does not match the authorized scroll arguments".into(),
        ));
    }
    page_deltas(event.direction, event.pages, event.extent).map_err(|error| {
        let code = match error {
            DeltaError::InvalidPages => "invalid_arguments",
            DeltaError::UnrepresentableDelta => "unsupported_native_delta",
        };
        native_page_refusal(code, error.to_string())
    })?;
    Ok(())
}

fn native_page_provenance(request: &crate::input::page_scroll::NativePageScrollRequest) -> Value {
    let event = &request.event;
    let direction = match event.direction {
        crate::input::page_scroll::PageDirection::Up => "up",
        crate::input::page_scroll::PageDirection::Down => "down",
        crate::input::page_scroll::PageDirection::Left => "left",
        crate::input::page_scroll::PageDirection::Right => "right",
    };
    serde_json::json!({
        "pid":event.pid,"window_id":event.window_id,
        "native_window_pixels":request.native_window_pixels,
        "native_window_pixels_unit":"window_local_physical_pixels",
        "screen_point":[event.screen_point.x,event.screen_point.y],
        "screen_point_unit":"global_logical_points",
        "window_bounds":{
            "x":event.window_bounds.origin.x,"y":event.window_bounds.origin.y,
            "width":event.window_bounds.size.width,"height":event.window_bounds.size.height,
        },
        "window_bounds_unit":"global_logical_points",
        "window_uses_flipped_coordinates":event.window_uses_flipped_coordinates,
        "direction":direction,"pages":event.pages,
        "extent":event.extent,"extent_unit":"logical_points",
    })
}

static DEF: std::sync::OnceLock<ToolDef> = std::sync::OnceLock::new();

fn scroll_amount(by: &str, requested: u64) -> Result<usize, String> {
    match by {
        "pixel" => (1..=20000)
            .contains(&requested)
            .then_some(requested as usize)
            .ok_or_else(|| "pixel scroll amount out of range".into()),
        "line" | "page" => ScrollInput::checked_amount(requested),
        _ => Err("unsupported scroll granularity".into()),
    }
}

fn scroll_parameters(args: &Value) -> Result<(&'static str, usize), ToolResult> {
    use cua_driver_core::tool_args::ArgsExt;

    let by = match args.get("by").and_then(Value::as_str) {
        None if args.get("by").is_none() => "line",
        Some("line") => "line",
        Some("page") => "page",
        Some("pixel") => "pixel",
        _ => return Err(ToolResult::error("unsupported scroll granularity")),
    };
    let requested = match args.get("amount") {
        Some(_) => args.require_u64("amount")?,
        None => ScrollInput::DEFAULT_AMOUNT,
    };
    scroll_amount(by, requested)
        .map(|amount| (by, amount))
        .map_err(ToolResult::error)
}

fn desktop_scroll_input(args: &Value, by: &str) -> Result<ScrollInput, ToolResult> {
    if by != "pixel" {
        return parse_typed_projection("scroll", args);
    }
    // Quartz pixels belong to the native tool, outside the portable line/page
    // projection used here to validate the desktop target and coordinates.
    let mut projection = args.clone();
    if let Some(fields) = projection.as_object_mut() {
        fields.remove("by");
        fields.remove("amount");
    }
    parse_typed_projection("scroll", &projection)
}

const ELECTRON_BACKGROUND_SCROLL_UNAVAILABLE: &str = "Background scroll is unavailable for \
     this Electron/Chromium window on macOS: it drops background wheel events and keystrokes, \
     and background scroll movement could not be established through accessibility. \
     Retry with delivery_mode:\"foreground\" (and the same window_id, element_token \
     or x,y); the driver briefly fronts that window, scrolls, and restores the prior frontmost \
     app.";

fn def() -> &'static ToolDef {
    DEF.get_or_init(|| ToolDef {
        name: "scroll".into(),
        description: "Scroll the target pid.\n\
            - Targeted wheel: pass `element_token` (preferred) or window-local `x, y`. Sends a real wheel event at that point, so it scrolls whatever is under it. The only way to scroll nested `overflow:auto` regions in web views.\n\
            - Keystroke: no target, just pid + direction. PageDown/PageUp (by='page') or arrows (by='line') on the focused scroller.\n\
            \n\
            Electron/Chromium windows drop background wheel events: there a background scroll reveals the content just past the edge of the scroll container under the target through accessibility (about `amount` notches); `delivery_mode:\"foreground\"` is the fallback.\n\
            `amount` is wheel notches (targeted) or key repetitions (keystroke).".into(),
        input_schema: serde_json::json!({
            "type": "object",
            // `pid` conditionally required (validated in code), not pinned in the
            // schema — keeps the contract consistent across platforms.
            "required": ["direction"],
            "properties": {
                "session": { "type": "string", "description": "For multi-call work, prefer a short public session label and repeat it on every call that accepts it." },
                "pid": { "type": "integer", "description": "Target process ID. Required unless scope is \"desktop\" or element_token is supplied." },
                "direction": {
                    "type": "string",
                    "enum": ["up", "down", "left", "right"],
                    "description": "Scroll direction."
                },
                "by": {
                    "type": "string",
                    "enum": ["line", "page", "pixel"],
                    "description": "Scroll granularity. Pixel delivers a Quartz pixel-unit input delta, requiring a live point or element. Default: line."
                },
                "amount": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 20000,
                    "description": "Pixel amount: 1–20000 input pixels. Line/page amount: 1–50 repetitions. Default: 3."
                },
                "window_id": { "type": "integer", "description": "Window ID. Required with x/y; optional with element_token." },
                "element_token": cua_driver_core::tool_schema::element_token_schema(),
                "x": { "type": "number", "description": "Window-local screenshot X (get_window_state PNG). With y, wheel-scrolls at that point; needs window_id." },
                "y": { "type": "number", "description": "Window-local screenshot Y." },
                "scope": { "type": "string", "enum": ["window", "desktop"], "default": "window", "description": "\"desktop\" with x,y and no pid/window_id uses get_desktop_state coordinates." },
                "delivery_mode": cua_driver_core::tool_schema::delivery_mode_schema_with("Default \"background\": no fronting or focus steal. \"foreground\": briefly front the window, act, restore the prior app; last resort when background did not land.")
            },
            "additionalProperties": false
        }),
        read_only: false,
        destructive: false,
        idempotent: false,
        open_world: true,
    })
}

#[async_trait]
impl Tool for ScrollTool {
    fn def(&self) -> &ToolDef {
        def()
    }

    async fn invoke(&self, args: Value) -> ToolResult {
        use cua_driver_core::tool_args::ArgsExt;
        if let Some(request) = crate::input::page_scroll::take_native_page_scroll() {
            return self.invoke_native_pages(args, request).await;
        }
        if args.get("pixels").is_some() {
            return ToolResult::error("unsupported: pixels is an X11-native scroll unit")
                .with_structured(serde_json::json!({"code":"unsupported"}));
        }
        let (by, amount) = match scroll_parameters(&args) {
            Ok(parameters) => parameters,
            Err(error) => return error,
        };
        let precise = by == "pixel";
        if args.opt_str("scope").as_deref() == Some("desktop")
            && args.get("pid").is_none()
            && args.get("window_id").is_none()
        {
            let input = match desktop_scroll_input(&args, by) {
                Ok(input) => input,
                Err(result) => return result,
            };
            let (x, y) = (input.x, input.y);
            let direction = input.direction.as_str();
            let step = if precise {
                amount as i32
            } else if by == "page" {
                WHEEL_STEP_PAGE_PX
            } else {
                WHEEL_STEP_LINE_PX
            };
            let (delta_y, delta_x) = match input.direction {
                ScrollDirection::Down => (-step, 0),
                ScrollDirection::Up => (step, 0),
                ScrollDirection::Right => (0, -step),
                ScrollDirection::Left => (0, step),
            };
            let (x, y) = super::desktop_screenshot_point(x, y);
            if let Some(refusal) =
                super::desktop_pointer_guard::check("scroll", &args, vec![(x, y)]).await
            {
                return refusal;
            }
            let result = tokio::task::spawn_blocking(move || {
                if precise {
                    crate::input::mouse::scroll_pixels_desktop(x, y, delta_y, delta_x)
                } else {
                    crate::input::mouse::scroll_wheel_desktop(x, y, delta_y, delta_x, amount)
                }
            })
            .await;
            return match result {
                Ok(Ok(())) => ToolResult::text(format!(
                    "Scrolled desktop {direction} by {by} × {amount} at ({x:.1}, {y:.1})."
                ))
                .with_structured(serde_json::json!({
                    "scope": "desktop",
                    "path": "hid",
                    "effect": "unverifiable"
                })),
                Ok(Err(error)) => ToolResult::error(format!("desktop scroll failed: {error}")),
                Err(error) => ToolResult::error(format!("desktop scroll task failed: {error}")),
            };
        }
        let pid = match super::target_pid(&self.state, &args) {
            Ok(v) => v,
            Err(e) => return e,
        };
        // delivery_mode: foreground briefly fronts the window before the
        // pixel-wheel dispatch (the explicit last resort for surfaces that drop
        // background CGEvents). Only the pixel-wheel path honors it; the
        // keystroke path is background-by-design and untouched.
        let delivery_mode = super::DeliveryMode::parse(args.opt_str("delivery_mode").as_deref());
        // Electron/Chromium drop background wheel events and keystrokes; a
        // background scroll there goes through accessibility instead (below).
        let electron_background =
            !delivery_mode.is_foreground() && crate::browser::ElectronJs::is_electron(pid);
        let direction = match args.require_str("direction") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let by = by.to_owned();
        let window_id_arg = args.opt_u64("window_id");
        let resolved = match self.state.snapshots.resolve(pid, &args) {
            Ok(r) => r,
            Err(e) => return e,
        };
        let (_, window_id, pre_focus_guard) = resolved.into_parts(window_id_arg);
        let window_id = match super::native_window_id(window_id) {
            Ok(window_id) => window_id,
            Err(error) => return error,
        };
        let pre_focus_ptr: Option<usize> = pre_focus_guard.as_ref().map(|g| g.as_ptr());

        let mut _mutation_lease: Option<super::BackgroundMutationLease> = None;

        // AppKit exposes vertical scroll-bar buttons beneath the text area's
        // AXScrollArea parent. Pressing those controls is a true
        // background-safe scroll: no activation, z-order change, or cursor move.
        if !precise && matches!(direction.as_str(), "up" | "down") {
            if let (Some(element_guard), Some(wid)) = (pre_focus_guard.clone(), window_id) {
                if !delivery_mode.is_foreground() {
                    if let Some(lease) = _mutation_lease.as_ref() {
                        if let Err(refusal_result) = lease
                            .gate_again(
                                wid,
                                pre_focus_ptr,
                                cua_driver_core::background_input::BackgroundAction::AxSemantic,
                            )
                            .await
                        {
                            return refusal_result;
                        }
                    } else {
                        match super::gate_background_window_action(
                            pid,
                            wid,
                            pre_focus_ptr,
                            cua_driver_core::background_input::BackgroundAction::AxSemantic,
                        )
                        .await
                        {
                            Ok(lease) => _mutation_lease = Some(lease),
                            Err(refusal_result) => return refusal_result,
                        }
                    }
                }
                let direction_for_ax = direction.clone();
                let by_for_ax = by.clone();
                let foreground = delivery_mode.is_foreground();
                let ax_result =
                    tokio::task::spawn_blocking(move || -> anyhow::Result<(bool, bool)> {
                        if foreground {
                            let mut delivered = false;
                            let fronted = crate::input::skylight::with_foreground_assist(
                                pid as libc::pid_t,
                                wid,
                                || {
                                    delivered = unsafe {
                                        scroll_native_text_area(
                                            element_guard.as_ptr() as AXUIElementRef,
                                            &direction_for_ax,
                                            &by_for_ax,
                                            amount,
                                        )
                                    };
                                    std::thread::sleep(std::time::Duration::from_millis(100));
                                    Ok(())
                                },
                            )?;
                            Ok((delivered, fronted))
                        } else {
                            Ok((
                                unsafe {
                                    scroll_native_text_area(
                                        element_guard.as_ptr() as AXUIElementRef,
                                        &direction_for_ax,
                                        &by_for_ax,
                                        amount,
                                    )
                                },
                                false,
                            ))
                        }
                    })
                    .await;
                match ax_result {
                    Ok(Ok((true, fronted))) => {
                        return ToolResult::text(format!(
                        "✅ Scrolled native macOS control {direction} by {by} × {amount} through AX."
                    ))
                    .with_structured(serde_json::json!({
                        "path": if fronted { "ax_fg" } else { "ax" },
                        "verified": false,
                        "effect": "unverifiable"
                    }));
                    }
                    Ok(Ok((false, _))) => {}
                    Ok(Err(error)) => {
                        return ToolResult::error(format!("Native AX scroll failed: {error}"));
                    }
                    Err(error) => {
                        return ToolResult::error(format!("Native AX scroll task failed: {error}"));
                    }
                }
            }
        }

        // ── Targeted wheel path ─────────────────────────────────────────────
        // A target — element (preferred) OR window-local x,y — routes the scroll
        // through a synthesized mouse-wheel event at that screen point, so the
        // renderer's hit-test delivers it to whatever element is under the
        // cursor. This is the ONLY way to scroll a nested overflow:auto region
        // that never takes keyboard focus (the keystroke path below no-ops on
        // it). No user-facing flag: presence of a target IS the switch.
        let x_arg = args
            .opt_f64("x")
            .or_else(|| args.opt_i64("x").map(|v| v as f64));
        let y_arg = args
            .opt_f64("y")
            .or_else(|| args.opt_i64("y").map(|v| v as f64));

        // Per-notch step + direction→delta mapping (sign convention lives
        // here; the mouse primitive stays sign-agnostic). macOS: +y reveals
        // content ABOVE, -y reveals BELOW; +x reveals LEFT, -x reveals RIGHT.
        let step = if precise {
            amount as i32
        } else if by == "page" {
            WHEEL_STEP_PAGE_PX
        } else {
            WHEEL_STEP_LINE_PX
        };
        let (delta_y, delta_x): (i32, i32) = match direction.as_str() {
            "down" => (-step, 0),
            "up" => (step, 0),
            "right" => (0, -step),
            "left" => (0, step),
            _ => (-step, 0),
        };

        // Resolve a screen-space wheel target, if a target was supplied.
        let wheel_target: Option<WheelTarget> = if let Some(element_ptr) = pre_focus_ptr {
            // Revealing an element is itself an AX mutation. Prove that the
            // cached element still belongs to the exact requested window before
            // AXScrollToVisible for every direction, then keep the lease for the
            // stricter pointer revalidation below.
            let semantic_gate = if !delivery_mode.is_foreground() {
                if let Some(wid) = window_id {
                    if let Some(lease) = _mutation_lease.as_ref() {
                        lease
                            .gate_again(
                                wid,
                                Some(element_ptr),
                                cua_driver_core::background_input::BackgroundAction::AxSemantic,
                            )
                            .await
                    } else {
                        match super::gate_background_window_action(
                            pid,
                            wid,
                            Some(element_ptr),
                            cua_driver_core::background_input::BackgroundAction::AxSemantic,
                        )
                        .await
                        {
                            Ok(lease) => {
                                _mutation_lease = Some(lease);
                                Ok(())
                            }
                            Err(refusal) => Err(refusal),
                        }
                    }
                } else {
                    Ok(())
                }
            } else {
                Ok(())
            };
            // Element path: wheel at the element's screen-space center. Both AX
            // coordinates and window bounds are logical top-left points, so no
            // Retina scaling is needed here.
            let wid = window_id;
            let target_guard = pre_focus_guard.clone();
            let target_task = tokio::task::spawn_blocking(move || {
                let _target_guard = target_guard;
                // Web content can be present in AX while its frame is below
                // the outer page viewport. Ask the accessibility hierarchy to
                // reveal the target before taking the screen-space center;
                // otherwise the wheel is posted outside the rendered window
                // and nested overflow regions never receive it.
                semantic_gate?;
                unsafe {
                    crate::ax::bindings::perform_action(
                        element_ptr as AXUIElementRef,
                        "AXScrollToVisible",
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(40));
                let center = unsafe { element_screen_center(element_ptr as AXUIElementRef) };
                let rect = unsafe {
                    crate::ax::bindings::element_screen_rect(element_ptr as AXUIElementRef)
                };
                Ok(center.map(|(cx, cy)| {
                    let win_local = wid
                        .and_then(crate::windows::window_bounds_by_id)
                        .map(|b| (cx - b.x, cy - b.y));
                    WheelTarget {
                        screen_x: cx,
                        screen_y: cy,
                        win_local,
                        wid,
                        rect,
                    }
                }))
            });
            match target_task.await {
                Ok(Ok(target)) => target,
                Ok(Err(refusal)) => return refusal,
                Err(_) => None,
            }
        } else if let (Some(mut cx), Some(mut cy)) = (x_arg, y_arg) {
            // Targeted x,y are window-local screenshot pixels and REQUIRE a
            // window_id to anchor the window→screen conversion (schema contract).
            // Without one, refuse rather than scrolling at screen-absolute coords.
            if window_id.is_none() {
                return ToolResult::error(
                    "window_id is required when scrolling by window-local x,y pixels.".to_string(),
                );
            }
            // Pixel path: x,y are window-local screenshot pixels. Mirror the
            // click pixel path — undo any session downscale, then translate
            // through the shared window frame (which refuses a window with no
            // live frame rather than scrolling at screen-absolute coords).
            let ratio = match super::screenshot_scale(&self.state, &args, pid, window_id) {
                Ok(ratio) => ratio,
                Err(refusal) => return refusal,
            };
            cx *= ratio;
            cy *= ratio;
            let Some(wid) = window_id else {
                // Unreachable: the None case refused above. Kept explicit so a
                // future edit cannot reintroduce the screen-absolute fallback.
                return ToolResult::error(
                    "window_id is required when scrolling by window-local x,y pixels.".to_string(),
                );
            };
            match super::px_frame::resolve_or_refuse(wid).await {
                Ok(frame) => {
                    let (sx, sy, lx, ly) = frame.to_screen(cx, cy);
                    Some(WheelTarget {
                        screen_x: sx,
                        screen_y: sy,
                        win_local: Some((lx, ly)),
                        wid: Some(wid),
                        rect: None,
                    })
                }
                Err(refusal) => return refusal,
            }
        } else {
            None
        };

        if electron_background && !precise {
            return electron_reveal_scroll(
                pid,
                window_id,
                wheel_target
                    .as_ref()
                    .map(|target| (target.screen_x, target.screen_y)),
                &direction,
                (step.unsigned_abs() as usize * amount) as f64,
                pre_focus_ptr,
                &mut _mutation_lease,
            )
            .await;
        }

        if let Some(target) = wheel_target {
            if !delivery_mode.is_foreground() {
                if let Some(wid) = target.wid {
                    if let (Some((lx, ly)), Some(bounds)) =
                        (target.win_local, crate::windows::window_bounds_by_id(wid))
                    {
                        if lx < 0.0 || ly < 0.0 || lx > bounds.width || ly > bounds.height {
                            return ToolResult::error(format!(
                                "scroll: window-local point ({lx:.1}, {ly:.1}) pt lies outside \
                                 window {wid}'s {:.0}×{:.0} pt frame; background delivery \
                                 refused",
                                bounds.width, bounds.height
                            ));
                        }
                    }
                    // The semantic reveal gate does not authorize pointer
                    // delivery. Revalidate the stricter route immediately
                    // before proceeding to wheel dispatch.
                    if let Some(lease) = _mutation_lease.as_ref() {
                        if let Err(refusal_result) = lease
                            .gate_again(
                                wid,
                                pre_focus_ptr,
                                cua_driver_core::background_input::BackgroundAction::WindowPointer,
                            )
                            .await
                        {
                            return refusal_result;
                        }
                    } else {
                        match super::gate_background_window_action(
                            pid,
                            wid,
                            pre_focus_ptr,
                            cua_driver_core::background_input::BackgroundAction::WindowPointer,
                        )
                        .await
                        {
                            Ok(lease) => _mutation_lease = Some(lease),
                            Err(refusal_result) => return refusal_result,
                        }
                    }
                }
            }
            let cursor_key = super::cursor_tools::resolve_cursor_key(&args);
            // Pin + glide the agent-cursor overlay to the target for visibility
            // (overlay only — does NOT move the hardware cursor). Mirrors click.
            if let Some(wid) = target.wid {
                crate::cursor::overlay::send_command(
                    cursor_key.clone(),
                    cursor_overlay::OverlayCommand::PinAbove(wid as u64),
                );
            }
            crate::cursor::overlay::animate_cursor_to_target(
                cursor_key.clone(),
                target.screen_x,
                target.screen_y,
                target.rect,
            )
            .await;
            self.state.cursor_registry.update_position(
                &cursor_key,
                target.screen_x,
                target.screen_y,
            );

            let prior_front = apps::frontmost_pid();
            let snapshot = WindowChangeDetector::snapshot(prior_front);

            let WheelTarget {
                screen_x,
                screen_y,
                win_local,
                wid,
                ..
            } = target;
            let amount_ticks = amount;
            let fg = delivery_mode.is_foreground() && wid.is_some();
            let result = focus_guard::with_focus_suppressed(
                Some(pid),
                prior_front,
                "scroll.CGScrollWheel",
                || async move {
                    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
                        let do_it = move || -> anyhow::Result<()> {
                            if precise {
                                crate::input::mouse::scroll_pixels_at_xy(
                                    pid, screen_x, screen_y, win_local, wid, delta_y, delta_x,
                                )
                            } else {
                                crate::input::mouse::scroll_wheel_at_xy(
                                    pid,
                                    screen_x,
                                    screen_y,
                                    win_local,
                                    wid,
                                    delta_y,
                                    delta_x,
                                    amount_ticks,
                                )
                            }
                        };
                        // Foreground rung: brief front → wheel → restore prior frontmost.
                        match (fg, wid) {
                            (true, Some(w)) => {
                                crate::input::skylight::with_foreground_assist(
                                    pid as libc::pid_t,
                                    w,
                                    do_it,
                                )?;
                                Ok(())
                            }
                            _ => do_it(),
                        }
                    })
                    .await
                },
            )
            .await;

            let changes = super::finish_window_observation(snapshot).await;
            let mode_label = if fg {
                " (delivery_mode:foreground)"
            } else {
                ""
            };
            return match result {
                Ok(Ok(())) => ToolResult::text(format!(
                    "✅ Sent {direction} scroll by {by} × {amount} via pixel wheel at \
                     ({screen_x:.0}, {screen_y:.0}){mode_label} (background CGEvent; not \
                     driver-verified — confirm via screenshot).{}",
                    changes.result_suffix()
                ))
                .with_structured(serde_json::json!({
                    "path": if fg { "cgevent_fg" } else { "cgevent" }, "verified": false, "effect": "unverifiable"
                })),
                Ok(Err(e)) => ToolResult::error(format!("Wheel scroll failed: {e}")),
                Err(e)     => ToolResult::error(format!("Task error: {e}")),
            };
        }

        if precise {
            return ToolResult::error(
                "pixel scroll requires an exact window point or retained element",
            );
        }
        let key = match (by.as_str(), direction.as_str()) {
            ("page", "down") | (_, "down") if by == "page" => "pagedown",
            ("page", "up") | (_, "up") if by == "page" => "pageup",
            ("line", "down") | (_, "down") => "down",
            ("line", "up") | (_, "up") => "up",
            (_, "left") => "left",
            (_, "right") => "right",
            _ => "down",
        };
        let key = key.to_owned();

        if !delivery_mode.is_foreground() {
            if let Some(wid) = window_id {
                if let Some(lease) = _mutation_lease.as_ref() {
                    if let Err(refusal_result) = lease
                        .gate_again(
                            wid,
                            pre_focus_ptr,
                            cua_driver_core::background_input::BackgroundAction::GenericKey,
                        )
                        .await
                    {
                        return refusal_result;
                    }
                } else {
                    match super::gate_background_window_action(
                        pid,
                        wid,
                        pre_focus_ptr,
                        cua_driver_core::background_input::BackgroundAction::GenericKey,
                    )
                    .await
                    {
                        Ok(lease) => _mutation_lease = Some(lease),
                        Err(refusal_result) => return refusal_result,
                    }
                }
            }
        }

        // ── Focus-suppression wrap (Swift WindowChangeDetector + FocusGuard) ──
        // Scroll keystrokes (PageDown / arrow) into search-box autocomplete
        // can spawn floating helper windows; rare but real. Wrap for parity
        // with the other action tools.
        //
        // The AX focus_element() pre-write also runs inside the closure so
        // any reflex activations it triggers are caught by both the wildcard
        // snapshot suppressor and the targeted FocusGuard lease.
        let prior_front = apps::frontmost_pid();
        let snapshot = WindowChangeDetector::snapshot(prior_front);

        let result = focus_guard::with_focus_suppressed(
            Some(pid),
            prior_front,
            "scroll.CGEvent",
            || async move {
                // Pre-focus the element under suppression so its
                // side-effects are captured by the snapshot + lease.
                if let Some(guard) = pre_focus_guard {
                    let _ = tokio::task::spawn_blocking(move || {
                        crate::input::ax_actions::focus_element(guard.as_ptr())
                    })
                    .await;
                    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
                }

                tokio::task::spawn_blocking(move || {
                    for _ in 0..amount {
                        crate::input::keyboard::press_key(pid, &key, &[])?;
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                    Ok::<(), anyhow::Error>(())
                })
                .await
            },
        )
        .await;

        let changes = super::finish_window_observation(snapshot).await;

        match result {
            Ok(Ok(())) => ToolResult::text(format!(
                "✅ Sent {direction} scroll by {by} × {amount} via keystroke \
                 (background; not driver-verified — confirm via screenshot).{}",
                changes.result_suffix()
            ))
            .with_structured(serde_json::json!({ "path": "key_events", "verified": false })),
            Ok(Err(e)) => ToolResult::error(format!("Scroll failed: {e}")),
            Err(e) => ToolResult::error(format!("Task error: {e}")),
        }
    }
}

/// Background scroll for Electron/Chromium windows, which drop background
/// wheel events: reveal the content just past the edge of the scroll
/// container under `point` (the window's center when there is no target)
/// through accessibility. Refuses as before when no container moves.
async fn electron_reveal_scroll(
    pid: i32,
    window_id: Option<u32>,
    point: Option<(f64, f64)>,
    direction: &str,
    distance: f64,
    pre_focus_ptr: Option<usize>,
    lease: &mut Option<super::BackgroundMutationLease>,
) -> ToolResult {
    let unavailable = || {
        cua_driver_core::delivery::background_unavailable_result(
            ELECTRON_BACKGROUND_SCROLL_UNAVAILABLE,
            "background_unavailable",
            "Electron/Chromium windows drop background wheel events and keystrokes on macOS",
            serde_json::json!({ "effect": "refused" }),
        )
    };
    let window = window_id.and_then(crate::windows::window_bounds_by_id);
    let Some(point) = point.or_else(|| {
        window
            .as_ref()
            .map(|b| (b.x + b.width / 2.0, b.y + b.height / 2.0))
    }) else {
        return unavailable();
    };
    if let Some(wid) = window_id {
        let gate = match lease.as_ref() {
            Some(lease) => {
                lease
                    .gate_again(
                        wid,
                        pre_focus_ptr,
                        cua_driver_core::background_input::BackgroundAction::AxSemantic,
                    )
                    .await
            }
            None => super::gate_background_window_action(
                pid,
                wid,
                pre_focus_ptr,
                cua_driver_core::background_input::BackgroundAction::AxSemantic,
            )
            .await
            .map(|granted| *lease = Some(granted)),
        };
        if let Err(refusal) = gate {
            return refusal;
        }
    }
    let window_rect = window.map(|b| [b.x, b.y, b.width, b.height]);
    let direction_owned = direction.to_owned();
    let outcome = tokio::task::spawn_blocking(move || unsafe {
        crate::ax::reveal_scroll::reveal_scroll(pid, point, window_rect, &direction_owned, distance)
    })
    .await;
    match outcome {
        Ok(Some(outcome)) => ToolResult::text(format!(
            "✅ Scrolled {direction} about {:.0} pt in the background through accessibility \
             (revealed the content just past the {}'s edge; this Electron/Chromium window drops \
             background wheel events).",
            outcome.moved, outcome.container_role
        ))
        .with_structured(serde_json::json!({
            "path": "ax",
            "verified": false,
            "effect": "unverifiable",
        })),
        _ => unavailable(),
    }
}

unsafe fn scroll_native_text_area(
    element: AXUIElementRef,
    direction: &str,
    by: &str,
    amount: usize,
) -> bool {
    if copy_string_attr(element, "AXRole").as_deref() != Some("AXTextArea") {
        return false;
    }
    let Some(scroll_area) = copy_element_attr(element, "AXParent") else {
        return false;
    };
    if copy_string_attr(scroll_area, "AXRole").as_deref() != Some("AXScrollArea") {
        CFRelease(scroll_area as CFTypeRef);
        return false;
    }
    let mut buttons = Vec::new();
    collect_ax_buttons(scroll_area, 0, &mut buttons);
    CFRelease(scroll_area as CFTypeRef);
    if buttons.is_empty() {
        return false;
    }

    let reverse = direction == "up";
    let base = if by == "page" && buttons.len() >= 4 {
        2
    } else {
        0
    };
    let index = base + usize::from(reverse);
    let mut delivered = false;
    if let Some(target) = buttons.get(index).copied() {
        for _ in 0..amount.max(1) {
            if perform_action(target, "AXPress") != kAXErrorSuccess {
                break;
            }
            delivered = true;
            std::thread::sleep(std::time::Duration::from_millis(30));
        }
    }
    for button in buttons {
        CFRelease(button as CFTypeRef);
    }
    delivered
}

unsafe fn collect_ax_buttons(
    element: AXUIElementRef,
    depth: usize,
    buttons: &mut Vec<AXUIElementRef>,
) {
    if depth >= 4 || buttons.len() >= 4 {
        return;
    }
    for child in copy_children(element) {
        if buttons.len() >= 4 {
            CFRelease(child as CFTypeRef);
        } else if copy_string_attr(child, "AXRole").as_deref() == Some("AXButton") {
            buttons.push(child);
        } else {
            collect_ax_buttons(child, depth + 1, buttons);
            CFRelease(child as CFTypeRef);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_pages_require_the_exact_recorded_target_amount_and_pixel_frame() {
        use crate::input::page_scroll::{
            NativePageScrollRequest, PageDirection, PageScrollRequest,
        };
        use core_graphics::geometry::{CGPoint, CGRect, CGSize};

        let request = NativePageScrollRequest {
            event: PageScrollRequest {
                pid: 123,
                window_id: 456,
                screen_point: CGPoint::new(-1.25, 42.5),
                window_bounds: CGRect::new(&CGPoint::new(-20.0, 30.0), &CGSize::new(0.0, 0.0)),
                window_uses_flipped_coordinates: true,
                direction: PageDirection::Left,
                pages: 51.25,
                extent: 100.25,
            },
            native_window_pixels: [37.5, 25.0],
        };
        let args = serde_json::json!({
            "pid":123,"window_id":456,"scope":"window",
            "delivery_mode":"background","direction":"left","by":"page",
            "amount":51.25,"x":37.5,"y":25.0,
        });
        native_page_arguments_match(&args, &request).unwrap();
        assert!(scroll_parameters(&args).is_err());
        for (field, value) in [
            ("pid", serde_json::json!(124)),
            ("window_id", serde_json::json!(457)),
            ("direction", serde_json::json!("right")),
            ("amount", serde_json::json!(51)),
            ("x", serde_json::json!(-1.25)),
            ("y", serde_json::json!(42.5)),
        ] {
            let mut wrong = args.clone();
            wrong[field] = value;
            assert_eq!(
                native_page_arguments_match(&wrong, &request)
                    .unwrap_err()
                    .structured_content
                    .unwrap()["code"],
                "native_page_request_mismatch"
            );
        }
        let provenance = native_page_provenance(&request);
        assert_eq!(
            provenance["native_window_pixels"],
            serde_json::json!([37.5, 25.0])
        );
        assert_eq!(provenance["screen_point"], serde_json::json!([-1.25, 42.5]));
        assert_eq!(
            provenance["native_window_pixels_unit"],
            "window_local_physical_pixels"
        );
        assert_eq!(provenance["screen_point_unit"], "global_logical_points");
        assert_eq!(provenance["window_bounds"]["width"], 0.0);
        assert_eq!(provenance["window_uses_flipped_coordinates"], true);

        // This is the actual post-success producer, without creating or
        // posting a native event. Its legacy payload must survive the core's
        // existing execution-record and public-result projection.
        use cua_driver_core::action_record::{
            ActionEffect, ActionExecutionRecord, ActionTransport, ActualDelivery, RequestedDelivery,
        };
        let produced = native_page_posted_result(&request);
        assert_ne!(produced.is_error, Some(true));
        let structured = produced.structured_content.as_ref().unwrap();
        assert_eq!(structured["path"], "cgevent");
        assert_eq!(structured["native_profile"], "native_pages");
        assert_eq!(structured["native_page_request"], provenance);
        let record = ActionExecutionRecord::from_legacy("scroll", &args, structured)
            .expect("the native posted result must identify its existing CGEvent transport");
        assert_eq!(record.transport, ActionTransport::MacosCgEventPid);
        assert_eq!(record.requested_delivery, RequestedDelivery::Background);
        assert_eq!(record.actual_delivery, Some(ActualDelivery::Background));
        assert_eq!(record.effect, ActionEffect::Unverifiable);
        let public = record.public_result().unwrap();
        public.validate_invariants().unwrap();
        assert_eq!(
            public.effect,
            cua_driver_contract::ActionEffect::Unverifiable
        );
        assert_eq!(
            public.route,
            cua_driver_contract::ActionRoute::SyntheticEvents
        );
        assert_eq!(
            public.delivery.unwrap().mode,
            cua_driver_contract::ActionDeliveryMode::Background
        );
        assert!(public.evidence.is_none());
        assert!(public.error.is_none());
    }

    #[test]
    fn amount_limits_preserve_pixel_deltas_and_refuse_invalid_repetitions() {
        assert_eq!(scroll_amount("pixel", 1100), Ok(1100));
        assert_eq!(scroll_amount("pixel", 20000), Ok(20000));
        assert_eq!(
            scroll_amount("pixel", 20001).unwrap_err(),
            "pixel scroll amount out of range"
        );
        assert_eq!(scroll_amount("line", 50), Ok(50));
        for (by, amount) in [("page", 51), ("line", 0)] {
            assert_eq!(
                scroll_amount(by, amount).unwrap_err(),
                "amount must be between 1 and 50 for line/page scrolling"
            );
        }
        assert_eq!(
            scroll_amount("unknown", 3).unwrap_err(),
            "unsupported scroll granularity"
        );
    }

    #[test]
    fn desktop_native_pixels_keep_their_own_amount_and_validate_coordinates() {
        let request = serde_json::json!({
            "scope":"desktop", "x":12.5, "y":34.0,
            "direction":"down", "by":"pixel", "amount":1100,
        });
        let (by, amount) = scroll_parameters(&request).unwrap();
        assert_eq!((by, amount), ("pixel", 1100));
        let input = desktop_scroll_input(&request, by).unwrap();
        assert_eq!((input.x, input.y), (12.5, 34.0));
        assert_eq!(input.direction, ScrollDirection::Down);

        let mut malformed = request.clone();
        malformed["x"] = serde_json::json!("12.5");
        assert_eq!(
            desktop_scroll_input(&malformed, by)
                .unwrap_err()
                .structured_content
                .unwrap()["code"],
            "invalid_arguments"
        );
        for amount in [serde_json::json!(0), serde_json::json!(1.5), Value::Null] {
            malformed = request.clone();
            malformed["amount"] = amount;
            assert_eq!(
                scroll_parameters(&malformed).unwrap_err().is_error,
                Some(true)
            );
        }
    }
}
