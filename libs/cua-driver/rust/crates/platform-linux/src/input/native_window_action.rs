// SPDX-License-Identifier: MIT
//! Typed original window actions over the existing native target lifetime.

use cua_driver_contract::{ClickButton, ScrollDirection};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeWindowAction {
    Move {
        point: [i16; 2],
        key: Option<String>,
    },
    Click {
        point: [i16; 2],
        button: ClickButton,
        count: u32,
        duration_ms: u64,
        key: Option<String>,
    },
    Scroll {
        x: Option<i16>,
        y: Option<i16>,
        direction: ScrollDirection,
        pixels: u16,
        key: Option<String>,
    },
    PressKey {
        key: String,
        duration_ms: u64,
    },
    Drag {
        path: Vec<[i16; 2]>,
        key: Option<String>,
    },
    TypeText {
        text: String,
    },
    TypeTextElement {
        text: String,
        element_id: String,
    },
    SecondaryAction {
        element_id: String,
        action: String,
    },
    ScrollElement {
        element_id: String,
        direction: ScrollDirection,
        pixels: u16,
        key: Option<String>,
    },
}

/// Data only; canonical Core admission still checks the actual selected target.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWindowActionRequest {
    pub pid: u32,
    pub window_id: u32,
    pub action: NativeWindowAction,
}

impl NativeWindowActionRequest {
    pub fn tool_name(&self) -> &'static str {
        if matches!(self.action, NativeWindowAction::TypeText { .. } | NativeWindowAction::TypeTextElement { .. }) {
            "native_paste_text"
        } else {
            "native_desktop_input"
        }
    }

    pub fn arguments(&self) -> Value {
        let mut arguments = match &self.action {
            NativeWindowAction::TypeTextElement { text, .. } => {
                // The native identity remains opaque Rust sidecar data. Core
                // still admits the same text/actual window/clipboard operation.
                serde_json::json!({"operation":"type_text", "text":text})
            }
            NativeWindowAction::ScrollElement { direction, pixels, key, .. } => {
                serde_json::json!({"operation":"scroll","x":null,"y":null,"direction":direction,"pixels":pixels,"key":key})
            }
            NativeWindowAction::SecondaryAction { action, .. } => {
                serde_json::json!({"operation":"secondary_action", "action":action})
            }
            action => serde_json::to_value(action).expect("typed native window action is serializable"),
        };
        arguments["pid"] = self.pid.into();
        arguments["window_id"] = self.window_id.into();
        arguments["scope"] = "window".into();
        arguments["delivery_mode"] = "background".into();
        arguments
    }

    pub fn recording_input(&self) -> Value {
        let mut input = self.arguments();
        if let Some(input) = input.as_object_mut() {
            if let Some(key) = input.remove("key") {
                input.insert("has_key".into(), (!key.is_null()).into());
            }
            if input.contains_key("text") {
                input.insert("text".into(), "[redacted]".into());
            }
        }
        if matches!(self.action, NativeWindowAction::TypeTextElement { .. } | NativeWindowAction::SecondaryAction { .. } | NativeWindowAction::ScrollElement { .. }) {
            input["has_element"] = true.into();
        }
        if let NativeWindowAction::SecondaryAction { .. } = &self.action {
            input["action"] = "[redacted]".into();
        }
        input
    }
}

/// Execute on the already prepared actual target. Clipboard ownership and its
/// authority stay with the caller's existing shared transaction.
pub(crate) fn execute(
    action: &NativeWindowAction,
    conn: &x11rb::rust_connection::RustConnection,
    context: &super::native_window::NativeWindowContext,
    paste: impl FnOnce(&str) -> anyhow::Result<()>,
    secondary: impl FnOnce() -> anyhow::Result<()>,
    element_scroll: impl FnOnce() -> anyhow::Result<[i16; 2]>,
) -> anyhow::Result<()> {
    use NativeWindowAction::*;
    match action {
        Move { point, key } => {
            let root = context.local_to_root(conn, *point)?;
            context.key_chord(conn, key.as_deref(), || {
                context.owned_move_to_root(conn, root, false)
            })
        }
        PressKey { key, duration_ms } => {
            if super::native_keys::symbols(Some(key))?.is_empty() {
                anyhow::bail!("key must be a non-empty string");
            }
            context.key_chord(conn, Some(key), || {
                context.pause(std::time::Duration::from_millis(
                    duration_ms.saturating_sub(33),
                ))
            })
        }
        Click {
            point,
            button,
            count,
            duration_ms,
            key,
        } => {
            // Even count0 moves before any pair's modifier/key resolution.
            let root = context.local_to_root(conn, *point)?;
            context.owned_move_to_root(conn, root, false)?;
            let button = match button {
                ClickButton::Left => 1,
                ClickButton::Middle => 2,
                ClickButton::Right => 3,
            };
            for _ in 0..*count {
                context.key_chord(conn, key.as_deref(), || {
                    context.owned_move_to_root(conn, root, false)?;
                    let pressed = context.button_edge_owned(conn, button, true);
                    let down_ack = pressed.is_ok();
                    let action = pressed.and_then(|()| {
                        context.pause(std::time::Duration::from_millis(*duration_ms))
                    });
                    // The actual held pair remains releasable after Stop/error.
                    let released = context.button_edge_owned(conn, button, false);
                    if down_ack && released.is_ok() {
                        context.mark_completed();
                    }
                    action.and(released)
                })?;
            }
            Ok(())
        }
        Scroll { x, y, direction, pixels, key } => {
            // Source coordinates/center translate before the zero/incomplete
            // point checks; an element's position is already root coordinates.
            let root = match (x, y) {
                (Some(x), Some(y)) => Some(context.local_to_root(conn, [*x, *y])?),
                (None, None) => Some(context.local_to_root(conn, context.client_center(conn)?)?),
                _ => None,
            };
            scroll_root(conn, context, root, direction, *pixels, key.as_deref())
        }
        ScrollElement { direction, pixels, key, .. } => {
            let root = element_scroll()?;
            scroll_root(conn, context, Some(root), direction, *pixels, key.as_deref())
        }
        Drag { path, key } => {
            // The window branch translates every supplied point once before
            // its path-length check, then interpolates the fixed root pixels.
            let path = path
                .iter()
                .copied()
                .map(|point| context.local_to_root(conn, point))
                .collect::<anyhow::Result<Vec<_>>>()?;
            if path.len() < 2 {
                anyhow::bail!("drag path must contain at least two points");
            }
            context.owned_move_to_root(conn, path[0], false)?;
            context.key_chord(conn, key.as_deref(), || {
                context.owned_move_to_root(conn, path[0], false)?;
                let pressed = context.button_edge_owned(conn, 1, true);
                let down_ack = pressed.is_ok();
                let action = pressed.and_then(|()| {
                    for segment in path.windows(2) {
                        for point in super::interactive::native_drag_points(segment[0], segment[1])
                        {
                            context.check()?;
                            // The same context retains the actual pressed child;
                            // its held move only translates and sends Motion.
                            context.owned_move_to_root(conn, point, false)?;
                            context.pause(std::time::Duration::from_millis(1))?;
                        }
                    }
                    Ok(())
                });
                let released = context.button_edge_owned(conn, 1, false);
                if down_ack && released.is_ok() {
                    context.mark_completed();
                }
                action.and(released)
            })
        }
        TypeText { text } | TypeTextElement { text, .. } => paste(text),
        SecondaryAction { .. } => secondary(),
    }
}

fn scroll_root(
    conn: &x11rb::rust_connection::RustConnection,
    context: &super::native_window::NativeWindowContext,
    root: Option<[i16; 2]>,
    direction: &ScrollDirection,
    pixels: u16,
    key: Option<&str>,
) -> anyhow::Result<()> {
    if pixels == 0 {
        anyhow::bail!("pixels must be non-zero");
    }
    let root = root.ok_or_else(|| anyhow::anyhow!("x and y must be provided together"))?;
    // Source validates symbols before its initial move, then presses the chord.
    super::native_keys::symbols(key)?;
    context.owned_move_to_root(conn, root, true)?;
    let button = super::scroll_button(direction.as_str())?;
    context.key_chord(conn, key, || {
        for _ in 0..super::native_window::scroll_detents(pixels) {
            context.check()?;
            let pressed = context.button_edge_owned(conn, button, true);
            let down_ack = pressed.is_ok();
            let action = pressed.and_then(|()| context.pause(std::time::Duration::from_millis(36)));
            let released = context.button_edge_owned(conn, button, false);
            if down_ack && released.is_ok() {
                context.mark_completed();
            }
            action.and(released)?;
        }
        Ok(())
    })
}
