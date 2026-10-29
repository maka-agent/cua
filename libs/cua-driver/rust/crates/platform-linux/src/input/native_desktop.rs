// SPDX-License-Identifier: MIT
//! Trusted native desktop requests over the existing Cua interactive engine.

use super::interactive::InteractiveInputSession;
use cua_driver_core::action_record::{
    ActionEffect, ActionExecutionRecord, ActionTransport, ActualDelivery, RequestedDelivery,
};
use cua_driver_core::protocol::ToolResult;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeDesktopRequest {
    Window {
        request: super::native_window_action::NativeWindowActionRequest,
    },
    TypeText {
        text: String,
    },
    Scroll {
        point: Option<[i16; 2]>,
        direction: cua_driver_contract::ScrollDirection,
        pixels: u16,
        key: Option<String>,
    },
    Drag {
        path: Vec<[i16; 2]>,
        key: Option<String>,
    },
    PressKey {
        key: String,
        duration_ms: u64,
    },
    Click {
        point: [i16; 2],
        button: cua_driver_contract::ClickButton,
        count: u32,
        duration_ms: u64,
        key: Option<String>,
    },
    Move {
        point: [i16; 2],
        key: Option<String>,
    },
    MoveRelative {
        delta: [i16; 2],
        key: Option<String>,
    },
    DragStart {
        handle: String,
        point: [i16; 2],
    },
    DragMove {
        handle: String,
        point: [i16; 2],
    },
    DragEnd {
        handle: String,
    },
}

impl NativeDesktopRequest {
    pub fn tool_name(&self) -> &'static str {
        match self {
            Self::Window { request } => request.tool_name(),
            Self::TypeText { .. } => "native_paste_text",
            _ => "native_desktop_input",
        }
    }

    pub fn arguments(&self) -> Value {
        if let Self::Window { request } = self {
            return request.arguments();
        }
        let mut value =
            serde_json::to_value(self).expect("typed native desktop request is serializable");
        value["scope"] = "desktop".into();
        value
    }

    pub fn recording_input(&self) -> Value {
        // The ordinary invocation owns its full request. This unreplayable
        // native diagnostic keeps no chord text or caller-chosen handle value.
        match self {
            Self::Window { request } => request.recording_input(),
            Self::TypeText { .. } => {
                json!({"operation":"type_text","text":"[redacted]","clipboard":"temporary_utf8"})
            }
            Self::Scroll {
                point,
                direction,
                pixels,
                key,
            } => {
                json!({"operation":"scroll","point":point,"direction":direction,"pixels":pixels,"has_key":key.is_some()})
            }
            Self::Drag { path, key } => {
                json!({"operation":"drag","path":path,"has_key":key.is_some()})
            }
            Self::PressKey { duration_ms, .. } => {
                json!({"operation":"press_key","duration_ms":duration_ms})
            }
            Self::Click {
                point,
                button,
                count,
                duration_ms,
                key,
            } => {
                json!({"operation":"click","point":point,"button":button,"count":count,"duration_ms":duration_ms,"has_key":key.is_some()})
            }
            Self::Move { point, key } => {
                json!({"operation":"move","point":point,"has_key":key.is_some()})
            }
            Self::MoveRelative { delta, key } => {
                json!({"operation":"move_relative","delta":delta,"has_key":key.is_some()})
            }
            Self::DragStart { point, .. } => json!({"operation":"drag_start","point":point}),
            Self::DragMove { point, .. } => json!({"operation":"drag_move","point":point}),
            Self::DragEnd { .. } => json!({"operation":"drag_end"}),
        }
    }
}

struct Handle {
    engine: InteractiveInputSession,
    started: bool,
}

struct PasteAttempt {
    result: Result<(), String>,
    mutation_attempted: bool,
}

struct ClipboardRestore {
    backend: Arc<crate::clipboard::LinuxClipboard>,
    bytes: Vec<u8>,
}
impl ClipboardRestore {
    fn restore(&self) -> Result<(), String> {
        // Cleanup may only reuse the exact already-created context and bytes.
        let clipboard = self.backend.retained_native_x11()?;
        let result = clipboard.write_utf8(self.bytes.clone());
        std::thread::sleep(Duration::from_millis(50));
        result
    }
}

#[derive(Default)]
struct State {
    closed: bool,
    pointer: Option<InteractiveInputSession>,
    handles: HashMap<String, Handle>,
    clipboard_restore: Option<ClipboardRestore>,
    window: Option<super::native_window::NativeWindowLifetime>,
}

/// One passive object per SDK binding/native epoch. Construction opens no OS
/// resource. Only an actual Core-admitted tool may execute a request.
#[derive(Default)]
pub struct NativeDesktop {
    closed: AtomicBool,
    state: Mutex<State>,
    pause_lock: Mutex<()>,
    pause_changed: Condvar,
}

// An abandoned observer can stop producers, but cannot release/drop the
// worker's Core lease or transfer its actual resource custody to a new call.
struct SealIfObservationDropped(Option<Arc<NativeDesktop>>);
impl Drop for SealIfObservationDropped {
    fn drop(&mut self) {
        if let Some(owner) = &self.0 {
            owner.seal();
        }
    }
}

fn refused(message: &str) -> ToolResult {
    ToolResult::error(message).with_structured(json!({
        "code":"native_desktop_refused", "effect":"refused", "input_attempted":false,
    }))
}

fn unknown(error: impl std::fmt::Display) -> ToolResult {
    ToolResult::error(error.to_string()).with_structured(json!({
        "code":"input_outcome_unknown", "effect":"unverifiable",
        "path":"XTest", "detail":"native desktop input or release ACK is unconfirmed",
    }))
}

fn acknowledged() -> ToolResult {
    let result = ToolResult::text("Native desktop input acknowledged by the X11 server.")
        .with_structured(json!({"effect":"unverifiable","path":"XTest","server_ack":true}));
    match ActionExecutionRecord::builder(
        ActionEffect::Unverifiable,
        ActionTransport::LinuxXTest,
        RequestedDelivery::Foreground,
    )
    .actual_delivery(ActualDelivery::Foreground)
    .build()
    {
        Ok(record) => result.with_action_record(record),
        Err(error) => unknown(format!("native desktop receipt failed: {error:?}")),
    }
}

fn window_acknowledged(completed: u32) -> ToolResult {
    ToolResult::text("Native window input acknowledged by the X11 server.")
        .with_structured(json!({"effect":"unverifiable","path":"x11_xsendevent","server_ack":true,"button_pairs":completed}))
        .with_action_record(ActionExecutionRecord::builder(ActionEffect::Unverifiable,ActionTransport::LinuxXSendEvent,RequestedDelivery::Background)
            .actual_delivery(ActualDelivery::Background).delivered_count(completed).build().expect("native window ACK carries its actual button-pair count"))
}
fn window_unknown(message: String, completed: u32) -> ToolResult {
    ToolResult::error(message).with_structured(json!({"code":"input_outcome_unknown","effect":"unverifiable","path":"x11_xsendevent","completed_button_pairs":completed}))
        .with_action_record(ActionExecutionRecord::builder(ActionEffect::Unverifiable,ActionTransport::LinuxXSendEvent,RequestedDelivery::Background)
            .actual_delivery(ActualDelivery::Background).delivered_count(completed).build().expect("unknown native window input keeps actual acknowledged pairs"))
}

fn accessibility_result(error: Option<String>) -> ToolResult {
    let (result, delivery) = match error {
        None => (
            ToolResult::text("Native accessibility action acknowledged by its target.")
                .with_structured(json!({"effect":"unverifiable","path":"atspi","atspi_ack":true})),
            ActualDelivery::Background,
        ),
        Some(error) => (
            ToolResult::error(error).with_structured(json!({
                "code":"input_outcome_unknown","effect":"unverifiable","path":"atspi"
            })),
            ActualDelivery::Unknown,
        ),
    };
    result.with_action_record(
        ActionExecutionRecord::builder(
            ActionEffect::Unverifiable,
            ActionTransport::LinuxAtSpiAction,
            RequestedDelivery::Background,
        )
        .actual_delivery(delivery)
        .build()
        .expect("native accessibility receipt has no effect readback or fallback"),
    )
}

impl NativeDesktop {
    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Synchronous producer fence, used for every owner before cleanup waits.
    pub fn seal(&self) {
        let _guard = self
            .pause_lock
            .lock()
            .expect("native desktop pause lock poisoned");
        self.closed.store(true, Ordering::Release);
        self.pause_changed.notify_all();
    }

    pub(crate) fn pause(
        &self,
        duration: Duration,
        cancellation: &super::native_window::NativeWindowCancellation,
    ) -> Result<(), cua_driver_core::interactive_input::TargetedInputError> {
        cancellation.check().map_err(super::targeted::failed)?;
        let guard = self
            .pause_lock
            .lock()
            .expect("native desktop pause lock poisoned");
        let (_guard, _elapsed) = self
            .pause_changed
            .wait_timeout_while(guard, duration, |_| !self.closed.load(Ordering::Acquire))
            .expect("native desktop pause lock poisoned");
        if self.closed.load(Ordering::Acquire) {
            return Err(super::targeted::failed("native desktop turn is closing"));
        }
        cancellation.check().map_err(super::targeted::failed)
    }

    async fn execute(
        self: Arc<Self>,
        request: NativeDesktopRequest,
        session_id: String,
        clipboard: Option<Arc<crate::clipboard::LinuxClipboard>>,
    ) -> ToolResult {
        if self.closed.load(Ordering::Acquire) {
            return refused("native desktop epoch is closing");
        }
        let Some(lease) = cua_driver_core::tool::current_native_input_worker_lease() else {
            return refused("native desktop input requires the current admitted Core worker");
        };
        let (_observation, cancellation) =
            super::native_window::NativeWindowCancellation::invocation(session_id);
        let mut observation = SealIfObservationDropped(Some(self.clone()));
        // Retain the original admitted worker in the actual blocking work, not
        // merely in its async observer. Dropping a waiter cannot release it.
        let result = tokio::task::spawn_blocking(move || {
            let _lease = lease;
            self.run(request, cancellation, clipboard)
        })
        .await;
        observation.0 = None;
        match result {
            Ok(result) => result,
            Err(error) => unknown(format!("native desktop worker outcome is unknown: {error}")),
        }
    }

    fn run(
        self: &Arc<Self>,
        request: NativeDesktopRequest,
        cancellation: super::native_window::NativeWindowCancellation,
        clipboard: Option<Arc<crate::clipboard::LinuxClipboard>>,
    ) -> ToolResult {
        let request = match request {
            NativeDesktopRequest::Window { request } => {
                return self.run_window(request, cancellation, clipboard);
            }
            request => request,
        };
        // Reuse the existing native worker cancellation, plus the original
        // owner's synchronous turn-close producer fence. Cleanup releases do
        // not consult this check, so a started edge always remains releasable.
        let check = || {
            if self.closed.load(Ordering::Acquire) {
                return Err(super::targeted::failed("native desktop turn is closing"));
            }
            cancellation.check().map_err(super::targeted::failed)
        };
        let wait = |duration| self.pause(duration, &cancellation);
        if let Err(error) = check() {
            return refused(&error.to_string());
        }
        let mut state = self
            .state
            .lock()
            .expect("native desktop owner lock poisoned");
        if self.closed.load(Ordering::Acquire) || state.closed {
            return refused("native desktop epoch is closing");
        }
        if crate::wayland::is_wayland() {
            return refused("the selected native desktop profile requires X11");
        }
        // These native argument refusals precede the first X connection or
        // input edge. They cannot mark an already-started action not-dispatched.
        match &request {
            NativeDesktopRequest::Scroll { pixels: 0, .. } => {
                return refused("pixels must be non-zero");
            }
            NativeDesktopRequest::Drag { path, .. } if path.len() < 2 => {
                return refused("drag path must contain at least two points");
            }
            NativeDesktopRequest::PressKey { key, .. } => {
                match super::native_keys::symbols(Some(key)) {
                    Ok(symbols) if symbols.is_empty() => {
                        return refused("key must be a non-empty string");
                    }
                    Err(error) => return refused(&error.to_string()),
                    _ => {}
                }
            }
            _ => {}
        }
        match request {
            NativeDesktopRequest::Window { .. } => {
                unreachable!("window requests enter their existing owned target lifetime")
            }
            NativeDesktopRequest::TypeText { text } => {
                let Some(backend) = clipboard else {
                    return refused("native paste requires the registered clipboard backend");
                };
                let State {
                    pointer,
                    clipboard_restore,
                    ..
                } = &mut *state;
                let attempt =
                    self.paste_text(text, backend, clipboard_restore, &check, &wait, || {
                        if pointer.is_none() {
                            *pointer = Some(
                                InteractiveInputSession::open_native_desktop()
                                    .map_err(|error| error.to_string())?,
                            );
                        }
                        pointer
                            .as_ref()
                            .expect("prepared paste key owner")
                            .press_native_key("CTRL+V", 33, &check, &wait)
                            .map_err(|error| error.to_string())
                    });
                match attempt.result {
                    Ok(()) => acknowledged(),
                    Err(error) if !attempt.mutation_attempted => refused(&error),
                    Err(error) => {
                        state.closed = true;
                        unknown(error)
                    }
                }
            }
            NativeDesktopRequest::Scroll {
                point,
                direction,
                pixels,
                key,
            } => {
                if state.pointer.is_none() {
                    match InteractiveInputSession::open_native_desktop() {
                        Ok(engine) => state.pointer = Some(engine),
                        Err(error) => return refused(&error.to_string()),
                    }
                }
                match state
                    .pointer
                    .as_ref()
                    .expect("prepared native input")
                    .scroll_native_pixels(point, direction, pixels, key.as_deref(), &check, &wait)
                {
                    Ok(()) => acknowledged(),
                    Err(error) => {
                        state.closed = true;
                        unknown(error)
                    }
                }
            }
            NativeDesktopRequest::Drag { path, key } => {
                if state.pointer.is_none() {
                    match InteractiveInputSession::open_native_desktop() {
                        Ok(engine) => state.pointer = Some(engine),
                        Err(error) => return refused(&error.to_string()),
                    }
                }
                match state
                    .pointer
                    .as_ref()
                    .expect("prepared native input")
                    .drag_native_path(&path, key.as_deref(), &check, &wait)
                {
                    Ok(()) => acknowledged(),
                    Err(error) => {
                        state.closed = true;
                        unknown(error)
                    }
                }
            }
            NativeDesktopRequest::PressKey { key, duration_ms } => {
                if state.pointer.is_none() {
                    match InteractiveInputSession::open_native_desktop() {
                        Ok(engine) => state.pointer = Some(engine),
                        Err(error) => return refused(&error.to_string()),
                    }
                }
                match state
                    .pointer
                    .as_ref()
                    .expect("prepared desktop input")
                    .press_native_key(&key, duration_ms, &check, &wait)
                {
                    Ok(()) => acknowledged(),
                    Err(error) => {
                        state.closed = true;
                        unknown(error)
                    }
                }
            }
            NativeDesktopRequest::Click {
                point,
                button,
                count,
                duration_ms,
                key,
            } => {
                if state.pointer.is_none() {
                    match InteractiveInputSession::open_native_desktop() {
                        Ok(engine) => state.pointer = Some(engine),
                        Err(error) => return refused(&error.to_string()),
                    }
                }
                match state
                    .pointer
                    .as_ref()
                    .expect("prepared desktop pointer")
                    .click_native_pixels(
                        super::interactive::NativeClick {
                            point,
                            button,
                            count,
                            duration_ms,
                            key: key.as_deref(),
                        },
                        &check,
                        &wait,
                    ) {
                    Ok(()) => acknowledged(),
                    Err(error) => {
                        state.closed = true;
                        unknown(error)
                    }
                }
            }
            NativeDesktopRequest::Move { point, key } => {
                if state.pointer.is_none() {
                    match InteractiveInputSession::open_native_desktop() {
                        Ok(engine) => state.pointer = Some(engine),
                        Err(error) => return refused(&error.to_string()),
                    }
                }
                let result = state
                    .pointer
                    .as_ref()
                    .expect("prepared desktop pointer")
                    .move_native_pixels_with_key(point, key.as_deref(), &check, &wait);
                match result {
                    Ok(()) => acknowledged(),
                    Err(error) => {
                        state.closed = true;
                        unknown(error)
                    }
                }
            }
            NativeDesktopRequest::MoveRelative { delta, key } => {
                if state.pointer.is_none() {
                    match InteractiveInputSession::open_native_desktop() {
                        Ok(engine) => state.pointer = Some(engine),
                        Err(error) => return refused(&error.to_string()),
                    }
                }
                let result = state
                    .pointer
                    .as_ref()
                    .expect("prepared desktop pointer")
                    .move_native_relative_with_key(delta, key.as_deref(), &check, &wait);
                match result {
                    Ok(()) => acknowledged(),
                    Err(error) => {
                        state.closed = true;
                        unknown(error)
                    }
                }
            }
            NativeDesktopRequest::DragStart { handle, point } => {
                if state.handles.contains_key(&handle) {
                    return refused("drag handle can only be started once");
                }
                let engine = match InteractiveInputSession::open_native_desktop() {
                    Ok(engine) => engine,
                    Err(error) => return refused(&error.to_string()),
                };
                state.handles.insert(
                    handle.clone(),
                    Handle {
                        engine,
                        started: false,
                    },
                );
                let entry = state
                    .handles
                    .get_mut(&handle)
                    .expect("retained native drag owner");
                match entry.engine.start_native_drag(point, &check, &wait) {
                    Ok(()) => {
                        entry.started = true;
                        acknowledged()
                    }
                    // Keep the real owner even if button-down or its ACK failed.
                    Err(error) => {
                        state.closed = true;
                        unknown(error)
                    }
                }
            }
            NativeDesktopRequest::DragMove { handle, point } => {
                let Some(entry) = state.handles.get(&handle).filter(|entry| entry.started) else {
                    return refused("Sky drag handle has not been started");
                };
                match entry.engine.move_native_pixels(point, &check, &wait) {
                    Ok(()) => acknowledged(),
                    Err(error) => {
                        state.closed = true;
                        unknown(error)
                    }
                }
            }
            NativeDesktopRequest::DragEnd { handle } => {
                let Some(entry) = state.handles.get(&handle).filter(|entry| entry.started) else {
                    return refused("Sky drag handle has not been started");
                };
                match entry.engine.release_native_desktop() {
                    Ok(()) => {
                        state.handles.remove(&handle);
                        acknowledged()
                    }
                    Err(error) => {
                        state.closed = true;
                        unknown(error)
                    }
                }
            }
        }
    }

    fn paste_text(
        &self,
        text: String,
        backend: Arc<crate::clipboard::LinuxClipboard>,
        restore: &mut Option<ClipboardRestore>,
        check: &dyn Fn() -> Result<(), cua_driver_core::interactive_input::TargetedInputError>,
        wait: &dyn Fn(
            Duration,
        )
            -> Result<(), cua_driver_core::interactive_input::TargetedInputError>,
        press: impl FnOnce() -> Result<(), String>,
    ) -> PasteAttempt {
        let clipboard = match backend.native_x11() {
            Ok(clipboard) => clipboard,
            Err(error) => {
                return PasteAttempt {
                    result: Err(error),
                    mutation_attempted: false,
                };
            }
        };
        let previous = clipboard.read_utf8().unwrap_or_default();
        if let Err(error) = check() {
            return PasteAttempt {
                result: Err(error.to_string()),
                mutation_attempted: false,
            };
        }
        *restore = Some(ClipboardRestore {
            backend: backend.clone(),
            bytes: previous,
        });
        let action = (|| -> Result<(), String> {
            clipboard.write_utf8(text.into_bytes())?;
            check().map_err(|error| error.to_string())?;
            press()?;
            wait(Duration::from_millis(500)).map_err(|error| error.to_string())
        })();
        let restored = clipboard.write_utf8(
            restore
                .as_ref()
                .expect("saved bytes before native clipboard replacement")
                .bytes
                .clone(),
        );
        std::thread::sleep(Duration::from_millis(50));
        if restored.is_ok() {
            *restore = None;
        }
        let result = match (action, restored) {
            (Ok(()), Ok(())) => Ok(()),
            (action, restore) => {
                let mut failures = Vec::new();
                if let Err(error) = action {
                    failures.push(error);
                }
                if let Err(error) = restore {
                    failures.push(format!(
                        "native clipboard restoration is unconfirmed: {error}"
                    ));
                }
                Err(failures.join("; "))
            }
        };
        PasteAttempt {
            result,
            mutation_attempted: true,
        }
    }

    fn run_window(
        self: &Arc<Self>,
        request: super::native_window_action::NativeWindowActionRequest,
        cancellation: super::native_window::NativeWindowCancellation,
        clipboard: Option<Arc<crate::clipboard::LinuxClipboard>>,
    ) -> ToolResult {
        if self.is_closed() {
            return refused("native window turn is closing");
        }
        let mut state = self
            .state
            .lock()
            .expect("native desktop owner lock poisoned");
        if state.closed {
            return refused("native window turn is closing");
        }
        if crate::wayland::is_wayland() {
            return refused("the selected native window profile requires X11");
        }
        let target = super::native_window::NativeWindowTarget {
            pid: request.pid,
            window_id: request.window_id,
        };
        let check = || -> anyhow::Result<()> {
            if self.is_closed() {
                anyhow::bail!("native window turn is closing");
            }
            cancellation.check()?;
            Ok(())
        };
        let prepared_typing = match &request.action {
            super::native_window_action::NativeWindowAction::TypeTextElement {
                element_id, ..
            } => {
                match crate::atspi::native::prepare_native_typing(
                    target,
                    element_id,
                    cancellation.session_id(),
                    &check,
                ) {
                    Ok(prepared) => Some(prepared),
                    Err(error) => return refused(&error.to_string()),
                }
            }
            _ => None,
        };
        let prepared_secondary = match &request.action {
            super::native_window_action::NativeWindowAction::SecondaryAction {
                element_id,
                action,
            } => {
                match crate::atspi::native::prepare_native_secondary(
                    target,
                    element_id,
                    action,
                    cancellation.session_id(),
                    &check,
                ) {
                    Ok(prepared) => Some(prepared),
                    Err(error) => return refused(&error.to_string()),
                }
            }
            _ => None,
        };
        let prepared_scroll = match &request.action {
            super::native_window_action::NativeWindowAction::ScrollElement {
                element_id, ..
            } => {
                match crate::atspi::native::prepare_native_scroll(
                    target,
                    element_id,
                    cancellation.session_id(),
                    &check,
                ) {
                    Ok(prepared) => Some(prepared),
                    Err(error) => return refused(&error.to_string()),
                }
            }
            _ => None,
        };
        let lifetime = match super::native_window::NativeWindowLifetime::open(target, cancellation)
        {
            Ok(lifetime) => lifetime,
            Err(error) => return refused(&error.error.to_string()),
        };
        // The same owner retains the actual connection before the first
        // virtual-focus edge, including a possibly ambiguous FocusIn ACK.
        state.window = Some(lifetime);
        let mut clipboard_mutated = false;
        let mut accessibility_attempted = false;
        let result = {
            let State {
                window,
                clipboard_restore,
                ..
            } = &mut *state;
            let lifetime = window.as_mut().expect("stored native window lifetime");
            lifetime
                .attach_owner(self)
                .and_then(|()| lifetime.start())
                .and_then(|()| {
                    let (conn, context) = lifetime.parts();
                    super::native_window_action::execute(
                        &request.action,
                        conn,
                        context,
                        |text| {
                            if let Some(prepared) = prepared_typing {
                                prepared.focus_before_paste(conn, context)?;
                            }
                            let backend = clipboard.ok_or_else(|| {
                                anyhow::anyhow!(
                                    "native paste requires the registered clipboard backend"
                                )
                            })?;
                            let check = || context.check().map_err(super::targeted::failed);
                            let wait =
                                |duration| context.pause(duration).map_err(super::targeted::failed);
                            let attempt = self.paste_text(
                                text.to_owned(),
                                backend,
                                clipboard_restore,
                                &check,
                                &wait,
                                || {
                                    context
                                        .key_chord(conn, Some("CTRL+V"), || Ok(()))
                                        .map_err(|error| error.to_string())
                                },
                            );
                            clipboard_mutated |= attempt.mutation_attempted;
                            attempt.result.map_err(anyhow::Error::msg)
                        },
                        || {
                            prepared_secondary
                                .ok_or_else(|| {
                                    anyhow::anyhow!(
                                        "native secondary action has no prepared target"
                                    )
                                })?
                                .dispatch(context, &mut accessibility_attempted)
                        },
                        || {
                            prepared_scroll
                                .ok_or_else(|| {
                                    anyhow::anyhow!("native element scroll has no prepared target")
                                })?
                                .position_owned(context)
                        },
                    )
                })
        };
        let phase = state
            .window
            .as_ref()
            .expect("stored native window lifetime")
            .phase();
        let cleanup = state
            .window
            .as_mut()
            .expect("stored native window lifetime")
            .finish_owned();
        if cleanup.is_ok() && state.clipboard_restore.is_none() {
            state.window = None;
        }
        match (result, cleanup) {
            (Ok(()), Ok(())) if accessibility_attempted => accessibility_result(None),
            (Ok(()), Ok(())) => window_acknowledged(phase.completed_button_pairs),
            (result, cleanup) => {
                let mut failures = Vec::new();
                if let Err(error) = result {
                    failures.push(error.to_string());
                }
                let cleanup_failed = cleanup.is_err();
                if let Err(error) = cleanup {
                    failures.push(format!("native window cleanup is unconfirmed: {error}"));
                }
                let message = failures.join("; ");
                if phase.input_attempted || clipboard_mutated || cleanup_failed {
                    state.closed = true;
                    self.seal();
                    if accessibility_attempted {
                        accessibility_result(Some(message))
                    } else {
                        window_unknown(message, phase.completed_button_pairs)
                    }
                } else {
                    refused(&message)
                }
            }
        }
    }

    /// Fixed owned cleanup: close producer admission before attempting releases.
    /// This may only release existing input; it accepts no new action/coordinates.
    pub async fn close(self: Arc<Self>) -> Result<(), String> {
        // This precedes queuing a blocking worker or waiting for an in-flight
        // connection ACK. New producers cannot win the cleanup mutex race.
        self.seal();
        tokio::task::spawn_blocking(move || {
            let mut state = self
                .state
                .lock()
                .expect("native desktop owner lock poisoned");
            state.closed = true;
            let mut failures = Vec::new();
            let mut released = Vec::new();
            for (id, handle) in &state.handles {
                match handle.engine.release_native_desktop() {
                    Ok(()) => released.push(id.clone()),
                    Err(error) => failures.push(error.to_string()),
                }
            }
            for id in released {
                state.handles.remove(&id);
            }
            if let Some(pointer) = &state.pointer {
                match pointer.release_native_desktop() {
                    Ok(()) => state.pointer = None,
                    Err(error) => failures.push(error.to_string()),
                }
            }
            if let Some(window) = &mut state.window {
                if let Err(error) = window.release_owned_input() {
                    failures.push(format!(
                        "native window input release is unconfirmed: {error}"
                    ));
                }
            }
            // Release attempted key/button edges before restoring clipboard
            // content, matching original KeyPresser then TemporaryClipboard.
            if let Some(restore) = &state.clipboard_restore {
                match restore.restore() {
                    Ok(()) => state.clipboard_restore = None,
                    Err(error) => failures.push(format!(
                        "native clipboard restoration is unconfirmed: {error}"
                    )),
                }
            }
            if let Some(window) = &mut state.window {
                if let Err(error) = window.finish_owned_context() {
                    failures.push(format!(
                        "native window context cleanup is unconfirmed: {error}"
                    ));
                }
            }
            if failures.is_empty() {
                state.window = None;
                Ok(())
            } else {
                Err(failures.join("; "))
            }
        })
        .await
        .map_err(|error| format!("native desktop cleanup worker lost: {error}"))?
    }
}

tokio::task_local! {
    static REQUEST: std::cell::RefCell<Option<(Arc<NativeDesktop>, NativeDesktopRequest)>>;
}

pub async fn with_native_desktop<F: Future>(
    owner: Arc<NativeDesktop>,
    request: NativeDesktopRequest,
    future: F,
) -> F::Output {
    REQUEST
        .scope(std::cell::RefCell::new(Some((owner, request))), future)
        .await
}

/// Call at the start of the corresponding existing Tool::invoke. Returning
/// None leaves ordinary Cua behavior intact; malformed trusted data refuses.
pub(crate) async fn invoke_if_native(name: &str, args: &Value) -> Option<ToolResult> {
    invoke_if_native_with_clipboard(name, args, None).await
}

pub(crate) async fn invoke_if_native_with_clipboard(
    name: &str,
    args: &Value,
    clipboard: Option<Arc<crate::clipboard::LinuxClipboard>>,
) -> Option<ToolResult> {
    let (owner, request) = REQUEST
        .try_with(|slot| slot.borrow_mut().take())
        .ok()
        .flatten()?;
    let expected = request.arguments();
    if request.tool_name() != name
        || expected
            .as_object()
            .expect("canonical native desktop object")
            .iter()
            .any(|(key, value)| args.get(key) != Some(value))
        || args.as_object().is_none_or(|actual| {
            actual.iter().any(|(key, value)| {
                !key.starts_with('_')
                    && !(key == "session" && value.is_string())
                    && expected.get(key).is_none()
            })
        })
    {
        return Some(refused(
            "native desktop sidecar does not match its admitted arguments",
        ));
    }
    let session_id = args
        .get("_session_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    Some(owner.execute(request, session_id, clipboard).await)
}

#[cfg(test)]
mod owned_scope_tests {
    use super::*;

    #[test]
    fn native_secondary_receipt_keeps_accessibility_ack_and_unknown_distinct() {
        let acknowledged = accessibility_result(None);
        assert_ne!(acknowledged.is_error, Some(true));
        assert_eq!(
            acknowledged.structured_content.as_ref().unwrap()["atspi_ack"],
            true
        );
        let record = acknowledged.action_record.unwrap();
        assert_eq!(record.transport, ActionTransport::LinuxAtSpiAction);
        assert_eq!(record.effect, ActionEffect::Unverifiable);
        assert_eq!(record.actual_delivery, Some(ActualDelivery::Background));
        assert!(record.evidence.is_empty());
        let unknown = accessibility_result(Some("DoAction reply unavailable".into()));
        assert_eq!(unknown.is_error, Some(true));
        let detail = unknown.structured_content.as_ref().unwrap();
        assert_eq!(detail["code"], "input_outcome_unknown");
        assert_eq!(detail["path"], "atspi");
        assert!(detail.get("server_ack").is_none());
        assert!(detail.get("atspi_ack").is_none());
        let record = unknown.action_record.unwrap();
        assert_eq!(record.transport, ActionTransport::LinuxAtSpiAction);
        assert_eq!(record.actual_delivery, Some(ActualDelivery::Unknown));
        assert!(record.fallbacks.is_empty());
        assert!(record.evidence.is_empty());
    }

    #[tokio::test]
    async fn extra_authority_fields_never_change_native_desktop_admission_scope() {
        for (key, value) in [
            ("pid", json!(42)),
            ("window_id", json!(7)),
            ("unexpected_scope", json!("application")),
        ] {
            let owner = Arc::new(NativeDesktop::default());
            let request = NativeDesktopRequest::Move {
                point: [1, 2],
                key: None,
            };
            let mut arguments = request.arguments();
            arguments[key] = value;
            let result = with_native_desktop(owner, request, async {
                invoke_if_native("native_desktop_input", &arguments)
                    .await
                    .expect("typed sidecar consumed")
            })
            .await;
            assert_eq!(result.is_error, Some(true));
            let detail = result
                .content
                .iter()
                .filter_map(|content| match content {
                    cua_driver_core::protocol::Content::Text { text, .. } => Some(text.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                detail.contains("sidecar does not match"),
                "extra {key} must refuse before worker or X11 access: {detail}"
            );
        }
    }
}

#[cfg(test)]
mod owned_window_live_tests {
    use super::super::native_window_action::{NativeWindowAction, NativeWindowActionRequest};
    use super::*;
    use cua_driver_core::authorization::PermissionMode;
    use cua_driver_core::session_authorization::{
        SessionAuthorizationRegistry, SessionModeCeiling,
    };
    use std::sync::Arc;
    use x11rb::connection::Connection;
    use x11rb::protocol::{
        xproto::{
            AtomEnum, ConnectionExt, CreateWindowAux, EventMask, InputFocus, PropMode, WindowClass,
        },
        Event,
    };
    use x11rb::wrapper::ConnectionExt as _;

    /// Run only in a task-owned disposable X11 server with Composite support.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires an isolated X11 display with Composite; never a personal desktop"]
    async fn native_owned_window_stop_releases_real_key_before_original_future_settles(
    ) -> anyhow::Result<()> {
        let (observer, screen) = x11rb::connect(None)?;
        let root = observer.setup().roots[screen].root;
        let window = observer.generate_id()?;
        observer
            .create_window(
                x11rb::COPY_DEPTH_FROM_PARENT,
                window,
                root,
                10,
                10,
                100,
                80,
                0,
                WindowClass::INPUT_OUTPUT,
                0,
                &CreateWindowAux::new().override_redirect(1).event_mask(
                    EventMask::KEY_PRESS | EventMask::KEY_RELEASE | EventMask::FOCUS_CHANGE,
                ),
            )?
            .check()?;
        let pid_atom = observer.intern_atom(false, b"_NET_WM_PID")?.reply()?.atom;
        observer
            .change_property32(
                PropMode::REPLACE,
                window,
                pid_atom,
                AtomEnum::CARDINAL,
                &[std::process::id()],
            )?
            .check()?;
        observer.map_window(window)?.check()?;
        observer
            .set_input_focus(InputFocus::POINTER_ROOT, root, x11rb::CURRENT_TIME)?
            .check()?;
        let before_focus = observer.get_input_focus()?.reply()?.focus;

        let ceiling = SessionModeCeiling::for_trusted_sessions(
            [PermissionMode::Standard],
            false,
            Duration::from_secs(60),
            Duration::from_secs(30),
        )
        .map_err(anyhow::Error::msg)?;
        let context = SessionAuthorizationRegistry::with_ceiling(ceiling)
            .compatibility_context(PermissionMode::Standard, None)
            .map_err(anyhow::Error::msg)?;
        let internal_session = format!(
            "__cua_runtime_{}:native-owned-window-stop",
            context.runtime_scope_key()
        );
        let registry = crate::tools::build_registry(false);
        let owner = Arc::new(NativeDesktop::default());
        let mut observation = SealIfObservationDropped(Some(owner.clone()));
        let request = NativeDesktopRequest::Window {
            request: NativeWindowActionRequest {
                pid: std::process::id(),
                window_id: window,
                action: NativeWindowAction::PressKey {
                    key: "F8+F9".into(),
                    duration_ms: 60_000,
                },
            },
        };
        let mut arguments = request.arguments();
        arguments["session"] = "native-owned-window-stop".into();
        let call_owner = owner.clone();
        let call = tokio::spawn(async move {
            with_native_desktop(
                call_owner,
                request,
                registry.invoke_with_context("native_desktop_input", arguments, context),
            )
            .await
        });
        let keys = tokio::time::timeout(Duration::from_secs(10), async {
            let mut keys = Vec::new();
            while keys.len() < 2 {
                match observer.poll_for_event()? {
                    Some(Event::KeyPress(event)) => keys.push(event),
                    Some(Event::Error(error)) => anyhow::bail!("fixture X11 error: {error:?}"),
                    _ => tokio::time::sleep(Duration::from_millis(1)).await,
                }
            }
            Ok::<_, anyhow::Error>(keys)
        })
        .await??;
        for key in &keys {
            assert_eq!(key.event, window);
            assert_eq!(
                [key.event_x, key.event_y, key.root_x, key.root_y],
                [0, 0, 0, 0]
            );
        }
        owner.seal();
        // Stop wakes the same duration wait. It never drops/replays the
        // accepted Core future, and a fixed UP ignores producer cancellation.
        // Stream the actual UP events before joining the same invocation.
        // Event timestamps measure the producing connection's cadence; a
        // delayed fixture observer cannot collapse the measured interval.
        let releases = tokio::time::timeout(Duration::from_secs(10), async {
            let mut releases = Vec::new();
            while releases.len() < 2 {
                match observer.poll_for_event()? {
                    Some(Event::KeyRelease(event)) => releases.push(event),
                    Some(Event::Error(error)) => anyhow::bail!("fixture X11 error: {error:?}"),
                    _ => tokio::time::sleep(Duration::from_millis(1)).await,
                }
            }
            Ok::<_, anyhow::Error>(releases)
        })
        .await??;
        assert_eq!(releases[0].detail, keys[1].detail);
        assert_eq!(releases[1].detail, keys[0].detail);
        assert!(releases.iter().all(|event| event.event == window));
        assert!(
            releases[1].time.wrapping_sub(releases[0].time) >= 33,
            "Stop must preserve the actual original post-UP spacing"
        );
        let result = tokio::time::timeout(Duration::from_secs(10), call).await??;
        assert_eq!(result.is_error, Some(true));
        assert_eq!(
            result
                .structured_content
                .as_ref()
                .and_then(|value| value.get("code"))
                .and_then(Value::as_str),
            Some("input_outcome_unknown")
        );
        let mut extra_releases = 0;
        while let Some(event) = observer.poll_for_event()? {
            match event {
                Event::KeyRelease(_) => extra_releases += 1,
                Event::Error(error) => anyhow::bail!("fixture X11 error: {error:?}"),
                _ => {}
            }
        }
        assert_eq!(
            extra_releases, 0,
            "fixed cleanup must not replay acknowledged UP edges"
        );
        assert_eq!(
            observer.get_input_focus()?.reply()?.focus,
            before_focus,
            "virtual background focus must not replace actual OS input focus"
        );
        Arc::clone(&owner)
            .close()
            .await
            .map_err(anyhow::Error::msg)?;
        assert!(owner
            .state
            .lock()
            .expect("native owner lock poisoned")
            .window
            .is_none());
        cua_driver_core::session::end_session(&internal_session);
        observer.destroy_window(window)?.check()?;
        observation.0 = None;
        Ok(())
    }
}
