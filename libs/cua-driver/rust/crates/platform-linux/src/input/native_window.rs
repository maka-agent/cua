// SPDX-License-Identifier: MIT

//! Bound native Linux pointer input for trusted Embedded SDK calls.
//!
//! Clicks and wheel trains share one selected target, X11 connection, clock,
//! virtual focus and admitted worker lifetime. Typed requests carry data only;
//! the ordinary named tool still authorizes the exact target and arguments.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::Value;
use x11rb::connection::Connection;
use x11rb::protocol::xproto::*;
use x11rb::protocol::composite::{ConnectionExt as _, Redirect};
use x11rb::rust_connection::RustConnection;

pub use cua_driver_contract::{
    ClickButton as NativeClickButton, ScrollDirection as NativeScrollDirection,
};

/// One original native pointer operation with client-local physical pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NativeWindowInput {
    /// One virtual window pointer move with no button edges.
    Move { point: [i16; 2] },
    /// A click train, including the meaningful zero-count virtual move.
    Click {
        point: [i16; 2],
        button: NativeClickButton,
        count: u32,
    },
    /// A wheel train whose optional coordinates are checked after focus setup.
    Scroll {
        x: Option<i16>,
        y: Option<i16>,
        direction: NativeScrollDirection,
        pixels: u16,
    },
}

/// A pointer operation addressed to one selected process and X11 client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeWindowInputRequest {
    pub pid: u32,
    pub window_id: u32,
    pub input: NativeWindowInput,
}

/// One selected live X11 client, independently of any coordinate operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeWindowTarget {
    pub(crate) pid: u32,
    pub(crate) window_id: u32,
}

/// Input attempted by the shared window context, not by its caller's actuator.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NativeWindowPhase {
    pub(crate) input_attempted: bool,
    pub(crate) completed_button_pairs: u32,
}

#[derive(Debug)]
pub(crate) struct NativeWindowSetupFailure {
    pub(crate) error: anyhow::Error,
    pub(crate) phase: NativeWindowPhase,
}

impl NativeWindowSetupFailure {
    pub(crate) fn no_input(error: anyhow::Error) -> Self {
        Self {
            error,
            phase: NativeWindowPhase::default(),
        }
    }
}

/// Keep the callback's own error and actuator phase intact after cleanup.
#[derive(Debug)]
pub(crate) struct NativeWindowOutcome<T, E> {
    pub(crate) result: Result<T, E>,
    pub(crate) phase: NativeWindowPhase,
}

impl NativeWindowInputRequest {
    /// The existing tool whose target and policy admit this operation.
    #[doc(hidden)]
    pub fn tool_name(&self) -> &'static str {
        match self.input {
            NativeWindowInput::Move { .. } => "native_window_move",
            NativeWindowInput::Click { .. } => "click",
            NativeWindowInput::Scroll { .. } => "scroll",
        }
    }

    /// Exact native arguments used for admission and truthful recording.
    #[doc(hidden)]
    pub fn arguments(&self) -> Value {
        let mut args = serde_json::json!({
            "pid":self.pid,"window_id":self.window_id,
            "scope":"window","delivery_mode":"background",
        });
        match self.input {
            NativeWindowInput::Move { point } => {
                args["x"] = point[0].into();
                args["y"] = point[1].into();
            }
            NativeWindowInput::Click {
                point,
                button,
                count,
            } => {
                args["x"] = point[0].into();
                args["y"] = point[1].into();
                args["button"] = button.as_str().into();
                args["count"] = count.into();
            }
            NativeWindowInput::Scroll {
                x,
                y,
                direction,
                pixels,
            } => {
                if let Some(x) = x {
                    args["x"] = x.into();
                }
                if let Some(y) = y {
                    args["y"] = y.into();
                }
                args["direction"] = direction.as_str().into();
                args["pixels"] = pixels.into();
            }
        }
        args
    }

    pub(crate) fn pairs(&self) -> u32 {
        match self.input {
            NativeWindowInput::Move { .. } => 0,
            NativeWindowInput::Click { count, .. } => count,
            NativeWindowInput::Scroll { pixels, .. } => scroll_detents(pixels),
        }
    }

    fn point(&self) -> Result<Option<[i16; 2]>, NativeWindowError> {
        match self.input {
            NativeWindowInput::Move { point } => Ok(Some(point)),
            NativeWindowInput::Click { point, .. } => Ok(Some(point)),
            NativeWindowInput::Scroll {
                x: Some(x),
                y: Some(y),
                ..
            } => Ok(Some([x, y])),
            NativeWindowInput::Scroll {
                x: None, y: None, ..
            } => Ok(None),
            NativeWindowInput::Scroll { .. } => Err(NativeWindowError::IncompletePoint),
        }
    }
}

/// Native integer pixel distance converted to wheel steps.
/// The caller rejects zero before dispatch; positive distances use one minimum.
pub(crate) fn scroll_detents(pixels: u16) -> u32 {
    (f32::from(pixels) / 100.0).round().max(1.0) as u32
}

tokio::task_local! {
    static NATIVE_WINDOW_INPUT: RefCell<Option<NativeWindowInputRequest>>;
}

/// Carry data inside the existing bound-session operation; grants no input.
#[doc(hidden)]
pub async fn with_native_window_input<F: Future>(
    request: NativeWindowInputRequest,
    operation: F,
) -> F::Output {
    NATIVE_WINDOW_INPUT
        .scope(RefCell::new(Some(request)), operation)
        .await
}

pub(crate) fn take_native_window_input() -> Option<NativeWindowInputRequest> {
    NATIVE_WINDOW_INPUT
        .try_with(|request| request.borrow_mut().take())
        .ok()
        .flatten()
}

/// Dropping the async observation stops the next pair, while a started pair
/// keeps its release edge and the worker keeps its admitted dispatch lease.
pub(crate) struct CancelOnDrop(Arc<AtomicBool>);

pub(crate) struct NativeWindowCancellation {
    cancelled: Arc<AtomicBool>,
    session_id: String,
    observation: Option<crate::atspi::native_observation::Observation>,
}

impl NativeWindowCancellation {
    pub(crate) fn session_id(&self) -> &str {
        &self.session_id
    }

    pub(crate) fn invocation(session_id: String) -> (CancelOnDrop, Self) {
        let cancelled = Arc::new(AtomicBool::new(false));
        (
            CancelOnDrop(cancelled.clone()),
            Self {
                cancelled,
                session_id,
                observation: None,
            },
        )
    }

    pub(crate) fn from_observation(
        session_id: String,
        observation: crate::atspi::native_observation::Observation,
    ) -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            session_id,
            observation: Some(observation),
        }
    }

    pub(crate) fn check(&self) -> Result<(), NativeWindowError> {
        if self.cancelled.load(Ordering::Acquire)
            || cua_driver_core::session::is_session_ending(&self.session_id)
        {
            return Err(NativeWindowError::Cancelled);
        }
        if self
            .observation
            .as_ref()
            .and_then(|observation| observation.stop_reason())
            .is_some()
        {
            return Err(NativeWindowError::Cancelled);
        }
        Ok(())
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl NativeWindowInputRequest {
    pub(crate) fn matches_arguments(&self, tool: &str, args: &Value) -> bool {
        let expected = self.arguments();
        tool == self.tool_name()
            && expected.as_object().is_some_and(|fields| {
                fields
                    .iter()
                    .all(|(name, value)| args.get(name) == Some(value))
                    && args.as_object().is_some_and(|actual| {
                        actual.keys().all(|name| {
                            name.starts_with('_')
                                || fields.contains_key(name)
                                || (name == "session" && actual[name].is_string())
                        })
                    })
            })
    }
}

fn validate_live_owner(target: NativeWindowTarget) -> Result<(), NativeWindowError> {
    if target.pid == 0
        || target.window_id == 0
        || !crate::proc_fs::is_process_live(target.pid)
        || !crate::x11::window_belongs_to_pid(u64::from(target.window_id), target.pid)
    {
        return Err(NativeWindowError::TargetUnavailable);
    }
    Ok(())
}

/// Native target state stays inside one worker and one X11 connection. It
/// never moves the physical pointer or enters the generic fallback routes.
pub(crate) struct NativeWindowContext {
    target: NativeWindowTarget,
    cancellation: NativeWindowCancellation,
    root: Window,
    clock: (u32, std::time::Instant),
    virtual_focus: Cell<bool>,
    attempted: Cell<bool>,
    completed: Cell<u32>,
    held_button: Cell<Option<u8>>,
    cached_target: Cell<Option<super::EventTarget>>,
    root_point: Cell<Option<[i16; 2]>>,
    pointer: Cell<PointerOperation>,
    owner: Option<std::sync::Weak<super::native_desktop::NativeDesktop>>,
    modifier_masks: [u16; 256],
    key_state: Cell<u16>,
    held_keys: RefCell<Vec<u8>>,
    held_button_target: Cell<Option<super::EventTarget>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PointerOperation {
    FocusOnly,
    Click,
    Wheel,
}

impl NativeWindowContext {
    pub(crate) fn session_id(&self) -> &str {
        self.cancellation.session_id()
    }

    pub(super) fn root(&self) -> Window {
        self.root
    }

    pub(super) fn clock(&self) -> (u32, std::time::Instant) {
        self.clock
    }

    fn timestamp(&self) -> u32 {
        self.clock
            .0
            .wrapping_add(self.clock.1.elapsed().as_millis() as u32)
    }

    pub(crate) fn check(&self) -> Result<(), NativeWindowError> {
        if self
            .owner
            .as_ref()
            .is_some_and(|owner| owner.upgrade().is_none_or(|owner| owner.is_closed()))
        {
            return Err(NativeWindowError::Cancelled);
        }
        self.cancellation.check()
    }

    pub(crate) fn pause(&self, duration: std::time::Duration) -> anyhow::Result<()> {
        if let Some(owner) = &self.owner {
            let owner = owner.upgrade().ok_or(NativeWindowError::Cancelled)?;
            owner
                .pause(duration, &self.cancellation)
                .map_err(anyhow::Error::from)
        } else {
            std::thread::sleep(duration);
            Ok(())
        }
    }

    pub(super) fn refreshes_target_per_pair(&self) -> bool {
        self.pointer.get() == PointerOperation::Click
    }

    pub(crate) fn mark_attempted(&self) {
        self.attempted.set(true);
    }

    pub(crate) fn mark_completed(&self) {
        self.completed.set(self.completed.get() + 1);
    }

    pub(super) fn mark_pressed(&self, button: u8) {
        self.held_button.set(Some(button));
        self.held_button_target.set(self.cached_target.get());
    }

    pub(super) fn mark_released(&self) {
        self.held_button.set(None);
        self.held_button_target.set(None);
    }

    fn send_focus(&self, conn: &RustConnection, focused: bool) -> anyhow::Result<()> {
        let event = FocusInEvent {
            response_type: if focused {
                FOCUS_IN_EVENT
            } else {
                FOCUS_OUT_EVENT
            },
            detail: NotifyDetail::NONLINEAR,
            sequence: 0,
            event: self.target.window_id,
            mode: NotifyMode::NORMAL,
        };
        self.mark_attempted();
        conn.send_event(false, self.target.window_id, EventMask::NO_EVENT, event)?
            .check()?;
        Ok(())
    }

    pub(super) fn move_to(&self, conn: &RustConnection) -> anyhow::Result<super::EventTarget> {
        let point = self
            .root_point
            .get()
            .ok_or_else(|| anyhow::anyhow!("native window input has no translated root point"))?;
        let held = self.held_button_target.get();
        let target = if let Some(held) = held {
            let translated = conn
                .translate_coordinates(self.root, held.window, point[0], point[1])?
                .reply()?;
            if !translated.same_screen {
                anyhow::bail!("native held pointer is on a different X11 screen");
            }
            super::EventTarget {
                window: held.window,
                root_x: point[0],
                root_y: point[1],
                local_x: translated.dst_x,
                local_y: translated.dst_y,
            }
        } else {
            resolve_event_target(conn, self.root, self.target.window_id, point)?
        };
        // Resolver roundtrips may outlive the caller. Stop before new input.
        self.check()?;
        let root = self.root;
        let enter = EnterNotifyEvent {
            response_type: ENTER_NOTIFY_EVENT,
            detail: NotifyDetail::NONLINEAR,
            sequence: 0,
            time: self.timestamp(),
            root,
            event: target.window,
            child: x11rb::NONE,
            root_x: target.root_x,
            root_y: target.root_y,
            event_x: target.local_x,
            event_y: target.local_y,
            state: self.pointer_state(),
            mode: NotifyMode::NORMAL,
            same_screen_focus: 2,
        };
        if held.is_none() {
            self.check()?;
            self.mark_attempted();
            conn.send_event(false, target.window, EventMask::NO_EVENT, enter)?
                .check()?;
        }
        let motion = MotionNotifyEvent {
            response_type: MOTION_NOTIFY_EVENT,
            detail: Motion::NORMAL,
            sequence: 0,
            time: self.timestamp(),
            root,
            event: target.window,
            child: x11rb::NONE,
            root_x: target.root_x,
            root_y: target.root_y,
            event_x: target.local_x,
            event_y: target.local_y,
            state: self.pointer_state(),
            same_screen: true,
        };
        self.check()?;
        self.mark_attempted();
        conn.send_event(false, target.window, EventMask::NO_EVENT, motion)?
            .check()?;
        self.cached_target.set(Some(target));
        Ok(target)
    }

    pub(super) fn cached_target(&self) -> anyhow::Result<super::EventTarget> {
        self.cached_target
            .get()
            .ok_or_else(|| anyhow::anyhow!("native window input has no prepared pointer target"))
    }

    fn pointer_state(&self) -> KeyButMask {
        KeyButMask::from(
            self.key_state.get()
                | self
                    .held_button
                    .get()
                    .map(super::button_state_mask)
                    .map(u16::from)
                    .unwrap_or(0),
        )
    }

    /// Fixed key release uses the selected keyboard destination and current
    /// acknowledged modifier state; it never checks producer cancellation.
    fn key_edge(&self, conn: &RustConnection, code: u8, down: bool) -> anyhow::Result<()> {
        let event = KeyPressEvent {
            response_type: if down {
                KEY_PRESS_EVENT
            } else {
                KEY_RELEASE_EVENT
            },
            detail: code,
            sequence: 0,
            time: self.timestamp(),
            root: self.root,
            event: self.target.window_id,
            child: x11rb::NONE,
            root_x: 0,
            root_y: 0,
            event_x: 0,
            event_y: 0,
            state: self.pointer_state(),
            same_screen: true,
        };
        self.mark_attempted();
        conn.send_event(false, self.target.window_id, EventMask::NO_EVENT, event)?
            .check()?;
        let mask = self.modifier_masks[usize::from(code)];
        self.key_state.set(if down {
            self.key_state.get() | mask
        } else {
            self.key_state.get() & !mask
        });
        Ok(())
    }

    pub(crate) fn key_chord<T>(
        &self,
        conn: &RustConnection,
        key: Option<&str>,
        action: impl FnOnce() -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        self.check()?;
        let mut keys = super::native_keys::NativeKeys::new(key)?;
        let mut attempted = Vec::new();
        let pressed = (|| -> anyhow::Result<()> {
            while let Some(code) = keys.next_code()? {
                self.check()?;
                self.held_keys.borrow_mut().push(code);
                attempted.push(code);
                self.key_edge(conn, code, true)?;
                self.pause(std::time::Duration::from_millis(33))?;
            }
            Ok(())
        })();
        let result = pressed.and_then(|()| {
            self.check()?;
            action()
        });
        let mut failures = Vec::new();
        for code in attempted.into_iter().rev() {
            match self.key_edge(conn, code, false) {
                Ok(()) => {
                    let mut held = self.held_keys.borrow_mut();
                    if let Some(index) = held.iter().rposition(|held| *held == code) {
                        held.remove(index);
                    }
                }
                Err(error) => failures.push(error.to_string()),
            }
            native_key_release_pause();
        }
        if failures.is_empty() {
            result
        } else {
            let mut failure = failures.join("; ");
            if let Err(error) = result {
                failure = format!("{error}; {failure}");
            }
            anyhow::bail!(failure)
        }
    }

    pub(crate) fn owned_move_to_root(
        &self,
        conn: &RustConnection,
        point: [i16; 2],
        wheel: bool,
    ) -> anyhow::Result<()> {
        self.pointer.set(if wheel {
            PointerOperation::Wheel
        } else {
            PointerOperation::Click
        });
        self.root_point.set(Some(point));
        self.move_to(conn).map(|_| ())
    }

    pub(crate) fn local_to_root(
        &self,
        conn: &RustConnection,
        point: [i16; 2],
    ) -> anyhow::Result<[i16; 2]> {
        let point = conn
            .translate_coordinates(self.target.window_id, self.root, point[0], point[1])?
            .reply()?;
        if !point.same_screen {
            anyhow::bail!("native window input point is on a different X11 screen");
        }
        Ok([point.dst_x, point.dst_y])
    }

    pub(crate) fn client_center(&self, conn: &RustConnection) -> anyhow::Result<[i16; 2]> {
        let geometry = conn.get_geometry(self.target.window_id)?.reply()?;
        Ok([(geometry.width / 2) as i16, (geometry.height / 2) as i16])
    }

    pub(crate) fn button_edge_owned(
        &self,
        conn: &RustConnection,
        button: u8,
        down: bool,
    ) -> anyhow::Result<()> {
        if down {
            self.check()?;
        }
        let target = self.cached_target()?;
        let state = self.pointer_state();
        if down {
            self.mark_pressed(button);
        }
        let event = ButtonPressEvent {
            response_type: if down {
                BUTTON_PRESS_EVENT
            } else {
                BUTTON_RELEASE_EVENT
            },
            detail: button,
            sequence: 0,
            time: self.timestamp(),
            root: self.root,
            event: target.window,
            child: x11rb::NONE,
            root_x: target.root_x,
            root_y: target.root_y,
            event_x: target.local_x,
            event_y: target.local_y,
            state,
            same_screen: true,
        };
        self.mark_attempted();
        conn.send_event(false, target.window, EventMask::NO_EVENT, event)?
            .check()?;
        if !down {
            self.mark_released();
        }
        Ok(())
    }

    fn finish(&self, conn: &RustConnection) {
        if let (Some(button), Some(target)) = (self.held_button.get(), self.cached_target.get()) {
            let release = ButtonReleaseEvent {
                response_type: BUTTON_RELEASE_EVENT,
                detail: button,
                sequence: 0,
                time: self.timestamp(),
                root: self.root,
                event: target.window,
                child: x11rb::NONE,
                root_x: target.root_x,
                root_y: target.root_y,
                event_x: target.local_x,
                event_y: target.local_y,
                state: super::button_state_mask(button),
                same_screen: true,
            };
            // The native target destructor attempts each retained release
            // once and does not replace the action's result with cleanup errors.
            if conn
                .send_event(false, target.window, EventMask::NO_EVENT, release)
                .is_ok_and(|cookie| cookie.check().is_ok())
            {
                self.mark_released();
            }
        }
        // The original target lifetime settles for 100 ms even with no button
        // pairs. Its synthetic focus never changes the OS input focus.
        std::thread::sleep(std::time::Duration::from_millis(100));
        if self.virtual_focus.get()
            && matches!(
                focus_is_within(conn, self.root, self.target.window_id),
                Ok(false)
            )
        {
            let _ = self.send_focus(conn, false);
        }
        super::settle_synthetic_events(conn);
    }

    fn phase(&self) -> NativeWindowPhase {
        NativeWindowPhase {
            input_attempted: self.attempted.get(),
            completed_button_pairs: self.completed.get(),
        }
    }

    fn prepare_coordinate_pointer(
        &self,
        conn: &RustConnection,
        point: [i16; 2],
        input: NativeWindowInput,
    ) -> anyhow::Result<()> {
        self.pointer.set(match input {
            NativeWindowInput::Move { .. } | NativeWindowInput::Click { .. } => {
                PointerOperation::Click
            }
            NativeWindowInput::Scroll { .. } => PointerOperation::Wheel,
        });
        self.root_point.set(Some(point));
        self.move_to(conn)?;
        Ok(())
    }

    /// The selected-window click helper receives a screen-i16 point directly.
    /// One initial move precedes the same per-pair move/press/12ms/release train.
    pub(crate) fn click_at_root(
        &self,
        conn: &RustConnection,
        point: [i16; 2],
        button: NativeClickButton,
        count: u32,
    ) -> anyhow::Result<()> {
        self.check()?;
        self.pointer.set(PointerOperation::Click);
        self.root_point.set(Some(point));
        let prepared = self.move_to(conn)?;
        super::send_button_sequence(
            conn,
            u64::from(self.target.window_id),
            [i32::from(prepared.local_x), i32::from(prepared.local_y)],
            count as usize,
            match button {
                NativeClickButton::Left => 1,
                NativeClickButton::Middle => 2,
                NativeClickButton::Right => 3,
            },
            &[],
            super::ButtonTiming {
                hold_ms: 12,
                gap_ms: 0,
                native_wheel: false,
                native_window: Some(self),
            },
        )
    }

    /// The caller already resolved a screen-i16 point. Keep it in that frame;
    /// the existing event resolver still computes the wire-local payload.
    pub(crate) fn scroll_at_root(
        &self,
        conn: &RustConnection,
        point: [i16; 2],
        direction: NativeScrollDirection,
        pixels: u16,
    ) -> anyhow::Result<()> {
        self.check()?;
        if pixels == 0 {
            return Err(NativeWindowError::InvalidPixels.into());
        }
        self.pointer.set(PointerOperation::Wheel);
        self.root_point.set(Some(point));
        let prepared = self.move_to(conn)?;
        super::send_button_sequence(
            conn,
            u64::from(self.target.window_id),
            [i32::from(prepared.local_x), i32::from(prepared.local_y)],
            scroll_detents(pixels) as usize,
            super::scroll_button(direction.as_str())?,
            &[],
            super::ButtonTiming {
                hold_ms: 36,
                gap_ms: 0,
                native_wheel: false,
                native_window: Some(self),
            },
        )
    }
}

pub(crate) struct NativeWindowLifetime {
    conn: RustConnection,
    context: NativeWindowContext,
    finished: bool,
    // This is the original connection's existing Composite resource custody,
    // including an attempted redirect whose acknowledgement was lost.
    buffer_retained: bool,
}

impl NativeWindowLifetime {
    pub(crate) fn open(
        target: NativeWindowTarget,
        cancellation: NativeWindowCancellation,
    ) -> Result<Self, NativeWindowSetupFailure> {
        let setup_error = NativeWindowSetupFailure::no_input;
        cancellation
            .check()
            .map_err(|error| setup_error(error.into()))?;
        validate_live_owner(target).map_err(|error| setup_error(error.into()))?;
        let (conn, screen) = super::connect_x11_for_input().map_err(setup_error)?;
        let root = conn.setup().roots[screen].root;
        let clock = super::native_window_clock(Some(root)).map_err(setup_error)?;
        Ok(Self {
            conn,
            context: NativeWindowContext {
                target,
                cancellation,
                root,
                clock,
                virtual_focus: Cell::new(false),
                attempted: Cell::new(false),
                completed: Cell::new(0),
                held_button: Cell::new(None),
                cached_target: Cell::new(None),
                root_point: Cell::new(None),
                pointer: Cell::new(PointerOperation::FocusOnly),
                owner: None,
                modifier_masks: [0; 256],
                key_state: Cell::new(0),
                held_keys: RefCell::new(Vec::new()),
                held_button_target: Cell::new(None),
            },
            finished: false,
            buffer_retained: false,
        })
    }

    pub(crate) fn attach_owner(
        &mut self,
        owner: &Arc<super::native_desktop::NativeDesktop>,
    ) -> anyhow::Result<()> {
        self.context.owner = Some(Arc::downgrade(owner));
        let mapping = self.conn.get_modifier_mapping()?.reply()?;
        let width = mapping.keycodes.len() / 8;
        if width > 0 {
            for (index, codes) in mapping.keycodes.chunks(width).enumerate() {
                for code in codes.iter().copied().filter(|code| *code != 0) {
                    self.context.modifier_masks[usize::from(code)] |= 1u16 << index;
                }
            }
        }
        Ok(())
    }

    fn retain_window_buffer(&mut self) -> anyhow::Result<()> {
        let attributes = self.conn.get_window_attributes(self.context.target.window_id)?.reply()?;
        if attributes.map_state != MapState::VIEWABLE {
            anyhow::bail!("window {} is not mapped; restore it before using background input or taking a screenshot", self.context.target.window_id);
        }
        self.conn.composite_query_version(0, 4)
            .map_err(anyhow::Error::from)
            .and_then(|cookie| cookie.reply().map_err(anyhow::Error::from))
            .map_err(|error| error.context("background window rendering requires the X Composite extension"))?;
        self.context.check()?;
        // Retain before the server roundtrip so an ambiguous connection error
        // cannot discard ownership of a redirect that may have been accepted.
        self.buffer_retained = true;
        let result = self.conn.composite_redirect_window(self.context.target.window_id, Redirect::AUTOMATIC)
            .map_err(anyhow::Error::from)
            .and_then(|cookie| match cookie.check() {
                Ok(()) => Ok(()),
                Err(x11rb::errors::ReplyError::X11Error(error)) => {
                    self.buffer_retained = false;
                    Err(anyhow::Error::from(x11rb::errors::ReplyError::X11Error(error)))
                }
                Err(error) => Err(error.into()),
            });
        result.map_err(|error| error.context("failed to retain the target window's rendering buffer"))?;
        std::thread::sleep(std::time::Duration::from_millis(100));
        self.context.check()?;
        Ok(())
    }

    pub(crate) fn start(&mut self) -> anyhow::Result<()> {
        self.context.check()?;
        let focused =
            focus_is_within(&self.conn, self.context.root, self.context.target.window_id)?;
        self.context.check()?;
        if self.context.owner.is_some() {
            self.retain_window_buffer()?;
        }
        if !focused {
            self.context.virtual_focus.set(true);
            self.context.send_focus(&self.conn, true)?;
        }
        Ok(())
    }

    pub(crate) fn parts(&self) -> (&RustConnection, &NativeWindowContext) {
        (&self.conn, &self.context)
    }
    pub(crate) fn phase(&self) -> NativeWindowPhase {
        self.context.phase()
    }

    /// Release only actual retained key/button resources, without caller checks.
    pub(crate) fn release_owned_input(&mut self) -> anyhow::Result<()> {
        if self.finished {
            return Ok(());
        }
        // The selected keyboard/focus/buffer destination and a hit-tested
        // button child are distinct resources. A child may be reparented out
        // before the selected window disappears.
        let selected_destroyed = match self.conn
            .get_window_attributes(self.context.target.window_id)?.reply() {
            Err(x11rb::errors::ReplyError::X11Error(error))
                if error.error_kind == x11rb::protocol::ErrorKind::Window => true,
            Err(error) => return Err(error.into()),
            Ok(_) => false,
        };
        let mut failures = Vec::new();
        if selected_destroyed {
            self.context.held_keys.borrow_mut().clear();
            self.context.virtual_focus.set(false);
            self.buffer_retained = false;
        } else {
            let mut retained = Vec::new();
            for code in self.context.held_keys.borrow().iter().rev().copied() {
                if let Err(error) = self.context.key_edge(&self.conn, code, false) {
                    retained.push(code);
                    failures.push(error.to_string());
                }
                native_key_release_pause();
            }
            retained.reverse();
            self.context.held_keys.replace(retained);
        }
        if let (Some(button), Some(target)) = (
            self.context.held_button.get(),
            self.context.held_button_target.get(),
        ) {
            let release = ButtonReleaseEvent {
                response_type: BUTTON_RELEASE_EVENT,
                detail: button,
                sequence: 0,
                time: self.context.timestamp(),
                root: self.context.root,
                event: target.window,
                child: x11rb::NONE,
                root_x: target.root_x,
                root_y: target.root_y,
                event_x: target.local_x,
                event_y: target.local_y,
                state: self.context.pointer_state(),
                same_screen: true,
            };
            match self
                .conn
                .send_event(false, target.window, EventMask::NO_EVENT, release)
                .map_err(anyhow::Error::from)
                .and_then(|cookie| match cookie.check() {
                    Ok(()) => Ok(()),
                    // Only this exact held destination can witness that its
                    // old button resource was destroyed; never re-hit-test.
                    Err(x11rb::errors::ReplyError::X11Error(error))
                        if error.error_kind == x11rb::protocol::ErrorKind::Window => Ok(()),
                    Err(error) => Err(error.into()),
                })
            {
                Ok(()) => self.context.mark_released(),
                Err(error) => failures.push(error.to_string()),
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            anyhow::bail!(failures.join("; "))
        }
    }

    /// Finish the original virtual-focus lifetime after fixed input/clipboard cleanup.
    pub(crate) fn finish_owned_context(&mut self) -> anyhow::Result<()> {
        if self.finished {
            return Ok(());
        }
        let mut failures = Vec::new();
        // The original delay also occurs after the target was destroyed.
        std::thread::sleep(std::time::Duration::from_millis(100));
        if self.context.virtual_focus.get() {
            match focus_is_within(&self.conn, self.context.root, self.context.target.window_id) {
                Ok(true) => self.context.virtual_focus.set(false),
                Ok(false) => match self.context.send_focus(&self.conn, false) {
                    Ok(()) => self.context.virtual_focus.set(false),
                    Err(error) => failures.push(error.to_string()),
                },
                Err(error) => failures.push(error.to_string()),
            }
        }
        // The original BackgroundWindow destructor sends FocusOut before
        // dropping WindowBuffer, which unredirects this exact same client.
        if self.buffer_retained {
            match self.conn.composite_unredirect_window(self.context.target.window_id, Redirect::AUTOMATIC)
                .map_err(anyhow::Error::from)
                .and_then(|cookie| match cookie.check() {
                    Ok(()) => Ok(()),
                    Err(x11rb::errors::ReplyError::X11Error(error))
                        if error.error_kind == x11rb::protocol::ErrorKind::Window => Ok(()),
                    Err(error) => Err(error.into()),
                }) {
                Ok(()) => self.buffer_retained = false,
                Err(error) => failures.push(format!("native window buffer release is unconfirmed: {error}")),
            }
        }
        if let Err(error) = self
            .conn
            .get_input_focus()
            .map_err(anyhow::Error::from)
            .and_then(|cookie| cookie.reply().map_err(anyhow::Error::from))
        {
            failures.push(error.to_string());
        }
        if !self.context.held_keys.borrow().is_empty() || self.context.held_button.get().is_some() {
            failures.push("native input release remains unconfirmed".into());
        }
        if failures.is_empty() {
            self.finished = true;
            Ok(())
        } else {
            anyhow::bail!(failures.join("; "))
        }
    }

    pub(crate) fn finish_owned(&mut self) -> anyhow::Result<()> {
        let release = self.release_owned_input();
        let finish = self.finish_owned_context();
        match (release, finish) {
            (Ok(()), Ok(())) => Ok(()),
            (release, finish) => {
                let failures = [release.err(), finish.err()]
                    .into_iter()
                    .flatten()
                    .map(|error| error.to_string())
                    .collect::<Vec<_>>();
                anyhow::bail!(failures.join("; "))
            }
        }
    }

    fn finish(&mut self) -> NativeWindowPhase {
        if !self.finished {
            self.finished = true;
            self.context.finish(&self.conn);
        }
        self.context.phase()
    }
}

impl Drop for NativeWindowLifetime {
    fn drop(&mut self) {
        if self.context.owner.is_some() {
            let _ = self.finish_owned();
        } else {
            let _ = self.finish();
        }
    }
}

/// Enter the existing focus lifetime on a blocking worker, outside Tokio.
/// Native AT-SPI callers may enter the existing runtime inside `operation`.
pub(crate) fn with_native_window_focus<T, E>(
    target: NativeWindowTarget,
    cancellation: NativeWindowCancellation,
    operation: impl FnOnce(&RustConnection, &NativeWindowContext) -> Result<T, E>,
) -> Result<NativeWindowOutcome<T, E>, NativeWindowSetupFailure> {
    let mut lifetime = NativeWindowLifetime::open(target, cancellation)?;
    let setup = lifetime.start();
    if let Err(error) = setup {
        return Err(NativeWindowSetupFailure {
            error,
            phase: lifetime.finish(),
        });
    }
    let result = operation(&lifetime.conn, &lifetime.context);
    let phase = lifetime.finish();
    Ok(NativeWindowOutcome { result, phase })
}

fn resolve_event_target(
    conn: &RustConnection,
    root: Window,
    selected: Window,
    root_point: [i16; 2],
) -> anyhow::Result<super::EventTarget> {
    let geometry = conn.get_geometry(selected)?.reply()?;
    let local_point = conn
        .translate_coordinates(root, selected, root_point[0], root_point[1])?
        .reply()?;
    let mut local = [local_point.dst_x, local_point.dst_y];
    validate_client_bounds(local, geometry.width, geometry.height)?;
    let mut window = selected;
    for _ in 0..100 {
        let tree = conn.query_tree(window)?.reply()?;
        let mut child_at_point = None;
        for child in tree.children.into_iter().rev() {
            let attributes = conn.get_window_attributes(child)?.reply()?;
            if attributes.map_state != MapState::VIEWABLE {
                continue;
            }
            let translated = conn
                .translate_coordinates(root, child, root_point[0], root_point[1])?
                .reply()?;
            let geometry = conn.get_geometry(child)?.reply()?;
            if client_point_is_inside(
                [translated.dst_x, translated.dst_y],
                geometry.width,
                geometry.height,
            ) {
                child_at_point = Some((child, [translated.dst_x, translated.dst_y]));
                break;
            }
        }
        let Some((child, point)) = child_at_point else {
            break;
        };
        window = child;
        local = point;
    }
    Ok(super::EventTarget {
        window,
        local_x: local[0],
        local_y: local[1],
        root_x: root_point[0],
        root_y: root_point[1],
    })
}

fn client_point_is_inside([x, y]: [i16; 2], width: u16, height: u16) -> bool {
    x >= 0 && y >= 0 && i32::from(x) < i32::from(width) && i32::from(y) < i32::from(height)
}

fn validate_client_bounds(
    point: [i16; 2],
    width: u16,
    height: u16,
) -> Result<(), NativeWindowError> {
    if !client_point_is_inside(point, width, height) {
        return Err(NativeWindowError::PointOutsideWindow);
    }
    Ok(())
}

fn focus_is_within(conn: &RustConnection, root: Window, selected: Window) -> anyhow::Result<bool> {
    let mut current = conn.get_input_focus()?.reply()?.focus;
    for _ in 0..100 {
        if current == selected {
            return Ok(true);
        }
        if current < 2 || current == root {
            return Ok(false);
        }
        current = conn.query_tree(current)?.reply()?.parent;
    }
    Ok(false)
}

pub(crate) fn execute(
    request: NativeWindowInputRequest,
    cancellation: NativeWindowCancellation,
) -> anyhow::Result<()> {
    if matches!(request.input, NativeWindowInput::Scroll { pixels: 0, .. }) {
        return Err(NativeWindowError::InvalidPixels.into());
    }
    let target = NativeWindowTarget {
        pid: request.pid,
        window_id: request.window_id,
    };
    let outcome = with_native_window_focus(
        target,
        cancellation,
        |conn, context| -> anyhow::Result<()> {
            let point = match request.point()? {
                Some(point) => point,
                None => {
                    // No supplied coordinate selects the live client center,
                    // after virtual focus setup and independently of any capture.
                    let geometry = conn.get_geometry(request.window_id)?.reply()?;
                    [(geometry.width / 2) as i16, (geometry.height / 2) as i16]
                }
            };
            let translated = conn
                .translate_coordinates(request.window_id, context.root(), point[0], point[1])?
                .reply()?;
            if !translated.same_screen {
                anyhow::bail!("native window input point is on a different X11 screen");
            }
            // A zero count still prepares one virtual move and validates its live
            // client bounds; it emits no button edges and never moves the pointer.
            context.prepare_coordinate_pointer(
                conn,
                [translated.dst_x, translated.dst_y],
                request.input,
            )?;
            let (button, hold_ms) = match request.input {
                NativeWindowInput::Move { .. } => return Ok(()),
                NativeWindowInput::Click { button, .. } => (
                    match button {
                        NativeClickButton::Left => 1,
                        NativeClickButton::Middle => 2,
                        NativeClickButton::Right => 3,
                    },
                    12,
                ),
                NativeWindowInput::Scroll { direction, .. } => {
                    (super::scroll_button(direction.as_str())?, 36)
                }
            };
            super::send_button_sequence(
                conn,
                u64::from(request.window_id),
                point.map(i32::from),
                request.pairs() as usize,
                button,
                &[],
                super::ButtonTiming {
                    hold_ms,
                    gap_ms: 0,
                    native_wheel: false,
                    native_window: Some(context),
                },
            )
        },
    );
    let (result, phase) = match outcome {
        Ok(outcome) => (outcome.result, outcome.phase),
        Err(error) => (Err(error.error), error.phase),
    };
    result.map_err(|cause| {
        if phase.input_attempted {
            NativeWindowError::Dispatch {
                completed: phase.completed_button_pairs,
                cause,
            }
            .into()
        } else {
            cause
        }
    })
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum NativeWindowError {
    #[error("native window input target is no longer owned by the selected process")]
    TargetUnavailable,
    #[error("background pointer position is outside the target window")]
    PointOutsideWindow,
    #[error("x and y must be provided together")]
    IncompletePoint,
    #[error("pixels must be a positive finite number.")]
    InvalidPixels,
    #[error("native window input invocation was cancelled")]
    Cancelled,
    #[error(
        "native window input input outcome is unknown after {completed} complete button pairs: {cause:#}"
    )]
    Dispatch {
        completed: u32,
        #[source]
        cause: anyhow::Error,
    },
}

/// Original KeyPresser Drop waits after every UP, including stopped cleanup.
/// Only producer duration/down waits may be woken by the owner fence.
pub(super) fn native_key_release_pause() {
    std::thread::sleep(std::time::Duration::from_millis(33));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Actual leaf cleanup, only on a disposable task-owned X11 server.
    #[test]
    #[ignore = "requires an isolated X11 display with Composite; never a personal desktop"]
    fn native_owned_cleanup_uses_the_exact_held_child_destruction_witness() -> anyhow::Result<()> {
        use x11rb::protocol::Event;
        use x11rb::wrapper::ConnectionExt as _;

        let (observer, screen) = x11rb::connect(None)?;
        let root = observer.setup().roots[screen].root;
        let pid_atom = observer.intern_atom(false, b"_NET_WM_PID")?.reply()?.atom;
        for reparent_child in [true, false] {
            let selected = observer.generate_id()?;
            let child = observer.generate_id()?;
            for (window, parent, width) in [(selected, root, 100), (child, selected, 50)] {
                observer.create_window(
                    x11rb::COPY_DEPTH_FROM_PARENT, window, parent,
                    if window == selected {20} else {0}, if window == selected {20} else {0},
                    width, width, 0, WindowClass::INPUT_OUTPUT, 0,
                    &CreateWindowAux::new().override_redirect(1)
                        .event_mask(EventMask::BUTTON_PRESS | EventMask::BUTTON_RELEASE | EventMask::FOCUS_CHANGE),
                )?.check()?;
                observer.change_property32(PropMode::REPLACE, window, pid_atom,
                    AtomEnum::CARDINAL, &[std::process::id()])?.check()?;
                observer.map_window(window)?.check()?;
            }
            observer.set_input_focus(InputFocus::POINTER_ROOT, root, x11rb::CURRENT_TIME)?.check()?;
            let owner = Arc::new(super::super::native_desktop::NativeDesktop::default());
            let (_cancel, cancellation) = NativeWindowCancellation::invocation(String::new());
            let mut lifetime = NativeWindowLifetime::open(
                NativeWindowTarget {pid:std::process::id(), window_id:selected}, cancellation,
            ).map_err(|error| error.error)?;
            lifetime.attach_owner(&owner)?;
            lifetime.start()?;
            {
                let (connection, context) = lifetime.parts();
                let point = context.local_to_root(connection, [5, 5])?;
                context.owned_move_to_root(connection, point, false)?;
                context.button_edge_owned(connection, 1, true)?;
                assert_eq!(context.held_button_target.get().map(|target| target.window), Some(child));
            }
            observer.get_input_focus()?.reply()?;
            let mut downs = 0;
            while let Some(event) = observer.poll_for_event()? {
                if let Event::ButtonPress(event) = event {
                    assert_eq!(event.event, child);
                    downs += 1;
                }
            }
            assert_eq!(downs, 1, "fixture must retain an actual acknowledged child DOWN");
            if reparent_child {
                observer.reparent_window(child, root, 200, 20)?.check()?;
                observer.map_window(child)?.check()?;
                observer.destroy_window(selected)?.check()?;
                assert_eq!(observer.get_window_attributes(child)?.reply()?.map_state, MapState::VIEWABLE);
            } else {
                observer.destroy_window(child)?.check()?;
                let (connection, context) = lifetime.parts();
                let error = context.button_edge_owned(connection, 1, false)
                    .expect_err("the actual UP destination was destroyed");
                assert!(matches!(error.downcast_ref::<x11rb::errors::ReplyError>(),
                    Some(x11rb::errors::ReplyError::X11Error(error))
                        if error.error_kind == x11rb::protocol::ErrorKind::Window));
            }
            owner.seal();
            lifetime.release_owned_input()?;
            assert!(lifetime.context.held_button.get().is_none());
            assert!(lifetime.context.held_button_target.get().is_none());
            lifetime.finish_owned_context()?;
            assert!(lifetime.finished);
            observer.get_input_focus()?.reply()?;
            let mut ups = 0;
            while let Some(event) = observer.poll_for_event()? {
                if let Event::ButtonRelease(event) = event {
                    assert_eq!(event.event, child, "cleanup must not retarget the held child");
                    ups += 1;
                }
            }
            assert_eq!(ups, usize::from(reparent_child),
                "live reparented child needs its actual UP; destroyed child needs its own typed witness");
            observer.destroy_window(if reparent_child {child} else {selected})?.check()?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn retained_observation_cancellation_works_outside_its_task_local_scope() {
        use crate::atspi::native_observation::{NativeObservationRequest, with_native_observation};

        let observation = with_native_observation(
            NativeObservationRequest {
                pid: 123,
                window_id: 456,
                deadline: None,
            },
            async { crate::atspi::native_observation::current().expect("scoped observation") },
        )
        .await;
        assert!(crate::atspi::native_observation::current().is_none());
        let cancellation = NativeWindowCancellation::from_observation(String::new(), observation);
        assert!(matches!(
            cancellation.check(),
            Err(NativeWindowError::Cancelled)
        ));

        with_native_observation(
            NativeObservationRequest {
                pid: 123,
                window_id: 456,
                deadline: Some(std::time::Instant::now()),
            },
            async {
                let observation =
                    crate::atspi::native_observation::current().expect("scoped deadline");
                let cancellation =
                    NativeWindowCancellation::from_observation(String::new(), observation);
                assert!(matches!(
                    cancellation.check(),
                    Err(NativeWindowError::Cancelled)
                ));
            },
        )
        .await;
    }

    fn click(count: u32) -> NativeWindowInputRequest {
        NativeWindowInputRequest {
            pid: 123,
            window_id: 456,
            input: NativeWindowInput::Click {
                point: [37, 41],
                button: NativeClickButton::Left,
                count,
            },
        }
    }

    fn scroll(x: Option<i16>, y: Option<i16>) -> NativeWindowInputRequest {
        NativeWindowInputRequest {
            pid: 123,
            window_id: 456,
            input: NativeWindowInput::Scroll {
                x,
                y,
                direction: NativeScrollDirection::Down,
                pixels: 150,
            },
        }
    }

    #[test]
    fn native_data_binds_the_exact_named_tool_target_and_actual_input() {
        for request in [
            click(0),
            click(4),
            click(u32::MAX),
            scroll(Some(37), Some(41)),
            scroll(None, Some(41)),
        ] {
            let arguments = request.arguments();
            assert!(request.matches_arguments(request.tool_name(), &arguments));
            let other_tool = if request.tool_name() == "click" {
                "scroll"
            } else {
                "click"
            };
            assert!(!request.matches_arguments(other_tool, &arguments));
            for (key, value) in [
                ("pid", json!(124)),
                ("window_id", json!(457)),
                ("x", json!(38)),
                ("y", json!(42)),
                ("scope", json!("desktop")),
                ("delivery_mode", json!("foreground")),
                ("capture_id", json!("capture")),
                ("modifier", json!([])),
                ("from_zoom", json!(false)),
                ("unrecognized", json!(true)),
            ] {
                let mut changed = arguments.clone();
                changed[key] = value;
                assert!(
                    !request.matches_arguments(request.tool_name(), &changed),
                    "{key}: {changed}"
                );
            }
            let mut admitted = arguments.clone();
            admitted["_session_id"] = json!("admitted");
            admitted["session"] = json!("namespaced-runtime-session");
            admitted["_native_window_pixels"] = json!(true);
            assert!(request.matches_arguments(request.tool_name(), &admitted));
        }
        for count in [0, 4, u32::MAX] {
            let request = click(count);
            assert_eq!(request.arguments()["count"], count);
            let mut substituted = request.arguments();
            substituted["count"] = json!(1);
            assert!(!request.matches_arguments("click", &substituted));
        }
        let request = scroll(Some(37), Some(41));
        for (key, value) in [
            ("pixels", json!(100)),
            ("direction", json!("up")),
            ("amount", json!(2)),
            ("by", json!("line")),
        ] {
            let mut changed = request.arguments();
            changed[key] = value;
            assert!(
                !request.matches_arguments("scroll", &changed),
                "{key}: {changed}"
            );
        }
    }

    #[test]
    fn an_absent_scroll_coordinate_stays_absent_and_cannot_be_substituted() {
        let request = scroll(None, Some(41));
        let args = request.arguments();
        assert!(args.get("x").is_none());
        assert_eq!(args["y"], 41);
        assert!(matches!(
            request.point(),
            Err(NativeWindowError::IncompletePoint)
        ));
        let mut substituted = args;
        substituted["x"] = json!(0);
        assert!(!request.matches_arguments("scroll", &substituted));
    }

    #[test]
    fn both_absent_scroll_coordinates_request_the_live_center_without_fabricating_a_point() {
        let request = scroll(None, None);
        let args = request.arguments();
        assert!(args.get("x").is_none());
        assert!(args.get("y").is_none());
        assert_eq!(request.point().unwrap(), None);
        let mut substituted = args;
        substituted["x"] = json!(0);
        substituted["y"] = json!(0);
        assert!(!request.matches_arguments("scroll", &substituted));
    }

    #[test]
    fn zero_click_count_cannot_change_live_client_bounds() {
        for point in [[0, 0], [639, 479]] {
            assert!(validate_client_bounds(point, 640, 480).is_ok());
        }
        for point in [[-1, 41], [37, -1], [640, 41], [37, 480], [i16::MAX, 41]] {
            assert!(matches!(
                validate_client_bounds(point, 640, 480),
                Err(NativeWindowError::PointOutsideWindow)
            ));
        }
        assert!(validate_client_bounds([0, 0], 0, 480).is_err());
        assert!(validate_client_bounds([0, 0], 640, 0).is_err());
    }

    #[tokio::test]
    async fn native_input_data_is_single_use_and_stays_with_its_future() {
        assert!(take_native_window_input().is_none());
        let (first, second) = tokio::join!(
            with_native_window_input(click(0), async {
                tokio::task::yield_now().await;
                let request = take_native_window_input().unwrap();
                assert!(take_native_window_input().is_none());
                request
            }),
            with_native_window_input(scroll(None, Some(41)), async {
                tokio::task::yield_now().await;
                take_native_window_input().unwrap()
            }),
        );
        assert_eq!(first, click(0));
        assert_eq!(second, scroll(None, Some(41)));
        assert!(take_native_window_input().is_none());
    }

    #[test]
    fn cancelling_one_invocation_does_not_cancel_the_next_one() {
        let (guard, cancellation) = NativeWindowCancellation::invocation(String::new());
        assert!(cancellation.check().is_ok());
        drop(guard);
        assert!(matches!(
            cancellation.check(),
            Err(NativeWindowError::Cancelled)
        ));
        let (_next_guard, next) = NativeWindowCancellation::invocation(String::new());
        assert!(next.check().is_ok());
    }
}
