// SPDX-License-Identifier: MIT

//! Bound native Linux pointer input for trusted Embedded SDK calls.
//!
//! Clicks and wheel trains share one selected target, X11 connection, clock,
//! virtual focus and admitted worker lifetime. Typed requests carry data only;
//! the ordinary named tool still authorizes the exact target and arguments.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde_json::Value;
use x11rb::connection::Connection;
use x11rb::protocol::xproto::*;
use x11rb::rust_connection::RustConnection;

pub use cua_driver_contract::{
    ClickButton as NativeClickButton, ScrollDirection as NativeScrollDirection,
};

/// One original native pointer operation with client-local physical pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NativeWindowInput {
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
            NativeWindowInput::Click { count, .. } => count,
            NativeWindowInput::Scroll { pixels, .. } => scroll_detents(pixels),
        }
    }

    fn point(&self) -> Result<Option<[i16; 2]>, NativeWindowError> {
        match self.input {
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
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PointerOperation {
    FocusOnly,
    Click,
    Wheel,
}

impl NativeWindowContext {
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
        self.cancellation.check()
    }

    pub(super) fn refreshes_target_per_pair(&self) -> bool {
        self.pointer.get() == PointerOperation::Click
    }

    pub(super) fn mark_attempted(&self) {
        self.attempted.set(true);
    }

    pub(super) fn mark_completed(&self) {
        self.completed.set(self.completed.get() + 1);
    }

    pub(super) fn mark_pressed(&self, button: u8) {
        self.held_button.set(Some(button));
    }

    pub(super) fn mark_released(&self) {
        self.held_button.set(None);
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
        let target = resolve_event_target(conn, self.root, self.target.window_id, point)?;
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
            state: KeyButMask::from(0u16),
            mode: NotifyMode::NORMAL,
            same_screen_focus: 2,
        };
        self.mark_attempted();
        conn.send_event(false, target.window, EventMask::NO_EVENT, enter)?
            .check()?;
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
            state: KeyButMask::from(0u16),
            same_screen: true,
        };
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
            NativeWindowInput::Click { .. } => PointerOperation::Click,
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

struct NativeWindowLifetime {
    conn: RustConnection,
    context: NativeWindowContext,
    finished: bool,
}

impl NativeWindowLifetime {
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
        let _ = self.finish();
    }
}

/// Enter the existing focus lifetime on a blocking worker, outside Tokio.
/// Native AT-SPI callers may enter the existing runtime inside `operation`.
pub(crate) fn with_native_window_focus<T, E>(
    target: NativeWindowTarget,
    cancellation: NativeWindowCancellation,
    operation: impl FnOnce(&RustConnection, &NativeWindowContext) -> Result<T, E>,
) -> Result<NativeWindowOutcome<T, E>, NativeWindowSetupFailure> {
    let setup_error = NativeWindowSetupFailure::no_input;
    cancellation
        .check()
        .map_err(|error| setup_error(error.into()))?;
    validate_live_owner(target).map_err(|error| setup_error(error.into()))?;
    let (conn, screen) = super::connect_x11_for_input().map_err(setup_error)?;
    let root = conn.setup().roots[screen].root;
    let clock = super::native_window_clock(Some(root)).map_err(setup_error)?;
    let mut lifetime = NativeWindowLifetime {
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
        },
        finished: false,
    };
    let setup = (|| -> anyhow::Result<()> {
        lifetime.context.check()?;
        let focused = focus_is_within(&lifetime.conn, root, target.window_id)?;
        lifetime.context.check()?;
        if !focused {
            lifetime.context.virtual_focus.set(true);
            lifetime.context.send_focus(&lifetime.conn, true)?;
        }
        Ok(())
    })();
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn retained_observation_cancellation_works_outside_its_task_local_scope() {
        use crate::atspi::native_observation::{with_native_observation, NativeObservationRequest};

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
