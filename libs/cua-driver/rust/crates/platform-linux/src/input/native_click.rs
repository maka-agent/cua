// SPDX-License-Identifier: MIT

//! Private-call data for the native Linux click profile.
//!
//! The SDK still dispatches the ordinary authorized `click` tool with a valid
//! generic count. Only this in-memory request carries the native u32 count;
//! there is no JSON field or public protocol route that opts into the profile.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde_json::Value;
use x11rb::connection::Connection;
use x11rb::protocol::xproto::*;
use x11rb::rust_connection::RustConnection;

pub use cua_driver_contract::ClickButton as NativeClickButton;

/// One native click train addressed to the selected process and X11 client.
///
/// Coordinates are client-local physical pixels, already parsed as i16. A
/// count of zero remains meaningful and must not bypass target validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeClickRequest {
    pub pid: u32,
    pub window_id: u32,
    pub point: [i16; 2],
    pub button: NativeClickButton,
    pub count: u32,
}

tokio::task_local! {
    static NATIVE_CLICK: RefCell<Option<NativeClickRequest>>;
}

/// Carry data inside the existing bound-session operation; grants no input.
#[doc(hidden)]
pub async fn with_native_click<F: Future>(request: NativeClickRequest, operation: F) -> F::Output {
    NATIVE_CLICK
        .scope(RefCell::new(Some(request)), operation)
        .await
}

pub(crate) fn take_native_click() -> Option<NativeClickRequest> {
    NATIVE_CLICK
        .try_with(|request| request.borrow_mut().take())
        .ok()
        .flatten()
}

/// Dropping the async observation stops the next pair, while a started pair
/// keeps its release edge and the worker keeps its admitted dispatch lease.
pub(crate) struct CancelOnDrop(Arc<AtomicBool>);

pub(crate) struct NativeClickCancellation {
    cancelled: Arc<AtomicBool>,
    session_id: String,
}

impl NativeClickCancellation {
    pub(crate) fn invocation(session_id: String) -> (CancelOnDrop, Self) {
        let cancelled = Arc::new(AtomicBool::new(false));
        (
            CancelOnDrop(cancelled.clone()),
            Self {
                cancelled,
                session_id,
            },
        )
    }

    pub(super) fn check(&self) -> Result<(), NativeClickError> {
        if self.cancelled.load(Ordering::Acquire)
            || cua_driver_core::session::is_session_ending(&self.session_id)
        {
            return Err(NativeClickError::Cancelled);
        }
        Ok(())
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl NativeClickRequest {
    pub(crate) fn matches_arguments(&self, args: &Value) -> bool {
        args.get("pid").and_then(Value::as_u64) == Some(u64::from(self.pid))
            && args.get("window_id").and_then(Value::as_u64) == Some(u64::from(self.window_id))
            && args.get("scope").and_then(Value::as_str) == Some("window")
            && args.get("delivery_mode").and_then(Value::as_str) == Some("background")
            && args.get("x").and_then(Value::as_i64) == Some(i64::from(self.point[0]))
            && args.get("y").and_then(Value::as_i64) == Some(i64::from(self.point[1]))
            && args.get("button").and_then(Value::as_str) == Some(self.button.as_str())
            && args.get("count").and_then(Value::as_u64) == Some(1)
            && [
                "modifier",
                "element_token",
                "element_index",
                "capture_id",
                "snapshot_id",
                "from_zoom",
                "coordinate_frame",
            ]
            .iter()
            .all(|key| args.get(key).is_none())
    }
}

fn validate_live_owner(request: &NativeClickRequest) -> Result<(), NativeClickError> {
    if request.pid == 0
        || request.window_id == 0
        || !crate::proc_fs::is_process_live(request.pid)
        || !crate::x11::window_belongs_to_pid(u64::from(request.window_id), request.pid)
    {
        return Err(NativeClickError::TargetUnavailable);
    }
    Ok(())
}

/// Native target state stays inside one worker and one X11 connection. It
/// never moves the physical pointer or enters the generic fallback routes.
pub(super) struct NativeClickContext {
    request: NativeClickRequest,
    cancellation: NativeClickCancellation,
    root: Window,
    clock: (u32, std::time::Instant),
    virtual_focus: Cell<bool>,
    attempted: Cell<bool>,
    completed: Cell<u32>,
    held_button: Cell<Option<u8>>,
    cached_target: Cell<Option<super::EventTarget>>,
    root_point: Cell<Option<[i16; 2]>>,
}

impl NativeClickContext {
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

    pub(super) fn check(&self) -> Result<(), NativeClickError> {
        self.cancellation.check()
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
            event: self.request.window_id,
            mode: NotifyMode::NORMAL,
        };
        self.mark_attempted();
        conn.send_event(false, self.request.window_id, EventMask::NO_EVENT, event)?
            .check()?;
        Ok(())
    }

    pub(super) fn move_to(&self, conn: &RustConnection) -> anyhow::Result<super::EventTarget> {
        let point = self
            .root_point
            .get()
            .ok_or_else(|| anyhow::anyhow!("native click has no translated root point"))?;
        let target = resolve_event_target(conn, self.root, self.request.window_id, point)?;
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
                focus_is_within(conn, self.root, self.request.window_id),
                Ok(false)
            )
        {
            let _ = self.send_focus(conn, false);
        }
        super::settle_synthetic_events(conn);
    }
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
) -> Result<(), NativeClickError> {
    if !client_point_is_inside(point, width, height) {
        return Err(NativeClickError::PointOutsideWindow);
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
    request: NativeClickRequest,
    cancellation: NativeClickCancellation,
) -> anyhow::Result<()> {
    cancellation.check()?;
    validate_live_owner(&request)?;
    let (conn, screen) = super::connect_x11_for_input()?;
    let root = conn.setup().roots[screen].root;
    let context = NativeClickContext {
        request,
        cancellation,
        root,
        clock: super::native_window_clock(Some(root))?,
        virtual_focus: Cell::new(false),
        attempted: Cell::new(false),
        completed: Cell::new(0),
        held_button: Cell::new(None),
        cached_target: Cell::new(None),
        root_point: Cell::new(None),
    };
    let result = (|| -> anyhow::Result<()> {
        context.check()?;
        if !focus_is_within(&conn, root, request.window_id)? {
            context.virtual_focus.set(true);
            context.send_focus(&conn, true)?;
        }
        let translated = conn
            .translate_coordinates(request.window_id, root, request.point[0], request.point[1])?
            .reply()?;
        if !translated.same_screen {
            anyhow::bail!("native click point is on a different X11 screen");
        }
        context
            .root_point
            .set(Some([translated.dst_x, translated.dst_y]));
        // A zero count still prepares one virtual move and validates its live
        // client bounds; it emits no button edges and never moves the pointer.
        context.move_to(&conn)?;
        super::send_button_sequence(
            &conn,
            u64::from(request.window_id),
            request.point.map(i32::from),
            request.count as usize,
            match request.button {
                NativeClickButton::Left => 1,
                NativeClickButton::Middle => 2,
                NativeClickButton::Right => 3,
            },
            &[],
            super::ButtonTiming {
                hold_ms: 12,
                gap_ms: 0,
                native_wheel: false,
                native_click: Some(&context),
            },
        )
    })();
    context.finish(&conn);
    result.map_err(|cause| {
        if context.attempted.get() {
            NativeClickError::Dispatch {
                completed: context.completed.get(),
                cause,
            }
            .into()
        } else {
            cause
        }
    })
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum NativeClickError {
    #[error("native click target is no longer owned by the selected process")]
    TargetUnavailable,
    #[error("native click point is outside the target window")]
    PointOutsideWindow,
    #[error("native click invocation was cancelled")]
    Cancelled,
    #[error("native click input outcome is unknown after {completed} complete clicks: {cause:#}")]
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

    fn request(count: u32) -> NativeClickRequest {
        NativeClickRequest {
            pid: 123,
            window_id: 456,
            point: [37, 41],
            button: NativeClickButton::Left,
            count,
        }
    }

    fn arguments() -> Value {
        json!({
            "pid":123,"window_id":456,"scope":"window","delivery_mode":"background",
            "x":37,"y":41,"button":"left","count":1,
        })
    }

    #[test]
    fn native_counts_bind_only_to_the_same_authorized_window_point_and_button() {
        for count in [0, 4, u32::MAX] {
            let request = request(count);
            assert!(request.matches_arguments(&arguments()));
            for (key, value) in [
                ("pid", json!(124)),
                ("window_id", json!(457)),
                ("x", json!(38)),
                ("y", json!(42)),
                ("button", json!("right")),
                ("count", json!(count)),
                ("scope", json!("desktop")),
                ("delivery_mode", json!("foreground")),
                ("capture_id", json!("capture")),
                ("modifier", json!([])),
                ("from_zoom", json!(false)),
            ] {
                let mut changed = arguments();
                changed[key] = value;
                assert!(
                    !request.matches_arguments(&changed),
                    "unexpected binding for {key}: {changed}"
                );
            }
        }
    }

    #[test]
    fn zero_count_cannot_bypass_live_client_bounds_validation() {
        for count in [0, 1, u32::MAX] {
            let mut request = request(count);
            for point in [[0, 0], [639, 479]] {
                request.point = point;
                assert!(validate_client_bounds(request.point, 640, 480).is_ok());
            }
            for point in [[-1, 41], [37, -1], [640, 41], [37, 480], [i16::MAX, 41]] {
                request.point = point;
                assert!(matches!(
                    validate_client_bounds(request.point, 640, 480),
                    Err(NativeClickError::PointOutsideWindow)
                ));
            }
            request.point = [0, 0];
            assert!(validate_client_bounds(request.point, 0, 480).is_err());
            assert!(validate_client_bounds(request.point, 640, 0).is_err());
        }
    }

    #[tokio::test]
    async fn native_click_data_is_single_use_and_stays_with_its_future() {
        assert!(take_native_click().is_none());
        let (first, second) = tokio::join!(
            with_native_click(request(0), async {
                tokio::task::yield_now().await;
                let request = take_native_click().unwrap();
                assert!(take_native_click().is_none());
                request.count
            }),
            with_native_click(request(u32::MAX), async {
                tokio::task::yield_now().await;
                take_native_click().unwrap().count
            }),
        );
        assert_eq!((first, second), (0, u32::MAX));
        assert!(take_native_click().is_none());
    }

    #[test]
    fn cancelling_one_invocation_does_not_cancel_the_next_one() {
        let (guard, cancellation) = NativeClickCancellation::invocation(String::new());
        assert!(cancellation.check().is_ok());
        drop(guard);
        assert!(matches!(
            cancellation.check(),
            Err(NativeClickError::Cancelled)
        ));
        let (_next_guard, next) = NativeClickCancellation::invocation(String::new());
        assert!(next.check().is_ok());
    }
}
