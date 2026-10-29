//! Low-latency, stateful input delivery to one X11 target (window or display
//! region): the Linux native session behind
//! [`cua_driver_core::interactive_input`].
//!
//! The session keeps one X connection and keyboard map for its lifetime, so a
//! streaming client's pointer samples do not pay a connect per event.
//!
//! - `PersistentForeground`: the target window is activated when the session
//!   opens (and again when something else took the focus), and events go
//!   through XTest into the focused root, exactly like physical input.
//! - `Background`: events are XSendEvent-addressed to the target window
//!   without moving the pointer or focus. Opening a background session on a
//!   window whose toolkit drops synthetic events (GTK3/4, Chromium) is refused
//!   with [`InteractiveInputError::WouldRequireActivation`](cua_driver_core::interactive_input::InteractiveInputError::WouldRequireActivation)
//!   instead of producing input that is reported as dispatched and never arrives.
//!
//! Every batch ends with an X round-trip, so the receipt means the server
//! processed the events. Held keys and buttons are released when the session
//! is released or dropped. Wayland has no per-window targeting and is refused
//! at open.

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Instant;

use cua_driver_core::interactive_input::{
    denormalize, extract_integral, validate_batch, InteractiveDeliveryMode, InteractiveInputBatch,
    InteractiveInputError, InteractiveInputEvent, InteractiveInputReceipt, KeyState, Modifier,
    PointerButton, PointerPhase, TargetedInputError,
};
use x11rb::protocol::xproto::*;
use x11rb::rust_connection::RustConnection;

use super::targeted::{self as x, KeyboardMap};

/// Pixels per wheel click for precise (trackpad) deltas.
const PRECISE_PIXELS_PER_CLICK: f64 = 40.0;

#[derive(Debug, Clone)]
pub struct InteractiveInputConfig {
    /// Target window, or `None` for a display region.
    pub window: Option<u32>,
    /// Display region in root coordinates `(x, y, width, height)`, used when
    /// `window` is `None`.
    pub region: Option<(i32, i32, u32, u32)>,
    pub delivery_mode: InteractiveDeliveryMode,
}

struct State {
    conn: RustConnection,
    root: Window,
    keymap: KeyboardMap,
    held_keys: HashSet<String>,
    native_held_keys: Vec<u8>,
    held_buttons: HashSet<u8>,
    last_point: (i32, i32),
    scroll_residual_x: f64,
    scroll_residual_y: f64,
}

pub struct InteractiveInputSession {
    config: InteractiveInputConfig,
    state: Mutex<Option<State>>,
}

#[derive(Debug)]
pub(crate) struct NativeClick<'a> {
    pub(crate) point: [i16; 2],
    pub(crate) button: cua_driver_contract::ClickButton,
    pub(crate) count: u32,
    pub(crate) duration_ms: u64,
    pub(crate) key: Option<&'a str>,
}

fn native(error: TargetedInputError) -> InteractiveInputError {
    match error {
        TargetedInputError::WouldRequireActivation(message) => {
            InteractiveInputError::WouldRequireActivation(message)
        }
        TargetedInputError::TargetUnavailable(message)
        | TargetedInputError::Unsupported(message) => InteractiveInputError::InvalidTarget(message),
        TargetedInputError::DeliveryFailed(message) => InteractiveInputError::Native(message),
    }
}

impl InteractiveInputSession {
    pub fn open(config: InteractiveInputConfig) -> Result<Self, InteractiveInputError> {
        if config.window.is_none() && config.region.is_none() {
            return Err(InteractiveInputError::InvalidTarget(
                "a window or a display region is required".into(),
            ));
        }
        let (conn, root) = x::connect().map_err(native)?;
        if let Some(window) = config.window {
            conn.get_geometry(window)
                .map_err(|e| InteractiveInputError::Native(e.to_string()))?
                .reply()
                .map_err(|_| InteractiveInputError::InvalidTarget("window is gone".into()))?;
            if config.delivery_mode == InteractiveDeliveryMode::Background {
                if let Some(toolkit) =
                    x::window_pid(&conn, window).and_then(x::synthetic_input_ignored_by)
                {
                    return Err(InteractiveInputError::WouldRequireActivation(format!(
                        "{toolkit} ignores synthetic (XSendEvent) input; open the session with \
                         persistent foreground delivery"
                    )));
                }
            }
        } else if config.delivery_mode == InteractiveDeliveryMode::Background {
            return Err(InteractiveInputError::WouldRequireActivation(
                "a display region has no window to address background input to".into(),
            ));
        }
        let keymap = KeyboardMap::load(&conn).map_err(native)?;
        let session = Self {
            config,
            state: Mutex::new(Some(State {
                conn,
                root,
                keymap,
                held_keys: HashSet::new(),
                native_held_keys: Vec::new(),
                held_buttons: HashSet::new(),
                last_point: (0, 0),
                scroll_residual_x: 0.0,
                scroll_residual_y: 0.0,
            })),
        };
        {
            let guard = session.state.lock().unwrap();
            let state = guard.as_ref().expect("fresh session state");
            session.prepare(state).map_err(native)?;
        }
        Ok(session)
    }

    fn is_foreground(&self) -> bool {
        self.config.delivery_mode == InteractiveDeliveryMode::PersistentForeground
    }

    /// Foreground sessions keep the target active; paid when the session opens
    /// and only again when another window took the focus.
    fn prepare(&self, state: &State) -> Result<(), TargetedInputError> {
        if let (true, Some(window)) = (self.is_foreground(), self.config.window) {
            if x::active_window(&state.conn, state.root) != Some(window) {
                x::activate(&state.conn, state.root, window)?;
            }
        }
        Ok(())
    }

    /// Deliver one ordered batch and wait until the X server processed it.
    pub fn dispatch(
        &self,
        batch: &InteractiveInputBatch,
    ) -> Result<InteractiveInputReceipt, InteractiveInputError> {
        let started = Instant::now();
        let through = validate_batch(batch)?;
        let mut guard = self.state.lock().unwrap();
        let state = guard.as_mut().ok_or(InteractiveInputError::Closed)?;
        self.prepare(state).map_err(native)?;
        for event in &batch.events {
            self.dispatch_event(state, event).map_err(native)?;
        }
        x::sync(&state.conn).map_err(native)?;
        Ok(InteractiveInputReceipt {
            through_sequence: through,
            event_count: batch.events.len(),
            dispatch_micros: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        })
    }

    /// Release every held key and button (best effort) and close the session.
    pub fn release_all(&self) {
        let Some(mut state) = self.state.lock().unwrap().take() else {
            return;
        };
        // This is destructor fallback only. Native acknowledged cleanup keeps
        // the same state until each exact attempted keycode release settles.
        for code in state.native_held_keys.iter().rev() {
            let _ = x::fake_key(&state.conn, false, *code, state.root);
            super::native_window::native_key_release_pause();
        }
        let keys: Vec<String> = state.held_keys.drain().collect();
        for key in keys {
            let _ = self.key_edge(&mut state, &key, false, &[]);
        }
        let buttons: Vec<u8> = state.held_buttons.drain().collect();
        let (px, py) = state.last_point;
        for button in buttons {
            let _ = self.button_edge(&mut state, px, py, button, false);
        }
        let _ = x::sync(&state.conn);
    }

    fn root_point(
        &self,
        state: &State,
        x_norm: f64,
        y_norm: f64,
    ) -> Result<(i32, i32), TargetedInputError> {
        let (ox, oy, width, height) = match (self.config.window, self.config.region) {
            (Some(window), _) => {
                let geometry = state
                    .conn
                    .get_geometry(window)
                    .map_err(x::failed)?
                    .reply()
                    .map_err(|_| x::gone())?;
                let origin = state
                    .conn
                    .translate_coordinates(window, state.root, 0, 0)
                    .map_err(x::failed)?
                    .reply()
                    .map_err(x::failed)?;
                (
                    i32::from(origin.dst_x),
                    i32::from(origin.dst_y),
                    u32::from(geometry.width),
                    u32::from(geometry.height),
                )
            }
            (None, Some(region)) => region,
            (None, None) => unreachable!("validated at open"),
        };
        Ok((
            ox + denormalize(x_norm, width),
            oy + denormalize(y_norm, height),
        ))
    }

    fn dispatch_event(
        &self,
        state: &mut State,
        event: &InteractiveInputEvent,
    ) -> Result<(), TargetedInputError> {
        match event {
            InteractiveInputEvent::TextCommit { text } => {
                if self.is_foreground() {
                    x::type_xtest(&state.conn, state.root, &state.keymap, text)
                } else {
                    super::send_type_text(u64::from(self.window()?), text).map_err(x::failed)
                }
            }
            InteractiveInputEvent::Key {
                key,
                state: key_state,
                modifiers,
                ..
            } => {
                let key = x::x_key_name(key);
                let modifiers = modifier_names(modifiers);
                match key_state {
                    KeyState::Down => {
                        state.held_keys.insert(key.clone());
                        self.key_edge(state, &key, true, &modifiers)
                    }
                    KeyState::Up => {
                        // A chord was delivered whole on its down edge.
                        if !state.held_keys.remove(&key) || !modifiers.is_empty() {
                            return Ok(());
                        }
                        self.key_edge(state, &key, false, &[])
                    }
                }
            }
            InteractiveInputEvent::Pointer {
                phase,
                button,
                x_normalized,
                y_normalized,
                ..
            } => {
                let (px, py) = self.root_point(state, *x_normalized, *y_normalized)?;
                state.last_point = (px, py);
                let button = match button {
                    Some(PointerButton::Right) => x::XBUTTON_RIGHT,
                    Some(PointerButton::Middle) => x::XBUTTON_MIDDLE,
                    _ => x::XBUTTON_LEFT,
                };
                match phase {
                    PointerPhase::Move => self.motion(state, px, py),
                    PointerPhase::Down => {
                        state.held_buttons.insert(button);
                        self.button_edge(state, px, py, button, true)
                    }
                    PointerPhase::Up | PointerPhase::Cancel => {
                        state.held_buttons.remove(&button);
                        self.button_edge(state, px, py, button, false)
                    }
                }
            }
            InteractiveInputEvent::Scroll {
                x_normalized,
                y_normalized,
                delta_x,
                delta_y,
                precise,
                ..
            } => {
                let (px, py) = self.root_point(state, *x_normalized, *y_normalized)?;
                let scale = if *precise {
                    1.0 / PRECISE_PIXELS_PER_CLICK
                } else {
                    1.0
                };
                state.scroll_residual_x += delta_x * scale;
                state.scroll_residual_y += delta_y * scale;
                let dx = extract_integral(&mut state.scroll_residual_x);
                let dy = extract_integral(&mut state.scroll_residual_y);
                for (amount, negative, positive) in [
                    (dy, x::XBUTTON_SCROLL_UP, x::XBUTTON_SCROLL_DOWN),
                    (dx, x::XBUTTON_SCROLL_LEFT, x::XBUTTON_SCROLL_RIGHT),
                ] {
                    let button = if amount < 0 { negative } else { positive };
                    for _ in 0..amount.unsigned_abs() {
                        self.button_edge(state, px, py, button, true)?;
                        self.button_edge(state, px, py, button, false)?;
                    }
                }
                Ok(())
            }
        }
    }

    fn window(&self) -> Result<u32, TargetedInputError> {
        self.config.window.ok_or_else(|| {
            TargetedInputError::WouldRequireActivation("no window for background input".into())
        })
    }

    fn local(
        &self,
        state: &State,
        px: i32,
        py: i32,
    ) -> Result<(u32, i32, i32), TargetedInputError> {
        let window = self.window()?;
        let reply = state
            .conn
            .translate_coordinates(state.root, window, px as i16, py as i16)
            .map_err(x::failed)?
            .reply()
            .map_err(|_| x::gone())?;
        Ok((window, i32::from(reply.dst_x), i32::from(reply.dst_y)))
    }

    fn motion(&self, state: &State, px: i32, py: i32) -> Result<(), TargetedInputError> {
        if self.is_foreground() {
            return x::fake_motion(&state.conn, state.root, px, py);
        }
        let (window, lx, ly) = self.local(state, px, py)?;
        let held = state.held_buttons.iter().next().copied();
        super::send_motion(u64::from(window), lx, ly, held).map_err(x::failed)
    }

    fn button_edge(
        &self,
        state: &mut State,
        px: i32,
        py: i32,
        button: u8,
        press: bool,
    ) -> Result<(), TargetedInputError> {
        if self.is_foreground() {
            x::fake_motion(&state.conn, state.root, px, py)?;
            return x::fake_button(&state.conn, press, button, state.root);
        }
        let (window, lx, ly) = self.local(state, px, py)?;
        let xid = u64::from(window);
        if press {
            super::send_button_down(xid, lx, ly, button)
        } else {
            super::send_button_up(xid, lx, ly, button)
        }
        .map_err(x::failed)
    }

    fn key_edge(
        &self,
        state: &mut State,
        key: &str,
        press: bool,
        modifiers: &[String],
    ) -> Result<(), TargetedInputError> {
        if !modifiers.is_empty() {
            // A chord: deliver as one press with modifiers on the down edge.
            if !press {
                return Ok(());
            }
            if self.is_foreground() {
                let held = x::press_modifiers(&state.conn, state.root, &state.keymap, modifiers)?;
                let (code, shift) = x::key_code(&state.keymap, key)?;
                x::tap(&state.conn, state.root, &state.keymap, code, shift)?;
                return x::release_keys(&state.conn, state.root, &held);
            }
            let modifiers: Vec<&str> = modifiers.iter().map(String::as_str).collect();
            return super::send_key(u64::from(self.window()?), key, &modifiers).map_err(x::failed);
        }
        let (code, _) = x::key_code(&state.keymap, key)?;
        if self.is_foreground() {
            x::fake_key(&state.conn, press, code, state.root)
        } else {
            x::background_key_event(&state.conn, state.root, self.window()?, code, press)
        }
    }
}

impl Drop for InteractiveInputSession {
    fn drop(&mut self) {
        self.release_all();
    }
}

fn modifier_names(modifiers: &[Modifier]) -> Vec<String> {
    modifiers
        .iter()
        .filter_map(|modifier| match modifier {
            Modifier::Shift => Some("shift"),
            Modifier::Control => Some("ctrl"),
            Modifier::Option => Some("alt"),
            Modifier::Command => Some("super"),
            Modifier::Function => None,
        })
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modifiers_map_to_x_names() {
        assert_eq!(
            modifier_names(&[
                Modifier::Command,
                Modifier::Shift,
                Modifier::Option,
                Modifier::Control,
                Modifier::Function
            ]),
            vec!["super", "shift", "alt", "ctrl"]
        );
    }

    #[test]
    fn a_session_needs_a_target() {
        let error = InteractiveInputSession::open(InteractiveInputConfig {
            window: None,
            region: None,
            delivery_mode: InteractiveDeliveryMode::PersistentForeground,
        })
        .err()
        .expect("no target");
        assert!(matches!(error, InteractiveInputError::InvalidTarget(_)));
    }

    #[test]
    fn background_display_regions_are_refused() {
        // Refused before any X connection is needed when there is no display;
        // with a display it is refused for lack of a window.
        match InteractiveInputSession::open(InteractiveInputConfig {
            window: None,
            region: Some((0, 0, 10, 10)),
            delivery_mode: InteractiveDeliveryMode::Background,
        }) {
            Err(InteractiveInputError::WouldRequireActivation(_))
            | Err(InteractiveInputError::InvalidTarget(_)) => {}
            Err(other) => panic!("unexpected error {other}"),
            Ok(_) => panic!("background display input must be refused"),
        }
    }
}

// Append inside platform-linux/src/input/interactive.rs. This extends the
// existing engine and reuses its connection, keyboard map, XTest and ACK path.

impl InteractiveInputSession {
    fn native_key_action(
        &self,
        key: Option<&str>,
        check: &dyn Fn() -> Result<(), TargetedInputError>,
        wait: &dyn Fn(std::time::Duration) -> Result<(), TargetedInputError>,
        action: impl FnOnce(&Self, &mut State) -> Result<(), TargetedInputError>,
    ) -> Result<(), InteractiveInputError> {
        self.require_native_desktop()?;
        check().map_err(native)?;
        let mut guard = self
            .state
            .lock()
            .expect("native desktop state lock poisoned");
        let state = guard.as_mut().ok_or(InteractiveInputError::Closed)?;
        let mut keys = super::native_keys::NativeKeys::new(key).map_err(native)?;
        let mut attempted = Vec::new();
        let mut pressed = Ok(());
        loop {
            let code = match keys.next_code() {
                Ok(Some(code)) => code,
                Ok(None) => break,
                Err(error) => {
                    pressed = Err(error);
                    break;
                }
            };
            if let Err(error) = check() {
                pressed = Err(error);
                break;
            }
            // Record the actual keycode before a possibly ambiguous DOWN ACK.
            state.native_held_keys.push(code);
            attempted.push(code);
            if let Err(error) =
                x::fake_key(&state.conn, true, code, state.root).and_then(|()| x::sync(&state.conn))
            {
                pressed = Err(error);
                break;
            }
            if let Err(error) = wait(std::time::Duration::from_millis(33)) {
                pressed = Err(error);
                break;
            }
        }
        let result = pressed
            .and_then(|()| check())
            .and_then(|()| action(self, state));
        let mut release = Ok(());
        for code in attempted.into_iter().rev() {
            match x::fake_key(&state.conn, false, code, state.root)
                .and_then(|()| x::sync(&state.conn))
            {
                Ok(()) => {
                    if let Some(index) = state
                        .native_held_keys
                        .iter()
                        .rposition(|held| *held == code)
                    {
                        state.native_held_keys.remove(index);
                    }
                }
                Err(error) => {
                    if release.is_ok() {
                        release = Err(error);
                    }
                }
            }
            super::native_window::native_key_release_pause();
        }
        result
            .and(release)
            .and_then(|()| x::sync(&state.conn))
            .map_err(native)
    }

    pub(crate) fn move_native_pixels_with_key(
        &self,
        point: [i16; 2],
        key: Option<&str>,
        check: &dyn Fn() -> Result<(), TargetedInputError>,
        wait: &dyn Fn(std::time::Duration) -> Result<(), TargetedInputError>,
    ) -> Result<(), InteractiveInputError> {
        self.native_key_action(key, check, wait, |session, state| {
            session.native_motion_path(state, point, check, wait)
        })
    }

    pub(crate) fn move_native_relative_with_key(
        &self,
        delta: [i16; 2],
        key: Option<&str>,
        check: &dyn Fn() -> Result<(), TargetedInputError>,
        wait: &dyn Fn(std::time::Duration) -> Result<(), TargetedInputError>,
    ) -> Result<(), InteractiveInputError> {
        self.native_key_action(key, check, wait, |_session, state| {
            x::fake_relative_motion(&state.conn, state.root, delta[0], delta[1])
        })
    }

    fn native_motion_path(
        &self,
        state: &mut State,
        target: [i16; 2],
        check: &dyn Fn() -> Result<(), TargetedInputError>,
        wait: &dyn Fn(std::time::Duration) -> Result<(), TargetedInputError>,
    ) -> Result<(), TargetedInputError> {
        check()?;
        let pointer = state
            .conn
            .query_pointer(state.root)
            .map_err(x::failed)?
            .reply()
            .map_err(x::failed)?;
        let path = native_motion_points([pointer.root_x, pointer.root_y], target);
        for (index, point) in path.iter().enumerate() {
            check()?;
            self.motion(state, i32::from(point[0]), i32::from(point[1]))?;
            x::sync(&state.conn)?;
            state.last_point = (i32::from(point[0]), i32::from(point[1]));
            if index + 1 < path.len() {
                wait(std::time::Duration::from_millis(8))?;
            }
        }
        Ok(())
    }

    pub(crate) fn click_native_pixels(
        &self,
        click: NativeClick<'_>,
        check: &dyn Fn() -> Result<(), TargetedInputError>,
        wait: &dyn Fn(std::time::Duration) -> Result<(), TargetedInputError>,
    ) -> Result<(), InteractiveInputError> {
        let NativeClick {
            point,
            button,
            count,
            duration_ms,
            key,
        } = click;
        // Original click performs this initial motion even for count zero.
        self.move_native_pixels(point, check, wait)?;
        let button = match button {
            cua_driver_contract::ClickButton::Left => x::XBUTTON_LEFT,
            cua_driver_contract::ClickButton::Right => x::XBUTTON_RIGHT,
            cua_driver_contract::ClickButton::Middle => x::XBUTTON_MIDDLE,
        };
        for _ in 0..count {
            // The original chord has one lifetime per pair, not per train.
            self.native_key_action(key, check, wait, |session, state| {
                session.native_motion_path(state, point, check, wait)?;
                check()?;
                state.held_buttons.insert(button);
                let down = x::fake_button(&state.conn, true, button, state.root)
                    .and_then(|()| x::sync(&state.conn));
                let action =
                    down.and_then(|()| wait(std::time::Duration::from_millis(duration_ms)));
                // Fixed cleanup is allowed after cancellation and down failure.
                let up = x::fake_button(&state.conn, false, button, state.root)
                    .and_then(|()| x::sync(&state.conn));
                if up.is_ok() {
                    state.held_buttons.remove(&button);
                }
                action.and(up)
            })?;
        }
        Ok(())
    }

    pub(crate) fn scroll_native_pixels(
        &self,
        point: Option<[i16; 2]>,
        direction: cua_driver_contract::ScrollDirection,
        pixels: u16,
        key: Option<&str>,
        check: &dyn Fn() -> Result<(), TargetedInputError>,
        wait: &dyn Fn(std::time::Duration) -> Result<(), TargetedInputError>,
    ) -> Result<(), InteractiveInputError> {
        if let Some(point) = point {
            self.move_native_pixels(point, check, wait)?;
        }
        let button = match direction {
            cua_driver_contract::ScrollDirection::Up => x::XBUTTON_SCROLL_UP,
            cua_driver_contract::ScrollDirection::Down => x::XBUTTON_SCROLL_DOWN,
            cua_driver_contract::ScrollDirection::Left => x::XBUTTON_SCROLL_LEFT,
            cua_driver_contract::ScrollDirection::Right => x::XBUTTON_SCROLL_RIGHT,
        };
        self.native_key_action(key, check, wait, |_session, state| {
            for _ in 0..super::native_window::scroll_detents(pixels) {
                check()?;
                state.held_buttons.insert(button);
                let down = x::fake_button(&state.conn, true, button, state.root)
                    .and_then(|()| x::sync(&state.conn));
                let action = down.and_then(|()| wait(std::time::Duration::from_millis(36)));
                let up = x::fake_button(&state.conn, false, button, state.root)
                    .and_then(|()| x::sync(&state.conn));
                if up.is_ok() {
                    state.held_buttons.remove(&button);
                }
                action.and(up)?;
            }
            Ok(())
        })
    }

    pub(crate) fn drag_native_path(
        &self,
        path: &[[i16; 2]],
        key: Option<&str>,
        check: &dyn Fn() -> Result<(), TargetedInputError>,
        wait: &dyn Fn(std::time::Duration) -> Result<(), TargetedInputError>,
    ) -> Result<(), InteractiveInputError> {
        if path.len() < 2 {
            return Err(InteractiveInputError::InvalidTarget(
                "drag path must contain at least two points".into(),
            ));
        }
        self.move_native_pixels(path[0], check, wait)?;
        self.native_key_action(key, check, wait, |session, state| {
            check()?;
            session.motion(state, i32::from(path[0][0]), i32::from(path[0][1]))?;
            x::sync(&state.conn)?;
            check()?;
            state.held_buttons.insert(x::XBUTTON_LEFT);
            let down = x::fake_button(&state.conn, true, x::XBUTTON_LEFT, state.root)
                .and_then(|()| x::sync(&state.conn));
            let action = down.and_then(|()| {
                for segment in path.windows(2) {
                    for point in native_drag_points(segment[0], segment[1]) {
                        check()?;
                        session.motion(state, i32::from(point[0]), i32::from(point[1]))?;
                        x::sync(&state.conn)?;
                        state.last_point = (i32::from(point[0]), i32::from(point[1]));
                        wait(std::time::Duration::from_millis(1))?;
                    }
                }
                Ok(())
            });
            let up = x::fake_button(&state.conn, false, x::XBUTTON_LEFT, state.root)
                .and_then(|()| x::sync(&state.conn));
            if up.is_ok() {
                state.held_buttons.remove(&x::XBUTTON_LEFT);
            }
            action.and(up)
        })
    }

    pub(crate) fn press_native_key(
        &self,
        key: &str,
        duration_ms: u64,
        check: &dyn Fn() -> Result<(), TargetedInputError>,
        wait: &dyn Fn(std::time::Duration) -> Result<(), TargetedInputError>,
    ) -> Result<(), InteractiveInputError> {
        if super::native_keys::symbols(Some(key))
            .map_err(native)?
            .is_empty()
        {
            return Err(InteractiveInputError::InvalidTarget(
                "key must be a non-empty string".into(),
            ));
        }
        self.native_key_action(Some(key), check, wait, |_session, _state| {
            // Original press_key counts one 33ms down delay toward duration.
            wait(std::time::Duration::from_millis(
                duration_ms.saturating_sub(33),
            ))
        })
    }

    pub(crate) fn open_native_desktop() -> Result<Self, InteractiveInputError> {
        let (conn, root) = x::connect().map_err(native)?;
        let bounds = conn
            .get_geometry(root)
            .map_err(|error| InteractiveInputError::Native(error.to_string()))?
            .reply()
            .map_err(|error| InteractiveInputError::Native(error.to_string()))?;
        let keymap = KeyboardMap::load(&conn).map_err(native)?;
        Ok(Self {
            config: InteractiveInputConfig {
                window: None,
                region: Some((0, 0, u32::from(bounds.width), u32::from(bounds.height))),
                delivery_mode: InteractiveDeliveryMode::PersistentForeground,
            },
            state: Mutex::new(Some(State {
                conn,
                root,
                keymap,
                held_keys: HashSet::new(),
                native_held_keys: Vec::new(),
                held_buttons: HashSet::new(),
                last_point: (0, 0),
                scroll_residual_x: 0.0,
                scroll_residual_y: 0.0,
            })),
        })
    }

    fn require_native_desktop(&self) -> Result<(), InteractiveInputError> {
        if self.config.window.is_some() || !self.is_foreground() {
            return Err(InteractiveInputError::InvalidTarget(
                "native desktop input requires its exact desktop session".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn move_native_pixels(
        &self,
        point: [i16; 2],
        check: &dyn Fn() -> Result<(), TargetedInputError>,
        wait: &dyn Fn(std::time::Duration) -> Result<(), TargetedInputError>,
    ) -> Result<(), InteractiveInputError> {
        check().map_err(native)?;
        self.require_native_desktop()?;
        let mut guard = self
            .state
            .lock()
            .expect("native desktop state lock poisoned");
        let state = guard.as_mut().ok_or(InteractiveInputError::Closed)?;
        self.native_motion_path(state, point, check, wait)
            .map_err(native)
    }

    pub(crate) fn start_native_drag(
        &self,
        point: [i16; 2],
        check: &dyn Fn() -> Result<(), TargetedInputError>,
        wait: &dyn Fn(std::time::Duration) -> Result<(), TargetedInputError>,
    ) -> Result<(), InteractiveInputError> {
        check().map_err(native)?;
        self.require_native_desktop()?;
        let mut guard = self
            .state
            .lock()
            .expect("native desktop state lock poisoned");
        let state = guard.as_mut().ok_or(InteractiveInputError::Closed)?;
        self.native_motion_path(state, point, check, wait)
            .map_err(native)?;
        self.motion(state, i32::from(point[0]), i32::from(point[1]))
            .map_err(native)?;
        x::sync(&state.conn).map_err(native)?;
        // Track a possible press immediately before its actual wire edge;
        // an earlier failed motion must not invent a held physical button.
        check().map_err(native)?;
        state.held_buttons.insert(x::XBUTTON_LEFT);
        x::fake_button(&state.conn, true, x::XBUTTON_LEFT, state.root).map_err(native)?;
        x::sync(&state.conn).map_err(native)
    }

    /// A successful return means all release edges and the server ACK arrived.
    /// Failure retains the exact connection and held state for original cleanup.
    pub(crate) fn release_native_desktop(&self) -> Result<(), InteractiveInputError> {
        self.require_native_desktop()?;
        let mut guard = self
            .state
            .lock()
            .expect("native desktop state lock poisoned");
        let Some(state) = guard.as_mut() else {
            return Ok(());
        };
        let mut failures = Vec::new();
        let mut retained = Vec::new();
        for code in state.native_held_keys.iter().rev() {
            if let Err(error) = x::fake_key(&state.conn, false, *code, state.root)
                .and_then(|()| x::sync(&state.conn))
            {
                retained.push(*code);
                failures.push(error.to_string());
            }
            super::native_window::native_key_release_pause();
        }
        retained.reverse();
        state.native_held_keys = retained;
        for key in state.held_keys.iter().cloned().collect::<Vec<_>>() {
            if let Err(error) = self.key_edge(state, &key, false, &[]) {
                failures.push(error.to_string());
            }
        }
        for button in state.held_buttons.iter().copied().collect::<Vec<_>>() {
            // Release at the actual current pointer, without moving it back to
            // a cached point after external input or atomic relative movement.
            if let Err(error) = x::fake_button(&state.conn, false, button, state.root) {
                failures.push(error.to_string());
            }
        }
        if let Err(error) = x::sync(&state.conn) {
            failures.push(error.to_string());
        }
        if !failures.is_empty() {
            return Err(InteractiveInputError::Native(failures.join("; ")));
        }
        state.held_keys.clear();
        state.held_buttons.clear();
        *guard = None;
        Ok(())
    }
}

// Native move_path 88090: ceil(hypot(dx,dy)/160*10), clamp 1..10;
// inclusive samples, nearest-away rounding, adjacent duplicate suppression.
fn native_motion_points(start: [i16; 2], target: [i16; 2]) -> Vec<[i16; 2]> {
    if start == target {
        return vec![target];
    }
    let dx = f64::from(target[0]) - f64::from(start[0]);
    let dy = f64::from(target[1]) - f64::from(start[1]);
    let steps = ((dx.hypot(dy) / 160.0) * 10.0).ceil().clamp(1.0, 10.0) as u32;
    let mut points = Vec::with_capacity(steps as usize + 1);
    for step in 0..=steps {
        let fraction = f64::from(step) / f64::from(steps);
        let point = [
            (f64::from(start[0]) + dx * fraction)
                .round()
                .clamp(f64::from(i16::MIN), f64::from(i16::MAX)) as i16,
            (f64::from(start[1]) + dy * fraction)
                .round()
                .clamp(f64::from(i16::MIN), f64::from(i16::MAX)) as i16,
        ];
        if points.last() != Some(&point) {
            points.push(point);
        }
    }
    points
}

// Native drag differs from move_path: floor(hypot) with a minimum of one,
// inclusive integer interpolation, no deduplication, and one millisecond after
// every emitted point. The source release build uses 32-bit multiply/divide.
pub(super) fn native_drag_points(
    start: [i16; 2],
    target: [i16; 2],
) -> impl Iterator<Item = [i16; 2]> {
    let dx = i32::from(target[0]) - i32::from(start[0]);
    let dy = i32::from(target[1]) - i32::from(start[1]);
    let steps = f64::from(dx).hypot(f64::from(dy)).max(1.0) as i32;
    (0..=steps).map(move |step| {
        [
            i32::from(start[0]).wrapping_add(step.wrapping_mul(dx) / steps) as i16,
            i32::from(start[1]).wrapping_add(step.wrapping_mul(dy) / steps) as i16,
        ]
    })
}

#[cfg(test)]
mod native_motion_path_tests {
    use super::{native_drag_points, native_motion_points};

    #[test]
    fn original_drag_uses_integer_steps_and_keeps_stationary_duplicates() {
        assert_eq!(
            native_drag_points([1, 2], [1, 2]).collect::<Vec<_>>(),
            vec![[1, 2], [1, 2]]
        );
        assert_eq!(
            native_drag_points([0, 0], [-3, -1]).collect::<Vec<_>>(),
            vec![[0, 0], [-1, 0], [-2, 0], [-3, -1]]
        );
        assert_eq!(
            native_drag_points([0, 0], [1, 1]).collect::<Vec<_>>(),
            vec![[0, 0], [1, 1]]
        );
    }

    #[test]
    fn original_inclusive_interpolation_preserves_endpoints_and_ceil_boundary() {
        assert_eq!(native_motion_points([7, -2], [7, -2]), vec![[7, -2]]);
        assert_eq!(native_motion_points([0, 0], [16, 0]), vec![[0, 0], [16, 0]]);
        assert_eq!(
            native_motion_points([0, 0], [17, 0]),
            vec![[0, 0], [9, 0], [17, 0]]
        );
        assert_eq!(
            native_motion_points([0, 0], [-17, 0]),
            vec![[0, 0], [-9, 0], [-17, 0]]
        );
        let long = native_motion_points([i16::MIN, i16::MAX], [i16::MAX, i16::MIN]);
        assert_eq!(long.len(), 11);
        assert_eq!(long.first(), Some(&[i16::MIN, i16::MAX]));
        assert_eq!(long.last(), Some(&[i16::MAX, i16::MIN]));
        assert!(long.windows(2).all(|pair| pair[0] != pair[1]));
    }
}
