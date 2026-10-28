// SPDX-License-Identifier: MIT

//! Exact writes and held inputs belonging to one native helper generation.
//! Physical user input is neither queried nor recorded here.

use cua_driver_core::windows_interruption::{
    current_windows_input_binding, with_windows_input_worker,
};
use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, Condvar, Mutex},
};
use windows::Win32::{
    Foundation::{SetLastError, ERROR_OPERATION_ABORTED, HWND, LPARAM, WPARAM},
    UI::{
        Input::KeyboardAndMouse::{
            INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP,
            KEYEVENTF_SCANCODE, KEYEVENTF_UNICODE, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
            MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_RIGHTDOWN,
            MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, MOUSEINPUT,
        },
        WindowsAndMessaging::{
            GetWindowThreadProcessId, PostMessageW, WM_KEYDOWN, WM_KEYUP, WM_LBUTTONDBLCLK,
            WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MBUTTONDBLCLK, WM_MBUTTONDOWN, WM_MBUTTONUP,
            WM_MOUSEMOVE, WM_RBUTTONDBLCLK, WM_RBUTTONDOWN, WM_RBUTTONUP, WM_SYSKEYDOWN,
            WM_SYSKEYUP, WM_XBUTTONDBLCLK, WM_XBUTTONDOWN, WM_XBUTTONUP,
        },
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Held {
    Key(u16, u16, u32),
    Button(u32, u32),
    Posted {
        window: usize,
        code: u32,
        key: usize,
    },
}
enum Release {
    Input(INPUT),
    Posted {
        window: usize,
        thread: u32,
        process: u32,
        message: u32,
        key: usize,
        position: isize,
    },
}
#[derive(Default)]
struct Journal {
    closed: bool,
    writing: usize,
    held: HashMap<Held, Release>,
}
#[derive(Default)]
pub(crate) struct Inputs {
    journal: Mutex<Journal>,
    writes: Mutex<()>,
    settled: Condvar,
}

impl Inputs {
    fn begin(&self) -> Option<Writing<'_>> {
        // One exact native write and its inserted-prefix update are ordered
        // together, including direct SDK callers sharing this binding.
        let serial = self.writes.lock().ok()?;
        let mut journal = self.journal.lock().ok()?;
        if journal.closed
            || current_windows_input_binding().is_some_and(|binding| binding.check().is_err())
        {
            return None;
        }
        journal.writing += 1;
        Some(Writing(self, serial))
    }
    /// Close admission, settle each actual short Win32 write, then release only
    /// the inserted DOWN prefix. No user key state or arbitrary PID is queried.
    pub(crate) fn close(&self) -> Result<(), String> {
        let mut journal = self
            .journal
            .lock()
            .map_err(|_| "native input journal mutex poisoned")?;
        journal.closed = true;
        while journal.writing != 0 {
            journal = self
                .settled
                .wait(journal)
                .map_err(|_| "native input write settlement mutex poisoned")?;
        }
        let keys: Vec<_> = journal.held.keys().copied().collect();
        let mut failures = Vec::new();
        for key in keys {
            let Some(release) = journal.held.get(&key) else {
                continue;
            };
            let result = match release {
                Release::Input(input) => {
                    // SAFETY: this is the UP for an actual inserted DOWN. New
                    // native writes are closed and all previous writes settled.
                    let sent = unsafe {
                        windows::Win32::UI::Input::KeyboardAndMouse::SendInput(
                            std::slice::from_ref(input),
                            std::mem::size_of::<INPUT>() as i32,
                        )
                    };
                    if sent == 1 {
                        Ok(())
                    } else {
                        Err(format!(
                            "release owned native input: {}",
                            windows::core::Error::from_win32()
                        ))
                    }
                }
                Release::Posted {
                    window,
                    thread,
                    process,
                    message,
                    key,
                    position,
                } => {
                    let target = HWND(*window as *mut _);
                    let mut actual_process = 0;
                    // SAFETY: identifiers are observations of the same target
                    // which accepted this message, never borrowed user pointers.
                    let actual_thread =
                        unsafe { GetWindowThreadProcessId(target, Some(&mut actual_process)) };
                    if actual_thread != *thread || actual_process != *process {
                        Err(
                            "owned posted-input target no longer matches its actual thread/process"
                                .into(),
                        )
                    } else {
                        unsafe { PostMessageW(target, *message, WPARAM(*key), LPARAM(*position)) }
                            .map_err(|error| format!("release owned posted native input: {error}"))
                    }
                }
            };
            match result {
                Ok(()) => {
                    journal.held.remove(&key);
                }
                Err(error) => failures.push(error),
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
    fn inserted(&self, input: &INPUT) {
        let mut journal = self
            .journal
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if input.r#type == INPUT_KEYBOARD {
            // SAFETY: the discriminant selects the keyboard union member.
            let key = unsafe { input.Anonymous.ki };
            let identity = Held::Key(
                key.wVk.0,
                key.wScan,
                key.dwFlags.0 & (KEYEVENTF_UNICODE | KEYEVENTF_SCANCODE | KEYEVENTF_EXTENDEDKEY).0,
            );
            if key.dwFlags & KEYEVENTF_KEYUP == KEYEVENTF_KEYUP {
                journal.held.remove(&identity);
            } else {
                let mut release = key;
                release.dwFlags |= KEYEVENTF_KEYUP;
                journal.held.insert(
                    identity,
                    Release::Input(INPUT {
                        r#type: INPUT_KEYBOARD,
                        Anonymous: INPUT_0 { ki: release },
                    }),
                );
            }
        } else if input.r#type == INPUT_MOUSE {
            // SAFETY: the discriminant selects the mouse union member.
            let pointer = unsafe { input.Anonymous.mi };
            for (down, up, button) in [
                (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, 1),
                (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, 2),
                (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, 3),
                (MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, 4),
            ] {
                let data = if button == 4 { pointer.mouseData } else { 0 };
                let identity = Held::Button(button, data);
                if pointer.dwFlags & up == up {
                    journal.held.remove(&identity);
                } else if pointer.dwFlags & down == down {
                    journal.held.insert(
                        identity,
                        Release::Input(INPUT {
                            r#type: INPUT_MOUSE,
                            Anonymous: INPUT_0 {
                                mi: MOUSEINPUT {
                                    dx: 0,
                                    dy: 0,
                                    mouseData: data,
                                    dwFlags: up,
                                    time: 0,
                                    dwExtraInfo: pointer.dwExtraInfo,
                                },
                            },
                        }),
                    );
                }
            }
        }
    }
    fn posted(&self, target: HWND, message: u32, key: WPARAM, position: LPARAM) {
        let mut journal = self
            .journal
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if message == WM_MOUSEMOVE {
            for (held, release) in &mut journal.held {
                if matches!(held, Held::Posted { window, code, .. } if *window == target.0 as usize && !matches!(*code, WM_KEYDOWN | WM_SYSKEYDOWN))
                {
                    if let Release::Posted {
                        position: release_position,
                        ..
                    } = release
                    {
                        *release_position = position.0;
                    }
                }
            }
            return;
        }
        let (down, up, identity_key) = match message {
            WM_KEYDOWN | WM_KEYUP => (WM_KEYDOWN, WM_KEYUP, key.0),
            WM_SYSKEYDOWN | WM_SYSKEYUP => (WM_SYSKEYDOWN, WM_SYSKEYUP, key.0),
            WM_LBUTTONDOWN | WM_LBUTTONDBLCLK | WM_LBUTTONUP => (WM_LBUTTONDOWN, WM_LBUTTONUP, 0),
            WM_RBUTTONDOWN | WM_RBUTTONDBLCLK | WM_RBUTTONUP => (WM_RBUTTONDOWN, WM_RBUTTONUP, 0),
            WM_MBUTTONDOWN | WM_MBUTTONDBLCLK | WM_MBUTTONUP => (WM_MBUTTONDOWN, WM_MBUTTONUP, 0),
            WM_XBUTTONDOWN | WM_XBUTTONDBLCLK | WM_XBUTTONUP => {
                (WM_XBUTTONDOWN, WM_XBUTTONUP, key.0 >> 16)
            }
            _ => return,
        };
        let identity = Held::Posted {
            window: target.0 as usize,
            code: down,
            key: identity_key,
        };
        if message == up {
            journal.held.remove(&identity);
            return;
        }
        let mut process = 0;
        // SAFETY: observe only the target to which the actual write succeeded.
        let thread = unsafe { GetWindowThreadProcessId(target, Some(&mut process)) };
        let is_key = matches!(down, WM_KEYDOWN | WM_SYSKEYDOWN);
        journal.held.insert(
            identity,
            Release::Posted {
                window: target.0 as usize,
                thread,
                process,
                message: up,
                key: if is_key {
                    key.0
                } else if down == WM_XBUTTONDOWN {
                    key.0 & 0xffff0000
                } else {
                    0
                },
                position: if is_key {
                    position.0 | (3_isize << 30)
                } else {
                    position.0
                },
            },
        );
    }
}
struct Writing<'a>(
    &'a Inputs,
    #[allow(dead_code)] std::sync::MutexGuard<'a, ()>,
);
impl Drop for Writing<'_> {
    fn drop(&mut self) {
        let mut journal = self
            .0
            .journal
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        journal.writing -= 1;
        self.0.settled.notify_all();
    }
}

tokio::task_local! { static INPUTS: Arc<Inputs>; }
thread_local! { static WORKER_INPUTS: std::cell::RefCell<Option<Arc<Inputs>>> = const { std::cell::RefCell::new(None) }; }
fn current() -> Option<Arc<Inputs>> {
    INPUTS
        .try_with(Arc::clone)
        .ok()
        .or_else(|| WORKER_INPUTS.with(|slot| slot.borrow().clone()))
}
pub(crate) async fn scope<T>(inputs: Arc<Inputs>, call: impl Future<Output = T>) -> T {
    INPUTS.scope(inputs, call).await
}

pub(crate) fn spawn_blocking<F, T>(call: F) -> tokio::task::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let inputs = current();
    let binding = current_windows_input_binding();
    let custody = cua_driver_core::tool::current_native_input_worker_lease();
    tokio::task::spawn_blocking(move || {
        struct Restore(Option<Arc<Inputs>>);
        impl Drop for Restore {
            fn drop(&mut self) {
                WORKER_INPUTS.with(|slot| {
                    slot.replace(self.0.take());
                });
            }
        }
        let _restore = Restore(WORKER_INPUTS.with(|slot| slot.replace(inputs)));
        let _accepted_native_worker = custody;
        match binding {
            Some(binding) => with_windows_input_worker(binding, call),
            None => call(),
        }
    })
}

/// Same Win32 boundary and return value; record only the successfully inserted
/// prefix. Failed or refused writes cannot invent held input ownership.
pub(crate) unsafe fn send_input(inputs: &[INPUT], size: i32) -> u32 {
    let Some(owner) = current() else {
        return unsafe { windows::Win32::UI::Input::KeyboardAndMouse::SendInput(inputs, size) };
    };
    let Some(_writing) = owner.begin() else {
        unsafe { SetLastError(ERROR_OPERATION_ABORTED) };
        return 0;
    };
    let sent = unsafe { windows::Win32::UI::Input::KeyboardAndMouse::SendInput(inputs, size) };
    for input in inputs.iter().take(sent as usize) {
        owner.inserted(input);
    }
    sent
}

pub(crate) unsafe fn post_message(
    target: HWND,
    message: u32,
    key: WPARAM,
    position: LPARAM,
) -> windows::core::Result<()> {
    let Some(owner) = current() else {
        return unsafe { PostMessageW(target, message, key, position) };
    };
    let Some(_writing) = owner.begin() else {
        unsafe { SetLastError(ERROR_OPERATION_ABORTED) };
        return Err(windows::core::Error::from_win32());
    };
    unsafe { PostMessageW(target, message, key, position) }?;
    owner.posted(target, message, key, position);
    Ok(())
}

pub(crate) unsafe fn set_cursor_pos(x: i32, y: i32) -> windows::core::Result<()> {
    let Some(owner) = current() else {
        return unsafe { windows::Win32::UI::WindowsAndMessaging::SetCursorPos(x, y) };
    };
    let Some(_writing) = owner.begin() else {
        unsafe { SetLastError(ERROR_OPERATION_ABORTED) };
        return Err(windows::core::Error::from_win32());
    };
    unsafe { windows::Win32::UI::WindowsAndMessaging::SetCursorPos(x, y) }
}

pub(crate) unsafe fn set_foreground_window(target: HWND) -> windows::Win32::Foundation::BOOL {
    let Some(owner) = current() else {
        return unsafe { windows::Win32::UI::WindowsAndMessaging::SetForegroundWindow(target) };
    };
    let Some(_writing) = owner.begin() else {
        unsafe { SetLastError(ERROR_OPERATION_ABORTED) };
        return windows::Win32::Foundation::BOOL(0);
    };
    unsafe { windows::Win32::UI::WindowsAndMessaging::SetForegroundWindow(target) }
}

pub(crate) unsafe fn set_window_pos(
    target: HWND,
    after: HWND,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    flags: windows::Win32::UI::WindowsAndMessaging::SET_WINDOW_POS_FLAGS,
) -> windows::core::Result<()> {
    let Some(owner) = current() else {
        return unsafe {
            windows::Win32::UI::WindowsAndMessaging::SetWindowPos(
                target, after, x, y, width, height, flags,
            )
        };
    };
    let Some(_writing) = owner.begin() else {
        unsafe { SetLastError(ERROR_OPERATION_ABORTED) };
        return Err(windows::core::Error::from_win32());
    };
    unsafe {
        windows::Win32::UI::WindowsAndMessaging::SetWindowPos(
            target, after, x, y, width, height, flags,
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TargetWindow {
    window: usize,
    thread: u32,
    process: u32,
}
impl TargetWindow {
    pub(crate) fn observe(window: HWND) -> Self {
        let mut process = 0;
        let thread = unsafe { GetWindowThreadProcessId(window, Some(&mut process)) };
        Self {
            window: window.0 as usize,
            thread,
            process,
        }
    }
    pub(crate) fn resolve(&self) -> Result<Option<HWND>, String> {
        let window = HWND(self.window as *mut _);
        if !unsafe { windows::Win32::UI::WindowsAndMessaging::IsWindow(window) }.as_bool() {
            return Ok(None);
        }
        let mut process = 0;
        let thread = unsafe { GetWindowThreadProcessId(window, Some(&mut process)) };
        if thread != self.thread || process != self.process {
            return Err("owned native window no longer matches its observed thread/process".into());
        }
        Ok(Some(window))
    }
}

struct TopmostState {
    target: TargetWindow,
    state: Mutex<(bool, bool)>,
}
impl NativeInputRelease for TopmostState {
    fn release(&self) -> Result<(), String> {
        use windows::Win32::UI::WindowsAndMessaging::{
            GetWindowLongPtrW, SetWindowPos, GWL_EXSTYLE, HWND_NOTOPMOST, SWP_NOACTIVATE,
            SWP_NOMOVE, SWP_NOSIZE, WS_EX_TOPMOST,
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| "native topmost guard mutex poisoned")?;
        state.1 = true;
        if state.0 {
            if let Some(target) = self.target.resolve()? {
                unsafe {
                    if GetWindowLongPtrW(target, GWL_EXSTYLE) as u32 & WS_EX_TOPMOST.0 != 0 {
                        SetWindowPos(
                            target,
                            HWND_NOTOPMOST,
                            0,
                            0,
                            0,
                            0,
                            SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE,
                        )
                        .map_err(|error| format!("restore owned native topmost bit: {error}"))?;
                        if GetWindowLongPtrW(target, GWL_EXSTYLE) as u32 & WS_EX_TOPMOST.0 != 0 {
                            return Err("owned native topmost bit remains set".into());
                        }
                    }
                }
            }
            state.0 = false;
        }
        Ok(())
    }
}
impl Drop for TopmostState {
    fn drop(&mut self) {
        let _ = self.release();
    }
}
pub(crate) struct TopmostGuard {
    guard: Arc<TopmostState>,
    _receipt: Option<NativeInputReceipt>,
}
impl TopmostGuard {
    pub(crate) fn raise(target: HWND) -> Self {
        use windows::Win32::UI::WindowsAndMessaging::{
            GetWindowLongPtrW, SetWindowPos, GWL_EXSTYLE, HWND_TOPMOST, SWP_NOACTIVATE, SWP_NOMOVE,
            SWP_NOSIZE, WS_EX_TOPMOST,
        };
        let guard = Arc::new(TopmostState {
            target: TargetWindow::observe(target),
            state: Mutex::new((false, false)),
        });
        let receipt = match current_windows_input_binding() {
            Some(binding) => match binding.retain_input_release(guard.clone()) {
                Ok(receipt) => Some(receipt),
                Err(_) => {
                    let _ = guard.release();
                    return Self {
                        guard,
                        _receipt: None,
                    };
                }
            },
            None => None,
        };
        {
            let mut state = guard
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if !state.1
                && unsafe { GetWindowLongPtrW(target, GWL_EXSTYLE) as u32 } & WS_EX_TOPMOST.0 == 0
            {
                let _ = unsafe {
                    SetWindowPos(
                        target,
                        HWND_TOPMOST,
                        0,
                        0,
                        0,
                        0,
                        SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE,
                    )
                };
                state.0 =
                    unsafe { GetWindowLongPtrW(target, GWL_EXSTYLE) as u32 } & WS_EX_TOPMOST.0 != 0;
            }
        }
        Self {
            guard,
            _receipt: receipt,
        }
    }
}
impl Drop for TopmostGuard {
    fn drop(&mut self) {
        let _ = self.guard.release();
    }
}

use cua_driver_core::windows_interruption::{NativeInputReceipt, NativeInputRelease};
use windows::Win32::{
    Foundation::{HANDLE, POINT, RECT},
    UI::{
        Controls::{HSYNTHETICPOINTERDEVICE, POINTER_TYPE_INFO, POINTER_TYPE_INFO_0},
        Input::Pointer::{
            POINTER_FLAG_DOWN, POINTER_FLAG_UP, POINTER_FLAG_UPDATE, POINTER_INFO,
            POINTER_PEN_INFO, POINTER_TOUCH_INFO,
        },
        WindowsAndMessaging::{PT_PEN, PT_TOUCH},
    },
};

enum ContactStyle {
    Pen {
        flags: u32,
        mask: u32,
        pressure: u32,
        rotation: u32,
        tilt_x: i32,
        tilt_y: i32,
    },
    Touch {
        flags: u32,
        mask: u32,
        contact: RECT,
        raw_contact: RECT,
        orientation: u32,
        pressure: u32,
    },
}
struct Contact {
    id: u32,
    position: POINT,
    style: ContactStyle,
}
impl Contact {
    fn from_input(input: &POINTER_TYPE_INFO) -> Result<Self, String> {
        if input.r#type == PT_PEN {
            // SAFETY: these internal helpers only construct the selected member.
            let pen = unsafe { input.Anonymous.penInfo };
            Ok(Self {
                id: pen.pointerInfo.pointerId,
                position: pen.pointerInfo.ptPixelLocation,
                style: ContactStyle::Pen {
                    flags: pen.penFlags,
                    mask: pen.penMask,
                    pressure: pen.pressure,
                    rotation: pen.rotation,
                    tilt_x: pen.tiltX,
                    tilt_y: pen.tiltY,
                },
            })
        } else if input.r#type == PT_TOUCH {
            let touch = unsafe { input.Anonymous.touchInfo };
            Ok(Self {
                id: touch.pointerInfo.pointerId,
                position: touch.pointerInfo.ptPixelLocation,
                style: ContactStyle::Touch {
                    flags: touch.touchFlags,
                    mask: touch.touchMask,
                    contact: touch.rcContact,
                    raw_contact: touch.rcContactRaw,
                    orientation: touch.orientation,
                    pressure: touch.pressure,
                },
            })
        } else {
            Err("unsupported owned native pointer kind".into())
        }
    }
    fn up(&self) -> POINTER_TYPE_INFO {
        let kind = match self.style {
            ContactStyle::Pen { .. } => PT_PEN,
            ContactStyle::Touch { .. } => PT_TOUCH,
        };
        let pointer = POINTER_INFO {
            pointerType: kind,
            pointerId: self.id,
            pointerFlags: POINTER_FLAG_UP,
            sourceDevice: HANDLE::default(),
            hwndTarget: HWND::default(),
            ptPixelLocation: self.position,
            ..Default::default()
        };
        match &self.style {
            ContactStyle::Pen {
                flags,
                mask,
                pressure,
                rotation,
                tilt_x,
                tilt_y,
            } => POINTER_TYPE_INFO {
                r#type: kind,
                Anonymous: POINTER_TYPE_INFO_0 {
                    penInfo: POINTER_PEN_INFO {
                        pointerInfo: pointer,
                        penFlags: *flags,
                        penMask: *mask,
                        pressure: *pressure,
                        rotation: *rotation,
                        tiltX: *tilt_x,
                        tiltY: *tilt_y,
                    },
                },
            },
            ContactStyle::Touch {
                flags,
                mask,
                contact,
                raw_contact,
                orientation,
                pressure,
            } => POINTER_TYPE_INFO {
                r#type: kind,
                Anonymous: POINTER_TYPE_INFO_0 {
                    touchInfo: POINTER_TOUCH_INFO {
                        pointerInfo: pointer,
                        touchFlags: *flags,
                        touchMask: *mask,
                        rcContact: *contact,
                        rcContactRaw: *raw_contact,
                        orientation: *orientation,
                        pressure: *pressure,
                    },
                },
            },
        }
    }
}
struct PointerState {
    closed: bool,
    destroyed: bool,
    held: Option<Contact>,
}
struct PointerLease {
    device: usize,
    owns_device: bool,
    state: Mutex<PointerState>,
}
impl PointerLease {
    fn device(&self) -> HSYNTHETICPOINTERDEVICE {
        HSYNTHETICPOINTERDEVICE(self.device as *mut _)
    }
    fn send(&self, inputs: &[POINTER_TYPE_INFO]) -> windows::core::Result<()> {
        let mut state = self.state.lock().map_err(|_| {
            windows::core::Error::new(
                windows::core::HRESULT(0x80004005_u32 as i32),
                "owned native pointer mutex poisoned",
            )
        })?;
        if state.closed
            || current_windows_input_binding().is_some_and(|binding| binding.check().is_err())
        {
            return Err(windows::core::Error::new(
                windows::core::HRESULT(0x80004004_u32 as i32),
                "native pointer owner retired",
            ));
        }
        // Keep the short actual injection and ownership update in one native
        // resource lock. Cleanup never needs the persistent-device mutex held
        // by a stroke or an unrelated UIA provider.
        // Existing callers inject one pointer per stroke. Validate before the
        // native write so an unsupported batch cannot lose an earlier DOWN.
        if inputs.len() != 1 {
            return Err(windows::core::Error::new(
                windows::core::HRESULT(0x80070057_u32 as i32),
                "owned native stroke requires exactly one pointer",
            ));
        }
        let input = &inputs[0];
        let contact = Contact::from_input(input).map_err(|error| {
            windows::core::Error::new(windows::core::HRESULT(0x80070057_u32 as i32), error)
        })?;
        if state
            .held
            .as_ref()
            .is_some_and(|held| held.id != contact.id)
        {
            return Err(windows::core::Error::new(
                windows::core::HRESULT(0x80070057_u32 as i32),
                "owned native stroke cannot replace a held pointer",
            ));
        }
        let flags = if input.r#type == PT_PEN {
            unsafe { input.Anonymous.penInfo.pointerInfo.pointerFlags }
        } else {
            unsafe { input.Anonymous.touchInfo.pointerInfo.pointerFlags }
        };
        if flags & POINTER_FLAG_DOWN == POINTER_FLAG_DOWN && state.held.is_some() {
            return Err(windows::core::Error::new(
                windows::core::HRESULT(0x80070057_u32 as i32),
                "owned native stroke already has a held pointer",
            ));
        }
        if state.held.as_ref().is_some_and(|held| {
            std::mem::discriminant(&held.style) != std::mem::discriminant(&contact.style)
        }) {
            return Err(windows::core::Error::new(
                windows::core::HRESULT(0x80070057_u32 as i32),
                "owned native stroke cannot change pointer kind",
            ));
        }
        unsafe {
            windows::Win32::UI::Input::Pointer::InjectSyntheticPointerInput(self.device(), inputs)
        }?;
        if flags & POINTER_FLAG_UP == POINTER_FLAG_UP {
            if state
                .held
                .as_ref()
                .is_some_and(|held| held.id == contact.id)
            {
                state.held = None;
            }
        } else if flags & POINTER_FLAG_DOWN == POINTER_FLAG_DOWN {
            state.held = Some(contact);
        } else if flags & POINTER_FLAG_UPDATE == POINTER_FLAG_UPDATE
            && state
                .held
                .as_ref()
                .is_some_and(|held| held.id == contact.id)
        {
            state.held = Some(contact);
        }
        Ok(())
    }
}
impl NativeInputRelease for PointerLease {
    fn phase(&self) -> cua_driver_core::windows_interruption::NativeReleasePhase {
        cua_driver_core::windows_interruption::NativeReleasePhase::ReleaseInput
    }
    fn release(&self) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "owned native pointer mutex poisoned")?;
        state.closed = true;
        if let Some(contact) = &state.held {
            let up = contact.up();
            unsafe {
                windows::Win32::UI::Input::Pointer::InjectSyntheticPointerInput(
                    self.device(),
                    &[up],
                )
            }
            .map_err(|error| format!("release owned native pointer contact: {error}"))?;
            state.held = None;
        }
        if self.owns_device && !state.destroyed {
            // This API has no error result. Contact UP above must succeed first;
            // final native process exit separately settles its kernel objects.
            unsafe { windows::Win32::UI::Controls::DestroySyntheticPointerDevice(self.device()) };
            state.destroyed = true;
        }
        Ok(())
    }
}
impl Drop for PointerLease {
    fn drop(&mut self) {
        let _ = self.release();
    }
}
pub(crate) struct PointerStroke {
    lease: Arc<PointerLease>,
    _receipt: Option<NativeInputReceipt>,
}
impl PointerStroke {
    pub(crate) fn new(device: HSYNTHETICPOINTERDEVICE, owns_device: bool) -> anyhow::Result<Self> {
        let lease = Arc::new(PointerLease {
            device: device.0 as usize,
            owns_device,
            state: Mutex::new(PointerState {
                closed: false,
                destroyed: false,
                held: None,
            }),
        });
        let receipt = match current_windows_input_binding() {
            Some(binding) => Some(
                binding
                    .retain_input_release(lease.clone())
                    .map_err(|error| anyhow::anyhow!(error))?,
            ),
            None => None,
        };
        Ok(Self {
            lease,
            _receipt: receipt,
        })
    }
    pub(crate) fn send(&self, inputs: &[POINTER_TYPE_INFO]) -> windows::core::Result<()> {
        self.lease.send(inputs)
    }
    pub(crate) fn close(&self) -> anyhow::Result<()> {
        self.lease.release().map_err(|error| anyhow::anyhow!(error))
    }
}
impl Drop for PointerStroke {
    fn drop(&mut self) {
        let _ = self.lease.release();
    }
}
