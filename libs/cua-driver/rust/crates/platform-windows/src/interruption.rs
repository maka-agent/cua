// SPDX-License-Identifier: MIT

//! Windows native input-interruption resource. No model or serialized authority.
//!
//! The owner supplies an actual bound producer. It must keep this resource in
//! the existing desktop actor, start it only inside admitted input, and await
//! `close` on a blocking worker before confirming turn/epoch cleanup.

pub use cua_driver_core::windows_interruption::{InterruptionSink, PhysicalInput};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyboardDecision {
    Forward,
    Activity,
    Escape,
}

fn keyboard_decision(code: i32, message: usize, vk: u32, flags: u32) -> KeyboardDecision {
    if code != 0 || !matches!(message, 0x100 | 0x104) || flags & 0x10 != 0 {
        return KeyboardDecision::Forward;
    }
    if vk == 0x1b {
        KeyboardDecision::Escape
    } else {
        KeyboardDecision::Activity
    }
}

fn mouse_activity(code: i32, message: usize, flags: u32) -> bool {
    code == 0
        && flags & 1 == 0
        && message
            .checked_sub(0x201)
            .is_some_and(|offset| offset <= 9 && (0x249_u32 & (1_u32 << offset)) != 0)
}

// A panic may be held only while independent physical cleanup is attempted.
// It is resumed at the ordinary Rust boundary, never converted into a resource
// error or permission to continue. Native Result::Err keeps its existing debt.
#[cfg(target_os = "windows")]
#[derive(Default)]
struct Cleanup {
    failures: Vec<String>,
    panic: Option<Box<dyn std::any::Any + Send>>,
}
#[cfg(target_os = "windows")]
impl Cleanup {
    fn attempt(&mut self, cleanup: impl FnOnce() -> Result<(), String>) {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(cleanup)) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => self.failures.push(error),
            Err(payload) if self.panic.is_none() => self.panic = Some(payload),
            // Dropping an arbitrary second payload can itself panic and skip
            // the remaining cleanup. Preserve the first on this terminal path.
            Err(secondary) => std::mem::forget(secondary),
        }
    }
    fn finish(self) -> Vec<String> {
        if let Some(payload) = self.panic {
            std::panic::resume_unwind(payload);
        }
        self.failures
    }
}

#[cfg(target_os = "windows")]
mod native {
    use super::{
        keyboard_decision, mouse_activity, InterruptionSink, KeyboardDecision, PhysicalInput,
    };
    use std::{
        cell::Cell,
        panic::{catch_unwind, resume_unwind, AssertUnwindSafe},
        rc::Rc,
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc, Arc,
        },
        thread::{self, JoinHandle},
    };
    use tokio::sync::watch;
    use windows::Win32::{
        Foundation::{
            CloseHandle, HANDLE, HINSTANCE, LPARAM, LRESULT, WAIT_FAILED, WAIT_OBJECT_0, WPARAM,
        },
        System::{
            LibraryLoader::GetModuleHandleW,
            Threading::{CreateEventW, SetEvent},
        },
        UI::WindowsAndMessaging::{
            CallNextHookEx, DispatchMessageW, MsgWaitForMultipleObjectsEx, PeekMessageW,
            SetWindowsHookExW, TranslateMessage, UnhookWindowsHookEx, HHOOK, KBDLLHOOKSTRUCT, MSG,
            MSLLHOOKSTRUCT, MWMO_INPUTAVAILABLE, PM_NOREMOVE, PM_REMOVE, QS_ALLINPUT,
            WH_KEYBOARD_LL, WH_MOUSE_LL, WM_APP, WM_QUIT,
        },
    };

    /// An owned event HANDLE stored as an address so the wrapper can cross
    /// threads without asserting Send/Sync for unrelated Win32 handle types.
    struct StopEvent(usize);
    impl StopEvent {
        fn new() -> Result<Self, String> {
            // SAFETY: no security/name pointers; the returned handle is owned.
            unsafe { CreateEventW(None, true, false, None) }
                .map(|event| Self(event.0 as usize))
                .map_err(|error| format!("create native interruption stop event: {error}"))
        }
        fn handle(&self) -> HANDLE {
            HANDLE(self.0 as *mut _)
        }
        fn signal(&self) -> Result<(), String> {
            // SAFETY: Arc ownership keeps this event open through every wait.
            unsafe { SetEvent(self.handle()) }
                .map_err(|error| format!("signal native interruption stop: {error}"))
        }
    }
    impl Drop for StopEvent {
        fn drop(&mut self) {
            // SAFETY: the last Arc owns the single event handle.
            let _ = unsafe { CloseHandle(self.handle()) };
        }
    }

    struct CallbackState {
        sink: Arc<dyn InterruptionSink>,
        escape_sent: AtomicBool,
        stop: Arc<StopEvent>,
    }
    enum CallbackFailure {
        Native(String),
        Panicked(Box<dyn std::any::Any + Send>),
        Transferred,
    }
    struct CallbackContext {
        state: Arc<CallbackState>,
        // Low-level callbacks and this slot belong to the installing thread.
        // Cell avoids poisoning or a RefCell borrow panic inside the ABI guard.
        failure: Cell<Option<CallbackFailure>>,
    }
    impl CallbackContext {
        fn fail(&self, failure: CallbackFailure) {
            let previous = self.failure.take();
            // An earlier native error must never hide a later original panic.
            let failure = match (previous, failure) {
                (
                    Some(previous @ CallbackFailure::Panicked(_)),
                    CallbackFailure::Panicked(secondary),
                ) => {
                    std::mem::forget(secondary);
                    previous
                }
                (Some(previous @ CallbackFailure::Panicked(_)), CallbackFailure::Native(_)) => {
                    previous
                }
                (_, failure @ CallbackFailure::Panicked(_)) | (None, failure) => failure,
                (Some(previous), _) => previous,
            };
            self.failure.set(Some(failure));
            // SAFETY: this exact owned event remains open through callbacks.
            // Signalling is a stop request, never physical cleanup proof.
            let _ = unsafe { SetEvent(self.state.stop.handle()) };
        }
        fn failed(&self) -> bool {
            let failure = self.failure.take();
            let failed = failure.is_some();
            self.failure.set(failure);
            failed
        }
        fn emit(&self, input: PhysicalInput) {
            if self.failed()
                || (input == PhysicalInput::Escape
                    && self.state.escape_sent.swap(true, Ordering::AcqRel))
            {
                return;
            }
            if let Err(reason) = self.state.sink.notify(input) {
                self.fail(CallbackFailure::Native(reason));
            }
            if input == PhysicalInput::Escape {
                // Stop only this physical native resource, never another Run.
                if let Err(reason) = self.state.stop.signal() {
                    self.fail(CallbackFailure::Native(reason));
                }
            }
        }
        fn guard<T>(&self, call: impl FnOnce() -> T) -> Option<T> {
            // This is the real OS callback boundary. Hold the original payload
            // on this thread, return through the ABI, then unhook before unwind.
            match catch_unwind(AssertUnwindSafe(call)) {
                Ok(value) => Some(value),
                Err(payload) => {
                    self.fail(CallbackFailure::Panicked(payload));
                    None
                }
            }
        }
    }

    thread_local! {
        // Physical hook custody, not a permission registry. Never hold a TLS
        // borrow across sink.notify: it can synchronously reenter a callback.
        static CALLBACK: Cell<Option<Rc<CallbackContext>>> = const { Cell::new(None) };
    }
    fn callback_context() -> Option<Rc<CallbackContext>> {
        CALLBACK
            .try_with(|slot| {
                let current = slot.take();
                slot.set(current.clone());
                current
            })
            .ok()
            .flatten()
    }

    unsafe extern "system" fn keyboard(code: i32, message: WPARAM, data: LPARAM) -> LRESULT {
        if let Some(context) = callback_context().filter(|_| code == 0 && data.0 != 0) {
            let consumed = Cell::new(false);
            let _ = context.guard(|| {
                // SAFETY: HC_ACTION supplies this struct for this callback only.
                let key = unsafe { &*(data.0 as *const KBDLLHOOKSTRUCT) };
                match keyboard_decision(code, message.0, key.vkCode, key.flags.0) {
                    KeyboardDecision::Escape => {
                        // Preserve physical Esc routing even if notify panics.
                        consumed.set(true);
                        context.emit(PhysicalInput::Escape);
                    }
                    KeyboardDecision::Activity => {
                        context.emit(PhysicalInput::Activity);
                    }
                    KeyboardDecision::Forward => {}
                }
            });
            if consumed.get() {
                return LRESULT(1);
            }
        }
        // SAFETY: forward the original hook arguments without retaining them.
        unsafe { CallNextHookEx(HHOOK::default(), code, message, data) }
    }

    unsafe extern "system" fn mouse(code: i32, message: WPARAM, data: LPARAM) -> LRESULT {
        if let Some(context) = callback_context().filter(|_| code == 0 && data.0 != 0) {
            let _ = context.guard(|| {
                // SAFETY: same callback-lifetime OS contract as keyboard.
                let pointer = unsafe { &*(data.0 as *const MSLLHOOKSTRUCT) };
                if mouse_activity(code, message.0, pointer.flags) {
                    context.emit(PhysicalInput::Activity);
                }
            });
        }
        // Activity observation never swallows a mouse event.
        unsafe { CallNextHookEx(HHOOK::default(), code, message, data) }
    }

    fn unhook(hook: HHOOK, label: &str) -> Result<(), String> {
        // SAFETY: only the installing thread owns and releases this hook.
        unsafe { UnhookWindowsHookEx(hook) }
            .map_err(|error| format!("unhook native {label} interruption monitor: {error}"))
    }

    fn run(
        state: Arc<CallbackState>,
        ready: mpsc::SyncSender<Result<(), String>>,
    ) -> Result<(), String> {
        let mut key = None;
        let mut pointer = None;
        let mut cleanup = super::Cleanup::default();
        cleanup.attempt(|| {
            // SAFETY: current module and callback ABI are valid for these hooks.
            let module = unsafe { GetModuleHandleW(None) }
                .map_err(|error| format!("resolve native interruption module: {error}"))?;
            key = Some(
                unsafe {
                    SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard), HINSTANCE(module.0), 0)
                }
                .map_err(|error| {
                    format!("install native keyboard interruption monitor: {error}")
                })?,
            );
            pointer = Some(
                unsafe { SetWindowsHookExW(WH_MOUSE_LL, Some(mouse), HINSTANCE(module.0), 0) }
                    .map_err(|error| {
                        format!("install native mouse interruption monitor: {error}")
                    })?,
            );
            let mut message = MSG::default();
            // SAFETY: establish the installing thread's message queue before ready.
            let _ = unsafe { PeekMessageW(&mut message, None, 0, 0, PM_NOREMOVE) };
            CALLBACK.with(|slot| {
                slot.set(Some(Rc::new(CallbackContext {
                    state: state.clone(),
                    failure: Cell::new(None),
                })))
            });
            if ready.send(Ok(())).is_err() {
                Err("native interruption startup observer disappeared".into())
            } else {
                'messages: loop {
                    // SAFETY: the owned event remains open and messages are pumped
                    // on the installing thread. A stop wake is not completion proof;
                    // the actual unhook and thread result below provide that proof.
                    let event = unsafe {
                        MsgWaitForMultipleObjectsEx(
                            Some(&[state.stop.handle()]),
                            u32::MAX,
                            QS_ALLINPUT,
                            MWMO_INPUTAVAILABLE,
                        )
                    };
                    if event == WAIT_OBJECT_0 {
                        break Ok(());
                    }
                    if event == WAIT_FAILED {
                        break Err(format!(
                            "native interruption message wait: {}",
                            windows::core::Error::from_win32()
                        ));
                    }
                    if event.0 != WAIT_OBJECT_0.0 + 1 {
                        break Err(format!(
                            "unexpected native interruption wait result: {}",
                            event.0
                        ));
                    }
                    while unsafe { PeekMessageW(&mut message, None, 0, 0, PM_REMOVE) }.as_bool() {
                        if message.message == WM_QUIT || message.message == WM_APP + 1 {
                            break 'messages Ok(());
                        }
                        unsafe {
                            let _ = TranslateMessage(&message);
                            DispatchMessageW(&message);
                        }
                    }
                }
            }
        });
        // A callback panic happened before any teardown. Preserve it as the
        // original even if an independent unhook also panics. Keep the TLS
        // terminal marker until clear so teardown cannot call the sink again.
        if let Some(context) = callback_context() {
            let failure = context.failure.replace(Some(CallbackFailure::Transferred));
            match failure {
                Some(CallbackFailure::Panicked(payload)) => {
                    if let Some(secondary) = cleanup.panic.replace(payload) {
                        std::mem::forget(secondary);
                    }
                }
                Some(CallbackFailure::Native(reason)) => cleanup.failures.push(reason),
                Some(CallbackFailure::Transferred) | None => {}
            }
        }
        // Attempt every independent cleanup before rethrowing the original
        // panic. Native unhook failures remain unconfirmed, never fake ACKs.
        cleanup.attempt(|| pointer.take().map_or(Ok(()), |hook| unhook(hook, "mouse")));
        cleanup.attempt(|| key.take().map_or(Ok(()), |hook| unhook(hook, "keyboard")));
        cleanup.attempt(|| {
            let context = CALLBACK.with(Cell::take);
            match context.and_then(|context| context.failure.take()) {
                Some(CallbackFailure::Native(reason)) => Err(reason),
                Some(CallbackFailure::Panicked(payload)) => resume_unwind(payload),
                Some(CallbackFailure::Transferred) | None => Ok(()),
            }
        });
        let failures = cleanup.finish();
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }

    #[derive(Clone, Copy)]
    enum MonitorCompletion {
        Running,
        Returned,
        Panicked,
    }

    fn monitor_worker(
        call: impl FnOnce() -> Result<(), String>,
        finished: watch::Sender<MonitorCompletion>,
    ) -> Result<(), String> {
        match catch_unwind(AssertUnwindSafe(call)) {
            Ok(result) => {
                finished.send_replace(MonitorCompletion::Returned);
                result
            }
            Err(payload) => {
                finished.send_replace(MonitorCompletion::Panicked);
                resume_unwind(payload)
            }
        }
    }

    fn monitor_finished(completion: &watch::Receiver<MonitorCompletion>) -> bool {
        !matches!(*completion.borrow(), MonitorCompletion::Running)
            || completion.has_changed().is_err()
    }

    pub struct WindowsInterruptionMonitor {
        stop: Arc<StopEvent>,
        thread: Option<JoinHandle<Result<(), String>>>,
        completion: watch::Receiver<MonitorCompletion>,
    }
    impl WindowsInterruptionMonitor {
        /// Blocking native startup. Run on the existing blocking worker.
        pub fn start(sink: Arc<dyn InterruptionSink>) -> Result<Self, String> {
            let stop = Arc::new(StopEvent::new()?);
            let state = Arc::new(CallbackState {
                sink,
                escape_sent: AtomicBool::new(false),
                stop: stop.clone(),
            });
            let (ready, readiness) = mpsc::sync_channel(1);
            let (finished, completion) = watch::channel(MonitorCompletion::Running);
            let worker = thread::Builder::new()
                .name("cua-windows-interruption".into())
                .spawn(move || monitor_worker(|| run(state, ready), finished))
                .map_err(|error| format!("start native interruption thread: {error}"))?;
            let mut monitor = Self {
                stop,
                thread: Some(worker),
                completion,
            };
            match readiness.recv() {
                Ok(Ok(())) => Ok(monitor),
                Ok(Err(reason)) => {
                    let cleanup = monitor.join();
                    Err(match cleanup {
                        Ok(()) => reason,
                        Err(cleanup) => format!("{reason}; {cleanup}"),
                    })
                }
                Err(_) => {
                    let cleanup = monitor.join();
                    Err(cleanup
                        .err()
                        .unwrap_or_else(|| "native interruption thread ended before ready".into()))
                }
            }
        }
        pub(super) fn has_finished(&self) -> bool {
            // Sender disappearance can never silently authorize another input.
            monitor_finished(&self.completion)
        }
        fn join(&mut self) -> Result<(), String> {
            self.thread
                .take()
                .map_or(Ok(()), |worker| match worker.join() {
                    Ok(result) => result,
                    Err(payload) => resume_unwind(payload),
                })
        }
        /// Blocking exact native settlement, including failure. The actor must
        /// retain this call even if the original observation is cancelled.
        pub fn close(mut self) -> Result<(), String> {
            let wake = self.stop.signal();
            let result = self.join();
            match (wake, result) {
                (Ok(()), result) => result,
                (Err(wake), Ok(())) => Err(wake),
                (Err(wake), Err(result)) => Err(format!("{wake}; {result}")),
            }
        }
    }
    impl Drop for WindowsInterruptionMonitor {
        fn drop(&mut self) {
            if self.thread.is_some() {
                // Fallback requests stop only. It does not claim cleanup; the
                // desktop actor must own close/join and the completion receiver.
                let _ = self.stop.signal();
            }
        }
    }
    #[cfg(test)]
    pub(super) async fn test_monitor(
        call: impl FnOnce() -> Result<(), String> + Send + 'static,
    ) -> Result<WindowsInterruptionMonitor, String> {
        let stop = Arc::new(StopEvent::new()?);
        let (finished, mut completion) = watch::channel(MonitorCompletion::Running);
        let thread = thread::spawn(move || monitor_worker(call, finished));
        while matches!(*completion.borrow(), MonitorCompletion::Running) {
            completion
                .changed()
                .await
                .map_err(|_| "fixture monitor lost its terminal notice")?;
        }
        Ok(WindowsInterruptionMonitor {
            stop,
            thread: Some(thread),
            completion,
        })
    }

    #[cfg(test)]
    mod boundary_tests {
        use super::*;
        struct Panics;
        impl InterruptionSink for Panics {
            fn notify(&self, _: PhysicalInput) -> Result<(), String> {
                std::panic::panic_any(73_u64)
            }
        }
        #[test]
        fn callback_guard_returns_through_abi_then_original_payload_reaches_join() {
            let worker = std::thread::spawn(|| {
                let context = CallbackContext {
                    state: Arc::new(CallbackState {
                        sink: Arc::new(Panics),
                        escape_sent: AtomicBool::new(false),
                        stop: Arc::new(StopEvent::new().unwrap()),
                    }),
                    failure: Cell::new(Some(CallbackFailure::Native(
                        "earlier native failure".into(),
                    ))),
                };
                // A previous native error must not mask a genuine later panic.
                let returned = context.guard(|| context.state.sink.notify(PhysicalInput::Activity));
                assert!(returned.is_none());
                let mut cleanup = super::super::Cleanup::default();
                let mut trace = Vec::new();
                cleanup.attempt(|| {
                    trace.push("unhook mouse");
                    Ok(())
                });
                cleanup.attempt(|| {
                    trace.push("unhook keyboard");
                    Ok(())
                });
                assert_eq!(trace, ["unhook mouse", "unhook keyboard"]);
                cleanup.attempt(|| match context.failure.take() {
                    Some(CallbackFailure::Panicked(payload)) => resume_unwind(payload),
                    _ => panic!("callback original panic was lost"),
                });
                cleanup.finish();
            });
            let original = worker.join().unwrap_err();
            assert_eq!(original.downcast_ref::<u64>(), Some(&73));
        }
        #[test]
        fn physical_escape_is_consumed_even_when_sink_panics() {
            let context = Rc::new(CallbackContext {
                state: Arc::new(CallbackState {
                    sink: Arc::new(Panics),
                    escape_sent: AtomicBool::new(false),
                    stop: Arc::new(StopEvent::new().unwrap()),
                }),
                failure: Cell::new(None),
            });
            CALLBACK.with(|slot| slot.set(Some(context.clone())));
            let key = KBDLLHOOKSTRUCT {
                vkCode: 0x1b,
                ..Default::default()
            };
            // Real callback ABI with a valid stack-lifetime OS struct; no hook,
            // input injection, desktop, or cleanup acknowledgement is claimed.
            let result = unsafe {
                keyboard(
                    0,
                    WPARAM(0x100),
                    LPARAM((&key as *const KBDLLHOOKSTRUCT) as isize),
                )
            };
            assert_eq!(result.0, 1);
            let held = CALLBACK.with(Cell::take).unwrap();
            assert!(Rc::ptr_eq(&held, &context));
            match context.failure.take() {
                Some(CallbackFailure::Panicked(payload)) => {
                    assert_eq!(payload.downcast_ref::<u64>(), Some(&73))
                }
                _ => panic!("physical escape lost original callback panic"),
            }
        }
        #[test]
        fn callback_primary_is_not_replaced_by_unhook_panic() {
            let mut cleanup = super::super::Cleanup {
                panic: Some(Box::new(73_u64)),
                ..Default::default()
            };
            cleanup.attempt(|| std::panic::panic_any(99_u64));
            let original =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cleanup.finish()))
                    .unwrap_err();
            assert_eq!(original.downcast_ref::<u64>(), Some(&73));
        }
        #[test]
        fn terminal_or_disconnected_monitor_watch_is_never_running() {
            for terminal in [MonitorCompletion::Returned, MonitorCompletion::Panicked] {
                let (sender, receiver) = watch::channel(MonitorCompletion::Running);
                assert!(!monitor_finished(&receiver));
                sender.send_replace(terminal);
                assert!(monitor_finished(&receiver));
            }
            let (sender, receiver) = watch::channel(MonitorCompletion::Running);
            drop(sender);
            assert!(monitor_finished(&receiver));
        }
    }
}

#[cfg(target_os = "windows")]
pub use native::WindowsInterruptionMonitor;

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "windows")]
    #[test]
    fn cleanup_finally_preserves_first_payload_and_attempts_every_step() {
        let mut trace = Vec::new();
        let original = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut cleanup = Cleanup::default();
            cleanup.attempt(|| {
                trace.push("resume");
                std::panic::panic_any(37_u64)
            });
            cleanup.attempt(|| {
                trace.push("up");
                Err("native release debt".into())
            });
            cleanup.attempt(|| {
                trace.push("restore");
                Ok(())
            });
            cleanup.attempt(|| {
                trace.push("mouse hook");
                Ok(())
            });
            cleanup.attempt(|| {
                trace.push("keyboard hook");
                Ok(())
            });
            cleanup.attempt(|| {
                trace.push("tls");
                Ok(())
            });
            cleanup.finish();
        }))
        .unwrap_err();
        assert_eq!(original.downcast_ref::<u64>(), Some(&37));
        assert_eq!(
            trace,
            [
                "resume",
                "up",
                "restore",
                "mouse hook",
                "keyboard hook",
                "tls"
            ]
        );
    }
    #[cfg(target_os = "windows")]
    #[test]
    fn ordinary_native_cleanup_error_is_not_a_panic() {
        let mut cleanup = Cleanup::default();
        cleanup.attempt(|| Err("native release debt".into()));
        cleanup.attempt(|| Ok(()));
        assert_eq!(cleanup.finish(), ["native release debt"]);
    }
    #[test]
    fn physical_escape_keydown_is_the_only_consumed_keyboard_decision() {
        for message in [0x100, 0x104] {
            assert_eq!(
                keyboard_decision(0, message, 0x1b, 0),
                KeyboardDecision::Escape
            );
        }
        for (code, message, vk, flags) in [
            (-1, 0x100, 0x1b, 0),
            (1, 0x100, 0x1b, 0),
            (0, 0x101, 0x1b, 0),
            (0, 0x105, 0x1b, 0),
            (0, 0x100, 0x1b, 0x10),
            (0, 0x104, 0x1b, 0x12),
        ] {
            assert_eq!(
                keyboard_decision(code, message, vk, flags),
                KeyboardDecision::Forward
            );
        }
        assert_eq!(
            keyboard_decision(0, 0x100, 0x41, 0),
            KeyboardDecision::Activity
        );
    }
    #[test]
    fn physical_mouse_activity_filters_injected_and_other_messages() {
        for offset in 0..=12 {
            let expected = offset <= 9 && 0x249 & (1 << offset) != 0;
            assert_eq!(mouse_activity(0, 0x201 + offset, 0), expected);
            assert!(!mouse_activity(0, 0x201 + offset, 1));
        }
        assert!(!mouse_activity(-1, 0x201, 0));
        assert!(!mouse_activity(0, 0x200, 0));
    }
}

#[cfg(target_os = "windows")]
mod service {
    use super::{InterruptionSink, PhysicalInput, WindowsInterruptionMonitor};
    use async_trait::async_trait;
    use cua_driver_core::{
        tool::ToolRegistry,
        windows_interruption::{
            current_windows_input_binding, InterruptionError, WindowsInputBinding,
            WindowsInterruptionBackend,
        },
    };
    use serde_json::Value;
    use std::{
        future::Future,
        sync::{Arc, Mutex},
    };

    struct BoundSink(Arc<WindowsInputBinding>);
    impl InterruptionSink for BoundSink {
        fn notify(&self, input: PhysicalInput) -> Result<(), String> {
            self.0.notify(input)
        }
    }
    enum MonitorFailure {
        Native(String),
        PanicUnconfirmed,
    }
    #[derive(Debug)]
    struct MonitorCleanupPanic;
    #[derive(Debug)]
    struct PanicCleanupWorkerCancelled;
    fn close_monitor_state(
        failure: &mut Option<MonitorFailure>,
        close: impl FnOnce() -> Result<(), String>,
    ) {
        *failure = Some(MonitorFailure::PanicUnconfirmed);
        *failure = close().err().map(MonitorFailure::Native);
    }
    struct Current {
        binding: Arc<WindowsInputBinding>,
        monitor: Option<WindowsInterruptionMonitor>,
        monitor_failure: Option<MonitorFailure>,
        inputs: Arc<crate::input::owned::Inputs>,
    }
    #[derive(Default)]
    struct Resource {
        current: Option<Current>,
        // Actual native cleanup uncertainty fences this same physical actor.
        // It is a retained resource result, never another permission registry.
        failure: Option<String>,
    }
    #[derive(Clone, Default)]
    struct Service {
        resource: Arc<Mutex<Resource>>,
    }

    fn starts_monitor(name: &str) -> bool {
        matches!(
            name,
            "launch_app"
                | "click"
                | "double_click"
                | "right_click"
                | "scroll"
                | "drag"
                | "mouse_drag"
                | "parallel_mouse_drag"
                | "move_cursor"
                | "mouse_button_down"
                | "mouse_button_up"
                | "type_text"
                | "press_key"
                | "hotkey"
                | "set_value"
                | "bring_to_front"
                | "set_window_frame"
                | "perform_secondary_action"
                | "native_secondary_action"
                | "click_element"
                | "scroll_element"
        )
    }
    // These are actual native helper routes. Core browser/CDP/JavaScript tools
    // and unrelated SDK tools never borrow this native turn's interruption.
    fn is_native_method(name: &str) -> bool {
        starts_monitor(name)
            || matches!(
                name,
                "list_apps"
                    | "list_windows"
                    | "get_window_state"
                    | "element_bounds"
                    | "start_audio_recording"
                    | "stop_audio_recording"
            )
    }
    impl Service {
        fn with_resource<T>(
            &self,
            call: impl FnOnce(&mut Resource) -> Result<T, String>,
        ) -> Result<T, String> {
            let mut resource = self
                .resource
                .lock()
                .expect("native monitor resource mutex poisoned");
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| call(&mut resource))) {
                Ok(result) => result,
                Err(payload) => {
                    // Close this actual owner before propagating a programmer
                    // failure, while the original resource guard is still held.
                    let mut cleanup = super::Cleanup {
                        panic: Some(payload),
                        ..Default::default()
                    };
                    cleanup.attempt(|| Self::retire(&mut resource));
                    cleanup.finish();
                    unreachable!("cleanup resumes the original resource panic")
                }
            }
        }
        fn retire(resource: &mut Resource) -> Result<(), String> {
            if let Some(current) = resource.current.as_mut() {
                current.binding.retire();
                let failures = Self::release_current(current);
                if !failures.is_empty() {
                    let reason = failures.join("; ");
                    resource.failure = Some(reason.clone());
                    return Err(reason);
                }
            }
            // Keep custody in-place during every cleanup attempt and unwind.
            resource.current = None;
            resource.failure = None;
            Ok(())
        }
        fn release_current(current: &mut Current) -> Vec<String> {
            let mut cleanup = super::Cleanup::default();
            cleanup.attempt(|| {
                let failures = Self::release_current_inputs(current);
                if failures.is_empty() {
                    Ok(())
                } else {
                    Err(failures.join("; "))
                }
            });
            cleanup.attempt(|| {
                if current.monitor.is_some() {
                    let monitor = &mut current.monitor;
                    close_monitor_state(&mut current.monitor_failure, || {
                        monitor
                            .take()
                            .expect("native monitor close retains its exact monitor")
                            .close()
                    });
                }
                match &current.monitor_failure {
                    Some(MonitorFailure::Native(reason)) => Err(reason.clone()),
                    Some(MonitorFailure::PanicUnconfirmed) => {
                        std::panic::panic_any(MonitorCleanupPanic)
                    }
                    None => Ok(()),
                }
            });
            cleanup.finish()
        }
        fn release_current_inputs(current: &mut Current) -> Vec<String> {
            current.binding.retire();
            let mut cleanup = super::Cleanup::default();
            use cua_driver_core::windows_interruption::NativeReleasePhase;
            // Preserve exact original phase order and attempt independent
            // owned debt even when a preceding phase panics.
            cleanup.attempt(|| {
                current
                    .binding
                    .release_owned_inputs_in_phase(NativeReleasePhase::ResumeTarget)
            });
            cleanup.attempt(|| current.inputs.close());
            cleanup.attempt(|| {
                current
                    .binding
                    .release_owned_inputs_in_phase(NativeReleasePhase::ReleaseInput)
            });
            cleanup.attempt(|| {
                current
                    .binding
                    .release_owned_inputs_in_phase(NativeReleasePhase::RestoreContext)
            });
            cleanup.finish()
        }
        fn prepare(&self, binding: Arc<WindowsInputBinding>, name: &str) -> Result<(), String> {
            self.with_resource(|resource| {
                if let Some(failure) = &resource.failure {
                    return Err(failure.clone());
                }
                let same = resource
                    .current
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(&current.binding, &binding));
                if !same {
                    // A real new binding retires the old monitor only. It does
                    // not invent a Stop for the prior Agent Run.
                    Self::retire(resource)?;
                }
                if !starts_monitor(name) {
                    return Ok(());
                }
                if same {
                    let Some(monitor) = resource
                        .current
                        .as_ref()
                        .and_then(|current| current.monitor.as_ref())
                    else {
                        return Err("native monitor is already closed for this binding".into());
                    };
                    if monitor.has_finished() {
                        let current = resource
                            .current
                            .as_mut()
                            .expect("same native binding retained its current resource");
                        // Actual join propagates a worker panic only after
                        // existing input debt and both hooks were attempted.
                        let failures = Self::release_current(current);
                        let reason = if failures.is_empty() {
                            "native monitor ended before turn cleanup".into()
                        } else {
                            failures.join("; ")
                        };
                        resource.failure = Some(reason.clone());
                        return Err(reason);
                    }
                    return Ok(());
                }
                match WindowsInterruptionMonitor::start(Arc::new(BoundSink(binding.clone()))) {
                    Ok(monitor) => {
                        resource.current = Some(Current {
                            binding,
                            monitor: Some(monitor),
                            monitor_failure: None,
                            inputs: Arc::new(crate::input::owned::Inputs::default()),
                        });
                        Ok(())
                    }
                    Err(reason) => {
                        // No later input may hide a failed/partially cleaned
                        // start by simply installing a replacement monitor.
                        resource.failure = Some(reason.clone());
                        Err(reason)
                    }
                }
            })
        }
        fn settle_interrupted(&self, binding: &Arc<WindowsInputBinding>) -> Result<(), String> {
            self.with_resource(|resource| {
                if let Some(current) = resource
                    .current
                    .as_mut()
                    .filter(|current| Arc::ptr_eq(&current.binding, binding))
                {
                    let failures = Self::release_current(current);
                    if !failures.is_empty() {
                        let reason = failures.join("; ");
                        resource.failure = Some(reason.clone());
                        return Err(reason);
                    }
                }
                resource.failure.clone().map_or(Ok(()), Err)
            })
        }
        async fn check(&self, binding: Arc<WindowsInputBinding>) -> Result<(), InterruptionError> {
            let ended = self
                .with_resource(|resource| {
                    Ok(resource
                        .current
                        .as_ref()
                        .filter(|current| Arc::ptr_eq(&current.binding, &binding))
                        .and_then(|current| current.monitor.as_ref())
                        .is_some_and(WindowsInterruptionMonitor::has_finished))
                })
                .map_err(InterruptionError::CleanupUnconfirmed)?;
            if ended {
                let status = binding.check();
                binding.retire();
                let service = self.clone();
                let closed = binding.clone();
                let custody = cua_driver_core::tool::current_native_input_worker_lease();
                tokio::task::spawn_blocking(move || {
                    let _accepted_worker = custody;
                    service.close_binding(&closed)
                })
                .await
                .map_err(|error| {
                    if error.is_panic() {
                        std::panic::resume_unwind(error.into_panic());
                    }
                    InterruptionError::CleanupUnconfirmed(format!(
                        "native terminal monitor close worker: {error}"
                    ))
                })?
                .map_err(InterruptionError::CleanupUnconfirmed)?;
                return match status {
                    Err(reason) => Err(reason),
                    Ok(()) => Err(InterruptionError::Unavailable(
                        "native monitor ended before turn cleanup".into(),
                    )),
                };
            }
            binding
                .failed_input_releases()
                .map_err(InterruptionError::CleanupUnconfirmed)?;
            match binding.check() {
                Err(InterruptionError::Interrupted) => {
                    let service = self.clone();
                    tokio::task::spawn_blocking(move || service.settle_interrupted(&binding))
                        .await
                        .map_err(|error| {
                            if error.is_panic() {
                                std::panic::resume_unwind(error.into_panic());
                            }
                            InterruptionError::CleanupUnconfirmed(format!(
                                "native interruption close worker: {error}"
                            ))
                        })?
                        .map_err(InterruptionError::CleanupUnconfirmed)?;
                    Err(InterruptionError::Interrupted)
                }
                result => result,
            }
        }
    }
    impl Service {
        async fn run_bound<F>(
            &self,
            binding: Arc<WindowsInputBinding>,
            operation: F,
        ) -> cua_driver_core::protocol::ToolResult
        where
            F: Future<Output = cua_driver_core::protocol::ToolResult> + Send,
        {
            let mut operation = Box::pin(operation);
            let result = std::future::poll_fn(|context| {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    operation.as_mut().poll(context)
                })) {
                    Ok(polled) => polled.map(Ok),
                    Err(payload) => std::task::Poll::Ready(Err(payload)),
                }
            })
            .await;
            if result.is_err() {
                binding.retire();
            }
            // Completed futures may still own destructors. Their panic is
            // part of this same accepted operation, not a post-terminal retry.
            let dropped =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(operation)));
            let payload = match (result, dropped) {
                (Ok(result), Ok(())) => return result,
                (Err(original), Err(secondary)) => {
                    std::mem::forget(secondary);
                    original
                }
                (Err(payload), Ok(())) | (Ok(_), Err(payload)) => payload,
            };
            binding.retire();
            let service = self.clone();
            let custody = cua_driver_core::tool::current_native_input_worker_lease();
            // Move the original payload into the same retained cleanup worker.
            // Cancelling this observation cannot quietly drop it in the parent
            // future while physical cleanup is still running.
            let settled = tokio::task::spawn_blocking(move || {
                let _accepted_worker = custody;
                let mut cleanup = super::Cleanup {
                    panic: Some(payload),
                    ..Default::default()
                };
                cleanup.attempt(|| service.close_binding(&binding));
                cleanup.finish();
                unreachable!("cleanup resumes the original native operation panic")
            })
            .await;
            match settled {
                Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
                // This handle is never aborted by the adapter. Runtime shutdown
                // before the queued worker starts provides no cleanup proof and
                // cannot turn an already known panic into a retryable error.
                Err(_) => std::panic::panic_any(PanicCleanupWorkerCancelled),
                Ok(_) => unreachable!("native panic cleanup worker cannot return normally"),
            }
        }
        async fn before_tool(&self, name: &str, args: &Value) -> Result<(), InterruptionError> {
            if !is_native_method(name) {
                return Ok(());
            }
            let Some(binding) = current_windows_input_binding() else {
                return Ok(());
            };
            if args.get("_session_id").and_then(Value::as_str) != Some(binding.owner()) {
                return Err(InterruptionError::Unavailable(
                    "native interruption binding changed its actual runtime/session".into(),
                ));
            }
            self.check(binding.clone()).await?;
            let lease =
                cua_driver_core::tool::current_native_input_worker_lease().ok_or_else(|| {
                    InterruptionError::Unavailable(
                        "native interruption start has no actual input-worker custody".into(),
                    )
                })?;
            let service = self.clone();
            let name = name.to_owned();
            let checked = binding.clone();
            tokio::task::spawn_blocking(move || {
                // Startup can survive a cancelled observation, but cannot
                // outlive this original accepted worker lease unowned.
                let _accepted_worker = lease;
                service.prepare(binding, &name)
            })
            .await
            .map_err(|error| {
                if error.is_panic() {
                    std::panic::resume_unwind(error.into_panic());
                }
                InterruptionError::CleanupUnconfirmed(format!(
                    "native interruption worker failed: {error}"
                ))
            })?
            .map_err(InterruptionError::CleanupUnconfirmed)?;
            self.check(checked).await
        }
        async fn after_tool(&self, name: &str, _args: &Value) -> Result<(), InterruptionError> {
            if !is_native_method(name) {
                return Ok(());
            }
            match current_windows_input_binding() {
                Some(binding) => self.check(binding).await,
                None => Ok(()),
            }
        }
    }
    fn refused(
        reason: InterruptionError,
        previous: Option<cua_driver_core::protocol::ToolResult>,
    ) -> cua_driver_core::protocol::ToolResult {
        use cua_driver_core::protocol::ToolResult;
        let after = previous.is_some();
        let code = match &reason {
            InterruptionError::Interrupted if after => "input_outcome_unknown",
            InterruptionError::Interrupted => "computer_use_interrupted",
            InterruptionError::Retired => "native_interruption_retired",
            InterruptionError::Unavailable(_) => "native_interruption_unavailable",
            InterruptionError::CleanupUnconfirmed(_) => "native_interruption_cleanup_unconfirmed",
        };
        ToolResult::error(reason.to_string()).with_structured(serde_json::json!({
            "code":code, "reason":reason.to_string(),
            "execution_state": if after { "unknown" } else { "not_started" },
            "native_cleanup": if matches!(reason, InterruptionError::CleanupUnconfirmed(_)) { "unconfirmed" } else { "confirmed" },
            "native_result":previous,
        }))
    }
    #[async_trait]
    impl WindowsInterruptionBackend for Service {
        async fn invoke(
            &self,
            tool: &dyn cua_driver_core::tool::Tool,
            name: &str,
            args: Value,
        ) -> cua_driver_core::protocol::ToolResult {
            if !is_native_method(name) || current_windows_input_binding().is_none() {
                return tool.invoke(args).await;
            }
            let binding = current_windows_input_binding().expect("checked native binding");
            self.run_bound(binding, async {
                if let Err(error) = self.before_tool(name, &args).await {
                    return refused(error, None);
                }
                let binding = current_windows_input_binding().expect("checked native binding");
                let inputs = match self.with_resource(|resource| {
                    Ok(resource
                        .current
                        .as_ref()
                        .filter(|current| Arc::ptr_eq(&current.binding, &binding))
                        .map(|current| current.inputs.clone()))
                }) {
                    Ok(inputs) => inputs,
                    Err(reason) => {
                        return refused(InterruptionError::CleanupUnconfirmed(reason), None)
                    }
                };
                let result = match inputs {
                    Some(inputs) => {
                        crate::input::owned::scope(inputs, tool.invoke(args.clone())).await
                    }
                    None => tool.invoke(args.clone()).await,
                };
                match self.after_tool(name, &args).await {
                    Ok(()) => result,
                    Err(error) => refused(error, Some(result)),
                }
            })
            .await
        }
        fn close_turn(&self, owner: &str, turn: &str) -> Result<(), String> {
            self.with_resource(|resource| {
                if resource.current.as_ref().is_some_and(|current| {
                    current.binding.owner() == owner && current.binding.turn() == turn
                }) {
                    Self::retire(resource)
                } else {
                    resource.failure.clone().map_or(Ok(()), Err)
                }
            })
        }
        fn close_binding(&self, binding: &Arc<WindowsInputBinding>) -> Result<(), String> {
            binding.retire();
            self.with_resource(|resource| {
                if resource
                    .current
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(&current.binding, binding))
                {
                    Self::retire(resource)
                } else {
                    binding.release_owned_inputs()?;
                    resource.failure.clone().map_or(Ok(()), Err)
                }
            })
        }
        fn release_binding_inputs(&self, binding: &Arc<WindowsInputBinding>) -> Result<(), String> {
            binding.retire();
            self.with_resource(|resource| {
                if let Some(current) = resource
                    .current
                    .as_mut()
                    .filter(|current| Arc::ptr_eq(&current.binding, binding))
                {
                    let failures = Self::release_current_inputs(current);
                    if !failures.is_empty() {
                        let reason = failures.join("; ");
                        resource.failure = Some(reason.clone());
                        return Err(reason);
                    }
                }
                Ok(())
            })
        }
        fn close_session(&self, owner: &str) -> Result<(), String> {
            self.with_resource(|resource| {
                if resource
                    .current
                    .as_ref()
                    .is_some_and(|current| current.binding.owner() == owner)
                {
                    Self::retire(resource)
                } else {
                    resource.failure.clone().map_or(Ok(()), Err)
                }
            })
        }
        fn close_all(&self) -> Result<(), String> {
            self.with_resource(Self::retire)
        }
    }

    #[cfg(test)]
    mod panic_tests {
        use super::*;
        use cua_driver_core::{
            protocol::ToolResult,
            windows_interruption::{InterruptionSink, NativeInputRelease, NativeReleasePhase},
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Sink;
        impl InterruptionSink for Sink {
            fn notify(&self, _: PhysicalInput) -> Result<(), String> {
                Ok(())
            }
        }
        struct Release {
            phase: NativeReleasePhase,
            calls: Arc<AtomicUsize>,
            fail: bool,
        }
        impl NativeInputRelease for Release {
            fn phase(&self) -> NativeReleasePhase {
                self.phase
            }
            fn release(&self) -> Result<(), String> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if self.fail {
                    Err("actual fixture release debt".into())
                } else {
                    Ok(())
                }
            }
        }
        struct ActivityPanics;
        impl InterruptionSink for ActivityPanics {
            fn notify(&self, _: PhysicalInput) -> Result<(), String> {
                std::panic::panic_any(83_u64)
            }
        }
        #[tokio::test]
        async fn already_terminal_activity_monitor_cannot_pass_after_check_or_metadata_prepare() {
            for debt in [false, true] {
                for after in [false, true] {
                    let binding = WindowsInputBinding::new(
                        "owner".into(),
                        "turn".into(),
                        Arc::new(ActivityPanics),
                    )
                    .unwrap();
                    if debt {
                        let receipt = binding
                            .retain_input_release(Arc::new(Release {
                                phase: NativeReleasePhase::ReleaseInput,
                                calls: Arc::new(AtomicUsize::new(0)),
                                fail: true,
                            }))
                            .unwrap();
                        drop(receipt);
                        assert!(binding.failed_input_releases().is_err());
                    }
                    let callback = binding.clone();
                    let monitor = super::super::native::test_monitor(move || {
                        callback.notify(PhysicalInput::Activity)
                    })
                    .await
                    .unwrap();
                    assert_eq!(
                        binding.check(),
                        Ok(()),
                        "Activity itself is not Escape/retirement"
                    );
                    let service = Service::default();
                    service
                        .with_resource(|resource| {
                            resource.current = Some(Current {
                                binding: binding.clone(),
                                monitor: Some(monitor),
                                monitor_failure: None,
                                inputs: Arc::new(crate::input::owned::Inputs::default()),
                            });
                            Ok(())
                        })
                        .unwrap();
                    let observed = binding.clone();
                    let call = tokio::spawn(
                        cua_driver_core::windows_interruption::with_windows_input_binding(
                            observed,
                            async move {
                                if after {
                                    service.after_tool("list_windows", &Value::Null).await
                                } else {
                                    // Real metadata before_tool seam. An already-known
                                    // terminal must win over ordinary release debt and
                                    // cannot reach startup/its worker-lease requirement.
                                    service
                                        .before_tool(
                                            "list_windows",
                                            &serde_json::json!({"_session_id":"owner"}),
                                        )
                                        .await
                                }
                            },
                        ),
                    );
                    let original = call.await.unwrap_err().into_panic();
                    assert_eq!(original.downcast_ref::<u64>(), Some(&83));
                    assert_eq!(binding.check(), Err(InterruptionError::Retired));
                }
            }
        }
        #[tokio::test]
        async fn terminal_notice_of_foreign_current_does_not_close_this_binding() {
            let current =
                WindowsInputBinding::new("current".into(), "turn".into(), Arc::new(ActivityPanics))
                    .unwrap();
            let observed = current.clone();
            let monitor = super::super::native::test_monitor(move || {
                observed.notify(PhysicalInput::Activity)
            })
            .await
            .unwrap();
            let foreign =
                WindowsInputBinding::new("foreign".into(), "turn".into(), Arc::new(Sink)).unwrap();
            let service = Service::default();
            service
                .with_resource(|resource| {
                    resource.current = Some(Current {
                        binding: current.clone(),
                        monitor: Some(monitor),
                        monitor_failure: None,
                        inputs: Arc::new(crate::input::owned::Inputs::default()),
                    });
                    Ok(())
                })
                .unwrap();
            assert_eq!(service.check(foreign.clone()).await, Ok(()));
            assert_eq!(foreign.check(), Ok(()));
            assert_eq!(current.check(), Ok(()));
            let closed = current.clone();
            let original = tokio::task::spawn_blocking(move || service.close_binding(&closed))
                .await
                .unwrap_err()
                .into_panic();
            assert_eq!(original.downcast_ref::<u64>(), Some(&83));
        }
        #[test]
        fn monitor_close_panic_cannot_be_erased_by_second_retire_finally() {
            let binding =
                WindowsInputBinding::new("owner".into(), "turn".into(), Arc::new(Sink)).unwrap();
            let mut current = Current {
                binding: binding.clone(),
                monitor: None,
                monitor_failure: None,
                inputs: Arc::new(crate::input::owned::Inputs::default()),
            };
            let original = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                close_monitor_state(&mut current.monitor_failure, || {
                    std::panic::panic_any(67_u64)
                });
            }))
            .unwrap_err();
            assert_eq!(original.downcast_ref::<u64>(), Some(&67));
            let mut resource = Resource {
                current: Some(current),
                failure: None,
            };
            for _ in 0..2 {
                let unknown = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    Service::retire(&mut resource)
                }))
                .unwrap_err();
                assert!(unknown.is::<MonitorCleanupPanic>());
                assert!(resource.current.as_ref().is_some_and(|current| matches!(
                    current.monitor_failure,
                    Some(MonitorFailure::PanicUnconfirmed)
                )));
            }
            assert_eq!(binding.check(), Err(InterruptionError::Retired));
        }
        #[tokio::test]
        async fn actual_native_future_boundary_retires_same_owner_before_original_panic() {
            let binding =
                WindowsInputBinding::new("owner".into(), "turn".into(), Arc::new(Sink)).unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let _receipt = binding
                .retain_input_release(Arc::new(Release {
                    phase: NativeReleasePhase::ReleaseInput,
                    calls: calls.clone(),
                    fail: true,
                }))
                .unwrap();
            let service = Service::default();
            service
                .with_resource(|resource| {
                    resource.current = Some(Current {
                        binding: binding.clone(),
                        monitor: None,
                        monitor_failure: None,
                        inputs: Arc::new(crate::input::owned::Inputs::default()),
                    });
                    Ok(())
                })
                .unwrap();
            let invoked = service.clone();
            let bound = binding.clone();
            let worker = tokio::spawn(async move {
                invoked
                    .run_bound(bound, async {
                        crate::input::owned::spawn_blocking(|| std::panic::panic_any(91_u64))
                            .await
                            .unwrap();
                        ToolResult::text("unreachable")
                    })
                    .await
            });
            let original = worker.await.unwrap_err().into_panic();
            assert_eq!(original.downcast_ref::<u64>(), Some(&91));
            assert_eq!(binding.check(), Err(InterruptionError::Retired));
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            let resource = service.resource.lock().unwrap();
            assert!(resource
                .current
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(&current.binding, &binding)));
            assert_eq!(
                resource.failure.as_deref(),
                Some("actual fixture release debt")
            );
        }
        #[tokio::test]
        async fn completed_future_drop_panic_still_retires_exact_binding() {
            struct Completed;
            impl Future for Completed {
                type Output = ToolResult;
                fn poll(
                    self: std::pin::Pin<&mut Self>,
                    _: &mut std::task::Context<'_>,
                ) -> std::task::Poll<ToolResult> {
                    std::task::Poll::Ready(ToolResult::text("completed body"))
                }
            }
            impl Drop for Completed {
                fn drop(&mut self) {
                    std::panic::panic_any(109_u64);
                }
            }
            let binding =
                WindowsInputBinding::new("owner".into(), "turn".into(), Arc::new(Sink)).unwrap();
            let bound = binding.clone();
            let original =
                tokio::spawn(async move { Service::default().run_bound(bound, Completed).await })
                    .await
                    .unwrap_err()
                    .into_panic();
            assert_eq!(original.downcast_ref::<u64>(), Some(&109));
            assert_eq!(binding.check(), Err(InterruptionError::Retired));
        }
        #[tokio::test]
        async fn ordinary_tool_failure_preserves_live_owner_and_result() {
            let binding =
                WindowsInputBinding::new("owner".into(), "turn".into(), Arc::new(Sink)).unwrap();
            let service = Service::default();
            let result = service
                .run_bound(binding.clone(), async {
                    ToolResult::error("native API error")
                })
                .await;
            assert_eq!(result.is_error, Some(true));
            assert_eq!(binding.check(), Ok(()));
        }
    }

    pub fn install(registry: &mut ToolRegistry) {
        let service = Arc::new(Service::default());
        let cleanup = service.clone();
        registry.retain_session_end_hook(
            cua_driver_core::session::register_scoped_fallible_session_end_hook(
                "windows_native_interruption",
                move |session| cleanup.close_session(session),
            ),
        );
        let fallback = service.clone();
        registry.retain_runtime_cleanup(move || {
            // Drop cannot acknowledge cleanup and must not block an async
            // executor. Explicit SDK shutdown awaits the same close_all first.
            let _ = std::thread::Builder::new()
                .name("cua-interruption-retire".into())
                .spawn(move || fallback.close_all());
        });
        registry
            .retain_windows_interruption_backend(service)
            .expect("Windows registry installs one actual monitor resource");
    }
}
#[cfg(target_os = "windows")]
pub use service::install;
