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

#[cfg(target_os = "windows")]
mod native {
    use super::{
        keyboard_decision, mouse_activity, InterruptionSink, KeyboardDecision, PhysicalInput,
    };
    use std::{
        cell::RefCell,
        panic::{catch_unwind, AssertUnwindSafe},
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc, Arc, Mutex,
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
        failure: Mutex<Option<String>>,
        stop: Arc<StopEvent>,
    }
    impl CallbackState {
        fn fail(&self, reason: String) {
            let mut failure = self
                .failure
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if failure.is_none() {
                *failure = Some(reason);
            }
            drop(failure);
            let _ = self.stop.signal();
        }
        fn emit(&self, input: PhysicalInput) {
            if input == PhysicalInput::Escape && self.escape_sent.swap(true, Ordering::AcqRel) {
                return;
            }
            match catch_unwind(AssertUnwindSafe(|| self.sink.notify(input))) {
                Ok(Ok(())) => {}
                Ok(Err(reason)) => self.fail(reason),
                Err(_) => self.fail("native interruption event sink panicked".into()),
            }
            if input == PhysicalInput::Escape {
                // Original exits its helper after a physical Esc. The embedded
                // runtime retires only this native observation resource; actual
                // unhook/close completion still comes from the worker result.
                if let Err(reason) = self.stop.signal() {
                    self.fail(reason);
                }
            }
        }
    }

    thread_local! {
        // Low-level callbacks are delivered on the thread which installed the
        // hook. This is physical resource custody, not a global permission map.
        static CALLBACK: RefCell<Option<Arc<CallbackState>>> = const { RefCell::new(None) };
    }

    unsafe extern "system" fn keyboard(code: i32, message: WPARAM, data: LPARAM) -> LRESULT {
        let state = CALLBACK.with(|slot| slot.try_borrow().ok().and_then(|slot| slot.clone()));
        if let Some(state) = state.filter(|_| code == 0 && data.0 != 0) {
            // SAFETY: for HC_ACTION the OS supplies a KBDLLHOOKSTRUCT valid for
            // this callback only. No native pointer or key contents are retained.
            let key = unsafe { &*(data.0 as *const KBDLLHOOKSTRUCT) };
            match keyboard_decision(code, message.0, key.vkCode, key.flags.0) {
                KeyboardDecision::Escape => {
                    state.emit(PhysicalInput::Escape);
                    // The callback remains registered until both hooks unhook;
                    // repeated Esc is still consumed without another Stop event.
                    return LRESULT(1);
                }
                KeyboardDecision::Activity => state.emit(PhysicalInput::Activity),
                KeyboardDecision::Forward => {}
            }
        }
        // SAFETY: forward the original hook arguments without retaining them.
        unsafe { CallNextHookEx(HHOOK::default(), code, message, data) }
    }

    unsafe extern "system" fn mouse(code: i32, message: WPARAM, data: LPARAM) -> LRESULT {
        let state = CALLBACK.with(|slot| slot.try_borrow().ok().and_then(|slot| slot.clone()));
        if let Some(state) = state.filter(|_| code == 0 && data.0 != 0) {
            // SAFETY: same callback-lifetime OS contract as the keyboard hook.
            let pointer = unsafe { &*(data.0 as *const MSLLHOOKSTRUCT) };
            if mouse_activity(code, message.0, pointer.flags) {
                state.emit(PhysicalInput::Activity);
            }
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
        // SAFETY: query the current executable module; no borrowed string.
        let module = unsafe { GetModuleHandleW(None) }
            .map_err(|error| format!("resolve native interruption module: {error}"))?;
        // SAFETY: callbacks have the required ABI and stay live in this module.
        let key =
            unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard), HINSTANCE(module.0), 0) }
                .map_err(|error| {
                    format!("install native keyboard interruption monitor: {error}")
                })?;
        let pointer =
            match unsafe { SetWindowsHookExW(WH_MOUSE_LL, Some(mouse), HINSTANCE(module.0), 0) } {
                Ok(hook) => hook,
                Err(error) => {
                    let primary = format!("install native mouse interruption monitor: {error}");
                    return Err(match unhook(key, "keyboard") {
                        Ok(()) => primary,
                        Err(cleanup) => format!("{primary}; {cleanup}"),
                    });
                }
            };
        let mut message = MSG::default();
        // SAFETY: establish the installing thread's message queue before ready.
        let _ = unsafe { PeekMessageW(&mut message, None, 0, 0, PM_NOREMOVE) };
        CALLBACK.with(|slot| *slot.borrow_mut() = Some(state.clone()));
        let result = if ready.send(Ok(())).is_err() {
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
        };
        // Always attempt both, including after a callback or message failure.
        let pointer_cleanup = unhook(pointer, "mouse");
        let key_cleanup = unhook(key, "keyboard");
        CALLBACK.with(|slot| *slot.borrow_mut() = None);
        let failure = state
            .failure
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        let mut failures: Vec<String> = result.err().into_iter().collect();
        failures.extend(pointer_cleanup.err());
        failures.extend(key_cleanup.err());
        failures.extend(failure);
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }

    pub struct WindowsInterruptionMonitor {
        stop: Arc<StopEvent>,
        thread: Option<JoinHandle<Result<(), String>>>,
        completion: watch::Receiver<Option<Result<(), String>>>,
    }
    impl WindowsInterruptionMonitor {
        /// Blocking native startup. Run on the existing blocking worker.
        pub fn start(sink: Arc<dyn InterruptionSink>) -> Result<Self, String> {
            let stop = Arc::new(StopEvent::new()?);
            let state = Arc::new(CallbackState {
                sink,
                escape_sent: AtomicBool::new(false),
                failure: Mutex::new(None),
                stop: stop.clone(),
            });
            let (ready, readiness) = mpsc::sync_channel(1);
            let (finished, completion) = watch::channel(None);
            let worker = thread::Builder::new()
                .name("cua-windows-interruption".into())
                .spawn(move || {
                    let result = catch_unwind(AssertUnwindSafe(|| run(state, ready)))
                        .unwrap_or_else(|_| Err("native interruption thread panicked".into()));
                    finished.send_replace(Some(result.clone()));
                    result
                })
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
        pub fn completion(&self) -> watch::Receiver<Option<Result<(), String>>> {
            self.completion.clone()
        }
        fn join(&mut self) -> Result<(), String> {
            self.thread.take().map_or(Ok(()), |worker| {
                worker
                    .join()
                    .map_err(|_| "join native interruption thread panicked".to_owned())?
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
}

#[cfg(target_os = "windows")]
pub use native::WindowsInterruptionMonitor;

#[cfg(test)]
mod tests {
    use super::*;
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
    use std::sync::{Arc, Mutex};

    struct BoundSink(Arc<WindowsInputBinding>);
    impl InterruptionSink for BoundSink {
        fn notify(&self, input: PhysicalInput) -> Result<(), String> {
            self.0.notify(input)
        }
    }
    struct Current {
        binding: Arc<WindowsInputBinding>,
        monitor: Option<WindowsInterruptionMonitor>,
        monitor_failure: Option<String>,
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
                .map_err(|_| "native monitor resource mutex poisoned")?;
            call(&mut resource)
        }
        fn retire(resource: &mut Resource) -> Result<(), String> {
            if let Some(mut current) = resource.current.take() {
                current.binding.retire();
                let failures = Self::release_current(&mut current);
                if !failures.is_empty() {
                    let reason = failures.join("; ");
                    resource.failure = Some(reason.clone());
                    // Keep failed resource custody for explicit retry.
                    resource.current = Some(current);
                    return Err(reason);
                }
            }
            resource.failure = None;
            Ok(())
        }
        fn release_current(current: &mut Current) -> Vec<String> {
            let mut failures = Self::release_current_inputs(current);
            if let Some(monitor) = current.monitor.take() {
                if let Err(error) = monitor.close() {
                    current.monitor_failure = Some(error);
                }
            }
            failures.extend(current.monitor_failure.clone());
            failures
        }
        fn release_current_inputs(current: &mut Current) -> Vec<String> {
            // Hook callbacks only send metadata and never take these input
            // locks. Keep the message pump available while actual short
            // writes and foreign-window guards settle, before native exit.
            current.binding.retire();
            let mut failures = Vec::new();
            use cua_driver_core::windows_interruption::NativeReleasePhase;
            failures.extend(
                current
                    .binding
                    .release_owned_inputs_in_phase(NativeReleasePhase::ResumeTarget)
                    .err(),
            );
            failures.extend(current.inputs.close().err());
            failures.extend(
                current
                    .binding
                    .release_owned_inputs_in_phase(NativeReleasePhase::ReleaseInput)
                    .err(),
            );
            failures.extend(
                current
                    .binding
                    .release_owned_inputs_in_phase(NativeReleasePhase::RestoreContext)
                    .err(),
            );
            failures
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
                    let completion = monitor.completion();
                    let finished = completion.borrow().clone();
                    if let Some(result) = finished {
                        return Err(result
                            .err()
                            .unwrap_or_else(|| "native monitor ended before turn cleanup".into()));
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
            match binding.check() {
                Err(InterruptionError::Interrupted) => {
                    let service = self.clone();
                    tokio::task::spawn_blocking(move || service.settle_interrupted(&binding))
                        .await
                        .map_err(|error| {
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
            binding
                .failed_input_releases()
                .map_err(InterruptionError::CleanupUnconfirmed)?;
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
                Some(binding) => {
                    binding
                        .failed_input_releases()
                        .map_err(InterruptionError::CleanupUnconfirmed)?;
                    self.check(binding).await
                }
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
                Err(reason) => return refused(InterruptionError::CleanupUnconfirmed(reason), None),
            };
            let result = match inputs {
                Some(inputs) => crate::input::owned::scope(inputs, tool.invoke(args.clone())).await,
                None => tool.invoke(args.clone()).await,
            };
            match self.after_tool(name, &args).await {
                Ok(()) => result,
                Err(error) => refused(error, Some(result)),
            }
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
