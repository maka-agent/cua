// SPDX-License-Identifier: MIT

//! Trusted Windows native interruption binding and actual resource boundary.
//! This does not grant input, define a model tool or select a Host turn from JSON.

use async_trait::async_trait;
use serde_json::Value;
use std::{
    future::Future,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhysicalInput {
    Escape,
    Activity,
}

const ACTIVE: u8 = 0;
const INTERRUPTED: u8 = 1;
const RETIRED: u8 = 2;
const INTERRUPTED_RETIRED: u8 = INTERRUPTED | RETIRED;

/// A refusal before the next native request, or an unconfirmed resource close.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InterruptionError {
    Interrupted,
    Retired,
    Unavailable(String),
    CleanupUnconfirmed(String),
}

impl std::fmt::Display for InterruptionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Interrupted => {
                formatter.write_str("Computer Use was interrupted by physical Escape for this turn")
            }
            Self::Retired => formatter.write_str("native interruption binding has retired"),
            Self::Unavailable(reason) | Self::CleanupUnconfirmed(reason) => {
                formatter.write_str(reason)
            }
        }
    }
}
impl std::error::Error for InterruptionError {}

/// Must deliver metadata to the original owned producer without blocking the
/// Win32 callback thread. Never retain key contents or fabricate a Host event.
pub trait InterruptionSink: Send + Sync + 'static {
    fn notify(&self, input: PhysicalInput) -> Result<(), String>;
}

/// Actual native resource custody, such as an injected key or target-thread
/// suspension. Implementations must close idempotently and report failures.
/// This is never synthesized from a caller's key/PID/session JSON.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeReleasePhase {
    ResumeTarget,
    ReleaseInput,
    RestoreContext,
}
pub trait NativeInputRelease: Send + Sync + 'static {
    fn phase(&self) -> NativeReleasePhase {
        NativeReleasePhase::RestoreContext
    }
    fn release(&self) -> Result<(), String>;
}
struct OwnedRelease {
    resource: Arc<dyn NativeInputRelease>,
    failure: std::sync::Mutex<Option<String>>,
}
impl OwnedRelease {
    fn release(&self) -> Result<(), String> {
        let result = self.resource.release();
        *self
            .failure
            .lock()
            .expect("native resource failure lock poisoned") = result.as_ref().err().cloned();
        result
    }
}

/// A worker's real resource registration. A failed Drop stays with the same
/// binding so explicit native retirement can retry and report the result.
pub struct NativeInputReceipt {
    binding: std::sync::Weak<WindowsInputBinding>,
    release: Arc<OwnedRelease>,
}
impl std::fmt::Debug for NativeInputReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeInputReceipt")
            .finish_non_exhaustive()
    }
}
impl Drop for NativeInputReceipt {
    fn drop(&mut self) {
        if self.release.release().is_ok() {
            if let Some(binding) = self.binding.upgrade() {
                binding.remove_release(&self.release);
            }
        }
    }
}

/// The SDK constructs this only from its actual immutable RuntimeSession.
/// NativeAbiSession separately checks the opaque SDK owner's pointer identity.
/// Public identity strings alone are never sufficient to select a binding.
pub struct WindowsInputBinding {
    owner: String,
    turn: String,
    sink: Arc<dyn InterruptionSink>,
    state: AtomicU8,
    releases: std::sync::Mutex<Vec<Arc<OwnedRelease>>>,
}
impl std::fmt::Debug for WindowsInputBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WindowsInputBinding")
            .field("turn", &self.turn)
            .finish_non_exhaustive()
    }
}
impl WindowsInputBinding {
    pub fn new(
        owner: String,
        turn: String,
        sink: Arc<dyn InterruptionSink>,
    ) -> Result<Arc<Self>, String> {
        if owner.is_empty() || turn.is_empty() {
            return Err("native interruption binding identity is empty".into());
        }
        Ok(Arc::new(Self {
            owner,
            turn,
            sink,
            state: AtomicU8::new(ACTIVE),
            releases: std::sync::Mutex::new(Vec::new()),
        }))
    }
    pub fn owner(&self) -> &str {
        &self.owner
    }
    pub fn turn(&self) -> &str {
        &self.turn
    }
    pub fn notify(&self, input: PhysicalInput) -> Result<(), String> {
        match input {
            PhysicalInput::Escape => {
                // State changes before delivery; a failed event observer may
                // never reopen this already interrupted native turn.
                if self
                    .state
                    .compare_exchange(ACTIVE, INTERRUPTED, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    return Ok(());
                }
            }
            PhysicalInput::Activity if self.state.load(Ordering::Acquire) != ACTIVE => {
                return Ok(())
            }
            PhysicalInput::Activity => {}
        }
        self.sink.notify(input)
    }
    pub fn check(&self) -> Result<(), InterruptionError> {
        match self.state.load(Ordering::Acquire) {
            ACTIVE => Ok(()),
            INTERRUPTED | INTERRUPTED_RETIRED => Err(InterruptionError::Interrupted),
            _ => Err(InterruptionError::Retired),
        }
    }
    /// Retiring this resource prevents late observations from reaching its
    /// former consumer. It does not cancel an Agent or grant another turn.
    pub fn retire(&self) {
        self.state.fetch_or(RETIRED, Ordering::AcqRel);
    }
    pub fn retain_input_release(
        self: &Arc<Self>,
        resource: Arc<dyn NativeInputRelease>,
    ) -> Result<NativeInputReceipt, InterruptionError> {
        let mut releases = self
            .releases
            .lock()
            .expect("native input release custody lock poisoned");
        self.check()?;
        let release = Arc::new(OwnedRelease {
            resource,
            failure: std::sync::Mutex::new(None),
        });
        releases.push(release.clone());
        Ok(NativeInputReceipt {
            binding: Arc::downgrade(self),
            release,
        })
    }
    fn remove_release(&self, release: &Arc<OwnedRelease>) {
        let mut releases = self
            .releases
            .lock()
            .expect("native input release custody lock poisoned");
        releases.retain(|held| !Arc::ptr_eq(held, release));
    }
    /// Release only real resources registered by native workers. This does not
    /// wait for an unrelated provider or claim its action outcome is known.
    pub fn release_owned_inputs(&self) -> Result<(), String> {
        let mut failures = Vec::new();
        for phase in [
            NativeReleasePhase::ResumeTarget,
            NativeReleasePhase::ReleaseInput,
            NativeReleasePhase::RestoreContext,
        ] {
            failures.extend(self.release_owned_inputs_in_phase(phase).err());
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
    pub fn release_owned_inputs_in_phase(&self, phase: NativeReleasePhase) -> Result<(), String> {
        let held = self
            .releases
            .lock()
            .expect("native input release custody lock poisoned")
            .clone();
        let mut failures = Vec::new();
        for release in held {
            if release.resource.phase() != phase {
                continue;
            }
            match release.release() {
                Ok(()) => self.remove_release(&release),
                Err(error) => failures.push(error),
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
    pub fn failed_input_releases(&self) -> Result<(), String> {
        let held = self
            .releases
            .lock()
            .expect("native input release custody lock poisoned");
        let failures: Vec<_> = held
            .iter()
            .filter_map(|release| {
                release
                    .failure
                    .lock()
                    .expect("native resource failure lock poisoned")
                    .clone()
            })
            .collect();
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
}

tokio::task_local! { static WINDOWS_INPUT_BINDING: Arc<WindowsInputBinding>; }
thread_local! {
    static WINDOWS_INPUT_WORKER: std::cell::RefCell<Option<Arc<WindowsInputBinding>>> = const { std::cell::RefCell::new(None) };
}

/// Typed SDK-only invocation wrapper; not part of the model/transport schema.
pub async fn with_windows_input_binding<F: Future>(
    binding: Arc<WindowsInputBinding>,
    call: F,
) -> F::Output {
    WINDOWS_INPUT_BINDING.scope(binding, call).await
}
pub fn current_windows_input_binding() -> Option<Arc<WindowsInputBinding>> {
    WINDOWS_INPUT_BINDING
        .try_with(Arc::clone)
        .ok()
        .or_else(|| WINDOWS_INPUT_WORKER.with(|worker| worker.borrow().clone()))
}

/// Carry the same immutable native binding into an already admitted blocking
/// worker. This creates no authority and restores nested worker state on drop.
pub fn with_windows_input_worker<T>(
    binding: Arc<WindowsInputBinding>,
    call: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<Arc<WindowsInputBinding>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            WINDOWS_INPUT_WORKER.with(|worker| {
                worker.replace(self.0.take());
            });
        }
    }
    let _restore = Restore(WINDOWS_INPUT_WORKER.with(|worker| worker.replace(Some(binding))));
    call()
}

/// One Windows physical monitor resource retained by the existing ToolRegistry.
/// Implementations use the real native worker lease before leaving the async
/// executor, then keep the thread in the ordinary runtime/session cleanup owner.
#[allow(
    clippy::double_must_use,
    reason = "async_trait emits redundant must_use attributes on boxed futures"
)]
#[async_trait]
pub trait WindowsInterruptionBackend: Send + Sync {
    async fn invoke(
        &self,
        tool: &dyn crate::tool::Tool,
        name: &str,
        args: Value,
    ) -> crate::protocol::ToolResult;
    /// Blocking exact native close/join; caller uses the existing cleanup worker.
    fn close_turn(&self, owner: &str, turn: &str) -> Result<(), String>;
    fn close_binding(&self, binding: &Arc<WindowsInputBinding>) -> Result<(), String>;
    fn release_binding_inputs(&self, binding: &Arc<WindowsInputBinding>) -> Result<(), String>;
    fn close_session(&self, owner: &str) -> Result<(), String>;
    fn close_all(&self) -> Result<(), String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Sink {
        events: Mutex<Vec<PhysicalInput>>,
        fail: bool,
    }
    impl InterruptionSink for Sink {
        fn notify(&self, input: PhysicalInput) -> Result<(), String> {
            self.events.lock().unwrap().push(input);
            if self.fail {
                Err("observer is unavailable".into())
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn physical_escape_refuses_same_binding_even_if_observer_fails() {
        let sink = Arc::new(Sink {
            events: Mutex::new(Vec::new()),
            fail: true,
        });
        let binding =
            WindowsInputBinding::new("runtime/session".into(), "turn-a".into(), sink.clone())
                .unwrap();
        assert_eq!(binding.check(), Ok(()));
        assert_eq!(
            binding.notify(PhysicalInput::Escape),
            Err("observer is unavailable".into())
        );
        assert_eq!(binding.check(), Err(InterruptionError::Interrupted));
        binding.notify(PhysicalInput::Escape).unwrap();
        assert_eq!(*sink.events.lock().unwrap(), vec![PhysicalInput::Escape]);
        let next =
            WindowsInputBinding::new("runtime/session".into(), "turn-b".into(), sink).unwrap();
        assert_eq!(next.check(), Ok(()));
    }

    #[test]
    fn retired_producer_cannot_notify_or_interrupt_its_replacement() {
        let sink = Arc::new(Sink {
            events: Mutex::new(Vec::new()),
            fail: false,
        });
        let old = WindowsInputBinding::new("runtime/session".into(), "turn-a".into(), sink.clone())
            .unwrap();
        let current =
            WindowsInputBinding::new("runtime/session".into(), "turn-b".into(), sink.clone())
                .unwrap();
        old.retire();
        old.notify(PhysicalInput::Escape).unwrap();
        old.notify(PhysicalInput::Activity).unwrap();
        assert_eq!(old.check(), Err(InterruptionError::Retired));
        assert_eq!(current.check(), Ok(()));
        assert!(sink.events.lock().unwrap().is_empty());
        current.notify(PhysicalInput::Escape).unwrap();
        assert_eq!(current.check(), Err(InterruptionError::Interrupted));
        assert_eq!(*sink.events.lock().unwrap(), vec![PhysicalInput::Escape]);
    }

    struct ReleaseOnce {
        failure_pending: std::sync::atomic::AtomicBool,
        held: std::sync::atomic::AtomicBool,
        released: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl NativeInputRelease for ReleaseOnce {
        fn release(&self) -> Result<(), String> {
            if self.failure_pending.swap(false, Ordering::AcqRel) {
                return Err("fixture native resource still held".into());
            }
            if self.held.swap(false, Ordering::AcqRel) {
                self.released.fetch_add(1, Ordering::AcqRel);
            }
            Ok(())
        }
    }

    #[test]
    fn failed_worker_drop_retains_actual_release_owner_until_confirmed_retry() {
        let sink = Arc::new(Sink {
            events: Mutex::new(Vec::new()),
            fail: false,
        });
        let binding =
            WindowsInputBinding::new("runtime/session".into(), "turn-a".into(), sink).unwrap();
        let released = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let resource = Arc::new(ReleaseOnce {
            failure_pending: std::sync::atomic::AtomicBool::new(true),
            held: std::sync::atomic::AtomicBool::new(true),
            released: released.clone(),
        });
        let weak = Arc::downgrade(&resource);
        let receipt = binding.retain_input_release(resource.clone()).unwrap();
        drop(resource);
        drop(receipt);
        assert!(
            weak.upgrade().is_some(),
            "failed native Drop must retain its real resource"
        );
        assert_eq!(
            binding.failed_input_releases(),
            Err("fixture native resource still held".into())
        );
        binding.retire();
        binding.release_owned_inputs().unwrap();
        assert_eq!(released.load(Ordering::Acquire), 1);
        assert!(
            weak.upgrade().is_none(),
            "confirmed release retires its retained resource"
        );
        binding.release_owned_inputs().unwrap();
        assert_eq!(
            released.load(Ordering::Acquire),
            1,
            "a completed resource must not be released twice"
        );
        let late = Arc::new(ReleaseOnce {
            failure_pending: std::sync::atomic::AtomicBool::new(false),
            held: std::sync::atomic::AtomicBool::new(true),
            released,
        });
        assert!(matches!(
            binding.retain_input_release(late),
            Err(InterruptionError::Retired)
        ));
    }

    #[test]
    fn owner_releases_resource_while_original_worker_still_holds_its_receipt() {
        let sink = Arc::new(Sink {
            events: Mutex::new(Vec::new()),
            fail: false,
        });
        let binding =
            WindowsInputBinding::new("runtime/session".into(), "turn-a".into(), sink).unwrap();
        let released = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let resource = Arc::new(ReleaseOnce {
            failure_pending: std::sync::atomic::AtomicBool::new(false),
            held: std::sync::atomic::AtomicBool::new(true),
            released: released.clone(),
        });
        let receipt = binding.retain_input_release(resource).unwrap();
        binding.notify(PhysicalInput::Escape).unwrap();
        binding.retire();
        binding.release_owned_inputs().unwrap();
        assert_eq!(binding.check(), Err(InterruptionError::Interrupted));
        assert_eq!(released.load(Ordering::Acquire), 1);
        drop(receipt);
        assert_eq!(
            released.load(Ordering::Acquire),
            1,
            "late worker Drop cannot release a new or already released resource"
        );
    }
    #[test]
    fn typed_native_release_settles_resume_before_up_and_context_while_worker_lives() {
        struct Resource {
            phase: NativeReleasePhase,
            held: std::sync::atomic::AtomicBool,
            trace: Arc<Mutex<Vec<NativeReleasePhase>>>,
        }
        impl NativeInputRelease for Resource {
            fn phase(&self) -> NativeReleasePhase {
                self.phase
            }
            fn release(&self) -> Result<(), String> {
                if self.held.swap(false, Ordering::AcqRel) {
                    self.trace.lock().unwrap().push(self.phase);
                }
                Ok(())
            }
        }
        let binding = WindowsInputBinding::new(
            "runtime/session".into(),
            "turn".into(),
            Arc::new(Sink {
                events: Mutex::new(Vec::new()),
                fail: false,
            }),
        )
        .unwrap();
        let trace = Arc::new(Mutex::new(Vec::new()));
        let mut receipts = Vec::new();
        // Registration order deliberately differs from required release order.
        for phase in [
            NativeReleasePhase::RestoreContext,
            NativeReleasePhase::ReleaseInput,
            NativeReleasePhase::ResumeTarget,
        ] {
            receipts.push(
                binding
                    .retain_input_release(Arc::new(Resource {
                        phase,
                        held: std::sync::atomic::AtomicBool::new(true),
                        trace: trace.clone(),
                    }))
                    .unwrap(),
            );
        }
        binding.retire();
        binding.release_owned_inputs().unwrap();
        assert_eq!(
            *trace.lock().unwrap(),
            [
                NativeReleasePhase::ResumeTarget,
                NativeReleasePhase::ReleaseInput,
                NativeReleasePhase::RestoreContext
            ]
        );
        drop(receipts);
        assert_eq!(
            trace.lock().unwrap().len(),
            3,
            "late worker Drop cannot release twice"
        );
    }

    #[test]
    #[should_panic(expected = "fixture resource programmer panic")]
    fn owned_release_propagates_programmer_panic() {
        struct PanicOnce(std::sync::atomic::AtomicBool);
        impl NativeInputRelease for PanicOnce {
            fn release(&self) -> Result<(), String> {
                if self.0.swap(false, Ordering::AcqRel) {
                    panic!("fixture resource programmer panic");
                }
                Ok(())
            }
        }
        let binding = WindowsInputBinding::new(
            "runtime/session".into(),
            "turn".into(),
            Arc::new(Sink {
                events: Mutex::new(Vec::new()),
                fail: false,
            }),
        )
        .unwrap();
        // The second release during receipt Drop succeeds, so this fixture
        // observes the original panic without causing a double-panic abort.
        let _receipt = binding
            .retain_input_release(Arc::new(PanicOnce(std::sync::atomic::AtomicBool::new(
                true,
            ))))
            .unwrap();
        let _ = binding.release_owned_inputs();
    }

    #[test]
    #[should_panic(expected = "native input release custody lock poisoned")]
    fn poisoned_release_custody_is_fatal() {
        let binding = WindowsInputBinding::new(
            "runtime/session".into(),
            "turn".into(),
            Arc::new(Sink {
                events: Mutex::new(Vec::new()),
                fail: false,
            }),
        )
        .unwrap();
        let poisoned = binding.clone();
        assert!(std::thread::spawn(move || {
            let _guard = poisoned.releases.lock().unwrap();
            panic!("fixture custody poison");
        })
        .join()
        .is_err());
        // Returning an ordinary Err must fail this should_panic keeper.
        let _ = binding.failed_input_releases();
    }
}
