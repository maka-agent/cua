//! Owned NSWorkspace activation notifications with explicit callback drainage.

use block2::RcBlock;
use objc2::{msg_send, rc::Retained, runtime::AnyObject, ClassType};
use objc2_app_kit::{
    NSRunningApplication, NSWorkspace, NSWorkspaceApplicationKey,
    NSWorkspaceDidActivateApplicationNotification,
};
use objc2_foundation::{NSNotification, NSNotificationCenter, NSObject};
use std::{
    collections::HashMap,
    panic::{self, AssertUnwindSafe},
    ptr::NonNull,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Condvar, Mutex,
    },
    thread::{self, JoinHandle, ThreadId},
};

/// Activation-observer startup or explicit cleanup failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ActivationObserverError {
    #[error("native activation-observer worker could not start")]
    Spawn(#[source] std::io::Error),
    #[error("native activation-observer startup channel closed")]
    StartupDisconnected,
    #[error("native activation-observer worker panicked")]
    WorkerPanicked,
    #[error("native activation-observer callback panicked")]
    CallbackPanicked,
    #[error("native activation-observer callback cannot wait for its own drainage")]
    WouldJoinSelf,
}

#[derive(Clone, Copy)]
enum Outcome {
    Complete,
    WorkerPanicked,
    CallbackPanicked,
}

impl Outcome {
    fn result(self) -> Result<(), ActivationObserverError> {
        match self {
            Self::Complete => Ok(()),
            Self::WorkerPanicked => Err(ActivationObserverError::WorkerPanicked),
            Self::CallbackPanicked => Err(ActivationObserverError::CallbackPanicked),
        }
    }
}

#[derive(Default)]
struct Gate {
    inflight: usize,
    threads: HashMap<ThreadId, usize>,
}

struct Shared {
    closed: AtomicBool,
    stop_requested: AtomicBool,
    callback_panicked: AtomicBool,
    gate: Mutex<Gate>,
    drained: Condvar,
    stop: mpsc::Sender<()>,
}

impl Shared {
    fn enter(self: &Arc<Self>) -> Option<InFlight> {
        let mut gate = self
            .gate
            .lock()
            .expect("native activation callback gate poisoned");
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        gate.inflight += 1;
        *gate.threads.entry(thread::current().id()).or_default() += 1;
        Some(InFlight {
            shared: Arc::clone(self),
            thread: thread::current().id(),
        })
    }

    fn is_callback_thread(&self) -> bool {
        self.gate
            .lock()
            .expect("native activation callback gate poisoned")
            .threads
            .contains_key(&thread::current().id())
    }

    fn request_stop(&self) {
        self.closed.store(true, Ordering::Release);
        if !self.stop_requested.swap(true, Ordering::AcqRel) {
            let _ = self.stop.send(());
        }
    }

    fn wait_drained(&self) {
        let mut gate = self
            .gate
            .lock()
            .expect("native activation callback gate poisoned");
        while gate.inflight != 0 {
            gate = self
                .drained
                .wait(gate)
                .expect("native activation callback gate poisoned");
        }
    }
}

struct InFlight {
    shared: Arc<Shared>,
    thread: ThreadId,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        let mut gate = self
            .shared
            .gate
            .lock()
            .expect("native activation callback gate poisoned");
        gate.inflight -= 1;
        let count = gate
            .threads
            .get_mut(&self.thread)
            .expect("native activation callback thread missing");
        *count -= 1;
        if *count == 0 {
            gate.threads.remove(&self.thread);
        }
        if gate.inflight == 0 {
            self.shared.drained.notify_all();
        }
    }
}

/// Owns the native observer token, block and center on one cleanup worker.
///
/// Notifications retain the original queue=nil behavior: the callback executes
/// on the posting thread. Drop requests closure only; explicit stop_and_join
/// removes the token and waits for every admitted callback before joining.
#[must_use = "retain the observer until explicit stop_and_join completes"]
pub struct ActivationObserver {
    shared: Arc<Shared>,
    worker: Option<JoinHandle<Outcome>>,
    completion: Option<Outcome>,
}

impl std::fmt::Debug for ActivationObserver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActivationObserver")
            .field("closed", &self.shared.closed.load(Ordering::Acquire))
            .field("joined", &self.worker.is_none())
            .finish_non_exhaustive()
    }
}

impl ActivationObserver {
    /// Register the NSWorkspace activation observer without an operation queue.
    ///
    /// No initial PID is synthesized; the caller owns its state-seeding read.
    ///
    /// # Errors
    /// Returns a worker-start or native registration panic failure.
    pub fn start(
        callback: Arc<dyn Fn(i32) + Send + Sync>,
    ) -> Result<Self, ActivationObserverError> {
        let (stop_tx, stop_rx) = mpsc::channel();
        let shared = Arc::new(Shared {
            closed: AtomicBool::new(false),
            stop_requested: AtomicBool::new(false),
            callback_panicked: AtomicBool::new(false),
            gate: Mutex::new(Gate::default()),
            drained: Condvar::new(),
            stop: stop_tx,
        });
        let worker_shared = Arc::clone(&shared);
        let (startup_tx, startup_rx) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("cua-native-focus-observer".into())
            .spawn(move || {
                let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
                    objc2::rc::autoreleasepool(|_| {
                        run_observer(worker_shared, callback, stop_rx, startup_tx.clone())
                    })
                }))
                .unwrap_or(Outcome::WorkerPanicked);
                let _ = startup_tx.send(outcome);
                outcome
            })
            .map_err(ActivationObserverError::Spawn)?;
        match startup_rx.recv() {
            Ok(Outcome::Complete) => Ok(Self {
                shared,
                worker: Some(worker),
                completion: None,
            }),
            Ok(failure) => {
                shared.request_stop();
                let outcome = worker.join().unwrap_or(Outcome::WorkerPanicked);
                outcome.result().and(failure.result())?;
                unreachable!("observer startup failure cannot report complete")
            }
            Err(_) => {
                shared.request_stop();
                let _ = worker.join();
                Err(ActivationObserverError::StartupDisconnected)
            }
        }
    }

    /// Close callback admission immediately; token removal remains explicit cleanup.
    pub fn seal(&self) {
        self.shared.request_stop();
    }

    /// Remove the native observer, drain admitted callbacks, and join its owner.
    ///
    /// Call outside policy locks on a cleanup worker. A callback cannot wait
    /// for itself: that refusal leaves the same join handle owned for retry.
    ///
    /// # Errors
    /// Returns WouldJoinSelf without consuming the handle, or the joined terminal
    /// failure. Repeated calls preserve the same terminal completion result.
    pub fn stop_and_join(&mut self) -> Result<(), ActivationObserverError> {
        self.shared.request_stop();
        if self.shared.is_callback_thread() {
            return Err(ActivationObserverError::WouldJoinSelf);
        }
        if let Some(worker) = self.worker.as_ref() {
            if worker.thread().id() == thread::current().id() {
                return Err(ActivationObserverError::WouldJoinSelf);
            }
        }
        if let Some(worker) = self.worker.take() {
            self.completion = Some(worker.join().unwrap_or(Outcome::WorkerPanicked));
        }
        self.completion.unwrap_or(Outcome::Complete).result()
    }
}

impl Drop for ActivationObserver {
    fn drop(&mut self) {
        self.shared.request_stop();
    }
}

struct Registration {
    shared: Arc<Shared>,
    center: Retained<NSNotificationCenter>,
    token: Retained<NSObject>,
    // Keep our own block until removeObserver and the admitted-callback drain finish.
    _block: RcBlock<dyn Fn(NonNull<NSNotification>)>,
    registered: bool,
}

impl Registration {
    fn remove_and_drain(&mut self) {
        self.shared.closed.store(true, Ordering::Release);
        if self.registered {
            // SAFETY: the same retained center and token own this registration.
            // No gate/policy lock is held while AppKit removes the observer.
            unsafe { self.center.removeObserver(&self.token) };
            self.registered = false;
        }
        self.shared.wait_drained();
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        // This owner stays on its dedicated cleanup worker even during unwinding.
        self.remove_and_drain();
    }
}

fn run_observer(
    shared: Arc<Shared>,
    callback: Arc<dyn Fn(i32) + Send + Sync>,
    stop: mpsc::Receiver<()>,
    startup: mpsc::Sender<Outcome>,
) -> Outcome {
    // SAFETY: these are the same NSWorkspace notification interfaces used by the
    // platform adapter. All owned AppKit handles remain on this worker.
    let workspace = unsafe { NSWorkspace::sharedWorkspace() };
    let center = unsafe { workspace.notificationCenter() };
    let callback_shared = Arc::clone(&shared);
    let block = RcBlock::new(move |notification: NonNull<NSNotification>| {
        // The outer catch also covers payload decoding: no Rust unwind crosses
        // the Objective-C block invocation boundary.
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            let Some(_inflight) = callback_shared.enter() else {
                return;
            };
            objc2::rc::autoreleasepool(|_| {
                // SAFETY: NSNotificationCenter lends this object for the block call.
                let note = unsafe { notification.as_ref() };
                if let Some(pid) = activation_pid(note) {
                    callback(pid);
                }
            });
        }));
        if result.is_err() {
            callback_shared
                .callback_panicked
                .store(true, Ordering::Release);
            callback_shared.request_stop();
        }
    });
    // SAFETY: notification name and block have their native types. Both object
    // and queue are nil, preserving synchronous delivery on the posting thread.
    let token = unsafe {
        center.addObserverForName_object_queue_usingBlock(
            Some(NSWorkspaceDidActivateApplicationNotification),
            None,
            None,
            &block,
        )
    };
    let mut registration = Registration {
        shared: Arc::clone(&shared),
        center,
        token,
        _block: block,
        registered: true,
    };
    if startup.send(Outcome::Complete).is_ok() {
        let _ = stop.recv();
    }
    registration.remove_and_drain();
    // Release our token, center and copied block only after the real drain.
    drop(registration);
    if shared.callback_panicked.load(Ordering::Acquire) {
        Outcome::CallbackPanicked
    } else {
        Outcome::Complete
    }
}

fn activation_pid(note: &NSNotification) -> Option<i32> {
    // SAFETY: this native notification's userInfo is borrowed for this callback.
    let info = unsafe { note.userInfo() }?;
    // SAFETY: NSWorkspaceApplicationKey is the documented notification key.
    let app: *mut AnyObject = unsafe { msg_send![&*info, objectForKey: NSWorkspaceApplicationKey] };
    if app.is_null() {
        return None;
    }
    // SAFETY: app is a live Objective-C object from the notification dictionary;
    // verify its class before using the NSRunningApplication PID selector.
    let is_running_app: bool =
        unsafe { msg_send![app, isKindOfClass: NSRunningApplication::class()] };
    if !is_running_app {
        return None;
    }
    // SAFETY: the checked object remains retained by userInfo for this call.
    Some(unsafe { msg_send![app, processIdentifier] })
}
