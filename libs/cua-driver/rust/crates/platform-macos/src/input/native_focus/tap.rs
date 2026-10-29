//! Owned CoreGraphics event taps; policy and PID authority stay with the caller.

use block2::{Block, RcBlock};
use core_foundation::{base::TCFType, runloop::CFRunLoop};
use std::{
    cell::{Cell, RefCell},
    ffi::c_void,
    marker::PhantomData,
    panic::{self, AssertUnwindSafe},
    ptr::{self, NonNull},
    sync::{
        atomic::{AtomicBool, AtomicPtr, Ordering},
        mpsc, Arc, Mutex,
    },
    thread::{self, JoinHandle},
};

const TAP_DISABLED_BY_TIMEOUT: u32 = 0xffff_fffe;
const TAP_DISABLED_BY_USER_INPUT: u32 = 0xffff_ffff;

/// Return the same event pointer, or suppress its original delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    Keep,
    Drop,
}

/// A CGEvent borrowed for this callback only, without acquiring PID authority.
#[derive(Debug)]
pub struct BorrowedEvent<'event> {
    event_type: u32,
    event: NonNull<c_void>,
    lifetime: PhantomData<&'event c_void>,
}

impl BorrowedEvent<'_> {
    /// The raw event type supplied by CoreGraphics.
    pub fn event_type(&self) -> u32 {
        self.event_type
    }

    /// The original pointer, valid only during the callback; ownership is unchanged.
    pub fn as_ptr(&self) -> *mut c_void {
        self.event.as_ptr()
    }

    /// Read a raw integer field from the borrowed event.
    pub fn integer_value_field(&self, raw_field: u32) -> i64 {
        // SAFETY: the callback retains the original event for this borrow.
        unsafe { CGEventGetIntegerValueField(self.event.as_ptr(), raw_field) }
    }

    /// Forward the same event to a PID, preserving its existing timestamp.
    ///
    /// The caller must separately authorize the recipient; this grants no access.
    pub fn post_to_pid(&self, pid: i32) {
        // SAFETY: the event remains live for this synchronous post. The API
        // accepts the PID by value and does not consume the borrowed event.
        unsafe { CGEventPostToPid(pid, self.event.as_ptr()) };
    }
}

/// Event-tap startup, callback or explicit cleanup failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TapError {
    #[error("native event-tap worker could not start")]
    Spawn(#[source] std::io::Error),
    #[error("native event tap could not be created")]
    CreateUnavailable,
    #[error("native event tap run-loop source could not be installed")]
    SourceUnavailable,
    #[error("native event tap could not be enabled")]
    EnableUnavailable,
    #[error("native event-tap startup channel closed")]
    StartupDisconnected,
    #[error("native event-tap worker panicked")]
    WorkerPanicked,
    #[error("native event-tap callback panicked")]
    CallbackPanicked,
    #[error("native event-tap run loop exited before closure")]
    UnexpectedExit,
    #[error("native event-tap callback cannot join its own worker")]
    WouldJoinSelf,
}

#[derive(Clone, Copy)]
enum Outcome {
    Complete,
    CreateUnavailable,
    SourceUnavailable,
    EnableUnavailable,
    WorkerPanicked,
    CallbackPanicked,
    UnexpectedExit,
}

impl Outcome {
    fn result(self) -> Result<(), TapError> {
        match self {
            Self::Complete => Ok(()),
            Self::CreateUnavailable => Err(TapError::CreateUnavailable),
            Self::SourceUnavailable => Err(TapError::SourceUnavailable),
            Self::EnableUnavailable => Err(TapError::EnableUnavailable),
            Self::WorkerPanicked => Err(TapError::WorkerPanicked),
            Self::CallbackPanicked => Err(TapError::CallbackPanicked),
            Self::UnexpectedExit => Err(TapError::UnexpectedExit),
        }
    }
}

struct LiveTap {
    // This atomic pointer preserves native pointer provenance across threads.
    // The worker owns the port; resources' mutex pins its lifetime for control calls.
    port: AtomicPtr<c_void>,
    run_loop: CFRunLoop,
}

struct Shared {
    open: AtomicBool,
    stop_requested: AtomicBool,
    callback_panicked: AtomicBool,
    resources: Mutex<Option<LiveTap>>,
}

impl Shared {
    fn seal(&self) {
        self.open.store(false, Ordering::Release);
        let resources = self
            .resources
            .lock()
            .expect("native tap resource lock poisoned");
        if let Some(live) = resources.as_ref() {
            // SAFETY: this lock pins the worker-owned port until the call returns.
            unsafe { CGEventTapEnable(live.port.load(Ordering::Relaxed), false) };
        }
    }

    fn request_stop(&self) {
        self.seal();
        if self.stop_requested.swap(true, Ordering::AcqRel) {
            return;
        }
        let resources = self
            .resources
            .lock()
            .expect("native tap resource lock poisoned");
        if let Some(live) = resources.as_ref() {
            let run_loop = live.run_loop.as_concrete_TypeRef().cast::<c_void>();
            // The queued block outlives this local RcBlock. It runs on its own
            // retained run loop, so its pointer is live when Stop is executed.
            let stop = RcBlock::new(move || {
                // SAFETY: CoreFoundation invokes this block on that same run loop.
                unsafe { CFRunLoopStop(run_loop) };
            });
            // SAFETY: CFRunLoopPerformBlock copies the block. Queuing, rather than
            // a pre-run Stop, preserves a stop request before the first Run call.
            unsafe {
                CFRunLoopPerformBlock(run_loop, kCFRunLoopDefaultMode, &stop);
                CFRunLoopWakeUp(run_loop);
            }
        }
    }
}

type Callback = dyn for<'event> FnMut(BorrowedEvent<'event>) -> Disposition + Send + 'static;

struct CallbackContext {
    shared: Arc<Shared>,
    callback: RefCell<Box<Callback>>,
    port: Cell<*mut c_void>,
}

/// Owns one tap, its callback allocation and its worker's retained completion.
///
/// Drop seals and requests stop only. Use [`Self::stop_and_join`] on a cleanup
/// worker for actual callback drainage and release completion.
#[must_use = "retain the tap until explicit stop_and_join completes"]
pub struct Tap {
    shared: Arc<Shared>,
    worker: Option<JoinHandle<Outcome>>,
    completion: Option<Outcome>,
}

impl std::fmt::Debug for Tap {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Tap")
            .field("sealed", &!self.shared.open.load(Ordering::Acquire))
            .field("joined", &self.worker.is_none())
            .finish_non_exhaustive()
    }
}

impl Tap {
    /// Install a global tap and await an acknowledgment from its running loop.
    ///
    /// # Errors
    /// Returns the exact native creation, source, enable or worker-start failure.
    pub fn global<F>(
        location: u32,
        placement: u32,
        options: u32,
        mask: u64,
        callback: F,
    ) -> Result<Self, TapError>
    where
        F: for<'event> FnMut(BorrowedEvent<'event>) -> Disposition + Send + 'static,
    {
        Self::start(
            Target::Global(location),
            placement,
            options,
            mask,
            Box::new(callback),
        )
    }

    /// Install a PID tap and await an acknowledgment from its running loop.
    ///
    /// # Errors
    /// Returns the exact native creation, source, enable or worker-start failure.
    pub fn for_pid<F>(
        pid: i32,
        placement: u32,
        options: u32,
        mask: u64,
        callback: F,
    ) -> Result<Self, TapError>
    where
        F: for<'event> FnMut(BorrowedEvent<'event>) -> Disposition + Send + 'static,
    {
        Self::start(
            Target::Pid(pid),
            placement,
            options,
            mask,
            Box::new(callback),
        )
    }

    fn start(
        target: Target,
        placement: u32,
        options: u32,
        mask: u64,
        callback: Box<Callback>,
    ) -> Result<Self, TapError> {
        let shared = Arc::new(Shared {
            open: AtomicBool::new(true),
            stop_requested: AtomicBool::new(false),
            callback_panicked: AtomicBool::new(false),
            resources: Mutex::new(None),
        });
        let (startup_tx, startup_rx) = mpsc::channel();
        let worker_shared = Arc::clone(&shared);
        let worker = thread::Builder::new()
            .name("cua-native-focus-tap".into())
            .spawn(move || {
                let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
                    run_tap(
                        worker_shared,
                        target,
                        placement,
                        options,
                        mask,
                        callback,
                        startup_tx.clone(),
                    )
                }))
                .unwrap_or(Outcome::WorkerPanicked);
                let _ = startup_tx.send(outcome);
                outcome
            })
            .map_err(TapError::Spawn)?;
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
                unreachable!("startup failure cannot report complete")
            }
            Err(_) => {
                shared.request_stop();
                let _ = worker.join();
                Err(TapError::StartupDisconnected)
            }
        }
    }

    /// Atomically reject new policy callbacks and disable the native tap.
    pub fn seal(&self) {
        self.shared.seal();
    }

    /// Stop the actual run loop and join the same worker without holding policy locks.
    ///
    /// # Errors
    /// Returns [`TapError::WouldJoinSelf`] without consuming the retained handle
    /// when invoked on the callback thread. Other errors report a terminal joined
    /// worker; repeated calls preserve that same completion result.
    pub fn stop_and_join(&mut self) -> Result<(), TapError> {
        self.shared.request_stop();
        if let Some(worker) = self.worker.as_ref() {
            if worker.thread().id() == thread::current().id() {
                return Err(TapError::WouldJoinSelf);
            }
        }
        if let Some(worker) = self.worker.take() {
            self.completion = Some(worker.join().unwrap_or(Outcome::WorkerPanicked));
        }
        self.completion.unwrap_or(Outcome::Complete).result()
    }
}

impl Drop for Tap {
    fn drop(&mut self) {
        self.shared.request_stop();
    }
}

#[derive(Clone, Copy)]
enum Target {
    Global(u32),
    Pid(i32),
}

struct ThreadResources {
    shared: Arc<Shared>,
    port: *mut c_void,
    source: *mut c_void,
    run_loop: CFRunLoop,
}

impl Drop for ThreadResources {
    fn drop(&mut self) {
        self.shared.open.store(false, Ordering::Release);
        // Remove cross-thread control handles before releasing either native object.
        let control = self
            .shared
            .resources
            .lock()
            .expect("native tap resource lock poisoned")
            .take();
        drop(control);
        // SAFETY: this worker owns both create-rule objects and the retained loop.
        // Run has returned, so no callback can still use its borrowed context.
        unsafe {
            CGEventTapEnable(self.port, false);
            CFMachPortInvalidate(self.port);
            if !self.source.is_null() {
                CFRunLoopRemoveSource(
                    self.run_loop.as_concrete_TypeRef().cast(),
                    self.source,
                    kCFRunLoopCommonModes,
                );
                CFRelease(self.source);
            }
            CFRelease(self.port);
        }
    }
}

fn run_tap(
    shared: Arc<Shared>,
    target: Target,
    placement: u32,
    options: u32,
    mask: u64,
    callback: Box<Callback>,
    startup: mpsc::Sender<Outcome>,
) -> Outcome {
    let mut context = Box::new(CallbackContext {
        shared: Arc::clone(&shared),
        callback: RefCell::new(callback),
        port: Cell::new(ptr::null_mut()),
    });
    let user_info = (&mut *context as *mut CallbackContext).cast::<c_void>();
    // SAFETY: the context allocation remains stable until the tap is invalidated,
    // its run loop has stopped and its source has been removed on this worker.
    let port = unsafe {
        match target {
            Target::Global(location) => {
                CGEventTapCreate(location, placement, options, mask, tap_callback, user_info)
            }
            Target::Pid(pid) => {
                CGEventTapCreateForPid(pid, placement, options, mask, tap_callback, user_info)
            }
        }
    };
    if port.is_null() {
        return Outcome::CreateUnavailable;
    }
    context.port.set(port);
    let mut resources = ThreadResources {
        shared: Arc::clone(&shared),
        port,
        source: ptr::null_mut(),
        run_loop: CFRunLoop::get_current(),
    };
    // SAFETY: port is the live create-rule tap owned by this worker.
    resources.source = unsafe { CFMachPortCreateRunLoopSource(ptr::null(), port, 0) };
    if resources.source.is_null() {
        return Outcome::SourceUnavailable;
    }
    let run_loop = resources.run_loop.as_concrete_TypeRef().cast::<c_void>();
    // SAFETY: all objects are live, and the source is installed on this same loop.
    unsafe {
        CFRunLoopAddSource(run_loop, resources.source, kCFRunLoopCommonModes);
        if !CFRunLoopContainsSource(run_loop, resources.source, kCFRunLoopCommonModes) {
            return Outcome::SourceUnavailable;
        }
        CGEventTapEnable(port, true);
        if !CGEventTapIsEnabled(port) {
            return Outcome::EnableUnavailable;
        }
    }
    *shared
        .resources
        .lock()
        .expect("native tap resource lock poisoned") = Some(LiveTap {
        port: AtomicPtr::new(port),
        run_loop: resources.run_loop.clone(),
    });
    let ready_shared = Arc::clone(&shared);
    let ready = RcBlock::new(move || {
        if startup.send(Outcome::Complete).is_err() {
            ready_shared.open.store(false, Ordering::Release);
            // SAFETY: this block is executing inside this same retained run loop.
            unsafe { CFRunLoopStop(run_loop) };
        }
    });
    // SAFETY: the copied startup block executes from inside the actual loop.
    unsafe {
        CFRunLoopPerformBlock(run_loop, kCFRunLoopDefaultMode, &ready);
        CFRunLoopRun();
    }
    let outcome = if shared.callback_panicked.load(Ordering::Acquire) {
        Outcome::CallbackPanicked
    } else if shared.open.load(Ordering::Acquire) {
        Outcome::UnexpectedExit
    } else {
        Outcome::Complete
    };
    // The callback context outlives all invalidation and source removal.
    drop(resources);
    drop(context);
    outcome
}

extern "C" fn tap_callback(
    _proxy: *mut c_void,
    event_type: u32,
    event: *mut c_void,
    user_info: *mut c_void,
) -> *mut c_void {
    // SAFETY: CG owns this callback borrow; the worker pins context through Run
    // and invalidates/removes its source before dropping the allocation.
    let context = unsafe { &*user_info.cast::<CallbackContext>() };
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        if event_type == TAP_DISABLED_BY_TIMEOUT || event_type == TAP_DISABLED_BY_USER_INPUT {
            let resources = context
                .shared
                .resources
                .lock()
                .expect("native tap resource lock poisoned");
            if context.shared.open.load(Ordering::Acquire) {
                if let Some(live) = resources.as_ref() {
                    // SAFETY: the resource lock pins the port; seal uses this same
                    // lock, so a disabled notification cannot revive a sealed tap.
                    unsafe { CGEventTapEnable(live.port.load(Ordering::Relaxed), true) };
                }
            }
            return event;
        }
        if !context.shared.open.load(Ordering::Acquire) {
            return event;
        }
        let Some(event_pointer) = NonNull::new(event) else {
            return event;
        };
        let disposition = objc2::rc::autoreleasepool(|_| {
            (context.callback.borrow_mut())(BorrowedEvent {
                event_type,
                event: event_pointer,
                lifetime: PhantomData,
            })
        });
        match disposition {
            Disposition::Keep => event,
            Disposition::Drop => ptr::null_mut(),
        }
    }));
    match result {
        Ok(result) => result,
        Err(_) => {
            context
                .shared
                .callback_panicked
                .store(true, Ordering::Release);
            context.shared.open.store(false, Ordering::Release);
            // SAFETY: this callback is executing on the owning worker while the
            // port and current run loop remain live. No panic crosses the C ABI.
            unsafe {
                CGEventTapEnable(context.port.get(), false);
                CFRunLoopStop(CFRunLoopGetCurrent());
            }
            event
        }
    }
}

type TapCallback = extern "C" fn(*mut c_void, u32, *mut c_void, *mut c_void) -> *mut c_void;

#[link(name = "ApplicationServices", kind = "framework")]
unsafe extern "C" {
    fn CGEventTapCreate(
        location: u32,
        placement: u32,
        options: u32,
        mask: u64,
        callback: TapCallback,
        user_info: *mut c_void,
    ) -> *mut c_void;
    fn CGEventTapCreateForPid(
        pid: i32,
        placement: u32,
        options: u32,
        mask: u64,
        callback: TapCallback,
        user_info: *mut c_void,
    ) -> *mut c_void;
    fn CGEventTapEnable(tap: *mut c_void, enable: bool);
    fn CGEventTapIsEnabled(tap: *mut c_void) -> bool;
    fn CGEventGetIntegerValueField(event: *mut c_void, field: u32) -> i64;
    fn CGEventPostToPid(pid: i32, event: *mut c_void);
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFMachPortCreateRunLoopSource(
        allocator: *const c_void,
        port: *mut c_void,
        order: isize,
    ) -> *mut c_void;
    fn CFMachPortInvalidate(port: *mut c_void);
    fn CFRunLoopAddSource(run_loop: *mut c_void, source: *mut c_void, mode: *const c_void);
    fn CFRunLoopRemoveSource(run_loop: *mut c_void, source: *mut c_void, mode: *const c_void);
    fn CFRunLoopContainsSource(
        run_loop: *mut c_void,
        source: *mut c_void,
        mode: *const c_void,
    ) -> bool;
    fn CFRunLoopPerformBlock(run_loop: *mut c_void, mode: *const c_void, block: &Block<dyn Fn()>);
    fn CFRunLoopWakeUp(run_loop: *mut c_void);
    fn CFRunLoopGetCurrent() -> *mut c_void;
    fn CFRunLoopRun();
    fn CFRunLoopStop(run_loop: *mut c_void);
    fn CFRelease(object: *const c_void);
    static kCFRunLoopCommonModes: *const c_void;
    static kCFRunLoopDefaultMode: *const c_void;
}
