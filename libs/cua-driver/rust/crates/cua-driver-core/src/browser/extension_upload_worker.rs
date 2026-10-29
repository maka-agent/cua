// SPDX-License-Identifier: MIT

//! Host-owned upload I/O, separate from extension messages and broker dispatch.
//!
//! The registered native-host entry creates this worker only after placement was
//! captured there. Dropping a client handle neither removes resources nor joins
//! this thread. Host shutdown cleans unselected stages after placement validation;
//! selected backing without confirmed tab retirement remains cleanup-unconfirmed.

use super::broker_delivery::ByteCharge;
use super::extension_upload::{ExtensionUploadFile, UploadError, UploadOwner, UploadResources};
use super::extension_upload_placement::{UploadPlacement, UploadPlacementError};
use std::{
    fmt, io,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc::{self, SyncSender, TrySendError},
        Arc,
    },
    thread::{self, JoinHandle},
};
use tokio::sync::oneshot;
use uuid::Uuid;

/// Matches the broker's existing maximum of 64 normal pending operations.
const UPLOAD_QUEUE: usize = 64;
pub(super) const JOB_QUEUED: u8 = 0;
pub(super) const JOB_RUNNING: u8 = 1;
pub(super) const JOB_CANCELLED: u8 = 2;
pub(super) const JOB_COMPLETED: u8 = 3;

/// Local resource work. No extension JSON request can construct this queue item.
pub(super) enum UploadWork {
    Begin {
        owner: UploadOwner,
        files: Arc<Vec<ExtensionUploadFile>>,
    },
    Write {
        session_id: String,
        stage: Uuid,
        file_index: u32,
        offset: u64,
        bytes: Vec<u8>,
    },
    Retain {
        session_id: String,
        stage: Uuid,
    },
    Abandon {
        session_id: String,
        stage: Uuid,
    },
    RetireTab {
        owner: UploadOwner,
    },
}

pub(super) struct UploadJob {
    pub(super) id: u64,
    pub(super) work: UploadWork,
    pub(super) phase: Arc<AtomicU8>,
    pub(super) gates: Vec<Arc<AtomicBool>>,
    // The same logical payload remains charged even if a queued cancellation
    // lets the broker release its Pending before the worker dequeues this item.
    pub(super) _charge: Option<Arc<ByteCharge>>,
}
impl fmt::Debug for UploadJob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UploadJob")
            .field("id", &self.id)
            .field("phase", &self.phase.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

/// Only winning the queued CAS proves that this operation never entered I/O.
pub(super) fn cancel_queued(phase: &AtomicU8) -> bool {
    phase
        .compare_exchange(
            JOB_QUEUED,
            JOB_CANCELLED,
            Ordering::SeqCst,
            Ordering::SeqCst,
        )
        .is_ok()
}

#[derive(Debug)]
pub(super) enum UploadWorkResult {
    Begun(Uuid),
    Written,
    Retained(Vec<PathBuf>),
    // Produced only by the local completion-delivery adapter after actual
    // retain when variable paths cannot enter the bounded transport.
    RetainedUnexposed,
    Abandoned,
    TabRetired,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum UploadWorkerError {
    #[error("upload operation was not dispatched: {reason}")]
    NotDispatched { reason: &'static str },
    #[error("upload job state is unavailable; prior I/O cannot be excluded")]
    StateUnavailable,
    #[error(transparent)]
    Placement(#[from] UploadPlacementError),
    #[error("upload backing was retained but path placement validation failed: {source}")]
    RetainedPlacement {
        #[source]
        source: UploadPlacementError,
    },
    #[error(transparent)]
    Resource(#[from] UploadError),
}

#[derive(Debug)]
pub(super) struct UploadCompletion {
    pub(super) id: u64,
    pub(super) phase: u8,
    pub(super) result: Result<UploadWorkResult, UploadWorkerError>,
}

pub(super) enum UploadEvent {
    /// Owner lookup reads the single UploadResources ledger. The actor must
    /// compare this owner with its current actual claim before releasing gates.
    Authorize {
        id: u64,
        owner: UploadOwner,
        reply: oneshot::Sender<Result<Vec<Arc<AtomicBool>>, &'static str>>,
    },
    Completed(UploadCompletion),
}

#[derive(Debug)]
pub(super) enum UploadSubmitError {
    Full(UploadJob),
    Closed(UploadJob),
}
impl fmt::Display for UploadSubmitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full(_) => formatter.write_str("upload worker queue is full"),
            Self::Closed(_) => formatter.write_str("upload worker is closed"),
        }
    }
}
impl std::error::Error for UploadSubmitError {}

enum Command {
    Job(UploadJob),
    Shutdown,
}

/// A submission handle. Its lifetime is independent from resource ownership.
#[derive(Clone)]
pub(super) struct UploadWorker {
    sender: SyncSender<Command>,
    accepting: Arc<AtomicBool>,
}

/// Only the native-host process scope owns this value. Its explicit shutdown is
/// blocking and must run off the broker actor, after that actor is joined or while
/// its event input is still being drained. Drop performs no I/O or blocking join.
pub(super) struct UploadWorkerOwner {
    sender: SyncSender<Command>,
    accepting: Arc<AtomicBool>,
    thread: JoinHandle<Result<(), UploadWorkerError>>,
}

impl UploadWorker {
    /// Start only from actual native-host setup, never from a broker actor.
    /// Startup succeeds after placement is checked on the actual I/O thread.
    pub(super) fn start(
        placement: UploadPlacement,
        emit: impl Fn(UploadEvent) -> bool + Send + 'static,
    ) -> io::Result<(Self, UploadWorkerOwner)> {
        let (sender, input) = mpsc::sync_channel(UPLOAD_QUEUE);
        let (ready, startup) = mpsc::sync_channel(1);
        let accepting = Arc::new(AtomicBool::new(true));
        let thread = thread::Builder::new()
            .name("maka-upload-io".to_owned())
            .spawn(move || {
                if let Err(error) = placement.revalidate() {
                    let _ = ready.send(Err(error));
                    return Ok(());
                }
                if ready.send(Ok(())).is_err() {
                    return Ok(());
                }
                let mut resources = UploadResources::default();
                while let Ok(command) = input.recv() {
                    match command {
                        Command::Job(job) => {
                            let completion = execute_job(&placement, &mut resources, job, &emit);
                            // A gone actor cannot accept new jobs or authorize
                            // resource work. Keep host resource custody until
                            // this process's owner closes the worker explicitly.
                            let _ = emit(UploadEvent::Completed(completion));
                        }
                        Command::Shutdown => return cleanup(&placement, &mut resources),
                    }
                }
                // All host-owned handles are gone. This is final worker scope
                // destruction, never a client/provider/claim Drop callback.
                cleanup(&placement, &mut resources)
            })?;
        match startup.recv() {
            Ok(Ok(())) => Ok((
                Self {
                    sender: sender.clone(),
                    accepting: accepting.clone(),
                },
                UploadWorkerOwner {
                    sender,
                    accepting,
                    thread,
                },
            )),
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(io::Error::other(error))
            }
            Err(_) => {
                let _ = thread.join();
                Err(io::Error::other(
                    "upload I/O thread ended before placement validation",
                ))
            }
        }
    }

    /// Never waits on the worker or performs filesystem I/O.
    pub(super) fn try_submit(&self, job: UploadJob) -> Result<(), UploadSubmitError> {
        if !self.accepting.load(Ordering::SeqCst) {
            return Err(UploadSubmitError::Closed(job));
        }
        match self.sender.try_send(Command::Job(job)) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(Command::Job(job))) => Err(UploadSubmitError::Full(job)),
            Err(TrySendError::Disconnected(Command::Job(job))) => {
                Err(UploadSubmitError::Closed(job))
            }
            Err(
                TrySendError::Full(Command::Shutdown)
                | TrySendError::Disconnected(Command::Shutdown),
            ) => {
                unreachable!("try_submit only constructs a job command")
            }
        }
    }
}

impl UploadWorkerOwner {
    /// End the actual host resource scope. No other caller may request cleanup.
    /// The process calls this on a blocking task, not inside the broker actor.
    pub(super) fn shutdown(self) -> thread::Result<Result<(), UploadWorkerError>> {
        self.accepting.store(false, Ordering::SeqCst);
        let _ = self.sender.send(Command::Shutdown);
        self.thread.join()
    }
}

fn cleanup(
    placement: &UploadPlacement,
    resources: &mut UploadResources,
) -> Result<(), UploadWorkerError> {
    placement.revalidate_owned_cleanup()?;
    resources.cleanup_all()?;
    Ok(())
}

fn execute_job(
    placement: &UploadPlacement,
    resources: &mut UploadResources,
    mut job: UploadJob,
    emit: &impl Fn(UploadEvent) -> bool,
) -> UploadCompletion {
    let result = (|| {
        if job.phase.load(Ordering::SeqCst) == JOB_CANCELLED {
            return Err(not_dispatched("queued operation was cancelled"));
        }
        if job.phase.load(Ordering::SeqCst) != JOB_QUEUED {
            return Err(UploadWorkerError::StateUnavailable);
        }
        if !job.gates.iter().all(|gate| gate.load(Ordering::SeqCst)) {
            return refuse_before_start(&job.phase, "captured upload scope is closed");
        }
        let owner = match &job.work {
            UploadWork::Begin { owner, .. } | UploadWork::RetireTab { owner } => owner.clone(),
            UploadWork::Write {
                session_id, stage, ..
            }
            | UploadWork::Retain { session_id, stage }
            | UploadWork::Abandon { session_id, stage } => {
                let owner = resources.owner_for_session(*stage, session_id)?;
                let gates = authorize(job.id, owner.clone(), emit)?;
                job.gates.extend(gates);
                owner
            }
        };
        let owned_cleanup = matches!(
            &job.work,
            UploadWork::Abandon { .. } | UploadWork::RetireTab { .. }
        );
        run_admitted(
            &job.phase,
            &job.gates,
            || {
                // Existing-resource cleanup never depends on a departed browser
                // or closed native pipe; new writes/retains still require those.
                if owned_cleanup {
                    placement.revalidate_owned_cleanup()
                } else {
                    placement.revalidate()
                }
            },
            || {
                // No await separates the queued preflight, Running CAS and I/O on
                // this exact thread. No native frame-written state is involved.
                match job.work {
                    UploadWork::Begin { files, .. } => {
                        resources.begin(owner, &files).map(UploadWorkResult::Begun)
                    }
                    UploadWork::Write {
                        stage,
                        file_index,
                        offset,
                        bytes,
                        ..
                    } => resources
                        .write_chunk(stage, &owner, file_index, offset, &bytes)
                        .map(|()| UploadWorkResult::Written),
                    UploadWork::Retain { stage, .. } => {
                        return retain_for_selection(resources, stage, &owner, |path| {
                            placement.revalidate_staging_path(path)
                        });
                    }
                    UploadWork::Abandon { stage, .. } => resources
                        .abandon(stage, &owner)
                        .map(|()| UploadWorkResult::Abandoned),
                    UploadWork::RetireTab { .. } => resources
                        .retire_tab(&owner)
                        .map(|()| UploadWorkResult::TabRetired),
                }
                .map_err(UploadWorkerError::Resource)
            },
        )
    })();
    // Memory-only lookup/authorization failures are also terminal no-I/O
    // operations. Preserve CANCELLED as the source of that fact; COMPLETED
    // is reserved for an operation which passed the Running transition.
    if job.phase.load(Ordering::SeqCst) == JOB_QUEUED {
        let _ = cancel_queued(&job.phase);
    }
    UploadCompletion {
        id: job.id,
        phase: job.phase.load(Ordering::SeqCst),
        result,
    }
}

// The existing resource ledger changes retained state before path exposure.
// Preserve that actual fact even when a subsequent placement check fails.
pub(super) fn retain_for_selection(
    resources: &mut UploadResources,
    stage: Uuid,
    owner: &UploadOwner,
    mut validate_path: impl FnMut(&Path) -> Result<(), UploadPlacementError>,
) -> Result<UploadWorkResult, UploadWorkerError> {
    let paths = resources.retain(stage, owner)?;
    for path in &paths {
        validate_path(path).map_err(|source| UploadWorkerError::RetainedPlacement { source })?;
    }
    Ok(UploadWorkResult::Retained(paths))
}

fn authorize(
    id: u64,
    owner: UploadOwner,
    emit: &impl Fn(UploadEvent) -> bool,
) -> Result<Vec<Arc<AtomicBool>>, UploadWorkerError> {
    let (reply, authorization) = oneshot::channel();
    if !emit(UploadEvent::Authorize { id, owner, reply }) {
        return Err(not_dispatched("broker closed before upload authorization"));
    }
    authorization
        .blocking_recv()
        .map_err(|_| not_dispatched("broker ended before upload authorization"))?
        .map_err(|reason| not_dispatched(reason))
}

fn not_dispatched(reason: &'static str) -> UploadWorkerError {
    UploadWorkerError::NotDispatched { reason }
}

fn refuse_before_start<T>(phase: &AtomicU8, reason: &'static str) -> Result<T, UploadWorkerError> {
    if cancel_queued(phase) || phase.load(Ordering::SeqCst) == JOB_CANCELLED {
        Err(not_dispatched(reason))
    } else {
        Err(UploadWorkerError::StateUnavailable)
    }
}

fn run_admitted<T>(
    phase: &AtomicU8,
    gates: &[Arc<AtomicBool>],
    preflight: impl FnOnce() -> Result<(), UploadPlacementError>,
    operation: impl FnOnce() -> Result<T, UploadWorkerError>,
) -> Result<T, UploadWorkerError> {
    match phase.load(Ordering::SeqCst) {
        JOB_QUEUED => {}
        JOB_CANCELLED => return Err(not_dispatched("queued operation was cancelled")),
        _ => return Err(UploadWorkerError::StateUnavailable),
    }
    if !gates.iter().all(|gate| gate.load(Ordering::SeqCst)) {
        return refuse_before_start(phase, "captured upload scope is closed");
    }
    if preflight().is_err() {
        return refuse_before_start(
            phase,
            "upload placement is unavailable before filesystem dispatch",
        );
    }
    // Scope cancellation may have occurred while observing the OS. Its gate
    // still precedes the actual queued-to-Running effect transition.
    if !gates.iter().all(|gate| gate.load(Ordering::SeqCst)) {
        return refuse_before_start(phase, "captured upload scope is closed");
    }
    match phase.compare_exchange(JOB_QUEUED, JOB_RUNNING, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(_) => {}
        Err(JOB_CANCELLED) => return Err(not_dispatched("queued operation was cancelled")),
        Err(_) => return Err(UploadWorkerError::StateUnavailable),
    }
    let result = operation();
    phase.store(JOB_COMPLETED, Ordering::SeqCst);
    result
}
