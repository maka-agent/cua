// SPDX-License-Identifier: MIT

//! Invocation context for trusted native Linux accessibility observations.
//!
//! The Rust caller supplies the target and its real deadline. This context
//! carries no authorization and is never selected by a JSON argument.

use anyhow::{Result, bail};
use std::{
    future::Future,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Notify;

/// Original Linux admission counts an attempted node before fetching properties.
pub(crate) const MAX_NODE_ATTEMPTS: usize = 5_000;
/// Original Linux admission includes depth 63 and skips deeper nodes before properties.
pub(crate) const MAX_DEPTH: usize = 63;

/// A trusted caller's exact native observation target and optional deadline.
#[derive(Clone, Copy, Debug)]
pub struct NativeObservationRequest {
    /// Expected process owning the selected window.
    pub pid: u32,
    /// Exact X11 client window to observe.
    pub window_id: u64,
    /// The caller's deadline; absence does not add a traversal timeout.
    pub deadline: Option<Instant>,
}

#[derive(Debug, Default)]
struct State {
    cancelled: AtomicBool,
    stopped: Notify,
    incomplete_reason: OnceLock<&'static str>,
}

/// Shared across the caller task and work owned by the native runtime.
#[derive(Clone, Debug)]
pub(crate) struct Observation {
    request: NativeObservationRequest,
    state: Arc<State>,
}

tokio::task_local! {
    static OBSERVATION: Observation;
}

struct CancelOnDrop(Observation);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// Bind one invocation and cancel its shared work when the invocation ends.
///
/// Dropping this future also cancels work that retained a context on the native
/// runtime. Nested invocations restore the caller's previous context.
pub async fn with_native_observation<F>(request: NativeObservationRequest, future: F) -> F::Output
where
    F: Future,
{
    let observation = Observation {
        request,
        state: Arc::new(State::default()),
    };
    let _cancel = CancelOnDrop(observation.clone());
    OBSERVATION.scope(observation, future).await
}

pub(crate) fn current() -> Option<Observation> {
    OBSERVATION.try_with(Clone::clone).ok()
}

/// Return the current context only when its exact target matches.
///
/// A mismatched native request is an error, never permission to use the generic
/// observation path instead.
pub(crate) fn for_window(pid: u32, window_id: u64) -> Result<Option<Observation>> {
    let Some(observation) = current() else {
        return Ok(None);
    };
    let request = observation.request;
    if request.pid != pid || request.window_id != window_id {
        bail!(
            "native observation target mismatch: scoped pid={} window_id={}, requested pid={} window_id={}",
            request.pid,
            request.window_id,
            pid,
            window_id
        );
    }
    Ok(Some(observation))
}

impl Observation {
    /// Rebind a retained context while its work runs on the native runtime.
    /// This does not take ownership of the caller invocation's cancellation.
    pub(crate) async fn scope<F>(&self, future: F) -> F::Output
    where
        F: Future,
    {
        OBSERVATION.scope(self.clone(), future).await
    }

    fn cancel(&self) {
        if !self.state.cancelled.swap(true, Ordering::AcqRel) {
            self.state.stopped.notify_waiters();
        }
    }

    pub(crate) fn stop_reason(&self) -> Option<&'static str> {
        if self.state.cancelled.load(Ordering::Acquire) {
            Some("cancelled")
        } else if self
            .request
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            Some("caller_deadline")
        } else {
            None
        }
    }

    /// Wait for cancellation or the caller's deadline, without adding a timeout.
    pub(crate) async fn stopped(&self) -> &'static str {
        loop {
            let notified = self.state.stopped.notified();
            tokio::pin!(notified);
            // Register before reading the flag so notify_waiters cannot race
            // between that read and the first poll of this notification.
            let _ = notified.as_mut().enable();
            if let Some(reason) = self.stop_reason() {
                return reason;
            }
            match self.request.deadline {
                Some(deadline) => {
                    tokio::select! {
                        _ = notified.as_mut() => {},
                        _ = tokio::time::sleep_until(deadline.into()) => {},
                    }
                }
                None => notified.await,
            }
        }
    }

    /// Remaining caller time, including zero after its deadline has elapsed.
    pub(crate) fn remaining(&self) -> Option<Duration> {
        self.request
            .deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }

    /// Retain the first incomplete-result cause across all work in the invocation.
    pub(crate) fn mark_incomplete(&self, reason: &'static str) {
        let _ = self.state.incomplete_reason.set(reason);
    }

    /// No marked cause is not by itself proof that an observation is complete.
    pub(crate) fn incomplete_reason(&self) -> Option<&'static str> {
        self.state.incomplete_reason.get().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{sync::oneshot, task::JoinHandle};

    const PID: u32 = 73;

    fn request(window_id: u64, deadline: Option<Instant>) -> NativeObservationRequest {
        NativeObservationRequest {
            pid: PID,
            window_id,
            deadline,
        }
    }

    fn blocking_waiter(
        observation: Observation,
        started: oneshot::Sender<()>,
        shutdown: oneshot::Receiver<()>,
    ) -> JoinHandle<&'static str> {
        tokio::task::spawn_blocking(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .expect("create the isolated native-work runtime");
            runtime.block_on(observation.scope(async {
                assert!(current().is_some(), "retained context is rebound");
                started
                    .send(())
                    .expect("test still awaits native readiness");
                tokio::select! {
                    reason = observation.stopped() => reason,
                    // Closing this test-owned channel releases blocking work
                    // during an assertion failure, keeping the keeper hermetic.
                    _ = shutdown => "test_shutdown",
                }
            }))
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_invocation_wakes_blocking_owned_context() {
        let (started_tx, started_rx) = oneshot::channel();
        let (worker_tx, worker_rx) = oneshot::channel();
        let (_shutdown, shutdown_rx) = oneshot::channel();
        let mut invocation = Box::pin(with_native_observation(request(11, None), async move {
            let observation = current().expect("invocation context is bound");
            assert_eq!(observation.remaining(), None);
            let worker = blocking_waiter(observation, started_tx, shutdown_rx);
            worker_tx
                .send(worker)
                .expect("test retains worker ownership");
            std::future::pending::<()>().await;
        }));
        tokio::select! {
            _ = invocation.as_mut() => panic!("the invocation must remain pending"),
            ready = started_rx => ready.expect("native work reached its scoped wait"),
        }
        drop(invocation);
        let worker = worker_rx.await.expect("the native worker was retained");
        let reason = tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .expect("dropping the invocation wakes native work")
            .expect("native worker exits without panicking");
        assert_eq!(reason, "cancelled");
        assert!(current().is_none());
    }

    #[tokio::test]
    async fn caller_deadline_is_preserved_on_the_native_runtime() {
        let budget = Duration::from_millis(20);
        let deadline = Instant::now() + budget;
        let (started_tx, started_rx) = oneshot::channel();
        let (_shutdown, shutdown_rx) = oneshot::channel();
        with_native_observation(request(12, Some(deadline)), async {
            let observation = current().expect("caller deadline is bound");
            assert!(observation.remaining().expect("caller supplied a deadline") <= budget);
            let worker = blocking_waiter(observation.clone(), started_tx, shutdown_rx);
            started_rx
                .await
                .expect("native work reached its scoped wait");
            let reason = tokio::time::timeout(Duration::from_secs(5), worker)
                .await
                .expect("the caller deadline is not replaced or extended")
                .expect("native worker exits without panicking");
            assert_eq!(reason, "caller_deadline");
            assert!(Instant::now() >= deadline);
            assert_eq!(observation.remaining(), Some(Duration::ZERO));
        })
        .await;
    }

    #[tokio::test]
    async fn nested_scope_restores_target_and_keeps_incomplete_causes_separate() {
        assert!(
            for_window(PID, 13)
                .expect("no scoped request is generic")
                .is_none()
        );
        with_native_observation(request(13, None), async {
            let outer = for_window(PID, 13)
                .expect("outer target matches")
                .expect("outer context exists");
            let inner = with_native_observation(request(14, None), async {
                let inner = for_window(PID, 14)
                    .expect("inner target matches")
                    .expect("inner context exists");
                assert_eq!(
                    for_window(PID, 13)
                        .expect_err("a scoped mismatch must not become generic")
                        .to_string(),
                    "native observation target mismatch: scoped pid=73 window_id=14, requested pid=73 window_id=13"
                );
                inner.mark_incomplete("timeout");
                inner.clone().mark_incomplete("node_error");
                assert_eq!(inner.incomplete_reason(), Some("timeout"));
                inner
            })
            .await;
            assert_eq!(inner.stop_reason(), Some("cancelled"));
            assert_eq!(outer.stop_reason(), None);
            assert_eq!(outer.incomplete_reason(), None);
            assert!(for_window(PID, 13).expect("outer context was restored").is_some());
        })
        .await;
        assert!(current().is_none());
    }
}
