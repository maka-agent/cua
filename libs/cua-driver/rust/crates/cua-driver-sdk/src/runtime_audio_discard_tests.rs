// SPDX-License-Identifier: MIT

//! Resource cleanup races without capturing a desktop or an audio device.

use super::*;
use cua_driver_core::audio::{AudioBackend, AudioBackendFactory, AudioCompletion};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

struct Gate {
    entered: tokio::sync::mpsc::UnboundedSender<()>,
    release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}

impl Gate {
    fn once(&self) {
        let release = self.release.lock().unwrap().take();
        if let Some(release) = release {
            self.entered.send(()).unwrap();
            release.recv().unwrap();
        }
    }
}

fn gate() -> (
    Arc<Gate>,
    tokio::sync::mpsc::UnboundedReceiver<()>,
    std::sync::mpsc::Sender<()>,
) {
    let (entered, reached) = tokio::sync::mpsc::unbounded_channel();
    let (release, wait) = std::sync::mpsc::channel();
    (
        Arc::new(Gate {
            entered,
            release: Mutex::new(Some(wait)),
        }),
        reached,
        release,
    )
}

#[derive(Default)]
struct Factory {
    active: Arc<AtomicUsize>,
    paths: Arc<Mutex<Vec<PathBuf>>>,
    starting: Option<Arc<Gate>>,
    stopping: Option<Arc<Gate>>,
}

struct Backend {
    path: PathBuf,
    active: Arc<AtomicUsize>,
    stopping: Option<Arc<Gate>>,
}

impl AudioBackendFactory for Factory {
    fn start(
        &self,
        path: &Path,
        _: Duration,
    ) -> cua_driver_core::audio::AudioResult<Box<dyn AudioBackend>> {
        self.paths.lock().unwrap().push(path.to_owned());
        if let Some(gate) = &self.starting {
            gate.once();
        }
        self.active.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Backend {
            path: path.to_owned(),
            active: self.active.clone(),
            stopping: self.stopping.clone(),
        }))
    }
}

impl AudioBackend for Backend {
    fn stop(self: Box<Self>) -> cua_driver_core::audio::AudioResult<()> {
        if let Some(gate) = &self.stopping {
            gate.once();
        }
        cua_driver_core::audio::write_pcm16_stereo_wav(&self.path, &[1, 0, 2, 0])
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

fn runtime(factory: Arc<dyn AudioBackendFactory>) -> Arc<DriverRuntime> {
    let ceiling = SessionModeCeiling::for_trusted_sessions(
        [PermissionMode::Standard],
        false,
        Duration::from_secs(60),
        Duration::from_secs(60),
    )
    .unwrap();
    let authorization_registry = Arc::new(SessionAuthorizationRegistry::with_ceiling(ceiling));
    let compatibility_context = authorization_registry
        .compatibility_context(PermissionMode::Standard, None)
        .unwrap();
    let mut registry = ToolRegistry::new();
    registry.register_session_tools();
    let audio = cua_driver_core::audio::register_tools(&mut registry, factory);
    let registry = Arc::new(registry);
    registry.init_self_weak();
    Arc::new(DriverRuntime {
        registry,
        audio: Some(audio),
        authorization_registry,
        compatibility_context,
        shutdown: AtomicBool::new(false),
        last_activity: AtomicU64::new(now_unix_secs()),
        lifecycle: tokio::sync::RwLock::new(()),
        lifecycle_maintenance: Mutex::new(None),
        activity_observer: None,
    })
}

async fn session(runtime: &Arc<DriverRuntime>, name: &str) -> Arc<RuntimeSession> {
    let session = runtime
        .create_trusted_session(DelegatedSessionRequest {
            public_session: name.into(),
            transport_session: format!("{name}-transport"),
            mode: PermissionMode::Standard,
            ttl: Duration::from_secs(60),
            idle_ttl: Duration::from_secs(60),
            capability_manifest: None,
        })
        .unwrap();
    let started = session
        .invoke("start_session", json!({"capture_scope":"window"}))
        .await
        .unwrap();
    assert_ne!(started.is_error, Some(true));
    session
}

async fn invoke(session: &RuntimeSession, name: &str) -> CoreToolResult {
    let result = session.invoke(name, json!({})).await.unwrap();
    assert_ne!(result.is_error, Some(true), "{result:?}");
    result
}

async fn writer_pending(runtime: &DriverRuntime) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while runtime.lifecycle.try_read().is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("discard must queue its write drain");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_discard_drains_an_admitted_start_and_preserves_session_and_other_audio() {
    let _runtime_test = TEST_RUNTIME_LOCK.lock().await;
    let (starting, mut entered, release) = gate();
    let factory = Arc::new(Factory {
        starting: Some(starting),
        ..Factory::default()
    });
    let runtime = runtime(factory.clone());
    let target = session(&runtime, "discard-admitted-start").await;
    let other = session(&runtime, "discard-foreign-session").await;
    let start = tokio::spawn({
        let target = target.clone();
        async move { invoke(&target, "start_audio_recording").await }
    });
    entered.recv().await.unwrap();
    invoke(&other, "start_audio_recording").await;
    let discard = tokio::spawn({
        let target = target.clone();
        async move { target.discard_audio().await }
    });
    writer_pending(&runtime).await;
    assert!(!discard.is_finished());
    release.send(()).unwrap();
    start.await.unwrap();
    discard.await.unwrap().unwrap();
    assert_eq!(
        factory.active.load(Ordering::SeqCst),
        1,
        "only the owning recording is discarded"
    );
    assert!(!factory.paths.lock().unwrap()[0].parent().unwrap().exists());
    let state = invoke(&target, "get_session_state")
        .await
        .structured_content
        .unwrap();
    assert_eq!(state["capture_scope"], "window", "{state:?}");
    let lifecycle = invoke(&target, "get_session")
        .await
        .structured_content
        .unwrap();
    assert_eq!(lifecycle["state"], "active");
    let other_result = invoke(&other, "stop_audio_recording").await;
    let other_path = other_result.structured_content.unwrap()["filepath"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(Path::new(&other_path).exists());
    // Fresh admission is the host's responsibility. Resource cleanup adds no
    // permanent audio grant/fence and does not retire this session binding.
    invoke(&target, "start_audio_recording").await;
    assert_eq!(factory.active.load(Ordering::SeqCst), 1);
    runtime.shutdown().await;
    assert_eq!(factory.active.load(Ordering::SeqCst), 0);
    assert!(!Path::new(&other_path).exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_discard_drains_an_admitted_stop_and_removes_its_returned_file() {
    let _runtime_test = TEST_RUNTIME_LOCK.lock().await;
    let (stopping, mut entered, release) = gate();
    let factory = Arc::new(Factory {
        stopping: Some(stopping),
        ..Factory::default()
    });
    let runtime = runtime(factory.clone());
    let target = session(&runtime, "discard-admitted-stop").await;
    invoke(&target, "start_audio_recording").await;
    let stop = tokio::spawn({
        let target = target.clone();
        async move { invoke(&target, "stop_audio_recording").await }
    });
    entered.recv().await.unwrap();
    let discard = tokio::spawn({
        let target = target.clone();
        async move { target.discard_audio().await }
    });
    writer_pending(&runtime).await;
    assert!(!discard.is_finished());
    release.send(()).unwrap();
    // A read-admitted stop settles before discard; the embedding host must
    // revalidate approval before exposing that already-produced result.
    let stopped = stop.await.unwrap();
    let path = stopped.structured_content.unwrap()["filepath"]
        .as_str()
        .unwrap()
        .to_owned();
    discard.await.unwrap().unwrap();
    assert_eq!(factory.active.load(Ordering::SeqCst), 0);
    assert!(!Path::new(&path).exists());
    invoke(&target, "get_session").await;
    runtime.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn canceling_host_discard_await_does_not_release_native_cleanup_or_its_drain() {
    let _runtime_test = TEST_RUNTIME_LOCK.lock().await;
    let (stopping, mut entered, release) = gate();
    let factory = Arc::new(Factory {
        stopping: Some(stopping),
        ..Factory::default()
    });
    let runtime = runtime(factory.clone());
    let target = session(&runtime, "discard-canceled-await").await;
    invoke(&target, "start_audio_recording").await;
    let discard = tokio::spawn({
        let target = target.clone();
        async move { target.discard_audio().await }
    });
    entered.recv().await.unwrap();
    discard.abort();
    assert!(discard.await.unwrap_err().is_cancelled());
    assert!(
        runtime.lifecycle.try_read().is_err(),
        "owned cleanup retains the write drain"
    );
    let shutdown = tokio::spawn({
        let runtime = runtime.clone();
        async move { runtime.shutdown().await }
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while runtime.is_running() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        !shutdown.is_finished(),
        "shutdown must wait for the owned native cleanup"
    );
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), shutdown)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(factory.active.load(Ordering::SeqCst), 0);
    assert!(!factory.paths.lock().unwrap()[0].parent().unwrap().exists());
}

#[derive(Default)]
struct CompletingFactory {
    workers: Mutex<Vec<std::sync::mpsc::Sender<bool>>>,
    active: Arc<AtomicUsize>,
    finished: Arc<AtomicUsize>,
}

struct CompletingBackend {
    stop: std::sync::mpsc::Sender<bool>,
    worker: Option<std::thread::JoinHandle<cua_driver_core::audio::AudioResult<()>>>,
    completion: AudioCompletion,
}

impl AudioBackendFactory for CompletingFactory {
    fn start(
        &self,
        path: &Path,
        _: Duration,
    ) -> cua_driver_core::audio::AudioResult<Box<dyn AudioBackend>> {
        let path = path.to_owned();
        let active = self.active.clone();
        let finished = self.finished.clone();
        let (stop, stopping) = std::sync::mpsc::channel();
        let (completion, completed) = AudioCompletion::channel();
        active.fetch_add(1, Ordering::SeqCst);
        let worker = std::thread::spawn(move || {
            let result = if stopping.recv().unwrap() {
                cua_driver_core::audio::write_pcm16_stereo_wav(&path, &[1, 0, 2, 0])
            } else {
                Err(std::io::Error::other("fixture native finalization failed").into())
            };
            active.fetch_sub(1, Ordering::SeqCst);
            completed.finish(&result);
            finished.fetch_add(1, Ordering::SeqCst);
            result
        });
        self.workers.lock().unwrap().push(stop.clone());
        Ok(Box::new(CompletingBackend {
            stop,
            worker: Some(worker),
            completion,
        }))
    }
}

impl CompletingBackend {
    fn finish(&mut self) -> cua_driver_core::audio::AudioResult<()> {
        let _ = self.stop.send(true);
        self.worker.take().map_or(Ok(()), |worker| {
            worker
                .join()
                .map_err(|_| std::io::Error::other("fixture native worker panicked"))?
        })
    }
}

impl AudioBackend for CompletingBackend {
    fn stop(mut self: Box<Self>) -> cua_driver_core::audio::AudioResult<()> {
        self.finish()
    }

    fn completion(&self) -> cua_driver_core::audio::AudioResult<AudioCompletion> {
        Ok(self.completion.clone())
    }
}

impl Drop for CompletingBackend {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

async fn observing_audio(
    runtime: &DriverRuntime,
    session: Arc<RuntimeSession>,
) -> tokio::task::JoinHandle<Result<(), String>> {
    let completion = session.audio_completion().await.unwrap();
    let wait =
        tokio::spawn(async move { completion.wait().await.map_err(|error| error.to_string()) });
    // Acquiring the writer proves the snapshot released admission. A waiter
    // that retained its read guard until capture end would deadlock here.
    let drained = tokio::time::timeout(Duration::from_secs(5), runtime.lifecycle.write())
        .await
        .expect("audio observation must release its lifecycle read guard");
    drop(drained);
    assert!(!wait.is_finished(), "native capture has not completed");
    wait
}

#[tokio::test(flavor = "current_thread")]
async fn host_wait_keeps_old_epoch_owned_until_native_completion_without_exposing_it_to_new_epoch()
{
    let _runtime_test = TEST_RUNTIME_LOCK.lock().await;
    let factory = Arc::new(CompletingFactory::default());
    let runtime = runtime(factory.clone());
    let old = session(&runtime, "audio-old-epoch").await;
    let new = session(&runtime, "audio-new-epoch").await;
    invoke(&old, "start_audio_recording").await;
    let waiting = observing_audio(&runtime, old.clone()).await;
    assert_eq!(factory.active.load(Ordering::SeqCst), 1);
    let no_recording = new.invoke("stop_audio_recording", json!({})).await.unwrap();
    assert_eq!(no_recording.is_error, Some(true));
    let refusal = no_recording.structured_content.unwrap();
    assert_eq!(refusal["refusal"]["code"], "audio_recording_unavailable");
    assert_eq!(
        refusal["refusal"]["message"],
        "computer audio recording is not active"
    );
    // The fixture native owner finalizes on a channel, never on a test timer.
    factory.workers.lock().unwrap()[0].send(true).unwrap();
    waiting.await.unwrap().unwrap();
    assert_eq!(factory.active.load(Ordering::SeqCst), 0);
    let duplicate = old
        .invoke("start_audio_recording", json!({}))
        .await
        .unwrap();
    assert_eq!(
        duplicate.is_error,
        Some(true),
        "completion retains the active slot"
    );
    let stopped = invoke(&old, "stop_audio_recording").await;
    let path = stopped.structured_content.unwrap()["filepath"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        Path::new(&path).exists(),
        "observation does not retrieve/delete the WAV"
    );
    old.discard_audio().await.unwrap();
    assert!(!Path::new(&path).exists());
    invoke(&new, "start_audio_recording").await;
    invoke(&new, "stop_audio_recording").await;
    runtime.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn host_discard_settles_a_native_completion_wait_without_deadlock() {
    let _runtime_test = TEST_RUNTIME_LOCK.lock().await;
    let factory = Arc::new(CompletingFactory::default());
    let runtime = runtime(factory.clone());
    let target = session(&runtime, "audio-wait-discard").await;
    invoke(&target, "start_audio_recording").await;
    let canceled = observing_audio(&runtime, target.clone()).await;
    canceled.abort();
    assert!(canceled.await.unwrap_err().is_cancelled());
    assert_eq!(factory.active.load(Ordering::SeqCst), 1);
    let waiting = observing_audio(&runtime, target.clone()).await;
    target.discard_audio().await.unwrap();
    waiting.await.unwrap().unwrap();
    assert_eq!(factory.active.load(Ordering::SeqCst), 0);
    invoke(&target, "get_session").await;
    runtime.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn host_wait_reports_native_failure_and_refuses_an_absent_or_unsupported_capture() {
    let _runtime_test = TEST_RUNTIME_LOCK.lock().await;
    let factory = Arc::new(CompletingFactory::default());
    let runtime = runtime(factory.clone());
    let target = session(&runtime, "audio-wait-failure").await;
    assert_eq!(
        target.audio_completion().await.err().unwrap(),
        "computer audio recording is not active"
    );
    invoke(&target, "start_audio_recording").await;
    let waiting = observing_audio(&runtime, target.clone()).await;
    factory.workers.lock().unwrap()[0].send(false).unwrap();
    assert_eq!(
        waiting.await.unwrap().unwrap_err(),
        "fixture native finalization failed"
    );
    // Native failure remains a failure when cleanup joins the same worker.
    assert_eq!(
        target.discard_audio().await.unwrap_err(),
        "fixture native finalization failed"
    );
    runtime.shutdown().await;

    let unsupported = self::runtime(Arc::new(Factory::default()));
    let target = session(&unsupported, "audio-wait-unsupported").await;
    invoke(&target, "start_audio_recording").await;
    assert_eq!(
        target.audio_completion().await.err().unwrap(),
        "native audio completion observation is unavailable for this backend"
    );
    unsupported.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn host_snapshot_keeps_the_original_capture_before_first_wait_poll_and_replacement() {
    let _runtime_test = TEST_RUNTIME_LOCK.lock().await;
    let factory = Arc::new(CompletingFactory::default());
    let runtime = runtime(factory.clone());
    let target = session(&runtime, "audio-exact-snapshot").await;
    invoke(&target, "start_audio_recording").await;
    let first = crate::AudioCompletion {
        native: target.audio_completion().await.unwrap(),
    };
    invoke(&target, "stop_audio_recording").await;
    invoke(&target, "start_audio_recording").await;
    let second = crate::AudioCompletion {
        native: target.audio_completion().await.unwrap(),
    };
    // No wait on first has been constructed or polled before capture two.
    tokio::time::timeout(Duration::from_secs(5), first.wait())
        .await
        .expect("the first capture completed before replacement")
        .unwrap();
    assert_eq!(factory.active.load(Ordering::SeqCst), 1);
    // Successful snapshot registration no longer owns runtime admission.
    let writer = tokio::time::timeout(Duration::from_secs(5), runtime.lifecycle.write())
        .await
        .expect("snapshot must release runtime admission before returning");
    drop(writer);
    drop(second.clone());
    {
        use std::future::Future;
        let mut detached = Box::pin(second.wait());
        std::future::poll_fn(|cx| {
            assert!(detached.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(detached);
    }
    assert_eq!(factory.active.load(Ordering::SeqCst), 1);
    factory.workers.lock().unwrap()[1].send(false).unwrap();
    for observation in [second.clone(), second] {
        assert!(matches!(
            observation.wait().await,
            Err(crate::DriverError::Protocol { reason })
                if reason == "fixture native finalization failed"
        ));
    }
    assert_eq!(factory.active.load(Ordering::SeqCst), 0);
    assert_eq!(
        target.discard_audio().await.unwrap_err(),
        "fixture native finalization failed"
    );
    runtime.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn host_snapshot_retains_native_completion_that_precedes_registration() {
    let _runtime_test = TEST_RUNTIME_LOCK.lock().await;
    let factory = Arc::new(CompletingFactory::default());
    let runtime = runtime(factory.clone());
    let target = session(&runtime, "audio-immediate-snapshot").await;
    invoke(&target, "start_audio_recording").await;
    factory.workers.lock().unwrap()[0].send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while factory.finished.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the fixture native worker finalizes on its channel");
    let completion = crate::AudioCompletion {
        native: target.audio_completion().await.unwrap(),
    };
    // Shutdown joins the already-completed native worker and removes outputs;
    // the detached observation remains the same capture's finalization result.
    runtime.shutdown().await;
    tokio::time::timeout(Duration::from_secs(5), completion.wait())
        .await
        .expect("a pre-registration completion must not be lost")
        .unwrap();
}
