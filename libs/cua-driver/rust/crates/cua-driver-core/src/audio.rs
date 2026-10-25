//! Opt-in, session-owned computer loopback audio. Backends never select a microphone.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{bail, Context};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::protocol::ToolResult;
use crate::tool::{Tool, ToolDef, ToolRegistry};

pub const SAMPLE_RATE: u32 = 24_000;
pub const CHANNELS: u16 = 2;
pub const DEFAULT_DURATION_MS: u64 = 60_000;
pub const MAX_DURATION_MS: u64 = 300_000;

/// The backend result type, available to hosts implementing this interface.
pub type AudioResult<T> = anyhow::Result<T>;

/// Observation of one native capture's finalization. It carries no authority
/// to stop the capture, read its WAV, or select another session.
#[derive(Clone)]
pub struct AudioCompletion {
    receiver: tokio::sync::watch::Receiver<Option<Result<(), String>>>,
}

pub struct AudioCompletionSender {
    sender: tokio::sync::watch::Sender<Option<Result<(), String>>>,
}

impl AudioCompletion {
    pub fn channel() -> (Self, AudioCompletionSender) {
        let (sender, receiver) = tokio::sync::watch::channel(None);
        (Self { receiver }, AudioCompletionSender { sender })
    }

    /// A duration deadline alone is not completion. The native owner reports
    /// only after capture, callbacks and output writes have actually settled.
    pub async fn wait(&self) -> AudioResult<()> {
        let mut receiver = self.receiver.clone();
        loop {
            if let Some(result) = receiver.borrow_and_update().clone() {
                return result.map_err(anyhow::Error::msg);
            }
            receiver
                .changed()
                .await
                .context("computer audio worker ended without reporting finalization")?;
        }
    }
}

impl AudioCompletionSender {
    pub fn finish(self, result: &AudioResult<()>) {
        let _ = self.sender.send_replace(Some(
            result
                .as_ref()
                .map(|_| ())
                .map_err(|error| format!("{error:#}")),
        ));
    }
}

/// An owned capture. `stop` settles native callbacks and writes before returning,
/// including on failure. Dropping an unfinished backend must stop capture too.
pub trait AudioBackend: Send {
    fn stop(self: Box<Self>) -> anyhow::Result<()>;

    fn completion(&self) -> AudioResult<AudioCompletion> {
        bail!("native audio completion observation is unavailable for this backend")
    }
}

pub trait AudioBackendFactory: Send + Sync {
    fn start(
        &self,
        output_path: &Path,
        max_duration: Duration,
    ) -> anyhow::Result<Box<dyn AudioBackend>>;
}

struct ActiveRecording {
    backend: Box<dyn AudioBackend>,
    directory: tempfile::TempDir,
}

#[derive(Default)]
struct SessionAudio {
    recording: RecordingState,
    // Returned local paths remain valid for the owning lifecycle episode.
    completed: Vec<tempfile::TempDir>,
}

#[derive(Default)]
enum RecordingState {
    #[default]
    Idle,
    Active(ActiveRecording),
    Closed,
}

/// Constructed once per opted-in runtime, never stored in a process-global slot.
pub struct AudioRecordings {
    factory: Arc<dyn AudioBackendFactory>,
    sessions: Mutex<HashMap<String, Arc<Mutex<SessionAudio>>>>,
}

#[derive(Debug)]
pub struct RecordedAudio {
    pub filepath: PathBuf,
    pub bytes: Vec<u8>,
}

impl AudioRecordings {
    fn new(factory: Arc<dyn AudioBackendFactory>) -> Self {
        Self {
            factory,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn reserve_session(&self, session: &str) -> Arc<Mutex<SessionAudio>> {
        self.sessions
            .lock()
            .unwrap()
            .entry(session.to_owned())
            .or_default()
            .clone()
    }

    #[cfg(test)]
    fn start(&self, session: &str, max_duration: Duration) -> anyhow::Result<()> {
        self.start_reserved(self.reserve_session(session), max_duration)
    }

    fn start_reserved(
        &self,
        owned: Arc<Mutex<SessionAudio>>,
        max_duration: Duration,
    ) -> anyhow::Result<()> {
        // This lock owns only this session's capture. Dispatch admission keeps
        // lifecycle cleanup after an accepted start; cleanup also takes this lock.
        let mut owned = owned.lock().unwrap();
        match owned.recording {
            RecordingState::Idle => {}
            RecordingState::Active(_) => bail!("computer audio recording is already active"),
            RecordingState::Closed => bail!("computer audio session is closed"),
        }
        let directory = tempfile::Builder::new().prefix("cua-audio-").tempdir()?;
        let backend = self
            .factory
            .start(&directory.path().join("recording.wav"), max_duration)?;
        owned.recording = RecordingState::Active(ActiveRecording { backend, directory });
        Ok(())
    }

    fn stop(&self, session: &str) -> anyhow::Result<RecordedAudio> {
        let owned = self
            .sessions
            .lock()
            .unwrap()
            .get(session)
            .cloned()
            .context("computer audio recording is not active")?;
        let mut owned = owned.lock().unwrap();
        let active = match std::mem::take(&mut owned.recording) {
            RecordingState::Active(active) => active,
            RecordingState::Idle => bail!("computer audio recording is not active"),
            RecordingState::Closed => {
                owned.recording = RecordingState::Closed;
                bail!("computer audio session is closed");
            }
        };
        active.backend.stop()?;
        let filepath = active.directory.path().join("recording.wav");
        let bytes = std::fs::read(&filepath).context("read finalized computer audio")?;
        validate_wav(&bytes)?;
        owned.completed.push(active.directory);
        Ok(RecordedAudio { filepath, bytes })
    }

    /// Snapshot the current capture only. Waiting on this handle must happen
    /// outside both the session mutex and the runtime lifecycle read guard so
    /// host revocation can still stop/discard this same native capture.
    pub fn completion(&self, session: &str) -> AudioResult<AudioCompletion> {
        let owned = self
            .sessions
            .lock()
            .unwrap()
            .get(session)
            .cloned()
            .context("computer audio recording is not active")?;
        let owned = owned.lock().unwrap();
        match &owned.recording {
            RecordingState::Active(active) => active.backend.completion(),
            RecordingState::Idle => bail!("computer audio recording is not active"),
            RecordingState::Closed => bail!("computer audio session is closed"),
        }
    }

    pub fn close_session(&self, session: &str) -> anyhow::Result<()> {
        let owned = self.sessions.lock().unwrap().get(session).cloned();
        let Some(owned) = owned else {
            return Ok(());
        };
        // Keep this same ownership entry discoverable while native stop joins.
        // Concurrent runtime shutdown must wait on it, even when session close
        // started cleanup first on another blocking worker.
        let result = close_owned(owned.clone());
        let mut sessions = self.sessions.lock().unwrap();
        if sessions
            .get(session)
            .is_some_and(|entry| Arc::ptr_eq(entry, &owned))
        {
            sessions.remove(session);
        }
        result
    }

    /// Call on a blocking worker after runtime admission has drained.
    pub fn close_all(&self) -> anyhow::Result<()> {
        let owned = std::mem::take(&mut *self.sessions.lock().unwrap());
        let mut errors = Vec::new();
        for session in owned.into_values() {
            if let Err(error) = close_owned(session) {
                errors.push(error.to_string());
            }
        }
        if !errors.is_empty() {
            bail!("computer audio cleanup failed: {}", errors.join("; "));
        }
        Ok(())
    }
}

fn close_owned(owned: Arc<Mutex<SessionAudio>>) -> anyhow::Result<()> {
    let mut owned = owned.lock().unwrap();
    let result = match std::mem::replace(&mut owned.recording, RecordingState::Closed) {
        RecordingState::Active(active) => active.backend.stop(),
        RecordingState::Idle | RecordingState::Closed => Ok(()),
    };
    owned.completed.clear();
    result
}

impl Drop for AudioRecordings {
    fn drop(&mut self) {
        let owned = std::mem::take(self.sessions.get_mut().unwrap());
        if !owned.is_empty() {
            // Explicit SDK shutdown awaits close_all. The destructor fallback
            // keeps native joins and filesystem work off an async executor.
            let _ = std::thread::Builder::new()
                .name("cua-audio-cleanup".into())
                .spawn(move || {
                    for session in owned.into_values() {
                        let _ = close_owned(session);
                    }
                });
        }
    }
}

/// Install only after a trusted runtime constructor has enabled computer audio.
pub fn register_tools(
    registry: &mut ToolRegistry,
    factory: Arc<dyn AudioBackendFactory>,
) -> Arc<AudioRecordings> {
    let recordings = Arc::new(AudioRecordings::new(factory));
    registry.register(Box::new(StartAudio {
        recordings: recordings.clone(),
    }));
    registry.register(Box::new(StopAudio {
        recordings: recordings.clone(),
    }));
    let weak = Arc::downgrade(&recordings);
    registry.retain_session_end_hook(crate::session::register_scoped_fallible_session_end_hook(
        "computer_audio",
        move |session| {
            weak.upgrade().map_or(Ok(()), |recordings| {
                recordings
                    .close_session(session)
                    .map_err(|error| error.to_string())
            })
        },
    ));
    recordings
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartInput {
    max_duration_ms: Option<u64>,
    #[allow(dead_code)]
    session: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StopInput {
    #[allow(dead_code)]
    session: Option<String>,
}

fn session(args: &Value) -> Result<String, ToolResult> {
    args.get("_session_id")
        .and_then(Value::as_str)
        .filter(|session| !session.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            refused(
                "permission_denied",
                "computer audio requires an admitted lifecycle session",
            )
        })
}

fn refused(code: &str, message: impl Into<String>) -> ToolResult {
    let message = message.into();
    ToolResult::error(message.clone()).with_structured(json!({
        "status":"refused", "refusal":{"code":code,"message":message}
    }))
}

struct StartAudio {
    recordings: Arc<AudioRecordings>,
}

#[async_trait]
impl Tool for StartAudio {
    fn def(&self) -> &ToolDef {
        static DEF: OnceLock<ToolDef> = OnceLock::new();
        DEF.get_or_init(|| ToolDef {
            name: "start_audio_recording".into(),
            description: "Start computer output loopback audio for this session while other actions continue. Never records a microphone. The recording stops at max_duration_ms and is retrieved with stop_audio_recording.".into(),
            input_schema: json!({"type":"object","properties":{
                "max_duration_ms":{"type":"integer","minimum":100,"maximum":MAX_DURATION_MS,"default":DEFAULT_DURATION_MS},
                "session":crate::tool_schema::session_schema()
            },"additionalProperties":false}),
            read_only:false,destructive:false,idempotent:false,open_world:true,
        })
    }

    async fn invoke(&self, args: Value) -> ToolResult {
        let session = match session(&args) {
            Ok(session) => session,
            Err(error) => return error,
        };
        let input = match crate::tool_args::parse_typed_input::<StartInput>(
            "start_audio_recording",
            args,
        ) {
            Ok(input) => input,
            Err(error) => return error,
        };
        let millis = input.max_duration_ms.unwrap_or(DEFAULT_DURATION_MS);
        if !(100..=MAX_DURATION_MS).contains(&millis) {
            return refused(
                "invalid_arguments",
                "max_duration_ms must be an integer from 100 through 300000",
            );
        }
        // Reserve ownership before queuing work. Cancellation can drop the
        // dispatch future while spawn_blocking is still queued; canonical end
        // must already be able to close the exact entry the worker will use.
        let owned = self.recordings.reserve_session(&session);
        let recordings = self.recordings.clone();
        match tokio::task::spawn_blocking(move || {
            recordings.start_reserved(owned, Duration::from_millis(millis))
        })
        .await
        {
            Ok(Ok(())) => ToolResult::text("Computer audio recording started."),
            Ok(Err(error)) => refused("audio_recording_unavailable", error.to_string()),
            Err(error) => refused("audio_recording_unavailable", error.to_string()),
        }
    }

    async fn protected_resource_scope(
        &self,
        adapter: &str,
        _: &Value,
    ) -> Result<Option<Value>, String> {
        Ok(system_audio_scope(adapter))
    }
}

struct StopAudio {
    recordings: Arc<AudioRecordings>,
}

#[async_trait]
impl Tool for StopAudio {
    fn def(&self) -> &ToolDef {
        static DEF: OnceLock<ToolDef> = OnceLock::new();
        DEF.get_or_init(|| ToolDef {
            name: "stop_audio_recording".into(),
            description: "Stop this session's computer audio recording and return its exact 24 kHz stereo PCM16 WAV as a local filepath and data_url. A recording that reached its duration remains retrievable until stopped or the owning session ends.".into(),
            input_schema:json!({"type":"object","properties":{"session":crate::tool_schema::session_schema()},"additionalProperties":false}),
            read_only:false,destructive:false,idempotent:false,open_world:false,
        })
    }

    async fn invoke(&self, args: Value) -> ToolResult {
        let session = match session(&args) {
            Ok(session) => session,
            Err(error) => return error,
        };
        if let Err(error) =
            crate::tool_args::parse_typed_input::<StopInput>("stop_audio_recording", args)
        {
            return error;
        }
        let recordings = self.recordings.clone();
        match tokio::task::spawn_blocking(move || recordings.stop(&session)).await {
            Ok(Ok(audio)) => ToolResult::text("Computer audio recording finalized.")
                .with_structured(json!({
                    "filepath":audio.filepath,
                    "byte_length":audio.bytes.len(),
                    "data_url":format!("data:audio/wav;base64,{}",STANDARD.encode(audio.bytes))
                })),
            Ok(Err(error)) => refused("audio_recording_unavailable", error.to_string()),
            Err(error) => refused("audio_recording_unavailable", error.to_string()),
        }
    }

    async fn protected_resource_scope(
        &self,
        adapter: &str,
        _: &Value,
    ) -> Result<Option<Value>, String> {
        Ok(system_audio_scope(adapter))
    }
}

fn system_audio_scope(adapter: &str) -> Option<Value> {
    (adapter == "system_audio_output").then(|| {
        json!({
            "kind":"system_audio_output", "capture_source":"default_output_loopback",
            "microphone":false, "caller_selectable_device":false,
        })
    })
}

pub fn write_pcm16_stereo_wav(path: &Path, pcm_le: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    if pcm_le.len() % 4 != 0 {
        bail!("computer audio contains an incomplete stereo PCM16 frame");
    }
    let bytes = u32::try_from(pcm_le.len()).context("computer audio exceeds WAV length")?;
    let riff_length = bytes
        .checked_add(36)
        .context("computer audio exceeds WAV length")?;
    let mut output = std::fs::File::create(path)?;
    output.write_all(b"RIFF")?;
    output.write_all(&riff_length.to_le_bytes())?;
    output.write_all(b"WAVEfmt \x10\0\0\0\x01\0\x02\0")?;
    output.write_all(&SAMPLE_RATE.to_le_bytes())?;
    output.write_all(&(SAMPLE_RATE * 4).to_le_bytes())?;
    output.write_all(b"\x04\0\x10\0data")?;
    output.write_all(&bytes.to_le_bytes())?;
    output.write_all(pcm_le)?;
    output.flush()?;
    Ok(())
}

fn validate_wav(bytes: &[u8]) -> anyhow::Result<()> {
    let u32_at = |offset: usize| -> Option<u32> {
        Some(u32::from_le_bytes(
            bytes.get(offset..offset + 4)?.try_into().ok()?,
        ))
    };
    if bytes.get(..4) != Some(b"RIFF")
        || bytes.get(8..12) != Some(b"WAVE")
        || u32_at(4).map(u64::from).map(|length| length + 8) != Some(bytes.len() as u64)
    {
        bail!("computer audio did not return a complete WAV");
    }
    let mut position = 12;
    let mut format = false;
    let mut data = false;
    while position + 8 <= bytes.len() {
        let length = u32_at(position + 4).unwrap() as usize;
        let begin = position + 8;
        let end = begin
            .checked_add(length)
            .context("invalid WAV chunk length")?;
        let chunk = bytes.get(begin..end).context("truncated WAV chunk")?;
        match bytes.get(position..position + 4) {
            Some(b"fmt ") => {
                if chunk.len() < 16
                    || chunk[..4] != [1, 0, 2, 0]
                    || chunk[4..8] != SAMPLE_RATE.to_le_bytes()
                    || chunk[8..12] != (SAMPLE_RATE * 4).to_le_bytes()
                    || chunk[12..16] != [4, 0, 16, 0]
                {
                    bail!("computer audio must be stereo PCM16 at 24000 Hz");
                }
                format = true;
            }
            Some(b"data") => {
                if length % 4 != 0 {
                    bail!("computer audio has a partial stereo sample");
                }
                data = true;
            }
            _ => {}
        }
        position = end.checked_add(length % 2).context("invalid WAV padding")?;
    }
    if !format || !data || position != bytes.len() {
        bail!("computer audio did not return complete PCM WAV chunks");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn missing_native_completion_report_is_a_failure() {
        let (completion, completed) = AudioCompletion::channel();
        drop(completed);
        assert_eq!(
            completion.wait().await.unwrap_err().to_string(),
            "computer audio worker ended without reporting finalization"
        );
    }

    struct Factory(Arc<AtomicUsize>);
    struct Backend(PathBuf, Arc<AtomicUsize>);
    impl AudioBackendFactory for Factory {
        fn start(&self, path: &Path, _: Duration) -> anyhow::Result<Box<dyn AudioBackend>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(Backend(path.to_owned(), self.0.clone())))
        }
    }
    impl AudioBackend for Backend {
        fn stop(self: Box<Self>) -> anyhow::Result<()> {
            write_pcm16_stereo_wav(&self.0, &[1, 0, 2, 0])?;
            self.1.fetch_sub(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn runtime_shutdown_waits_for_a_session_close_already_stopping_native_audio() {
        struct BlockingFactory {
            entered: std::sync::mpsc::Sender<()>,
            release: Arc<Mutex<std::sync::mpsc::Receiver<()>>>,
        }
        struct BlockingBackend {
            entered: std::sync::mpsc::Sender<()>,
            release: Arc<Mutex<std::sync::mpsc::Receiver<()>>>,
        }
        impl AudioBackendFactory for BlockingFactory {
            fn start(&self, _: &Path, _: Duration) -> anyhow::Result<Box<dyn AudioBackend>> {
                Ok(Box::new(BlockingBackend {
                    entered: self.entered.clone(),
                    release: self.release.clone(),
                }))
            }
        }
        impl AudioBackend for BlockingBackend {
            fn stop(self: Box<Self>) -> anyhow::Result<()> {
                self.entered.send(()).unwrap();
                self.release.lock().unwrap().recv().unwrap();
                Ok(())
            }
        }
        let (entered, reached) = std::sync::mpsc::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let recordings = Arc::new(AudioRecordings::new(Arc::new(BlockingFactory {
            entered,
            release: Arc::new(Mutex::new(wait)),
        })));
        recordings.start("closing", Duration::from_secs(1)).unwrap();
        let closing = recordings.clone();
        let close = std::thread::spawn(move || closing.close_session("closing").unwrap());
        reached.recv().unwrap();
        let draining = recordings.clone();
        let (done, completion) = std::sync::mpsc::channel();
        let shutdown = std::thread::spawn(move || {
            draining.close_all().unwrap();
            done.send(()).unwrap();
        });
        assert!(matches!(
            completion.recv_timeout(Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        release.send(()).unwrap();
        close.join().unwrap();
        shutdown.join().unwrap();
        completion.recv().unwrap();
        assert!(recordings.sessions.lock().unwrap().is_empty());
    }

    #[test]
    fn sessions_own_capture_and_returned_file_lifetimes() {
        let active = Arc::new(AtomicUsize::new(0));
        let recordings = AudioRecordings::new(Arc::new(Factory(active.clone())));
        recordings.start("a", Duration::from_secs(1)).unwrap();
        recordings.start("b", Duration::from_secs(1)).unwrap();
        assert_eq!(
            recordings
                .start("a", Duration::from_secs(1))
                .unwrap_err()
                .to_string(),
            "computer audio recording is already active"
        );
        let audio = recordings.stop("a").unwrap();
        assert_eq!(&audio.bytes[44..], &[1, 0, 2, 0]);
        assert_eq!(std::fs::read(&audio.filepath).unwrap(), audio.bytes);
        assert_eq!(active.load(Ordering::SeqCst), 1);
        assert_eq!(
            recordings.stop("a").unwrap_err().to_string(),
            "computer audio recording is not active"
        );
        recordings.close_session("a").unwrap();
        assert!(!audio.filepath.exists());
        assert_eq!(active.load(Ordering::SeqCst), 1);
        recordings.close_all().unwrap();
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn wav_format_and_lengths_are_checked_before_returning_audio() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sample.wav");
        write_pcm16_stereo_wav(&path, &[0, 0, 1, 0]).unwrap();
        let mut wav = std::fs::read(path).unwrap();
        validate_wav(&wav).unwrap();
        wav[22] = 1;
        assert!(validate_wav(&wav).is_err());
        wav[22] = 2;
        wav.pop();
        assert!(validate_wav(&wav).is_err());
    }

    #[tokio::test]
    async fn invalid_start_options_never_open_a_backend() {
        let active = Arc::new(AtomicUsize::new(0));
        let tool = StartAudio {
            recordings: Arc::new(AudioRecordings::new(Arc::new(Factory(active.clone())))),
        };
        for millis in [json!(99), json!(300001), json!(100.5), json!(-1)] {
            let result = tool
                .invoke(json!({"_session_id":"audio-invalid", "max_duration_ms":millis}))
                .await;
            assert_eq!(result.is_error, Some(true));
        }
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn canceled_start_queued_on_a_blocking_worker_cannot_record_after_session_end() {
        use crate::authorization::PermissionMode;
        use crate::session_authorization::{SessionAuthorizationRegistry, SessionModeCeiling};
        let executor = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        executor.block_on(async {
            let (entered, mut reached) = tokio::sync::mpsc::unbounded_channel();
            let (release, wait) = std::sync::mpsc::channel();
            let occupied = tokio::task::spawn_blocking(move || {
                entered.send(()).unwrap();
                wait.recv().unwrap();
            });
            reached.recv().await.unwrap();
            let active = Arc::new(AtomicUsize::new(0));
            let mut registry = ToolRegistry::new();
            registry.register_session_tools();
            let recordings = register_tools(&mut registry, Arc::new(Factory(active.clone())));
            let registry = Arc::new(registry);
            let ceiling = SessionModeCeiling::for_trusted_sessions(
                [PermissionMode::Standard],
                false,
                Duration::from_secs(60),
                Duration::from_secs(60),
            )
            .unwrap();
            let context = SessionAuthorizationRegistry::with_ceiling(ceiling)
                .compatibility_context(PermissionMode::Standard, None)
                .unwrap();
            let internal = context.runtime_session_key("audio-canceled-queued-start");
            let dispatched = registry.clone();
            let start = tokio::spawn(async move {
                dispatched
                    .invoke_with_context(
                        "start_audio_recording",
                        json!({"session":"audio-canceled-queued-start"}),
                        context,
                    )
                    .await
            });
            tokio::time::timeout(Duration::from_secs(5), async {
                while recordings.sessions.lock().unwrap().is_empty() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("accepted start reserves its session before queueing native work");
            start.abort();
            assert!(start.await.unwrap_err().is_cancelled());
            crate::session::end_session(&internal);
            assert!(crate::session::session_cleanup_status(&internal).complete);
            release.send(()).unwrap();
            occupied.await.unwrap();
            tokio::task::spawn_blocking(|| ()).await.unwrap();
            assert_eq!(active.load(Ordering::SeqCst), 0);
            assert!(recordings.sessions.lock().unwrap().is_empty());
            assert!(crate::session::is_session_ended(&internal));
        });
    }

    #[cfg(feature = "yaml")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn desktop_manifest_does_not_implicitly_authorize_system_audio() {
        use crate::authorization::PermissionMode;
        use crate::session_authorization::{SessionAuthorizationRegistry, SessionModeCeiling};
        let active = Arc::new(AtomicUsize::new(0));
        let mut registry = ToolRegistry::new();
        let recordings = register_tools(&mut registry, Arc::new(Factory(active.clone())));
        let directory = tempfile::tempdir().unwrap();
        for allowed in [false, true] {
            let path = directory.path().join("manifest.yaml");
            std::fs::write(&path,format!("version: 3\nexpires_after: 1m\nidle_timeout: 30s\nresources:\n  desktop:\n    display: true\n    windows: [{{pid: 42, window_id: 7}}]\n  system_audio_output: {allowed}\nallow:\n  tools: [start_audio_recording, stop_audio_recording]\n")).unwrap();
            let manifest = Arc::new(crate::session_manifest::load_manifest(&path).unwrap());
            let ceiling = SessionModeCeiling::for_trusted_sessions(
                [PermissionMode::Bounded],
                false,
                Duration::from_secs(60),
                Duration::from_secs(60),
            )
            .unwrap();
            let context = SessionAuthorizationRegistry::with_ceiling(ceiling)
                .compatibility_context(PermissionMode::Bounded, Some(manifest))
                .unwrap();
            let started = registry
                .invoke_with_context(
                    "start_audio_recording",
                    json!({"session":"bounded-audio"}),
                    context.clone(),
                )
                .await;
            if !allowed {
                assert_eq!(
                    started.structured_content.unwrap()["refusal"]["code"],
                    "bounded_resource_outside_manifest"
                );
                assert_eq!(active.load(Ordering::SeqCst), 0);
            } else {
                assert_ne!(started.is_error, Some(true));
                assert_eq!(active.load(Ordering::SeqCst), 1);
                let stopped = registry
                    .invoke_with_context(
                        "stop_audio_recording",
                        json!({"session":"bounded-audio"}),
                        context,
                    )
                    .await;
                assert_ne!(stopped.is_error, Some(true));
                assert_eq!(active.load(Ordering::SeqCst), 0);
            }
        }
        recordings.close_all().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accepted_start_settles_before_ended_session_cleanup() {
        use crate::authorization::PermissionMode;
        use crate::session_authorization::{SessionAuthorizationRegistry, SessionModeCeiling};
        use std::sync::mpsc;
        struct StartingFactory {
            entered: mpsc::SyncSender<()>,
            release: Mutex<mpsc::Receiver<()>>,
            active: Arc<AtomicUsize>,
        }
        impl AudioBackendFactory for StartingFactory {
            fn start(&self, path: &Path, _: Duration) -> anyhow::Result<Box<dyn AudioBackend>> {
                self.entered.send(())?;
                self.release.lock().unwrap().recv()?;
                self.active.fetch_add(1, Ordering::SeqCst);
                Ok(Box::new(Backend(path.to_owned(), self.active.clone())))
            }
        }
        let (entered, started) = mpsc::sync_channel(1);
        let (release, released) = mpsc::sync_channel(1);
        let active = Arc::new(AtomicUsize::new(0));
        let mut registry = ToolRegistry::new();
        registry.register_session_tools();
        let recordings = register_tools(
            &mut registry,
            Arc::new(StartingFactory {
                entered,
                release: Mutex::new(released),
                active: active.clone(),
            }),
        );
        let registry = Arc::new(registry);
        let ceiling = SessionModeCeiling::for_trusted_sessions(
            [PermissionMode::Standard],
            false,
            Duration::from_secs(60),
            Duration::from_secs(60),
        )
        .unwrap();
        let context = SessionAuthorizationRegistry::with_ceiling(ceiling)
            .compatibility_context(PermissionMode::Standard, None)
            .unwrap();
        let session = "audio-pending-start-cleanup";
        let mut start = tokio::spawn({
            let registry = registry.clone();
            let context = context.clone();
            async move {
                registry
                    .invoke_with_context(
                        "start_audio_recording",
                        json!({"session":session}),
                        context,
                    )
                    .await
            }
        });
        tokio::select! {
            observed = tokio::task::spawn_blocking(move || started.recv()) => {
                observed.unwrap().expect("audio factory must start");
            }
            early = &mut start => panic!("start refused before reaching the backend: {:?}",early.unwrap().structured_content),
        }
        let ended = registry
            .invoke_with_context("end_session", json!({"session":session}), context.clone())
            .await;
        assert_eq!(ended.is_error, Some(true));
        release.send(()).unwrap();
        let started = start.await.unwrap();
        assert_ne!(started.is_error, Some(true));
        let internal = context.runtime_session_key(session);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let cleanup = crate::session::session_cleanup_status(&internal);
                assert!(cleanup.failures.is_empty(), "{cleanup:?}");
                if cleanup.complete {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("accepted startup must be followed by complete native cleanup");
        let ended = registry
            .invoke_with_context("end_session", json!({"session":session}), context.clone())
            .await;
        assert_ne!(ended.is_error, Some(true));
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert!(recordings.sessions.lock().unwrap().is_empty());
        let stale = registry
            .invoke_with_context("start_audio_recording", json!({"session":session}), context)
            .await;
        assert_eq!(
            stale.structured_content.unwrap()["refusal"]["code"],
            "session_ended"
        );
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }
}
