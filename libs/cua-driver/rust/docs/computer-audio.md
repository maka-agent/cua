# Opt-in computer output audio

The embedded SDK registers `start_audio_recording` and `stop_audio_recording`
only when the trusted constructor sets `ConfiguredDriverOptions.audio_enabled`
to `true`. The default is `false`. Tool arguments cannot enable recording.
Recording captures the default system output, never a microphone. Linux needs
locally installed FFmpeg with PulseAudio support and `pactl`; it does not acquire
either program. macOS uses ScreenCaptureKit; Windows uses WASAPI loopback.

`start_audio_recording` accepts an optional integer `max_duration_ms` between
100 and 300000 inclusive, defaulting to 60000. A session has one active capture.
Reaching the limit completes native capture but retains its slot and result
until `stop_audio_recording`; another start is rejected. Stopping an idle
session is rejected. Stop returns a WAV at 24000 Hz, two channels, signed
16-bit PCM. The raw tool result contains `filepath`, `byte_length`, and
`data_url`; a language facade may reconstruct its byte array from the data URL.
The path is local to the native worker and cannot be assumed readable by a
remote caller. Bytes in the data URL are the exact finalized file bytes.

Recordings belong to the authenticated runtime session, rather than a turn or
a process-wide recorder. Linux and macOS retain returned temporary files until
that session ends, including across subsequent recordings. Windows consumes the
previous result's file retention at the next parsed Start attempt: after the
active-recording check it attempts to unlink only that WAV, then validates the
new supported duration. A deletion failure does not block validation or a new
capture, and that consumed file is not retried by a later Start. Directory
custody remains with the session for terminal cleanup. Explicit session end
waits for native cleanup when no earlier action is in flight. If an accepted
start is still running, session end closes admission and reports pending
cleanup; completion of the accepted action triggers the same canonical cleanup
hooks. The caller may retry session end to observe final status. Closing the
bound SDK session schedules this exact session cleanup. Explicit runtime
shutdown drains accepted calls and awaits native audio cleanup. Synchronous
native cleanup hooks execute off the async executor, including with a
current-thread Tokio runtime.

Trusted Rust hosts may call `CuaDriverSession::discard_audio().await` on an
embedded binding to stop/discard just its audio and remove its WAV files. This
does not end the session, change its capture policy, or reset unrelated native,
browser, or JavaScript state. The method is absent from UniFFI, the C ABI, and
model tools; remote, private-worker and service sessions refuse it until their
transport implements trusted forwarding. The existing runtime write lock
drains read-admitted operations before cleanup, and an owned cleanup task
retains that drain through native settlement even if the host cancels its
await. Discard returns no audio result. A read-admitted stop can finish before
the drain; the embedding host must revalidate approval before exposing its
result.

This is resource cleanup, not another permission authority or a persistent
audio denial. A later start works only after the host admits it under its own
fresh approval. The host must serialize native invocation, cancellation
settlement, and discard. Maka uses its existing Driver lock for that order.
The SDK drain begins at `DriverRuntime` read admission: a C-ABI operation
queued on its executor before taking that lock is outside the drained set.
Discard can wait for unrelated read-admitted native calls on the same runtime;
it preserves their state and does not promise to interrupt them. Tests cover
admitted start/stop races, canceled discard awaits, foreign-session ownership,
and reuse of the same session after discard.

Rust hosts may also await `CuaDriverSession::wait_audio_finished()` on the
current recording of an embedded binding. This observes the actual native
capture finalization and propagates exit, close, and write errors. It does not
stop capture, retrieve audio, or clear the active slot. Linux waits for the
owned FFmpeg child exit and progress-reader close; macOS and Windows publish
the result after their capture worker releases native resources and finishes
its WAV write. The duration deadline by itself is never completion evidence.
An unreported worker exit/panic is a failure. The snapshot releases runtime
admission before awaiting finalization, allowing concurrent trusted discard or
runtime shutdown to stop the same worker. Canceling this observation does not
stop capture. Audio disabled, absent active recording, unsupported backends,
and non-embedded transports are explicit errors.

A host retaining recordings across its JavaScript-kernel reset must retain
the old bound session until native completion or trusted discard. Each new
host epoch needs a distinct native `public_session` in the same runtime:
resource keys use the runtime generation and that public session, rather than
the identity of the SDK handle. A fresh epoch then has no active recording to
stop, while permission revocation can still discard the retained old binding.
This host API adds no model operation or approval authority.

Audio uses a `system_audio_output` observation adapter. Its
scope names the trusted runtime, session, fixed default-output loopback, and
absence of microphone or caller-selected device. Stop also authorizes the
owned temporary file output. A bounded manifest must explicitly set
`resources.system_audio_output: true`; a display or window resource does not
grant system audio. The trusted host remains responsible for its user-facing
audio opt-in and platform approval policy. In particular, the original macOS
reference requires a high-risk session audio grant; enabling Cua alone does
not implement that host user interface.

## Platform requirements and limits

Short Linux captures need output to be playing before capture starts. PulseAudio
render latency can otherwise consume part of the recording interval before the
signal reaches the monitor. Duration limits use device timestamps and do not
guarantee an exact PCM sample count or wall-clock interval.

The Windows duration parser accepts null or an unsigned 32-bit integer. It
rejects strings, fractional numbers, negative values, and larger integers before
checking active capture or touching the previous file. Null or an absent field
uses the default. Linux and macOS use their platform argument normalization.

After Windows Start consumes a previous WAV slot, terminal cleanup does not
retry that file or recursively remove other contents of its private wrapper
directory. It only attempts to remove that directory if empty. An unconsumed
result and an active capture retain their session cleanup obligations. Outer
host or operating-system temporary-file cleanup is independent of this policy.

macOS requires ScreenCaptureKit permission; Windows requires an available
WASAPI loopback endpoint. Device changes, OS permission settings, and backend
failures can affect capture.

For isolated Linux loopback checks, use
`scripts/ci/run-rust-loopback-audio-e2e.sh`. It creates a private PulseAudio null
sink and generated output; never run it against a personal sound server.
