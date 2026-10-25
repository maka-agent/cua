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
a process-wide recorder. Returned temporary files remain readable until that
session ends, including across subsequent recordings. Explicit session end
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

Audio has its own reviewed `system_audio_output` observation adapter. Its
scope names the trusted runtime, session, fixed default-output loopback, and
absence of microphone or caller-selected device. Stop also authorizes the
owned temporary file output. A bounded manifest must explicitly set
`resources.system_audio_output: true`; a display or window resource does not
grant system audio. The trusted host remains responsible for its user-facing
audio opt-in and platform approval policy. In particular, the original macOS
reference requires a high-risk session audio grant; enabling Cua alone does
not implement that host user interface.

## Evidence and verification limits

The public behavior above is based on inspection of the original shipped
runtime and its type declarations in the task-owned verified Linux development
fixture. The private REA audit summary has evidence ID
`ev_9015d8f727058f31eec7b97e59ef21aca32f0e2e6916347a2198a9cc377eb1dd`.
Source artifact identity is SHA-256
`71d2a64db3d7b74c00cdb73bf47cbee76d60e7611e4c6e23f2aced25c5c22957`.
No original implementation or application binary is included here.

Core tests cover options, WAV chunk validation, isolated session ownership,
output lifetime, bounded-manifest denial, and an accepted-start/end race.
SDK tests cover constructor registration and canonical bound-session cleanup.
The ignored `audio_loopback_test` uses generated 440 Hz output and a private
PulseAudio null sink through `scripts/ci/run-rust-loopback-audio-e2e.sh`; it
must never run against a personal sound server. It checks PCM format, signal,
returned bytes, retained completion, and native session cleanup. The runner
does not use the caller's audio server or microphone.

The Linux x86_64 SDK test passed in a disposable, network-disabled container:
73006 exact WAV bytes, 439.69 Hz measured generated tone, identical stereo
channels, native automatic completion, explicit end cleanup, returned-file
retirement, and bound SDK session close cleanup. An independent original
public-client probe in the same private null-sink fixture measured 439.85 Hz.
The source-backed FFmpeg/Pulse pipeline uses device timestamps for its duration
limit: the original 1500 ms automatic recording contained 0.81392 seconds of
PCM, while this candidate run contained 0.75967 seconds. This fixture does not
establish exact sample-count or wall-clock duration equivalence. Output must
already be playing before short captures, because Pulse render latency can
otherwise consume the short recording before the generated tone reaches its
monitor. These observations do not justify changing native recording flags or
claiming exact timing parity.

Windows GNU cross-checks and pure timeline tests, and macOS API type checking
and pure conversion/timeline tests, are structural evidence only. They do not
prove native endpoint behavior, ScreenCaptureKit permissions, device changes,
or parity with original helpers. Real task-owned macOS and Windows audio
fixtures remain required before claiming platform behavior equivalence.
