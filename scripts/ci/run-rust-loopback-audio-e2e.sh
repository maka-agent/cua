#!/usr/bin/env bash
# Own a private output-only PulseAudio fixture; never connect to caller audio.
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
fixture=$(mktemp -d /tmp/cua-loopback-audio.XXXXXXXX)
chmod 700 "$fixture"
task_audio_home="$fixture/home"
task_audio_cargo_home="${CARGO_HOME:-$HOME/.cargo}"
task_audio_rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
export XDG_CONFIG_HOME="$fixture/config"
export XDG_RUNTIME_DIR="$fixture/runtime"
export PULSE_SERVER="unix:$fixture/native"
export PULSE_SINK=cua_audio_fixture
mkdir -p "$task_audio_home" "$XDG_CONFIG_HOME" "$XDG_RUNTIME_DIR"
chmod 700 "$XDG_RUNTIME_DIR"
env HOME="$task_audio_home" pulseaudio -n --daemonize=no --exit-idle-time=-1 --use-pid-file=no \
  --load="module-native-protocol-unix socket=$fixture/native auth-anonymous=1" \
  --load="module-null-sink sink_name=cua_audio_fixture rate=24000 channels=2" \
  --log-target="file:$fixture/pulse.log" &
audio_pid=$!
cleanup() {
  kill "$audio_pid" 2>/dev/null || true
  wait "$audio_pid" 2>/dev/null || true
  rm -rf -- "$fixture"
}
trap cleanup EXIT
until pactl info >/dev/null 2>&1; do
  if ! kill -0 "$audio_pid" 2>/dev/null; then
    cat "$fixture/pulse.log" >&2
    exit 1
  fi
  sleep 0.05
done
pactl set-default-sink cua_audio_fixture
if [[ $# -gt 0 ]]; then
  env HOME="$task_audio_home" "$@"
else
  cd "$repo/libs/cua-driver/rust"
  env HOME="$task_audio_home" CARGO_HOME="$task_audio_cargo_home" RUSTUP_HOME="$task_audio_rustup_home" \
    cargo test -p cua-driver-e2e --test audio_loopback_test --locked -- \
    --ignored --nocapture --test-threads=1
fi
