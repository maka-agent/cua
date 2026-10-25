//! Run only through scripts/ci/run-rust-loopback-audio-e2e.sh, which owns a
//! private PulseAudio server and generated output sink. Never records a microphone.
#![cfg(target_os = "linux")]

use std::process::{Child, Command, Stdio};
use std::time::Instant;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use cua_driver_sdk::{
    ConfiguredDriverOptions, CuaDriver, CuaDriverSession, RuntimeAuthorizationOptions,
    SessionPermissionMode, TrustedSessionOptions,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn source_outputs() -> usize {
    let result = Command::new("pactl")
        .args(["list", "source-outputs", "short"])
        .output()
        .unwrap();
    assert!(result.status.success());
    String::from_utf8(result.stdout).unwrap().lines().count()
}

async fn call(session: &CuaDriverSession, name: &str, args: Value) -> Value {
    let result = session
        .call_tool(name.into(), args.to_string())
        .await
        .unwrap();
    assert!(!result.is_error, "{name}: {}", result.text);
    serde_json::from_str(&result.raw_json).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the private generated-tone PulseAudio fixture runner"]
async fn loopback_audio_captures_generated_output_and_settles_its_session() {
    assert!(std::env::var("PULSE_SERVER")
        .unwrap()
        .starts_with("unix:/tmp/cua-loopback-audio."));
    let sink = Command::new("pactl")
        .arg("get-default-sink")
        .output()
        .unwrap();
    assert!(sink.status.success());
    assert_eq!(
        String::from_utf8(sink.stdout).unwrap().trim(),
        "cua_audio_fixture"
    );
    assert_eq!(source_outputs(), 0);
    let driver = CuaDriver::create_configured(ConfiguredDriverOptions {
        claude_code_compatibility: false,
        audio_enabled: true,
        authorization: RuntimeAuthorizationOptions {
            allowed_modes: vec![SessionPermissionMode::Standard],
            compatibility_mode: SessionPermissionMode::Standard,
            compatibility_capability_manifest_path: None,
            compatibility_bounded_manifest_path: None,
            unrestricted_acknowledged: false,
            max_session_ttl_seconds: 60,
            max_idle_ttl_seconds: 60,
        },
    })
    .unwrap();
    let session = driver
        .create_trusted_session(TrustedSessionOptions {
            public_session: "audio-tone-fixture".into(),
            mode: SessionPermissionMode::Standard,
            ttl_seconds: 60,
            idle_ttl_seconds: 60,
            capability_manifest_path: None,
            bounded_manifest_path: None,
        })
        .unwrap();
    call(&session, "start_session", json!({"capture_scope":"window"})).await;
    // Start output before capture so Pulse render latency cannot consume this
    // short recording before the first generated sample reaches the monitor.
    struct GeneratedTone(Child);
    impl Drop for GeneratedTone {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let tone_wall = Instant::now();
    let tone = GeneratedTone(
        Command::new("ffmpeg")
            .args([
                "-hide_banner",
                "-loglevel",
                "error",
                "-re",
                "-f",
                "lavfi",
                "-i",
                "sine=frequency=440:sample_rate=24000:duration=30",
                "-ac",
                "2",
                "-f",
                "pulse",
                "cua_audio_fixture",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let start_wall = Instant::now();
    call(
        &session,
        "start_audio_recording",
        json!({"max_duration_ms":1500}),
    )
    .await;
    let start_seconds = start_wall.elapsed().as_secs_f64();
    assert_eq!(source_outputs(), 1);
    // A retired host epoch retains its old binding, while a new epoch gets a
    // distinct public session in the same embedded runtime. It cannot stop or
    // retrieve the old epoch's still-running recording.
    let fresh = driver
        .create_trusted_session(TrustedSessionOptions {
            public_session: "audio-fresh-epoch-fixture".into(),
            mode: SessionPermissionMode::Standard,
            ttl_seconds: 60,
            idle_ttl_seconds: 60,
            capability_manifest_path: None,
            bounded_manifest_path: None,
        })
        .unwrap();
    let absent = fresh
        .call_tool("stop_audio_recording".into(), "{}".into())
        .await
        .unwrap();
    let absent: Value = serde_json::from_str(&absent.raw_json).unwrap();
    assert_eq!(absent["isError"], true);
    assert_eq!(
        absent["structuredContent"]["refusal"]["message"],
        "computer audio recording is not active"
    );
    assert_eq!(source_outputs(), 1);
    let deadline_wall = Instant::now();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        session.wait_audio_finished(),
    )
    .await
    .expect("native capture must reach its automatic duration without stop")
    .expect("native capture must finalize successfully");
    assert_eq!(source_outputs(), 0);
    let completion_seconds = deadline_wall.elapsed().as_secs_f64();
    let playback_seconds = tone_wall.elapsed().as_secs_f64();
    let duplicate = session
        .call_tool("start_audio_recording".into(), "{}".into())
        .await
        .unwrap();
    assert!(duplicate.is_error && duplicate.text.contains("already active"));
    let result = call(&session, "stop_audio_recording", json!({})).await;
    drop(tone);
    let audio = &result["structuredContent"];
    let bytes = STANDARD
        .decode(
            audio["data_url"]
                .as_str()
                .unwrap()
                .strip_prefix("data:audio/wav;base64,")
                .unwrap(),
        )
        .unwrap();
    assert_eq!(audio["byte_length"].as_u64().unwrap(), bytes.len() as u64);
    assert_eq!(
        std::fs::read(audio["filepath"].as_str().unwrap()).unwrap(),
        bytes
    );
    let mut position = 12;
    let mut pcm = None;
    let mut format = None;
    while position + 8 <= bytes.len() {
        let length =
            u32::from_le_bytes(bytes[position + 4..position + 8].try_into().unwrap()) as usize;
        let data = &bytes[position + 8..position + 8 + length];
        match &bytes[position..position + 4] {
            b"fmt " => format = Some(data),
            b"data" => pcm = Some(data),
            _ => {}
        }
        position += 8 + length + length % 2;
    }
    let format = format.unwrap();
    assert_eq!(&format[..4], &[1, 0, 2, 0]);
    assert_eq!(u32::from_le_bytes(format[4..8].try_into().unwrap()), 24_000);
    assert_eq!(&format[12..16], &[4, 0, 16, 0]);
    let left: Vec<_> = pcm
        .unwrap()
        .chunks_exact(4)
        .map(|frame| i16::from_le_bytes(frame[..2].try_into().unwrap()))
        .collect();
    let duration = left.len() as f64 / 24_000.0;
    eprintln!(
        "AUDIO_LOOPBACK_TIMING {}",
        json!({"start_seconds":start_seconds,"playback_seconds":playback_seconds,"duration_seconds":duration})
    );
    if let Some(directory) = std::env::var_os("CUA_E2E_ARTIFACT_DIR") {
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            std::path::Path::new(&directory).join("generated-loopback.wav"),
            &bytes,
        )
        .unwrap();
    }
    // The original FFmpeg/Pulse pipeline uses device timestamps for -t.
    // In this fixture its 1500 ms auto-completion produced 0.81392 s of PCM;
    // requested duration is not an exact sample-count or wall-clock promise.
    assert!((0.25..=1.60).contains(&duration), "duration={duration}");
    assert!(pcm
        .unwrap()
        .chunks_exact(4)
        .all(|frame| frame[..2] == frame[2..]));
    let first = left.iter().position(|sample| sample.abs() > 100).unwrap();
    let last = left.iter().rposition(|sample| sample.abs() > 100).unwrap();
    let signal = &left[first..=last];
    let crossings = signal
        .windows(2)
        .filter(|pair| pair[0] <= 0 && pair[1] > 0)
        .count();
    let frequency = crossings as f64 * 24_000.0 / signal.len() as f64;
    assert!((430.0..450.0).contains(&frequency), "frequency={frequency}");
    let (sine, cosine, power) = signal.iter().enumerate().fold(
        (0.0, 0.0, 0.0),
        |(sine, cosine, power), (index, sample)| {
            let sample = f64::from(*sample);
            let phase = std::f64::consts::TAU * 440.0 * index as f64 / 24_000.0;
            (
                sine + sample * phase.sin(),
                cosine + sample * phase.cos(),
                power + sample * sample,
            )
        },
    );
    let tone_correlation = 2.0 * (sine * sine + cosine * cosine) / (signal.len() as f64 * power);
    assert!(
        tone_correlation > 0.90,
        "tone_correlation={tone_correlation}"
    );
    assert_eq!(source_outputs(), 0);
    let idle = session
        .call_tool("stop_audio_recording".into(), "{}".into())
        .await
        .unwrap();
    assert!(idle.is_error && idle.text.contains("not active"));
    call(
        &session,
        "start_audio_recording",
        json!({"max_duration_ms":5000}),
    )
    .await;
    assert_eq!(source_outputs(), 1);
    // Completion observation must not hold runtime read admission and prevent
    // host revocation from stopping the same native worker.
    let observing = tokio::spawn({
        let session = session.clone();
        async move { session.wait_audio_finished().await }
    });
    tokio::task::yield_now().await;
    tokio::time::timeout(std::time::Duration::from_secs(5), session.discard_audio())
        .await
        .expect("discard must not deadlock behind completion observation")
        .unwrap();
    // If discard wins before the observation's snapshot, it truthfully sees
    // no active capture. Both orders must settle; no native worker remains.
    if let Err(error) = observing.await.unwrap() {
        assert!(error
            .to_string()
            .contains("computer audio recording is not active"));
    }
    assert_eq!(source_outputs(), 0);
    assert!(!std::path::Path::new(audio["filepath"].as_str().unwrap()).exists());
    let state = call(&session, "get_session_state", json!({})).await;
    let lifecycle = call(&session, "get_session", json!({})).await;
    assert_eq!(lifecycle["structuredContent"]["state"], "active");
    assert_eq!(state["structuredContent"]["capture_scope"], "window");
    // A later host-approved operation reuses the same session binding. The
    // trusted cleanup API grants no permission of its own.
    call(
        &session,
        "start_audio_recording",
        json!({"max_duration_ms":5000}),
    )
    .await;
    assert_eq!(source_outputs(), 1);
    call(&session, "end_session", json!({})).await;
    assert_eq!(source_outputs(), 0);
    assert!(!std::path::Path::new(audio["filepath"].as_str().unwrap()).exists());
    let closing_session = driver
        .create_trusted_session(TrustedSessionOptions {
            public_session: "audio-close-fixture".into(),
            mode: SessionPermissionMode::Standard,
            ttl_seconds: 60,
            idle_ttl_seconds: 60,
            capability_manifest_path: None,
            bounded_manifest_path: None,
        })
        .unwrap();
    call(
        &closing_session,
        "start_audio_recording",
        json!({"max_duration_ms":5000}),
    )
    .await;
    assert_eq!(source_outputs(), 1);
    closing_session.close();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while source_outputs() != 0 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("SDK close must settle the session-owned recorder");
    eprintln!(
        "AUDIO_LOOPBACK_RESULT {}",
        json!({"bytes":bytes.len(),"sha256":format!("{:x}",Sha256::digest(&bytes)),
        "channels":2,"sample_rate":24000,"bits":16,"duration_seconds":duration,
        "tone_hz":frequency,"tone_correlation":tone_correlation,"identical_generated_stereo_channels":true,"duplicate_start_refused":true,"idle_stop_refused":true,"session_cleanup":true,
        "sdk_session_close_cleanup":true,"host_discard_cleanup":true,"same_session_restart_after_discard":true,"capture_policy_preserved_after_discard":true,"start_seconds":start_seconds,"playback_seconds":playback_seconds,"completion_seconds":completion_seconds,"automatic_completion_observed":true,"host_native_completion_observed":true,"new_epoch_cannot_stop_old_capture":true})
    );
    driver.shutdown().await.unwrap();
}
