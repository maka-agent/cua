//! Computer output loopback through the locally installed PulseAudio and FFmpeg.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{bail, Context};
use cua_driver_core::audio::{AudioBackend, AudioBackendFactory};

pub struct LoopbackAudioBackendFactory;

impl AudioBackendFactory for LoopbackAudioBackendFactory {
    fn start(
        &self,
        output_path: &Path,
        max_duration: Duration,
    ) -> anyhow::Result<Box<dyn AudioBackend>> {
        let sink = Command::new("pactl")
            .arg("get-default-sink")
            .output()
            .context(
                "computer audio requires a locally installed pactl and PulseAudio output sink",
            )?;
        if !sink.status.success() {
            bail!(
                "PulseAudio default output is unavailable: {}",
                String::from_utf8_lossy(&sink.stderr)
            );
        }
        let sink = std::str::from_utf8(&sink.stdout)?.trim();
        if sink.is_empty() {
            bail!("PulseAudio returned an empty default output sink");
        }
        let mut child = Command::new("ffmpeg")
            .args([
                "-hide_banner",
                "-loglevel",
                "error",
                "-y",
                "-progress",
                "pipe:2",
                "-f",
                "pulse",
                "-i",
            ])
            .arg(format!("{sink}.monitor"))
            .arg("-t")
            .arg(max_duration.as_secs_f64().to_string())
            .args(["-ar", "24000", "-ac", "2", "-c:a", "pcm_s16le"])
            .arg(output_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("computer audio requires a locally installed ffmpeg with PulseAudio input")?;
        let stderr = child
            .stderr
            .take()
            .context("FFmpeg computer audio has no progress pipe")?;
        let (ready, readiness) = mpsc::sync_channel(1);
        let stderr = std::thread::Builder::new()
            .name("cua-audio-ffmpeg".into())
            .spawn(move || {
                let mut output = String::new();
                let mut ready = Some(ready);
                for line in BufReader::new(stderr).lines() {
                    match line {
                        Ok(line) => {
                            if line == "progress=continue" {
                                if let Some(ready) = ready.take() {
                                    let _ = ready.send(Ok(()));
                                }
                            }
                            output.push_str(&line);
                            output.push('\n');
                        }
                        Err(error) => {
                            output.push_str(&error.to_string());
                            break;
                        }
                    }
                }
                if let Some(ready) = ready.take() {
                    let _ = ready.send(Err(
                        "FFmpeg stopped before computer audio recording started",
                    ));
                }
                output
            });
        let stderr = match stderr {
            Ok(stderr) => stderr,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.into());
            }
        };
        let mut backend = FfmpegAudio {
            child: Some(child),
            stderr: Some(stderr),
        };
        if let Err(error) = readiness.recv().context("FFmpeg progress worker ended")? {
            let finalization = backend.finish();
            bail!(
                "{error}: {}",
                finalization
                    .err()
                    .map(|error| error.to_string())
                    .unwrap_or_default()
            );
        }
        Ok(Box::new(backend))
    }
}

struct FfmpegAudio {
    child: Option<Child>,
    stderr: Option<JoinHandle<String>>,
}

impl FfmpegAudio {
    fn finish(&mut self) -> anyhow::Result<()> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        if let Some(mut input) = child.stdin.take() {
            let _ = input.write_all(b"q\n");
        }
        let status = match child.wait() {
            Ok(status) => status,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context("wait for computer audio capture");
            }
        };
        let stderr = self
            .stderr
            .take()
            .map(|worker| {
                worker
                    .join()
                    .unwrap_or_else(|_| "FFmpeg progress worker panicked".into())
            })
            .unwrap_or_default();
        if !status.success() {
            bail!(
                "FFmpeg computer audio capture failed ({status}): {}",
                stderr.trim()
            );
        }
        Ok(())
    }
}

impl AudioBackend for FfmpegAudio {
    fn stop(mut self: Box<Self>) -> anyhow::Result<()> {
        self.finish()
    }
}

impl Drop for FfmpegAudio {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(worker) = self.stderr.take() {
            let _ = worker.join();
        }
    }
}
