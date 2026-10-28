// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! WASAPI capture of the default console render endpoint, as 24 kHz stereo PCM16.
//! No capture endpoint or microphone is opened.
//!
//! Native contracts:
//! - https://learn.microsoft.com/en-us/windows/win32/coreaudio/loopback-recording
//! - https://learn.microsoft.com/en-us/windows/win32/coreaudio/audclnt-streamflags-xxx-constants
//! - https://learn.microsoft.com/en-us/windows/win32/api/audioclient/nf-audioclient-iaudiocaptureclient-getbuffer

const SAMPLE_RATE: usize = 24_000;
const FRAME_BYTES: usize = 4;
const HNS_PER_SECOND: i128 = 10_000_000;

/// Packet positions share the WASAPI device clock. Missing render packets are
/// silence; an explicitly reported discontinuity is rejected by the adapter.
struct PcmTimeline {
    bytes: Vec<u8>,
    max_frames: usize,
}

impl PcmTimeline {
    fn new(max_frames: usize) -> Self {
        Self {
            bytes: Vec::new(),
            max_frames,
        }
    }

    fn append(&mut self, first_frame: i128, frames: usize, data: Option<&[u8]>) {
        let skip = usize::try_from((-first_frame).max(0))
            .unwrap_or(usize::MAX)
            .min(frames);
        let start = usize::try_from(first_frame.max(0)).unwrap_or(usize::MAX);
        if start >= self.max_frames || skip == frames {
            return;
        }
        let end = start.saturating_add(frames - skip).min(self.max_frames);
        let retained_start = (self.bytes.len() / FRAME_BYTES).max(start);
        if retained_start >= end {
            return;
        }
        self.bytes.resize(end * FRAME_BYTES, 0);
        if let Some(data) = data {
            let source_start = (skip + retained_start - start) * FRAME_BYTES;
            let destination = retained_start * FRAME_BYTES;
            self.bytes[destination..end * FRAME_BYTES].copy_from_slice(
                &data[source_start..source_start + (end - retained_start) * FRAME_BYTES],
            );
        }
    }

    fn finish(mut self, frames: usize) -> Vec<u8> {
        self.bytes
            .resize(frames.min(self.max_frames) * FRAME_BYTES, 0);
        self.bytes
    }
}

#[cfg(target_os = "windows")]
pub use native::LoopbackAudioBackendFactory;

#[cfg(target_os = "windows")]
mod native {
    use super::{PcmTimeline, FRAME_BYTES, HNS_PER_SECOND, SAMPLE_RATE};
    use anyhow::{anyhow, Context, Result};
    use cua_driver_core::audio::{
        AudioBackend, AudioBackendFactory, AudioCompletion, CompletedRecordingLifetime,
    };
    use std::{
        path::Path,
        sync::mpsc::{self, Receiver, Sender},
        thread::{self, JoinHandle},
        time::Duration,
    };
    use windows::Win32::{
        Media::Audio::{
            eConsole, eRender, IAudioCaptureClient, IAudioClient, IMMDeviceEnumerator,
            MMDeviceEnumerator, AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY, AUDCLNT_BUFFERFLAGS_SILENT,
            AUDCLNT_BUFFERFLAGS_TIMESTAMP_ERROR, AUDCLNT_SHAREMODE_SHARED,
            AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM, AUDCLNT_STREAMFLAGS_LOOPBACK,
            AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY, WAVEFORMATEX, WAVE_FORMAT_PCM,
        },
        System::{
            Com::{
                CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_ALL, COINIT_MULTITHREADED,
            },
            Performance::{QueryPerformanceCounter, QueryPerformanceFrequency},
        },
    };

    pub struct LoopbackAudioBackendFactory;

    impl AudioBackendFactory for LoopbackAudioBackendFactory {
        fn completed_recording_lifetime(&self) -> CompletedRecordingLifetime {
            CompletedRecordingLifetime::UntilNextStartAttempt
        }

        fn start(
            &self,
            output_path: &Path,
            max_duration: Duration,
        ) -> Result<Box<dyn AudioBackend>> {
            let path = output_path.to_owned();
            let (stop, stopping) = mpsc::channel();
            let (ready, started) = mpsc::sync_channel(1);
            let (completion, finished) = AudioCompletion::channel();
            let worker = thread::Builder::new()
                .name("cua-audio-loopback".into())
                .spawn(move || {
                    let result = record_on_worker(&path, max_duration, stopping, ready);
                    // The native scope has released Capture and its apartment;
                    // the actual capture/write result is now safe to publish.
                    finished.finish(&result);
                    result
                })
                .context("could not start WASAPI capture thread")?;
            match started.recv() {
                Ok(Ok(())) => Ok(Box::new(LoopbackAudioBackend {
                    stop,
                    worker: Some(worker),
                    completion,
                })),
                Ok(Err(error)) => {
                    let _ = worker.join();
                    Err(anyhow!(
                        "could not start system-output audio capture: {error}"
                    ))
                }
                Err(_) => match worker.join() {
                    Ok(Err(error)) => Err(error),
                    _ => Err(anyhow!("WASAPI capture thread ended before startup")),
                },
            }
        }
    }

    struct LoopbackAudioBackend {
        stop: Sender<()>,
        worker: Option<JoinHandle<Result<()>>>,
        completion: AudioCompletion,
    }

    impl AudioBackend for LoopbackAudioBackend {
        fn stop(mut self: Box<Self>) -> Result<()> {
            let _ = self.stop.send(());
            self.worker
                .take()
                .expect("owned capture thread")
                .join()
                .map_err(|_| anyhow!("WASAPI capture thread panicked"))?
        }

        fn completion(&self) -> Result<AudioCompletion> {
            Ok(self.completion.clone())
        }
    }

    impl Drop for LoopbackAudioBackend {
        fn drop(&mut self) {
            if let Some(worker) = self.worker.take() {
                let _ = self.stop.send(());
                if let Ok(Err(error)) = worker.join() {
                    tracing::warn!(%error, "system-output audio cleanup failed");
                }
            }
        }
    }

    fn record_on_worker(
        path: &Path,
        max_duration: Duration,
        stopping: Receiver<()>,
        ready: mpsc::SyncSender<Result<(), String>>,
    ) -> Result<()> {
        // Every interface is created, consumed and released on this thread,
        // before its COM apartment is uninitialized.
        let apartment = match Apartment::initialize() {
            Ok(apartment) => apartment,
            Err(error) => {
                let error = format!("{error:#}");
                let _ = ready.send(Err(error.clone()));
                return Err(anyhow!(error));
            }
        };
        let result = (|| {
            let mut capture = match Capture::open() {
                Ok(capture) => capture,
                Err(error) => {
                    let _ = ready.send(Err(format!("{error:#}")));
                    return Err(error);
                }
            };
            let origin = match capture.start() {
                Ok(origin) => origin,
                Err(error) => {
                    let _ = ready.send(Err(format!("{error:#}")));
                    return Err(error);
                }
            };
            if ready.send(Ok(())).is_err() {
                return Err(anyhow!("audio start caller disconnected"));
            }
            capture.record(path, origin, max_duration, stopping)
        })();
        // Windows errors can retain IErrorInfo. Release those errors while the
        // apartment is alive, retaining only owned text across this boundary.
        let result = result.map_err(|error| anyhow!("{error:#}"));
        drop(apartment);
        result
    }

    struct Apartment;
    impl Apartment {
        fn initialize() -> Result<Self> {
            // SAFETY: the owned worker uses no COM interfaces before this call.
            unsafe { CoInitializeEx(None, COINIT_MULTITHREADED).ok()? };
            Ok(Self)
        }
    }
    impl Drop for Apartment {
        fn drop(&mut self) {
            // SAFETY: balances successful initialization, including S_FALSE.
            unsafe { CoUninitialize() };
        }
    }

    struct Capture {
        client: IAudioClient,
        packets: IAudioCaptureClient,
        clock_frequency: i64,
        poll_interval: Duration,
        running: bool,
    }

    impl Capture {
        fn open() -> Result<Self> {
            // SAFETY: this thread owns a COM apartment and every returned
            // interface remains confined to it. The format is packed Win32 ABI.
            unsafe {
                let devices: IMMDeviceEnumerator =
                    CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL)?;
                let device = devices
                    .GetDefaultAudioEndpoint(eRender, eConsole)
                    .context("default Windows render endpoint is unavailable")?;
                let client: IAudioClient = device.Activate(CLSCTX_ALL, None)?;
                let mut device_period = 0;
                client.GetDevicePeriod(Some(&mut device_period), None)?;
                anyhow::ensure!(
                    device_period > 0,
                    "WASAPI returned an invalid device period"
                );
                let format = WAVEFORMATEX {
                    wFormatTag: WAVE_FORMAT_PCM as u16,
                    nChannels: 2,
                    nSamplesPerSec: SAMPLE_RATE as u32,
                    nAvgBytesPerSec: (SAMPLE_RATE * FRAME_BYTES) as u32,
                    nBlockAlign: FRAME_BYTES as u16,
                    wBitsPerSample: 16,
                    cbSize: 0,
                };
                client
                    .Initialize(
                        AUDCLNT_SHAREMODE_SHARED,
                        AUDCLNT_STREAMFLAGS_LOOPBACK
                            | AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM
                            | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY,
                        device_period
                            .checked_mul(4)
                            .context("invalid WASAPI buffer duration")?,
                        0,
                        &format,
                        None,
                    )
                    .context("WASAPI could not open 24 kHz stereo PCM16 loopback capture")?;
                let packets = client.GetService::<IAudioCaptureClient>()?;
                let mut clock_frequency = 0;
                QueryPerformanceFrequency(&mut clock_frequency)?;
                anyhow::ensure!(
                    clock_frequency > 0,
                    "performance clock frequency is unavailable"
                );
                Ok(Self {
                    client,
                    packets,
                    clock_frequency,
                    poll_interval: Duration::from_nanos(device_period as u64 * 100) / 2,
                    running: false,
                })
            }
        }

        fn clock_hns(&self) -> Result<i128> {
            let mut ticks = 0;
            // SAFETY: a valid writable counter is supplied.
            unsafe { QueryPerformanceCounter(&mut ticks)? };
            Ok(i128::from(ticks) * HNS_PER_SECOND / i128::from(self.clock_frequency))
        }

        fn start(&mut self) -> Result<i128> {
            let origin = self.clock_hns()?;
            // SAFETY: Initialize succeeded and the stream is not running.
            unsafe { self.client.Start()? };
            self.running = true;
            Ok(origin)
        }

        fn stop_capture(&mut self) -> Result<()> {
            if self.running {
                // SAFETY: this thread owns the running stream.
                unsafe { self.client.Stop()? };
                self.running = false;
            }
            Ok(())
        }

        fn record(
            &mut self,
            path: &Path,
            origin: i128,
            duration: Duration,
            stopping: Receiver<()>,
        ) -> Result<()> {
            let max_frames =
                usize::try_from(duration.as_nanos() * SAMPLE_RATE as u128 / 1_000_000_000)?;
            let deadline = origin + i128::try_from(duration.as_nanos() / 100)?;
            let mut timeline = PcmTimeline::new(max_frames);
            let mut anchor = None;
            loop {
                self.drain_packets(&mut timeline, &mut anchor, origin)?;
                let now = self.clock_hns()?;
                if now >= deadline {
                    break;
                }
                let until_deadline = Duration::from_nanos(u64::try_from((deadline - now) * 100)?);
                match stopping.recv_timeout(self.poll_interval.min(until_deadline)) {
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
            self.stop_capture()?;
            let ended = self.clock_hns()?.min(deadline);
            self.drain_packets(&mut timeline, &mut anchor, origin)?;
            let frames =
                usize::try_from((ended - origin).max(0) * SAMPLE_RATE as i128 / HNS_PER_SECOND)?;
            cua_driver_core::audio::write_pcm16_stereo_wav(path, &timeline.finish(frames))
        }

        fn drain_packets(
            &self,
            timeline: &mut PcmTimeline,
            anchor: &mut Option<(u64, i128)>,
            origin: i128,
        ) -> Result<()> {
            // SAFETY: GetBuffer/ReleaseBuffer pairs stay on this worker. No
            // borrowed native bytes survive ReleaseBuffer or a COM method call.
            unsafe {
                while self.packets.GetNextPacketSize()? != 0 {
                    let mut data = std::ptr::null_mut();
                    let (mut frames, mut flags, mut device_position, mut qpc) = (0, 0, 0, 0);
                    self.packets.GetBuffer(
                        &mut data,
                        &mut frames,
                        &mut flags,
                        Some(&mut device_position),
                        Some(&mut qpc),
                    )?;
                    if frames == 0 {
                        break;
                    }
                    let result = (|| {
                        anyhow::ensure!(
                            flags & AUDCLNT_BUFFERFLAGS_TIMESTAMP_ERROR.0 as u32 == 0,
                            "WASAPI returned an invalid audio timestamp"
                        );
                        anyhow::ensure!(
                            anchor.is_none()
                                || flags & AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY.0 as u32 == 0,
                            "WASAPI reported a capture discontinuity; audio frames may be missing"
                        );
                        let (first_position, first_frame) = *anchor.get_or_insert_with(|| {
                            (
                                device_position,
                                (i128::from(qpc) - origin) * SAMPLE_RATE as i128 / HNS_PER_SECOND,
                            )
                        });
                        let offset = device_position
                            .checked_sub(first_position)
                            .context("WASAPI device position moved backwards")?;
                        let position = first_frame + i128::from(offset);
                        let silent = flags & AUDCLNT_BUFFERFLAGS_SILENT.0 as u32 != 0;
                        anyhow::ensure!(
                            silent || !data.is_null(),
                            "WASAPI returned no packet data"
                        );
                        let bytes = if silent {
                            None
                        } else {
                            Some(std::slice::from_raw_parts(
                                data,
                                frames as usize * FRAME_BYTES,
                            ))
                        };
                        timeline.append(position, frames as usize, bytes);
                        Ok(())
                    })();
                    let released = self.packets.ReleaseBuffer(frames);
                    result?;
                    released?;
                }
                Ok(())
            }
        }
    }

    impl Drop for Capture {
        fn drop(&mut self) {
            if let Err(error) = self.stop_capture() {
                tracing::warn!(%error, "WASAPI stream stop failed during cleanup");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frames(values: &[i16]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.to_le_bytes().repeat(2))
            .collect()
    }

    #[test]
    fn keeps_device_clock_silence_gaps_and_does_not_duplicate_overlapping_packets() {
        let mut timeline = PcmTimeline::new(8);
        timeline.append(2, 2, Some(&frames(&[10, 20])));
        timeline.append(3, 3, Some(&frames(&[999, 30, 40])));
        timeline.append(7, 1, Some(&frames(&[50])));
        assert_eq!(timeline.finish(8), frames(&[0, 0, 10, 20, 30, 40, 0, 50]));
    }

    #[test]
    fn trims_packets_outside_the_recording_interval_and_keeps_silent_payloads() {
        let mut timeline = PcmTimeline::new(5);
        timeline.append(-2, 4, Some(&frames(&[10, 20, 30, 40])));
        timeline.append(2, 2, None);
        timeline.append(4, 4, Some(&frames(&[50, 60, 70, 80])));
        timeline.append(100, 2, Some(&frames(&[90, 100])));
        assert_eq!(timeline.finish(100), frames(&[30, 40, 0, 0, 50]));
    }

    #[test]
    fn an_all_silent_capture_keeps_its_native_clock_duration() {
        assert_eq!(PcmTimeline::new(12).finish(7), vec![0; 7 * FRAME_BYTES]);
    }
}
