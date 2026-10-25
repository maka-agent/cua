// SPDX-License-Identifier: MIT
//! System-audio loopback capture through the embedding process's ScreenCaptureKit grant.

#[cfg(target_os = "macos")]
pub use native::LoopbackAudioBackendFactory;

#[cfg(any(target_os = "macos", test))]
mod samples {
    #[derive(Clone, Copy)]
    pub(super) enum Format {
        Float32,
        Signed16,
    }

    impl Format {
        fn bytes(self) -> usize {
            match self {
                Self::Float32 => 4,
                Self::Signed16 => 2,
            }
        }

        fn sample(self, bytes: &[u8]) -> anyhow::Result<i16> {
            match self {
                Self::Signed16 => Ok(i16::from_le_bytes([bytes[0], bytes[1]])),
                Self::Float32 => {
                    let value = f32::from_le_bytes(bytes[..4].try_into().unwrap());
                    anyhow::ensure!(value.is_finite(), "audio contains a non-finite sample");
                    Ok((value * 32768.0).round().clamp(-32768.0, 32767.0) as i16)
                }
            }
        }
    }

    #[derive(Clone, Copy)]
    pub(super) enum Channels<'a> {
        Interleaved(&'a [u8]),
        Planar(&'a [u8], &'a [u8]),
    }

    /// Core Media owns the input buffers; copy only complete frames into the
    /// duration-limited recording before the callback relinquishes them.
    pub(super) fn append(
        output: &mut Vec<u8>,
        format: Format,
        channels: Channels<'_>,
        frames: usize,
        frame_limit: usize,
        start_frame: i128,
    ) -> anyhow::Result<()> {
        let sample_bytes = format.bytes();
        let channel_bytes = frames
            .checked_mul(sample_bytes)
            .ok_or_else(|| anyhow::anyhow!("audio buffer length overflow"))?;
        match channels {
            Channels::Interleaved(data) => {
                anyhow::ensure!(
                    data.len() >= channel_bytes.saturating_mul(2),
                    "incomplete interleaved stereo audio buffer"
                );
            }
            Channels::Planar(left, right) => {
                anyhow::ensure!(
                    left.len() >= channel_bytes && right.len() >= channel_bytes,
                    "incomplete planar stereo audio buffer"
                );
            }
        }
        let retained_start = start_frame.max((output.len() / 4) as i128).max(0);
        let skipped = (retained_start - start_frame).min(frames as i128) as usize;
        if skipped == frames {
            return Ok(());
        }
        output.resize(retained_start.min(frame_limit as i128) as usize * 4, 0);
        if retained_start >= frame_limit as i128 {
            return Ok(());
        }
        let retained_start = retained_start as usize;
        let count = (frames - skipped).min(frame_limit - retained_start);
        for frame in skipped..skipped + count {
            let (left, right) = match channels {
                Channels::Interleaved(data) => {
                    let offset = frame * sample_bytes * 2;
                    (&data[offset..], &data[offset + sample_bytes..])
                }
                Channels::Planar(left, right) => {
                    let offset = frame * sample_bytes;
                    (&left[offset..], &right[offset..])
                }
            };
            output.extend_from_slice(&format.sample(left)?.to_le_bytes());
            output.extend_from_slice(&format.sample(right)?.to_le_bytes());
        }
        Ok(())
    }

    pub(super) fn frame_position(origin: (i64, i32), time: (i64, i32)) -> anyhow::Result<i128> {
        anyhow::ensure!(
            origin.1 > 0 && time.1 > 0,
            "audio presentation timestamp has no positive timescale"
        );
        let numerator = (i128::from(time.0) * i128::from(origin.1)
            - i128::from(origin.0) * i128::from(time.1))
            * 24_000;
        let denominator = i128::from(origin.1) * i128::from(time.1);
        Ok(if numerator < 0 {
            -((-numerator + denominator / 2) / denominator)
        } else {
            (numerator + denominator / 2) / denominator
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn planar_float_audio_preserves_channels_and_saturates_pcm16() {
            let left: Vec<_> = [-1.0_f32, 0.5, 2.0]
                .into_iter()
                .flat_map(f32::to_le_bytes)
                .collect();
            let right: Vec<_> = [1.0_f32, -0.5, -2.0]
                .into_iter()
                .flat_map(f32::to_le_bytes)
                .collect();
            let mut pcm = Vec::new();
            append(
                &mut pcm,
                Format::Float32,
                Channels::Planar(&left, &right),
                3,
                3,
                0,
            )
            .unwrap();
            assert_eq!(
                pcm,
                [-32768_i16, 32767, 16384, -16384, 32767, -32768]
                    .into_iter()
                    .flat_map(i16::to_le_bytes)
                    .collect::<Vec<_>>()
            );
        }

        #[test]
        fn packed_pcm_keeps_exact_samples_and_respects_recording_duration() {
            let input: Vec<_> = [1_i16, -2, 3, -4, 5, -6]
                .into_iter()
                .flat_map(i16::to_le_bytes)
                .collect();
            let mut pcm = Vec::new();
            append(
                &mut pcm,
                Format::Signed16,
                Channels::Interleaved(&input),
                3,
                2,
                0,
            )
            .unwrap();
            append(
                &mut pcm,
                Format::Signed16,
                Channels::Interleaved(&input),
                3,
                2,
                3,
            )
            .unwrap();
            assert_eq!(pcm, input[..8]);
        }

        #[test]
        fn malformed_or_nonfinite_audio_is_not_reported_as_valid_capture() {
            let mut pcm = Vec::new();
            let error = append(
                &mut pcm,
                Format::Signed16,
                Channels::Interleaved(&[0, 1]),
                1,
                1,
                0,
            )
            .unwrap_err();
            assert_eq!(
                error.to_string(),
                "incomplete interleaved stereo audio buffer"
            );
            let nan = f32::NAN.to_le_bytes();
            let error = append(
                &mut pcm,
                Format::Float32,
                Channels::Planar(&nan, &nan),
                1,
                1,
                0,
            )
            .unwrap_err();
            assert_eq!(error.to_string(), "audio contains a non-finite sample");
        }

        #[test]
        fn presentation_gaps_are_silent_and_overlapping_frames_are_not_repeated() {
            let input: Vec<_> = [1_i16, -1, 2, -2]
                .into_iter()
                .flat_map(i16::to_le_bytes)
                .collect();
            let mut pcm = Vec::new();
            for start in [0, 4, 5] {
                append(
                    &mut pcm,
                    Format::Signed16,
                    Channels::Interleaved(&input),
                    2,
                    7,
                    start,
                )
                .unwrap();
            }
            assert_eq!(
                pcm,
                [1_i16, -1, 2, -2, 0, 0, 0, 0, 1, -1, 2, -2, 2, -2]
                    .into_iter()
                    .flat_map(i16::to_le_bytes)
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                frame_position((900_000_000, 1_000_000), (900_000_500, 1_000_000)).unwrap(),
                12
            );
            assert_eq!(frame_position((1, 1), (48_002, 48_000)).unwrap(), 1);
            assert_eq!(frame_position((1, 1), (47_998, 48_000)).unwrap(), -1);
            let mut clipped = input.clone();
            append(
                &mut clipped,
                Format::Signed16,
                Channels::Interleaved(&input),
                2,
                7,
                10,
            )
            .unwrap();
            let mut expected = input;
            expected.resize(7 * 4, 0);
            assert_eq!(clipped, expected);
        }
    }
}

#[cfg(target_os = "macos")]
mod native {
    use std::path::{Path, PathBuf};
    use std::sync::{mpsc, Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::Duration;

    use cua_driver_core::audio::{
        write_pcm16_stereo_wav, AudioBackend, AudioBackendFactory, AudioCompletion,
    };
    use screencapturekit::cm::{CMSampleBuffer, CMSampleBufferExt};
    use screencapturekit::prelude::{
        SCContentFilter, SCShareableContent, SCStream, SCStreamConfiguration, SCStreamOutputType,
    };
    use screencapturekit::stream::delegate_trait::StreamCallbacks;

    use super::samples::{self, Channels, Format};

    pub struct LoopbackAudioBackendFactory;

    impl AudioBackendFactory for LoopbackAudioBackendFactory {
        fn start(
            &self,
            output_path: &Path,
            max_duration: Duration,
        ) -> anyhow::Result<Box<dyn AudioBackend>> {
            let output_path = output_path.to_path_buf();
            let (stop, receiver) = mpsc::channel();
            let (started, readiness) = mpsc::sync_channel(1);
            let signal = stop.clone();
            let (completion, completed) = AudioCompletion::channel();
            let worker = std::thread::Builder::new()
                .name("cua-system-audio".into())
                .spawn(move || {
                    // capture returns only after stopping/dropping the native
                    // stream, closing callback admission, and writing the WAV.
                    let result = capture(output_path, max_duration, receiver, signal, started);
                    completed.finish(&result);
                    result
                })?;
            match readiness.recv() {
                Ok(Ok(())) => Ok(Box::new(SckitAudioBackend {
                    stop: Some(stop),
                    worker: Some(worker),
                    completion,
                })),
                Ok(Err(error)) => {
                    let _ = worker.join();
                    anyhow::bail!(error)
                }
                Err(_) => match worker.join() {
                    Ok(result) => {
                        result?;
                        anyhow::bail!("ScreenCaptureKit audio worker stopped before startup")
                    }
                    Err(_) => {
                        anyhow::bail!("ScreenCaptureKit audio worker panicked during startup")
                    }
                },
            }
        }
    }

    struct SckitAudioBackend {
        stop: Option<mpsc::Sender<()>>,
        worker: Option<JoinHandle<anyhow::Result<()>>>,
        completion: AudioCompletion,
    }

    impl SckitAudioBackend {
        fn finish(&mut self) -> anyhow::Result<()> {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            if let Some(worker) = self.worker.take() {
                return worker
                    .join()
                    .map_err(|_| anyhow::anyhow!("ScreenCaptureKit audio worker panicked"))?;
            }
            Ok(())
        }
    }

    impl AudioBackend for SckitAudioBackend {
        fn stop(mut self: Box<Self>) -> anyhow::Result<()> {
            self.finish()
        }

        fn completion(&self) -> anyhow::Result<AudioCompletion> {
            Ok(self.completion.clone())
        }
    }

    impl Drop for SckitAudioBackend {
        fn drop(&mut self) {
            let _ = self.finish();
        }
    }

    struct CapturedAudio {
        pcm: Vec<u8>,
        first_timestamp: Option<(i64, i32)>,
        error: Option<String>,
        accepting: bool,
    }

    fn capture(
        output_path: PathBuf,
        max_duration: Duration,
        stop: mpsc::Receiver<()>,
        signal: mpsc::Sender<()>,
        started: mpsc::SyncSender<Result<(), String>>,
    ) -> anyhow::Result<()> {
        let audio = Arc::new(Mutex::new(CapturedAudio {
            pcm: Vec::new(),
            first_timestamp: None,
            error: None,
            accepting: true,
        }));
        let stream = match prepare_stream(&audio, &signal, max_duration) {
            Ok(stream) => stream,
            Err(error) => {
                let _ = started.send(Err(error.to_string()));
                return Err(error);
            }
        };
        if started.send(Ok(())).is_err() {
            let _ = stream.stop_capture();
            anyhow::bail!("audio startup caller disconnected");
        }
        let _ = stop.recv_timeout(max_duration);
        let stopped = stream
            .stop_capture()
            .map_err(|error| anyhow::anyhow!("ScreenCaptureKit audio stop failed: {error}"));
        let (pcm, error) = {
            let mut audio = audio.lock().unwrap_or_else(|error| error.into_inner());
            audio.accepting = false;
            (std::mem::take(&mut audio.pcm), audio.error.take())
        };
        drop(stream);
        if let Some(error) = error {
            anyhow::bail!(error);
        }
        stopped?;
        write_pcm16_stereo_wav(&output_path, &pcm)
    }

    fn prepare_stream(
        audio: &Arc<Mutex<CapturedAudio>>,
        signal: &mpsc::Sender<()>,
        max_duration: Duration,
    ) -> anyhow::Result<SCStream> {
        let frame_limit = usize::try_from(max_duration.as_micros() * 24_000 / 1_000_000)?;
        let content = SCShareableContent::get()
            .map_err(|error| anyhow::anyhow!("ScreenCaptureKit audio discovery failed: {error}"))?;
        let display =
            content.displays().into_iter().next().ok_or_else(|| {
                anyhow::anyhow!("no display is available for system-audio capture")
            })?;
        let filter = SCContentFilter::create()
            .with_display(&display)
            .with_excluding_windows(&[])
            .build();
        let config = SCStreamConfiguration::new()
            .with_width(2)
            .with_height(2)
            .with_captures_audio(true)
            .with_sample_rate(24_000)
            .with_channel_count(2)
            .with_captures_microphone(false)
            .with_excludes_current_process_audio(false)
            .with_shows_cursor(false);
        let failures = audio.clone();
        let failed = signal.clone();
        let delegate = StreamCallbacks::new().on_error(move |error| {
            record_error(&failures, &failed, error.to_string());
        });
        let mut stream = SCStream::new_with_delegate(&filter, &config, delegate);
        let captured = audio.clone();
        let failed = signal.clone();
        anyhow::ensure!(
            stream
                .add_output_handler(
                    move |sample: CMSampleBuffer, output_type| {
                        if output_type != SCStreamOutputType::Audio {
                            return;
                        }
                        if let Err(error) = append_buffer(&captured, sample, frame_limit) {
                            record_error(&captured, &failed, error.to_string());
                        }
                    },
                    SCStreamOutputType::Audio,
                )
                .is_some(),
            "ScreenCaptureKit refused the system-audio output handler"
        );
        stream
            .start_capture()
            .map_err(|error| anyhow::anyhow!("ScreenCaptureKit audio start failed: {error}"))?;
        Ok(stream)
    }

    fn record_error(audio: &Mutex<CapturedAudio>, signal: &mpsc::Sender<()>, error: String) {
        let mut audio = audio.lock().unwrap_or_else(|error| error.into_inner());
        if audio.accepting {
            audio.error.get_or_insert(error);
            audio.accepting = false;
            let _ = signal.send(());
        }
    }

    fn append_buffer(
        audio: &Mutex<CapturedAudio>,
        sample: CMSampleBuffer,
        frame_limit: usize,
    ) -> anyhow::Result<()> {
        let mut audio = audio.lock().unwrap_or_else(|error| error.into_inner());
        if !audio.accepting {
            return Ok(());
        }
        let format = sample
            .format_description()
            .ok_or_else(|| anyhow::anyhow!("audio sample has no format description"))?;
        anyhow::ensure!(
            format.audio_sample_rate() == Some(24_000.0)
                && format.audio_channel_count() == Some(2)
                && !format.audio_is_big_endian(),
            "ScreenCaptureKit did not produce 24 kHz little-endian stereo audio"
        );
        let encoding = match (format.audio_is_float(), format.audio_bits_per_channel()) {
            (true, Some(32)) => Format::Float32,
            (false, Some(16))
                if format
                    .audio_format_flags()
                    .is_some_and(|flags| flags & 4 != 0) =>
            {
                Format::Signed16
            }
            _ => anyhow::bail!("unsupported ScreenCaptureKit audio sample format"),
        };
        let frames = usize::try_from(sample.num_samples())?;
        let buffers = sample
            .audio_buffer_list()
            .ok_or_else(|| anyhow::anyhow!("audio sample has no audio buffers"))?;
        let channels = match (buffers.num_buffers(), buffers.get(0), buffers.get(1)) {
            (1, Some(packed), None) if packed.number_channels == 2 => {
                Channels::Interleaved(packed.data())
            }
            (2, Some(left), Some(right))
                if left.number_channels == 1 && right.number_channels == 1 =>
            {
                Channels::Planar(left.data(), right.data())
            }
            _ => anyhow::bail!("unsupported ScreenCaptureKit stereo buffer layout"),
        };
        let time = sample.presentation_timestamp();
        anyhow::ensure!(
            time.is_valid()
                && !time.is_indefinite()
                && !time.is_positive_infinity()
                && !time.is_negative_infinity(),
            "audio sample has no numeric presentation timestamp"
        );
        let time = (time.value, time.timescale);
        let origin = *audio.first_timestamp.get_or_insert(time);
        let start_frame = samples::frame_position(origin, time)?;
        samples::append(
            &mut audio.pcm,
            encoding,
            channels,
            frames,
            frame_limit,
            start_frame,
        )
    }
}
