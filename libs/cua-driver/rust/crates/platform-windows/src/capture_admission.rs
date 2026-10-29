use std::sync::Arc;

use cua_driver_core::capture_runtime::{
    CaptureActionError, CaptureActionRequest, CaptureDragRequest, CaptureLookupError,
    CapturePublication, CaptureService, CaptureTarget, EncodedScreenshotDimensions,
    NativeActionDimensions, ScreenshotCodec, ScreenshotToActionTransform,
};
use cua_driver_core::tool::NativeWindowFrame;
use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsCaptureTarget {
    Window { pid: u32, window_id: u64 },
    PrimaryDesktop,
}

impl WindowsCaptureTarget {
    fn core(self) -> CaptureTarget {
        match self {
            Self::Window { pid, window_id } => CaptureTarget::Window { pid, window_id },
            Self::PrimaryDesktop => CaptureTarget::PrimaryDesktop,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct CaptureGeometry {
    pub encoded_width: u32,
    pub encoded_height: u32,
    pub native_width: u32,
    pub native_height: u32,
}

impl CaptureGeometry {
    pub(crate) fn new(
        encoded_width: u32,
        encoded_height: u32,
        native_width: u32,
        native_height: u32,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            encoded_width > 0 && encoded_height > 0 && native_width > 0 && native_height > 0,
            "capture dimensions must be positive"
        );
        Ok(Self {
            encoded_width,
            encoded_height,
            native_width,
            native_height,
        })
    }
}

pub(crate) fn round_action_point(x: f64, y: f64) -> anyhow::Result<(i32, i32)> {
    fn round(value: f64) -> anyhow::Result<i32> {
        let rounded = value.round();
        anyhow::ensure!(
            rounded.is_finite() && rounded >= f64::from(i32::MIN) && rounded <= f64::from(i32::MAX),
            "capture action coordinate is outside the Windows pixel range"
        );
        Ok(rounded as i32)
    }
    Ok((round(x)?, round(y)?))
}

/// Capture admission already bounded the point to the actual image. A valid
/// image may include non-client pixels outside DWM's visible frame.
pub(crate) fn capture_screen_point(
    frame: NativeWindowFrame,
    x: i32,
    y: i32,
) -> anyhow::Result<(i32, i32)> {
    let [left, top, _, _] = frame.bounds();
    left.checked_add(x)
        .zip(top.checked_add(y))
        .ok_or_else(|| anyhow::anyhow!("capture screen point overflows Windows coordinates"))
}

pub(crate) struct WindowsCaptureBridge {
    service: Arc<CaptureService>,
}

impl WindowsCaptureBridge {
    pub(crate) fn new(service: Arc<CaptureService>) -> Arc<Self> {
        Arc::new(Self { service })
    }

    pub(crate) fn publish(
        &self,
        args: &Value,
        png_bytes: Vec<u8>,
        target: WindowsCaptureTarget,
        geometry: CaptureGeometry,
    ) -> anyhow::Result<Option<String>> {
        let binding = self.service.binding_from_args(args)?;
        let encoded_dimensions =
            EncodedScreenshotDimensions::new(geometry.encoded_width, geometry.encoded_height)?;
        let native_action_dimensions =
            NativeActionDimensions::new(geometry.native_width, geometry.native_height)?;
        let screenshot_to_action = ScreenshotToActionTransform::from_dimensions(
            encoded_dimensions,
            native_action_dimensions,
        );
        let capture_id = self.service.publish(CapturePublication {
            encoded_bytes: png_bytes,
            codec: ScreenshotCodec::Png,
            target: target.core(),
            encoded_dimensions,
            native_action_dimensions,
            screenshot_to_action,
            session_id: binding.session_id().into(),
            session_generation: binding.session_generation(),
        })?;
        Ok(Some(capture_id.to_string()))
    }

    /// Refresh only the raw observation records of this existing binding.
    /// The caller supplies geometry obtained from the actual native window.
    pub(crate) fn refresh_window_observation(
        &self,
        args: &Value,
        frame: NativeWindowFrame,
    ) -> anyhow::Result<()> {
        let binding = self.service.binding_from_args(args)?;
        self.service.refresh_window_observation(&binding, frame);
        Ok(())
    }

    pub(crate) fn retire_window_observations(&self, args: &Value) -> anyhow::Result<()> {
        let binding = self.service.binding_from_args(args)?;
        self.service.retire_window_observations(&binding);
        Ok(())
    }

    pub(crate) fn publish_window_observation(
        &self,
        args: &Value,
        png: Vec<u8>,
        target: WindowsCaptureTarget,
        geometry: CaptureGeometry,
        frame: NativeWindowFrame,
        image_bounds: Option<[i32; 4]>,
    ) -> anyhow::Result<Option<String>> {
        let binding = self.service.binding_from_args(args)?;
        let encoded =
            EncodedScreenshotDimensions::new(geometry.encoded_width, geometry.encoded_height)?;
        let image = NativeActionDimensions::new(geometry.native_width, geometry.native_height)?;
        let [left, top, width, height] = frame.bounds();
        let native = NativeActionDimensions::new(width as u32, height as u32)?;
        let transform = match image_bounds {
            Some([x, y, w, h]) => {
                anyhow::ensure!(
                    w > 0
                        && h > 0
                        && w as u32 == geometry.native_width
                        && h as u32 == geometry.native_height,
                    "capture image bounds disagree with its native pixels"
                );
                ScreenshotToActionTransform::from_cropped_dimensions(
                    encoded,
                    image,
                    [
                        x.checked_sub(left)
                            .ok_or_else(|| anyhow::anyhow!("capture x offset overflows"))?,
                        y.checked_sub(top)
                            .ok_or_else(|| anyhow::anyhow!("capture y offset overflows"))?,
                    ],
                )
            }
            None => ScreenshotToActionTransform::from_dimensions(encoded, image),
        };
        let publication = CapturePublication {
            encoded_bytes: png,
            codec: ScreenshotCodec::Png,
            target: target.core(),
            encoded_dimensions: encoded,
            native_action_dimensions: native,
            screenshot_to_action: transform,
            session_id: binding.session_id().into(),
            session_generation: binding.session_generation(),
        };
        // The image may still be returned and retained when its producer has
        // no origin. That record has no action or visual-grounding transform.
        let id = if image_bounds.is_some() {
            self.service
                .publish_window_observation(publication, frame)?
        } else {
            self.service
                .publish_window_observation_without_origin(publication, frame)?
        };
        Ok(Some(id.to_string()))
    }

    /// Inert expected-frame metadata for the same capture. Actual action
    /// admission and the final owned-worker check remain mandatory.
    pub(crate) fn action_frame(
        &self,
        args: &Value,
        target: WindowsCaptureTarget,
    ) -> anyhow::Result<Option<NativeWindowFrame>> {
        let Some(id) = args.get("capture_id").and_then(Value::as_str) else {
            return Ok(None);
        };
        let binding = self.service.binding_from_args(args)?;
        let id = id.parse()?;
        let mut capture = self
            .service
            .read_for_perception(id, &binding)
            .map_err(CaptureActionError::Lookup)?;
        // The old one-shot surface has no full-window-record obligation.
        // Only a real raw observation requires the stronger retained-frame
        // probe; never impose its visible/titled lookup on ordinary captures.
        if capture.window_observation_frame().is_some() {
            let WindowsCaptureTarget::Window { .. } = target else {
                return Err(CaptureActionError::Lookup(CaptureLookupError::TargetMismatch).into());
            };
            self.service
                .refresh_window_observation(&binding, live_window_frame(target)?);
            capture = self
                .service
                .read_for_perception(id, &binding)
                .map_err(CaptureActionError::Lookup)?;
        }
        if capture.target() != &target.core() {
            return Err(CaptureActionError::Lookup(CaptureLookupError::TargetMismatch).into());
        }
        Ok(capture.window_observation_frame())
    }

    pub(crate) fn admit_click(
        &self,
        args: &Value,
        target: WindowsCaptureTarget,
        screenshot_x: f64,
        screenshot_y: f64,
    ) -> anyhow::Result<Option<(f64, f64)>> {
        if args.get("capture_id").and_then(Value::as_str).is_none() {
            return Ok(None);
        }
        let frame = self.action_frame(args, target)?;
        let current_geometry = match frame {
            Some(frame) => {
                let [_, _, width, height] = frame.bounds();
                CaptureGeometry::new(width as u32, height as u32, width as u32, height as u32)?
            }
            None => live_geometry(target)?,
        };
        self.admit_click_with_frame(
            args,
            target,
            current_geometry,
            screenshot_x,
            screenshot_y,
            frame,
        )
    }

    pub(crate) fn admit_drag(
        &self,
        args: &Value,
        target: WindowsCaptureTarget,
        from: (f64, f64),
        to: (f64, f64),
    ) -> anyhow::Result<Option<[(f64, f64); 2]>> {
        if args.get("capture_id").and_then(Value::as_str).is_none() {
            return Ok(None);
        }
        let frame = self.action_frame(args, target)?;
        let current_geometry = match frame {
            Some(frame) => {
                let [_, _, width, height] = frame.bounds();
                CaptureGeometry::new(width as u32, height as u32, width as u32, height as u32)?
            }
            None => live_geometry(target)?,
        };
        self.admit_drag_with_frame(args, target, current_geometry, from, to, frame)
    }

    fn admit_drag_with_frame(
        &self,
        args: &Value,
        target: WindowsCaptureTarget,
        current_geometry: CaptureGeometry,
        from: (f64, f64),
        to: (f64, f64),
        frame: Option<NativeWindowFrame>,
    ) -> anyhow::Result<Option<[(f64, f64); 2]>> {
        let Some(capture_id) = args.get("capture_id").and_then(Value::as_str) else {
            return Ok(None);
        };
        let binding = self.service.binding_from_args(args)?;
        let request = CaptureDragRequest {
            from: CaptureActionRequest {
                capture_id: capture_id.parse()?,
                binding,
                target: target.core(),
                current_native_action_dimensions: NativeActionDimensions::new(
                    current_geometry.native_width,
                    current_geometry.native_height,
                )?,
                screenshot_x: from.0,
                screenshot_y: from.1,
            },
            to_x: to.0,
            to_y: to.1,
        };
        let admission = match frame {
            Some(frame) => {
                self.service
                    .refresh_window_observation(&request.from.binding, frame);
                self.service.admit_window_drag(request, frame)?
            }
            None => self.service.admit_drag(request)?,
        };
        Ok(Some([
            (admission.from.action_x, admission.from.action_y),
            (admission.action_to_x, admission.action_to_y),
        ]))
    }

    #[cfg(test)]
    fn admit_click_with_geometry(
        &self,
        args: &Value,
        target: WindowsCaptureTarget,
        geometry: CaptureGeometry,
        x: f64,
        y: f64,
    ) -> anyhow::Result<Option<(f64, f64)>> {
        self.admit_click_with_frame(args, target, geometry, x, y, None)
    }

    fn admit_click_with_frame(
        &self,
        args: &Value,
        target: WindowsCaptureTarget,
        current_geometry: CaptureGeometry,
        screenshot_x: f64,
        screenshot_y: f64,
        frame: Option<NativeWindowFrame>,
    ) -> anyhow::Result<Option<(f64, f64)>> {
        let Some(capture_id) = args.get("capture_id").and_then(Value::as_str) else {
            return Ok(None);
        };
        let binding = self.service.binding_from_args(args)?;
        let request = CaptureActionRequest {
            capture_id: capture_id.parse()?,
            binding,
            target: target.core(),
            current_native_action_dimensions: NativeActionDimensions::new(
                current_geometry.native_width,
                current_geometry.native_height,
            )?,
            screenshot_x,
            screenshot_y,
        };
        let admission = match frame {
            Some(frame) => {
                self.service
                    .refresh_window_observation(&request.binding, frame);
                self.service.admit_window_action(request, frame)?
            }
            None => self.service.admit_action(request)?,
        };
        Ok(Some((admission.action_x, admission.action_y)))
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn live_window_frame(target: WindowsCaptureTarget) -> anyhow::Result<NativeWindowFrame> {
    use windows::Win32::Foundation::{HWND, RECT};
    use windows::Win32::Graphics::Dwm::{DwmGetWindowAttribute, DWMWA_EXTENDED_FRAME_BOUNDS};
    use windows::Win32::UI::WindowsAndMessaging::{
        GetWindowRect, GetWindowThreadProcessId, IsWindow,
    };
    let WindowsCaptureTarget::Window { pid, window_id } = target else {
        anyhow::bail!("retained observation requires a native window");
    };
    let hwnd = HWND(window_id as usize as *mut std::ffi::c_void);
    let mut rect = RECT::default();
    // SAFETY: all pointers reference initialized local storage. The handle is
    // observed only; no message, activation, capture or native input is sent.
    unsafe {
        anyhow::ensure!(
            IsWindow(hwnd).as_bool(),
            "native window is no longer available"
        );
        let mut before = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut before));
        anyhow::ensure!(before == pid, "native window owner changed");
        if DwmGetWindowAttribute(
            hwnd,
            DWMWA_EXTENDED_FRAME_BOUNDS,
            &mut rect as *mut _ as *mut _,
            std::mem::size_of::<RECT>() as u32,
        )
        .is_err()
        {
            GetWindowRect(hwnd, &mut rect)?;
        }
        let mut after = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut after));
        anyhow::ensure!(
            after == pid && IsWindow(hwnd).as_bool(),
            "native window owner changed while reading bounds"
        );
    }
    let width = rect
        .right
        .checked_sub(rect.left)
        .ok_or_else(|| anyhow::anyhow!("native window width overflows"))?;
    let height = rect
        .bottom
        .checked_sub(rect.top)
        .ok_or_else(|| anyhow::anyhow!("native window height overflows"))?;
    NativeWindowFrame::try_new(pid, window_id, [rect.left, rect.top, width, height])
        .map_err(anyhow::Error::msg)
}
#[cfg(not(target_os = "windows"))]
fn live_window_frame(_target: WindowsCaptureTarget) -> anyhow::Result<NativeWindowFrame> {
    anyhow::bail!("live Windows frame validation is unavailable on this platform")
}

#[cfg(target_os = "windows")]
fn live_geometry(target: WindowsCaptureTarget) -> anyhow::Result<CaptureGeometry> {
    let png = match target {
        WindowsCaptureTarget::Window { pid, window_id } => {
            use windows::Win32::Foundation::HWND;
            use windows::Win32::UI::WindowsAndMessaging::{GetWindowThreadProcessId, IsWindow};
            let hwnd = HWND(window_id as usize as *mut std::ffi::c_void);
            anyhow::ensure!(
                unsafe { IsWindow(hwnd).as_bool() },
                "native window was replaced"
            );
            let mut owner_pid = 0_u32;
            unsafe { GetWindowThreadProcessId(hwnd, Some(&mut owner_pid)) };
            anyhow::ensure!(
                owner_pid == pid,
                "native window owner changed after capture"
            );
            crate::capture::screenshot_window_bytes(window_id)?
        }
        WindowsCaptureTarget::PrimaryDesktop => crate::capture::screenshot_display_bytes()?,
    };
    let (width, height) = crate::capture::png_dimensions_pub(&png)?;
    CaptureGeometry::new(width, height, width, height)
}

#[cfg(not(target_os = "windows"))]
fn live_geometry(_target: WindowsCaptureTarget) -> anyhow::Result<CaptureGeometry> {
    anyhow::bail!("live Windows capture validation is unavailable on this platform")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use cua_driver_core::capture_runtime::{admission_error_code, CaptureService};
    use serde_json::json;

    use super::{
        round_action_point, CaptureGeometry, EncodedScreenshotDimensions, NativeActionDimensions,
        ScreenshotToActionTransform, WindowsCaptureBridge, WindowsCaptureTarget,
    };

    fn png() -> Vec<u8> {
        cua_driver_core::image_utils::encode_rgba_to_png(&[10, 20, 30, 255], 1, 1).unwrap()
    }

    fn args() -> serde_json::Value {
        json!({
            "capture_id": "replaced-after-publication",
            "_session_id": "capture-test",
        })
    }

    fn publish(bridge: &WindowsCaptureBridge, target: WindowsCaptureTarget) -> String {
        let mut publication_args = args();
        publication_args
            .as_object_mut()
            .unwrap()
            .remove("capture_id");
        bridge
            .publish(
                &publication_args,
                png(),
                target,
                CaptureGeometry::new(1, 1, 1, 1).unwrap(),
            )
            .unwrap()
            .unwrap()
    }

    #[test]
    fn resized_capture_maps_each_axis_into_native_window_pixels() {
        let geometry = CaptureGeometry::new(800, 450, 1600, 900).unwrap();
        let transform = ScreenshotToActionTransform::from_dimensions(
            EncodedScreenshotDimensions::new(geometry.encoded_width, geometry.encoded_height)
                .unwrap(),
            NativeActionDimensions::new(geometry.native_width, geometry.native_height).unwrap(),
        );
        assert_eq!(transform.apply(100.0, 50.0), (200.0, 100.0));
    }

    #[test]
    fn non_uniform_dimensions_preserve_full_affine_scale() {
        let geometry = CaptureGeometry::new(640, 360, 1280, 1080).unwrap();
        let transform = ScreenshotToActionTransform::from_dimensions(
            EncodedScreenshotDimensions::new(geometry.encoded_width, geometry.encoded_height)
                .unwrap(),
            NativeActionDimensions::new(geometry.native_width, geometry.native_height).unwrap(),
        );
        assert_eq!(transform.apply(100.0, 50.0), (200.0, 150.0));
    }

    #[test]
    fn admitted_centers_round_once_at_native_dispatch_boundary() {
        assert_eq!(round_action_point(10.49, -20.49).unwrap(), (10, -20));
        assert_eq!(round_action_point(10.5, -20.5).unwrap(), (11, -21));
        assert!(round_action_point(f64::NAN, 0.0).is_err());
        assert!(round_action_point(f64::from(i32::MAX) + 1.0, 0.0).is_err());
    }

    #[test]
    fn target_mismatch_refuses_before_dispatch() {
        let bridge = WindowsCaptureBridge::new(Arc::new(CaptureService::default()));
        let capture_id = publish(
            &bridge,
            WindowsCaptureTarget::Window {
                pid: 7,
                window_id: 70,
            },
        );
        let mut request = args();
        request["capture_id"] = json!(capture_id);
        let admission = bridge.admit_click_with_geometry(
            &request,
            WindowsCaptureTarget::Window {
                pid: 7,
                window_id: 71,
            },
            CaptureGeometry::new(1, 1, 1, 1).unwrap(),
            0.0,
            0.0,
        );
        let mut dispatches = 0;
        if admission.is_ok() {
            dispatches += 1;
        }
        assert_eq!(
            admission_error_code(&admission.unwrap_err()),
            "capture_target_mismatch"
        );
        assert_eq!(dispatches, 0);
    }

    #[test]
    fn out_of_bounds_point_reports_the_shared_coordinate_code() {
        let bridge = WindowsCaptureBridge::new(Arc::new(CaptureService::default()));
        let target = WindowsCaptureTarget::PrimaryDesktop;
        let capture_id = publish(&bridge, target);
        let mut request = args();
        request["capture_id"] = json!(capture_id);
        let admission = bridge.admit_click_with_geometry(
            &request,
            target,
            CaptureGeometry::new(1, 1, 1, 1).unwrap(),
            5.0,
            0.0,
        );
        assert_eq!(
            admission_error_code(&admission.unwrap_err()),
            "capture_coordinate_invalid"
        );
    }

    #[test]
    fn retired_capture_refuses_before_dispatch() {
        let bridge = WindowsCaptureBridge::new(Arc::new(CaptureService::default()));
        let target = WindowsCaptureTarget::PrimaryDesktop;
        let capture_id = publish(&bridge, target);
        bridge.service.retire_session_id("capture-test");
        let mut request = args();
        request["capture_id"] = json!(capture_id);
        let admission = bridge.admit_click_with_geometry(
            &request,
            target,
            CaptureGeometry::new(1, 1, 1, 1).unwrap(),
            0.0,
            0.0,
        );
        let mut dispatches = 0;
        if admission.is_ok() {
            dispatches += 1;
        }
        assert_eq!(
            admission_error_code(&admission.unwrap_err()),
            "capture_not_found"
        );
        assert_eq!(dispatches, 0);
    }

    #[test]
    fn capture_publication_without_a_runtime_session_is_an_error() {
        let bridge = WindowsCaptureBridge::new(Arc::new(CaptureService::default()));
        let error = bridge
            .publish(
                &json!({}),
                png(),
                WindowsCaptureTarget::PrimaryDesktop,
                CaptureGeometry::new(1, 1, 1, 1).unwrap(),
            )
            .unwrap_err();
        assert_eq!(error.to_string(), "capture binding is invalid");
    }

    #[test]
    fn cross_session_capture_refuses_before_dispatch() {
        let bridge = WindowsCaptureBridge::new(Arc::new(CaptureService::default()));
        let target = WindowsCaptureTarget::PrimaryDesktop;
        let capture_id = publish(&bridge, target);
        let request = json!({
            "capture_id": capture_id,
            "_session_id": "another-session",
        });
        let admission = bridge.admit_click_with_geometry(
            &request,
            target,
            CaptureGeometry::new(1, 1, 1, 1).unwrap(),
            0.0,
            0.0,
        );
        assert_eq!(
            admission_error_code(&admission.unwrap_err()),
            "capture_generation_mismatch"
        );
    }

    #[test]
    fn live_resize_refuses_before_dispatch_without_consuming_capture() {
        let bridge = WindowsCaptureBridge::new(Arc::new(CaptureService::default()));
        let target = WindowsCaptureTarget::Window {
            pid: 7,
            window_id: 70,
        };
        let capture_id = publish(&bridge, target);
        let mut request = args();
        request["capture_id"] = json!(capture_id);
        let mut dispatches = 0;
        let refusal = bridge.admit_click_with_geometry(
            &request,
            target,
            CaptureGeometry::new(1, 1, 2, 1).unwrap(),
            0.25,
            0.25,
        );
        if refusal.is_ok() {
            dispatches += 1;
        }
        assert_eq!(dispatches, 0);
        assert_eq!(
            admission_error_code(&refusal.unwrap_err()),
            "capture_frame_mismatch"
        );
        assert_eq!(
            bridge
                .admit_click_with_geometry(
                    &request,
                    target,
                    CaptureGeometry::new(1, 1, 1, 1).unwrap(),
                    0.25,
                    0.25,
                )
                .unwrap(),
            Some((0.25, 0.25))
        );
    }

    #[test]
    fn ordinary_click_without_capture_id_skips_live_capture_validation() {
        let bridge = WindowsCaptureBridge::new(Arc::new(CaptureService::default()));
        let request = json!({"_session_id": "capture-test"});
        assert_eq!(
            bridge
                .admit_click(&request, WindowsCaptureTarget::PrimaryDesktop, 0.25, 0.25,)
                .unwrap(),
            None
        );
    }
}
