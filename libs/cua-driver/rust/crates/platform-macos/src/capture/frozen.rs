//! One host-prepared window capture, carried through normal tool admission.

use crate::geometry::NativeWindowGeometry;
use core_foundation::{
    base::{kCFAllocatorDefault, CFType, CFTypeRef, TCFType},
    data::{CFData, CFDataCreateMutable},
    dictionary::CFDictionary,
    number::CFNumber,
    string::{CFString, CFStringRef},
};
use cua_driver_core::capture_runtime::ScreenshotCodec;
use serde::Serialize;
use std::{cell::RefCell, ffi::c_void, future::Future};

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NativeScreenshotEncoding {
    Png,
    Jpeg { quality: Option<f64> },
}

impl NativeScreenshotEncoding {
    fn codec(self) -> ScreenshotCodec {
        match self {
            Self::Png => ScreenshotCodec::Png,
            Self::Jpeg { .. } => ScreenshotCodec::Jpeg,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct FrozenWindowCapture {
    geometry: NativeWindowGeometry,
    requested_image_size: [f64; 2],
    output_dimensions: [u32; 2],
    encoding: NativeScreenshotEncoding,
}

impl FrozenWindowCapture {
    /// Explicit original source defaults; remote configuration is unobserved.
    pub fn source_defaults(
        geometry: NativeWindowGeometry,
        requested_image_size: [f64; 2],
    ) -> anyhow::Result<Self> {
        let output_dimensions = [
            ceil_dimension(requested_image_size[0])?,
            ceil_dimension(requested_image_size[1])?,
        ];
        Ok(Self {
            geometry,
            requested_image_size,
            output_dimensions,
            encoding: NativeScreenshotEncoding::Jpeg { quality: Some(0.8) },
        })
    }

    pub fn geometry(&self) -> &NativeWindowGeometry {
        &self.geometry
    }

    pub(crate) fn capture(self) -> anyhow::Result<FrozenWindowScreenshot> {
        super::refuse_without_direct_capture_consent()?;
        // The Host owns the native work until it is Ready. A caller-visible
        // timeout cannot turn an outstanding SCK/ImageIO worker into settlement.
        super::start_native_capture_worker(super::native_capture_gate(), move || {
            self.capture_sck()
        })?
        .recv()
        .map_err(|_| anyhow::anyhow!("ScreenCaptureKit worker ended without a result"))?
    }

    fn capture_sck(self) -> anyhow::Result<FrozenWindowScreenshot> {
        use screencapturekit::{
            prelude::{SCContentFilter, SCShareableContent, SCStreamConfiguration},
            screenshot_manager::SCScreenshotManager,
        };

        let content = SCShareableContent::get()
            .map_err(|error| anyhow::anyhow!("ScreenCaptureKit content lookup failed: {error}"))?;
        let window = content
            .windows()
            .into_iter()
            .find(|window| window.window_id() == self.geometry.window_id)
            .ok_or_else(|| anyhow::anyhow!("window_id_not_found: {}", self.geometry.window_id))?;
        let owner = window.owning_application().map(|app| app.process_id());
        if owner != Some(self.geometry.pid) {
            anyhow::bail!("window_owner_pid_mismatch: prepared window owner changed");
        }
        let filter = SCContentFilter::create().with_window(&window).build();
        let config = SCStreamConfiguration::new()
            .with_width(self.output_dimensions[0])
            .with_height(self.output_dimensions[1])
            .with_shows_cursor(false)
            .with_ignores_shadows_single_window(true)
            .with_ignores_shadows_display(true)
            .with_should_be_opaque(true);
        let image = SCScreenshotManager::capture_image(&filter, &config)
            .map_err(|error| anyhow::anyhow!("prepared window capture failed: {error}"))?;
        let dimensions = [
            u32::try_from(image.width())?,
            u32::try_from(image.height())?,
        ];
        if dimensions.contains(&0) {
            anyhow::bail!("prepared capture returned an empty image");
        }
        let encoded_bytes = encode_image(&image, self.encoding)?;
        Ok(FrozenWindowScreenshot {
            codec: self.encoding.codec(),
            prepared: self,
            encoded_bytes,
            dimensions,
        })
    }
}

pub(crate) struct FrozenWindowScreenshot {
    pub prepared: FrozenWindowCapture,
    pub encoded_bytes: Vec<u8>,
    pub codec: ScreenshotCodec,
    pub dimensions: [u32; 2],
}

fn ceil_dimension(value: f64) -> anyhow::Result<u32> {
    let rounded = value.ceil();
    if !rounded.is_finite() || rounded < 1.0 || rounded > f64::from(u32::MAX) {
        anyhow::bail!("requested capture dimension does not fit the SCK setter: {value}");
    }
    Ok(rounded as u32)
}

tokio::task_local! {
    static PREPARED_CAPTURE: RefCell<Option<FrozenWindowCapture>>;
}

/// Rust-host request data only. This scope grants no authority; the future
/// must use the ordinary bound-session get_window_state operation.
#[doc(hidden)]
pub async fn with_frozen_window_capture<F: Future>(
    prepared: FrozenWindowCapture,
    operation: F,
) -> F::Output {
    PREPARED_CAPTURE
        .scope(RefCell::new(Some(prepared)), operation)
        .await
}

pub(crate) fn take_for_target(
    pid: i32,
    window_id: u32,
) -> anyhow::Result<Option<FrozenWindowCapture>> {
    let request = PREPARED_CAPTURE
        .try_with(|request| request.borrow_mut().take())
        .ok()
        .flatten();
    if request.as_ref().is_some_and(|request| {
        request.geometry.pid != pid || request.geometry.window_id != window_id
    }) {
        anyhow::bail!("prepared capture does not match the authorized window target");
    }
    Ok(request)
}

fn encode_image(
    image: &screencapturekit::screenshot_manager::CGImage,
    encoding: NativeScreenshotEncoding,
) -> anyhow::Result<Vec<u8>> {
    #[link(name = "ImageIO", kind = "framework")]
    unsafe extern "C" {
        static kCGImageDestinationLossyCompressionQuality: CFStringRef;
        fn CGImageDestinationCreateWithData(
            data: *mut c_void,
            image_type: CFStringRef,
            count: usize,
            options: CFTypeRef,
        ) -> CFTypeRef;
        fn CGImageDestinationAddImage(
            destination: CFTypeRef,
            image: *const c_void,
            properties: CFTypeRef,
        );
        fn CGImageDestinationFinalize(destination: CFTypeRef) -> bool;
    }

    let image_type = CFString::new(match encoding {
        NativeScreenshotEncoding::Png => "public.png",
        NativeScreenshotEncoding::Jpeg { .. } => "public.jpeg",
    });
    // SAFETY: CoreFoundation create-rule values are checked and owned by
    // wrappers; ImageIO borrows them and the retained CGImage for each call.
    unsafe {
        let mutable = CFDataCreateMutable(kCFAllocatorDefault, 0);
        if mutable.is_null() {
            anyhow::bail!("ImageIO output allocation failed");
        }
        let data = CFData::wrap_under_create_rule(mutable.cast());
        let destination = CGImageDestinationCreateWithData(
            mutable.cast(),
            image_type.as_concrete_TypeRef(),
            1,
            std::ptr::null(),
        );
        if destination.is_null() {
            anyhow::bail!("ImageIO screenshot encoder unavailable");
        }
        let destination = CFType::wrap_under_create_rule(destination);
        let properties = match encoding {
            NativeScreenshotEncoding::Jpeg {
                quality: Some(quality),
            } => Some(CFDictionary::from_CFType_pairs(&[(
                CFString::wrap_under_get_rule(kCGImageDestinationLossyCompressionQuality),
                CFNumber::from(quality),
            )])),
            NativeScreenshotEncoding::Png | NativeScreenshotEncoding::Jpeg { quality: None } => {
                None
            }
        };
        CGImageDestinationAddImage(
            destination.as_CFTypeRef(),
            image.as_ptr(),
            properties
                .as_ref()
                .map_or(std::ptr::null(), |properties| properties.as_CFTypeRef()),
        );
        if !CGImageDestinationFinalize(destination.as_CFTypeRef()) {
            anyhow::bail!("ImageIO screenshot encoding failed");
        }
        Ok(data.bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prepared() -> FrozenWindowCapture {
        FrozenWindowCapture::source_defaults(
            NativeWindowGeometry {
                window_id: 7,
                pid: 42,
                layer: 1,
                bounds: crate::windows::WindowBounds {
                    x: -10.5,
                    y: 20.25,
                    width: 100.25,
                    height: 80.125,
                },
                native_scale: 2.0,
            },
            [200.5, 160.25],
        )
        .unwrap()
    }

    #[test]
    fn prepared_capture_keeps_raw_geometry_separate_from_integer_output_and_codec() {
        let capture = prepared();
        assert_eq!(capture.geometry.bounds.x, -10.5);
        assert_eq!(capture.geometry.layer, 1);
        assert_eq!(capture.geometry.native_scale, 2.0);
        assert_eq!(capture.requested_image_size, [200.5, 160.25]);
        assert_eq!(capture.output_dimensions, [201, 161]);
        match capture.encoding {
            NativeScreenshotEncoding::Jpeg { quality } => assert_eq!(quality, Some(0.8)),
            NativeScreenshotEncoding::Png => panic!("source defaults select JPEG"),
        }
        assert_eq!(capture.encoding.codec().mime_type(), "image/jpeg");
    }

    #[tokio::test]
    async fn prepared_request_is_consumed_once_and_never_leaks_to_another_operation() {
        assert!(take_for_target(42, 7).unwrap().is_none());
        with_frozen_window_capture(prepared(), async {
            assert!(take_for_target(42, 7).unwrap().is_some());
            assert!(take_for_target(42, 7).unwrap().is_none());
        })
        .await;
        with_frozen_window_capture(prepared(), async {
            assert!(take_for_target(43, 7).is_err());
            assert!(take_for_target(42, 7).unwrap().is_none());
        })
        .await;
        assert!(take_for_target(42, 7).unwrap().is_none());
    }

    #[test]
    fn independent_ceil_preserves_fractional_requested_dimensions() {
        assert_eq!(ceil_dimension(200.5).unwrap(), 201);
        assert_eq!(ceil_dimension(160.25).unwrap(), 161);
        assert_eq!(ceil_dimension(1.0).unwrap(), 1);
        for invalid in [0.0, f64::NAN, f64::INFINITY, f64::from(u32::MAX) + 1.0] {
            assert!(ceil_dimension(invalid).is_err());
        }
    }
}
