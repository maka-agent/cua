//! Public runtime facade for capture publication and capture-bound actions.
//!
//! [`CaptureService::publish`] retains the default one-shot, TTL-bound behavior.
//! Explicit window observations use [`CaptureService::publish_window_observation`]
//! and require a trusted current native window frame at action admission. Their
//! image bytes and records remain in the same bounded registry.

pub use crate::capture_registry::{
    admission_error_code, CaptureActionAdmission, CaptureActionError, CaptureActionRequest,
    CaptureBinding, CaptureDragAdmission, CaptureDragRequest, CaptureId, CaptureIdParseError,
    CaptureLookupError, CapturePublication, CaptureService, CaptureStoreError, CaptureTarget,
    EncodedScreenshotDimensions, NativeActionDimensions, PruneOutcome, ScreenshotCodec,
    ScreenshotToActionTransform, CAPTURE_ACTION_REFUSED_CODE, CAPTURE_ID_INVALID_CODE,
};
