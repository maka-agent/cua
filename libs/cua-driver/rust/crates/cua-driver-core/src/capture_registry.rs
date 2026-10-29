//! Bounded, immutable screenshot storage for later coordinate-bound actions.
//!
//! This registry deliberately does not store accessibility elements or mirror
//! the element cache. A later integration with the snapshot-owned transforms
//! from #3630 should keep the snapshot as the authority for element tokens and
//! screenshot freshness. At capture publication, compose the snapshot's
//! delivered-image-to-native transform with any native-to-action transform and
//! store that single screenshot-to-action transform here. Retire the capture
//! when the owning snapshot, session, or runtime generation is retired.
//!
//! The registry grants no screenshot or action permission. Callers must pass
//! already-authorized image bytes and must independently authorize every action.
//! In particular, this foundation is not wired into platform adapters, action
//! dispatch, session hooks, or permission checks. That P1 integration remains
//! required before a capture ID can authorize or drive any production action.
//! Target-specific bounds and coordinate semantics must be revalidated there.
//!
//! Ordinary captures are consumed once and expire by TTL. Explicit window
//! observations instead remain reusable until snapshot replacement, real frame
//! invalidation, owner retirement or bounded storage eviction. They require a
//! trusted current full window frame at every action admission.
//!
//! TTL cleanup is bounded and lazy: [`CaptureService::prune_expired`] scans at
//! most `max_captures` entries and drops expired image references. An eventual
//! runtime owner must call it from its maintenance/metrics path if no store or
//! lookup traffic is occurring.

use crate::tool::NativeWindowFrame;
use image::{ImageDecoder, Limits};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::io::Cursor;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;
use uuid::Uuid;

pub(crate) const DEFAULT_MAX_CAPTURE_BYTES: usize = 64 * 1024 * 1024;

/// The producer's actual encoded image format, independent of facade labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScreenshotCodec {
    Png,
    Jpeg,
}

impl ScreenshotCodec {
    pub fn mime_type(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
        }
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct CaptureId {
    namespace: [u8; 16],
    sequence: u64,
}

impl fmt::Debug for CaptureId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CaptureId(")?;
        fmt::Display::fmt(self, formatter)?;
        formatter.write_str(")")
    }
}

impl fmt::Display for CaptureId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("capture_")?;
        for byte in self.namespace {
            write!(formatter, "{byte:02x}")?;
        }
        write!(formatter, "_{:016x}", self.sequence)
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum CaptureIdParseError {
    #[error("capture id has an invalid format")]
    InvalidFormat,
}

impl FromStr for CaptureId {
    type Err = CaptureIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value
            .strip_prefix("capture_")
            .ok_or(CaptureIdParseError::InvalidFormat)?;
        let (namespace, sequence) = value
            .split_once('_')
            .ok_or(CaptureIdParseError::InvalidFormat)?;
        if namespace.len() != 32 || sequence.len() != 16 {
            return Err(CaptureIdParseError::InvalidFormat);
        }
        let mut namespace_bytes = [0_u8; 16];
        for (index, byte) in namespace_bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&namespace[index * 2..index * 2 + 2], 16)
                .map_err(|_| CaptureIdParseError::InvalidFormat)?;
        }
        let sequence =
            u64::from_str_radix(sequence, 16).map_err(|_| CaptureIdParseError::InvalidFormat)?;
        Ok(Self {
            namespace: namespace_bytes,
            sequence,
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ContentDigest([u8; 32]);

impl ContentDigest {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn hex(&self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

impl fmt::Debug for ContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("sha256:")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum CaptureTarget {
    Window { pid: u32, window_id: u64 },
    PrimaryDesktop,
}

impl CaptureTarget {
    fn validate(&self) -> Result<(), CaptureStoreError> {
        match self {
            Self::Window { pid, window_id } if *pid == 0 || *window_id == 0 => {
                Err(CaptureStoreError::InvalidTarget)
            }
            Self::Window { .. } | Self::PrimaryDesktop => Ok(()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodedScreenshotDimensions {
    width: u32,
    height: u32,
}

impl EncodedScreenshotDimensions {
    pub fn new(width: u32, height: u32) -> Result<Self, CaptureStoreError> {
        if width == 0 || height == 0 {
            return Err(CaptureStoreError::InvalidEncodedDimensions);
        }
        Ok(Self { width, height })
    }

    pub fn width(self) -> u32 {
        self.width
    }

    pub fn height(self) -> u32 {
        self.height
    }
}

/// Dimensions of the full-resolution native frame used by action coordinates.
///
/// These may differ from [`EncodedScreenshotDimensions`] when a screenshot is
/// downscaled. They are metadata for later integration; this inert registry
/// does not claim that the action frame matches the target's current bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeActionDimensions {
    width: u32,
    height: u32,
}

impl NativeActionDimensions {
    pub fn new(width: u32, height: u32) -> Result<Self, CaptureStoreError> {
        if width == 0 || height == 0 {
            return Err(CaptureStoreError::InvalidNativeActionDimensions);
        }
        Ok(Self { width, height })
    }

    pub fn width(self) -> u32 {
        self.width
    }

    pub fn height(self) -> u32 {
        self.height
    }
}

/// Mapping from screenshot pixels to action coordinates.
///
/// [`Self::new`] preserves continuous affine behavior:
/// `((m11*x) + (m12*y) + tx, (m21*x) + (m22*y) + ty)`.
/// [`Self::from_dimensions`] additionally preserves its explicit integer
/// rectangle mapping for integral points within the encoded image.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ScreenshotToActionTransform {
    m11: f64,
    m12: f64,
    m21: f64,
    m22: f64,
    tx: f64,
    ty: f64,
    rectangle: Option<RectangleRatio>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RectangleRatio {
    offset: [i32; 2],
    encoded: EncodedScreenshotDimensions,
    native: NativeActionDimensions,
}

impl RectangleRatio {
    fn apply_integral(self, x: f64, y: f64) -> Option<(f64, f64)> {
        let bounded_integer = |value: f64, extent: u32| {
            value.is_finite() && value.fract() == 0.0 && value >= 0.0 && value < f64::from(extent)
        };
        if !bounded_integer(x, self.encoded.width) || !bounded_integer(y, self.encoded.height) {
            return None;
        }
        // Each factor fits u32, so the u64 product and resulting integer are
        // exact. Checked operations keep that boundary explicit.
        let scale = |point: f64, native: u32, encoded: u32| {
            (point as u64)
                .checked_mul(u64::from(native))?
                .checked_div(u64::from(encoded))
                .map(|mapped| mapped as f64)
        };
        Some((
            scale(x, self.native.width, self.encoded.width)? + f64::from(self.offset[0]),
            scale(y, self.native.height, self.encoded.height)? + f64::from(self.offset[1]),
        ))
    }
}

impl ScreenshotToActionTransform {
    pub fn new(
        m11: f64,
        m12: f64,
        m21: f64,
        m22: f64,
        tx: f64,
        ty: f64,
    ) -> Result<Self, CaptureStoreError> {
        let values = [m11, m12, m21, m22, tx, ty];
        let determinant = m11.mul_add(m22, -(m12 * m21));
        if values.iter().any(|value| !value.is_finite())
            || !determinant.is_finite()
            || determinant.abs() <= f64::EPSILON
        {
            return Err(CaptureStoreError::InvalidTransform);
        }
        Ok(Self {
            m11,
            m12,
            m21,
            m22,
            tx,
            ty,
            rectangle: None,
        })
    }

    /// Construct a zero-origin rectangle mapping from actual image extents.
    ///
    /// Both dimension types already require nonzero extents. Integral points
    /// inside the image use exact integer multiplication/division, truncated
    /// toward zero. If either coordinate is fractional or outside the image,
    /// `apply` retains the continuous ratio mapping; this constructor grants no
    /// action admission. Arbitrary affine coefficients are never recognized as
    /// rectangle provenance by inspection.
    pub fn from_dimensions(
        encoded: EncodedScreenshotDimensions,
        native: NativeActionDimensions,
    ) -> Self {
        Self {
            m11: f64::from(native.width) / f64::from(encoded.width),
            m12: 0.0,
            m21: 0.0,
            m22: f64::from(native.height) / f64::from(encoded.height),
            tx: 0.0,
            ty: 0.0,
            rectangle: Some(RectangleRatio {
                encoded,
                native,
                offset: [0, 0],
            }),
        }
    }

    /// Map a real cropped native image into its full window frame. Integer
    /// image points retain rectangle-ratio truncation before the crop offset.
    pub fn from_cropped_dimensions(
        encoded: EncodedScreenshotDimensions,
        image: NativeActionDimensions,
        offset: [i32; 2],
    ) -> Self {
        let mut transform = Self::from_dimensions(encoded, image);
        transform.tx = f64::from(offset[0]);
        transform.ty = f64::from(offset[1]);
        transform.rectangle = Some(RectangleRatio {
            encoded,
            native: image,
            offset,
        });
        transform
    }

    pub fn identity() -> Self {
        Self {
            m11: 1.0,
            m12: 0.0,
            m21: 0.0,
            m22: 1.0,
            tx: 0.0,
            ty: 0.0,
            rectangle: None,
        }
    }

    pub fn apply(self, x: f64, y: f64) -> (f64, f64) {
        if let Some(mapped) = self.rectangle.and_then(|ratio| ratio.apply_integral(x, y)) {
            return mapped;
        }
        (
            self.m11.mul_add(x, self.m12.mul_add(y, self.tx)),
            self.m21.mul_add(x, self.m22.mul_add(y, self.ty)),
        )
    }

    pub fn coefficients(self) -> [f64; 6] {
        [self.m11, self.m12, self.m21, self.m22, self.tx, self.ty]
    }

    fn validate_extent(
        self,
        dimensions: EncodedScreenshotDimensions,
    ) -> Result<(), CaptureStoreError> {
        let max_x = f64::from(dimensions.width.saturating_sub(1));
        let max_y = f64::from(dimensions.height.saturating_sub(1));
        for (x, y) in [(0.0, 0.0), (max_x, 0.0), (0.0, max_y), (max_x, max_y)] {
            let (action_x, action_y) = self.apply(x, y);
            if !action_x.is_finite() || !action_y.is_finite() {
                return Err(CaptureStoreError::InvalidTransformExtent);
            }
        }
        Ok(())
    }

    /// Compose affine coefficients, applying `self` first and `next` second.
    ///
    /// The result is a continuous affine transform. Explicit rectangle
    /// provenance and its native integer quantization are not inferred through
    /// arbitrary affine composition.
    pub fn then(self, next: Self) -> Result<Self, CaptureStoreError> {
        Self::new(
            next.m11.mul_add(self.m11, next.m12 * self.m21),
            next.m11.mul_add(self.m12, next.m12 * self.m22),
            next.m21.mul_add(self.m11, next.m22 * self.m21),
            next.m21.mul_add(self.m12, next.m22 * self.m22),
            next.m11
                .mul_add(self.tx, next.m12.mul_add(self.ty, next.tx)),
            next.m21
                .mul_add(self.tx, next.m22.mul_add(self.ty, next.ty)),
        )
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct CaptureBinding {
    runtime_generation: u64,
    session_id: Arc<str>,
    session_generation: u64,
}

impl fmt::Debug for CaptureBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CaptureBinding")
            .field("runtime_generation", &self.runtime_generation)
            .field("session_id", &"[redacted]")
            .field("session_generation", &self.session_generation)
            .finish()
    }
}

impl CaptureBinding {
    pub fn new(
        runtime_generation: u64,
        session_id: impl Into<Arc<str>>,
        session_generation: u64,
    ) -> Result<Self, CaptureStoreError> {
        let session_id = session_id.into();
        if runtime_generation == 0 || session_generation == 0 || session_id.trim().is_empty() {
            return Err(CaptureStoreError::InvalidBinding);
        }
        Ok(Self {
            runtime_generation,
            session_id,
            session_generation,
        })
    }

    pub fn runtime_generation(&self) -> u64 {
        self.runtime_generation
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn session_generation(&self) -> u64 {
        self.session_generation
    }
}

pub trait MonotonicClock: Send + Sync + 'static {
    fn now(&self) -> Duration;
}

#[derive(Debug)]
pub struct SystemMonotonicClock {
    origin: Instant,
}

impl SystemMonotonicClock {
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemMonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock for SystemMonotonicClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureRegistryConfig {
    pub max_captures: usize,
    pub max_total_bytes: usize,
    pub max_encoded_width: u32,
    pub max_encoded_height: u32,
    pub max_decoded_bytes: u64,
    pub ttl: Duration,
}

impl CaptureRegistryConfig {
    fn validate(self) -> Result<Self, CaptureStoreError> {
        if self.max_captures == 0
            || self.max_total_bytes == 0
            || self.max_encoded_width == 0
            || self.max_encoded_height == 0
            || self.max_decoded_bytes == 0
            || self.ttl.is_zero()
        {
            return Err(CaptureStoreError::InvalidConfig);
        }
        Ok(self)
    }
}

impl Default for CaptureRegistryConfig {
    fn default() -> Self {
        Self {
            max_captures: 32,
            max_total_bytes: DEFAULT_MAX_CAPTURE_BYTES,
            max_encoded_width: 16_384,
            max_encoded_height: 16_384,
            max_decoded_bytes: 512 * 1024 * 1024,
            ttl: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CaptureStoreError {
    #[error("capture registry limits and ttl must be non-zero")]
    InvalidConfig,
    #[error("capture binding is invalid")]
    InvalidBinding,
    #[error("capture target is invalid")]
    InvalidTarget,
    #[error("encoded screenshot dimensions are invalid or do not match the image")]
    InvalidEncodedDimensions,
    #[error("native action dimensions are invalid")]
    InvalidNativeActionDimensions,
    #[error("screenshot-to-action transform is invalid")]
    InvalidTransform,
    #[error("screenshot-to-action transform is not finite across the encoded image extent")]
    InvalidTransformExtent,
    #[error("capture bytes are not a valid image in the declared codec")]
    InvalidEncodedImage,
    #[error("image dimensions or decoded allocation exceed registry limits")]
    DecodeLimitExceeded,
    #[error("capture exceeds the registry byte limit")]
    CaptureTooLarge,
    #[error("capture id space is exhausted")]
    IdExhausted,
    #[error("capture expiry cannot be represented")]
    ExpiryOverflow,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum CaptureLookupError {
    #[error("capture id is unknown")]
    Unknown,
    #[error("capture has expired")]
    Expired,
    #[error("capture belongs to another runtime or session generation")]
    GenerationMismatch,
    #[error("capture belongs to another target")]
    TargetMismatch,
    #[error("window observation requires the trusted current native window frame")]
    WindowFrameRequired,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PruneOutcome {
    pub captures_removed: usize,
    pub encoded_bytes_released: usize,
}

struct CaptureRegistration {
    encoded_bytes: Vec<u8>,
    codec: ScreenshotCodec,
    target: CaptureTarget,
    encoded_dimensions: EncodedScreenshotDimensions,
    native_action_dimensions: NativeActionDimensions,
    screenshot_to_action: ScreenshotToActionTransform,
    binding: CaptureBinding,
}

pub struct CapturePublication {
    pub encoded_bytes: Vec<u8>,
    pub codec: ScreenshotCodec,
    pub target: CaptureTarget,
    pub encoded_dimensions: EncodedScreenshotDimensions,
    pub native_action_dimensions: NativeActionDimensions,
    pub screenshot_to_action: ScreenshotToActionTransform,
    pub session_id: Arc<str>,
    pub session_generation: u64,
}

pub struct CaptureActionRequest {
    pub capture_id: CaptureId,
    pub binding: CaptureBinding,
    /// Target identity observed immediately before native dispatch.
    pub target: CaptureTarget,
    /// Native action frame observed immediately before native dispatch.
    pub current_native_action_dimensions: NativeActionDimensions,
    pub screenshot_x: f64,
    pub screenshot_y: f64,
}

#[derive(Debug)]
pub struct CaptureActionAdmission {
    pub capture_id: CaptureId,
    pub target: CaptureTarget,
    pub action_x: f64,
    pub action_y: f64,
    pub native_action_dimensions: NativeActionDimensions,
    pub digest: ContentDigest,
}

/// Two endpoints admitted together against one immutable capture.
///
/// The `from` request supplies the shared capture, binding, target and live
/// frame. Both screenshot points must pass before admission. Ordinary captures
/// are consumed once; window observations remain reusable with an exact frame.
pub struct CaptureDragRequest {
    pub from: CaptureActionRequest,
    pub to_x: f64,
    pub to_y: f64,
}

#[derive(Debug)]
pub struct CaptureDragAdmission {
    pub from: CaptureActionAdmission,
    /// Actual delivered-image extents from the same admitted capture.
    /// Adapters with a proven axis-aligned rectangle mapping may use these
    /// integer extents without inferring a rectangle from arbitrary affine data.
    pub encoded_dimensions: EncodedScreenshotDimensions,
    pub action_to_x: f64,
    pub action_to_y: f64,
}

#[derive(Clone, Copy, Debug, Error, PartialEq)]
pub enum CaptureActionError {
    #[error(transparent)]
    Lookup(#[from] CaptureLookupError),
    #[error("screenshot point must be finite and within the encoded capture")]
    InvalidScreenshotPoint,
    #[error("mapped action point is not finite")]
    InvalidMappedPoint,
    #[error("capture native action frame no longer matches the live target")]
    NativeActionFrameMismatch,
    #[error("capture producer did not report a native image origin")]
    NativeActionMappingUnavailable,
}

/// Wire code for a capture ID that does not parse.
pub const CAPTURE_ID_INVALID_CODE: &str = "capture_id_invalid";

/// Wire code for a capture-bound action refusal with no more specific cause.
pub const CAPTURE_ACTION_REFUSED_CODE: &str = "capture_action_refused";

impl CaptureIdParseError {
    /// Stable structured `code` reported by every platform adapter.
    pub const fn wire_code(&self) -> &'static str {
        CAPTURE_ID_INVALID_CODE
    }
}

impl CaptureLookupError {
    /// Stable structured `code` reported by every platform adapter.
    pub const fn wire_code(&self) -> &'static str {
        match self {
            Self::Unknown => "capture_not_found",
            Self::Expired => "capture_expired",
            Self::GenerationMismatch => "capture_generation_mismatch",
            Self::TargetMismatch => "capture_target_mismatch",
            Self::WindowFrameRequired => "capture_frame_required",
        }
    }
}

impl CaptureActionError {
    /// Stable structured `code` reported by every platform adapter when
    /// capture-bound action admission refuses. Adapters must not remap it.
    pub const fn wire_code(&self) -> &'static str {
        match self {
            Self::Lookup(lookup) => lookup.wire_code(),
            Self::InvalidScreenshotPoint | Self::InvalidMappedPoint => "capture_coordinate_invalid",
            Self::NativeActionFrameMismatch => "capture_frame_mismatch",
            Self::NativeActionMappingUnavailable => CAPTURE_ACTION_REFUSED_CODE,
        }
    }
}

/// Maps an adapter's admission failure to its shared wire code. Parse and
/// admission errors keep their core code; any other failure is a generic
/// capture-bound action refusal.
pub fn admission_error_code(error: &anyhow::Error) -> &'static str {
    if let Some(parse) = error.downcast_ref::<CaptureIdParseError>() {
        return parse.wire_code();
    }
    error
        .downcast_ref::<CaptureActionError>()
        .map_or(CAPTURE_ACTION_REFUSED_CODE, CaptureActionError::wire_code)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaptureLifetime {
    OneShot,
    WindowObservation(NativeWindowFrame),
    UnmappedWindowObservation(NativeWindowFrame),
}

impl CaptureLifetime {
    fn is_window_observation(self) -> bool {
        matches!(
            self,
            Self::WindowObservation(_) | Self::UnmappedWindowObservation(_)
        )
    }
}

#[derive(Clone)]
struct StoredCapture {
    id: CaptureId,
    encoded_bytes: Arc<[u8]>,
    codec: ScreenshotCodec,
    digest: ContentDigest,
    target: CaptureTarget,
    encoded_dimensions: EncodedScreenshotDimensions,
    native_action_dimensions: NativeActionDimensions,
    screenshot_to_action: Option<ScreenshotToActionTransform>,
    binding: CaptureBinding,
    lifetime: CaptureLifetime,
    created_at: Duration,
    expires_at: Option<Duration>,
}

impl fmt::Debug for StoredCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredCapture")
            .field("id", &self.id)
            .field("byte_len", &self.encoded_bytes.len())
            .field("codec", &self.codec)
            .field("digest", &self.digest)
            .field("target", &self.target)
            .field("encoded_dimensions", &self.encoded_dimensions)
            .field("native_action_dimensions", &self.native_action_dimensions)
            .field("screenshot_to_action", &self.screenshot_to_action)
            .field("binding", &self.binding)
            .field("lifetime", &self.lifetime)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct PerceptionCapture(StoredCapture);

impl PerceptionCapture {
    pub fn id(&self) -> CaptureId {
        self.0.id
    }

    pub fn encoded_bytes(&self) -> Arc<[u8]> {
        self.0.encoded_bytes.clone()
    }

    pub fn codec(&self) -> ScreenshotCodec {
        self.0.codec
    }

    pub fn digest(&self) -> ContentDigest {
        self.0.digest
    }

    pub fn target(&self) -> &CaptureTarget {
        &self.0.target
    }

    pub fn encoded_dimensions(&self) -> EncodedScreenshotDimensions {
        self.0.encoded_dimensions
    }

    /// Inert full-frame metadata of a retained window observation. This is not
    /// an action admission or proof that the frame still describes a live window.
    pub fn window_observation_frame(&self) -> Option<NativeWindowFrame> {
        match self.0.lifetime {
            CaptureLifetime::OneShot => None,
            CaptureLifetime::WindowObservation(frame)
            | CaptureLifetime::UnmappedWindowObservation(frame) => Some(frame),
        }
    }

    pub(crate) fn screenshot_to_action(&self) -> Option<ScreenshotToActionTransform> {
        self.0.screenshot_to_action
    }

    pub fn created_at(&self) -> Duration {
        self.0.created_at
    }

    /// Ordinary captures have a TTL; window observations have no time expiry.
    pub fn expires_at(&self) -> Option<Duration> {
        self.0.expires_at
    }
}

struct RegistryInner {
    captures: HashMap<CaptureId, StoredCapture>,
    insertion_order: VecDeque<CaptureId>,
    expired_ids: HashSet<CaptureId>,
    expired_order: VecDeque<CaptureId>,
    total_bytes: usize,
    next_sequence: u64,
}

struct CaptureRegistry {
    config: CaptureRegistryConfig,
    clock: Arc<dyn MonotonicClock>,
    namespace: [u8; 16],
    inner: Mutex<RegistryInner>,
}

impl CaptureRegistry {
    fn with_clock(
        config: CaptureRegistryConfig,
        clock: Arc<dyn MonotonicClock>,
    ) -> Result<Self, CaptureStoreError> {
        let config = config.validate()?;
        Ok(Self {
            config,
            clock,
            namespace: *Uuid::new_v4().as_bytes(),
            inner: Mutex::new(RegistryInner {
                captures: HashMap::new(),
                insertion_order: VecDeque::new(),
                expired_ids: HashSet::new(),
                expired_order: VecDeque::new(),
                total_bytes: 0,
                next_sequence: 0,
            }),
        })
    }

    fn store(&self, registration: CaptureRegistration) -> Result<CaptureId, CaptureStoreError> {
        self.store_with_lifetime(registration, CaptureLifetime::OneShot)
    }

    fn store_window_observation(
        &self,
        registration: CaptureRegistration,
        frame: NativeWindowFrame,
    ) -> Result<CaptureId, CaptureStoreError> {
        if registration.target
            != (CaptureTarget::Window {
                pid: frame.pid(),
                window_id: frame.window_id(),
            })
        {
            return Err(CaptureStoreError::InvalidTarget);
        }
        self.store_with_lifetime(registration, CaptureLifetime::WindowObservation(frame))
    }

    fn store_with_lifetime(
        &self,
        registration: CaptureRegistration,
        lifetime: CaptureLifetime,
    ) -> Result<CaptureId, CaptureStoreError> {
        registration.target.validate()?;
        if registration.encoded_bytes.len() > self.config.max_total_bytes {
            return Err(CaptureStoreError::CaptureTooLarge);
        }
        let mut limits = Limits::default();
        limits.max_image_width = Some(self.config.max_encoded_width);
        limits.max_image_height = Some(self.config.max_encoded_height);
        limits.max_alloc = Some(self.config.max_decoded_bytes);
        match registration.codec {
            ScreenshotCodec::Png => {
                let decoder = image::codecs::png::PngDecoder::with_limits(
                    Cursor::new(&registration.encoded_bytes),
                    limits,
                )
                .map_err(map_image_admission_error)?;
                validate_capture_decoder(decoder, &registration, self.config.max_decoded_bytes)?;
            }
            ScreenshotCodec::Jpeg => {
                let mut decoder =
                    image::codecs::jpeg::JpegDecoder::new(Cursor::new(&registration.encoded_bytes))
                        .map_err(map_image_admission_error)?;
                decoder
                    .set_limits(limits)
                    .map_err(map_image_admission_error)?;
                validate_capture_decoder(decoder, &registration, self.config.max_decoded_bytes)?;
            }
        }
        let encoded_bytes: Arc<[u8]> = registration.encoded_bytes.into();
        let byte_len = encoded_bytes.len();
        let digest = ContentDigest(Sha256::digest(&encoded_bytes).into());
        let created_at = self.clock.now();
        let expires_at = match lifetime {
            CaptureLifetime::OneShot => Some(
                created_at
                    .checked_add(self.config.ttl)
                    .ok_or(CaptureStoreError::ExpiryOverflow)?,
            ),
            CaptureLifetime::WindowObservation(_)
            | CaptureLifetime::UnmappedWindowObservation(_) => None,
        };

        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.prune_expired_locked(&mut inner, created_at);
        if inner.next_sequence == u64::MAX {
            return Err(CaptureStoreError::IdExhausted);
        }
        // All fallible image/target admission and ID allocation checks precede
        // snapshot replacement. A failed publication retains the previous set.
        if lifetime.is_window_observation() {
            self.retire_matching_locked(&mut inner, |capture| {
                capture.binding == registration.binding && capture.lifetime.is_window_observation()
            });
        }
        while inner.captures.len() >= self.config.max_captures
            || inner.total_bytes.saturating_add(byte_len) > self.config.max_total_bytes
        {
            self.evict_oldest(&mut inner);
        }
        let sequence = inner.next_sequence;
        inner.next_sequence += 1;
        let id = CaptureId {
            namespace: self.namespace,
            sequence,
        };
        let capture = StoredCapture {
            id,
            encoded_bytes,
            codec: registration.codec,
            digest,
            target: registration.target,
            encoded_dimensions: registration.encoded_dimensions,
            native_action_dimensions: registration.native_action_dimensions,
            screenshot_to_action: match lifetime {
                CaptureLifetime::UnmappedWindowObservation(_) => None,
                _ => Some(registration.screenshot_to_action),
            },
            binding: registration.binding,
            lifetime,
            created_at,
            expires_at,
        };
        inner.total_bytes += byte_len;
        inner.insertion_order.push_back(id);
        inner.captures.insert(id, capture);
        Ok(id)
    }

    /// Read immutable screenshot material without making it action-capable.
    fn read_for_perception(
        &self,
        id: CaptureId,
        binding: &CaptureBinding,
    ) -> Result<PerceptionCapture, CaptureLookupError> {
        let now = self.clock.now();
        let mut inner = self.lock_inner();
        self.resolve_locked(&mut inner, id, binding, now)
            .map(|capture| PerceptionCapture(capture.clone()))
    }

    fn admit_action(
        &self,
        request: CaptureActionRequest,
    ) -> Result<CaptureActionAdmission, CaptureActionError> {
        self.admit_action_in_frame(request, None)
    }

    fn admit_action_in_frame(
        &self,
        request: CaptureActionRequest,
        current_frame: Option<NativeWindowFrame>,
    ) -> Result<CaptureActionAdmission, CaptureActionError> {
        // A one-point action is the same transaction with coincident endpoints.
        // Keep its public result and validation semantics unchanged.
        let to_x = request.screenshot_x;
        let to_y = request.screenshot_y;
        self.admit_drag_in_frame(
            CaptureDragRequest {
                from: request,
                to_x,
                to_y,
            },
            current_frame,
        )
        .map(|admission| admission.from)
    }

    fn admit_drag(
        &self,
        drag: CaptureDragRequest,
    ) -> Result<CaptureDragAdmission, CaptureActionError> {
        self.admit_drag_in_frame(drag, None)
    }

    fn admit_drag_in_frame(
        &self,
        drag: CaptureDragRequest,
        current_frame: Option<NativeWindowFrame>,
    ) -> Result<CaptureDragAdmission, CaptureActionError> {
        let CaptureDragRequest {
            from: request,
            to_x,
            to_y,
        } = drag;
        let now = self.clock.now();
        let mut inner = self.lock_inner();
        let capture = self.resolve_locked(&mut inner, request.capture_id, &request.binding, now)?;
        if capture.target != request.target {
            return Err(CaptureLookupError::TargetMismatch.into());
        }
        if matches!(
            capture.lifetime,
            CaptureLifetime::UnmappedWindowObservation(_)
        ) {
            return Err(CaptureActionError::NativeActionMappingUnavailable);
        }
        if let CaptureLifetime::WindowObservation(recorded_frame) = capture.lifetime {
            let current_frame = current_frame.ok_or(CaptureLookupError::WindowFrameRequired)?;
            if recorded_frame != current_frame {
                return Err(CaptureActionError::NativeActionFrameMismatch);
            }
        }
        if let Some(frame) = current_frame {
            if capture.target
                != (CaptureTarget::Window {
                    pid: frame.pid(),
                    window_id: frame.window_id(),
                })
            {
                return Err(CaptureActionError::NativeActionFrameMismatch);
            }
        }
        if capture.native_action_dimensions != request.current_native_action_dimensions {
            return Err(CaptureActionError::NativeActionFrameMismatch);
        }
        let max_x = f64::from(capture.encoded_dimensions.width);
        let max_y = f64::from(capture.encoded_dimensions.height);
        let map_point = |x: f64, y: f64| {
            if !x.is_finite() || !y.is_finite() || x < 0.0 || y < 0.0 || x >= max_x || y >= max_y {
                return Err(CaptureActionError::InvalidScreenshotPoint);
            }
            let transform = capture
                .screenshot_to_action
                .ok_or(CaptureActionError::NativeActionMappingUnavailable)?;
            let (action_x, action_y) = transform.apply(x, y);
            if !action_x.is_finite() || !action_y.is_finite() {
                return Err(CaptureActionError::InvalidMappedPoint);
            }
            Ok((action_x, action_y))
        };
        let (action_x, action_y) = map_point(request.screenshot_x, request.screenshot_y)?;
        let (action_to_x, action_to_y) = map_point(to_x, to_y)?;
        let admission = CaptureDragAdmission {
            from: CaptureActionAdmission {
                capture_id: capture.id,
                target: capture.target.clone(),
                action_x,
                action_y,
                native_action_dimensions: capture.native_action_dimensions,
                digest: capture.digest,
            },
            encoded_dimensions: capture.encoded_dimensions,
            action_to_x,
            action_to_y,
        };
        // No endpoint can be admitted separately or consume on validation failure.
        if capture.lifetime == CaptureLifetime::OneShot {
            self.remove_capture(&mut inner, request.capture_id);
        }
        Ok(admission)
    }

    fn retire(&self, id: CaptureId, binding: &CaptureBinding) -> Result<(), CaptureLookupError> {
        let now = self.clock.now();
        let mut inner = self.lock_inner();
        self.resolve_locked(&mut inner, id, binding, now)?;
        self.remove_capture(&mut inner, id);
        Ok(())
    }

    /// The one lookup every read, admission, and retirement shares. Refusal
    /// order: an expired entry (tombstoned on first sight) or tombstone
    /// reports `Expired`, a missing entry `Unknown`, then a foreign binding
    /// `GenerationMismatch`.
    fn resolve_locked<'a>(
        &self,
        inner: &'a mut RegistryInner,
        id: CaptureId,
        binding: &CaptureBinding,
        now: Duration,
    ) -> Result<&'a StoredCapture, CaptureLookupError> {
        if inner
            .captures
            .get(&id)
            .is_some_and(|capture| capture.expires_at.is_some_and(|expiry| expiry <= now))
        {
            self.remove_capture(inner, id);
            self.remember_expired(inner, id);
            return Err(CaptureLookupError::Expired);
        }
        let capture = inner.captures.get(&id).ok_or_else(|| {
            if inner.expired_ids.contains(&id) {
                CaptureLookupError::Expired
            } else {
                CaptureLookupError::Unknown
            }
        })?;
        if capture.binding != *binding {
            return Err(CaptureLookupError::GenerationMismatch);
        }
        Ok(capture)
    }

    fn lock_inner(&self) -> std::sync::MutexGuard<'_, RegistryInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn retire_session(&self, binding: &CaptureBinding) -> usize {
        self.retire_matching(|capture| capture.binding == *binding)
    }

    fn retire_runtime(&self, runtime_generation: u64) -> usize {
        self.retire_matching(|capture| capture.binding.runtime_generation == runtime_generation)
    }

    fn retire_window_observations(&self, binding: &CaptureBinding) -> usize {
        self.retire_matching(|capture| {
            capture.binding == *binding && capture.lifetime.is_window_observation()
        })
    }

    fn refresh_window_observation(
        &self,
        binding: &CaptureBinding,
        current_frame: NativeWindowFrame,
    ) -> usize {
        self.retire_matching(|capture| {
            capture.binding == *binding
                && matches!(
                    capture.lifetime,
                    CaptureLifetime::WindowObservation(recorded) | CaptureLifetime::UnmappedWindowObservation(recorded) if recorded != current_frame
                )
        })
    }

    /// Drop all registry-owned references whose TTL has elapsed.
    ///
    /// Work is bounded by `max_captures`. The returned byte count is the sum of
    /// encoded PNG lengths removed from the registry; independently cloned
    /// perception results may keep their own immutable references alive.
    fn prune_expired(&self) -> PruneOutcome {
        let now = self.clock.now();
        let mut inner = self.lock_inner();
        self.prune_expired_locked(&mut inner, now)
    }

    fn retire_matching(&self, matches: impl Fn(&StoredCapture) -> bool) -> usize {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.retire_matching_locked(&mut inner, matches)
    }

    fn retire_matching_locked(
        &self,
        inner: &mut RegistryInner,
        matches: impl Fn(&StoredCapture) -> bool,
    ) -> usize {
        let ids = inner
            .insertion_order
            .iter()
            .copied()
            .filter(|id| inner.captures.get(id).is_some_and(&matches))
            .collect::<Vec<_>>();
        for id in &ids {
            self.remove_capture(inner, *id);
        }
        ids.len()
    }

    fn prune_expired_locked(&self, inner: &mut RegistryInner, now: Duration) -> PruneOutcome {
        let expired = inner
            .insertion_order
            .iter()
            .copied()
            .filter(|id| {
                inner
                    .captures
                    .get(id)
                    .is_some_and(|capture| capture.expires_at.is_some_and(|expiry| expiry <= now))
            })
            .collect::<Vec<_>>();
        let mut outcome = PruneOutcome::default();
        for id in expired {
            outcome.encoded_bytes_released += self.remove_capture(inner, id);
            outcome.captures_removed += 1;
            self.remember_expired(inner, id);
        }
        outcome
    }

    fn evict_oldest(&self, inner: &mut RegistryInner) {
        if let Some(id) = inner.insertion_order.front().copied() {
            self.remove_capture(inner, id);
        }
    }

    fn remove_capture(&self, inner: &mut RegistryInner, id: CaptureId) -> usize {
        let mut removed_bytes = 0;
        if let Some(capture) = inner.captures.remove(&id) {
            removed_bytes = capture.encoded_bytes.len();
            inner.total_bytes = inner.total_bytes.saturating_sub(removed_bytes);
        }
        if let Some(index) = inner
            .insertion_order
            .iter()
            .position(|candidate| *candidate == id)
        {
            inner.insertion_order.remove(index);
        }
        removed_bytes
    }

    fn remember_expired(&self, inner: &mut RegistryInner, id: CaptureId) {
        if inner.expired_ids.insert(id) {
            inner.expired_order.push_back(id);
        }
        while inner.expired_order.len() > self.config.max_captures {
            if let Some(oldest) = inner.expired_order.pop_front() {
                inner.expired_ids.remove(&oldest);
            }
        }
    }
}

static NEXT_RUNTIME_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Runtime-owned facade for immutable capture publication, perception reads,
/// and admission under each capture's explicit lifetime.
pub struct CaptureService {
    runtime_generation: u64,
    registry: CaptureRegistry,
    session_generations: Mutex<HashMap<Arc<str>, u64>>,
}

impl CaptureService {
    pub fn new(config: CaptureRegistryConfig) -> Result<Self, CaptureStoreError> {
        Self::with_clock(config, Arc::new(SystemMonotonicClock::new()))
    }

    pub(crate) fn with_clock(
        config: CaptureRegistryConfig,
        clock: Arc<dyn MonotonicClock>,
    ) -> Result<Self, CaptureStoreError> {
        let runtime_generation = NEXT_RUNTIME_GENERATION
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                (current != 0 && current != u64::MAX).then_some(current + 1)
            })
            .map_err(|_| CaptureStoreError::IdExhausted)?;
        Ok(Self {
            runtime_generation,
            registry: CaptureRegistry::with_clock(config, clock)?,
            session_generations: Mutex::new(HashMap::new()),
        })
    }

    pub fn runtime_generation(&self) -> u64 {
        self.runtime_generation
    }

    pub fn binding(
        &self,
        session_id: impl Into<Arc<str>>,
        session_generation: u64,
    ) -> Result<CaptureBinding, CaptureStoreError> {
        CaptureBinding::new(self.runtime_generation, session_id, session_generation)
    }

    /// Return the current private generation for a runtime-scoped session.
    pub fn current_binding(
        &self,
        session_id: impl Into<Arc<str>>,
    ) -> Result<CaptureBinding, CaptureStoreError> {
        let session_id = session_id.into();
        if session_id.trim().is_empty() {
            return Err(CaptureStoreError::InvalidBinding);
        }
        let generation = *self
            .session_generations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(session_id.clone())
            .or_insert(1);
        self.binding(session_id, generation)
    }

    /// Resolve trusted runtime arguments after the dispatch boundary has
    /// replaced the public session label with `_session_id`.
    pub fn binding_from_args(
        &self,
        args: &serde_json::Value,
    ) -> Result<CaptureBinding, CaptureStoreError> {
        let session_id = args
            .get("_session_id")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or(CaptureStoreError::InvalidBinding)?;
        self.current_binding(Arc::<str>::from(session_id))
    }

    pub fn publish(&self, publication: CapturePublication) -> Result<CaptureId, CaptureStoreError> {
        let binding = self.binding(publication.session_id, publication.session_generation)?;
        self.registry.store(CaptureRegistration {
            encoded_bytes: publication.encoded_bytes,
            codec: publication.codec,
            target: publication.target,
            encoded_dimensions: publication.encoded_dimensions,
            native_action_dimensions: publication.native_action_dimensions,
            screenshot_to_action: publication.screenshot_to_action,
            binding,
        })
    }

    /// Commit a reusable window observation, replacing prior window
    /// observations of this exact runtime/session binding in one transaction.
    /// Ordinary captures and other bindings retain their usual lifecycle and
    /// all entries remain subject to the existing storage limits.
    ///
    /// The caller supplies an already-authorized image and a trusted native
    /// frame from that observation. This method grants no Host permission and
    /// does not infer full-window geometry from cropped action dimensions.
    ///
    /// # Errors
    /// Rejects a target that differs from the supplied frame or any invalid
    /// image, transform, binding or exhausted ID. Failure leaves prior window
    /// observations in place.
    pub fn publish_window_observation(
        &self,
        publication: CapturePublication,
        frame: NativeWindowFrame,
    ) -> Result<CaptureId, CaptureStoreError> {
        let binding = self.binding(publication.session_id, publication.session_generation)?;
        self.registry.store_window_observation(
            CaptureRegistration {
                encoded_bytes: publication.encoded_bytes,
                codec: publication.codec,
                target: publication.target,
                encoded_dimensions: publication.encoded_dimensions,
                native_action_dimensions: publication.native_action_dimensions,
                screenshot_to_action: publication.screenshot_to_action,
                binding,
            },
            frame,
        )
    }

    /// Retain image bytes whose native pixel origin was not reported by the
    /// producer. No action transform is stored or inferred from image size.
    /// The publication's image-local scale is ignored for action admission.
    ///
    /// # Errors
    /// Rejects a foreign target, invalid image or binding, and exhausted storage
    /// before replacing any previous window observation.
    pub fn publish_window_observation_without_origin(
        &self,
        publication: CapturePublication,
        frame: NativeWindowFrame,
    ) -> Result<CaptureId, CaptureStoreError> {
        if publication.target
            != (CaptureTarget::Window {
                pid: frame.pid(),
                window_id: frame.window_id(),
            })
        {
            return Err(CaptureStoreError::InvalidTarget);
        }
        let binding = self.binding(publication.session_id, publication.session_generation)?;
        self.registry.store_with_lifetime(
            CaptureRegistration {
                encoded_bytes: publication.encoded_bytes,
                codec: publication.codec,
                target: publication.target,
                encoded_dimensions: publication.encoded_dimensions,
                native_action_dimensions: publication.native_action_dimensions,
                screenshot_to_action: publication.screenshot_to_action,
                binding,
            },
            CaptureLifetime::UnmappedWindowObservation(frame),
        )
    }

    pub fn parse_capture_id(&self, value: &str) -> Result<CaptureId, CaptureIdParseError> {
        value.parse()
    }

    pub fn read_for_perception(
        &self,
        id: CaptureId,
        binding: &CaptureBinding,
    ) -> Result<PerceptionCapture, CaptureLookupError> {
        self.registry.read_for_perception(id, binding)
    }

    pub fn admit_action(
        &self,
        request: CaptureActionRequest,
    ) -> Result<CaptureActionAdmission, CaptureActionError> {
        self.registry.admit_action(request)
    }

    /// Validate both drag endpoints and consume their capture in one transaction.
    ///
    /// # Errors
    /// Rejects stale/foreign captures, a changed live frame, or either invalid
    /// point. A point or frame refusal leaves a live capture unconsumed.
    pub fn admit_drag(
        &self,
        request: CaptureDragRequest,
    ) -> Result<CaptureDragAdmission, CaptureActionError> {
        self.registry.admit_drag(request)
    }

    /// Admit a window action against an independently observed current frame.
    /// Window observations remain reusable; ordinary captures consume once.
    /// Native adapters must still revalidate the frame immediately before
    /// input. This admission does not execute input or grant permission.
    ///
    /// # Errors
    /// Rejects an unknown, expired or foreign capture, changed full window
    /// frame or action dimensions, or an invalid screenshot point.
    pub fn admit_window_action(
        &self,
        request: CaptureActionRequest,
        current_frame: NativeWindowFrame,
    ) -> Result<CaptureActionAdmission, CaptureActionError> {
        self.registry
            .admit_action_in_frame(request, Some(current_frame))
    }

    /// Validate both endpoints together against one current full window frame.
    /// Window observations remain reusable; ordinary captures consume once.
    ///
    /// # Errors
    /// Rejects the same stale/foreign/frame conditions as
    /// [`Self::admit_window_action`], or either invalid endpoint. Refusal never
    /// consumes a live capture or admits either endpoint separately.
    pub fn admit_window_drag(
        &self,
        request: CaptureDragRequest,
        current_frame: NativeWindowFrame,
    ) -> Result<CaptureDragAdmission, CaptureActionError> {
        self.registry
            .admit_drag_in_frame(request, Some(current_frame))
    }

    /// Retire only window observations of this exact binding, for example when
    /// a state observation deliberately omits screenshots. No grant is changed.
    pub fn retire_window_observations(&self, binding: &CaptureBinding) -> usize {
        self.registry.retire_window_observations(binding)
    }

    /// Invalidate retained observations of this binding whose exact target or
    /// full native rectangle differs from the supplied trusted current frame.
    /// Matching observations, ordinary captures and other bindings are kept.
    pub fn refresh_window_observation(
        &self,
        binding: &CaptureBinding,
        current_frame: NativeWindowFrame,
    ) -> usize {
        self.registry
            .refresh_window_observation(binding, current_frame)
    }

    /// Predict, without consuming anything, whether a capture-bound action
    /// with these trusted runtime arguments will be refused at admission.
    /// Returns the stable refusal wire code (`capture_id_invalid`,
    /// `capture_binding_failed`, `capture_not_found`, `capture_expired`,
    /// `capture_generation_mismatch`) or `None` when the capture is currently
    /// admissible or `args` carries no `capture_id`.
    ///
    /// This is advisory: admission in the platform adapter remains the only
    /// authority. Callers use it to avoid expensive work (for example
    /// recording evidence) for calls that cannot dispatch. The refusals it
    /// reports are monotonic: an unknown, expired, or superseded capture never
    /// becomes admissible again.
    pub fn predict_action_refusal(&self, args: &serde_json::Value) -> Option<&'static str> {
        let capture_id = args.get("capture_id")?.as_str()?;
        let id = match capture_id.parse::<CaptureId>() {
            Ok(id) => id,
            Err(error) => return Some(error.wire_code()),
        };
        let Ok(binding) = self.binding_from_args(args) else {
            return Some("capture_binding_failed");
        };
        self.registry
            .read_for_perception(id, &binding)
            .err()
            .map(|error| error.wire_code())
    }

    pub fn retire_session(&self, binding: &CaptureBinding) -> usize {
        let removed = self.registry.retire_session(binding);
        if binding.runtime_generation == self.runtime_generation {
            let mut generations = self
                .session_generations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let generation = generations
                .entry(binding.session_id.clone())
                .or_insert(binding.session_generation);
            if *generation == binding.session_generation {
                *generation = generation.saturating_add(1).max(1);
            }
        }
        removed
    }

    /// Retire one capture when its owning snapshot is superseded.
    pub fn retire_capture(
        &self,
        id: CaptureId,
        binding: &CaptureBinding,
    ) -> Result<(), CaptureLookupError> {
        self.registry.retire(id, binding)
    }

    pub fn retire_session_id(&self, session_id: &str) -> usize {
        let Ok(binding) = self.current_binding(Arc::<str>::from(session_id)) else {
            return 0;
        };
        self.retire_session(&binding)
    }

    pub fn retire_runtime(&self) -> usize {
        self.registry.retire_runtime(self.runtime_generation)
    }

    pub fn prune_expired(&self) -> PruneOutcome {
        self.registry.prune_expired()
    }
}

impl Default for CaptureService {
    fn default() -> Self {
        Self::new(CaptureRegistryConfig::default()).expect("default capture config is valid")
    }
}

impl Drop for CaptureService {
    fn drop(&mut self) {
        self.registry.retire_runtime(self.runtime_generation);
    }
}

fn validate_capture_decoder<D: ImageDecoder>(
    decoder: D,
    registration: &CaptureRegistration,
    max_decoded_bytes: u64,
) -> Result<(), CaptureStoreError> {
    if decoder.dimensions()
        != (
            registration.encoded_dimensions.width,
            registration.encoded_dimensions.height,
        )
    {
        return Err(CaptureStoreError::InvalidEncodedDimensions);
    }
    if decoder.total_bytes() > max_decoded_bytes {
        return Err(CaptureStoreError::DecodeLimitExceeded);
    }
    registration
        .screenshot_to_action
        .validate_extent(registration.encoded_dimensions)?;
    image::DynamicImage::from_decoder(decoder).map_err(map_image_admission_error)?;
    Ok(())
}

fn map_image_admission_error(error: image::ImageError) -> CaptureStoreError {
    if matches!(error, image::ImageError::Limits(_)) {
        CaptureStoreError::DecodeLimitExceeded
    } else {
        CaptureStoreError::InvalidEncodedImage
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_utils::encode_rgba_to_png;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Default)]
    struct ManualClock(AtomicU64);

    impl ManualClock {
        fn advance(&self, duration: Duration) {
            self.0.fetch_add(
                u64::try_from(duration.as_millis()).expect("test duration fits"),
                Ordering::SeqCst,
            );
        }
    }

    impl MonotonicClock for ManualClock {
        fn now(&self) -> Duration {
            Duration::from_millis(self.0.load(Ordering::SeqCst))
        }
    }

    fn config(max_captures: usize, max_total_bytes: usize) -> CaptureRegistryConfig {
        CaptureRegistryConfig {
            max_captures,
            max_total_bytes,
            max_encoded_width: 4096,
            max_encoded_height: 4096,
            max_decoded_bytes: 64 * 1024 * 1024,
            ttl: Duration::from_secs(10),
        }
    }

    fn clocked(config: CaptureRegistryConfig) -> (CaptureService, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::default());
        (
            CaptureService::with_clock(config, clock.clone()).unwrap(),
            clock,
        )
    }

    fn binding(runtime: u64, session: &str, generation: u64) -> CaptureBinding {
        CaptureBinding::new(runtime, Arc::<str>::from(session), generation).unwrap()
    }

    fn png(width: u32, height: u32, value: u8) -> Vec<u8> {
        encode_rgba_to_png(
            &vec![value; usize::try_from(width * height * 4).unwrap()],
            width,
            height,
        )
        .unwrap()
    }

    fn encoded(codec: ScreenshotCodec, width: u32, height: u32, value: u8) -> Vec<u8> {
        let bytes = png(width, height, value);
        match codec {
            ScreenshotCodec::Png => bytes,
            ScreenshotCodec::Jpeg => crate::image_utils::png_bytes_to_jpeg(&bytes, 80).unwrap(),
        }
    }

    /// A 2x2 identity-mapped capture published for `session` at `generation`.
    fn publication(
        encoded_bytes: Vec<u8>,
        target: CaptureTarget,
        session: &str,
        generation: u64,
    ) -> CapturePublication {
        CapturePublication {
            encoded_bytes,
            codec: ScreenshotCodec::Png,
            target,
            encoded_dimensions: EncodedScreenshotDimensions::new(2, 2).unwrap(),
            native_action_dimensions: NativeActionDimensions::new(2, 2).unwrap(),
            screenshot_to_action: ScreenshotToActionTransform::identity(),
            session_id: Arc::from(session),
            session_generation: generation,
        }
    }

    /// Registry-level registration, used only where a test needs captures
    /// owned by a runtime generation other than the service's own.
    fn registration(
        encoded_bytes: Vec<u8>,
        target: CaptureTarget,
        binding: CaptureBinding,
    ) -> CaptureRegistration {
        CaptureRegistration {
            encoded_bytes,
            codec: ScreenshotCodec::Png,
            target,
            encoded_dimensions: EncodedScreenshotDimensions::new(2, 2).unwrap(),
            native_action_dimensions: NativeActionDimensions::new(2, 2).unwrap(),
            screenshot_to_action: ScreenshotToActionTransform::identity(),
            binding,
        }
    }

    fn action_request(
        capture_id: CaptureId,
        binding: CaptureBinding,
        target: CaptureTarget,
        native: (u32, u32),
    ) -> CaptureActionRequest {
        CaptureActionRequest {
            capture_id,
            binding,
            target,
            current_native_action_dimensions: NativeActionDimensions::new(native.0, native.1)
                .unwrap(),
            screenshot_x: 0.5,
            screenshot_y: 0.5,
        }
    }

    fn unknown_id() -> CaptureId {
        CaptureId {
            namespace: [0; 16],
            sequence: 99,
        }
    }

    #[test]
    fn stores_immutable_image_metadata_and_never_reuses_ids() {
        for codec in [ScreenshotCodec::Png, ScreenshotCodec::Jpeg] {
            let service = CaptureService::new(config(2, 10_000)).unwrap();
            let owner = service.binding("session-a", 1).unwrap();
            let target = CaptureTarget::Window {
                pid: 7,
                window_id: 9,
            };
            let bytes = encoded(codec, 2, 2, 42);
            let expected_digest = Sha256::digest(&bytes);
            let first = service
                .publish(CapturePublication {
                    codec,
                    ..publication(bytes.clone(), target.clone(), "session-a", 1)
                })
                .unwrap();
            let capture = service.read_for_perception(first, &owner).unwrap();
            assert_eq!(capture.encoded_bytes().as_ref(), bytes.as_slice());
            assert_eq!(capture.codec(), codec);
            assert_eq!(capture.digest().as_bytes(), expected_digest.as_slice());
            assert_eq!(capture.target(), &target);
            assert_eq!(
                capture.encoded_dimensions(),
                EncodedScreenshotDimensions::new(2, 2).unwrap()
            );
            service.retire_capture(first, &owner).unwrap();
            let second = service
                .publish(CapturePublication {
                    codec,
                    ..publication(bytes, target, "session-a", 1)
                })
                .unwrap();
            assert_ne!(first, second);
        }
    }

    #[test]
    fn rejects_invalid_png_dimensions_target_and_transform_before_storage() {
        let service = CaptureService::new(config(4, 10_000)).unwrap();
        let target = CaptureTarget::PrimaryDesktop;
        assert_eq!(
            service.publish(publication(
                b"not a png".to_vec(),
                target.clone(),
                "session-a",
                1
            )),
            Err(CaptureStoreError::InvalidEncodedImage)
        );
        assert_eq!(
            service.publish(publication(png(3, 2, 1), target, "session-a", 1)),
            Err(CaptureStoreError::InvalidEncodedDimensions)
        );
        let invalid_target = CaptureTarget::Window {
            pid: 0,
            window_id: 9,
        };
        assert_eq!(
            service.publish(publication(png(2, 2, 1), invalid_target, "session-a", 1)),
            Err(CaptureStoreError::InvalidTarget)
        );
        assert_eq!(service.retire_runtime(), 0, "nothing was stored");
        assert_eq!(
            ScreenshotToActionTransform::new(f64::NAN, 0.0, 0.0, 1.0, 0.0, 0.0),
            Err(CaptureStoreError::InvalidTransform)
        );
        assert_eq!(
            ScreenshotToActionTransform::new(1.0, 2.0, 2.0, 4.0, 0.0, 0.0),
            Err(CaptureStoreError::InvalidTransform)
        );
    }

    #[test]
    fn declared_codec_must_match_valid_supported_image_bytes() {
        let service = CaptureService::new(config(4, 10_000)).unwrap();
        let target = CaptureTarget::PrimaryDesktop;
        for (codec, bytes) in [
            (
                ScreenshotCodec::Png,
                encoded(ScreenshotCodec::Jpeg, 2, 2, 1),
            ),
            (
                ScreenshotCodec::Jpeg,
                encoded(ScreenshotCodec::Png, 2, 2, 1),
            ),
            (ScreenshotCodec::Png, b"GIF89a unsupported format".to_vec()),
            (ScreenshotCodec::Jpeg, b"not an image".to_vec()),
        ] {
            let mut input = publication(bytes, target.clone(), "session-a", 1);
            input.codec = codec;
            assert_eq!(
                service.publish(input),
                Err(CaptureStoreError::InvalidEncodedImage)
            );
            assert_eq!(service.retire_runtime(), 0);
        }
    }

    #[test]
    fn rejects_images_before_decode_when_dimensions_or_allocation_exceed_limits() {
        for codec in [ScreenshotCodec::Png, ScreenshotCodec::Jpeg] {
            let bytes = encoded(codec, 2, 2, 1);
            let target = CaptureTarget::PrimaryDesktop;
            let input = |bytes, target| CapturePublication {
                codec,
                ..publication(bytes, target, "session-a", 1)
            };
            let mut dimension_config = config(2, 10_000);
            dimension_config.max_encoded_width = 1;
            let service = CaptureService::new(dimension_config).unwrap();
            assert_eq!(
                service.publish(input(bytes.clone(), target.clone())),
                Err(CaptureStoreError::DecodeLimitExceeded)
            );
            let mut allocation_config = config(2, 10_000);
            allocation_config.max_decoded_bytes = 8;
            let service = CaptureService::new(allocation_config).unwrap();
            assert_eq!(
                service.publish(input(bytes, target)),
                Err(CaptureStoreError::DecodeLimitExceeded)
            );
        }
    }

    #[test]
    fn transform_composition_preserves_continuous_coordinates() {
        let image_to_native =
            ScreenshotToActionTransform::new(2.0, 0.0, 0.0, 3.0, 4.0, 5.0).unwrap();
        let native_to_action =
            ScreenshotToActionTransform::new(1.0, 0.5, 0.0, 1.0, -2.0, 7.0).unwrap();
        let composed = image_to_native.then(native_to_action).unwrap();
        let intermediate = image_to_native.apply(1.25, 2.5);
        assert_eq!(
            composed.apply(1.25, 2.5),
            native_to_action.apply(intermediate.0, intermediate.1)
        );
    }

    #[test]
    fn downscaled_capture_keeps_encoded_and_native_action_dimensions_distinct() {
        for codec in [ScreenshotCodec::Png, ScreenshotCodec::Jpeg] {
            let service = CaptureService::new(config(2, 10_000)).unwrap();
            let owner = service.binding("session-a", 1).unwrap();
            let target = CaptureTarget::PrimaryDesktop;
            let id = service
                .publish(CapturePublication {
                    encoded_bytes: encoded(codec, 2, 2, 1),
                    codec,
                    target: target.clone(),
                    encoded_dimensions: EncodedScreenshotDimensions::new(2, 2).unwrap(),
                    native_action_dimensions: NativeActionDimensions::new(4, 6).unwrap(),
                    screenshot_to_action: ScreenshotToActionTransform::new(
                        2.0, 0.0, 0.0, 3.0, 0.0, 0.0,
                    )
                    .unwrap(),
                    session_id: Arc::from("session-a"),
                    session_generation: 1,
                })
                .unwrap();
            let capture = service.read_for_perception(id, &owner).unwrap();
            assert_eq!(capture.codec(), codec);
            assert_eq!(capture.encoded_bytes().as_ref(), encoded(codec, 2, 2, 1));
            assert_eq!(
                capture.encoded_dimensions(),
                EncodedScreenshotDimensions::new(2, 2).unwrap()
            );
            let mut request = action_request(id, owner, target, (4, 6));
            request.screenshot_x = 1.0;
            request.screenshot_y = 1.0;
            let admission = service.admit_action(request).unwrap();
            assert_eq!((admission.action_x, admission.action_y), (2.0, 3.0));
            assert_eq!(
                admission.native_action_dimensions,
                NativeActionDimensions::new(4, 6).unwrap()
            );
        }
    }

    #[test]
    fn rejects_transform_that_overflows_across_encoded_extent() {
        let service = CaptureService::new(config(2, 10_000)).unwrap();
        let capture = CapturePublication {
            encoded_dimensions: EncodedScreenshotDimensions::new(3, 2).unwrap(),
            screenshot_to_action: ScreenshotToActionTransform::new(
                f64::MAX,
                0.0,
                0.0,
                1.0,
                0.0,
                0.0,
            )
            .unwrap(),
            ..publication(png(3, 2, 1), CaptureTarget::PrimaryDesktop, "session-a", 1)
        };
        assert_eq!(
            service.publish(capture),
            Err(CaptureStoreError::InvalidTransformExtent)
        );
    }

    #[test]
    fn perception_read_refusals_are_specific() {
        let service = CaptureService::new(config(4, 10_000)).unwrap();
        let owner = service.binding("session-a", 1).unwrap();
        let id = service
            .publish(publication(
                png(2, 2, 1),
                CaptureTarget::PrimaryDesktop,
                "session-a",
                1,
            ))
            .unwrap();
        assert_eq!(
            service
                .read_for_perception(unknown_id(), &owner)
                .unwrap_err(),
            CaptureLookupError::Unknown
        );
        assert_eq!(
            service
                .read_for_perception(id, &service.binding("session-a", 2).unwrap())
                .unwrap_err(),
            CaptureLookupError::GenerationMismatch
        );
        assert!(service.read_for_perception(id, &owner).is_ok());
    }

    #[test]
    fn unknown_expired_session_runtime_target_replacement_eviction_and_resize_refuse_dispatch() {
        let dispatched = AtomicU64::new(0);
        let attempt = |service: &CaptureService, request: CaptureActionRequest| {
            let result = service.admit_action(request);
            if result.is_ok() {
                dispatched.fetch_add(1, Ordering::SeqCst);
            }
            result
        };
        let target = CaptureTarget::Window {
            pid: 42,
            window_id: 7,
        };
        let publish = |service: &CaptureService, value: u8| {
            service
                .publish(publication(
                    png(2, 2, value),
                    target.clone(),
                    "session-a",
                    3,
                ))
                .unwrap()
        };

        let service = CaptureService::new(config(8, 100_000)).unwrap();
        let owner = service.binding("session-a", 3).unwrap();
        assert_eq!(
            attempt(
                &service,
                action_request(unknown_id(), owner.clone(), target.clone(), (2, 2))
            )
            .unwrap_err(),
            CaptureActionError::Lookup(CaptureLookupError::Unknown)
        );

        for wrong_binding in [
            service.binding("session-b", 3).unwrap(),
            binding(service.runtime_generation() + 1, "session-a", 3),
        ] {
            let id = publish(&service, 1);
            assert_eq!(
                attempt(
                    &service,
                    action_request(id, wrong_binding, target.clone(), (2, 2))
                )
                .unwrap_err(),
                CaptureActionError::Lookup(CaptureLookupError::GenerationMismatch)
            );
            service.retire_capture(id, &owner).unwrap();
        }

        let id = publish(&service, 2);
        assert_eq!(
            attempt(
                &service,
                action_request(id, owner.clone(), CaptureTarget::PrimaryDesktop, (2, 2))
            )
            .unwrap_err(),
            CaptureActionError::Lookup(CaptureLookupError::TargetMismatch)
        );
        service.retire_capture(id, &owner).unwrap();

        let replaced = publish(&service, 3);
        service.retire_capture(replaced, &owner).unwrap();
        let _replacement = publish(&service, 4);
        assert_eq!(
            attempt(
                &service,
                action_request(replaced, owner.clone(), target.clone(), (2, 2))
            )
            .unwrap_err(),
            CaptureActionError::Lookup(CaptureLookupError::Unknown)
        );

        let resized = publish(&service, 5);
        assert_eq!(
            attempt(
                &service,
                action_request(resized, owner.clone(), target.clone(), (3, 2))
            )
            .unwrap_err(),
            CaptureActionError::NativeActionFrameMismatch
        );

        let evicting = CaptureService::new(config(1, 100_000)).unwrap();
        let evicting_owner = evicting.binding("session-a", 3).unwrap();
        let evicted = publish(&evicting, 6);
        let _newest = publish(&evicting, 7);
        assert_eq!(
            attempt(
                &evicting,
                action_request(evicted, evicting_owner, target.clone(), (2, 2))
            )
            .unwrap_err(),
            CaptureActionError::Lookup(CaptureLookupError::Unknown)
        );

        let (expiring, clock) = clocked(config(2, 100_000));
        let expiring_owner = expiring.binding("session-a", 3).unwrap();
        let expired = publish(&expiring, 8);
        clock.advance(Duration::from_secs(10));
        assert_eq!(
            attempt(
                &expiring,
                action_request(expired, expiring_owner, target.clone(), (2, 2))
            )
            .unwrap_err(),
            CaptureActionError::Lookup(CaptureLookupError::Expired)
        );
        assert_eq!(dispatched.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn refusal_precedence_when_several_conditions_fail() {
        let (service, clock) = clocked(config(8, 100_000));
        let owner = service.binding("owner", 1).unwrap();
        let stranger = service.binding("stranger", 1).unwrap();
        let target = CaptureTarget::Window {
            pid: 42,
            window_id: 7,
        };
        let publish = || {
            service
                .publish(publication(png(2, 2, 1), target.clone(), "owner", 1))
                .unwrap()
        };

        // Expired beats a foreign binding, both on first sight of the live
        // entry and afterwards from its tombstone.
        let read = publish();
        clock.advance(Duration::from_secs(10));
        for _ in 0..2 {
            assert_eq!(
                service.read_for_perception(read, &stranger).unwrap_err(),
                CaptureLookupError::Expired
            );
        }
        let retired = publish();
        clock.advance(Duration::from_secs(10));
        for _ in 0..2 {
            assert_eq!(
                service.retire_capture(retired, &stranger),
                Err(CaptureLookupError::Expired)
            );
        }
        let admitted = publish();
        clock.advance(Duration::from_secs(10));
        for _ in 0..2 {
            assert_eq!(
                service
                    .admit_action(action_request(
                        admitted,
                        stranger.clone(),
                        target.clone(),
                        (2, 2)
                    ))
                    .unwrap_err(),
                CaptureActionError::Lookup(CaptureLookupError::Expired)
            );
        }

        // Live capture: every refusal below leaves it readable by its owner.
        let id = publish();
        let still_live = || assert!(service.read_for_perception(id, &owner).is_ok());

        // Generation beats target.
        assert_eq!(
            service
                .admit_action(action_request(
                    id,
                    stranger.clone(),
                    CaptureTarget::PrimaryDesktop,
                    (2, 2)
                ))
                .unwrap_err(),
            CaptureActionError::Lookup(CaptureLookupError::GenerationMismatch)
        );
        still_live();

        // Target beats native frame.
        assert_eq!(
            service
                .admit_action(action_request(
                    id,
                    owner.clone(),
                    CaptureTarget::PrimaryDesktop,
                    (3, 2)
                ))
                .unwrap_err(),
            CaptureActionError::Lookup(CaptureLookupError::TargetMismatch)
        );
        still_live();

        // Native frame beats an out-of-bounds screenshot point.
        let mut request = action_request(id, owner.clone(), target.clone(), (3, 2));
        request.screenshot_x = 2.0;
        assert_eq!(
            service.admit_action(request).unwrap_err(),
            CaptureActionError::NativeActionFrameMismatch
        );
        still_live();

        // Retirement refuses a foreign binding without removing the capture.
        assert_eq!(
            service.retire_capture(id, &stranger),
            Err(CaptureLookupError::GenerationMismatch)
        );
        still_live();
    }

    #[test]
    fn mapped_point_overflow_refuses_without_consuming() {
        // Storage validates the transform only at the pixel-centre corners
        // (x <= width - 1), while admission accepts fractional points up to the
        // exclusive width. A huge finite scale passes storage yet overflows for
        // an admitted point between the last pixel centre and the edge.
        let service = CaptureService::new(config(2, 10_000)).unwrap();
        let owner = service.binding("session-a", 1).unwrap();
        let target = CaptureTarget::PrimaryDesktop;
        let id = service
            .publish(CapturePublication {
                screenshot_to_action: ScreenshotToActionTransform::new(
                    f64::MAX,
                    0.0,
                    0.0,
                    1.0,
                    0.0,
                    0.0,
                )
                .unwrap(),
                ..publication(png(2, 2, 1), target.clone(), "session-a", 1)
            })
            .unwrap();
        let at = |x: f64, y: f64| {
            let mut request = action_request(id, owner.clone(), target.clone(), (2, 2));
            request.screenshot_x = x;
            request.screenshot_y = y;
            service.admit_action(request)
        };

        let refusal = at(1.5, 0.5).unwrap_err();
        assert_eq!(refusal, CaptureActionError::InvalidMappedPoint);
        assert_eq!(refusal.wire_code(), "capture_coordinate_invalid");
        assert!(service.read_for_perception(id, &owner).is_ok());
        assert_eq!(
            service.predict_action_refusal(&serde_json::json!({
                "capture_id": id.to_string(),
                "_session_id": "session-a",
            })),
            None
        );

        // An out-of-bounds point that would also overflow reports the point.
        assert_eq!(
            at(2.0, 0.5).unwrap_err(),
            CaptureActionError::InvalidScreenshotPoint
        );

        let admission = at(0.5, 0.5).unwrap();
        assert_eq!(
            (admission.action_x, admission.action_y),
            (0.5 * f64::MAX, 0.5)
        );
    }

    #[test]
    fn encoded_pixel_edges_are_half_open_and_refuse_without_consuming() {
        let service = CaptureService::new(config(2, 10_000)).unwrap();
        let owner = service.binding("edge", 1).unwrap();
        let target = CaptureTarget::PrimaryDesktop;
        let id = service
            .publish(publication(png(2, 2, 1), target.clone(), "edge", 1))
            .unwrap();
        let mut request = action_request(id, owner.clone(), target.clone(), (2, 2));
        request.screenshot_x = 2.0;
        assert_eq!(
            service.admit_action(request).unwrap_err(),
            CaptureActionError::InvalidScreenshotPoint
        );
        assert!(service.read_for_perception(id, &owner).is_ok());

        let mut request = action_request(id, owner.clone(), target.clone(), (2, 2));
        request.screenshot_y = 2.0;
        assert_eq!(
            service.admit_action(request).unwrap_err(),
            CaptureActionError::InvalidScreenshotPoint
        );
        assert!(service.read_for_perception(id, &owner).is_ok());

        let mut request = action_request(id, owner, target, (2, 2));
        request.screenshot_x = 2.0 - f64::EPSILON;
        request.screenshot_y = 2.0 - f64::EPSILON;
        assert!(service.admit_action(request).is_ok());
    }

    #[test]
    fn bounded_maintenance_releases_expired_png_without_lookup_or_store() {
        let (service, clock) = clocked(config(2, 10_000));
        let owner = service.binding("session-a", 1).unwrap();
        let id = service
            .publish(publication(
                png(2, 2, 1),
                CaptureTarget::PrimaryDesktop,
                "session-a",
                1,
            ))
            .unwrap();
        let bytes = service
            .read_for_perception(id, &owner)
            .unwrap()
            .encoded_bytes();
        let weak_bytes = Arc::downgrade(&bytes);
        let byte_len = bytes.len();
        drop(bytes);
        clock.advance(Duration::from_secs(10));
        assert_eq!(
            service.prune_expired(),
            PruneOutcome {
                captures_removed: 1,
                encoded_bytes_released: byte_len,
            }
        );
        assert!(weak_bytes.upgrade().is_none());
        assert_eq!(
            service.read_for_perception(id, &owner).unwrap_err(),
            CaptureLookupError::Expired
        );
        assert_eq!(service.retire_runtime(), 0, "pruning left nothing behind");
    }

    #[test]
    fn count_and_byte_limits_evict_oldest_deterministically() {
        let sample = png(2, 2, 1);
        let byte_limit = sample.len() * 2;
        for (name, limits) in [
            ("count", config(2, 100_000)),
            ("bytes", config(4, byte_limit)),
        ] {
            let service = CaptureService::new(limits).unwrap();
            let owner = service.binding("session-a", 1).unwrap();
            let store = || {
                service
                    .publish(publication(
                        sample.clone(),
                        CaptureTarget::PrimaryDesktop,
                        "session-a",
                        1,
                    ))
                    .unwrap()
            };
            let (first, second, third) = (store(), store(), store());
            assert_eq!(
                service.read_for_perception(first, &owner).unwrap_err(),
                CaptureLookupError::Unknown,
                "{name} limit evicts the oldest"
            );
            assert!(
                service.read_for_perception(second, &owner).is_ok(),
                "{name}"
            );
            assert!(service.read_for_perception(third, &owner).is_ok(), "{name}");
            assert_eq!(service.retire_runtime(), 2, "{name}");
        }
    }

    #[test]
    fn session_and_runtime_cleanup_are_generation_exact() {
        // One registry holding captures from two runtime generations: the
        // storage seam a single runtime-owned service cannot construct.
        let registry =
            CaptureRegistry::with_clock(config(4, 10_000), Arc::new(ManualClock::default()))
                .unwrap();
        let target = CaptureTarget::PrimaryDesktop;
        let first = binding(1, "same-label", 1);
        let second = binding(1, "same-label", 2);
        let other_runtime = binding(2, "same-label", 1);
        let store = |value: u8, owner: &CaptureBinding| {
            registry
                .store(registration(
                    png(2, 2, value),
                    target.clone(),
                    owner.clone(),
                ))
                .unwrap()
        };
        let first_id = store(1, &first);
        let second_id = store(2, &second);
        let other_id = store(3, &other_runtime);
        let reads = |id, owner: &CaptureBinding| registry.read_for_perception(id, owner).is_ok();

        assert_eq!(registry.retire_session(&first), 1);
        assert!(!reads(first_id, &first));
        assert!(reads(second_id, &second));
        assert!(reads(other_id, &other_runtime));

        assert_eq!(registry.retire_runtime(1), 1);
        assert!(!reads(second_id, &second));
        assert!(reads(other_id, &other_runtime));

        assert_eq!(registry.retire_runtime(2), 1);
        assert!(!reads(other_id, &other_runtime));
        assert_eq!(registry.retire_runtime(2), 0);

        // The service retires only its own runtime generation.
        let service = CaptureService::new(config(4, 10_000)).unwrap();
        let own = service
            .publish(publication(png(2, 2, 4), target.clone(), "same-label", 1))
            .unwrap();
        let foreign = binding(service.runtime_generation() + 1, "same-label", 1);
        let foreign_id = service
            .registry
            .store(registration(png(2, 2, 5), target, foreign.clone()))
            .unwrap();
        assert_eq!(service.retire_runtime(), 1);
        assert_eq!(
            service
                .read_for_perception(own, &service.binding("same-label", 1).unwrap())
                .unwrap_err(),
            CaptureLookupError::Unknown
        );
        assert!(service
            .registry
            .read_for_perception(foreign_id, &foreign)
            .is_ok());
    }

    #[test]
    fn service_round_trips_ids_and_applies_full_affine_once() {
        for codec in [ScreenshotCodec::Png, ScreenshotCodec::Jpeg] {
            let service = CaptureService::new(config(4, 10_000)).unwrap();
            let target = CaptureTarget::Window {
                pid: 42,
                window_id: 7,
            };
            let transform =
                ScreenshotToActionTransform::new(2.0, 0.5, -0.25, 3.0, 11.0, -4.0).unwrap();
            let id = service
                .publish(CapturePublication {
                    encoded_bytes: encoded(codec, 4, 3, 9),
                    codec,
                    target: target.clone(),
                    encoded_dimensions: EncodedScreenshotDimensions::new(4, 3).unwrap(),
                    native_action_dimensions: NativeActionDimensions::new(40, 30).unwrap(),
                    screenshot_to_action: transform,
                    session_id: Arc::from("session-a"),
                    session_generation: 2,
                })
                .unwrap();
            assert_eq!(service.parse_capture_id(&id.to_string()).unwrap(), id);
            let binding = service.binding("session-a", 2).unwrap();
            let capture = service.read_for_perception(id, &binding).unwrap();
            assert_eq!(capture.codec(), codec);
            assert_eq!(capture.encoded_bytes().as_ref(), encoded(codec, 4, 3, 9));
            let admission = service
                .admit_action(CaptureActionRequest {
                    capture_id: id,
                    binding: binding.clone(),
                    target: target.clone(),
                    current_native_action_dimensions: NativeActionDimensions::new(40, 30).unwrap(),
                    screenshot_x: 2.5,
                    screenshot_y: 1.5,
                })
                .unwrap();
            assert_eq!((admission.action_x, admission.action_y), (16.75, -0.125));
            assert_eq!(admission.target, target);
            assert_eq!(
                service
                    .admit_action(CaptureActionRequest {
                        capture_id: id,
                        binding,
                        target: CaptureTarget::Window {
                            pid: 42,
                            window_id: 7,
                        },
                        current_native_action_dimensions: NativeActionDimensions::new(40, 30)
                            .unwrap(),
                        screenshot_x: 2.5,
                        screenshot_y: 1.5,
                    })
                    .unwrap_err(),
                CaptureActionError::Lookup(CaptureLookupError::Unknown)
            );
        }
    }

    #[test]
    fn invalid_action_point_does_not_consume_capture() {
        let service = CaptureService::new(config(4, 10_000)).unwrap();
        let target = CaptureTarget::PrimaryDesktop;
        let id = service
            .publish(CapturePublication {
                encoded_bytes: png(2, 2, 5),
                codec: ScreenshotCodec::Png,
                target: target.clone(),
                encoded_dimensions: EncodedScreenshotDimensions::new(2, 2).unwrap(),
                native_action_dimensions: NativeActionDimensions::new(2, 2).unwrap(),
                screenshot_to_action: ScreenshotToActionTransform::identity(),
                session_id: Arc::from("session-a"),
                session_generation: 1,
            })
            .unwrap();
        let binding = service.binding("session-a", 1).unwrap();
        assert_eq!(
            service
                .admit_action(CaptureActionRequest {
                    capture_id: id,
                    binding: binding.clone(),
                    target: target.clone(),
                    current_native_action_dimensions: NativeActionDimensions::new(2, 2).unwrap(),
                    screenshot_x: f64::NAN,
                    screenshot_y: 0.0,
                })
                .unwrap_err(),
            CaptureActionError::InvalidScreenshotPoint
        );
        assert!(service.read_for_perception(id, &binding).is_ok());
    }

    #[test]
    fn capture_id_parser_rejects_noncanonical_ids() {
        let id = CaptureId {
            namespace: [0xab; 16],
            sequence: 15,
        };
        assert_eq!(id.to_string().parse::<CaptureId>().unwrap(), id);
        for invalid in [
            "",
            "capture_deadbeef_000000000000000f",
            "capture_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz_000000000000000f",
            "capture_abababababababababababababababab_0_f",
        ] {
            assert_eq!(
                invalid.parse::<CaptureId>().unwrap_err(),
                CaptureIdParseError::InvalidFormat
            );
        }
    }

    fn observation_frame() -> NativeWindowFrame {
        NativeWindowFrame::try_new(7, 9, [-40, 12, 122, 70]).unwrap()
    }

    fn observation_publication(
        binding: &CaptureBinding,
        frame: NativeWindowFrame,
        value: u8,
    ) -> CapturePublication {
        let encoded_dimensions = EncodedScreenshotDimensions::new(2, 2).unwrap();
        // This deliberately represents a cropped action frame. A real full
        // window is independent metadata, not guessed from these dimensions.
        let native_action_dimensions = NativeActionDimensions::new(6, 4).unwrap();
        CapturePublication {
            encoded_bytes: png(2, 2, value),
            codec: ScreenshotCodec::Png,
            target: CaptureTarget::Window {
                pid: frame.pid(),
                window_id: frame.window_id(),
            },
            encoded_dimensions,
            native_action_dimensions,
            screenshot_to_action: ScreenshotToActionTransform::from_dimensions(
                encoded_dimensions,
                native_action_dimensions,
            ),
            session_id: Arc::from(binding.session_id()),
            session_generation: binding.session_generation(),
        }
    }

    fn observation_request(
        id: CaptureId,
        binding: &CaptureBinding,
        frame: NativeWindowFrame,
    ) -> CaptureActionRequest {
        let mut request = action_request(
            id,
            binding.clone(),
            CaptureTarget::Window {
                pid: frame.pid(),
                window_id: frame.window_id(),
            },
            (6, 4),
        );
        request.screenshot_x = 1.0;
        request.screenshot_y = 1.0;
        request
    }

    #[test]
    fn window_observation_id_repeats_on_the_same_native_frame() {
        let service = CaptureService::new(config(8, 100_000)).unwrap();
        let owner = service.current_binding("raw-owner").unwrap();
        let frame = observation_frame();
        let id = service
            .publish_window_observation(observation_publication(&owner, frame, 31), frame)
            .unwrap();
        for _ in 0..2 {
            let admitted = service
                .admit_window_action(observation_request(id, &owner, frame), frame)
                .unwrap();
            assert_eq!(admitted.capture_id, id);
            assert_eq!((admitted.action_x, admitted.action_y), (3.0, 2.0));
            let drag = service
                .admit_window_drag(
                    CaptureDragRequest {
                        from: observation_request(id, &owner, frame),
                        to_x: 0.0,
                        to_y: 0.0,
                    },
                    frame,
                )
                .unwrap();
            assert_eq!(drag.from.capture_id, id);
            assert_eq!((drag.from.action_x, drag.from.action_y), (3.0, 2.0));
            assert_eq!((drag.action_to_x, drag.action_to_y), (0.0, 0.0));
        }
    }

    #[test]
    fn window_observation_refuses_a_changed_native_frame_without_consuming_id() {
        let service = CaptureService::new(config(8, 100_000)).unwrap();
        let owner = service.current_binding("raw-owner").unwrap();
        let frame = observation_frame();
        let id = service
            .publish_window_observation(observation_publication(&owner, frame, 32), frame)
            .unwrap();
        let moved = NativeWindowFrame::try_new(7, 9, [-39, 12, 122, 70]).unwrap();
        assert_eq!(
            service
                .admit_window_action(observation_request(id, &owner, frame), moved)
                .unwrap_err(),
            CaptureActionError::NativeActionFrameMismatch
        );
        assert_eq!(
            service
                .admit_window_action(observation_request(id, &owner, frame), frame)
                .unwrap()
                .capture_id,
            id
        );
    }

    #[test]
    fn drag_admits_both_endpoints_only_after_the_second_point_is_valid() {
        let service = CaptureService::new(config(4, 100_000)).unwrap();
        let target = CaptureTarget::Window {
            pid: 42,
            window_id: 7,
        };
        let owner = service.binding("drag-owner", 1).unwrap();
        let id = service
            .publish(CapturePublication {
                encoded_bytes: png(2, 2, 5),
                codec: ScreenshotCodec::Png,
                target: target.clone(),
                encoded_dimensions: EncodedScreenshotDimensions::new(2, 2).unwrap(),
                native_action_dimensions: NativeActionDimensions::new(6, 4).unwrap(),
                screenshot_to_action: ScreenshotToActionTransform::from_dimensions(
                    EncodedScreenshotDimensions::new(2, 2).unwrap(),
                    NativeActionDimensions::new(6, 4).unwrap(),
                ),
                session_id: Arc::from("drag-owner"),
                session_generation: 1,
            })
            .unwrap();
        let request = || CaptureDragRequest {
            from: action_request(id, owner.clone(), target.clone(), (6, 4)),
            to_x: 2.0,
            to_y: 0.0,
        };
        assert_eq!(
            service.admit_drag(request()).unwrap_err(),
            CaptureActionError::InvalidScreenshotPoint
        );
        let mut valid = request();
        valid.to_x = 1.0;
        valid.to_y = 1.0;
        let admitted = service.admit_drag(valid).unwrap();
        assert_eq!(admitted.from.capture_id, id);
        assert_eq!((admitted.from.action_x, admitted.from.action_y), (1.5, 1.0));
        assert_eq!((admitted.action_to_x, admitted.action_to_y), (3.0, 2.0));
        assert_eq!(
            service
                .admit_action(action_request(id, owner, target, (6, 4)))
                .unwrap_err(),
            CaptureActionError::Lookup(CaptureLookupError::Unknown)
        );
    }

    #[test]
    fn service_owns_session_generation_and_advances_it_on_retirement() {
        let service = CaptureService::new(config(4, 10_000)).unwrap();
        let first = service
            .binding_from_args(&serde_json::json!({"_session_id": "runtime/session-a"}))
            .unwrap();
        assert_eq!(first.session_generation(), 1);
        assert_eq!(service.retire_session_id("runtime/session-a"), 0);
        let second = service.current_binding("runtime/session-a").unwrap();
        assert_eq!(second.session_generation(), 2);
        assert_eq!(first.runtime_generation(), second.runtime_generation());
        assert_eq!(
            service
                .binding_from_args(&serde_json::json!({"session": "public-forgery"}))
                .unwrap_err(),
            CaptureStoreError::InvalidBinding
        );
    }

    #[test]
    fn poisoned_registry_and_session_locks_recover_without_panicking_or_underflowing() {
        let service = Arc::new(CaptureService::new(config(2, 10_000)).unwrap());
        let owner = service.binding("poisoned", 1).unwrap();
        let id = service
            .publish(publication(
                png(2, 2, 1),
                CaptureTarget::PrimaryDesktop,
                "poisoned",
                1,
            ))
            .unwrap();
        let poisoned_registry = service.clone();
        assert!(std::thread::spawn(move || {
            let mut inner = poisoned_registry.registry.inner.lock().unwrap();
            inner.total_bytes = 0;
            panic!("poison registry lock");
        })
        .join()
        .is_err());
        assert_eq!(service.retire_capture(id, &owner), Ok(()));
        assert_eq!(service.registry.lock_inner().total_bytes, 0);

        let service = Arc::new(CaptureService::new(config(2, 10_000)).unwrap());
        let poisoned_sessions = service.clone();
        assert!(std::thread::spawn(move || {
            let _guard = poisoned_sessions.session_generations.lock().unwrap();
            panic!("poison session lock");
        })
        .join()
        .is_err());
        assert_eq!(
            service
                .current_binding("still-available")
                .unwrap()
                .session_generation(),
            1
        );
    }

    #[test]
    fn capture_refusals_have_one_wire_code_table() {
        for (error, code) in [
            (
                CaptureActionError::Lookup(CaptureLookupError::Unknown),
                "capture_not_found",
            ),
            (
                CaptureActionError::Lookup(CaptureLookupError::Expired),
                "capture_expired",
            ),
            (
                CaptureActionError::Lookup(CaptureLookupError::GenerationMismatch),
                "capture_generation_mismatch",
            ),
            (
                CaptureActionError::Lookup(CaptureLookupError::TargetMismatch),
                "capture_target_mismatch",
            ),
            (
                CaptureActionError::Lookup(CaptureLookupError::WindowFrameRequired),
                "capture_frame_required",
            ),
            (
                CaptureActionError::InvalidScreenshotPoint,
                "capture_coordinate_invalid",
            ),
            (
                CaptureActionError::InvalidMappedPoint,
                "capture_coordinate_invalid",
            ),
            (
                CaptureActionError::NativeActionFrameMismatch,
                "capture_frame_mismatch",
            ),
        ] {
            assert_eq!(error.wire_code(), code);
            assert_eq!(admission_error_code(&anyhow::Error::new(error)), code);
        }
        assert_eq!(
            admission_error_code(&anyhow::Error::new(CaptureIdParseError::InvalidFormat)),
            "capture_id_invalid"
        );
        assert_eq!(
            admission_error_code(&anyhow::anyhow!("live target unavailable")),
            "capture_action_refused"
        );
    }

    #[test]
    fn refusal_prediction_matches_admission_without_consuming_the_capture() {
        let clock = Arc::new(ManualClock::default());
        let service = CaptureService::with_clock(config(4, 10_000), clock.clone()).unwrap();
        let args = serde_json::json!({"_session_id": "predict"});
        let binding = service.binding_from_args(&args).unwrap();
        let publish = || {
            service
                .publish(CapturePublication {
                    encoded_bytes: png(2, 2, 1),
                    codec: ScreenshotCodec::Png,
                    target: CaptureTarget::PrimaryDesktop,
                    encoded_dimensions: EncodedScreenshotDimensions::new(2, 2).unwrap(),
                    native_action_dimensions: NativeActionDimensions::new(2, 2).unwrap(),
                    screenshot_to_action: ScreenshotToActionTransform::identity(),
                    session_id: Arc::<str>::from("predict"),
                    session_generation: binding.session_generation(),
                })
                .unwrap()
        };
        let with_capture = |id: &str, session: Option<&str>| {
            let mut value = serde_json::json!({"capture_id": id, "x": 0, "y": 0});
            if let Some(session) = session {
                value["_session_id"] = serde_json::json!(session);
            }
            value
        };
        let admit = |id: CaptureId| {
            service.admit_action(CaptureActionRequest {
                capture_id: id,
                binding: binding.clone(),
                target: CaptureTarget::PrimaryDesktop,
                current_native_action_dimensions: NativeActionDimensions::new(2, 2).unwrap(),
                screenshot_x: 0.0,
                screenshot_y: 0.0,
            })
        };

        assert_eq!(service.predict_action_refusal(&args), None, "no capture_id");
        assert_eq!(
            service.predict_action_refusal(&with_capture("not-a-capture", Some("predict"))),
            Some(CAPTURE_ID_INVALID_CODE)
        );

        let live = publish();
        let live_text = live.to_string();
        assert_eq!(
            service.predict_action_refusal(&with_capture(&live_text, None)),
            Some("capture_binding_failed")
        );
        assert_eq!(
            service.predict_action_refusal(&with_capture(&live_text, Some("other"))),
            Some("capture_generation_mismatch")
        );
        // Predicting admissibility must not consume the one-shot capture.
        assert_eq!(
            service.predict_action_refusal(&with_capture(&live_text, Some("predict"))),
            None
        );
        admit(live).expect("prediction left the capture admissible");
        assert_eq!(
            service.predict_action_refusal(&with_capture(&live_text, Some("predict"))),
            Some("capture_not_found")
        );
        assert_eq!(admit(live).unwrap_err().wire_code(), "capture_not_found");

        let expiring = publish();
        clock.advance(Duration::from_secs(11));
        assert_eq!(
            service.predict_action_refusal(&with_capture(&expiring.to_string(), Some("predict"))),
            Some("capture_expired")
        );
        assert_eq!(admit(expiring).unwrap_err().wire_code(), "capture_expired");
    }
}
