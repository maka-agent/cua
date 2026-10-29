//! Keyboard layout mapping and prebuilt CGEvent groups.

use super::native_move::{NativeEventError, PreparedNativeEvent};
use crate::geometry::MainThreadMarker;
use core_foundation::{
    base::{CFType, TCFType},
    data::CFDataGetBytePtr,
};
use core_graphics::{
    event::{CGEvent, CGEventFlags, CGEventType},
    event_source::{CGEventSource, CGEventSourceStateID},
};
use serde::{Deserialize, Serialize};
use std::ffi::c_void;

/// Layout search order in Carbon modifier bits.
const LAYOUT_MODIFIERS: [u32; 8] = [0, 0x200, 0x800, 0xa00, 0x1000, 0x1200, 0x1800, 0x1a00];
/// UCKeyTranslate's display action, used for every independent candidate.
const LAYOUT_DISPLAY_ACTION: u16 = 3;
/// Maximum UTF-16 units returned by each layout translation.
const LAYOUT_CHARACTER_CAPACITY: usize = 4;

/// A resolved native key press; characters remain UTF-16 rather than normalized text.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeKeyPress {
    pub key_code: u16,
    /// Carbon modifier bits, not CGEvent/NSEvent flag bits.
    pub modifiers: u32,
    /// Optional complete translated string, including an explicitly empty string.
    pub characters: Option<Vec<u16>>,
}

impl std::fmt::Debug for NativeKeyPress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeKeyPress")
            .field("key_code", &self.key_code)
            .field("modifiers", &self.modifiers)
            .field("character_units", &self.characters.as_ref().map(Vec::len))
            .finish()
    }
}

/// Owned translation results; no native keyboard-layout bytes or pointers cross threads.
#[derive(Clone, Serialize, Deserialize)]
pub struct NativeKeyboardLayout {
    entries: Vec<NativeKeyPress>,
}

impl std::fmt::Debug for NativeKeyboardLayout {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeKeyboardLayout")
            .field("entry_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl NativeKeyboardLayout {
    fn key_presses(&self, text: &str) -> Vec<NativeKeyPress> {
        text.encode_utf16()
            .filter_map(|unit| {
                let unit = if unit == 0x000a { 0x000d } else { unit };
                self.entries
                    .iter()
                    .find(|key| {
                        key.characters
                            .as_deref()
                            .and_then(|characters| characters.first())
                            == Some(&unit)
                    })
                    .cloned()
            })
            .collect()
    }
}

/// Four prepared events, retained until their down/up groups settle.
#[derive(Debug)]
#[must_use = "preparing native keys does not send them"]
pub struct NativeKeyPair {
    /// Requested flagsChanged, then keyDown.
    pub down: Vec<PreparedNativeEvent>,
    /// keyUp, then flagsChanged restoring the preparation-time session flags.
    pub up: Vec<PreparedNativeEvent>,
}

/// The native factory or current keyboard layout could not be used.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NativeKeyboardError {
    #[error("native keyboard event source could not be created")]
    EventSourceUnavailable,
    #[error("native keyboard event could not be created")]
    EventUnavailable,
    #[error("native keyboard character cannot fit the source scalar payload")]
    UnrepresentableCharacter,
    #[error("current native keyboard layout input source is unavailable")]
    InputSourceUnavailable,
    #[error("current native keyboard Unicode layout data is unavailable")]
    LayoutUnavailable,
    #[error("current native keyboard layout bytes are unavailable")]
    LayoutBytesUnavailable,
    #[error(transparent)]
    Event(#[from] NativeEventError),
}

/// One HID-state source shared by all keys in a prepared native plan.
///
/// Create and consume its events on the same native worker; this owns no PID
/// authority, focus lease, delivery delay, or cancellation behavior.
pub struct NativeKeyboardSource {
    source: CGEventSource,
}

impl std::fmt::Debug for NativeKeyboardSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeKeyboardSource")
            .finish_non_exhaustive()
    }
}

impl NativeKeyboardSource {
    /// Create a HIDSystemState event source (raw value 1).
    ///
    /// # Errors
    /// Returns EventSourceUnavailable if CoreGraphics returns a null source.
    pub fn new() -> Result<Self, NativeKeyboardError> {
        let source = CGEventSource::new(CGEventSourceStateID::HIDSystemState)
            .map_err(|_| NativeKeyboardError::EventSourceUnavailable)?;
        Ok(Self { source })
    }

    /// Prepare both event groups before sending any part of this key press.
    ///
    /// # Errors
    /// Returns a native event factory or shared timestamp preparation failure.
    pub fn prepare_pair(&self, key: &NativeKeyPress) -> Result<NativeKeyPair, NativeKeyboardError> {
        let flags = event_flags(key.modifiers);
        let characters = key.characters.as_deref().map(scalar_payload).transpose()?;
        let flags_down =
            CGEvent::new(self.source.clone()).map_err(|_| NativeKeyboardError::EventUnavailable)?;
        flags_down.set_type(CGEventType::FlagsChanged);
        flags_down.set_flags(CGEventFlags::from_bits_retain(flags));
        let key_down = CGEvent::new_keyboard_event(self.source.clone(), key.key_code, true)
            .map_err(|_| NativeKeyboardError::EventUnavailable)?;
        key_down.set_flags(CGEventFlags::from_bits_retain(flags));
        if let Some(characters) = characters.as_deref() {
            key_down.set_string_from_utf16_unchecked(characters);
        }
        let key_up = CGEvent::new_keyboard_event(self.source.clone(), key.key_code, false)
            .map_err(|_| NativeKeyboardError::EventUnavailable)?;
        key_up.set_flags(CGEventFlags::from_bits_retain(flags));
        if let Some(characters) = characters.as_deref() {
            key_up.set_string_from_utf16_unchecked(characters);
        }
        // SAFETY: raw state 0 is CombinedSessionState. Read at preparation time,
        // before creating the restoring flagsChanged event.
        let restore_flags = unsafe { CGEventSourceFlagsState(0) };
        let flags_up =
            CGEvent::new(self.source.clone()).map_err(|_| NativeKeyboardError::EventUnavailable)?;
        flags_up.set_type(CGEventType::FlagsChanged);
        flags_up.set_flags(CGEventFlags::from_bits_retain(restore_flags));
        Ok(NativeKeyPair {
            down: vec![
                PreparedNativeEvent::from_cg_event(flags_down)?,
                PreparedNativeEvent::from_cg_event(key_down)?,
            ],
            up: vec![
                PreparedNativeEvent::from_cg_event(key_up)?,
                PreparedNativeEvent::from_cg_event(flags_up)?,
            ],
        })
    }
}

// Payloads contain Unicode scalar values narrowed to UInt16. Replace isolated
// UTF-16 surrogates and refuse scalar values that cannot fit the payload.
fn scalar_payload(units: &[u16]) -> Result<Vec<u16>, NativeKeyboardError> {
    char::decode_utf16(units.iter().copied())
        .map(|scalar| {
            let scalar = scalar.unwrap_or(char::REPLACEMENT_CHARACTER);
            u16::try_from(u32::from(scalar))
                .map_err(|_| NativeKeyboardError::UnrepresentableCharacter)
        })
        .collect()
}

/// Map Carbon shift/option/control/command bits to CGEvent flags.
fn event_flags(modifiers: u32) -> u64 {
    [
        (0x200, 0x20000),
        (0x800, 0x80000),
        (0x1000, 0x40000),
        (0x100, 0x100000),
    ]
    .into_iter()
    .filter(|(carbon, _)| modifiers & carbon != 0)
    .fold(0, |flags, (_, cg)| flags | cg)
}

struct CurrentLayout {
    // TIS owns the property; keep the +1 input source alive through all translation calls.
    _source: CFType,
    bytes: *const c_void,
    keyboard_type: u32,
}

impl CurrentLayout {
    fn current(_main: MainThreadMarker) -> Result<Self, NativeKeyboardError> {
        // SAFETY: this returns a create-rule retained TIS source, or null.
        let source = unsafe { TISCopyCurrentKeyboardLayoutInputSource() };
        if source.is_null() {
            return Err(NativeKeyboardError::InputSourceUnavailable);
        }
        // SAFETY: the nonnull source carries the +1 returned by the TIS API.
        let source = unsafe { CFType::wrap_under_create_rule(source) };
        // SAFETY: the source is live and this exact property is CFData layout data.
        let property = unsafe {
            TISGetInputSourceProperty(source.as_CFTypeRef(), kTISPropertyUnicodeKeyLayoutData)
        };
        if property.is_null() {
            return Err(NativeKeyboardError::LayoutUnavailable);
        }
        // SAFETY: the property's TIS contract supplies a live CFData object.
        let bytes = unsafe { CFDataGetBytePtr(property.cast()) };
        if bytes.is_null() {
            return Err(NativeKeyboardError::LayoutBytesUnavailable);
        }
        // SAFETY: LMGetKbdType is the read-only native keyboard-type query.
        let keyboard_type = u32::from(unsafe { LMGetKbdType() });
        Ok(Self {
            _source: source,
            bytes: bytes.cast(),
            keyboard_type,
        })
    }

    fn translate(
        &self,
        key_code: u16,
        modifiers: u32,
    ) -> (i32, usize, [u16; LAYOUT_CHARACTER_CAPACITY]) {
        let mut dead_key_state = 0_u32;
        let mut count = 0_usize;
        let mut characters = [0_u16; LAYOUT_CHARACTER_CAPACITY];
        // SAFETY: the retained source pins the exact UCKeyboardLayout bytes.
        // Native scalar and out-parameter types match UCKeyTranslate, and the
        // system API limits returned characters to the supplied buffer capacity.
        let status = unsafe {
            UCKeyTranslate(
                self.bytes,
                key_code,
                LAYOUT_DISPLAY_ACTION,
                (modifiers >> 8) & 0xff,
                self.keyboard_type,
                0,
                &mut dead_key_state,
                LAYOUT_CHARACTER_CAPACITY,
                &mut count,
                characters.as_mut_ptr(),
            )
        };
        (status, count, characters)
    }
}

/// Capture the current layout entirely on the main thread using read-only APIs.
///
/// Prefetch all eight modifier sets and 128 keycodes for a stable snapshot.
/// It reads keyboard type once and retains TIS data until every translation ends.
/// No user text, event factory, input posting or raw layout pointer is exported.
///
/// # Errors
/// Returns the missing input source, Unicode property or layout-byte stage.
pub fn capture_layout(main: MainThreadMarker) -> Result<NativeKeyboardLayout, NativeKeyboardError> {
    let layout = CurrentLayout::current(main)?;
    let mut entries = Vec::new();
    for modifiers in LAYOUT_MODIFIERS {
        for key_code in 0..=127_u16 {
            let (status, count, characters) = layout.translate(key_code, modifiers);
            if status == 0 && count != 0 {
                entries.push(NativeKeyPress {
                    key_code,
                    modifiers,
                    characters: Some(characters[..count].to_vec()),
                });
            }
        }
    }
    Ok(NativeKeyboardLayout { entries })
}

/// Resolve text through a main-thread snapshot without a fixed-layout fallback.
///
/// LF searches as CR; the first matching output unit selects the first entry in
/// search order. Its complete translated string becomes the payload.
/// Unmapped UTF-16 input units are skipped. Even empty text captures the layout.
///
/// # Errors
/// Returns the missing input source, Unicode property or layout-byte stage.
pub fn layout_key_presses(
    main: MainThreadMarker,
    text: &str,
) -> Result<Vec<NativeKeyPress>, NativeKeyboardError> {
    Ok(capture_layout(main)?.key_presses(text))
}

/// Select owned layout entries and prepare their events on the source's own worker.
///
/// The source must already have been created before the main-thread metadata query.
/// This function never calls TIS or UCKeyTranslate and never accepts native layout bytes.
///
/// # Errors
/// Returns the first native event or scalar-payload preparation failure.
pub fn prepare_text_from_layout(
    source: &NativeKeyboardSource,
    text: &str,
    layout: &NativeKeyboardLayout,
) -> Result<Vec<NativeKeyPair>, NativeKeyboardError> {
    let keys = layout.key_presses(text);
    keys.iter().map(|key| source.prepare_pair(key)).collect()
}

/// Prepare a key plan, preserving input order and each down/up group.
///
/// # Errors
/// Returns the source or first event-preparation failure before any event is sent.
pub fn prepare_press_keys(
    keys: &[NativeKeyPress],
) -> Result<Vec<NativeKeyPair>, NativeKeyboardError> {
    let source = NativeKeyboardSource::new()?;
    keys.iter().map(|key| source.prepare_pair(key)).collect()
}

/// Create the source first, resolve the layout, then prebuild the complete key plan.
///
/// # Errors
/// Returns the missing layout or first native event-preparation failure.
pub fn prepare_text(
    main: MainThreadMarker,
    text: &str,
) -> Result<Vec<NativeKeyPair>, NativeKeyboardError> {
    let source = NativeKeyboardSource::new()?;
    let layout = capture_layout(main)?;
    prepare_text_from_layout(&source, text, &layout)
}

#[link(name = "Carbon", kind = "framework")]
unsafe extern "C" {
    fn TISCopyCurrentKeyboardLayoutInputSource() -> *const c_void;
    fn TISGetInputSourceProperty(
        source: *const c_void,
        property_key: *const c_void,
    ) -> *const c_void;
    fn LMGetKbdType() -> u8;
    fn UCKeyTranslate(
        layout: *const c_void,
        key_code: u16,
        action: u16,
        modifiers: u32,
        keyboard_type: u32,
        options: u32,
        dead_key_state: *mut u32,
        capacity: usize,
        actual_count: *mut usize,
        characters: *mut u16,
    ) -> i32;
    static kTISPropertyUnicodeKeyLayoutData: *const c_void;
}

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    fn CGEventSourceFlagsState(state: i32) -> u64;
}
