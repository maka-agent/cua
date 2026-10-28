// SPDX-License-Identifier: MIT

//! Trusted per-operation metadata for extension browser wire adapters.
//!
//! This context conveys the existing Host's session and turn; it creates no
//! authorization. Main uses SessionOwner.browser_owner's standard UUID string
//! and the immutable trusted invocation turn. Never infer either from a page,
//! model arguments, an attached tab's previous turn, or an ambient current turn.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Instant;

/// Already expanded trusted Host headers. This type selects no identity or grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionHeader {
    pub name: String,
    pub value: String,
}

/// Exact current document already admitted by the Host's origin and site policy.
/// The DTO itself is metadata, never an authorization or a fresh browser grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionPreparationDocument {
    pub frame_id: String,
    pub loader_id: String,
    pub url: String,
}

/// Explicit trusted Host policy for upgrading one existing physical claim.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionPreparationPolicy {
    pub popup_enabled: bool,
    pub header_enabled: bool,
    pub headers: Vec<ExtensionHeader>,
}

/// Actual session preparation service, independent of debugger attachment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionSessionPreparation {
    #[default]
    Unknown,
    MetadataOnly,
    ProviderSession,
    ExplicitFixed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtensionFixedUiColor {
    Blue,
    Mint,
    Violet,
    Amber,
    Rose,
    Cyan,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionFixedUiCursor {
    pub id: String,
    pub label: String,
    pub color: ExtensionFixedUiColor,
    pub enabled: bool,
    pub reduced_motion: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ExtensionFixedUiOperation {
    Configure,
    State,
    Update,
    Control,
    ControlStop,
    Hide,
    Remove,
    Finalize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtensionFixedUiAction {
    Idle,
    Click,
    Key,
    Scroll,
    Drag,
    Observe,
}
/// Closed fixed renderer input. No executable markup or code crosses this wire.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionFixedUiRequest {
    pub operation: ExtensionFixedUiOperation,
    pub cursor: ExtensionFixedUiCursor,
    pub owner_epoch: String,
    pub point: Option<[f64; 2]>,
    pub action: ExtensionFixedUiAction,
}
impl ExtensionFixedUiRequest {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.cursor.id.is_empty() {
            return Err("fixed UI cursor identity is empty");
        }
        if self
            .owner_epoch
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .map(|value| value.to_string())
            .as_deref()
            != Some(self.owner_epoch.as_str())
        {
            return Err("fixed UI owner epoch is not a canonical positive u64");
        }
        if self
            .point
            .is_some_and(|point| point.iter().any(|value| !value.is_finite()))
        {
            return Err("fixed UI point is not finite");
        }
        Ok(())
    }
    pub(crate) fn validate_preparation(&self) -> Result<(), &'static str> {
        self.validate()?;
        if self.operation != ExtensionFixedUiOperation::Control || self.point.is_some() {
            return Err("session preparation requires a control publication without a point");
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtensionFixedUiRenderStatus {
    Ready,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionFixedUiRenderState {
    pub status: ExtensionFixedUiRenderStatus,
    pub visible: bool,
    #[serde(deserialize_with = "required_fixed_ui_point")]
    pub requested_position: Option<[f64; 2]>,
}
fn required_fixed_ui_point<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<[f64; 2]>, D::Error> {
    Option::<[f64; 2]>::deserialize(deserializer)
}
/// An actual service attempt is distinct from a renderer acknowledgement.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum ExtensionFixedUiAck {
    NotAttempted,
    Attempted {
        acknowledged: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        state: Option<ExtensionFixedUiRenderState>,
    },
    Unknown,
}

const MAX_ID_BYTES: usize = 4096;

/// Maximum finite normalized action batch accepted by the serialized actor.
///
/// A translator must fit all terminal custody replies plus its final marker;
/// the bound is independent of per-request and per-message byte accounting.
pub(crate) const MAX_ACTION_BATCH: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "WireContextFields")]
pub struct ExtensionWireContext {
    host_session_id: String,
    host_turn_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireContextFields {
    host_session_id: String,
    host_turn_id: String,
}

/// An invalid transport context is a local refusal, never a Chrome rejection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ExtensionWireContextError {
    #[error("trusted Host session ID is empty")]
    MissingSession,
    #[error("trusted Host turn ID is empty")]
    MissingTurn,
    #[error("trusted Host session ID exceeds the bounded metadata budget")]
    SessionTooLong,
    #[error("trusted Host turn ID exceeds the bounded metadata budget")]
    TurnTooLong,
}

impl ExtensionWireContext {
    /// Preserve exact IDs supplied by trusted Host code for one operation.
    ///
    /// # Errors
    /// Rejects missing or oversized IDs; performs no authorization or I/O.
    pub fn new(
        session: impl Into<String>,
        turn: impl Into<String>,
    ) -> Result<Self, ExtensionWireContextError> {
        let session = session.into();
        let turn = turn.into();
        if session.trim().is_empty() {
            return Err(ExtensionWireContextError::MissingSession);
        }
        if turn.trim().is_empty() {
            return Err(ExtensionWireContextError::MissingTurn);
        }
        if session.len() > MAX_ID_BYTES {
            return Err(ExtensionWireContextError::SessionTooLong);
        }
        if turn.len() > MAX_ID_BYTES {
            return Err(ExtensionWireContextError::TurnTooLong);
        }
        Ok(Self {
            host_session_id: session,
            host_turn_id: turn,
        })
    }

    pub fn host_session_id(&self) -> &str {
        &self.host_session_id
    }
    pub fn host_turn_id(&self) -> &str {
        &self.host_turn_id
    }
}

impl TryFrom<WireContextFields> for ExtensionWireContext {
    type Error = ExtensionWireContextError;
    fn try_from(value: WireContextFields) -> Result<Self, Self::Error> {
        Self::new(value.host_session_id, value.host_turn_id)
    }
}

/// A extension RPC reply associated with one exact trusted semantic request.
///
/// This type has no serialization or deserialization path. Only the Rust RPC
/// matcher may construct it after matching the extension request ID to its stored
/// semantic call and immutable Host context. It proves extension invocation
/// termination, never Chrome success, input success, or Host effect settlement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MatchedExtensionReply {
    generation: String,
    owner: String,
    semantic_id: String,
    wire_context: Option<ExtensionWireContext>,
}

impl MatchedExtensionReply {
    pub(crate) fn from_matched_rpc(
        generation: String,
        owner: String,
        semantic_id: String,
        wire_context: Option<ExtensionWireContext>,
    ) -> Self {
        Self {
            generation,
            owner,
            semantic_id,
            wire_context,
        }
    }

    pub(crate) fn matches(
        &self,
        generation: &str,
        owner: &str,
        semantic_id: &str,
        wire_context: Option<&ExtensionWireContext>,
    ) -> bool {
        self.generation == generation
            && self.owner == owner
            && self.semantic_id == semantic_id
            && self.wire_context.as_ref() == wire_context
    }
}

/// Dispatch state observed by the broker's existing extension writer.
///
/// Only the broker may produce this value from its dispatch state. It conveys
/// extension write progress, never Chrome execution or Host effect settlement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExtensionCdpWritePhase {
    Queued,
    Started,
    Written,
    Skipped,
    Unknown,
}

/// In-process reply origin, separate from any extension/page JSON fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ExtensionReplyProvenance {
    /// Actual extension input from the selected Maka-profile transport; never
    /// adapter-synthesized output.
    DirectExtension,
    /// Adapter-generated normalization without a matched extension RPC reply.
    Adapted,
    /// A Rust matcher associated an actual extension success or error reply.
    Matched(MatchedExtensionReply),
}

/// Passive correlation captured from the adapter's existing typed request state.
/// This is never serialized onto extension IPC and carries no payload or authority.
#[derive(Clone, Debug)]
pub(crate) struct ExtensionRpcTrace {
    generation: String,
    extension_rpc_id: String,
    extension_method: &'static str,
    semantic_id: Option<String>,
    owner: Option<String>,
    context: Option<ExtensionWireContext>,
}

impl ExtensionRpcTrace {
    pub(crate) fn captured(
        generation: &str,
        extension_rpc_id: &str,
        extension_method: &'static str,
        semantic_id: Option<&str>,
        owner: Option<&str>,
        context: Option<&ExtensionWireContext>,
    ) -> Self {
        Self {
            generation: generation.to_owned(),
            extension_rpc_id: extension_rpc_id.to_owned(),
            extension_method,
            semantic_id: semantic_id.map(str::to_owned),
            owner: owner.map(str::to_owned),
            context: context.cloned(),
        }
    }

    pub(crate) fn frame_written(&self) {
        self.record("frame_written", None);
    }

    pub(crate) fn completion(&self, category: &'static str) {
        self.record("rpc_completion", Some(category));
    }

    fn record(&self, phase: &'static str, completion_category: Option<&'static str>) {
        tracing::trace!(
            target: "maka::extension_rpc_phase",
            extension_host_pid = std::process::id(),
            generation = %self.generation,
            extension_rpc_id = %self.extension_rpc_id,
            extension_method = self.extension_method,
            semantic_id = ?self.semantic_id,
            owner = ?self.owner,
            host_session_id = ?self.context.as_ref().map(ExtensionWireContext::host_session_id),
            host_turn_id = ?self.context.as_ref().map(ExtensionWireContext::host_turn_id),
            phase,
            completion_category = ?completion_category,
            "extension RPC phase"
        );
    }
}

/// Protocol actions keep actual extension frames separate from broker semantics.
#[derive(Debug)]
pub(crate) enum ExtensionWireAction {
    ExtensionFrame {
        message: Value,
        semantic_id: Option<String>,
        trace: Option<ExtensionRpcTrace>,
    },
    BrokerMessage(Value),
    MatchedBrokerMessage {
        message: Value,
        terminal: MatchedExtensionReply,
    },
    Diagnostic {
        semantic_id: Option<String>,
        message: String,
    },
    /// The translator no longer retains the input Value; any queued extension
    /// frame which contains it still owns its reservation until physical write.
    SemanticPayloadReleased {
        semantic_id: String,
    },
    /// Terminal translator bookkeeping only, never physical release proof.
    SemanticFinished {
        semantic_id: String,
    },
    /// Retire the extension transport only after earlier normalized custody has
    /// been queued. A terminal protocol error must not discard actual ACKs.
    TransportEnded {
        reason: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ExtensionWireError {
    #[error("extension wire adapter refused locally ({code}): {message}")]
    LocalRefusal { code: String, message: String },
    #[error("extension wire protocol failed: {0}")]
    Protocol(String),
}

/// One serialized protocol translator for a extension-port lifetime.
///
/// The finite host retains generation/owner/claim fences and byte permits by
/// `semantic_id`. Follow-up extension phases of one semantic request share those
/// exact fences. Only the first actual write marks that semantic dispatch as
/// started. Translators perform no framing, desktop input or selector work.
pub(crate) trait ExtensionWireAdapter: Send {
    fn start(&mut self, now: Instant) -> Result<Vec<ExtensionWireAction>, ExtensionWireError>;
    fn on_semantic(
        &mut self,
        envelope: Value,
        context: Option<&ExtensionWireContext>,
        now: Instant,
    ) -> Result<Vec<ExtensionWireAction>, ExtensionWireError>;
    fn on_extension(
        &mut self,
        frame: Value,
        now: Instant,
    ) -> Result<Vec<ExtensionWireAction>, ExtensionWireError>;
    fn on_cancel(&mut self, semantic_id: &str) -> Vec<ExtensionWireAction>;
    fn on_eof(&mut self, reason: &str) -> Vec<ExtensionWireAction>;
    fn expire(&mut self, now: Instant) -> Vec<ExtensionWireAction>;
}

/// The default maka protocol is already the broker's reviewed semantic protocol.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MakaWireAdapter {
    started: bool,
}

#[cfg(test)]
impl ExtensionWireAdapter for MakaWireAdapter {
    fn start(&mut self, _now: Instant) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
        if self.started {
            return Err(ExtensionWireError::Protocol(
                "Maka extension adapter was started twice".to_owned(),
            ));
        }
        self.started = true;
        Ok(Vec::new())
    }
    fn on_semantic(
        &mut self,
        envelope: Value,
        _context: Option<&ExtensionWireContext>,
        _now: Instant,
    ) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
        if !self.started {
            return Err(ExtensionWireError::Protocol(
                "Maka extension adapter has not started".to_owned(),
            ));
        }
        if envelope["kind"] == "bound"
            && envelope["protocol"] == 1
            && envelope["generation"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        {
            return Ok(vec![ExtensionWireAction::ExtensionFrame {
                message: envelope,
                semantic_id: None,
                trace: None,
            }]);
        }
        let semantic_id = envelope["id"]
            .as_str()
            .filter(|id| {
                !id.is_empty()
                    && !id.starts_with('0')
                    && id.bytes().all(|byte| byte.is_ascii_digit())
                    && id.parse::<u64>().is_ok()
            })
            .ok_or_else(|| {
                ExtensionWireError::Protocol(
                    "Maka extension request lacks a canonical semantic ID".to_owned(),
                )
            })?
            .to_owned();
        if envelope["kind"] != "request" || envelope["protocol"] != 1 {
            return Err(ExtensionWireError::Protocol(
                "Maka extension request envelope is invalid".to_owned(),
            ));
        }
        Ok(vec![
            ExtensionWireAction::ExtensionFrame {
                message: envelope,
                semantic_id: Some(semantic_id.clone()),
                trace: None,
            },
            ExtensionWireAction::SemanticPayloadReleased { semantic_id },
        ])
    }
    fn on_extension(
        &mut self,
        frame: Value,
        _now: Instant,
    ) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
        if !self.started {
            return Err(ExtensionWireError::Protocol(
                "Maka extension adapter has not started".to_owned(),
            ));
        }
        let finished = if frame["kind"] == "response" {
            frame["id"].as_str().map(str::to_owned)
        } else {
            None
        };
        let mut actions = vec![ExtensionWireAction::BrokerMessage(frame)];
        if let Some(semantic_id) = finished {
            actions.push(ExtensionWireAction::SemanticFinished { semantic_id });
        }
        Ok(actions)
    }
    fn on_cancel(&mut self, semantic_id: &str) -> Vec<ExtensionWireAction> {
        vec![ExtensionWireAction::SemanticFinished {
            semantic_id: semantic_id.to_owned(),
        }]
    }
    fn on_eof(&mut self, _reason: &str) -> Vec<ExtensionWireAction> {
        Vec::new()
    }
    fn expire(&mut self, _now: Instant) -> Vec<ExtensionWireAction> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matched_reply_evidence_requires_the_same_generation_owner_request_and_context() {
        let context = ExtensionWireContext::new("actual-session", "actual-turn").unwrap();
        let evidence = MatchedExtensionReply::from_matched_rpc(
            "generation-A".to_owned(),
            "owner-A".to_owned(),
            "7".to_owned(),
            Some(context.clone()),
        );
        assert!(evidence.matches("generation-A", "owner-A", "7", Some(&context)));
        assert!(!evidence.matches("generation-B", "owner-A", "7", Some(&context)));
        assert!(!evidence.matches("generation-A", "owner-B", "7", Some(&context)));
        assert!(!evidence.matches("generation-A", "owner-A", "8", Some(&context)));
        assert!(!evidence.matches("generation-A", "owner-A", "7", None));
        let later_turn = ExtensionWireContext::new("actual-session", "later-turn").unwrap();
        assert!(!evidence.matches("generation-A", "owner-A", "7", Some(&later_turn)));
        let other_session = ExtensionWireContext::new("other-session", "actual-turn").unwrap();
        assert!(!evidence.matches("generation-A", "owner-A", "7", Some(&other_session)));
    }

    #[test]
    fn exact_host_ids_round_trip_without_turn_or_session_substitution() {
        let context =
            ExtensionWireContext::new("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "trusted-turn-1")
                .unwrap();
        let encoded = serde_json::to_value(&context).unwrap();
        assert_eq!(
            encoded,
            json!({"hostSessionId":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","hostTurnId":"trusted-turn-1"})
        );
        let decoded: ExtensionWireContext = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, context);
        assert_eq!(decoded.host_turn_id(), "trusted-turn-1");
    }

    #[test]
    fn decoding_rejects_empty_unknown_and_oversized_transport_context() {
        for value in [
            json!({"hostSessionId":"s","hostTurnId":""}),
            json!({"hostSessionId":"s","hostTurnId":"t","owner":"forged"}),
            json!({"hostSessionId":"s","hostTurnId":"x".repeat(4097)}),
        ] {
            assert!(serde_json::from_value::<ExtensionWireContext>(value).is_err());
        }
    }

    #[test]
    fn maka_adapter_preserves_bound_handshake_without_fabricating_request_id() {
        let mut adapter = MakaWireAdapter::default();
        let now = Instant::now();
        assert!(adapter.start(now).unwrap().is_empty());
        let bound = json!({"kind":"bound","protocol":1,"generation":"actual-host-generation"});
        let actions = adapter.on_semantic(bound.clone(), None, now).unwrap();
        assert!(
            matches!(&actions[..],[ExtensionWireAction::ExtensionFrame{message,semantic_id:None,..}] if message==&bound)
        );
    }

    #[test]
    fn maka_cancel_retires_only_adapter_bookkeeping_without_a_wire_cleanup_or_ack() {
        let mut adapter = MakaWireAdapter::default();
        adapter.start(Instant::now()).unwrap();
        let actions = adapter.on_cancel("19");
        assert!(
            matches!(&actions[..], [ExtensionWireAction::SemanticFinished { semantic_id }] if semantic_id == "19")
        );
    }
}

#[cfg(test)]
pub(crate) mod rpc_phase_test {
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };
    use tracing::{
        Event, Metadata, Subscriber,
        field::{Field, Visit},
        span::{Attributes, Id, Record},
    };

    #[derive(Clone, Default)]
    pub(crate) struct Capture(Arc<Mutex<Vec<BTreeMap<String, String>>>>);
    impl Capture {
        pub(crate) fn rows(&self) -> Vec<BTreeMap<String, String>> {
            self.0.lock().expect("trace capture lock poisoned").clone()
        }
    }
    struct Fields(BTreeMap<String, String>);
    impl Visit for Fields {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0.insert(field.name().to_owned(), format!("{value:?}"));
        }
        fn record_str(&mut self, field: &Field, value: &str) {
            self.0.insert(field.name().to_owned(), value.to_owned());
        }
        fn record_u64(&mut self, field: &Field, value: u64) {
            self.0.insert(field.name().to_owned(), value.to_string());
        }
    }
    impl Subscriber for Capture {
        fn enabled(&self, metadata: &Metadata<'_>) -> bool {
            metadata.target() == "maka::extension_rpc_phase"
        }
        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _: &Id, _: &Record<'_>) {}
        fn record_follows_from(&self, _: &Id, _: &Id) {}
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
        fn event(&self, event: &Event<'_>) {
            let mut fields = Fields(BTreeMap::new());
            event.record(&mut fields);
            self.0
                .lock()
                .expect("trace capture lock poisoned")
                .push(fields.0);
        }
    }
}
