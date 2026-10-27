// SPDX-License-Identifier: MIT

//! Trusted per-operation metadata for native browser wire adapters.
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
pub struct NativeHeader {
    pub name: String,
    pub value: String,
}

/// Exact current document already admitted by the Host's origin and site policy.
/// The DTO itself is metadata, never an authorization or a fresh browser grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativePreparationDocument {
    pub frame_id: String,
    pub loader_id: String,
    pub url: String,
}

/// Explicit trusted Host policy for upgrading one existing physical claim.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativePreparationPolicy {
    pub popup_enabled: bool,
    pub header_enabled: bool,
    pub headers: Vec<NativeHeader>,
}

const MAX_ID_BYTES: usize = 4096;

/// Maximum finite normalized action batch accepted by the serialized actor.
///
/// A translator must fit all terminal custody replies plus its final marker;
/// the bound is independent of per-request and per-message byte accounting.
pub(crate) const MAX_ACTION_BATCH: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "WireContextFields")]
pub struct NativeWireContext {
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
pub enum NativeWireContextError {
    #[error("trusted Host session ID is empty")]
    MissingSession,
    #[error("trusted Host turn ID is empty")]
    MissingTurn,
    #[error("trusted Host session ID exceeds the bounded metadata budget")]
    SessionTooLong,
    #[error("trusted Host turn ID exceeds the bounded metadata budget")]
    TurnTooLong,
}

impl NativeWireContext {
    /// Preserve exact IDs supplied by trusted Host code for one operation.
    ///
    /// # Errors
    /// Rejects missing or oversized IDs; performs no authorization or I/O.
    pub fn new(
        session: impl Into<String>,
        turn: impl Into<String>,
    ) -> Result<Self, NativeWireContextError> {
        let session = session.into();
        let turn = turn.into();
        if session.trim().is_empty() {
            return Err(NativeWireContextError::MissingSession);
        }
        if turn.trim().is_empty() {
            return Err(NativeWireContextError::MissingTurn);
        }
        if session.len() > MAX_ID_BYTES {
            return Err(NativeWireContextError::SessionTooLong);
        }
        if turn.len() > MAX_ID_BYTES {
            return Err(NativeWireContextError::TurnTooLong);
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

impl TryFrom<WireContextFields> for NativeWireContext {
    type Error = NativeWireContextError;
    fn try_from(value: WireContextFields) -> Result<Self, Self::Error> {
        Self::new(value.host_session_id, value.host_turn_id)
    }
}

/// A native RPC reply associated with one exact trusted semantic request.
///
/// This type has no serialization or deserialization path. Only the Rust RPC
/// matcher may construct it after matching the native request ID to its stored
/// semantic call and immutable Host context. It proves native invocation
/// termination, never Chrome success, input success, or Host effect settlement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MatchedNativeReply {
    generation: String,
    owner: String,
    semantic_id: String,
    wire_context: Option<NativeWireContext>,
}

impl MatchedNativeReply {
    pub(crate) fn from_matched_rpc(
        generation: String,
        owner: String,
        semantic_id: String,
        wire_context: Option<NativeWireContext>,
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
        wire_context: Option<&NativeWireContext>,
    ) -> bool {
        self.generation == generation
            && self.owner == owner
            && self.semantic_id == semantic_id
            && self.wire_context.as_ref() == wire_context
    }
}

/// Dispatch state observed by the broker's existing native writer.
///
/// Only the broker may produce this value from its dispatch state. It conveys
/// native write progress, never Chrome execution or Host effect settlement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NativeCdpWritePhase {
    Queued,
    Started,
    Written,
    Skipped,
    Unknown,
}

/// In-process reply origin, separate from any native/page JSON fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum NativeReplyProvenance {
    /// The selected Own extension completed its actual direct native request.
    DirectNative,
    /// Adapter-generated normalization without a matched native RPC reply.
    Adapted,
    /// A Rust matcher associated an actual native success or error reply.
    Matched(MatchedNativeReply),
}

/// Protocol actions keep actual native frames separate from broker semantics.
#[derive(Debug)]
pub(crate) enum NativeWireAction {
    NativeFrame {
        message: Value,
        semantic_id: Option<String>,
    },
    BrokerMessage(Value),
    MatchedBrokerMessage {
        message: Value,
        terminal: MatchedNativeReply,
    },
    Diagnostic {
        semantic_id: Option<String>,
        message: String,
    },
    /// The translator no longer retains the input Value; any queued native
    /// frame which contains it still owns its reservation until physical write.
    SemanticPayloadReleased {
        semantic_id: String,
    },
    /// Terminal translator bookkeeping only, never physical release proof.
    SemanticFinished {
        semantic_id: String,
    },
    /// Retire the native transport only after earlier normalized custody has
    /// been queued. A terminal protocol error must not discard actual ACKs.
    TransportEnded {
        reason: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum NativeWireError {
    #[error("native wire adapter refused locally ({code}): {message}")]
    LocalRefusal { code: String, message: String },
    #[error("native wire protocol failed: {0}")]
    Protocol(String),
}

/// One serialized protocol translator for a native-port lifetime.
///
/// The finite host retains generation/owner/claim fences and byte permits by
/// `semantic_id`. Follow-up native phases of one semantic request share those
/// exact fences. Only the first actual write marks that semantic dispatch as
/// started. Translators perform no framing, desktop input or selector work.
pub(crate) trait NativeWireAdapter: Send {
    fn start(&mut self, now: Instant) -> Result<Vec<NativeWireAction>, NativeWireError>;
    fn on_semantic(
        &mut self,
        envelope: Value,
        context: Option<&NativeWireContext>,
        now: Instant,
    ) -> Result<Vec<NativeWireAction>, NativeWireError>;
    fn on_native(
        &mut self,
        frame: Value,
        now: Instant,
    ) -> Result<Vec<NativeWireAction>, NativeWireError>;
    fn on_cancel(&mut self, semantic_id: &str) -> Vec<NativeWireAction>;
    fn on_eof(&mut self, reason: &str) -> Vec<NativeWireAction>;
    fn expire(&mut self, now: Instant) -> Vec<NativeWireAction>;
}

/// The default own protocol is already the broker's reviewed semantic protocol.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct OwnWireAdapter {
    started: bool,
}

#[cfg(test)]
impl NativeWireAdapter for OwnWireAdapter {
    fn start(&mut self, _now: Instant) -> Result<Vec<NativeWireAction>, NativeWireError> {
        if self.started {
            return Err(NativeWireError::Protocol(
                "own native adapter was started twice".to_owned(),
            ));
        }
        self.started = true;
        Ok(Vec::new())
    }
    fn on_semantic(
        &mut self,
        envelope: Value,
        _context: Option<&NativeWireContext>,
        _now: Instant,
    ) -> Result<Vec<NativeWireAction>, NativeWireError> {
        if !self.started {
            return Err(NativeWireError::Protocol(
                "own native adapter has not started".to_owned(),
            ));
        }
        if envelope["kind"] == "bound"
            && envelope["protocol"] == 1
            && envelope["generation"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        {
            return Ok(vec![NativeWireAction::NativeFrame {
                message: envelope,
                semantic_id: None,
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
                NativeWireError::Protocol(
                    "own native request lacks a canonical semantic ID".to_owned(),
                )
            })?
            .to_owned();
        if envelope["kind"] != "request" || envelope["protocol"] != 1 {
            return Err(NativeWireError::Protocol(
                "own native request envelope is invalid".to_owned(),
            ));
        }
        Ok(vec![
            NativeWireAction::NativeFrame {
                message: envelope,
                semantic_id: Some(semantic_id.clone()),
            },
            NativeWireAction::SemanticPayloadReleased { semantic_id },
        ])
    }
    fn on_native(
        &mut self,
        frame: Value,
        _now: Instant,
    ) -> Result<Vec<NativeWireAction>, NativeWireError> {
        if !self.started {
            return Err(NativeWireError::Protocol(
                "own native adapter has not started".to_owned(),
            ));
        }
        let finished = if frame["kind"] == "response" {
            frame["id"].as_str().map(str::to_owned)
        } else {
            None
        };
        let mut actions = vec![NativeWireAction::BrokerMessage(frame)];
        if let Some(semantic_id) = finished {
            actions.push(NativeWireAction::SemanticFinished { semantic_id });
        }
        Ok(actions)
    }
    fn on_cancel(&mut self, semantic_id: &str) -> Vec<NativeWireAction> {
        vec![NativeWireAction::SemanticFinished {
            semantic_id: semantic_id.to_owned(),
        }]
    }
    fn on_eof(&mut self, _reason: &str) -> Vec<NativeWireAction> {
        Vec::new()
    }
    fn expire(&mut self, _now: Instant) -> Vec<NativeWireAction> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matched_reply_evidence_requires_the_same_generation_owner_request_and_context() {
        let context = NativeWireContext::new("actual-session", "actual-turn").unwrap();
        let evidence = MatchedNativeReply::from_matched_rpc(
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
        let later_turn = NativeWireContext::new("actual-session", "later-turn").unwrap();
        assert!(!evidence.matches("generation-A", "owner-A", "7", Some(&later_turn)));
        let other_session = NativeWireContext::new("other-session", "actual-turn").unwrap();
        assert!(!evidence.matches("generation-A", "owner-A", "7", Some(&other_session)));
    }

    #[test]
    fn exact_host_ids_round_trip_without_turn_or_session_substitution() {
        let context =
            NativeWireContext::new("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "trusted-turn-1")
                .unwrap();
        let encoded = serde_json::to_value(&context).unwrap();
        assert_eq!(
            encoded,
            json!({"hostSessionId":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","hostTurnId":"trusted-turn-1"})
        );
        let decoded: NativeWireContext = serde_json::from_value(encoded).unwrap();
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
            assert!(serde_json::from_value::<NativeWireContext>(value).is_err());
        }
    }

    #[test]
    fn own_adapter_preserves_bound_handshake_without_fabricating_request_id() {
        let mut adapter = OwnWireAdapter::default();
        let now = Instant::now();
        assert!(adapter.start(now).unwrap().is_empty());
        let bound = json!({"kind":"bound","protocol":1,"generation":"actual-host-generation"});
        let actions = adapter.on_semantic(bound.clone(), None, now).unwrap();
        assert!(
            matches!(&actions[..],[NativeWireAction::NativeFrame{message,semantic_id:None}] if message==&bound)
        );
    }

    #[test]
    fn own_cancel_retires_only_adapter_bookkeeping_without_a_wire_cleanup_or_ack() {
        let mut adapter = OwnWireAdapter::default();
        adapter.start(Instant::now()).unwrap();
        let actions = adapter.on_cancel("19");
        assert!(
            matches!(&actions[..], [NativeWireAction::SemanticFinished { semantic_id }] if semantic_id == "19")
        );
    }
}
