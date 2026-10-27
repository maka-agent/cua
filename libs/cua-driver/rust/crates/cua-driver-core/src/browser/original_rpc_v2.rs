// SPDX-License-Identifier: MIT

//! Correlates the observed Original extension JSON-RPC without owning browser authorization or transport.
//!
//! Private source proposal. Native byte framing belongs to the existing helper boundary.
//! The host must inject its own authorized context before calling [`RpcCodec::begin`].
//! No OpenAI implementation is imported. Tests below are authored, not compiled or run.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::time::Instant;

use serde_json::{json, Map, Value};

/// Hard resource ceiling for this bounded native generation's pending requests.
const MAX_PENDING: usize = 4096;
/// Keeps externally supplied host nonces bounded before constructing wire identifiers.
const MAX_GENERATION_BYTES: usize = 128;

/// Original native method names established by the current retained extension source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Method {
    #[cfg(test)]
    Ping,
    GetInfo,
    GetUserTabs,
    GetTabs,
    CreateTab,
    ClaimUserTab,
    Attach,
    #[cfg(test)]
    AttachTarget,
    Detach,
    #[cfg(test)]
    DetachTarget,
    ExecuteCdp,
    #[cfg(test)]
    FocusTab,
    TurnEnded,
    #[cfg(test)]
    MarkTab,
    FinalizeTabs,
    #[cfg(test)]
    GetCommittedTabUrl,
    #[cfg(test)]
    NameSession,
    MoveMouse,
}

impl Method {
    /// Returns the exact native wire method without selecting a backend or app version.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            #[cfg(test)]
            Self::Ping => "ping",
            Self::GetInfo => "getInfo",
            Self::GetUserTabs => "getUserTabs",
            Self::GetTabs => "getTabs",
            Self::CreateTab => "createTab",
            Self::ClaimUserTab => "claimUserTab",
            Self::Attach => "attach",
            #[cfg(test)]
            Self::AttachTarget => "attachTarget",
            Self::Detach => "detach",
            #[cfg(test)]
            Self::DetachTarget => "detachTarget",
            Self::ExecuteCdp => "executeCdp",
            #[cfg(test)]
            Self::FocusTab => "focusTab",
            Self::TurnEnded => "turnEnded",
            #[cfg(test)]
            Self::MarkTab => "markTab",
            Self::FinalizeTabs => "finalizeTabs",
            #[cfg(test)]
            Self::GetCommittedTabUrl => "getCommittedTabUrl",
            #[cfg(test)]
            Self::NameSession => "nameSession",
            Self::MoveMouse => "moveMouse",
        }
    }

    /// Conservatively classifies methods that may activate a turn or mutate browser state.
    #[must_use]
    pub(crate) const fn call_effect(self) -> CallEffect {
        match self {
            Self::GetInfo | Self::GetUserTabs => CallEffect::MetadataRead,
            #[cfg(test)]
            Self::Ping => CallEffect::MetadataRead,
            // getTabs/getCommittedTabUrl activate sessions. Even readonly CDP can
            // start control tracking/scripts through requireSessionTab.
            _ => CallEffect::MayMutate,
        }
    }

    /// Identifies source-known void methods, including the actually observed id-only acknowledgements.
    #[must_use]
    pub(crate) const fn returns_void(self) -> bool {
        match self {
            Self::Attach
            | Self::Detach
            | Self::TurnEnded
            | Self::FinalizeTabs
            | Self::MoveMouse => true,
            #[cfg(test)]
            Self::AttachTarget | Self::DetachTarget | Self::MarkTab | Self::NameSession => true,
            _ => false,
        }
    }

    fn accepts_result(self, result: &Value) -> bool {
        match self {
            #[cfg(test)]
            Self::Ping => result.as_str() == Some("pong"),
            Self::GetInfo | Self::CreateTab | Self::ClaimUserTab => result.is_object(),
            Self::GetUserTabs | Self::GetTabs => result.is_array(),
            // The authorized host always injects session_id. The original
            // no-session focusTab branch returning undefined is not this contract.
            #[cfg(test)]
            Self::FocusTab => result.is_boolean(),
            #[cfg(test)]
            Self::GetCommittedTabUrl => result.is_string(),
            // CDP method results remain opaque to this correlation layer.
            Self::ExecuteCdp => true,
            _ => result.is_null(),
        }
    }
}

/// Timeout/loss classification; it never asserts that a remote handler rolled back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CallEffect {
    MetadataRead,
    MayMutate,
}

/// An identifier minted by one codec and never reused after completion or failure.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RequestId(String);

impl RequestId {
    /// Returns the exact identifier for existing helper framing and local correlation.
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One outbound object, already registered before a caller attempts its single write.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub(crate) struct Outbound {
    pub(crate) id: RequestId,
    pub(crate) message: Value,
}

/// Distinguishes exact missing-result acknowledgements from explicitly serialized null.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VoidAck {
    IdOnly,
    ExplicitNull,
}

/// A matched acknowledgement is transport evidence, not exclusive physical browser acquisition.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Reply {
    Value(Value),
    Void(VoidAck),
}

/// Original code 1 can come from extension validation, policy, or a Chrome API error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorProvenance {
    MixedExtensionOrChrome,
}

/// Preserves a real matched native rejection without fabricating Chrome-only provenance.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RemoteError {
    pub(crate) code: i64,
    pub(crate) message: String,
    pub(crate) data: Option<Value>,
    pub(crate) provenance: ErrorProvenance,
}

impl fmt::Display for RemoteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "native error {}: {}", self.code, self.message)
    }
}

impl Error for RemoteError {}

/// Explains why a pending operation lost its matched usable response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LossCause {
    Timeout,
    #[cfg(test)]
    WriteFailed,
    Eof,
    Protocol,
}

/// Distinguishes protocol/read loss from a possibly accepted mutation and actual remote rejection.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum RpcError {
    Protocol { message: String },
    ReadUnavailable { cause: LossCause, detail: String },
    OutcomeUnknown { cause: LossCause, detail: String },
    Remote(RemoteError),
}

impl fmt::Display for RpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol { message } => write!(formatter, "native protocol error: {message}"),
            Self::ReadUnavailable { cause, detail } => {
                write!(formatter, "native read unavailable ({cause:?}): {detail}")
            }
            Self::OutcomeUnknown { cause, detail } => {
                write!(
                    formatter,
                    "native operation outcome unknown ({cause:?}): {detail}"
                )
            }
            Self::Remote(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl Error for RpcError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Remote(error) => Some(error),
            _ => None,
        }
    }
}

/// One terminal outcome; the host retains its own request owner and cleanup authority separately.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub(crate) struct Completion {
    pub(crate) id: RequestId,
    pub(crate) method: Method,
    pub(crate) outcome: Result<Reply, RpcError>,
}

/// Preserves arrival order and original notification params, including raw source/session fields.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Notification {
    pub(crate) sequence: u64,
    pub(crate) method: String,
    pub(crate) params: Option<Value>,
}

/// Transport-independent effects for the existing finite native helper actor to consume in order.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub(crate) enum RpcEvent {
    Reply(Completion),
    Send(Value),
    Notification(Notification),
    IgnoredReply { id: Value },
    ProtocolViolation { message: String },
}

/// Rejects a new local operation before any native write can be attempted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AdmissionError {
    InvalidGeneration,
    InvalidPendingLimit,
    Closed,
    Capacity,
    SequenceExhausted,
    ParamsNotObject,
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidGeneration => "invalid native generation nonce",
            Self::InvalidPendingLimit => "invalid native pending limit",
            Self::Closed => "native generation is closed",
            Self::Capacity => "native pending limit reached",
            Self::SequenceExhausted => "native request sequence exhausted",
            Self::ParamsNotObject => "native method params must be an object",
        })
    }
}

impl Error for AdmissionError {}

#[derive(Debug)]
struct Pending {
    id: RequestId,
    method: Method,
    deadline: Instant,
}

impl Pending {
    fn failed(self, cause: LossCause, detail: String) -> Completion {
        let error = match (self.method.call_effect(), cause) {
            (CallEffect::MetadataRead, LossCause::Protocol) => {
                RpcError::Protocol { message: detail }
            }
            (CallEffect::MetadataRead, _) => RpcError::ReadUnavailable { cause, detail },
            (CallEffect::MayMutate, _) => RpcError::OutcomeUnknown { cause, detail },
        };
        Completion {
            id: self.id,
            method: self.method,
            outcome: Err(error),
        }
    }
}

/// Owns correlation for one fresh native generation without spawning tasks or doing I/O.
#[derive(Debug)]
pub(crate) struct RpcCodec {
    prefix: String,
    max_pending: usize,
    next_sequence: u64,
    notification_sequence: u64,
    pending: BTreeMap<u64, Pending>,
    closed: bool,
}

impl RpcCodec {
    /// Starts a native namespace from the host's fresh, collision-resistant lifetime nonce.
    ///
    /// The caller must never reuse a generation nonce after EOF or reconnect. This
    /// codec validates its grammar, not the caller's randomness or client identity.
    ///
    /// # Errors
    /// Returns an admission error for an invalid nonce or an unbounded pending limit.
    pub(crate) fn new(generation: String, max_pending: usize) -> Result<Self, AdmissionError> {
        if generation.is_empty()
            || generation.len() > MAX_GENERATION_BYTES
            || !generation
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(AdmissionError::InvalidGeneration);
        }
        if max_pending == 0 || max_pending > MAX_PENDING {
            return Err(AdmissionError::InvalidPendingLimit);
        }
        Ok(Self {
            prefix: format!("maka-original-compat:{generation}:"),
            max_pending,
            next_sequence: 0,
            notification_sequence: 0,
            pending: BTreeMap::new(),
            closed: false,
        })
    }

    /// Registers one call before returning the only outbound write attempt for it.
    ///
    /// Params must already contain the host's authorized session/turn context where
    /// required. This layer neither adds nor trusts client ownership fields.
    ///
    /// # Errors
    /// Rejects closed/full generations, nonobject params, and exhausted request IDs.
    pub(crate) fn begin(
        &mut self,
        method: Method,
        params: Value,
        deadline: Instant,
    ) -> Result<Outbound, AdmissionError> {
        if self.closed {
            return Err(AdmissionError::Closed);
        }
        if !params.is_object() {
            return Err(AdmissionError::ParamsNotObject);
        }
        if self.pending.len() >= self.max_pending {
            return Err(AdmissionError::Capacity);
        }
        let sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(AdmissionError::SequenceExhausted)?;
        self.next_sequence = sequence;
        let id = RequestId(format!("{}{sequence}", self.prefix));
        let message = json!({ "jsonrpc": "2.0", "id": id.as_str(), "method": method.as_str(), "params": params });
        // The small immutable ID is intentionally owned by both the outbound
        // receipt and pending record. No canceled ID can be minted again.
        self.pending.insert(
            sequence,
            Pending {
                id: id.clone(),
                method,
                deadline,
            },
        );
        Ok(Outbound { id, message })
    }

    /// Consumes one already-decoded native JSON object after expiring deadlines first.
    ///
    /// Native ping requests get a pong effect. Notifications preserve arrival order.
    /// Malformed matched mutation replies remain unknown and are never replayed.
    #[must_use]
    pub(crate) fn receive(&mut self, message: Value, now: Instant) -> Vec<RpcEvent> {
        let mut effects: Vec<_> = self.expire(now).into_iter().map(RpcEvent::Reply).collect();
        if self.closed {
            return effects;
        }
        let Value::Object(mut object) = message else {
            effects.extend(self.protocol_failure("native message is not an object"));
            return effects;
        };
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            effects.extend(self.protocol_failure("native message has an invalid jsonrpc version"));
            return effects;
        }
        if object.contains_key("method") {
            let Some(Value::String(method)) = object.remove("method") else {
                effects.extend(self.protocol_failure("native method is not a string"));
                return effects;
            };
            if object.contains_key("result") || object.contains_key("error") {
                effects.extend(self.protocol_failure("native request contains response fields"));
                return effects;
            }
            if let Some(id) = object.remove("id") {
                if !valid_wire_id(&id) {
                    effects.extend(self.protocol_failure("native request id is invalid"));
                    return effects;
                }
                let reply = if method == "ping" {
                    json!({ "jsonrpc": "2.0", "id": id, "result": "pong" })
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": "Maka host does not implement this native method" } })
                };
                effects.push(RpcEvent::Send(reply));
            } else {
                let Some(sequence) = self.notification_sequence.checked_add(1) else {
                    effects.extend(self.protocol_failure("native notification sequence exhausted"));
                    return effects;
                };
                self.notification_sequence = sequence;
                effects.push(RpcEvent::Notification(Notification {
                    sequence,
                    method,
                    params: object.remove("params"),
                }));
            }
            return effects;
        }
        let Some(id) = object.remove("id") else {
            effects.extend(self.protocol_failure("native response id is absent"));
            return effects;
        };
        if !valid_wire_id(&id) {
            effects.extend(self.protocol_failure("native response id is invalid"));
            return effects;
        }
        let sequence = id
            .as_str()
            .and_then(|value| value.strip_prefix(self.prefix.as_str()))
            .and_then(|value| value.parse::<u64>().ok());
        let matched = sequence.and_then(|sequence| {
            self.pending
                .get(&sequence)
                .filter(|pending| Some(pending.id.as_str()) == id.as_str())
                .map(|_| sequence)
        });
        let Some(pending) = matched.and_then(|sequence| self.pending.remove(&sequence)) else {
            effects.push(RpcEvent::IgnoredReply { id });
            return effects;
        };
        effects.push(RpcEvent::Reply(complete_response(pending, object)));
        effects
    }

    /// Retires every expired call in request order, without returning any resend effect.
    #[must_use]
    pub(crate) fn expire(&mut self, now: Instant) -> Vec<Completion> {
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(&sequence, pending)| (pending.deadline <= now).then_some(sequence))
            .collect();
        expired
            .into_iter()
            .filter_map(|sequence| self.pending.remove(&sequence))
            .map(|pending| {
                pending.failed(
                    LossCause::Timeout,
                    "native RPC deadline expired; not replayed".to_owned(),
                )
            })
            .collect()
    }

    /// Records one uncertain write failure; the caller closes other pending calls on transport EOF.
    ///
    /// A write error may follow a partial accepted write, so mutating outcomes stay unknown.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn write_failed(
        &mut self,
        id: &RequestId,
        detail: impl Into<String>,
    ) -> Option<Completion> {
        let sequence = self
            .pending
            .iter()
            .find_map(|(&sequence, pending)| (&pending.id == id).then_some(sequence))?;
        self.pending
            .remove(&sequence)
            .map(|pending| pending.failed(LossCause::WriteFailed, detail.into()))
    }

    /// Closes this generation and retires every pending operation without replay or ID reuse.
    #[must_use]
    pub(crate) fn eof(&mut self, detail: impl Into<String>) -> Vec<Completion> {
        self.closed = true;
        let detail = detail.into();
        std::mem::take(&mut self.pending)
            .into_values()
            .map(|pending| pending.failed(LossCause::Eof, detail.clone()))
            .collect()
    }

    /// Exposes only the bounded pending count, never the host's authorization state.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    fn protocol_failure(&mut self, message: &str) -> Vec<RpcEvent> {
        self.closed = true;
        let mut effects: Vec<_> = std::mem::take(&mut self.pending)
            .into_values()
            .map(|pending| RpcEvent::Reply(pending.failed(LossCause::Protocol, message.to_owned())))
            .collect();
        effects.push(RpcEvent::ProtocolViolation {
            message: message.to_owned(),
        });
        effects
    }
}

fn valid_wire_id(id: &Value) -> bool {
    matches!(id, Value::String(_) | Value::Number(_))
}

fn complete_response(pending: Pending, mut object: Map<String, Value>) -> Completion {
    let result = object.remove("result");
    let error = object.remove("error");
    if result.is_some() && error.is_some() {
        return pending.failed(
            LossCause::Protocol,
            "native reply contains both result and error".to_owned(),
        );
    }
    if let Some(error) = error {
        let Some(code) = error.get("code").and_then(Value::as_i64) else {
            return pending.failed(
                LossCause::Protocol,
                "native error has no integer code".to_owned(),
            );
        };
        let Some(message) = error.get("message").and_then(Value::as_str) else {
            return pending.failed(
                LossCause::Protocol,
                "native error has no message string".to_owned(),
            );
        };
        return Completion {
            id: pending.id,
            method: pending.method,
            outcome: Err(RpcError::Remote(RemoteError {
                code,
                message: message.to_owned(),
                data: error.get("data").cloned(),
                provenance: ErrorProvenance::MixedExtensionOrChrome,
            })),
        };
    }
    let reply = match result {
        None if pending.method.returns_void()
            && object.len() == 1
            && object.contains_key("jsonrpc") =>
        {
            Reply::Void(VoidAck::IdOnly)
        }
        None => {
            return pending.failed(
                LossCause::Protocol,
                "native result field is absent for a result-returning method".to_owned(),
            );
        }
        Some(value) if !pending.method.accepts_result(&value) => {
            return pending.failed(
                LossCause::Protocol,
                "native result does not match the method's source-known top-level type".to_owned(),
            );
        }
        Some(_) if pending.method.returns_void() => Reply::Void(VoidAck::ExplicitNull),
        Some(value) => Reply::Value(value),
    };
    Completion {
        id: pending.id,
        method: pending.method,
        outcome: Ok(reply),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn codec() -> RpcCodec {
        RpcCodec::new("test-generation".to_owned(), 16)
            .expect("test generation and limit are valid")
    }

    fn one_reply(events: Vec<RpcEvent>) -> Completion {
        assert_eq!(events.len(), 1, "expected one effect, received {events:?}");
        match events.into_iter().next().expect("one effect was checked") {
            RpcEvent::Reply(reply) => reply,
            other => panic!("expected a reply effect, received {other:?}"),
        }
    }

    #[test]
    fn out_of_order_replies_ping_and_notifications_remain_independent() {
        let mut codec = codec();
        let now = Instant::now();
        let first = codec
            .begin(Method::GetInfo, json!({}), now + Duration::from_secs(1))
            .expect("metadata admission");
        let second = codec
            .begin(Method::GetUserTabs, json!({}), now + Duration::from_secs(1))
            .expect("inventory admission");
        let reply = one_reply(codec.receive(
            json!({"jsonrpc":"2.0","id":second.id.as_str(),"result":[]}),
            now,
        ));
        assert_eq!(
            reply.id, second.id,
            "out-of-order result must match its original id"
        );
        assert_eq!(
            codec.receive(json!({"jsonrpc":"2.0","id":1,"method":"ping"}), now),
            vec![RpcEvent::Send(
                json!({"jsonrpc":"2.0","id":1,"result":"pong"})
            )],
            "native heartbeat must not consume a pending host call"
        );
        let raw = json!({"source":{"tabId":7,"sessionId":"opaque-child"},"method":"Page.loadEventFired","params":{}});
        for sequence in 1..=2 {
            assert_eq!(
                codec.receive(
                    json!({"jsonrpc":"2.0","method":"onCDPEvent","params":raw}),
                    now
                ),
                vec![RpcEvent::Notification(Notification {
                    sequence,
                    method: "onCDPEvent".to_owned(),
                    params: Some(raw.clone())
                })],
                "notification params and arrival sequence must be preserved"
            );
        }
        assert_eq!(
            one_reply(codec.receive(
                json!({"jsonrpc":"2.0","id":first.id.as_str(),"result":{"type":"extension"}}),
                now
            ))
            .id,
            first.id,
            "heartbeat and events must not steal the pending metadata response"
        );
    }

    #[test]
    fn only_exact_pending_void_methods_accept_id_only_acknowledgements() {
        let now = Instant::now();
        for method in [
            Method::Attach,
            Method::AttachTarget,
            Method::Detach,
            Method::DetachTarget,
            Method::TurnEnded,
            Method::MarkTab,
            Method::FinalizeTabs,
            Method::NameSession,
        ] {
            let mut codec = codec();
            let outbound = codec
                .begin(method, json!({}), now + Duration::from_secs(1))
                .expect("void admission");
            let reply =
                one_reply(codec.receive(json!({"jsonrpc":"2.0","id":outbound.id.as_str()}), now));
            assert_eq!(
                reply.outcome,
                Ok(Reply::Void(VoidAck::IdOnly)),
                "known void method {method:?}"
            );
        }
        for method in [
            Method::Ping,
            Method::GetInfo,
            Method::GetUserTabs,
            Method::GetTabs,
            Method::CreateTab,
            Method::ClaimUserTab,
            Method::ExecuteCdp,
            Method::FocusTab,
            Method::GetCommittedTabUrl,
        ] {
            let mut codec = codec();
            let outbound = codec
                .begin(method, json!({}), now + Duration::from_secs(1))
                .expect("result admission");
            let reply =
                one_reply(codec.receive(json!({"jsonrpc":"2.0","id":outbound.id.as_str()}), now));
            match method.call_effect() {
                CallEffect::MetadataRead => assert!(
                    matches!(reply.outcome, Err(RpcError::Protocol { .. })),
                    "missing metadata result must be a protocol error for {method:?}"
                ),
                CallEffect::MayMutate => assert!(
                    matches!(
                        reply.outcome,
                        Err(RpcError::OutcomeUnknown {
                            cause: LossCause::Protocol,
                            ..
                        })
                    ),
                    "missing mutating result must stay unknown for {method:?}"
                ),
            }
        }
        let mut codec = codec();
        let malformed = codec
            .begin(Method::Attach, json!({}), now + Duration::from_secs(1))
            .expect("void admission");
        let reply = one_reply(codec.receive(
            json!({"jsonrpc":"2.0","id":malformed.id.as_str(),"params":{"unexpected":"payload"}}),
            now,
        ));
        assert!(
            matches!(
                reply.outcome,
                Err(RpcError::OutcomeUnknown {
                    cause: LossCause::Protocol,
                    ..
                })
            ),
            "an id-only acknowledgement cannot carry unrelated request fields"
        );
    }

    #[test]
    fn actual_error_keeps_code_message_data_and_mixed_provenance() {
        let mut codec = codec();
        let now = Instant::now();
        let outbound = codec
            .begin(
                Method::ClaimUserTab,
                json!({"tabId":7}),
                now + Duration::from_secs(1),
            )
            .expect("claim admission");
        let reply = one_reply(codec.receive(json!({"jsonrpc":"2.0","id":outbound.id.as_str(),"error":{"code":1,"message":"Tab 7 is already part of browser session owner","data":{"scope":"native"}}}), now));
        assert_eq!(
            reply.outcome,
            Err(RpcError::Remote(RemoteError {
                code: 1,
                message: "Tab 7 is already part of browser session owner".to_owned(),
                data: Some(json!({"scope":"native"})),
                provenance: ErrorProvenance::MixedExtensionOrChrome
            })),
            "matched original rejection must not be relabeled a Chrome-only failure"
        );
    }

    #[test]
    fn deadline_then_late_ack_never_reuses_or_completes_another_request() {
        let mut codec = codec();
        let now = Instant::now();
        let old = codec
            .begin(Method::Attach, json!({}), now)
            .expect("attach admission");
        let effects = codec.receive(json!({"jsonrpc":"2.0","id":old.id.as_str()}), now);
        assert_eq!(
            effects.len(),
            2,
            "timeout must precede ignored late response"
        );
        assert!(
            matches!(
                &effects[0],
                RpcEvent::Reply(Completion {
                    outcome: Err(RpcError::OutcomeUnknown {
                        cause: LossCause::Timeout,
                        ..
                    }),
                    ..
                })
            ),
            "attach deadline must remain unknown"
        );
        assert!(
            matches!(&effects[1], RpcEvent::IgnoredReply { .. }),
            "late acknowledgement must be ignored"
        );
        let fresh = codec
            .begin(Method::Attach, json!({}), now + Duration::from_secs(1))
            .expect("new explicit admission");
        assert_ne!(old.id, fresh.id, "canceled request id must not be reused");
        assert_eq!(
            codec.receive(json!({"jsonrpc":"2.0","id":old.id.as_str()}), now),
            vec![RpcEvent::IgnoredReply {
                id: json!(old.id.as_str())
            }],
            "old response must not consume new pending request"
        );
        assert_eq!(codec.pending_len(), 1, "new request remains pending");
    }

    #[test]
    fn write_failure_and_eof_preserve_unknown_mutations_without_resend() {
        let mut codec = codec();
        let now = Instant::now();
        let mutation = codec
            .begin(Method::ExecuteCdp, json!({}), now + Duration::from_secs(1))
            .expect("CDP admission");
        let metadata = codec
            .begin(Method::GetInfo, json!({}), now + Duration::from_secs(1))
            .expect("metadata admission");
        let failure = codec
            .write_failed(&mutation.id, "partial write")
            .expect("write must retire this request");
        assert!(
            matches!(
                failure.outcome,
                Err(RpcError::OutcomeUnknown {
                    cause: LossCause::WriteFailed,
                    ..
                })
            ),
            "possibly accepted mutation cannot be marked failed-before-execution"
        );
        let eof = codec.eof("native port EOF");
        assert_eq!(
            eof.len(),
            1,
            "EOF only retires the still-pending metadata call"
        );
        assert_eq!(eof[0].id, metadata.id, "EOF result keeps request identity");
        assert!(
            matches!(
                &eof[0].outcome,
                Err(RpcError::ReadUnavailable {
                    cause: LossCause::Eof,
                    ..
                })
            ),
            "metadata loss does not invent a remote rejection"
        );
        assert_eq!(
            codec.begin(Method::Ping, json!({}), now),
            Err(AdmissionError::Closed),
            "EOF retires the entire generation"
        );
    }

    #[test]
    fn capacity_sequence_and_top_level_result_validation_fail_without_replay() {
        assert!(
            matches!(
                RpcCodec::new("bad:nonce".to_owned(), 1),
                Err(AdmissionError::InvalidGeneration)
            ),
            "generation grammar cannot inject request namespace separators"
        );
        assert!(
            matches!(
                RpcCodec::new("valid".to_owned(), 0),
                Err(AdmissionError::InvalidPendingLimit)
            ),
            "zero bound is invalid"
        );
        let now = Instant::now();
        let mut bounded = RpcCodec::new("bounded".to_owned(), 1).expect("valid bound");
        let first = bounded
            .begin(Method::FocusTab, json!({}), now + Duration::from_secs(1))
            .expect("first admission");
        assert_eq!(
            bounded.begin(Method::Ping, json!({}), now),
            Err(AdmissionError::Capacity),
            "full pending map refuses a new write"
        );
        let wrong = one_reply(bounded.receive(
            json!({"jsonrpc":"2.0","id":first.id.as_str(),"result":null}),
            now,
        ));
        assert!(
            matches!(
                wrong.outcome,
                Err(RpcError::OutcomeUnknown {
                    cause: LossCause::Protocol,
                    ..
                })
            ),
            "context-bearing focusTab requires a boolean result"
        );
        bounded.next_sequence = u64::MAX;
        assert_eq!(
            bounded.begin(Method::Ping, json!({}), now),
            Err(AdmissionError::SequenceExhausted),
            "request sequence must never wrap"
        );
    }

    #[test]
    fn malformed_envelope_closes_pending_generation_and_void_result_union_is_not_success() {
        let now = Instant::now();
        let mut codec = codec();
        let request = codec
            .begin(Method::TurnEnded, json!({}), now + Duration::from_secs(1))
            .expect("turn end admission");
        let malformed = one_reply(codec.receive(json!({"jsonrpc":"2.0","id":request.id.as_str(),"result":null,"error":{"code":1,"message":"bad"}}), now));
        assert!(
            matches!(
                malformed.outcome,
                Err(RpcError::OutcomeUnknown {
                    cause: LossCause::Protocol,
                    ..
                })
            ),
            "both result and error cannot acknowledge cleanup"
        );
        let _pending = codec
            .begin(Method::CreateTab, json!({}), now + Duration::from_secs(1))
            .expect("second admission");
        let effects = codec.receive(json!(["invalid batch"]), now);
        assert!(
            effects
                .iter()
                .any(|event| matches!(event, RpcEvent::ProtocolViolation { .. })),
            "invalid native envelope must be reported"
        );
        assert!(
            effects.iter().any(|event| matches!(
                event,
                RpcEvent::Reply(Completion {
                    outcome: Err(RpcError::OutcomeUnknown {
                        cause: LossCause::Protocol,
                        ..
                    }),
                    ..
                })
            )),
            "malformed transport must not silently discard a possible create"
        );
        assert_eq!(
            codec.pending_len(),
            0,
            "protocol closure retires all pending calls"
        );
    }
}
