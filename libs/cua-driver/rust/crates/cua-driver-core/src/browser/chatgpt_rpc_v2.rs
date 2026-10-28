// SPDX-License-Identifier: MIT

//! Correlates the observed Chatgpt extension JSON-RPC without owning browser authorization or transport.
//!
//! Private source proposal. Extension byte framing belongs to the existing helper boundary.
//! The host must inject its maka authorized context before calling [`RpcCodec::begin`].
//! No OpenAI implementation is imported. Tests below are authored, not compiled or run.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::time::Instant;

use serde_json::{json, value::RawValue, Map, Value};

/// Hard resource ceiling for this bounded extension generation's pending requests.
const MAX_PENDING: usize = 4096;
/// Keeps externally supplied host nonces bounded before constructing wire identifiers.
const MAX_GENERATION_BYTES: usize = 128;

/// Chatgpt extension method names established by the current retained extension source.
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
    ExecuteTabRead,
    #[cfg(test)]
    FocusTab,
    TurnEnded,
    #[cfg(test)]
    MarkTab,
    FinalizeTabs,
    GetCommittedTabUrl,
    NameSession,
    GetUserHistory,
    MoveMouse,
}

impl Method {
    /// Returns the exact extension wire method without selecting a backend or app version.
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
            Self::ExecuteTabRead => "executeTabRead",
            #[cfg(test)]
            Self::FocusTab => "focusTab",
            Self::TurnEnded => "turnEnded",
            #[cfg(test)]
            Self::MarkTab => "markTab",
            Self::FinalizeTabs => "finalizeTabs",
            Self::GetCommittedTabUrl => "getCommittedTabUrl",
            Self::NameSession => "nameSession",
            Self::GetUserHistory => "getUserHistory",
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
            | Self::MoveMouse
            | Self::NameSession => true,
            #[cfg(test)]
            Self::AttachTarget | Self::DetachTarget | Self::MarkTab => true,
            _ => false,
        }
    }

    fn accepts_result(self, result: &Value) -> bool {
        match self {
            #[cfg(test)]
            Self::Ping => result.as_str() == Some("pong"),
            Self::GetInfo | Self::CreateTab | Self::ClaimUserTab => result.is_object(),
            Self::GetUserTabs | Self::GetTabs | Self::GetUserHistory => result.is_array(),
            // The authorized host always injects session_id. The original
            // no-session focusTab branch returning undefined is not this contract.
            #[cfg(test)]
            Self::FocusTab => result.is_boolean(),
            Self::GetCommittedTabUrl => result.is_string(),
            // CDP method results remain opaque to this correlation layer.
            Self::ExecuteCdp | Self::ExecuteTabRead => true,
            _ => result.is_null(),
        }
    }

    fn accepts_result_json(self, json: &str) -> bool {
        match self {
            #[cfg(test)]
            Self::Ping => {
                serde_json::from_str::<Value>(json)
                    .ok()
                    .as_ref()
                    .and_then(Value::as_str)
                    == Some("pong")
            }
            Self::GetInfo | Self::CreateTab | Self::ClaimUserTab => json.starts_with('{'),
            Self::GetUserTabs | Self::GetTabs | Self::GetUserHistory => json.starts_with('['),
            #[cfg(test)]
            Self::FocusTab => matches!(json, "true" | "false"),
            Self::GetCommittedTabUrl => json.starts_with('"'),
            Self::ExecuteCdp | Self::ExecuteTabRead => true,
            _ => json == "null",
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
    /// Original result JSON retained before any Unicode-scalar Value decoding.
    JsonText(String),
    Void(VoidAck),
}

/// Chatgpt code 1 can come from extension validation, policy, or a Chrome API error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorProvenance {
    MixedExtensionOrChrome,
}

/// Preserves a real matched extension rejection without fabricating Chrome-only provenance.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RemoteError {
    pub(crate) code: i64,
    pub(crate) message: String,
    pub(crate) data: Option<Value>,
    pub(crate) provenance: ErrorProvenance,
}

impl fmt::Display for RemoteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "extension error {}: {}", self.code, self.message)
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
            Self::Protocol { message } => write!(formatter, "extension protocol error: {message}"),
            Self::ReadUnavailable { cause, detail } => {
                write!(
                    formatter,
                    "extension read unavailable ({cause:?}): {detail}"
                )
            }
            Self::OutcomeUnknown { cause, detail } => {
                write!(
                    formatter,
                    "extension operation outcome unknown ({cause:?}): {detail}"
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

/// One terminal outcome; the host retains its maka request owner and cleanup authority separately.
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

/// Transport-independent effects for the existing finite extension helper actor to consume in order.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub(crate) enum RpcEvent {
    Reply(Completion),
    Send(Value),
    Notification(Notification),
    JsonNotification {
        sequence: u64,
        method: String,
        params_json: Option<String>,
    },
    IgnoredReply {
        id: Value,
    },
    ProtocolViolation {
        message: String,
    },
}

/// Rejects a new local operation before any extension write can be attempted.
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
            Self::InvalidGeneration => "invalid extension generation nonce",
            Self::InvalidPendingLimit => "invalid extension pending limit",
            Self::Closed => "extension generation is closed",
            Self::Capacity => "extension pending limit reached",
            Self::SequenceExhausted => "extension request sequence exhausted",
            Self::ParamsNotObject => "extension method params must be an object",
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

/// Owns correlation for one fresh extension generation without spawning tasks or doing I/O.
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
    /// Starts a extension namespace from the host's fresh, collision-resistant lifetime nonce.
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

    fn pending_sequence(&self, id: &RequestId) -> Option<u64> {
        let sequence = id
            .as_str()
            .strip_prefix(self.prefix.as_str())?
            .parse()
            .ok()?;
        self.pending
            .get(&sequence)
            .filter(|pending| pending.id == *id)
            .map(|_| sequence)
    }

    pub(crate) fn pending_method(&self, id: &RequestId) -> Option<Method> {
        self.pending_sequence(id)
            .and_then(|sequence| self.pending.get(&sequence))
            .map(|pending| pending.method)
    }

    /// Removes only an exact local request whose physical writer never started.
    /// No remote completion or rollback is inferred, and its ID stays consumed.
    pub(crate) fn discard_unwritten(&mut self, id: &RequestId) -> Option<Method> {
        let sequence = self.pending_sequence(id)?;
        self.pending.remove(&sequence).map(|pending| pending.method)
    }

    /// Consumes one already-decoded extension JSON object after expiring deadlines first.
    ///
    /// Extension ping requests get a pong effect. Notifications preserve arrival order.
    /// Malformed matched mutation replies remain unknown and are never replayed.
    #[must_use]
    pub(crate) fn receive(&mut self, message: Value, now: Instant) -> Vec<RpcEvent> {
        self.receive_with_result_json(message, now, None, None)
    }

    /// Preserve opaque result text until the original pending method is matched.
    pub(crate) fn receive_json(&mut self, frame: &RawValue, now: Instant) -> Vec<RpcEvent> {
        let mut effects: Vec<_> = self.expire(now).into_iter().map(RpcEvent::Reply).collect();
        if self.closed {
            return effects;
        }
        if !frame.get().starts_with('{') {
            effects.extend(self.receive(Value::Null, now));
            return effects;
        }
        let mut fields: BTreeMap<String, Box<RawValue>> = match serde_json::from_str(frame.get()) {
            Ok(fields) => fields,
            Err(error) => {
                effects.extend(self.protocol_failure(&format!(
                    "extension message is not a usable protocol object: {error}"
                )));
                return effects;
            }
        };
        let result_json = fields.remove("result");
        let params_json = fields.remove("params");
        let mut object = Map::new();
        for (key, raw) in fields {
            let value = match serde_json::from_str(raw.get()) {
                Ok(value) => value,
                Err(error) => {
                    effects.extend(self.protocol_failure(&format!(
                        "extension protocol field is unavailable: {error}"
                    )));
                    return effects;
                }
            };
            object.insert(key, value);
        }
        // Presence is independent of the raw token's value, including null.
        if result_json.is_some() {
            object.insert("result".to_owned(), Value::Null);
        }
        if params_json.is_some() {
            object.insert("params".to_owned(), Value::Null);
        }
        effects.extend(self.receive_with_result_json(
            Value::Object(object),
            now,
            result_json,
            params_json,
        ));
        effects
    }

    fn receive_with_result_json(
        &mut self,
        message: Value,
        now: Instant,
        result_json: Option<Box<RawValue>>,
        params_json: Option<Box<RawValue>>,
    ) -> Vec<RpcEvent> {
        let mut effects: Vec<_> = self.expire(now).into_iter().map(RpcEvent::Reply).collect();
        if self.closed {
            return effects;
        }
        let Value::Object(mut object) = message else {
            effects.extend(self.protocol_failure("extension message is not an object"));
            return effects;
        };
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            effects
                .extend(self.protocol_failure("extension message has an invalid jsonrpc version"));
            return effects;
        }
        if object.contains_key("method") {
            let Some(Value::String(method)) = object.remove("method") else {
                effects.extend(self.protocol_failure("extension method is not a string"));
                return effects;
            };
            if object.contains_key("result") || object.contains_key("error") {
                effects.extend(self.protocol_failure("extension request contains response fields"));
                return effects;
            }
            if !(method == "onCDPEvent" && !object.contains_key("id")) {
                if let Some(raw) = params_json.as_ref() {
                    let value = match serde_json::from_str(raw.get()) {
                        Ok(value) => value,
                        Err(error) => {
                            effects.extend(self.protocol_failure(&format!(
                                "extension params decoding failed: {error}"
                            )));
                            return effects;
                        }
                    };
                    object.insert("params".to_owned(), value);
                }
            }
            if let Some(id) = object.remove("id") {
                if !valid_wire_id(&id) {
                    effects.extend(self.protocol_failure("extension request id is invalid"));
                    return effects;
                }
                let reply = if method == "ping" {
                    json!({ "jsonrpc": "2.0", "id": id, "result": "pong" })
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": "Maka host does not implement this extension method" } })
                };
                effects.push(RpcEvent::Send(reply));
            } else {
                let Some(sequence) = self.notification_sequence.checked_add(1) else {
                    effects
                        .extend(self.protocol_failure("extension notification sequence exhausted"));
                    return effects;
                };
                self.notification_sequence = sequence;
                if method == "onCDPEvent" && params_json.is_some() {
                    effects.push(RpcEvent::JsonNotification {
                        sequence,
                        method,
                        params_json: params_json.map(|raw| raw.get().to_owned()),
                    });
                } else {
                    effects.push(RpcEvent::Notification(Notification {
                        sequence,
                        method,
                        params: object.remove("params"),
                    }));
                }
            }
            return effects;
        }
        let Some(id) = object.remove("id") else {
            effects.extend(self.protocol_failure("extension response id is absent"));
            return effects;
        };
        if !valid_wire_id(&id) {
            effects.extend(self.protocol_failure("extension response id is invalid"));
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
        // Only this exact namespace/sequence/full-ID match produces this event.
        // These fields are minted request metadata, never incoming method/params.
        tracing::trace!(
            target: "maka::extension_rpc_phase",
            extension_host_pid = std::process::id(),
            extension_rpc_id = %pending.id,
            extension_method = pending.method.as_str(),
            phase = "reply_id_matched",
            "extension RPC phase"
        );
        effects.push(RpcEvent::Reply(complete_response_json(
            pending,
            object,
            result_json,
        )));
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
                    "extension RPC deadline expired; not replayed".to_owned(),
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

fn complete_response_json(
    pending: Pending,
    mut object: Map<String, Value>,
    result_json: Option<Box<RawValue>>,
) -> Completion {
    let Some(raw) = result_json else {
        return complete_response(pending, object);
    };
    if object.contains_key("error") {
        // Retain both-presence rejection, including result:null/error:null.
        return complete_response(pending, object);
    }
    if !pending.method.accepts_result_json(raw.get()) {
        return pending.failed(
            LossCause::Protocol,
            "extension result does not match the method's source-known top-level type".to_owned(),
        );
    }
    if matches!(
        pending.method,
        Method::ExecuteCdp
            | Method::GetUserTabs
            | Method::GetTabs
            | Method::CreateTab
            | Method::ClaimUserTab
    ) {
        return Completion {
            id: pending.id,
            method: pending.method,
            outcome: Ok(Reply::JsonText(raw.get().to_owned())),
        };
    }
    let value = match serde_json::from_str(raw.get()) {
        Ok(value) => value,
        Err(error) => {
            return pending.failed(
                LossCause::Protocol,
                format!("extension result decoding failed: {error}"),
            )
        }
    };
    object.insert("result".to_owned(), value);
    complete_response(pending, object)
}

fn complete_response(pending: Pending, mut object: Map<String, Value>) -> Completion {
    let result = object.remove("result");
    let error = object.remove("error");
    if result.is_some() && error.is_some() {
        return pending.failed(
            LossCause::Protocol,
            "extension reply contains both result and error".to_owned(),
        );
    }
    if let Some(error) = error {
        let Some(code) = error.get("code").and_then(Value::as_i64) else {
            return pending.failed(
                LossCause::Protocol,
                "extension error has no integer code".to_owned(),
            );
        };
        let Some(message) = error.get("message").and_then(Value::as_str) else {
            return pending.failed(
                LossCause::Protocol,
                "extension error has no message string".to_owned(),
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
                "extension result field is absent for a result-returning method".to_owned(),
            );
        }
        Some(value) if !pending.method.accepts_result(&value) => {
            return pending.failed(
                LossCause::Protocol,
                "extension result does not match the method's source-known top-level type"
                    .to_owned(),
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

    #[test]
    fn unwritten_discard_is_exact_and_does_not_reuse_ids_or_expire_the_other_call() {
        let now = Instant::now();
        let mut rpc = codec();
        let first = rpc
            .begin(Method::GetTabs, json!({}), now + Duration::from_secs(1))
            .unwrap();
        let sibling = rpc
            .begin(
                Method::GetUserTabs,
                json!({}),
                now + Duration::from_secs(10),
            )
            .unwrap();
        assert_eq!(rpc.discard_unwritten(&first.id), Some(Method::GetTabs));
        assert_eq!(rpc.discard_unwritten(&first.id), None);
        assert_eq!(rpc.pending_method(&sibling.id), Some(Method::GetUserTabs));
        assert!(rpc.expire(now + Duration::from_secs(2)).is_empty());
        let replacement = rpc
            .begin(Method::GetTabs, json!({}), now + Duration::from_secs(10))
            .unwrap();
        assert_ne!(first.id, replacement.id);
        assert_eq!(rpc.pending_len(), 2);
        assert!(matches!(
            &rpc.receive(
                json!({"jsonrpc":"2.0","id":first.id.as_str(),"result":[]}),
                now
            )[..],
            [RpcEvent::IgnoredReply { .. }]
        ));
        assert_eq!(rpc.pending_len(), 2);
    }

    fn one_reply(events: Vec<RpcEvent>) -> Completion {
        assert_eq!(events.len(), 1, "expected one effect, received {events:?}");
        match events.into_iter().next().expect("one effect was checked") {
            RpcEvent::Reply(reply) => reply,
            other => panic!("expected a reply effect, received {other:?}"),
        }
    }

    #[test]
    fn passive_match_trace_uses_exact_local_ids_not_payload_or_expiry() {
        use super::super::extension_wire::rpc_phase_test::Capture;
        let capture = Capture::default();
        let now = Instant::now();
        let mut rpc = codec();
        let first = rpc
            .begin(
                Method::ClaimUserTab,
                json!({"url":"URL_SENTINEL","headers":"HEADER_SENTINEL"}),
                now + Duration::from_secs(1),
            )
            .unwrap();
        let second = rpc
            .begin(Method::GetUserTabs, json!({}), now + Duration::from_secs(1))
            .unwrap();
        tracing::subscriber::with_default(capture.clone(), || {
            let _ = rpc.receive(
                json!({"jsonrpc":"2.0","id":"foreign-generation:1","result":"RESULT_SENTINEL"}),
                now,
            );
            let _ = rpc.receive(json!({"jsonrpc":"2.0","method":"NOTIFICATION_SENTINEL","params":{"headers":"HEADER_SENTINEL"}}), now);
            assert!(capture.rows().is_empty());
            let response = one_reply(rpc.receive(
                json!({"jsonrpc":"2.0","id":second.id.as_str(),"result":[]}),
                now,
            ));
            assert!(response.outcome.is_ok());
            let malformed = one_reply(rpc.receive(
                json!({"jsonrpc":"2.0","id":first.id.as_str(),"result":"RESULT_SENTINEL"}),
                now,
            ));
            assert!(matches!(
                malformed.outcome,
                Err(RpcError::OutcomeUnknown {
                    cause: LossCause::Protocol,
                    ..
                })
            ));
            let _ = rpc.receive(
                json!({"jsonrpc":"2.0","id":first.id.as_str(),"result":{}}),
                now,
            );
            let remote = rpc
                .begin(Method::GetInfo, json!({}), now + Duration::from_secs(1))
                .unwrap();
            let failed = one_reply(rpc.receive(json!({"jsonrpc":"2.0","id":remote.id.as_str(),"error":{"code":1,"message":"ERROR_MESSAGE_SENTINEL","data":{"headers":"ERROR_DATA_SENTINEL"}}}), now));
            assert!(matches!(failed.outcome, Err(RpcError::Remote(_))));
            let expired = rpc.begin(Method::ClaimUserTab, json!({}), now).unwrap();
            let _ = rpc.receive(
                json!({"jsonrpc":"2.0","id":expired.id.as_str(),"result":{}}),
                now,
            );
            let _ = rpc.eof("EOF_SENTINEL");
        });
        let rows = capture.rows();
        assert_eq!(
            rows.len(),
            3,
            "unmatched/duplicate/expired IDs cannot manufacture reply matches"
        );
        assert_eq!(rows[0]["extension_rpc_id"], second.id.as_str());
        assert_eq!(rows[1]["extension_rpc_id"], first.id.as_str());
        assert!(rows.iter().all(|row| row["phase"] == "reply_id_matched"
            && row["extension_host_pid"] == std::process::id().to_string()));
        let rendered = format!("{rows:?}");
        for forbidden in [
            "URL_SENTINEL",
            "HEADER_SENTINEL",
            "RESULT_SENTINEL",
            "NOTIFICATION_SENTINEL",
            "EOF_SENTINEL",
            "ERROR_MESSAGE_SENTINEL",
            "ERROR_DATA_SENTINEL",
        ] {
            assert!(!rendered.contains(forbidden), "trace disclosed {forbidden}");
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
            "extension heartbeat must not consume a pending host call"
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
        let eof = codec.eof("extension port EOF");
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
            "invalid extension envelope must be reported"
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
    #[test]
    fn raw_results_match_the_original_pending_method_and_preserve_lone_surrogates() {
        let now = Instant::now();
        let mut rpc = codec();
        let first = rpc
            .begin(Method::GetTabs, json!({}), now + Duration::from_secs(1))
            .unwrap();
        let second = rpc
            .begin(Method::ExecuteCdp, json!({}), now + Duration::from_secs(1))
            .unwrap();
        let text = format!(
            r#"{{"jsonrpc":"2.0","id":{},"result":[{{"id":17,"title":"\ud800"}}]}}"#,
            serde_json::to_string(first.id.as_str()).unwrap()
        );
        let raw: &RawValue = serde_json::from_str(&text).unwrap();
        let completion = one_reply(rpc.receive_json(raw, now));
        assert_eq!(completion.id, first.id);
        assert_eq!(completion.method, Method::GetTabs);
        assert!(
            matches!(completion.outcome, Ok(Reply::JsonText(ref body)) if body == r#"[{"id":17,"title":"\ud800"}]"#)
        );
        assert_eq!(rpc.pending_len(), 1);
        let stale = rpc.receive_json(raw, now);
        assert!(matches!(stale.as_slice(), [RpcEvent::IgnoredReply { .. }]));
        let remaining = format!(
            r#"{{"jsonrpc":"2.0","id":{},"result":{{"node":{{"backendNodeId":17,"attributes":["title","\udc00"]}}}}}}"#,
            serde_json::to_string(second.id.as_str()).unwrap()
        );
        let completion =
            one_reply(rpc.receive_json(serde_json::from_str(&remaining).unwrap(), now));
        assert_eq!(completion.id, second.id);
        assert!(matches!(completion.outcome, Ok(Reply::JsonText(_))));
        assert_eq!(rpc.pending_len(), 0);
    }

    #[test]
    fn raw_outer_map_keeps_null_presence_extra_fields_and_last_wins() {
        let now = Instant::now();
        for (suffix, expected) in [
            ("", Some(VoidAck::IdOnly)),
            (r#", "result":null"#, Some(VoidAck::ExplicitNull)),
            (r#", "result":null,"error":null"#, None),
            (r#", "error":null"#, None),
            (r#", "unused":0"#, None),
            (r#", "method":null"#, None),
        ] {
            let mut rpc = codec();
            let request = rpc
                .begin(Method::NameSession, json!({}), now + Duration::from_secs(1))
                .unwrap();
            let text = format!(
                r#"{{"jsonrpc":"2.0","id":{}{suffix}}}"#,
                serde_json::to_string(request.id.as_str()).unwrap()
            );
            let rows = rpc.receive_json(serde_json::from_str(&text).unwrap(), now);
            let completion = rows
                .into_iter()
                .find_map(|row| match row {
                    RpcEvent::Reply(completion) => Some(completion),
                    _ => None,
                })
                .unwrap();
            match expected {
                Some(expected) => {
                    assert_eq!(completion.outcome, Ok(Reply::Void(expected)), "{suffix}")
                }
                None => assert!(completion.outcome.is_err(), "{suffix}"),
            }
        }
        let mut rpc = codec();
        let request = rpc
            .begin(Method::NameSession, json!({}), now + Duration::from_secs(1))
            .unwrap();
        let text = format!(
            r#"{{"jsonrpc":"2.0","id":{},"result":false,"result":null}}"#,
            serde_json::to_string(request.id.as_str()).unwrap()
        );
        assert_eq!(
            one_reply(rpc.receive_json(serde_json::from_str(&text).unwrap(), now)).outcome,
            Ok(Reply::Void(VoidAck::ExplicitNull))
        );
    }

    #[test]
    fn raw_notifications_keep_the_same_sequence_and_unexpanded_cdp_params() {
        let now = Instant::now();
        let mut rpc = codec();
        let raw: &RawValue = serde_json::from_str(r#"{"jsonrpc":"2.0","method":"onCDPEvent","params":{"method":"Target.attachedToTarget","params":{"targetInfo":{"title":"\ud800"}}}}"#).unwrap();
        assert!(
            matches!(rpc.receive_json(raw, now).as_slice(), [RpcEvent::JsonNotification { sequence:1, method, params_json:Some(text) }] if method == "onCDPEvent" && text.contains(r#"\ud800"#))
        );
        assert!(matches!(
            rpc.receive_json(raw, now).as_slice(),
            [RpcEvent::JsonNotification { sequence: 2, .. }]
        ));
    }
    #[test]
    fn raw_json_parser_keeps_surrogates_without_accepting_malformed_escapes() {
        for text in [
            r#""\ud800""#,
            r#""\udc00""#,
            r#"{"value":"\ud800","\udc00":null}"#,
        ] {
            assert!(serde_json::from_str::<Value>(text).is_err(), "{text}");
            let raw: Box<RawValue> = serde_json::from_str(text).unwrap();
            assert_eq!(raw.get(), text);
            assert!(serde_json::from_str::<serde::de::IgnoredAny>(text).is_ok());
            let encoded = serde_json::to_string(&raw.get()).unwrap();
            assert_eq!(serde_json::from_str::<String>(&encoded).unwrap(), text);
        }
        for text in [r#""\ud800\!""#, r#""\ud800\u""#] {
            assert!(
                serde_json::from_str::<Box<RawValue>>(text).is_err(),
                "{text}"
            );
            assert!(
                serde_json::from_str::<serde::de::IgnoredAny>(text).is_err(),
                "{text}"
            );
        }
        assert_eq!(
            serde_json::from_str::<String>(r#""\ud83d\ude00""#).unwrap(),
            "😀"
        );
        assert_eq!(
            serde_json::from_str::<String>(r#""\\ud800""#).unwrap(),
            r#"\ud800"#
        );
    }
}
