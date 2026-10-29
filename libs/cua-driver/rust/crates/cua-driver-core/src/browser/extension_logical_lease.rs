// SPDX-License-Identifier: MIT

//! Browser-session retention metadata. None of these fields is a physical claim
//! or permission to acquire, prepare, read, or clean up a tab.

use serde::{Deserialize, Serialize};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionLogicalLeaseOrigin {
    AgentCreated,
    UserClaimed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtensionLogicalLeasePhase {
    Live,
    Handoff,
}

/// A validated projection of the connector's existing logical resource record.
/// It deliberately contains no owner-connection, physical token, or grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "LogicalLeaseWire", into = "LogicalLeaseWire")]
pub struct ExtensionLogicalLease {
    pub chrome_session_id: String,
    pub logical_lease_id: String,
    pub tab_id: u64,
    pub host_session_id: String,
    pub host_turn_id: String,
    pub origin: ExtensionLogicalLeaseOrigin,
    pub status: Option<super::ExtensionKeepStatus>,
    pub phase: ExtensionLogicalLeasePhase,
    pub sequence: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LogicalLeaseWire {
    chrome_session_id: String,
    logical_lease_id: String,
    tab_id: u64,
    host_session_id: String,
    host_turn_id: String,
    origin: ExtensionLogicalLeaseOrigin,
    #[serde(deserialize_with = "required_status")]
    status: Option<super::ExtensionKeepStatus>,
    phase: ExtensionLogicalLeasePhase,
    sequence: u64,
}

fn required_status<'de, D>(deserializer: D) -> Result<Option<super::ExtensionKeepStatus>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<super::ExtensionKeepStatus>::deserialize(deserializer)
}

fn valid_scope(value: &str) -> bool {
    // ECMAScript String.prototype.trim's WhiteSpace and LineTerminator set.
    let space = |ch: char| {
        matches!(ch, '\u{0009}'..='\u{000d}' | '\u{0020}' | '\u{00a0}'
        | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}'
        | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}')
    };
    value.encode_utf16().count() <= 4096 && !value.trim_matches(space).is_empty()
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value)
}

impl TryFrom<LogicalLeaseWire> for ExtensionLogicalLease {
    type Error = &'static str;

    fn try_from(wire: LogicalLeaseWire) -> Result<Self, Self::Error> {
        if !canonical_uuid(&wire.chrome_session_id)
            || !canonical_uuid(&wire.logical_lease_id)
            || !(1..=MAX_SAFE_INTEGER).contains(&wire.tab_id)
            || !(1..=MAX_SAFE_INTEGER).contains(&wire.sequence)
            || !valid_scope(&wire.host_session_id)
            || !valid_scope(&wire.host_turn_id)
            || (wire.phase == ExtensionLogicalLeasePhase::Handoff && wire.status.is_some())
        {
            return Err("invalid logical lease projection");
        }
        Ok(Self {
            chrome_session_id: wire.chrome_session_id,
            logical_lease_id: wire.logical_lease_id,
            tab_id: wire.tab_id,
            host_session_id: wire.host_session_id,
            host_turn_id: wire.host_turn_id,
            origin: wire.origin,
            status: wire.status,
            phase: wire.phase,
            sequence: wire.sequence,
        })
    }
}

impl From<ExtensionLogicalLease> for LogicalLeaseWire {
    fn from(lease: ExtensionLogicalLease) -> Self {
        Self {
            chrome_session_id: lease.chrome_session_id,
            logical_lease_id: lease.logical_lease_id,
            tab_id: lease.tab_id,
            host_session_id: lease.host_session_id,
            host_turn_id: lease.host_turn_id,
            origin: lease.origin,
            status: lease.status,
            phase: lease.phase,
            sequence: lease.sequence,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionReleasedLogicalLease {
    pub logical_lease_id: String,
    pub tab_id: u64,
    pub origin: ExtensionLogicalLeaseOrigin,
    #[serde(deserialize_with = "required_status")]
    pub status: Option<super::ExtensionKeepStatus>,
}

/// An acknowledgement of the logical projection commit after Host cleanup.
/// This never substitutes for detach, draining, or physical retirement proof.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionLogicalLeaseCommit {
    pub chrome_session_id: String,
    pub kept: Vec<ExtensionLogicalLease>,
    pub released: Vec<ExtensionReleasedLogicalLease>,
}

impl ExtensionLogicalLeaseCommit {
    pub(super) fn matches(&self, session: &str, turn: &str) -> bool {
        let mut tabs = std::collections::HashSet::new();
        let mut leases = std::collections::HashSet::new();
        canonical_uuid(&self.chrome_session_id)
            && self.kept.iter().all(|lease| {
                lease.chrome_session_id == self.chrome_session_id
                    && lease.host_session_id == session
                    && lease.host_turn_id == turn
                    && lease.phase == ExtensionLogicalLeasePhase::Handoff
                    && lease.status.is_none()
                    && tabs.insert(lease.tab_id)
                    && leases.insert(lease.logical_lease_id.as_str())
            })
            && self.released.iter().all(|lease| {
                canonical_uuid(&lease.logical_lease_id)
                    && (1..=MAX_SAFE_INTEGER).contains(&lease.tab_id)
                    && lease.status != Some(super::ExtensionKeepStatus::Handoff)
                    && tabs.insert(lease.tab_id)
                    && leases.insert(lease.logical_lease_id.as_str())
            })
    }
}
