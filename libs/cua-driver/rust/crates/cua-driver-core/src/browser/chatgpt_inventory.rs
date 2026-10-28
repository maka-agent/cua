// SPDX-License-Identifier: MIT

//! Validates Chatgpt full extension inventory and narrowly scopes Created-tab absence observations.
//!
//! Private source proposal; authored tests have not been compiled or executed.
//! Source basis: current retained background.js `getUserTabs({})` selects `Uw`
//! then `pu({})`, with no query/protocol/incognito filter and a 1000-row cap.
//! Supplying limit/query/includeFavicons selects a different search path; that
//! path cannot establish the full-inventory observation used here.

use std::collections::HashSet;
use std::error::Error;
use std::fmt;

use serde_json::Value;

/// Extension full inventory silently caps its already sorted result at this size.
pub(crate) const FULL_INVENTORY_CAP: usize = 1000;
/// Chrome integer IDs must also survive their JavaScript number representation exactly.
const MAX_SAFE_TAB_ID: u64 = 9_007_199_254_740_991;

/// Retains original row order and fields without inventing timestamps or window metadata.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Inventory {
    rows: Vec<Value>,
    ids: HashSet<u64>,
}

impl Inventory {
    /// Borrows the exact validated extension rows, including lastOpened and providerTabId.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn rows(&self) -> &[Value] {
        &self.rows
    }

    /// Transfers rows to the adapter without reordering or changing unknown metadata fields.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn into_rows(self) -> Vec<Value> {
        self.rows
    }

    /// Returns the actual row count, including the saturation boundary.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.rows.len()
    }

    /// Reports whether the matched extension observation contained no tabs.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Checks one raw browser-session ID without using URL/title as identity.
    #[must_use]
    pub(crate) fn contains_tab(&self, raw_tab_id: u64) -> bool {
        self.ids.contains(&raw_tab_id)
    }
}

/// Invalid source shape cannot produce any absence proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InventoryError {
    NotArray,
    TooManyRows { count: usize },
    RowNotObject { index: usize },
    InvalidTabId { index: usize },
    DuplicateTabId { raw_tab_id: u64 },
}

impl fmt::Display for InventoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotArray => formatter.write_str("extension full inventory is not an array"),
            Self::TooManyRows { count } => write!(
                formatter,
                "extension inventory exceeds the source cap: {count} rows"
            ),
            Self::RowNotObject { index } => {
                write!(
                    formatter,
                    "extension inventory row {index} is not an object"
                )
            }
            Self::InvalidTabId { index } => write!(
                formatter,
                "extension inventory row {index} has no nonnegative safe integer tab id"
            ),
            Self::DuplicateTabId { raw_tab_id } => write!(
                formatter,
                "extension inventory repeats raw tab id {raw_tab_id}"
            ),
        }
    }
}

impl Error for InventoryError {}

/// Validates the source-known full inventory shape; it does not itself observe a live query.
///
/// The caller must obtain this value from the exact matched extension
/// `getUserTabs` request with an empty object params payload. No timestamp is
/// created, and the source's existing order/metadata is preserved verbatim.
///
/// # Errors
/// Rejects nonarrays, more than 1000 rows, invalid IDs and duplicate raw IDs.
pub(crate) fn authoritative_inventory(value: Value) -> Result<Inventory, InventoryError> {
    let Value::Array(rows) = value else {
        return Err(InventoryError::NotArray);
    };
    if rows.len() > FULL_INVENTORY_CAP {
        return Err(InventoryError::TooManyRows { count: rows.len() });
    }
    let mut ids = HashSet::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        if !row.is_object() {
            return Err(InventoryError::RowNotObject { index });
        }
        let id = row
            .get("id")
            .and_then(Value::as_u64)
            .filter(|id| valid_metadata_tab_id(*id))
            .ok_or(InventoryError::InvalidTabId { index })?;
        if !ids.insert(id) {
            return Err(InventoryError::DuplicateTabId { raw_tab_id: id });
        }
    }
    Ok(Inventory { rows, ids })
}

/// Both lifetime fields must remain exactly equal across creation and observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EndpointIdentity {
    pub(crate) generation: String,
    pub(crate) extension_instance_id: String,
}

/// A trusted retained Created receipt, never a user claim or a model-supplied declaration.
#[derive(Debug, Clone, Copy)]
pub(crate) struct KnownCreated<'a> {
    pub(crate) owner: &'a str,
    pub(crate) host_session_id: &'a str,
    pub(crate) raw_tab_id: u64,
    pub(crate) endpoint: &'a EndpointIdentity,
}

/// The exact authenticated caller and raw ID that requested observation of its receipt.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Caller<'a> {
    pub(crate) owner: &'a str,
    pub(crate) host_session_id: &'a str,
    pub(crate) raw_tab_id: u64,
}

/// Freshness comes only from the serialized host workflow, never from a extension timestamp.
#[derive(Debug, Clone, Copy)]
pub(crate) struct InventoryFreshness<'a> {
    /// Only construct after the exact newly dispatched response was matched
    /// in the same live endpoint; JSON/timestamps cannot prove this boundary.
    pub(crate) extension_request_id: &'a str,
}

/// Groups the host's immutable receipt and current matched-observation boundary.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AbsenceEvidence<'a> {
    pub(crate) expected_endpoint: &'a EndpointIdentity,
    pub(crate) observed_endpoint: &'a EndpointIdentity,
    pub(crate) known_created: KnownCreated<'a>,
    pub(crate) caller: Caller<'a>,
    pub(crate) freshness: Option<InventoryFreshness<'a>>,
}

/// A bounded TabAbsenceObserved record, distinct from detach ACK or close ACK evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AbsentProof {
    owner: String,
    host_session_id: String,
    raw_tab_id: u64,
    endpoint: EndpointIdentity,
    extension_request_id: String,
}

impl AbsentProof {
    /// Names the observed evidence without claiming which operation removed the tab.
    #[must_use]
    pub(crate) const fn evidence_name(&self) -> &'static str {
        "tab_absence_observed"
    }

    #[must_use]
    pub(crate) fn owner(&self) -> &str {
        &self.owner
    }
    #[must_use]
    pub(crate) fn host_session_id(&self) -> &str {
        &self.host_session_id
    }
    #[must_use]
    pub(crate) const fn raw_tab_id(&self) -> u64 {
        self.raw_tab_id
    }
    #[must_use]
    pub(crate) fn endpoint(&self) -> &EndpointIdentity {
        &self.endpoint
    }
    #[must_use]
    pub(crate) fn extension_request_id(&self) -> &str {
        &self.extension_request_id
    }
}

/// An unsuccessful observation keeps physical cleanup unknown; it is never evidence of presence or closure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AbsenceUnknown {
    UnfreshObservation,
    InvalidEndpointIdentity,
    EndpointGenerationChanged,
    ExtensionInstanceChanged,
    CreatedEndpointChanged,
    InvalidCreatedReceipt,
    ForeignOwner,
    ForeignSession,
    ForeignTab,
    ObservationRequestChanged,
    SaturatedInventory,
    TabStillPresent,
}

impl fmt::Display for AbsenceUnknown {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnfreshObservation => "inventory has no fresh matched extension reply boundary",
            Self::InvalidEndpointIdentity => "endpoint identity is missing or invalid",
            Self::EndpointGenerationChanged => "extension endpoint generation changed",
            Self::ExtensionInstanceChanged => "extension instance changed",
            Self::CreatedEndpointChanged => "created receipt belongs to another endpoint lifetime",
            Self::InvalidCreatedReceipt => "created receipt identity is invalid",
            Self::ForeignOwner => "created receipt belongs to another authenticated owner",
            Self::ForeignSession => "created receipt belongs to another Host session",
            Self::ForeignTab => "caller raw tab id differs from the created receipt",
            Self::ObservationRequestChanged => {
                "inventory request id belongs to another extension namespace"
            }
            Self::SaturatedInventory => {
                "inventory reached its source cap and may omit the created tab"
            }
            Self::TabStillPresent => "created tab remains in the matched extension inventory",
        })
    }
}

impl Error for AbsenceUnknown {}

/// Confirms a known Created ID was absent from an unsaturated same-instance fresh observation.
///
/// This does not establish that `turnEnded` closed it, that a debugger detached,
/// or that arbitrary browser state is clean. A count of exactly 1000 remains
/// unknown because the original source can truncate its full inventory there.
///
/// # Errors
/// Keeps cleanup unknown if freshness, endpoint, ownership, ID, completeness or absence is unproved.
pub(crate) fn prove_created_absent(
    inventory: &Inventory,
    evidence: AbsenceEvidence<'_>,
) -> Result<AbsentProof, AbsenceUnknown> {
    let Some(InventoryFreshness {
        extension_request_id,
    }) = evidence.freshness
    else {
        return Err(AbsenceUnknown::UnfreshObservation);
    };
    let expected = evidence.expected_endpoint;
    let observed = evidence.observed_endpoint;
    if !valid_generation(&expected.generation)
        || expected.extension_instance_id.trim().is_empty()
        || observed.extension_instance_id.trim().is_empty()
    {
        return Err(AbsenceUnknown::InvalidEndpointIdentity);
    }
    if expected.generation != observed.generation {
        return Err(AbsenceUnknown::EndpointGenerationChanged);
    }
    if expected.extension_instance_id != observed.extension_instance_id {
        return Err(AbsenceUnknown::ExtensionInstanceChanged);
    }
    let created = evidence.known_created;
    if created.endpoint != expected {
        return Err(AbsenceUnknown::CreatedEndpointChanged);
    }
    if created.owner.trim().is_empty()
        || created.host_session_id.trim().is_empty()
        || !valid_created_tab_id(created.raw_tab_id)
    {
        return Err(AbsenceUnknown::InvalidCreatedReceipt);
    }
    if created.owner != evidence.caller.owner {
        return Err(AbsenceUnknown::ForeignOwner);
    }
    if created.host_session_id != evidence.caller.host_session_id {
        return Err(AbsenceUnknown::ForeignSession);
    }
    if created.raw_tab_id != evidence.caller.raw_tab_id {
        return Err(AbsenceUnknown::ForeignTab);
    }
    let prefix = format!("maka-original-compat:{}:", expected.generation);
    let valid_request = extension_request_id
        .strip_prefix(prefix.as_str())
        .and_then(|sequence| {
            sequence
                .parse::<u64>()
                .ok()
                .filter(|id| *id > 0)
                .map(|id| id.to_string() == sequence)
        })
        .unwrap_or(false);
    if !valid_request {
        return Err(AbsenceUnknown::ObservationRequestChanged);
    }
    if inventory.len() == FULL_INVENTORY_CAP {
        return Err(AbsenceUnknown::SaturatedInventory);
    }
    if inventory.contains_tab(created.raw_tab_id) {
        return Err(AbsenceUnknown::TabStillPresent);
    }
    Ok(AbsentProof {
        owner: created.owner.to_owned(),
        host_session_id: created.host_session_id.to_owned(),
        raw_tab_id: created.raw_tab_id,
        endpoint: expected.clone(),
        extension_request_id: extension_request_id.to_owned(),
    })
}

fn valid_created_tab_id(id: u64) -> bool {
    id > 0 && id <= MAX_SAFE_TAB_ID
}

fn valid_metadata_tab_id(id: u64) -> bool {
    id <= MAX_SAFE_TAB_ID
}
fn valid_generation(generation: &str) -> bool {
    !generation.is_empty()
        && generation.len() <= 128
        && generation
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn endpoint() -> EndpointIdentity {
        EndpointIdentity {
            generation: "generation-one".to_owned(),
            extension_instance_id: "actual-instance".to_owned(),
        }
    }
    fn evidence<'a>(endpoint: &'a EndpointIdentity) -> AbsenceEvidence<'a> {
        AbsenceEvidence {
            expected_endpoint: endpoint,
            observed_endpoint: endpoint,
            known_created: KnownCreated {
                owner: "owner",
                host_session_id: "Host-session",
                raw_tab_id: 2000,
                endpoint,
            },
            caller: Caller {
                owner: "owner",
                host_session_id: "Host-session",
                raw_tab_id: 2000,
            },
            freshness: Some(InventoryFreshness {
                extension_request_id: "maka-original-compat:generation-one:42",
            }),
        }
    }

    #[test]
    fn original_rows_preserve_order_and_metadata_without_inventing_fields() {
        let rows = json!([{"id":9,"lastOpened":"2026-10-27T03:00:00.000Z","providerTabId":"opaque-nine"},{"id":3,"title":"existing"}]);
        let inventory = authoritative_inventory(rows.clone()).expect("valid actual inventory");
        assert_eq!(
            inventory.rows(),
            rows.as_array().expect("test array"),
            "source order and opaque fields must survive"
        );
        assert!(
            !inventory.rows()[0]
                .as_object()
                .expect("test row")
                .contains_key("lastAccessed"),
            "no clock may be invented"
        );
        assert_eq!(
            inventory.into_rows(),
            rows.as_array().expect("test array").clone(),
            "owning extraction must preserve every field"
        );
    }

    #[test]
    fn invalid_duplicate_and_out_of_range_inventory_cannot_be_authoritative() {
        for value in [
            json!({}),
            json!([null]),
            json!([{"id":-1}]),
            json!([{"id":1.5}]),
            json!([{"id":9_007_199_254_740_992_u64}]),
            json!([{"id":7},{"id":7}]),
        ] {
            assert!(
                authoritative_inventory(value.clone()).is_err(),
                "invalid inventory {value:?}"
            );
        }
        let over: Vec<_> = (1..=1001).map(|id| json!({"id":id})).collect();
        assert!(
            matches!(
                authoritative_inventory(Value::Array(over)),
                Err(InventoryError::TooManyRows { count: 1001 })
            ),
            "source-cap violation must not be silently truncated"
        );
        let zero = authoritative_inventory(json!([{"id":0,"title":"actual metadata"}]))
            .expect("ChatGPT Jb accepts a nonnegative safe metadata id");
        assert_eq!(
            zero.rows()[0]["id"],
            0,
            "metadata id zero must be preserved"
        );
    }

    #[test]
    fn absence_at_999_is_observable_but_1000_is_unknown() {
        let identity = endpoint();
        for count in [999, 1000] {
            let rows: Vec<_> = (1..=count).map(|id| json!({"id":id})).collect();
            let inventory =
                authoritative_inventory(Value::Array(rows)).expect("source-bounded inventory");
            let result = prove_created_absent(&inventory, evidence(&identity));
            if count == 999 {
                let proof = result.expect("unsaturated exact Created absence");
                assert_eq!(
                    proof.evidence_name(),
                    "tab_absence_observed",
                    "proof must name observation, not close ACK"
                );
                assert_eq!(
                    proof.raw_tab_id(),
                    2000,
                    "proof must retain exact Created ID"
                );
            } else {
                assert_eq!(
                    result,
                    Err(AbsenceUnknown::SaturatedInventory),
                    "1000 rows cannot prove absence beyond truncation"
                );
            }
        }
    }

    #[test]
    fn endpoint_generation_and_extension_instance_changes_keep_cleanup_unknown() {
        let identity = endpoint();
        let inventory = authoritative_inventory(json!([])).expect("empty valid inventory");
        let mut generation_changed = identity.clone();
        generation_changed.generation = "new-generation".to_owned();
        let mut request = evidence(&identity);
        request.observed_endpoint = &generation_changed;
        assert_eq!(
            prove_created_absent(&inventory, request),
            Err(AbsenceUnknown::EndpointGenerationChanged),
            "reconnect cannot prove old Created gone"
        );
        let mut instance_changed = identity.clone();
        instance_changed.extension_instance_id = "new-instance".to_owned();
        let mut request = evidence(&identity);
        request.observed_endpoint = &instance_changed;
        assert_eq!(
            prove_created_absent(&inventory, request),
            Err(AbsenceUnknown::ExtensionInstanceChanged),
            "worker/browser instance change cannot prove old raw ID gone"
        );
        let mut request = evidence(&identity);
        request.known_created.endpoint = &generation_changed;
        assert_eq!(
            prove_created_absent(&inventory, request),
            Err(AbsenceUnknown::CreatedEndpointChanged),
            "a fresh current snapshot cannot reconcile a Created receipt from an old endpoint"
        );
    }

    #[test]
    fn foreign_owner_session_or_tab_cannot_observe_someone_elses_created_receipt() {
        let identity = endpoint();
        let inventory = authoritative_inventory(json!([])).expect("empty inventory");
        let mut request = evidence(&identity);
        request.caller.owner = "other";
        assert_eq!(
            prove_created_absent(&inventory, request),
            Err(AbsenceUnknown::ForeignOwner),
            "owner must match"
        );
        request = evidence(&identity);
        request.caller.host_session_id = "other-session";
        assert_eq!(
            prove_created_absent(&inventory, request),
            Err(AbsenceUnknown::ForeignSession),
            "Host session must match"
        );
        request = evidence(&identity);
        request.caller.raw_tab_id = 2001;
        assert_eq!(
            prove_created_absent(&inventory, request),
            Err(AbsenceUnknown::ForeignTab),
            "raw ID must match exact Created receipt"
        );
        request = evidence(&identity);
        request.known_created.raw_tab_id = 0;
        request.caller.raw_tab_id = 0;
        assert_eq!(
            prove_created_absent(&inventory, request),
            Err(AbsenceUnknown::InvalidCreatedReceipt),
            "Created cleanup receipts still require a positive raw tab ID"
        );
    }

    #[test]
    fn stale_unmatched_or_present_observations_never_become_absence_proof() {
        let identity = endpoint();
        let empty = authoritative_inventory(json!([])).expect("empty inventory");
        let mut request = evidence(&identity);
        request.freshness = None;
        assert_eq!(
            prove_created_absent(&empty, request),
            Err(AbsenceUnknown::UnfreshObservation),
            "cached data is not fresh evidence"
        );
        for id in [
            "maka-original-compat:other-generation:42",
            "maka-original-compat:generation-one:0",
            "maka-original-compat:generation-one:042",
        ] {
            request = evidence(&identity);
            request.freshness = Some(InventoryFreshness {
                extension_request_id: id,
            });
            assert_eq!(
                prove_created_absent(&empty, request),
                Err(AbsenceUnknown::ObservationRequestChanged),
                "request namespace {id:?} must be exact"
            );
        }
        let present =
            authoritative_inventory(json!([{"id":2000}])).expect("present Created inventory");
        assert_eq!(
            prove_created_absent(&present, evidence(&identity)),
            Err(AbsenceUnknown::TabStillPresent),
            "presence does not prove cleanup"
        );
    }
}
