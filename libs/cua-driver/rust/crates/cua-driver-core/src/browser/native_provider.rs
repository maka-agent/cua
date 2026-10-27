// SPDX-License-Identifier: MIT

//! Trusted Rust-host facade for one current-user native browser connection.
//!
//! This module owns transport correlation and a claim-channel pool only. The
//! embedding host owns tab origin, logical session/turn authority and consent.
//! A canceled control mutation is never replayed: its completion stays in the
//! bounded pending-operation map until Host-ledger application and acknowledgement.
//! Broker-observed orphan CDP replies are retained there too. Generic CDP calls
//! retain Cua PendingCall's unknown/no-replay behavior; a reply queued before
//! waiter cancellation has no new consumed-ACK guarantee. Empty control snapshots
//! do not settle CDP input. IPC EOF is not a physical cleanup proof.

use super::cdp_ws::{CdpConnection, NativeCdpCommand, NativeCdpInbound};
use super::local_ipc::{self, IpcError, NativeEndpointIdentity, ValidatedNativeEndpoint};
use super::native_process::{NativeAdapterSelection, NativeAdapterSelectionError};
use super::native_wire::NativeWireContext;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::sync::{broadcast, mpsc, oneshot};

const REQUEST_BUDGET: usize = 64;
const ACTOR_QUEUE: usize = 128;
const ROUTE_QUEUE: usize = 64;
const EVENT_QUEUE: usize = 128;
const MAX_RETAINED_RECEIPTS: usize = 256;
const MAX_PENDING_NATIVE_CONTEXTS: usize = 4096;
const IPC_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Discovery reports rejected/stale records without weakening endpoint checks.
#[derive(Clone, Debug)]
pub struct NativeEndpointRejection {
    pub descriptor_path: std::path::PathBuf,
    pub reason: String,
}
#[derive(Clone, Debug)]
pub struct NativeEndpointDiscovery {
    pub endpoints: Vec<ValidatedNativeEndpoint>,
    pub rejected: Vec<NativeEndpointRejection>,
}
/// Read only the own adapter's installation-selected private runtime directory.
/// No executable, endpoint URL or descriptor path is accepted from a tool call.
/// Other adapter records are not promoted to an own claim-capable provider.
pub async fn discover_registered_endpoints() -> Result<NativeEndpointDiscovery, IpcError> {
    discover_registered(super::native_host::OWN_HOST_NAME).await
}
/// Select an adapter name only from trusted installation configuration.
/// This is not a tool/model parameter and accepts no descriptor or socket path.
pub async fn discover_registered(
    expected_adapter: &str,
) -> Result<NativeEndpointDiscovery, IpcError> {
    if expected_adapter.is_empty()
        || expected_adapter.starts_with('.')
        || expected_adapter.ends_with('.')
        || expected_adapter.contains("..")
        || !expected_adapter.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.')
        })
    {
        return Err(IpcError::Rejected(
            "trusted registered adapter namespace is invalid".into(),
        ));
    }
    let expected = expected_adapter.to_owned();
    tokio::task::spawn_blocking(move || discover_registered_endpoints_blocking(&expected))
        .await
        .map_err(|error| {
            IpcError::Io(std::io::Error::other(format!(
                "native discovery task failed: {error}"
            )))
        })?
}
fn discover_registered_endpoints_blocking(
    expected_adapter: &str,
) -> Result<NativeEndpointDiscovery, IpcError> {
    let directory = local_ipc::current_user_runtime_directory()?;
    discover_directory_blocking(&directory, expected_adapter, None)
}
fn discover_directory_blocking(
    directory: &std::path::Path,
    expected_adapter: &str,
    expected_extension: Option<&str>,
) -> Result<NativeEndpointDiscovery, IpcError> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(NativeEndpointDiscovery {
                endpoints: Vec::new(),
                rejected: Vec::new(),
            })
        }
        Err(error) => return Err(error.into()),
    };
    local_ipc::validate_runtime_directory(directory)?;
    let mut result = NativeEndpointDiscovery {
        endpoints: Vec::new(),
        rejected: Vec::new(),
    };
    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|value| value.to_str()) else {
            continue;
        };
        let Ok(generation) = uuid::Uuid::parse_str(stem) else {
            continue;
        };
        if generation.to_string() != stem {
            continue;
        }
        match ValidatedNativeEndpoint::load(&path, expected_adapter) {
            Ok(endpoint) => {
                if expected_extension
                    .is_some_and(|extension| endpoint.identity().extension_id != extension)
                {
                    result.rejected.push(NativeEndpointRejection {
                        descriptor_path: path,
                        reason: "descriptor extension differs from the installed registration"
                            .into(),
                    });
                } else {
                    result.endpoints.push(endpoint);
                }
            }
            Err(error) => result.rejected.push(NativeEndpointRejection {
                descriptor_path: path,
                reason: error.to_string(),
            }),
        }
    }
    result
        .endpoints
        .sort_by(|left, right| left.identity().generation.cmp(&right.identity().generation));
    Ok(result)
}

/// Responsibility/capability metadata. These fields grant no authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NativeEffectOwner {
    Host,
    Provider,
    Unavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NativeUserTabsOrder {
    Host,
    Provider,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NativeHeaderPolicyScope {
    Claim,
    Session,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeProviderCapabilities {
    pub user_tabs_order: NativeUserTabsOrder,
    pub header_scope: NativeHeaderPolicyScope,
    pub created_presentation_owner: NativeEffectOwner,
    pub cursor_presentation_owner: NativeEffectOwner,
    pub cursor_hide_owner: NativeEffectOwner,
    pub turn_lifecycle_owner: NativeEffectOwner,
    #[serde(default)]
    pub download_notifications: bool,
}

/// Global observed metadata: no owner, claim or tab is attributed here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeDownloadStatus {
    Started,
    InProgress,
    Complete,
    Failed,
    Canceled,
}
#[derive(Clone, Debug, Deserialize)]
pub struct NativeDownloadMetadata {
    pub id: String,
    pub filename: String,
    pub url: String,
    pub status: NativeDownloadStatus,
}

/// Select only the exact adapter/extension/directory verified by installation.
/// No model path, foreign descriptor heuristic or second config parser is used.
pub async fn discover_registered_for(
    selection: &NativeAdapterSelection,
) -> Result<NativeEndpointDiscovery, IpcError> {
    let adapter = selection.adapter_name().to_owned();
    let extension = selection.expected_extension_id().to_owned();
    let directory = selection.runtime_directory().to_path_buf();
    tokio::task::spawn_blocking(move || {
        discover_directory_blocking(&directory, &adapter, Some(&extension))
    })
    .await
    .map_err(|error| {
        IpcError::Io(std::io::Error::other(format!(
            "native discovery task failed: {error}"
        )))
    })?
}
/// Product convenience entry: reads the same selected sidecar as native startup.
pub async fn discover_installed_native_endpoints(
) -> Result<NativeEndpointDiscovery, NativeProviderError> {
    let selection = tokio::task::spawn_blocking(NativeAdapterSelection::load_installed)
        .await
        .map_err(|error| protocol(&format!("installed selection task failed: {error}")))?;
    match selection {
        Ok(selection) => Ok(discover_registered_for(&selection).await?),
        Err(error) if error.is_missing() => Ok(NativeEndpointDiscovery {
            endpoints: Vec::new(),
            rejected: Vec::new(),
        }),
        Err(error) => Err(error.into()),
    }
}

/// Actual Chrome tab metadata. No activity time or public tab ID is invented.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeTabInfo {
    pub id: u64,
    pub window_id: Option<i64>,
    pub index: Option<i64>,
    pub group_id: Option<i64>,
    pub title: Option<String>,
    pub url: Option<String>,
    #[serde(default)]
    pub last_opened: Option<String>,
    #[serde(default)]
    pub provider_tab_id: Option<String>,
    pub pending_url: Option<String>,
    pub active: Option<bool>,
    pub last_accessed: Option<f64>,
    pub group_title: Option<String>,
}

/// The transport receipt is internal Rust-host data, not model-facing JSON.
#[derive(Clone, Debug)]
pub struct NativePhysicalClaim {
    binding: uuid::Uuid,
    generation: String,
    token: String,
    tab_id: u64,
    target_id: String,
    completion_id: u64,
    cleanup_only: bool,
}
impl NativePhysicalClaim {
    pub fn is_cleanup_only(&self) -> bool {
        self.cleanup_only
    }
    pub fn claim_id(&self) -> &str {
        &self.token
    }
    pub fn tab_id(&self) -> u64 {
        self.tab_id
    }
    pub fn target_id(&self) -> &str {
        &self.target_id
    }
    pub fn generation(&self) -> &str {
        &self.generation
    }
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
}

/// Exact receipt for a tab this connector created for this owner connection.
#[derive(Clone, Debug)]
pub struct NativeCreationReceipt {
    binding: uuid::Uuid,
    generation: String,
    token: String,
    tab_id: Option<u64>,
    cleanup_only: bool,
}

impl NativeCreationReceipt {
    pub fn tab_id(&self) -> Option<u64> {
        self.tab_id
    }
    pub fn is_cleanup_only(&self) -> bool {
        self.cleanup_only
    }
    pub fn creation_id(&self) -> &str {
        &self.token
    }
    pub fn generation(&self) -> &str {
        &self.generation
    }
}

#[derive(Clone, Debug)]
pub struct NativeCreatedTab {
    pub tab: NativeTabInfo,
    receipt: NativeCreationReceipt,
    completion_id: u64,
}
impl NativeCreatedTab {
    pub fn creation_receipt(&self) -> &NativeCreationReceipt {
        &self.receipt
    }
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
}

/// Only an actual matched connector proof can construct this evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupEvidence {
    DetachAcknowledged,
    DetachEvent,
    TabRemoved,
    CloseAcknowledged,
    TabAbsenceObserved,
}
#[derive(Clone, Debug)]
pub struct NativeTabAbsenceObservation {
    tab_id: u64,
    native_request_id: String,
}
impl NativeTabAbsenceObservation {
    pub fn tab_id(&self) -> u64 {
        self.tab_id
    }
    pub fn native_request_id(&self) -> &str {
        &self.native_request_id
    }
}
#[derive(Clone, Debug)]
pub struct CleanupProof {
    evidence: CleanupEvidence,
    completion_id: u64,
    tab_absence: Option<NativeTabAbsenceObservation>,
}
impl CleanupProof {
    pub fn tab_absence_observation(&self) -> Option<&NativeTabAbsenceObservation> {
        self.tab_absence.as_ref()
    }
    pub fn evidence(&self) -> CleanupEvidence {
        self.evidence
    }
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
}

/// Already expanded trusted-host headers. This layer chooses no identity label.
#[derive(Clone, Debug, Serialize)]
pub struct NativeHeader {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeHeaderScope {
    pub claim: String,
    pub generation: String,
    pub owner: String,
    pub tab_id: u64,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeHeaderProof {
    pub state_confirmed: bool,
    pub cleanup_confirmed: bool,
    pub active: bool,
    pub pending_removal: bool,
    pub scope: Option<NativeHeaderScope>,
    pub applied: Option<bool>,
    #[serde(skip)]
    completion_id: u64,
}
impl NativeHeaderProof {
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeSessionHeaderProof {
    pub host_session_id: String,
    pub host_turn_id: String,
    pub generation: String,
    pub owner: String,
    pub state_confirmed: bool,
    pub active: bool,
    pub cleanup_confirmed: bool,
    #[serde(skip)]
    completion_id: u64,
}
impl NativeSessionHeaderProof {
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
}
/// Acknowledged native overlay request, not physical pointer/input evidence.
#[derive(Clone, Debug)]
pub struct NativeCursorPresentationAck {
    pub requested_x: f64,
    pub requested_y: f64,
    pub wait_for_arrival_requested: Option<bool>,
    completion_id: u64,
}
impl NativeCursorPresentationAck {
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
}

#[derive(Clone, Debug)]
pub struct NativePreparedTab {
    pub tab: NativeTabInfo,
    pub normalized: bool,
    completion_id: u64,
}
impl NativePreparedTab {
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeMutationDiagnostic {
    pub attempted: bool,
    pub mutation_acknowledged: bool,
    #[serde(deserialize_with = "required_nullable_bool")]
    pub changed: Option<bool>,
    pub diagnostic: Option<String>,
    pub reason: Option<String>,
    #[serde(skip)]
    completion_id: u64,
}
impl NativeMutationDiagnostic {
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NativeGroupColor {
    Grey,
    Blue,
    Red,
    Yellow,
    Green,
    Pink,
    Purple,
    Cyan,
    Orange,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct NativeGroupPresentation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<NativeGroupColor>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManagedGroupWire {
    group: String,
    owner: String,
    generation: String,
    group_id: u64,
    window_id: u64,
}
#[derive(Clone, Debug)]
pub struct NativeManagedGroupReceipt {
    binding: uuid::Uuid,
    wire: ManagedGroupWire,
    cleanup_only: bool,
}
impl NativeManagedGroupReceipt {
    pub fn is_cleanup_only(&self) -> bool {
        self.cleanup_only
    }
    pub fn group_receipt_id(&self) -> &str {
        &self.wire.group
    }
    pub fn group_id(&self) -> u64 {
        self.wire.group_id
    }
    pub fn window_id(&self) -> u64 {
        self.wire.window_id
    }
    pub fn generation(&self) -> &str {
        &self.wire.generation
    }
}
#[derive(Clone, Debug)]
pub struct NativeGroupProof {
    pub group: NativeManagedGroupReceipt,
    pub grouping_acknowledged: Option<bool>,
    pub presentation_acknowledged: Option<bool>,
    completion_id: u64,
}
impl NativeGroupProof {
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeGroupReleaseEvidence {
    AlreadyNotMember,
    UngroupAcknowledged,
}
#[derive(Clone, Debug)]
pub struct NativeGroupReleaseProof {
    pub evidence: NativeGroupReleaseEvidence,
    completion_id: u64,
}
impl NativeGroupReleaseProof {
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NativeKeepStatus {
    Handoff,
    Deliverable,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeKeepTab {
    pub tab_id: u64,
    pub status: NativeKeepStatus,
}
/// Only a matched logical finish ACK. This is deliberately not CleanupProof.
#[derive(Clone, Debug)]
pub struct NativeTurnFinishAck {
    pub host_session_id: String,
    pub host_turn_id: String,
    completion_id: u64,
}
impl NativeTurnFinishAck {
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
}

/// One exact-claim native invocation retained by the existing CDP pending map.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativePendingCdpRequest {
    pub route: u64,
    pub id: u64,
    pub wire_context: Option<NativeWireContext>,
    pub unknown_reason: Option<String>,
}

/// A fresh snapshot taken after fencing this claim's future CDP dispatch.
#[derive(Clone, Debug)]
pub struct NativeClaimCdpSnapshot {
    provider: NativeEndpointIdentity,
    claim: String,
    pending: Vec<NativePendingCdpRequest>,
    observation_id: u64,
}
impl NativeClaimCdpSnapshot {
    pub fn claim_id(&self) -> &str {
        &self.claim
    }
    pub fn provider(&self) -> &NativeEndpointIdentity {
        &self.provider
    }
    pub fn pending(&self) -> &[NativePendingCdpRequest] {
        &self.pending
    }
    pub fn is_drained(&self) -> bool {
        self.pending.is_empty()
    }
    pub fn has_unknown(&self) -> bool {
        self.pending
            .iter()
            .any(|request| request.unknown_reason.is_some())
    }
    /// A local fence observation ID, not a Chrome command or cleanup ACK.
    pub fn observation_id(&self) -> u64 {
        self.observation_id
    }
}

/// Matched native invocation completion for one fenced CDP claim.
///
/// This does not prove Chrome effect termination, physical detach, clipboard
/// cleanup, input success, or Host operation settlement. In particular, an
/// answered native error may follow the Original extension's Chrome timeout
/// while a Chrome effect can still complete later.
#[derive(Clone, Debug)]
pub struct NativeClaimCdpDrainProof {
    provider: NativeEndpointIdentity,
    claim: String,
    observation_id: u64,
}
impl NativeClaimCdpDrainProof {
    pub fn claim_id(&self) -> &str {
        &self.claim
    }
    pub fn provider(&self) -> &NativeEndpointIdentity {
        &self.provider
    }
    pub fn observation_id(&self) -> u64 {
        self.observation_id
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClaimCdpSnapshotFields {
    claim: String,
    generation: String,
    fenced: bool,
    pending: Vec<NativePendingCdpRequest>,
}

/// Operations describe pending transport receipts, not a second tab ledger.
#[derive(Clone, Debug)]
pub enum NativeOperation {
    Inventory,
    Resolve {
        raw_id: String,
    },
    Attach {
        tab_id: u64,
    },
    Detach {
        claim: String,
    },
    FenceCdp {
        claim: String,
    },
    CreateTab {
        preferred_window_id: Option<i64>,
    },
    CloseTab {
        claim: String,
    },
    StopCreatedTab {
        creation: String,
        tab_id: Option<u64>,
    },
    SetScopedHeaders {
        claim: String,
    },
    ClearScopedHeaders {
        claim: String,
    },
    SetSessionHeaders {
        has_headers: bool,
    },
    ClearSessionHeaders,
    MoveMousePresentation {
        claim: String,
        x: f64,
        y: f64,
        wait_for_arrival: Option<bool>,
    },
    FinishTurn {
        keep: Option<Vec<NativeKeepTab>>,
    },
    PrepareUserTab {
        tab_id: u64,
    },
    MuteCreatedTab {
        creation: String,
    },
    UnmuteCreatedTabIfActive {
        creation: String,
    },
    EnsureCreatedTabGroup {
        creation: String,
    },
    UpdateCreatedTabGroup {
        creation: String,
        group: String,
    },
    ReleaseCreatedTabGroup {
        creation: String,
        group: String,
    },
    OrphanCdpCompletion {
        route: u64,
        claim: String,
        id: u64,
        event: NativeCdpCompletionOutcome,
    },
    EffectsCleanup {
        claim: String,
        effect: String,
        cleanup_confirmed: bool,
        error: Option<String>,
    },
}
impl NativeOperation {
    fn method(&self) -> &'static str {
        match self {
            Self::Inventory => "inventory",
            Self::Resolve { .. } => "resolve",
            Self::Attach { .. } => "attach",
            Self::Detach { .. } => "detach",
            Self::FenceCdp { .. } => "fenceCdp",
            Self::CreateTab { .. } => "createTab",
            Self::CloseTab { .. } => "closeTab",
            Self::StopCreatedTab { .. } => "stopCreatedTab",
            Self::SetScopedHeaders { .. } => "setScopedHeaders",
            Self::ClearScopedHeaders { .. } => "clearScopedHeaders",
            Self::SetSessionHeaders { .. } => "setSessionHeaders",
            Self::ClearSessionHeaders => "clearSessionHeaders",
            Self::MoveMousePresentation { .. } => "moveMouse",
            Self::FinishTurn { .. } => "finishTurn",
            Self::PrepareUserTab { .. } => "prepareUserTab",
            Self::MuteCreatedTab { .. } => "muteCreatedTab",
            Self::UnmuteCreatedTabIfActive { .. } => "unmuteCreatedTabIfActive",
            Self::EnsureCreatedTabGroup { .. } => "ensureCreatedTabGroup",
            Self::UpdateCreatedTabGroup { .. } => "updateCreatedTabGroup",
            Self::ReleaseCreatedTabGroup { .. } => "releaseCreatedTabGroup",
            Self::OrphanCdpCompletion { .. } => "orphanCdpCompletion",
            Self::EffectsCleanup { .. } => "effectsCleanup",
        }
    }
    fn mutation(&self) -> bool {
        !matches!(
            self,
            Self::Inventory | Self::Resolve { .. } | Self::FenceCdp { .. }
        )
    }
    fn pending_budget(&self) -> usize {
        if matches!(self, Self::FenceCdp { .. }) {
            MAX_RETAINED_RECEIPTS
        } else {
            REQUEST_BUDGET
        }
    }
}

/// The same tagged outcome emitted by the native broker's control channel.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "camelCase")]
pub enum NativeOperationOutcome {
    Result(Value),
    ChromeRejected {
        message: String,
        details: Option<Value>,
    },
    ConnectorRejected {
        kind: String,
        message: String,
        details: Option<Value>,
    },
    Unknown {
        reason: String,
        details: Option<Value>,
    },
}
impl NativeOperationOutcome {
    fn into_result(self, operation: &str) -> Result<Value, NativeProviderError> {
        match self {
            Self::Result(value) => Ok(value),
            Self::ChromeRejected { message, details } => Err(NativeProviderError::ChromeRejected {
                operation: operation.to_owned(),
                message,
                details,
            }),
            Self::ConnectorRejected {
                kind,
                message,
                details,
            } => Err(NativeProviderError::Refused {
                kind,
                message,
                details,
            }),
            Self::Unknown { reason, details } => Err(NativeProviderError::OutcomeUnknown {
                operation: operation.to_owned(),
                reason,
                details,
            }),
        }
    }
}
/// Caller-assigned correlation from the existing trusted Host ledger.
/// It chooses no authorization and is never sent to Chrome or the native host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeHostOperation {
    pub operation_id: String,
    pub turn_id: String,
}

#[derive(Clone, Debug)]
pub struct NativeOperationCompletion {
    pub id: u64,
    pub host_operation: Option<NativeHostOperation>,
    pub wire_context: Option<NativeWireContext>,
    pub provider: NativeEndpointIdentity,
    pub operation: NativeOperation,
    pub outcome: NativeOperationOutcome,
}

/// FIFO actor snapshot includes admitted in-flight operations and retained ACKs.
#[derive(Clone, Debug)]
pub struct NativePendingOperation {
    pub id: u64,
    pub host_operation: Option<NativeHostOperation>,
    pub wire_context: Option<NativeWireContext>,
    pub provider: NativeEndpointIdentity,
    pub operation: NativeOperation,
    pub outcome: Option<NativeOperationOutcome>,
}
#[derive(Clone, Debug, Default)]
pub struct NativeKnownCustody {
    pub claim: Option<NativePhysicalClaim>,
    pub created: Option<NativeCreatedTab>,
    pub creation: Option<NativeCreationReceipt>,
    pub group: Option<NativeManagedGroupReceipt>,
    pub cleanup: Option<CleanupProof>,
    pub headers: Option<NativeHeaderProof>,
    pub turn_finished: Option<NativeTurnFinishAck>,
    pub session_headers: Option<NativeSessionHeaderProof>,
    pub cursor_presentation: Option<NativeCursorPresentationAck>,
}
/// Capabilities below originate only from the actor's still-retained completion.
/// Unknown positive-ACK capabilities are cleanup-only and remain old-generation.
#[derive(Clone, Debug)]
pub enum NativeRecoveredOperation {
    SessionHeaders(NativeSessionHeaderProof),
    CursorPresentation(NativeCursorPresentationAck),
    TurnFinished(NativeTurnFinishAck),
    Claim(NativePhysicalClaim),
    Created(NativeCreatedTab),
    Cleanup(CleanupProof),
    Headers(NativeHeaderProof),
    Prepared(NativePreparedTab),
    Presentation(NativeMutationDiagnostic),
    Group(NativeGroupProof),
    GroupReleased(NativeGroupReleaseProof),
    Refused {
        kind: String,
        message: String,
        details: Option<Value>,
    },
    ChromeRejected {
        message: String,
        details: Option<Value>,
    },
    Unknown {
        operation: NativeOperation,
        reason: String,
        details: Option<Value>,
        custody: Box<NativeKnownCustody>,
    },
    OrphanCdpCompletion {
        route: u64,
        claim: String,
        id: u64,
        event: NativeCdpCompletionOutcome,
        wire_context: Option<NativeWireContext>,
    },
    EffectsCleanup {
        claim: String,
        effect: String,
        cleanup_confirmed: bool,
        error: Option<String>,
    },
}

#[derive(Clone, Debug, Deserialize)]
pub struct NativeMetadataError {
    pub kind: String,
    pub message: String,
}

#[derive(Clone, Debug)]
pub enum NativeProviderEvent {
    CompletionReady {
        id: u64,
    },
    ClaimUnavailable {
        claim: String,
        reason: String,
    },
    RouteUnavailable {
        claim: String,
        reason: String,
    },
    ClaimCdpProgress {
        claim: String,
    },
    GenerationClosed {
        reason: String,
    },
    OrphanCdpCompletion {
        route: u64,
        claim: String,
        id: u64,
        outcome: NativeCdpCompletionOutcome,
        wire_context: Option<NativeWireContext>,
    },
    EffectsCleanup {
        claim: String,
        effect: String,
        cleanup_confirmed: bool,
        error: Option<String>,
    },
    TabStateChanged {
        claim: String,
        tab_id: u64,
        window_id: Option<i64>,
        active: bool,
    },
    TabStateUnknown {
        claim: String,
        tab_id: u64,
        error: NativeMetadataError,
    },
    DownloadChanged {
        download: NativeDownloadMetadata,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum NativeProviderError {
    #[error(transparent)]
    Endpoint(#[from] IpcError),
    #[error(transparent)]
    Selection(#[from] NativeAdapterSelectionError),
    #[error("native connector refused ({kind}): {message}")]
    Refused {
        kind: String,
        message: String,
        details: Option<Value>,
    },
    #[error("Chrome rejected {operation}: {message}")]
    ChromeRejected {
        operation: String,
        message: String,
        details: Option<Value>,
    },
    #[error("native {operation} outcome is unknown: {reason}")]
    OutcomeUnknown {
        operation: String,
        reason: String,
        details: Option<Value>,
    },
    #[error("native provider protocol failed: {0}")]
    Protocol(String),
}

struct ProviderInner {
    identity: NativeEndpointIdentity,
    binding: uuid::Uuid,
    commands: mpsc::Sender<ClientCommand>,
    events: broadcast::Sender<NativeProviderEvent>,
    alive: AtomicBool,
}

impl Drop for ProviderInner {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::SeqCst);
        // A full queue already wakes the actor, which rechecks this Weak owner.
        let _ = self.commands.try_send(ClientCommand::OwnerDropped);
    }
}

/// One owner connection, retained by the embedding Driver across native epochs.
#[derive(Clone)]
pub struct NativeBrowserProvider {
    inner: Arc<ProviderInner>,
    host_operation: Option<NativeHostOperation>,
    wire_context: Option<NativeWireContext>,
}
/// Immutable call-scoped provider view sharing the same owner/transport actor.
/// The name is an alias: it carries no extra session or authority store.
pub type NativeBrowserOperation = NativeBrowserProvider;
impl NativeBrowserProvider {
    pub async fn connect(endpoint: ValidatedNativeEndpoint) -> Result<Self, NativeProviderError> {
        let identity = endpoint.identity().clone();
        let stream = endpoint.connect().await?;
        let (commands, incoming) = mpsc::channel(ACTOR_QUEUE);
        let (events, _) = broadcast::channel(EVENT_QUEUE);
        let inner = Arc::new(ProviderInner {
            identity,
            binding: uuid::Uuid::new_v4(),
            commands: commands.clone(),
            events: events.clone(),
            alive: AtomicBool::new(true),
        });
        tokio::spawn(run_client(
            stream,
            incoming,
            commands.downgrade(),
            Arc::downgrade(&inner),
            events,
        ));
        Ok(Self {
            inner,
            host_operation: None,
            wire_context: None,
        })
    }
    pub fn with_host_operation(&self, context: NativeHostOperation) -> NativeBrowserOperation {
        Self {
            inner: self.inner.clone(),
            host_operation: Some(context),
            wire_context: self.wire_context.clone(),
        }
    }
    /// Supply exact trusted owner-session/turn metadata for this call view.
    /// A persistent claim/channel never supplies an ambient replacement turn.
    pub fn with_wire_context(&self, context: NativeWireContext) -> NativeBrowserOperation {
        Self {
            inner: self.inner.clone(),
            host_operation: self.host_operation.clone(),
            wire_context: Some(context),
        }
    }
    pub fn is_closed(&self) -> bool {
        !self.inner.alive.load(Ordering::SeqCst)
    }
    pub fn identity(&self) -> &NativeEndpointIdentity {
        &self.inner.identity
    }
    pub fn capabilities(&self) -> Result<NativeProviderCapabilities, NativeProviderError> {
        decode(self.identity().capabilities.clone())
    }
    /// A lagged receiver must query pending_completions and reconcile its ledger.
    /// Completion data remains in the bounded pending map until explicit ACK.
    pub fn subscribe_events(&self) -> broadcast::Receiver<NativeProviderEvent> {
        self.inner.events.subscribe()
    }

    async fn control(
        &self,
        operation: NativeOperation,
        params: Value,
    ) -> Result<ControlReply, NativeProviderError> {
        let name = operation.method();
        self.check_operation_capability(&operation)?;
        if self
            .host_operation
            .as_ref()
            .zip(self.wire_context.as_ref())
            .is_some_and(|(operation, wire)| operation.turn_id != wire.host_turn_id())
        {
            return Err(refused(
                "context_mismatch",
                "receipt correlation and wire metadata name different trusted turns",
            ));
        }
        if !self.inner.alive.load(Ordering::SeqCst) {
            return Err(unknown(name, "owner IPC connection is closed"));
        }
        let (reply, result) = oneshot::channel();
        self.inner
            .commands
            .send(ClientCommand::Control {
                operation,
                params,
                context: self.host_operation.clone(),
                wire_context: self.wire_context.clone(),
                reply,
            })
            .await
            .map_err(|_| unknown(name, "runtime actor ended before admission"))?;
        result
            .await
            .map_err(|_| unknown(name, "runtime actor ended before receipt delivery"))
    }
    fn check_operation_capability(
        &self,
        operation: &NativeOperation,
    ) -> Result<(), NativeProviderError> {
        let supported = match operation {
            NativeOperation::SetSessionHeaders { .. } | NativeOperation::ClearSessionHeaders => {
                self.capabilities()?.header_scope == NativeHeaderPolicyScope::Session
            }
            NativeOperation::SetScopedHeaders { .. }
            | NativeOperation::ClearScopedHeaders { .. } => {
                self.capabilities()?.header_scope == NativeHeaderPolicyScope::Claim
            }
            NativeOperation::MoveMousePresentation { .. } => {
                self.capabilities()?.cursor_presentation_owner == NativeEffectOwner::Provider
            }
            NativeOperation::FinishTurn { .. } => {
                self.capabilities()?.turn_lifecycle_owner == NativeEffectOwner::Provider
            }
            NativeOperation::MuteCreatedTab { .. }
            | NativeOperation::UnmuteCreatedTabIfActive { .. }
            | NativeOperation::EnsureCreatedTabGroup { .. }
            | NativeOperation::UpdateCreatedTabGroup { .. }
            | NativeOperation::ReleaseCreatedTabGroup { .. } => {
                self.capabilities()?.created_presentation_owner == NativeEffectOwner::Host
            }
            _ => true,
        };
        if !supported {
            return Err(refused(
                "unsupported",
                "selected provider delegates this operation to a different scope or owner",
            ));
        }
        Ok(())
    }
    fn check_claim(&self, claim: &NativePhysicalClaim) -> Result<(), NativeProviderError> {
        if claim.binding != self.inner.binding || claim.generation != self.inner.identity.generation
        {
            return Err(refused(
                "claim_unavailable",
                "claim belongs to another owner connection or generation",
            ));
        }
        Ok(())
    }
    pub async fn list_user_tabs(&self) -> Result<Vec<NativeTabInfo>, NativeProviderError> {
        let reply = self.control(NativeOperation::Inventory, json!({})).await?;
        let result = reply.outcome.into_result("inventory")?;
        decode(
            result
                .get("tabs")
                .cloned()
                .ok_or_else(|| protocol("inventory result lacks tabs"))?,
        )
    }
    pub async fn resolve_user_tab(
        &self,
        raw_id: &str,
    ) -> Result<NativeTabInfo, NativeProviderError> {
        let reply = self
            .control(
                NativeOperation::Resolve {
                    raw_id: raw_id.to_owned(),
                },
                json!({"rawId":raw_id}),
            )
            .await?;
        let result = reply.outcome.into_result("resolve")?;
        decode(
            result
                .get("tab")
                .cloned()
                .ok_or_else(|| protocol("resolve result lacks actual tab"))?,
        )
    }
    pub async fn attach_tab(
        &self,
        raw_id: u64,
    ) -> Result<NativePhysicalClaim, NativeProviderError> {
        let reply = self
            .control(
                NativeOperation::Attach { tab_id: raw_id },
                json!({"tabId":raw_id}),
            )
            .await?;
        let result = reply.outcome.into_result("attach")?;
        let tab_id = result["tabId"]
            .as_u64()
            .ok_or_else(|| protocol("attach result lacks raw tab ID"))?;
        if tab_id != raw_id {
            return Err(protocol("attach changed raw tab identity"));
        }
        Ok(NativePhysicalClaim {
            binding: self.inner.binding,
            generation: self.identity().generation.clone(),
            token: nonempty(&result, "claim")?,
            tab_id,
            target_id: nonempty(&result, "targetId")?,
            completion_id: reply.id,
            cleanup_only: false,
        })
    }
    pub async fn open_cdp_channel(
        &self,
        claim: &NativePhysicalClaim,
    ) -> Result<Arc<CdpConnection>, NativeProviderError> {
        self.check_claim(claim)?;
        if claim.cleanup_only {
            return Err(refused(
                "claim_unavailable",
                "uncertain attachment receipt permits cleanup only",
            ));
        }
        let (reply, result) = oneshot::channel();
        self.inner
            .commands
            .send(ClientCommand::OpenCdp {
                claim: claim.token.clone(),
                reply,
            })
            .await
            .map_err(|_| unknown("openCdp", "runtime actor ended"))?;
        result
            .await
            .map_err(|_| unknown("openCdp", "route acknowledgement was lost"))?
    }
    /// Fence future dispatch for this claim and inspect its actual CDP requests.
    ///
    /// Queued requests remain pending until their writer reports known refusal;
    /// accepted invocations remain pending until their actual native reply.
    /// Missing replies remain Unknown and cannot turn into an empty proof.
    /// Native reply completion does not settle the underlying Chrome effect.
    ///
    /// # Errors
    /// Refuses foreign bindings and reports an unknown outcome when the current
    /// broker generation, claim custody, or IPC observation cannot be established.
    pub async fn fence_claim_cdp(
        &self,
        claim: &NativePhysicalClaim,
    ) -> Result<NativeClaimCdpSnapshot, NativeProviderError> {
        self.check_claim(claim)?;
        let reply = self
            .control(
                NativeOperation::FenceCdp {
                    claim: claim.token.clone(),
                },
                json!({"claim": claim.token}),
            )
            .await?;
        let fields: ClaimCdpSnapshotFields = decode(reply.outcome.into_result("fenceCdp")?)?;
        if fields.claim != claim.token
            || fields.generation != self.identity().generation
            || !fields.fenced
        {
            return Err(protocol(
                "CDP fence snapshot changed its exact claim or generation",
            ));
        }
        if fields.pending.len() > MAX_PENDING_NATIVE_CONTEXTS {
            return Err(protocol(
                "CDP fence snapshot exceeds the pending-request bound",
            ));
        }
        let mut identities = std::collections::HashSet::new();
        if fields
            .pending
            .iter()
            .any(|request| !identities.insert((request.route, request.id)))
        {
            return Err(protocol("CDP fence snapshot repeats a request identity"));
        }
        Ok(NativeClaimCdpSnapshot {
            provider: self.identity().clone(),
            claim: claim.token.clone(),
            pending: fields.pending,
            observation_id: reply.id,
        })
    }

    /// Wait for native invocation replies after fencing this exact claim.
    ///
    /// Progress notifications only trigger a fresh broker observation. Subscribe
    /// before fencing so a terminal reply racing the first snapshot is not lost.
    /// No native command is replayed or consumed by this observation API.
    ///
    /// # Errors
    /// A missing native reply, transport loss or deadline returns Unknown. A
    /// physical detach ACK and an empty control snapshot cannot replace this
    /// observation; an answered error still leaves Host effect outcome Unknown.
    pub async fn wait_claim_cdp_drained(
        &self,
        claim: &NativePhysicalClaim,
        timeout: std::time::Duration,
    ) -> Result<NativeClaimCdpDrainProof, NativeProviderError> {
        self.check_claim(claim)?;
        let mut notifications = self.subscribe_events();
        let drain =
            async {
                loop {
                    let snapshot = self.fence_claim_cdp(claim).await?;
                    if snapshot.has_unknown() {
                        return Err(unknown(
                            "drainClaimCdp",
                            "a fenced CDP request has an unresolved outcome",
                        ));
                    }
                    if snapshot.is_drained() {
                        return Ok(NativeClaimCdpDrainProof {
                            provider: snapshot.provider,
                            claim: snapshot.claim,
                            observation_id: snapshot.observation_id,
                        });
                    }
                    loop {
                        match notifications.recv().await {
                            Ok(NativeProviderEvent::ClaimCdpProgress { claim: changed })
                                if changed == claim.token =>
                            {
                                break
                            }
                            Ok(NativeProviderEvent::GenerationClosed { reason }) => {
                                return Err(unknown("drainClaimCdp", &reason))
                            }
                            Ok(NativeProviderEvent::ClaimUnavailable {
                                claim: changed, ..
                            }) if changed == claim.token => break,
                            Err(broadcast::error::RecvError::Lagged(_)) => break,
                            Err(broadcast::error::RecvError::Closed) => {
                                return Err(unknown(
                                    "drainClaimCdp",
                                    "native progress channel closed before CDP settlement",
                                ))
                            }
                            _ => {}
                        }
                    }
                }
            };
        tokio::time::timeout(timeout, drain).await.map_err(|_| {
            unknown(
                "drainClaimCdp",
                "claim native invocations did not answer before the drain deadline",
            )
        })?
    }

    pub async fn detach_tab(
        &self,
        claim: &NativePhysicalClaim,
    ) -> Result<CleanupProof, NativeProviderError> {
        self.check_claim(claim)?;
        let reply = self
            .control(
                NativeOperation::Detach {
                    claim: claim.token.clone(),
                },
                json!({"claim":claim.token}),
            )
            .await?;
        detach_proof(reply)
    }
    pub async fn create_tab(
        &self,
        preferred_window_id: Option<i64>,
    ) -> Result<NativeCreatedTab, NativeProviderError> {
        let params = match preferred_window_id {
            Some(id) => json!({"windowId":id}),
            None => json!({}),
        };
        let reply = self
            .control(
                NativeOperation::CreateTab {
                    preferred_window_id,
                },
                params,
            )
            .await?;
        let result = reply.outcome.into_result("createTab")?;
        self.created_from_result(&result, reply.id, false)
    }
    pub async fn close_tab(
        &self,
        claim: &NativePhysicalClaim,
    ) -> Result<CleanupProof, NativeProviderError> {
        self.check_claim(claim)?;
        if claim.cleanup_only {
            return Err(refused(
                "claim_unavailable",
                "uncertain attachment can be detached, not promoted to close authority",
            ));
        }
        let reply = self
            .control(
                NativeOperation::CloseTab {
                    claim: claim.token.clone(),
                },
                json!({"claim":claim.token}),
            )
            .await?;
        close_proof(reply, None)
    }
    pub async fn stop_created_tab(
        &self,
        receipt: &NativeCreationReceipt,
    ) -> Result<CleanupProof, NativeProviderError> {
        if receipt.binding != self.inner.binding || receipt.generation != self.identity().generation
        {
            return Err(refused(
                "creation_unavailable",
                "created-tab receipt belongs to another owner or generation",
            ));
        }
        let reply = self
            .control(
                NativeOperation::StopCreatedTab {
                    creation: receipt.token.clone(),
                    tab_id: receipt.tab_id,
                },
                json!({"creation":receipt.token}),
            )
            .await?;
        close_proof(reply, receipt.tab_id)
    }
    pub async fn set_scoped_headers(
        &self,
        claim: &NativePhysicalClaim,
        session_id: &str,
        headers: Option<&[NativeHeader]>,
    ) -> Result<NativeHeaderProof, NativeProviderError> {
        self.check_claim(claim)?;
        if claim.cleanup_only {
            return Err(refused(
                "claim_unavailable",
                "uncertain attachment permits header cleanup only",
            ));
        }
        let reply = self
            .control(
                NativeOperation::SetScopedHeaders {
                    claim: claim.token.clone(),
                },
                json!({"claim":claim.token,"sessionId":session_id,"headers":headers}),
            )
            .await?;
        header_proof(
            reply,
            "setScopedHeaders",
            &claim.token,
            &claim.generation,
            Some(claim.tab_id),
            headers.is_some_and(|headers| !headers.is_empty()),
        )
    }
    pub async fn clear_scoped_headers(
        &self,
        claim: &NativePhysicalClaim,
    ) -> Result<NativeHeaderProof, NativeProviderError> {
        self.check_claim(claim)?;
        let reply = self
            .control(
                NativeOperation::ClearScopedHeaders {
                    claim: claim.token.clone(),
                },
                json!({"claim":claim.token}),
            )
            .await?;
        header_proof(
            reply,
            "clearScopedHeaders",
            &claim.token,
            &claim.generation,
            Some(claim.tab_id),
            false,
        )
    }
    fn check_creation(&self, receipt: &NativeCreationReceipt) -> Result<(), NativeProviderError> {
        if receipt.binding != self.inner.binding
            || receipt.generation != self.identity().generation
            || receipt.cleanup_only
        {
            return Err(refused(
                "creation_unavailable",
                "creation receipt is foreign, stale or cleanup-only",
            ));
        }
        Ok(())
    }
    fn check_group(&self, group: &NativeManagedGroupReceipt) -> Result<(), NativeProviderError> {
        if group.binding != self.inner.binding
            || group.wire.generation != self.identity().generation
            || group.cleanup_only
        {
            return Err(refused(
                "group_unavailable",
                "group receipt is foreign, stale or cleanup-only",
            ));
        }
        Ok(())
    }
    pub async fn prepare_user_tab(
        &self,
        tab_id: u64,
    ) -> Result<NativePreparedTab, NativeProviderError> {
        let reply = self
            .control(
                NativeOperation::PrepareUserTab { tab_id },
                json!({"tabId":tab_id}),
            )
            .await?;
        let result = reply.outcome.into_result("prepareUserTab")?;
        Ok(NativePreparedTab {
            tab: decode(
                result
                    .get("tab")
                    .cloned()
                    .ok_or_else(|| protocol("prepared tab metadata missing"))?,
            )?,
            normalized: result["normalized"]
                .as_bool()
                .ok_or_else(|| protocol("normalization acknowledgement missing"))?,
            completion_id: reply.id,
        })
    }
    async fn presentation_diagnostic(
        &self,
        creation: &NativeCreationReceipt,
        unmute: bool,
    ) -> Result<NativeMutationDiagnostic, NativeProviderError> {
        self.check_creation(creation)?;
        let operation = if unmute {
            NativeOperation::UnmuteCreatedTabIfActive {
                creation: creation.token.clone(),
            }
        } else {
            NativeOperation::MuteCreatedTab {
                creation: creation.token.clone(),
            }
        };
        let method = operation.method();
        let reply = self
            .control(operation, json!({"creation":creation.token}))
            .await?;
        let mut result: NativeMutationDiagnostic = decode(reply.outcome.into_result(method)?)?;
        result.completion_id = reply.id;
        Ok(result)
    }
    pub async fn mute_created_tab(
        &self,
        creation: &NativeCreationReceipt,
    ) -> Result<NativeMutationDiagnostic, NativeProviderError> {
        self.presentation_diagnostic(creation, false).await
    }
    pub async fn unmute_created_tab_if_active(
        &self,
        creation: &NativeCreationReceipt,
    ) -> Result<NativeMutationDiagnostic, NativeProviderError> {
        self.presentation_diagnostic(creation, true).await
    }
    fn group_proof(
        &self,
        reply: ControlReply,
        method: &str,
    ) -> Result<NativeGroupProof, NativeProviderError> {
        let result = reply.outcome.into_result(method)?;
        let wire: ManagedGroupWire = decode(
            result
                .get("group")
                .cloned()
                .ok_or_else(|| protocol("managed group receipt missing"))?,
        )?;
        if wire.group.is_empty()
            || wire.owner.is_empty()
            || wire.generation != self.identity().generation
            || wire.group_id > 9_007_199_254_740_991
            || wire.window_id > 9_007_199_254_740_991
        {
            return Err(protocol("managed group receipt identity is invalid"));
        }
        let grouping_acknowledged = result
            .get("groupingAcknowledged")
            .map(|value| {
                value
                    .as_bool()
                    .ok_or_else(|| protocol("grouping acknowledgement is not boolean"))
            })
            .transpose()?;
        let presentation_acknowledged = result
            .get("presentationAcknowledged")
            .map(|value| {
                value
                    .as_bool()
                    .ok_or_else(|| protocol("presentation acknowledgement is not boolean"))
            })
            .transpose()?;
        if (method == "ensureCreatedTabGroup" && grouping_acknowledged.is_none())
            || (method == "updateCreatedTabGroup" && presentation_acknowledged.is_none())
        {
            return Err(protocol("exact group acknowledgement missing"));
        }
        Ok(NativeGroupProof {
            group: NativeManagedGroupReceipt {
                binding: self.inner.binding,
                wire,
                cleanup_only: false,
            },
            grouping_acknowledged,
            presentation_acknowledged,
            completion_id: reply.id,
        })
    }
    pub async fn ensure_created_tab_group(
        &self,
        creation: &NativeCreationReceipt,
        existing_group: Option<&NativeManagedGroupReceipt>,
        presentation: &NativeGroupPresentation,
    ) -> Result<NativeGroupProof, NativeProviderError> {
        self.check_creation(creation)?;
        if let Some(group) = existing_group {
            self.check_group(group)?;
        }
        let mut presentation =
            serde_json::to_value(presentation).map_err(|error| protocol(&error.to_string()))?;
        if let Some(group) = existing_group {
            presentation["existingGroup"] =
                serde_json::to_value(&group.wire).map_err(|error| protocol(&error.to_string()))?;
        }
        let reply = self
            .control(
                NativeOperation::EnsureCreatedTabGroup {
                    creation: creation.token.clone(),
                },
                json!({"creation":creation.token,"presentation":presentation}),
            )
            .await?;
        self.group_proof(reply, "ensureCreatedTabGroup")
    }
    pub async fn update_created_tab_group(
        &self,
        creation: &NativeCreationReceipt,
        group: &NativeManagedGroupReceipt,
        presentation: &NativeGroupPresentation,
    ) -> Result<NativeGroupProof, NativeProviderError> {
        self.check_creation(creation)?;
        self.check_group(group)?;
        let reply = self
            .control(
                NativeOperation::UpdateCreatedTabGroup {
                    creation: creation.token.clone(),
                    group: group.wire.group.clone(),
                },
                json!({"creation":creation.token,"group":group.wire,"presentation":presentation}),
            )
            .await?;
        self.group_proof(reply, "updateCreatedTabGroup")
    }
    pub async fn release_created_tab_group(
        &self,
        creation: &NativeCreationReceipt,
        group: &NativeManagedGroupReceipt,
    ) -> Result<NativeGroupReleaseProof, NativeProviderError> {
        if creation.binding != self.inner.binding
            || creation.generation != self.identity().generation
            || group.binding != self.inner.binding
            || group.wire.generation != self.identity().generation
        {
            return Err(refused(
                "group_unavailable",
                "cleanup receipts are foreign or stale",
            ));
        }
        let reply = self
            .control(
                NativeOperation::ReleaseCreatedTabGroup {
                    creation: creation.token.clone(),
                    group: group.wire.group.clone(),
                },
                json!({"creation":creation.token,"group":group.wire}),
            )
            .await?;
        let result = reply.outcome.into_result("releaseCreatedTabGroup")?;
        if result["released"] != true {
            return Err(protocol("group release acknowledgement missing"));
        }
        let evidence = match result["proof"].as_str() {
            Some("already_not_member") => NativeGroupReleaseEvidence::AlreadyNotMember,
            Some("ungroup_ack") => NativeGroupReleaseEvidence::UngroupAcknowledged,
            _ => return Err(protocol("unknown group release proof")),
        };
        Ok(NativeGroupReleaseProof {
            evidence,
            completion_id: reply.id,
        })
    }
    pub async fn set_session_headers(
        &self,
        headers: &[NativeHeader],
    ) -> Result<NativeSessionHeaderProof, NativeProviderError> {
        let context = self
            .wire_context
            .as_ref()
            .ok_or_else(|| {
                refused(
                    "missing_context",
                    "session headers require trusted session and turn metadata",
                )
            })?
            .clone();
        let reply = self
            .control(
                NativeOperation::SetSessionHeaders {
                    has_headers: !headers.is_empty(),
                },
                json!({"headers":headers}),
            )
            .await?;
        session_header_proof(
            reply,
            &context,
            &self.identity().generation,
            !headers.is_empty(),
        )
    }
    pub async fn clear_session_headers(
        &self,
    ) -> Result<NativeSessionHeaderProof, NativeProviderError> {
        let context = self
            .wire_context
            .as_ref()
            .ok_or_else(|| {
                refused(
                    "missing_context",
                    "session header cleanup requires trusted session and turn metadata",
                )
            })?
            .clone();
        let reply = self
            .control(NativeOperation::ClearSessionHeaders, json!({}))
            .await?;
        session_header_proof(reply, &context, &self.identity().generation, false)
    }
    pub async fn move_mouse_presentation(
        &self,
        claim: &NativePhysicalClaim,
        x: f64,
        y: f64,
        wait_for_arrival: Option<bool>,
    ) -> Result<NativeCursorPresentationAck, NativeProviderError> {
        self.check_claim(claim)?;
        if self.wire_context.is_none() {
            return Err(refused(
                "missing_context",
                "native cursor presentation requires trusted session and turn metadata",
            ));
        }
        if claim.cleanup_only {
            return Err(refused(
                "claim_unavailable",
                "uncertain attachment cannot install new presentation",
            ));
        }
        if !x.is_finite() || !y.is_finite() {
            return Err(refused(
                "invalid_request",
                "cursor presentation coordinates must be finite",
            ));
        }
        let mut params = json!({"claim":claim.token,"x":x,"y":y});
        if let Some(wait) = wait_for_arrival {
            params["waitForArrival"] = json!(wait);
        }
        let reply = self
            .control(
                NativeOperation::MoveMousePresentation {
                    claim: claim.token.clone(),
                    x,
                    y,
                    wait_for_arrival,
                },
                params,
            )
            .await?;
        reply.outcome.into_result("moveMouse")?;
        Ok(NativeCursorPresentationAck {
            requested_x: x,
            requested_y: y,
            wait_for_arrival_requested: wait_for_arrival,
            completion_id: reply.id,
        })
    }
    /// Invoke once from the trusted Host's complete logical-turn cleanup plan.
    /// None selects turnEnded; Some selects the full finalizeTabs keep plan.
    /// Neither a void wire ACK nor this receipt proves physical tab release.
    pub async fn finish_turn(
        &self,
        keep: Option<&[NativeKeepTab]>,
    ) -> Result<NativeTurnFinishAck, NativeProviderError> {
        let context = self
            .wire_context
            .as_ref()
            .ok_or_else(|| {
                refused(
                    "missing_context",
                    "logical turn finish requires trusted session and turn metadata",
                )
            })?
            .clone();
        let reply = self
            .control(
                NativeOperation::FinishTurn {
                    keep: keep.map(<[NativeKeepTab]>::to_vec),
                },
                json!({"keep":keep}),
            )
            .await?;
        reply.outcome.into_result("finishTurn")?;
        Ok(NativeTurnFinishAck {
            host_session_id: context.host_session_id().to_owned(),
            host_turn_id: context.host_turn_id().to_owned(),
            completion_id: reply.id,
        })
    }
    /// FIFO barrier for control operations only (attach/create/preparation/
    /// headers/cleanup). For a Host operation not previously acknowledged,
    /// absence after its enqueue has settled means no control dispatch; None
    /// outcome remains in flight. Previously acknowledged operations are also
    /// absent, so the Host must retain that distinction in its existing ledger.
    /// Generic CdpConnection calls have their own pending/unknown semantics:
    /// this snapshot never authorizes replay of CDP input or JavaScript.
    pub async fn pending_operations(
        &self,
    ) -> Result<Vec<NativePendingOperation>, NativeProviderError> {
        let (reply, result) = oneshot::channel();
        self.inner
            .commands
            .send(ClientCommand::Snapshot { reply })
            .await
            .map_err(|_| unknown("pendingOperations", "runtime actor ended"))?;
        result
            .await
            .map_err(|_| unknown("pendingOperations", "runtime actor ended"))
    }
    /// Effect-free typed recovery from a currently retained, issued receipt.
    /// This performs no native request and never replays the original mutation.
    pub async fn recover_completion(
        &self,
        receipt_id: u64,
    ) -> Result<NativeRecoveredOperation, NativeProviderError> {
        let completion = self
            .pending_completions()
            .await?
            .into_iter()
            .find(|completion| completion.id == receipt_id)
            .ok_or_else(|| {
                refused(
                    "completion_unavailable",
                    "issued completion is not retained",
                )
            })?;
        self.materialize_retained(&completion)
    }
    pub async fn materialize_completion(
        &self,
        completion: &NativeOperationCompletion,
    ) -> Result<NativeRecoveredOperation, NativeProviderError> {
        let current = self
            .pending_completions()
            .await?
            .into_iter()
            .find(|entry| {
                entry.id == completion.id
                    && entry.provider == completion.provider
                    && entry.host_operation == completion.host_operation
                    && entry.wire_context == completion.wire_context
            })
            .ok_or_else(|| {
                refused(
                    "completion_unavailable",
                    "receipt identity/context is not currently retained",
                )
            })?;
        self.materialize_retained(&current)
    }
    fn materialize_retained(
        &self,
        completion: &NativeOperationCompletion,
    ) -> Result<NativeRecoveredOperation, NativeProviderError> {
        if completion.provider != *self.identity() {
            return Err(refused(
                "completion_unavailable",
                "receipt belongs to another provider generation",
            ));
        }
        let result = match &completion.outcome {
            NativeOperationOutcome::Result(result) => result.clone(),
            NativeOperationOutcome::ChromeRejected { message, details } => {
                return Ok(NativeRecoveredOperation::ChromeRejected {
                    message: message.clone(),
                    details: details.clone(),
                })
            }
            NativeOperationOutcome::ConnectorRejected {
                kind,
                message,
                details,
            } => {
                return Ok(NativeRecoveredOperation::Refused {
                    kind: kind.clone(),
                    message: message.clone(),
                    details: details.clone(),
                })
            }
            NativeOperationOutcome::Unknown { reason, details } => {
                return Ok(NativeRecoveredOperation::Unknown {
                    operation: completion.operation.clone(),
                    reason: reason.clone(),
                    details: details.clone(),
                    custody: Box::new(self.recover_known_custody(completion, details.as_ref())?),
                })
            }
        };
        let reply = || ControlReply {
            id: completion.id,
            outcome: NativeOperationOutcome::Result(result.clone()),
        };
        Ok(match &completion.operation {
            NativeOperation::SetSessionHeaders { .. } | NativeOperation::ClearSessionHeaders => {
                let context = completion.wire_context.as_ref().ok_or_else(|| {
                    protocol("session header receipt lost immutable wire context")
                })?;
                NativeRecoveredOperation::SessionHeaders(session_header_proof(
                    reply(),
                    context,
                    &self.identity().generation,
                    matches!(
                        &completion.operation,
                        NativeOperation::SetSessionHeaders { has_headers: true }
                    ),
                )?)
            }
            NativeOperation::MoveMousePresentation {
                x,
                y,
                wait_for_arrival,
                ..
            } => NativeRecoveredOperation::CursorPresentation(NativeCursorPresentationAck {
                requested_x: *x,
                requested_y: *y,
                wait_for_arrival_requested: *wait_for_arrival,
                completion_id: completion.id,
            }),
            NativeOperation::FinishTurn { .. } => {
                let context = completion
                    .wire_context
                    .as_ref()
                    .ok_or_else(|| protocol("finish completion lost its immutable wire context"))?;
                NativeRecoveredOperation::TurnFinished(NativeTurnFinishAck {
                    host_session_id: context.host_session_id().to_owned(),
                    host_turn_id: context.host_turn_id().to_owned(),
                    completion_id: completion.id,
                })
            }
            NativeOperation::Attach { tab_id } => NativeRecoveredOperation::Claim(
                self.claim_from_result(&result, *tab_id, completion.id, false)?,
            ),
            NativeOperation::CreateTab { .. } => NativeRecoveredOperation::Created(
                self.created_from_result(&result, completion.id, false)?,
            ),
            NativeOperation::Detach { .. } => {
                NativeRecoveredOperation::Cleanup(detach_proof(reply())?)
            }
            NativeOperation::CloseTab { .. } => {
                NativeRecoveredOperation::Cleanup(close_proof(reply(), None)?)
            }
            NativeOperation::StopCreatedTab { tab_id, .. } => {
                NativeRecoveredOperation::Cleanup(close_proof(reply(), *tab_id)?)
            }
            NativeOperation::SetScopedHeaders { claim }
            | NativeOperation::ClearScopedHeaders { claim } => {
                NativeRecoveredOperation::Headers(header_proof(
                    reply(),
                    completion.operation.method(),
                    claim,
                    &self.identity().generation,
                    None,
                    false,
                )?)
            }
            NativeOperation::PrepareUserTab { tab_id } => {
                let tab: NativeTabInfo = decode(result["tab"].clone())?;
                if tab.id != *tab_id {
                    return Err(protocol("prepared completion changed tab identity"));
                }
                NativeRecoveredOperation::Prepared(NativePreparedTab {
                    tab,
                    normalized: result["normalized"]
                        .as_bool()
                        .ok_or_else(|| protocol("normalization acknowledgement missing"))?,
                    completion_id: completion.id,
                })
            }
            NativeOperation::MuteCreatedTab { .. }
            | NativeOperation::UnmuteCreatedTabIfActive { .. } => {
                let mut value: NativeMutationDiagnostic = decode(result)?;
                value.completion_id = completion.id;
                NativeRecoveredOperation::Presentation(value)
            }
            NativeOperation::EnsureCreatedTabGroup { .. }
            | NativeOperation::UpdateCreatedTabGroup { .. } => NativeRecoveredOperation::Group(
                self.group_proof(reply(), completion.operation.method())?,
            ),
            NativeOperation::ReleaseCreatedTabGroup { .. } => {
                if result["released"] != true {
                    return Err(protocol("group release acknowledgement missing"));
                }
                let evidence = match result["proof"].as_str() {
                    Some("already_not_member") => NativeGroupReleaseEvidence::AlreadyNotMember,
                    Some("ungroup_ack") => NativeGroupReleaseEvidence::UngroupAcknowledged,
                    _ => return Err(protocol("unknown group release proof")),
                };
                NativeRecoveredOperation::GroupReleased(NativeGroupReleaseProof {
                    evidence,
                    completion_id: completion.id,
                })
            }
            NativeOperation::OrphanCdpCompletion {
                route,
                claim,
                id,
                event,
            } => NativeRecoveredOperation::OrphanCdpCompletion {
                route: *route,
                claim: claim.clone(),
                id: *id,
                event: event.clone(),
                wire_context: completion.wire_context.clone(),
            },
            NativeOperation::EffectsCleanup {
                claim,
                effect,
                cleanup_confirmed,
                error,
            } => NativeRecoveredOperation::EffectsCleanup {
                claim: claim.clone(),
                effect: effect.clone(),
                cleanup_confirmed: *cleanup_confirmed,
                error: error.clone(),
            },
            NativeOperation::Inventory
            | NativeOperation::Resolve { .. }
            | NativeOperation::FenceCdp { .. } => {
                return Err(refused(
                    "completion_unavailable",
                    "read-only observations are not retained mutation receipts",
                ))
            }
        })
    }
    fn claim_from_result(
        &self,
        result: &Value,
        tab_id: u64,
        completion_id: u64,
        cleanup_only: bool,
    ) -> Result<NativePhysicalClaim, NativeProviderError> {
        if result["tabId"].as_u64() != Some(tab_id) {
            return Err(protocol("acknowledged claim changed original tab identity"));
        }
        Ok(NativePhysicalClaim {
            binding: self.inner.binding,
            generation: self.identity().generation.clone(),
            token: nonempty(result, "claim")?,
            tab_id,
            target_id: nonempty(result, "targetId")?,
            completion_id,
            cleanup_only,
        })
    }
    fn created_from_result(
        &self,
        result: &Value,
        completion_id: u64,
        cleanup_only: bool,
    ) -> Result<NativeCreatedTab, NativeProviderError> {
        let tab: NativeTabInfo = decode(result["tab"].clone())?;
        let tab_id = Some(tab.id);
        Ok(NativeCreatedTab {
            tab,
            receipt: NativeCreationReceipt {
                binding: self.inner.binding,
                generation: self.identity().generation.clone(),
                token: nonempty(result, "creation")?,
                tab_id,
                cleanup_only,
            },
            completion_id,
        })
    }
    fn recover_known_custody(
        &self,
        completion: &NativeOperationCompletion,
        details: Option<&Value>,
    ) -> Result<NativeKnownCustody, NativeProviderError> {
        let mut custody = NativeKnownCustody::default();
        let Some(details) = details else {
            return Ok(custody);
        };
        let acknowledged = details.get("acknowledgedResult");
        match &completion.operation {
            NativeOperation::SetSessionHeaders { .. } | NativeOperation::ClearSessionHeaders => {
                if let Some(result) = acknowledged {
                    let context = completion
                        .wire_context
                        .as_ref()
                        .ok_or_else(|| protocol("unknown session header receipt lost metadata"))?;
                    custody.session_headers = Some(session_header_proof(
                        ControlReply {
                            id: completion.id,
                            outcome: NativeOperationOutcome::Result(result.clone()),
                        },
                        context,
                        &self.identity().generation,
                        matches!(
                            &completion.operation,
                            NativeOperation::SetSessionHeaders { has_headers: true }
                        ),
                    )?);
                }
            }
            NativeOperation::MoveMousePresentation {
                x,
                y,
                wait_for_arrival,
                ..
            } => {
                if acknowledged.is_some() {
                    custody.cursor_presentation = Some(NativeCursorPresentationAck {
                        requested_x: *x,
                        requested_y: *y,
                        wait_for_arrival_requested: *wait_for_arrival,
                        completion_id: completion.id,
                    });
                }
            }
            NativeOperation::FinishTurn { .. } => {
                if acknowledged.is_some() {
                    let context = completion
                        .wire_context
                        .as_ref()
                        .ok_or_else(|| protocol("unknown finish receipt lost wire context"))?;
                    custody.turn_finished = Some(NativeTurnFinishAck {
                        host_session_id: context.host_session_id().to_owned(),
                        host_turn_id: context.host_turn_id().to_owned(),
                        completion_id: completion.id,
                    });
                }
            }
            NativeOperation::Attach { tab_id } => {
                if let Some(value) = details.get("custody").or(acknowledged) {
                    custody.claim =
                        Some(self.claim_from_result(value, *tab_id, completion.id, true)?);
                }
            }
            NativeOperation::CreateTab { .. } => {
                if let Some(value) = acknowledged {
                    custody.created = Some(self.created_from_result(value, completion.id, true)?);
                } else if let Some(token) = details
                    .get("creation")
                    .and_then(Value::as_str)
                    .filter(|token| !token.is_empty())
                {
                    custody.creation = Some(NativeCreationReceipt {
                        binding: self.inner.binding,
                        generation: self.identity().generation.clone(),
                        token: token.to_owned(),
                        tab_id: None,
                        cleanup_only: true,
                    });
                }
            }
            NativeOperation::Detach { .. } => {
                if let Some(result) = acknowledged {
                    custody.cleanup = Some(detach_proof(ControlReply {
                        id: completion.id,
                        outcome: NativeOperationOutcome::Result(result.clone()),
                    })?);
                }
            }
            NativeOperation::CloseTab { .. } | NativeOperation::StopCreatedTab { .. } => {
                if let Some(result) = acknowledged {
                    let expected_absence_tab = match &completion.operation {
                        NativeOperation::StopCreatedTab { tab_id, .. } => *tab_id,
                        _ => None,
                    };
                    custody.cleanup = Some(close_proof(
                        ControlReply {
                            id: completion.id,
                            outcome: NativeOperationOutcome::Result(result.clone()),
                        },
                        expected_absence_tab,
                    )?);
                }
            }
            NativeOperation::SetScopedHeaders { claim }
            | NativeOperation::ClearScopedHeaders { claim } => {
                if let Some(result) = acknowledged {
                    custody.headers = Some(header_proof(
                        ControlReply {
                            id: completion.id,
                            outcome: NativeOperationOutcome::Result(result.clone()),
                        },
                        completion.operation.method(),
                        claim,
                        &self.identity().generation,
                        None,
                        false,
                    )?);
                }
            }
            _ => {}
        }
        if let Some(group) = details
            .get("group")
            .or_else(|| acknowledged.and_then(|value| value.get("group")))
        {
            let wire: ManagedGroupWire = decode(group.clone())?;
            if wire.generation != self.identity().generation
                || wire.group.is_empty()
                || wire.owner.is_empty()
                || wire.group_id > 9_007_199_254_740_991
                || wire.window_id > 9_007_199_254_740_991
            {
                return Err(protocol("acknowledged group custody identity is invalid"));
            }
            custody.group = Some(NativeManagedGroupReceipt {
                binding: self.inner.binding,
                wire,
                cleanup_only: true,
            });
        }
        Ok(custody)
    }
    /// Apply each receipt to the existing Host ledger before acknowledging it.
    pub async fn pending_completions(
        &self,
    ) -> Result<Vec<NativeOperationCompletion>, NativeProviderError> {
        let (reply, result) = oneshot::channel();
        self.inner
            .commands
            .send(ClientCommand::Pending { reply })
            .await
            .map_err(|_| unknown("pendingCompletions", "runtime actor ended"))?;
        result
            .await
            .map_err(|_| unknown("pendingCompletions", "runtime actor ended"))
    }
    pub async fn acknowledge_completion(&self, id: u64) -> Result<(), NativeProviderError> {
        self.inner
            .commands
            .send(ClientCommand::Acknowledge { id })
            .await
            .map_err(|_| unknown("acknowledgeCompletion", "runtime actor ended"))
    }
    /// Ends only this logical owner's transport. It proves no physical cleanup.
    /// The host retains closing custody until separate cleanup proof/reconcile.
    pub async fn close(&self) {
        self.inner.alive.store(false, Ordering::SeqCst);
        let (reply, closed) = oneshot::channel();
        if self
            .inner
            .commands
            .send(ClientCommand::Close { reply })
            .await
            .is_ok()
        {
            let _ = closed.await;
        }
    }
}

fn session_header_proof(
    reply: ControlReply,
    context: &NativeWireContext,
    generation: &str,
    expected_active: bool,
) -> Result<NativeSessionHeaderProof, NativeProviderError> {
    let mut proof: NativeSessionHeaderProof = decode(reply.outcome.into_result("sessionHeaders")?)?;
    if proof.host_session_id != context.host_session_id()
        || proof.host_turn_id != context.host_turn_id()
        || proof.generation != generation
        || proof.owner.is_empty()
    {
        return Err(protocol(
            "session header proof changed its exact trusted scope",
        ));
    }
    if !proof.state_confirmed {
        return Err(unknown(
            "sessionHeaders",
            "session policy state is not confirmed",
        ));
    }
    if proof.active != expected_active || proof.cleanup_confirmed == expected_active {
        return Err(protocol(
            "session header acknowledgement changed the requested policy state",
        ));
    }
    proof.completion_id = reply.id;
    Ok(proof)
}

fn required_nullable_bool<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<bool>, D::Error> {
    Option::<bool>::deserialize(deserializer)
}
fn decode<T: for<'de> Deserialize<'de>>(value: Value) -> Result<T, NativeProviderError> {
    serde_json::from_value(value).map_err(|error| protocol(&error.to_string()))
}
fn nonempty(value: &Value, field: &str) -> Result<String, NativeProviderError> {
    value[field]
        .as_str()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| protocol(&format!("result lacks {field}")))
}
fn protocol(message: &str) -> NativeProviderError {
    NativeProviderError::Protocol(message.to_owned())
}
fn refused(kind: &str, message: &str) -> NativeProviderError {
    NativeProviderError::Refused {
        kind: kind.to_owned(),
        message: message.to_owned(),
        details: None,
    }
}
fn unknown(operation: &str, reason: &str) -> NativeProviderError {
    NativeProviderError::OutcomeUnknown {
        operation: operation.to_owned(),
        reason: reason.to_owned(),
        details: None,
    }
}
struct ControlReply {
    id: u64,
    outcome: NativeOperationOutcome,
}
fn detach_proof(reply: ControlReply) -> Result<CleanupProof, NativeProviderError> {
    let result = reply.outcome.into_result("detach")?;
    if result["detached"] != true {
        return Err(protocol("detach success lacks acknowledgement"));
    }
    let evidence = match result["proof"].as_str() {
        Some("detach_ack") => CleanupEvidence::DetachAcknowledged,
        Some("detach_event") => CleanupEvidence::DetachEvent,
        Some("tab_removed") => CleanupEvidence::TabRemoved,
        _ => return Err(protocol("unknown detach proof")),
    };
    Ok(CleanupProof {
        evidence,
        completion_id: reply.id,
        tab_absence: None,
    })
}
fn close_proof(
    reply: ControlReply,
    expected_absence_tab: Option<u64>,
) -> Result<CleanupProof, NativeProviderError> {
    let result = reply.outcome.into_result("closeTab")?;
    if result["closed"] != true {
        return Err(protocol("close success lacks exact acknowledgement"));
    }
    let (evidence, tab_absence) = match result["proof"].as_str() {
        Some("close_ack") => (CleanupEvidence::CloseAcknowledged, None),
        Some("tab_absent") => {
            let tab_id = expected_absence_tab.ok_or_else(|| {
                protocol("tab absence requires the original issued Created identity")
            })?;
            if result["tabId"].as_u64() != Some(tab_id) {
                return Err(protocol(
                    "tab absence changed the original Created tab identity",
                ));
            }
            let native_request_id = nonempty(&result, "observationRequestId")?;
            (
                CleanupEvidence::TabAbsenceObserved,
                Some(NativeTabAbsenceObservation {
                    tab_id,
                    native_request_id,
                }),
            )
        }
        _ => return Err(protocol("close success lacks a recognized exact proof")),
    };
    Ok(CleanupProof {
        evidence,
        completion_id: reply.id,
        tab_absence,
    })
}
fn header_proof(
    reply: ControlReply,
    operation: &str,
    claim: &str,
    generation: &str,
    tab_id: Option<u64>,
    require_scope: bool,
) -> Result<NativeHeaderProof, NativeProviderError> {
    let mut result: NativeHeaderProof = decode(reply.outcome.into_result(operation)?)?;
    if !result.state_confirmed {
        return Err(unknown(operation, "header state was not confirmed"));
    }
    if let Some(scope) = &result.scope {
        if scope.claim != claim
            || scope.generation != generation
            || tab_id.is_some_and(|id| id != scope.tab_id)
            || scope.owner.is_empty()
        {
            return Err(protocol("header proof names another physical claim"));
        }
    } else if require_scope {
        return Err(protocol("applied header proof lacks its physical scope"));
    }
    result.completion_id = reply.id;
    Ok(result)
}

enum ClientCommand {
    Control {
        operation: NativeOperation,
        params: Value,
        context: Option<NativeHostOperation>,
        wire_context: Option<NativeWireContext>,
        reply: oneshot::Sender<ControlReply>,
    },
    OpenCdp {
        claim: String,
        reply: oneshot::Sender<Result<Arc<CdpConnection>, NativeProviderError>>,
    },
    Cdp {
        route: u64,
        command: NativeCdpCommand,
    },
    CloseCdp {
        route: u64,
    },
    Pending {
        reply: oneshot::Sender<Vec<NativeOperationCompletion>>,
    },
    Snapshot {
        reply: oneshot::Sender<Vec<NativePendingOperation>>,
    },
    Acknowledge {
        id: u64,
    },
    Close {
        reply: oneshot::Sender<()>,
    },
    OwnerDropped,
}
struct PendingControl {
    operation: NativeOperation,
    context: Option<NativeHostOperation>,
    wire_context: Option<NativeWireContext>,
    reply: Option<oneshot::Sender<ControlReply>>,
    outcome: Option<NativeOperationOutcome>,
}
struct PendingOpen {
    claim: String,
    replies: Vec<oneshot::Sender<Result<Arc<CdpConnection>, NativeProviderError>>>,
}
struct RuntimeRoute {
    claim: String,
    inbound: mpsc::Sender<NativeCdpInbound>,
    connection: Arc<CdpConnection>,
    request_contexts: HashMap<u64, NativeWireContext>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "camelCase")]
enum ControlEvent {
    ClaimCdpProgress {
        claim: String,
    },
    Reply {
        id: u64,
        outcome: NativeOperationOutcome,
    },
    ClaimUnavailable {
        claim: String,
        reason: String,
    },
    GenerationClosed {
        reason: String,
    },
    OrphanCdpCompletion {
        route: u64,
        claim: String,
        id: u64,
        event: NativeCdpCompletionOutcome,
        #[serde(default, rename = "wireContext")]
        wire_context: Option<NativeWireContext>,
    },
    EffectsCleanup {
        claim: String,
        effect: String,
        #[serde(rename = "cleanupConfirmed")]
        cleanup_confirmed: bool,
        error: Option<String>,
    },
    TabStateChanged {
        claim: String,
        #[serde(rename = "tabId")]
        tab_id: u64,
        #[serde(rename = "windowId")]
        window_id: Option<i64>,
        active: bool,
    },
    TabStateUnknown {
        claim: String,
        #[serde(rename = "tabId")]
        tab_id: u64,
        error: NativeMetadataError,
    },
    DownloadChanged {
        download: NativeDownloadMetadata,
    },
}
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "camelCase")]
pub enum NativeCdpCompletionOutcome {
    ChromeMessage(Value),
    LocalRejected {
        id: u64,
        code: String,
        message: String,
    },
    TransportFailure(String),
}

async fn run_client(
    stream: local_ipc::LocalStream,
    mut commands: mpsc::Receiver<ClientCommand>,
    sender: mpsc::WeakSender<ClientCommand>,
    owner: std::sync::Weak<ProviderInner>,
    events: broadcast::Sender<NativeProviderEvent>,
) {
    let identity = match owner.upgrade() {
        Some(owner) => owner.identity.clone(),
        None => return,
    };
    let (mut read, write) = tokio::io::split(stream);
    let (reader_events, mut native) = mpsc::channel(ROUTE_QUEUE);
    // The framing reader is never canceled by an unrelated actor command.
    let reader = tokio::spawn(async move {
        loop {
            let message = match local_ipc::read_json(&mut read).await {
                Ok(Some(value)) => Ok(value),
                Ok(None) => Err("owner IPC EOF".to_owned()),
                Err(error) => Err(error.to_string()),
            };
            let ended = message.is_err();
            if reader_events.send(message).await.is_err() || ended {
                break;
            }
        }
    });
    let mut writer = Some(write);
    let mut pending = HashMap::<u64, PendingControl>::new();
    let mut opening = HashMap::<u64, PendingOpen>::new();
    let mut routes = HashMap::<u64, RuntimeRoute>::new();
    let mut retired_contexts = HashMap::<(u64, u64), NativeWireContext>::new();
    let mut next_id = 0u64;
    loop {
        if owner.upgrade().is_none() {
            break;
        }
        let action = tokio::select! {
            message=native.recv(),if writer.is_some()=> {
                match message {
                    Some(Ok(value))=>Some((false,value)),
                    Some(Err(reason))=>{disconnect(&reason,&owner,&events,&mut pending,&mut opening,&mut routes);writer=None;reader.abort();None},
                    None=>{disconnect("IPC reader ended",&owner,&events,&mut pending,&mut opening,&mut routes);writer=None;reader.abort();None},
                }
            }
            command=commands.recv()=>{
                let Some(command)=command else {break;};
                match command {
                    ClientCommand::Pending{reply}=>{let _=reply.send(pending.iter().filter_map(|(id,entry)|entry.outcome.as_ref().map(|outcome|NativeOperationCompletion{id:*id,host_operation:entry.context.clone(),wire_context:entry.wire_context.clone(),provider:identity.clone(),operation:entry.operation.clone(),outcome:outcome.clone()})).collect());None},
                    ClientCommand::Snapshot{reply}=>{let _=reply.send(pending.iter().map(|(id,entry)|NativePendingOperation{id:*id,host_operation:entry.context.clone(),wire_context:entry.wire_context.clone(),provider:identity.clone(),operation:entry.operation.clone(),outcome:entry.outcome.clone()}).collect());None},
                    ClientCommand::Acknowledge{id}=>{if pending.get(&id).is_some_and(|entry|entry.outcome.is_some()){pending.remove(&id);}None},
                    ClientCommand::OwnerDropped=>{break;},
                    ClientCommand::Close{reply}=>{disconnect("logical owner explicitly closed its IPC transport",&owner,&events,&mut pending,&mut opening,&mut routes);writer=None;reader.abort();let _=reply.send(());None},
                    ClientCommand::Control{operation,params,context,wire_context,reply}=>{
                        if reply.is_closed(){None}
                        else if !owner_admitting(&owner){let _=reply.send(ControlReply{id:0,outcome:NativeOperationOutcome::ConnectorRejected{kind:"owner_closed".into(),message:"logical owner is closing; control was not dispatched".into(),details:None}});None}
                        else if writer.is_none(){let _=reply.send(ControlReply{id:0,outcome:NativeOperationOutcome::Unknown{reason:"owner IPC is closed".into(),details:None}});None}
                        else if pending.len()+opening.len()>=operation.pending_budget(){let _=reply.send(ControlReply{id:0,outcome:NativeOperationOutcome::ConnectorRejected{kind:"request_budget".into(),message:"pending receipts must be applied and acknowledged before more requests".into(),details:None}});None}
                        else if let Some(id)=next_id.checked_add(1){next_id=id;let method=operation.method();pending.insert(id,PendingControl{operation,context,wire_context:wire_context.clone(),reply:Some(reply),outcome:None});Some((true,with_wire_context(json!({"kind":"control","request":merge_request(method,id,params)}),wire_context.as_ref())))}
                        else{let _=reply.send(ControlReply{id:0,outcome:NativeOperationOutcome::ConnectorRejected{kind:"request_budget".into(),message:"local request IDs exhausted".into(),details:None}});None}
                    }
                    ClientCommand::OpenCdp{claim,reply}=>{
                        for entry in opening.values_mut(){entry.replies.retain(|reply|!reply.is_closed());}
                        let waiters=opening.values().map(|entry|entry.replies.len()).sum::<usize>();
                        if reply.is_closed(){None}
                        else if !owner_admitting(&owner){let _=reply.send(Err(refused("owner_closed","logical owner is closing; route was not admitted")));None}
                        else if let Some(route)=routes.values().find(|route|route.claim==claim&&!route.connection.is_closed()){let _=reply.send(Ok(route.connection.clone()));None}
                        else if waiters+pending.len()>=REQUEST_BUDGET{let _=reply.send(Err(refused("request_budget","native open-route waiter budget exhausted")));None}
                        else if let Some(entry)=opening.values_mut().find(|entry|entry.claim==claim){entry.replies.push(reply);None}
                        else if writer.is_none(){let _=reply.send(Err(unknown("openCdp","owner IPC is closed")));None}
                        else if pending.len()+opening.len()>=REQUEST_BUDGET{let _=reply.send(Err(refused("request_budget","native pending-operation budget exhausted")));None}
                        else if let Some(id)=next_id.checked_add(1){next_id=id;opening.insert(id,PendingOpen{claim:claim.clone(),replies:vec![reply]});Some((true,json!({"kind":"openCdp","id":id,"claim":claim})))}
                        else{let _=reply.send(Err(refused("request_budget","local request IDs exhausted")));None}
                    }
                    ClientCommand::Cdp{route,command}=>{
                        if writer.is_some()&&routes.contains_key(&route){
                            // The opaque command is released only here, directly
                            // before the actor's serial IPC write, not in its queue.
                            command.into_dispatch_if_live().and_then(|dispatch|{
                                let message=dispatch.message;
                                if !owner_admitting(&owner){
                                    if let(Some(state),Some(id))=(routes.get(&route),message["id"].as_u64()){let _=state.inbound.try_send(NativeCdpInbound::LocalRejected{id,code:"owner_closed".into(),message:"logical owner is closing; command was not dispatched".into()});}
                                    None
                                }else if pending.len()>=REQUEST_BUDGET{
                                    if let(Some(state),Some(id))=(routes.get(&route),message["id"].as_u64()){let _=state.inbound.try_send(NativeCdpInbound::LocalRejected{id,code:"request_budget".into(),message:"Host must apply and acknowledge pending receipts before dispatch".into()});}
                                    None
                                }else{
                                    if let(Some(context),Some(id))=(dispatch.wire_context.as_ref(),message["id"].as_u64()){
                                        let count=retired_contexts.len()+routes.values().map(|state|state.request_contexts.len()).sum::<usize>();
                                        if count>=MAX_PENDING_NATIVE_CONTEXTS{if let Some(state)=routes.get(&route){let _=state.inbound.try_send(NativeCdpInbound::LocalRejected{id,code:"request_budget".into(),message:"pending native metadata budget exhausted".into()});}return None;}
                                        if let Some(state)=routes.get_mut(&route){state.request_contexts.insert(id,context.clone());}
                                    }
                                    Some((true,with_wire_context(json!({"kind":"cdp","route":route,"message":message}),dispatch.wire_context.as_ref())))
                                }
                            })
                        }else{None}
                    },
                    ClientCommand::CloseCdp{route}=>{
                        if let Some(mut state)=routes.remove(&route){retire_contexts(route,&mut state,&mut retired_contexts);let _=state.inbound.try_send(NativeCdpInbound::TransportFailure("local CDP route ended; no physical cleanup proof".into()));let _=events.send(NativeProviderEvent::RouteUnavailable{claim:state.claim,reason:"local CDP route ended".into()});}
                        if writer.is_some(){Some((true,json!({"kind":"closeCdp","route":route})))}else{None}
                    }
                }
            }
        };
        let Some((outbound, frame)) = action else {
            continue;
        };
        if outbound {
            // Final check at the serial write boundary. Already-started writes
            // stay unknown if owner closure races them; queued work is fenced.
            if !owner_admitting(&owner) && frame["kind"] != "closeCdp" {
                fence_unsent(&frame, &mut pending, &mut opening, &routes, &events);
                continue;
            }
            if let Some(output) = &mut writer {
                let written =
                    tokio::time::timeout(IPC_WRITE_TIMEOUT, local_ipc::write_json(output, &frame))
                        .await;
                let failure = match written {
                    Ok(Ok(())) => None,
                    Ok(Err(error)) => Some(error.to_string()),
                    Err(_) => Some(
                        "native IPC write deadline expired; dispatched effects are unknown".into(),
                    ),
                };
                if let Some(reason) = failure {
                    disconnect(
                        &reason,
                        &owner,
                        &events,
                        &mut pending,
                        &mut opening,
                        &mut routes,
                    );
                    writer = None;
                    reader.abort();
                }
            }
            continue;
        }
        if frame["kind"] == "cdpOpened" && !owner_admitting(&owner) {
            if let Some(id) = frame["id"].as_u64() {
                if let Some(entry) = opening.remove(&id) {
                    for reply in entry.replies {
                        let _ = reply.send(Err(refused(
                            "owner_closed",
                            "logical owner ended before route publication",
                        )));
                    }
                }
            }
            if let (Some(route), Some(sender)) = (frame["route"].as_u64(), sender.upgrade()) {
                let _ = sender.try_send(ClientCommand::CloseCdp { route });
            }
            continue;
        }
        let applied = apply_server(
            frame,
            &mut pending,
            &mut opening,
            RouteReceipts {
                routes: &mut routes,
                retired_contexts: &mut retired_contexts,
            },
            &sender,
            &events,
            &mut next_id,
        );
        if let Err(error) = applied {
            disconnect(
                &error.to_string(),
                &owner,
                &events,
                &mut pending,
                &mut opening,
                &mut routes,
            );
            writer = None;
            reader.abort();
        }
    }
    disconnect(
        "native provider owner was dropped",
        &owner,
        &events,
        &mut pending,
        &mut opening,
        &mut routes,
    );
    reader.abort();
}

fn retire_contexts(
    route: u64,
    state: &mut RuntimeRoute,
    retired: &mut HashMap<(u64, u64), NativeWireContext>,
) {
    for (id, context) in state.request_contexts.drain() {
        retired.insert((route, id), context);
    }
}

fn with_wire_context(mut frame: Value, context: Option<&NativeWireContext>) -> Value {
    if let Some(context) = context {
        frame["wireContext"] = json!(context);
    }
    frame
}

fn owner_admitting(owner: &std::sync::Weak<ProviderInner>) -> bool {
    owner
        .upgrade()
        .is_some_and(|owner| owner.alive.load(Ordering::SeqCst))
}
fn fence_unsent(
    frame: &Value,
    pending: &mut HashMap<u64, PendingControl>,
    opening: &mut HashMap<u64, PendingOpen>,
    routes: &HashMap<u64, RuntimeRoute>,
    events: &broadcast::Sender<NativeProviderEvent>,
) {
    match frame["kind"].as_str() {
        Some("control") => {
            if let Some(id) = frame["request"]["id"].as_u64() {
                let _ = finish_control(
                    id,
                    NativeOperationOutcome::ConnectorRejected {
                        kind: "owner_closed".into(),
                        message: "logical owner closed before serial IPC dispatch".into(),
                        details: None,
                    },
                    pending,
                    events,
                );
            }
        }
        Some("openCdp") => {
            if let Some(id) = frame["id"].as_u64() {
                if let Some(entry) = opening.remove(&id) {
                    for reply in entry.replies {
                        let _ = reply.send(Err(refused(
                            "owner_closed",
                            "logical owner closed before serial IPC dispatch",
                        )));
                    }
                }
            }
        }
        Some("cdp") => {
            if let (Some(route), Some(id)) =
                (frame["route"].as_u64(), frame["message"]["id"].as_u64())
            {
                if let Some(route) = routes.get(&route) {
                    let _ = route.inbound.try_send(NativeCdpInbound::LocalRejected {
                        id,
                        code: "owner_closed".into(),
                        message: "logical owner closed before serial IPC dispatch".into(),
                    });
                }
            }
        }
        _ => {}
    }
}

fn merge_request(method: &str, id: u64, params: Value) -> Value {
    let mut request = params;
    if let Some(object) = request.as_object_mut() {
        object.insert("method".into(), Value::String(method.into()));
        object.insert("id".into(), Value::from(id));
    }
    request
}
fn finish_control(
    id: u64,
    outcome: NativeOperationOutcome,
    pending: &mut HashMap<u64, PendingControl>,
    events: &broadcast::Sender<NativeProviderEvent>,
) -> Result<(), NativeProviderError> {
    let Some(entry) = pending.get_mut(&id) else {
        return Err(protocol(
            "control response names an unissued/completed request",
        ));
    };
    if entry.outcome.is_some() {
        return Err(protocol("control request settled more than once"));
    }
    let mutation = entry.operation.mutation();
    if mutation {
        entry.outcome = Some(outcome.clone());
    }
    if let Some(reply) = entry.reply.take() {
        let _ = reply.send(ControlReply { id, outcome });
    }
    if mutation {
        let _ = events.send(NativeProviderEvent::CompletionReady { id });
    } else {
        pending.remove(&id);
    }
    Ok(())
}
fn retain_event_receipt(
    operation: NativeOperation,
    pending: &mut HashMap<u64, PendingControl>,
    events: &broadcast::Sender<NativeProviderEvent>,
    next_id: &mut u64,
) -> Result<(), NativeProviderError> {
    if pending.len() >= MAX_RETAINED_RECEIPTS {
        return Err(unknown(
            "retainReceipt",
            "bounded retained-receipt budget exhausted; keep Host custody unknown",
        ));
    }
    *next_id = next_id
        .checked_add(1)
        .ok_or_else(|| protocol("local receipt IDs exhausted"))?;
    let id = *next_id;
    pending.insert(
        id,
        PendingControl {
            operation,
            context: None,
            wire_context: None,
            reply: None,
            outcome: Some(NativeOperationOutcome::Result(Value::Null)),
        },
    );
    let _ = events.send(NativeProviderEvent::CompletionReady { id });
    Ok(())
}
/// Live routes and their retired request contexts stay in the same actor.
struct RouteReceipts<'a> {
    routes: &'a mut HashMap<u64, RuntimeRoute>,
    retired_contexts: &'a mut HashMap<(u64, u64), NativeWireContext>,
}

fn apply_server(
    frame: Value,
    pending: &mut HashMap<u64, PendingControl>,
    opening: &mut HashMap<u64, PendingOpen>,
    route_receipts: RouteReceipts<'_>,
    sender: &mpsc::WeakSender<ClientCommand>,
    events: &broadcast::Sender<NativeProviderEvent>,
    next_id: &mut u64,
) -> Result<(), NativeProviderError> {
    let RouteReceipts {
        routes,
        retired_contexts,
    } = route_receipts;
    match frame["kind"].as_str() {
        Some("controlEvent") => match decode::<ControlEvent>(frame["event"].clone())? {
            ControlEvent::Reply { id, outcome } => finish_control(id, outcome, pending, events)?,
            ControlEvent::ClaimCdpProgress { claim } => {
                let _ = events.send(NativeProviderEvent::ClaimCdpProgress { claim });
            }
            ControlEvent::ClaimUnavailable { claim, reason } => {
                let ids = routes
                    .iter()
                    .filter(|(_, route)| route.claim == claim)
                    .map(|(id, _)| *id)
                    .collect::<Vec<_>>();
                for id in ids {
                    if let Some(mut route) = routes.remove(&id) {
                        retire_contexts(id, &mut route, retired_contexts);
                        let _ = route
                            .inbound
                            .try_send(NativeCdpInbound::TransportFailure(reason.clone()));
                    }
                }
                let _ = events.send(NativeProviderEvent::ClaimUnavailable { claim, reason });
            }
            ControlEvent::DownloadChanged { download } => {
                let _ = events.send(NativeProviderEvent::DownloadChanged { download });
            }
            ControlEvent::GenerationClosed { reason } => {
                return Err(unknown("nativeGeneration", &reason))
            }
            ControlEvent::OrphanCdpCompletion {
                route,
                claim,
                id,
                event,
                wire_context,
            } => {
                let remembered = routes
                    .get_mut(&route)
                    .and_then(|state| state.request_contexts.remove(&id))
                    .or_else(|| retired_contexts.remove(&(route, id)));
                if wire_context
                    .as_ref()
                    .zip(remembered.as_ref())
                    .is_some_and(|(wire, remembered)| wire != remembered)
                {
                    return Err(protocol(
                        "orphan native metadata changed its exact request scope",
                    ));
                }
                let wire_context = wire_context.or(remembered);
                retain_event_receipt(
                    NativeOperation::OrphanCdpCompletion {
                        route,
                        claim: claim.clone(),
                        id,
                        event: event.clone(),
                    },
                    pending,
                    events,
                    next_id,
                )?;
                if let Some(entry) = pending.get_mut(next_id) {
                    entry.wire_context = wire_context.clone();
                }
                let _ = events.send(NativeProviderEvent::OrphanCdpCompletion {
                    route,
                    claim,
                    id,
                    outcome: event,
                    wire_context,
                });
            }
            ControlEvent::EffectsCleanup {
                claim,
                effect,
                cleanup_confirmed,
                error,
            } => {
                retain_event_receipt(
                    NativeOperation::EffectsCleanup {
                        claim: claim.clone(),
                        effect: effect.clone(),
                        cleanup_confirmed,
                        error: error.clone(),
                    },
                    pending,
                    events,
                    next_id,
                )?;
                let _ = events.send(NativeProviderEvent::EffectsCleanup {
                    claim,
                    effect,
                    cleanup_confirmed,
                    error,
                });
            }
            ControlEvent::TabStateChanged {
                claim,
                tab_id,
                window_id,
                active,
            } => {
                let _ = events.send(NativeProviderEvent::TabStateChanged {
                    claim,
                    tab_id,
                    window_id,
                    active,
                });
            }
            ControlEvent::TabStateUnknown {
                claim,
                tab_id,
                error,
            } => {
                let _ = events.send(NativeProviderEvent::TabStateUnknown {
                    claim,
                    tab_id,
                    error,
                });
            }
        },
        Some("cdpOpened") => {
            let id = frame["id"]
                .as_u64()
                .ok_or_else(|| protocol("open route lacks request ID"))?;
            let route = frame["route"]
                .as_u64()
                .filter(|id| *id > 0)
                .ok_or_else(|| protocol("open route lacks route ID"))?;
            let entry = opening
                .remove(&id)
                .ok_or_else(|| protocol("route opened without pending request"))?;
            if routes.contains_key(&route) {
                return Err(protocol("broker reused live route ID"));
            }
            let (outbound, commands) = mpsc::channel(ROUTE_QUEUE);
            let (inbound, incoming) = mpsc::channel(ROUTE_QUEUE);
            let (close, closed) = oneshot::channel();
            let connection = Arc::new(CdpConnection::from_native_channels(
                outbound, incoming, close,
            ));
            routes.insert(
                route,
                RuntimeRoute {
                    claim: entry.claim,
                    inbound,
                    connection: connection.clone(),
                    request_contexts: HashMap::new(),
                },
            );
            let pump_sender = sender
                .upgrade()
                .ok_or_else(|| unknown("openCdp", "provider owner ended before route admission"))?;
            tokio::spawn(pump_cdp(route, commands, closed, pump_sender));
            for reply in entry.replies {
                let _ = reply.send(Ok(connection.clone()));
            }
        }
        Some("cdpOpenRejected") => {
            let id = frame["id"]
                .as_u64()
                .ok_or_else(|| protocol("route rejection lacks ID"))?;
            let entry = opening
                .remove(&id)
                .ok_or_else(|| protocol("route rejection names no request"))?;
            let code = nonempty(&frame, "code")?;
            let message = nonempty(&frame, "message")?;
            for reply in entry.replies {
                let _ = reply.send(Err(refused(&code, &message)));
            }
        }
        Some("cdpEvent") => {
            let route = frame["route"]
                .as_u64()
                .ok_or_else(|| protocol("CDP event lacks route"))?;
            let Some(state) = routes.get_mut(&route) else {
                return Ok(());
            };
            let decoded = decode::<NativeCdpCompletionOutcome>(frame["event"].clone())?;
            let reply_id = match &decoded {
                NativeCdpCompletionOutcome::ChromeMessage(value) => value["id"].as_u64(),
                NativeCdpCompletionOutcome::LocalRejected { id, .. } => Some(*id),
                NativeCdpCompletionOutcome::TransportFailure(_) => None,
            };
            if let Some(id) = reply_id {
                state.request_contexts.remove(&id);
            }
            let ended = matches!(decoded, NativeCdpCompletionOutcome::TransportFailure(_));
            let inbound = match decoded {
                NativeCdpCompletionOutcome::ChromeMessage(value) => {
                    NativeCdpInbound::ChromeMessage(value)
                }
                NativeCdpCompletionOutcome::LocalRejected { id, code, message } => {
                    NativeCdpInbound::LocalRejected { id, code, message }
                }
                NativeCdpCompletionOutcome::TransportFailure(reason) => {
                    NativeCdpInbound::TransportFailure(reason)
                }
            };
            let queue_failed = state.inbound.try_send(inbound).is_err();
            if ended || queue_failed {
                let claim = state.claim.clone();
                if let Some(mut state) = routes.remove(&route) {
                    retire_contexts(route, &mut state, retired_contexts);
                }
                let _ = events.send(NativeProviderEvent::RouteUnavailable {
                    claim,
                    reason: if ended {
                        "native claim route ended"
                    } else {
                        "CDP event queue exceeded its bound or consumer ended"
                    }
                    .into(),
                });
                if let Some(sender) = sender.upgrade() {
                    let _ = sender.try_send(ClientCommand::CloseCdp { route });
                }
            }
        }
        _ => return Err(protocol("unexpected native IPC server frame")),
    }
    Ok(())
}
async fn pump_cdp(
    route: u64,
    mut commands: mpsc::Receiver<NativeCdpCommand>,
    mut closed: oneshot::Receiver<()>,
    sender: mpsc::Sender<ClientCommand>,
) {
    loop {
        tokio::select! {biased;
            _=&mut closed=>{let _=sender.send(ClientCommand::CloseCdp{route}).await;break;},
            command=commands.recv()=>{let Some(command)=command else{let _=sender.send(ClientCommand::CloseCdp{route}).await;break;};
                // Keep the command opaque through the actor queue. The actor
                // checks its liveness immediately before the serial IPC write.
                if sender.send(ClientCommand::Cdp{route,command}).await.is_err(){break;}
            }
        }
    }
}
fn disconnect(
    reason: &str,
    owner: &std::sync::Weak<ProviderInner>,
    events: &broadcast::Sender<NativeProviderEvent>,
    pending: &mut HashMap<u64, PendingControl>,
    opening: &mut HashMap<u64, PendingOpen>,
    routes: &mut HashMap<u64, RuntimeRoute>,
) {
    if let Some(owner) = owner.upgrade() {
        owner.alive.store(false, Ordering::SeqCst);
    }
    let ids = pending
        .iter()
        .filter(|(_, entry)| entry.outcome.is_none())
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();
    for id in ids {
        let _ = finish_control(
            id,
            NativeOperationOutcome::Unknown {
                reason: reason.to_owned(),
                details: None,
            },
            pending,
            events,
        );
    }
    for (_, entry) in opening.drain() {
        for reply in entry.replies {
            let _ = reply.send(Err(unknown("openCdp", reason)));
        }
    }
    for (_, route) in routes.drain() {
        let _ = route
            .inbound
            .try_send(NativeCdpInbound::TransportFailure(reason.to_owned()));
    }
    let _ = events.send(NativeProviderEvent::GenerationClosed {
        reason: reason.to_owned(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;

    async fn bounded<T>(future: impl Future<Output = T>) -> T {
        tokio::time::timeout(std::time::Duration::from_secs(2), future)
            .await
            .expect("hermetic actor boundary must complete")
    }
    #[cfg(unix)]
    fn fixture() -> (NativeBrowserProvider, tokio::net::UnixStream) {
        fixture_with_capabilities(own_capabilities())
    }
    fn own_capabilities() -> Value {
        json!({"metadata":true,"rawTabCdp":true,"userTabsOrder":"host","headerScope":"claim","createdPresentationOwner":"host","cursorPresentationOwner":"host","cursorHideOwner":"host","turnLifecycleOwner":"host","downloadNotifications":true})
    }
    fn original_capabilities() -> Value {
        json!({"metadata":true,"rawTabCdp":true,"userTabsOrder":"provider","headerScope":"session","createdPresentationOwner":"provider","cursorPresentationOwner":"provider","cursorHideOwner":"unavailable","turnLifecycleOwner":"provider","downloadNotifications":true})
    }
    #[cfg(unix)]
    fn fixture_with_capabilities(
        capabilities: Value,
    ) -> (NativeBrowserProvider, tokio::net::UnixStream) {
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        let (commands, incoming) = mpsc::channel(ACTOR_QUEUE);
        let (events, _) = broadcast::channel(EVENT_QUEUE);
        let inner = Arc::new(ProviderInner {
            identity: NativeEndpointIdentity {
                adapter: "org.apache.maka.browser_connector".into(),
                extension_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                instance_id: "fixture-instance".into(),
                generation: uuid::Uuid::new_v4().to_string(),
                capabilities,
                host_pid: std::process::id(),
            },
            binding: uuid::Uuid::new_v4(),
            commands: commands.clone(),
            events: events.clone(),
            alive: AtomicBool::new(true),
        });
        tokio::spawn(run_client(
            client,
            incoming,
            commands.downgrade(),
            Arc::downgrade(&inner),
            events,
        ));
        (
            NativeBrowserProvider {
                inner,
                host_operation: None,
                wire_context: None,
            },
            server,
        )
    }
    #[cfg(unix)]
    async fn request(server: &mut tokio::net::UnixStream) -> Value {
        bounded(local_ipc::read_json(server))
            .await
            .unwrap()
            .expect("runtime request")
    }
    #[cfg(unix)]
    async fn control_result(server: &mut tokio::net::UnixStream, id: u64, result: Value) {
        local_ipc::write_json(server,&json!({"kind":"controlEvent","event":{"kind":"reply","data":{"id":id,"outcome":{"kind":"result","data":result}}}})).await.unwrap();
    }
    #[cfg(unix)]
    async fn attach_fixture(
        provider: &NativeBrowserProvider,
        server: &mut tokio::net::UnixStream,
        tab_id: u64,
        token: &str,
    ) -> NativePhysicalClaim {
        let call = {
            let provider = provider.clone();
            tokio::spawn(async move { provider.attach_tab(tab_id).await })
        };
        let sent = request(server).await;
        assert_eq!(sent["request"]["method"], "attach");
        control_result(
            server,
            sent["request"]["id"].as_u64().unwrap(),
            json!({"claim":token,"tabId":tab_id,"targetId":format!("target-{tab_id}")}),
        )
        .await;
        let claim = bounded(call).await.unwrap().unwrap();
        provider
            .acknowledge_completion(claim.completion_id())
            .await
            .unwrap();
        claim
    }
    #[cfg(unix)]
    async fn wait_ready(provider: &NativeBrowserProvider) -> Vec<NativeOperationCompletion> {
        bounded(async {
            loop {
                let ready = provider.pending_completions().await.unwrap();
                if !ready.is_empty() {
                    return ready;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
    }

    #[test]
    fn actual_metadata_is_optional_and_mutation_diagnostic_requires_nullable_changed() {
        let tab: NativeTabInfo =
            decode(json!({"id":0,"lastAccessed":1234.5,"active":false,"pendingUrl":"about:blank"}))
                .unwrap();
        assert_eq!(tab.id, 0);
        assert_eq!(tab.last_accessed, Some(1234.5));
        assert_eq!(tab.active, Some(false));
        assert!(tab.title.is_none());
        let diagnostic: NativeMutationDiagnostic =
            decode(json!({"attempted":true,"mutationAcknowledged":false,"changed":null})).unwrap();
        assert_eq!(diagnostic.changed, None);
        assert!(decode::<NativeMutationDiagnostic>(
            json!({"attempted":true,"mutationAcknowledged":false})
        )
        .is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn canceled_attach_keeps_original_context_and_recovers_cleanup_without_replay() {
        let (provider, mut server) = fixture();
        let context = NativeHostOperation {
            operation_id: "canonical-operation-A".into(),
            turn_id: "original-turn".into(),
        };
        let scoped = provider.with_host_operation(context.clone());
        let call = tokio::spawn(async move { scoped.attach_tab(12).await });
        let sent = request(&mut server).await;
        let id = sent["request"]["id"].as_u64().unwrap();
        call.abort();
        let _ = call.await;
        let snapshot = provider.pending_operations().await.unwrap();
        assert_eq!(snapshot.len(), 1);
        assert!(snapshot[0].outcome.is_none());
        assert_eq!(snapshot[0].host_operation, Some(context.clone()));
        control_result(
            &mut server,
            id,
            json!({"claim":"owned-claim-A","tabId":12,"targetId":"target-A"}),
        )
        .await;
        let completed = wait_ready(&provider).await;
        assert_eq!(completed[0].host_operation, Some(context));
        let recovered = provider.recover_completion(id).await.unwrap();
        let NativeRecoveredOperation::Claim(claim) = recovered else {
            panic!("matched attach must recover physical claim");
        };
        assert_eq!(claim.claim_id(), "owned-claim-A");
        assert_eq!(claim.tab_id(), 12);
        let detach = {
            let provider = provider.clone();
            tokio::spawn(async move { provider.detach_tab(&claim).await })
        };
        let cleanup = request(&mut server).await;
        assert_eq!(cleanup["request"]["method"], "detach");
        assert_eq!(cleanup["request"]["claim"], "owned-claim-A");
        let detach_id = cleanup["request"]["id"].as_u64().unwrap();
        control_result(
            &mut server,
            detach_id,
            json!({"detached":true,"proof":"detach_ack"}),
        )
        .await;
        assert_eq!(
            bounded(detach).await.unwrap().unwrap().evidence(),
            CleanupEvidence::DetachAcknowledged
        );
        provider.acknowledge_completion(id).await.unwrap();
        provider.acknowledge_completion(detach_id).await.unwrap();
        assert!(provider.pending_completions().await.unwrap().is_empty());
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn delivered_control_reply_is_retained_until_host_ack_and_snapshot_is_a_barrier() {
        let (provider, mut server) = fixture();
        let call = {
            let provider = provider.clone();
            tokio::spawn(async move { provider.create_tab(None).await })
        };
        let sent = request(&mut server).await;
        let id = sent["request"]["id"].as_u64().unwrap();
        control_result(
            &mut server,
            id,
            json!({"creation":"creation-A","tab":{"id":44,"windowId":7}}),
        )
        .await;
        let created = bounded(call).await.unwrap().unwrap();
        assert_eq!(created.tab.id, 44);
        let snapshot = provider.pending_operations().await.unwrap();
        assert_eq!(snapshot.len(), 1);
        assert!(snapshot[0].outcome.is_some());
        let NativeRecoveredOperation::Created(recovered) =
            provider.recover_completion(id).await.unwrap()
        else {
            panic!("creation must be recoverable");
        };
        assert_eq!(recovered.creation_receipt().creation_id(), "creation-A");
        provider.acknowledge_completion(id).await.unwrap();
        assert!(provider.pending_operations().await.unwrap().is_empty());
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cleanup_only_attachment_cannot_set_headers_but_can_clear_exact_scope() {
        let (provider, mut server) = fixture();
        let call = {
            let provider = provider.clone();
            tokio::spawn(async move { provider.attach_tab(23).await })
        };
        let sent = request(&mut server).await;
        let id = sent["request"]["id"].as_u64().unwrap();
        local_ipc::write_json(&mut server,&json!({"kind":"controlEvent","event":{"kind":"reply","data":{"id":id,"outcome":{"kind":"unknown","data":{"reason":"cleanup unconfirmed","details":{"custody":{"claim":"cleanup-token","tabId":23,"targetId":"target-23"}}}}}}})).await.unwrap();
        assert!(matches!(
            bounded(call).await.unwrap(),
            Err(NativeProviderError::OutcomeUnknown { .. })
        ));
        let NativeRecoveredOperation::Unknown { custody, .. } =
            provider.recover_completion(id).await.unwrap()
        else {
            panic!("unknown attachment must retain typed custody");
        };
        let claim = custody.claim.unwrap();
        assert!(claim.is_cleanup_only());
        let error = provider
            .set_scoped_headers(
                &claim,
                "trusted-session",
                Some(&[NativeHeader {
                    name: "x-browser-agent".into(),
                    value: "Maka/trusted-session".into(),
                }]),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, NativeProviderError::Refused { .. }));
        let clear = {
            let provider = provider.clone();
            let claim = claim.clone();
            tokio::spawn(async move { provider.clear_scoped_headers(&claim).await })
        };
        let sent = request(&mut server).await;
        assert_eq!(sent["request"]["method"], "clearScopedHeaders");
        let clear_id = sent["request"]["id"].as_u64().unwrap();
        control_result(&mut server,clear_id,json!({"stateConfirmed":true,"cleanupConfirmed":true,"active":false,"pendingRemoval":false,"scope":{"claim":"cleanup-token","generation":provider.identity().generation,"owner":"owner-A","tabId":23}})).await;
        assert!(bounded(clear).await.unwrap().unwrap().cleanup_confirmed);
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn orphan_and_effect_receipts_survive_without_a_broadcast_subscriber() {
        let (provider, mut server) = fixture();
        local_ipc::write_json(&mut server,&json!({"kind":"controlEvent","event":{"kind":"orphanCdpCompletion","data":{"route":7,"claim":"claim-A","id":5,"event":{"kind":"chromeMessage","data":{"id":5,"result":{"ack":true}}}}}})).await.unwrap();
        local_ipc::write_json(&mut server,&json!({"kind":"controlEvent","event":{"kind":"effectsCleanup","data":{"claim":"claim-A","effect":"headers","cleanupConfirmed":true,"error":null}}})).await.unwrap();
        let ready = bounded(async {
            loop {
                let ready = provider.pending_completions().await.unwrap();
                if ready.len() == 2 {
                    return ready;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        let mut saw_orphan = false;
        let mut saw_headers = false;
        for receipt in ready {
            match provider.recover_completion(receipt.id).await.unwrap() {
                NativeRecoveredOperation::OrphanCdpCompletion { route, id, .. } => {
                    assert_eq!((route, id), (7, 5));
                    saw_orphan = true;
                }
                NativeRecoveredOperation::EffectsCleanup {
                    effect,
                    cleanup_confirmed,
                    ..
                } => {
                    assert_eq!(effect, "headers");
                    assert!(cleanup_confirmed);
                    saw_headers = true;
                }
                _ => panic!("event proof must not become a physical detach proof"),
            };
            provider.acknowledge_completion(receipt.id).await.unwrap();
        }
        assert!(saw_orphan && saw_headers);
        assert!(provider.pending_completions().await.unwrap().is_empty());
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn empty_control_snapshot_during_cdp_input_is_not_cleanup_or_settlement() {
        let (provider, mut server) = fixture();
        let claim = attach_fixture(&provider, &mut server, 31, "claim-A").await;
        let open = {
            let provider = provider.clone();
            tokio::spawn(async move { provider.open_cdp_channel(&claim).await })
        };
        let request_open = request(&mut server).await;
        let open_id = request_open["id"].as_u64().unwrap();
        local_ipc::write_json(
            &mut server,
            &json!({"kind":"cdpOpened","id":open_id,"route":11}),
        )
        .await
        .unwrap();
        let connection = bounded(open).await.unwrap().unwrap();
        let input = {
            let connection = connection.clone();
            tokio::spawn(async move {
                connection
                    .call(None, "Input.insertText", json!({"text":"once"}))
                    .await
            })
        };
        let sent = request(&mut server).await;
        assert_eq!(sent["kind"], "cdp");
        assert_eq!(sent["message"]["method"], "Input.insertText");
        assert!(provider.pending_operations().await.unwrap().is_empty());
        assert!(!input.is_finished());
        input.abort();
        let _ = input.await;
        let fenced = request(&mut server).await;
        assert_eq!(fenced["kind"], "closeCdp");
        assert_eq!(fenced["route"], 11);
        assert!(!provider.is_closed());
        let inventory = {
            let provider = provider.clone();
            tokio::spawn(async move { provider.list_user_tabs().await })
        };
        let next = request(&mut server).await;
        assert_eq!(
            next["request"]["method"], "inventory",
            "route cancellation must not detach claim or end sibling owner"
        );
        control_result(
            &mut server,
            next["request"]["id"].as_u64().unwrap(),
            json!({"tabs":[]}),
        )
        .await;
        assert!(bounded(inventory).await.unwrap().unwrap().is_empty());
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn duplicate_open_waiters_are_bounded_and_share_one_route() {
        let (provider, mut server) = fixture();
        let claim = attach_fixture(&provider, &mut server, 32, "claim-B").await;
        let (results, mut result) = mpsc::channel(65);
        let mut tasks = Vec::new();
        for _ in 0..65 {
            let provider = provider.clone();
            let claim = claim.clone();
            let results = results.clone();
            tasks.push(tokio::spawn(async move {
                let value = provider.open_cdp_channel(&claim).await;
                let _ = results.send(value).await;
            }));
        }
        drop(results);
        let opening = request(&mut server).await;
        let first = bounded(result.recv()).await.unwrap();
        assert!(
            matches!(first,Err(NativeProviderError::Refused{ref kind,..})if kind=="request_budget")
        );
        local_ipc::write_json(
            &mut server,
            &json!({"kind":"cdpOpened","id":opening["id"],"route":12}),
        )
        .await
        .unwrap();
        let mut shared = None;
        for _ in 0..64 {
            let connection = bounded(result.recv()).await.unwrap().unwrap();
            if let Some(first) = &shared {
                assert!(Arc::ptr_eq(first, &connection));
            } else {
                shared = Some(connection);
            }
        }
        for task in tasks {
            bounded(task).await.unwrap();
        }
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn final_provider_drop_closes_ipc_instead_of_self_sender_task_cycle() {
        let (provider, mut server) = fixture();
        let claim = attach_fixture(&provider, &mut server, 41, "drop-claim").await;
        let open = {
            let provider = provider.clone();
            tokio::spawn(async move { provider.open_cdp_channel(&claim).await })
        };
        let opening = request(&mut server).await;
        local_ipc::write_json(
            &mut server,
            &json!({"kind":"cdpOpened","id":opening["id"],"route":18}),
        )
        .await
        .unwrap();
        let connection = bounded(open).await.unwrap().unwrap();
        drop(provider);
        assert!(bounded(local_ipc::read_json(&mut server))
            .await
            .unwrap()
            .is_none());
        bounded(async {
            while !connection.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await;
    }
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn explicit_close_fences_control_already_queued_but_not_written() {
        let (provider, mut server) = fixture();
        let (reply, result) = oneshot::channel();
        provider
            .inner
            .commands
            .send(ClientCommand::Control {
                operation: NativeOperation::Attach { tab_id: 51 },
                params: json!({"tabId":51}),
                context: None,
                wire_context: None,
                reply,
            })
            .await
            .unwrap();
        let close = provider.close();
        tokio::pin!(close);
        assert!(futures_util::poll!(close.as_mut()).is_pending());
        assert!(provider.is_closed());
        let response = bounded(result).await.unwrap();
        assert!(
            matches!(response.outcome,NativeOperationOutcome::ConnectorRejected{ref kind,..}if kind=="owner_closed")
        );
        bounded(close).await;
        assert!(
            bounded(local_ipc::read_json(&mut server))
                .await
                .unwrap()
                .is_none(),
            "queued control must not reach the host after close begins"
        );
        assert!(provider.pending_operations().await.unwrap().is_empty());
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn immutable_control_wire_context_survives_late_ack_and_new_turn_view() {
        let (provider, mut server) = fixture();
        let wire = NativeWireContext::new("existing-canonical-owner", "turn-A").unwrap();
        let context = NativeHostOperation {
            operation_id: "existing-operation-A".into(),
            turn_id: "turn-A".into(),
        };
        let scoped = provider
            .with_host_operation(context.clone())
            .with_wire_context(wire.clone());
        let call = tokio::spawn(async move { scoped.attach_tab(61).await });
        let sent = request(&mut server).await;
        let id = sent["request"]["id"].as_u64().unwrap();
        assert_eq!(
            sent["wireContext"],
            json!({"hostSessionId":"existing-canonical-owner","hostTurnId":"turn-A"})
        );
        assert!(sent["request"].get("wireContext").is_none());
        call.abort();
        let _ = call.await;
        let _new_view = provider.with_wire_context(
            NativeWireContext::new("existing-canonical-owner", "turn-B").unwrap(),
        );
        control_result(
            &mut server,
            id,
            json!({"claim":"late-A","tabId":61,"targetId":"target-A"}),
        )
        .await;
        let ready = wait_ready(&provider).await;
        assert_eq!(ready[0].wire_context, Some(wire));
        assert_eq!(ready[0].host_operation, Some(context));
        let NativeRecoveredOperation::Claim(claim) = provider.recover_completion(id).await.unwrap()
        else {
            panic!("matched late claim expected");
        };
        assert_eq!(claim.tab_id(), 61);
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn each_cdp_call_uses_explicit_wire_context_on_the_same_route() {
        let (provider, mut server) = fixture();
        let claim = attach_fixture(&provider, &mut server, 62, "context-claim").await;
        let open = {
            let provider = provider.clone();
            tokio::spawn(async move { provider.open_cdp_channel(&claim).await })
        };
        let opening = request(&mut server).await;
        local_ipc::write_json(
            &mut server,
            &json!({"kind":"cdpOpened","id":opening["id"],"route":27}),
        )
        .await
        .unwrap();
        let connection = bounded(open).await.unwrap().unwrap();
        for turn in ["turn-A", "turn-B"] {
            let context = NativeWireContext::new("existing-owner", turn).unwrap();
            let call = {
                let connection = connection.clone();
                tokio::spawn(async move {
                    connection
                        .call_with_native_context(
                            &context,
                            None,
                            "Runtime.evaluate",
                            json!({"expression":"1"}),
                        )
                        .await
                })
            };
            let sent = request(&mut server).await;
            assert_eq!(sent["wireContext"]["hostTurnId"], turn);
            assert!(sent["message"].get("wireContext").is_none());
            local_ipc::write_json(&mut server,&json!({"kind":"cdpEvent","route":27,"event":{"kind":"chromeMessage","data":{"id":sent["message"]["id"],"result":{"value":1}}}})).await.unwrap();
            assert_eq!(bounded(call).await.unwrap().unwrap()["value"], 1);
        }
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn logical_finish_requires_context_and_returns_no_physical_cleanup_proof() {
        let (provider, mut server) = fixture_with_capabilities(original_capabilities());
        assert!(
            matches!(provider.finish_turn(None).await,Err(NativeProviderError::Refused{ref kind,..})if kind=="missing_context")
        );
        let context = NativeWireContext::new("existing-owner", "finishing-turn").unwrap();
        let scoped = provider.with_wire_context(context);
        let call = tokio::spawn(async move {
            scoped
                .finish_turn(Some(&[NativeKeepTab {
                    tab_id: 72,
                    status: NativeKeepStatus::Deliverable,
                }]))
                .await
        });
        let sent = request(&mut server).await;
        assert_eq!(sent["request"]["method"], "finishTurn");
        assert_eq!(
            sent["request"]["keep"],
            json!([{"tabId":72,"status":"deliverable"}])
        );
        assert_eq!(sent["wireContext"]["hostTurnId"], "finishing-turn");
        let id = sent["request"]["id"].as_u64().unwrap();
        control_result(&mut server, id, Value::Null).await;
        let acknowledged = bounded(call).await.unwrap().unwrap();
        assert_eq!(acknowledged.host_turn_id, "finishing-turn");
        assert!(matches!(
            provider.recover_completion(id).await.unwrap(),
            NativeRecoveredOperation::TurnFinished(_)
        ));
        provider.close().await;
    }

    #[test]
    fn original_tab_strings_are_preserved_without_date_or_id_invention() {
        let tab:NativeTabInfo=decode(json!({"id":82,"providerTabId":"actual-opaque-provider-id","lastOpened":"2026-10-27T01:02:03.004Z","groupTitle":"actual-group"})).unwrap();
        assert_eq!(tab.last_opened.as_deref(), Some("2026-10-27T01:02:03.004Z"));
        assert_eq!(
            tab.provider_tab_id.as_deref(),
            Some("actual-opaque-provider-id")
        );
        assert!(tab.last_accessed.is_none());
        assert!(tab.window_id.is_none());
    }
    #[test]
    fn routing_metadata_preserves_provider_scope_and_refuses_missing_lifecycle_fact() {
        let own: NativeProviderCapabilities = decode(own_capabilities()).unwrap();
        assert_eq!(own.header_scope, NativeHeaderPolicyScope::Claim);
        assert_eq!(own.created_presentation_owner, NativeEffectOwner::Host);
        let original: NativeProviderCapabilities = decode(original_capabilities()).unwrap();
        assert_eq!(original.user_tabs_order, NativeUserTabsOrder::Provider);
        assert_eq!(original.header_scope, NativeHeaderPolicyScope::Session);
        assert_eq!(original.cursor_hide_owner, NativeEffectOwner::Unavailable);
        assert_eq!(original.turn_lifecycle_owner, NativeEffectOwner::Provider);
        let mut incomplete = own_capabilities();
        incomplete
            .as_object_mut()
            .unwrap()
            .remove("turnLifecycleOwner");
        assert!(decode::<NativeProviderCapabilities>(incomplete).is_err());
    }

    #[test]
    fn tab_absence_is_bound_to_created_identity_and_distinct_from_logical_acknowledgement() {
        let result = json!({"closed":true,"proof":"tab_absent","tabId":81,"observationRequestId":"actual-native-request"});
        let reply = |value| ControlReply {
            id: 9,
            outcome: NativeOperationOutcome::Result(value),
        };
        let proof = close_proof(reply(result.clone()), Some(81)).unwrap();
        assert_eq!(proof.evidence(), CleanupEvidence::TabAbsenceObserved);
        assert_ne!(proof.evidence(), CleanupEvidence::CloseAcknowledged);
        assert_eq!(
            proof.tab_absence_observation().unwrap().native_request_id(),
            "actual-native-request"
        );
        assert_eq!(proof.tab_absence_observation().unwrap().tab_id(), 81);
        assert!(close_proof(reply(result.clone()), None).is_err());
        assert!(close_proof(reply(result), Some(82)).is_err());
        for value in [
            Value::Null,
            json!({"closed":true,"proof":"tab_absent"}),
            json!({"closed":true,"proof":"tab_absent","tabId":81}),
            json!({"closed":true,"proof":"tab_absent","tabId":81,"observationRequestId":""}),
            json!({"closed":true,"proof":"turn_ended"}),
        ] {
            assert!(close_proof(reply(value), Some(81)).is_err());
        }
    }

    #[test]
    fn session_policy_proof_requires_exact_context_and_requested_state() {
        let context = NativeWireContext::new("stable-session", "old-turn").unwrap();
        let proof = json!({"hostSessionId":"stable-session","hostTurnId":"old-turn","generation":"generation","owner":"owner","stateConfirmed":true,"active":false,"cleanupConfirmed":true});
        let reply = |value| ControlReply {
            id: 15,
            outcome: NativeOperationOutcome::Result(value),
        };
        assert!(
            !session_header_proof(reply(proof.clone()), &context, "generation", false)
                .unwrap()
                .active
        );
        assert!(session_header_proof(reply(proof.clone()), &context, "generation", true).is_err());
        let mut wrong_turn = proof.clone();
        wrong_turn["hostTurnId"] = json!("new-turn");
        assert!(session_header_proof(reply(wrong_turn), &context, "generation", false).is_err());
        assert!(
            session_header_proof(reply(proof), &context, "replacement-generation", false).is_err()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn canceled_session_header_result_recovers_exact_old_scope_without_claim_or_replay() {
        let (provider, mut server) = fixture_with_capabilities(original_capabilities());
        let context = NativeWireContext::new("stable-browser-owner", "captured-old-turn").unwrap();
        let scoped = provider
            .with_wire_context(context)
            .with_host_operation(NativeHostOperation {
                operation_id: "existing-host-operation".into(),
                turn_id: "captured-old-turn".into(),
            });
        let call = tokio::spawn(async move {
            scoped
                .set_session_headers(&[NativeHeader {
                    name: "X-Maka-Session".into(),
                    value: "trusted-expanded-value".into(),
                }])
                .await
        });
        let sent = request(&mut server).await;
        assert_eq!(sent["request"]["method"], "setSessionHeaders");
        assert!(sent["request"].get("claim").is_none());
        assert_eq!(sent["wireContext"]["hostTurnId"], "captured-old-turn");
        let id = sent["request"]["id"].as_u64().unwrap();
        call.abort();
        let _ = call.await;
        let _later_view = provider
            .with_wire_context(NativeWireContext::new("stable-browser-owner", "new-turn").unwrap());
        control_result(&mut server,id,json!({"hostSessionId":"stable-browser-owner","hostTurnId":"captured-old-turn","generation":provider.identity().generation,"owner":"broker-owner","stateConfirmed":true,"active":true,"cleanupConfirmed":false})).await;
        let ready = wait_ready(&provider).await;
        assert_eq!(ready.len(), 1);
        assert_eq!(
            ready[0].host_operation.as_ref().unwrap().operation_id,
            "existing-host-operation"
        );
        let NativeRecoveredOperation::SessionHeaders(proof) =
            provider.recover_completion(id).await.unwrap()
        else {
            panic!("must recover exact policy receipt")
        };
        assert_eq!(proof.host_turn_id, "captured-old-turn");
        assert!(proof.active);
        assert!(!proof.cleanup_confirmed);
        provider.acknowledge_completion(id).await.unwrap();
        let inventory = {
            let provider = provider.clone();
            tokio::spawn(async move { provider.list_user_tabs().await })
        };
        let next = request(&mut server).await;
        assert_eq!(next["request"]["method"], "inventory");
        control_result(
            &mut server,
            next["request"]["id"].as_u64().unwrap(),
            json!({"tabs":[]}),
        )
        .await;
        assert!(bounded(inventory).await.unwrap().unwrap().is_empty());
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn own_capabilities_refuse_original_only_methods_before_dispatch() {
        let (provider, mut server) = fixture();
        let claim = attach_fixture(&provider, &mut server, 91, "own-claim").await;
        let scoped = provider.with_wire_context(NativeWireContext::new("owner", "turn").unwrap());
        for result in [
            scoped.set_session_headers(&[]).await.map(|_| ()),
            scoped.clear_session_headers().await.map(|_| ()),
            scoped
                .move_mouse_presentation(&claim, 1.0, 2.0, None)
                .await
                .map(|_| ()),
            scoped.finish_turn(None).await.map(|_| ()),
        ] {
            assert!(
                matches!(result,Err(NativeProviderError::Refused{ref kind,..})if kind=="unsupported")
            );
        }
        assert!(provider.pending_operations().await.unwrap().is_empty());
        let inventory = {
            let provider = provider.clone();
            tokio::spawn(async move { provider.list_user_tabs().await })
        };
        let next = request(&mut server).await;
        assert_eq!(next["request"]["method"], "inventory");
        control_result(
            &mut server,
            next["request"]["id"].as_u64().unwrap(),
            json!({"tabs":[]}),
        )
        .await;
        bounded(inventory).await.unwrap().unwrap();
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn native_cursor_ack_is_only_presentation_and_rejects_uncertain_claim_and_nan() {
        let (provider, mut server) = fixture_with_capabilities(original_capabilities());
        let claim = attach_fixture(&provider, &mut server, 92, "original-claim").await;
        let scoped =
            provider.with_wire_context(NativeWireContext::new("owner", "cursor-turn").unwrap());
        let mut uncertain = claim.clone();
        uncertain.cleanup_only = true;
        assert!(
            matches!(scoped.move_mouse_presentation(&uncertain,1.0,2.0,None).await,Err(NativeProviderError::Refused{ref kind,..})if kind=="claim_unavailable")
        );
        assert!(
            matches!(scoped.move_mouse_presentation(&claim,f64::NAN,2.0,None).await,Err(NativeProviderError::Refused{ref kind,..})if kind=="invalid_request")
        );
        let call = tokio::spawn(async move {
            scoped
                .move_mouse_presentation(&claim, 10.0, 20.0, Some(true))
                .await
        });
        let sent = request(&mut server).await;
        assert_eq!(sent["request"]["method"], "moveMouse");
        assert_eq!(sent["request"]["waitForArrival"], true);
        assert_eq!(sent["wireContext"]["hostTurnId"], "cursor-turn");
        let id = sent["request"]["id"].as_u64().unwrap();
        control_result(&mut server, id, Value::Null).await;
        let ack = bounded(call).await.unwrap().unwrap();
        assert_eq!(ack.requested_x, 10.0);
        assert!(matches!(
            provider.recover_completion(id).await.unwrap(),
            NativeRecoveredOperation::CursorPresentation(_)
        ));
        provider.acknowledge_completion(id).await.unwrap();
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn global_download_metadata_never_creates_custody_or_cleanup_receipt() {
        let (provider, mut server) = fixture();
        let mut events = provider.subscribe_events();
        local_ipc::write_json(&mut server,&json!({"kind":"controlEvent","event":{"kind":"downloadChanged","data":{"download":{"id":"actual-download","filename":"","url":"https://fixture.invalid/file","status":"in_progress"}}}})).await.unwrap();
        let NativeProviderEvent::DownloadChanged { download } =
            bounded(events.recv()).await.unwrap()
        else {
            panic!("expected global metadata event")
        };
        assert_eq!(download.id, "actual-download");
        assert_eq!(download.filename, "");
        assert_eq!(download.status, NativeDownloadStatus::InProgress);
        assert!(provider.pending_completions().await.unwrap().is_empty());
        assert!(provider.pending_operations().await.unwrap().is_empty());
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn claim_drain_captures_progress_before_the_first_fence_reply() {
        let (provider, mut server) = fixture();
        let claim = attach_fixture(&provider, &mut server, 23, "drain-owned").await;
        assert!(provider.pending_operations().await.unwrap().is_empty());
        let waiting = {
            let provider = provider.clone();
            let claim = claim.clone();
            tokio::spawn(async move {
                provider
                    .wait_claim_cdp_drained(&claim, std::time::Duration::from_secs(1))
                    .await
            })
        };
        let first = request(&mut server).await;
        assert_eq!(first["request"]["method"], "fenceCdp");
        assert_eq!(first["request"]["claim"], "drain-owned");
        // This progress races the initial observation. A post-reply subscriber
        // would miss it and never perform the required fresh observation.
        local_ipc::write_json(&mut server, &json!({"kind":"controlEvent","event":{"kind":"claimCdpProgress","data":{"claim":"drain-owned"}}})).await.unwrap();
        control_result(&mut server, first["request"]["id"].as_u64().unwrap(), json!({"claim":"drain-owned","generation":provider.identity().generation,"fenced":true,"pending":[{"route":7,"id":11,"wireContext":null,"unknownReason":null}]})).await;
        let fresh = request(&mut server).await;
        assert_eq!(fresh["request"]["method"], "fenceCdp");
        assert_ne!(first["request"]["id"], fresh["request"]["id"]);
        control_result(&mut server, fresh["request"]["id"].as_u64().unwrap(), json!({"claim":"drain-owned","generation":provider.identity().generation,"fenced":true,"pending":[]})).await;
        let proof = bounded(waiting).await.unwrap().unwrap();
        assert_eq!(proof.claim_id(), "drain-owned");
        assert_eq!(proof.provider().generation, provider.identity().generation);
        assert_eq!(
            proof.observation_id(),
            fresh["request"]["id"].as_u64().unwrap()
        );
        assert!(
            provider.pending_operations().await.unwrap().is_empty(),
            "local fence reads are not consumed CDP completion receipts"
        );
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn claim_drain_unknown_and_transport_eof_never_become_an_empty_proof() {
        for unknown_outcome in [true, false] {
            let (provider, mut server) = fixture();
            let claim = attach_fixture(&provider, &mut server, 23, "drain-unknown").await;
            let waiting = {
                let provider = provider.clone();
                let claim = claim.clone();
                tokio::spawn(async move {
                    provider
                        .wait_claim_cdp_drained(&claim, std::time::Duration::from_secs(1))
                        .await
                })
            };
            let fence = request(&mut server).await;
            let reason =
                unknown_outcome.then_some("native RPC timed out without its matched reply");
            control_result(&mut server, fence["request"]["id"].as_u64().unwrap(), json!({"claim":"drain-unknown","generation":provider.identity().generation,"fenced":true,"pending":[{"route":7,"id":11,"wireContext":null,"unknownReason":reason}]})).await;
            if !unknown_outcome {
                drop(server);
            }
            let failure = bounded(waiting).await.unwrap().unwrap_err();
            assert!(
                matches!(failure, NativeProviderError::OutcomeUnknown { operation, .. } if operation == "drainClaimCdp")
            );
            provider.close().await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn claim_drain_timeout_and_foreign_snapshot_refuse_without_detach() {
        let (provider, mut server) = fixture();
        let claim = attach_fixture(&provider, &mut server, 23, "drain-timeout").await;
        let waiting = {
            let provider = provider.clone();
            let claim = claim.clone();
            tokio::spawn(async move {
                provider
                    .wait_claim_cdp_drained(&claim, std::time::Duration::from_millis(100))
                    .await
            })
        };
        let fence = request(&mut server).await;
        assert_eq!(fence["request"]["method"], "fenceCdp");
        control_result(&mut server, fence["request"]["id"].as_u64().unwrap(), json!({"claim":"drain-timeout","generation":provider.identity().generation,"fenced":true,"pending":[{"route":7,"id":11,"wireContext":null,"unknownReason":null}]})).await;
        assert!(
            matches!(bounded(waiting).await.unwrap(), Err(NativeProviderError::OutcomeUnknown { reason, .. }) if reason == "claim native invocations did not answer before the drain deadline")
        );
        let observing = {
            let provider = provider.clone();
            let claim = claim.clone();
            tokio::spawn(async move { provider.fence_claim_cdp(&claim).await })
        };
        let fence = request(&mut server).await;
        control_result(&mut server, fence["request"]["id"].as_u64().unwrap(), json!({"claim":"foreign-claim","generation":provider.identity().generation,"fenced":true,"pending":[]})).await;
        assert!(
            matches!(bounded(observing).await.unwrap(), Err(NativeProviderError::Protocol(reason)) if reason == "CDP fence snapshot changed its exact claim or generation")
        );
        provider.close().await;
    }
}
