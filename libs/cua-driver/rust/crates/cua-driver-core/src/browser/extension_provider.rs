// SPDX-License-Identifier: MIT

//! Trusted Rust-host facade for one current-user extension browser connection.
//!
//! This module owns transport correlation and a claim-channel pool only. The
//! embedding host owns tab origin, logical session/turn authority and consent.
//! A canceled control mutation is never replayed: its completion stays in the
//! bounded pending-operation map until Host-ledger application and acknowledgement.
//! Broker-observed orphan CDP replies are retained there too. Generic CDP calls
//! retain Cua PendingCall's unknown/no-replay behavior; a reply queued before
//! waiter cancellation has no new consumed-ACK guarantee. Empty control snapshots
//! do not settle CDP input. IPC EOF is not a physical cleanup proof.

use super::broker_delivery::{ByteBudget, ByteCharge};
use super::cdp_ws::{
    CdpConnection, CdpFailureDisposition, ExtensionCdpCommand, ExtensionCdpInbound,
    ReplyDisposition,
};
use super::extension_process::{ExtensionAdapterSelection, ExtensionAdapterSelectionError};
pub use super::extension_upload::{
    ExtensionRetainedUpload, ExtensionUploadAbandonAck, ExtensionUploadChunkAck,
    ExtensionUploadDescriptorError, ExtensionUploadFile, ExtensionUploadModifiedTime,
    ExtensionUploadStage, EXTENSION_UPLOAD_CHUNK_BYTES,
};
use super::extension_wire::{ExtensionCdpWritePhase, ExtensionWireContext};
pub use super::extension_wire::{
    ExtensionFixedUiAck, ExtensionFixedUiAction, ExtensionFixedUiColor, ExtensionFixedUiCursor,
    ExtensionFixedUiOperation, ExtensionFixedUiRenderState, ExtensionFixedUiRenderStatus,
    ExtensionFixedUiRequest, ExtensionHeader, ExtensionPreparationDocument,
    ExtensionPreparationPolicy, ExtensionSessionPreparation,
};
use super::local_ipc::{self, ExtensionEndpointIdentity, IpcError, ValidatedExtensionEndpoint};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};
use tokio::sync::{broadcast, mpsc, oneshot};

const REQUEST_BUDGET: usize = 64;
const ACTOR_QUEUE: usize = 128;
const ROUTE_QUEUE: usize = 64;
const EVENT_QUEUE: usize = 128;
const MAX_RETAINED_RECEIPTS: usize = 256;
const MAX_PENDING_EXTENSION_CONTEXTS: usize = 4096;
const IPC_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Discovery reports rejected/stale records without weakening endpoint checks.
#[derive(Clone, Debug)]
pub struct ExtensionEndpointRejection {
    pub descriptor_path: std::path::PathBuf,
    pub reason: String,
}
#[derive(Clone, Debug)]
pub struct ExtensionEndpointDiscovery {
    pub endpoints: Vec<ValidatedExtensionEndpoint>,
    pub rejected: Vec<ExtensionEndpointRejection>,
}
/// Read only the maka adapter's installation-selected private runtime directory.
/// No executable, endpoint URL or descriptor path is accepted from a tool call.
/// Other adapter records are not promoted to an maka claim-capable provider.
pub async fn discover_registered_endpoints() -> Result<ExtensionEndpointDiscovery, IpcError> {
    discover_registered(super::extension_host::MAKA_HOST_NAME).await
}
/// Select an adapter name only from trusted installation configuration.
/// This is not a tool/model parameter and accepts no descriptor or socket path.
pub async fn discover_registered(
    expected_adapter: &str,
) -> Result<ExtensionEndpointDiscovery, IpcError> {
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
                "extension discovery task failed: {error}"
            )))
        })?
}
fn discover_registered_endpoints_blocking(
    expected_adapter: &str,
) -> Result<ExtensionEndpointDiscovery, IpcError> {
    let directory = local_ipc::current_user_runtime_directory()?;
    discover_directory_blocking(&directory, expected_adapter, None)
}
fn discover_directory_blocking(
    directory: &std::path::Path,
    expected_adapter: &str,
    expected_extension: Option<&str>,
) -> Result<ExtensionEndpointDiscovery, IpcError> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ExtensionEndpointDiscovery {
                endpoints: Vec::new(),
                rejected: Vec::new(),
            });
        }
        Err(error) => return Err(error.into()),
    };
    local_ipc::validate_runtime_directory(directory)?;
    let mut result = ExtensionEndpointDiscovery {
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
        match ValidatedExtensionEndpoint::load(&path, expected_adapter) {
            Ok(endpoint) => {
                if expected_extension
                    .is_some_and(|extension| endpoint.identity().extension_id != extension)
                {
                    result.rejected.push(ExtensionEndpointRejection {
                        descriptor_path: path,
                        reason: "descriptor extension differs from the installed registration"
                            .into(),
                    });
                } else {
                    result.endpoints.push(endpoint);
                }
            }
            Err(error) => result.rejected.push(ExtensionEndpointRejection {
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
pub enum ExtensionEffectOwner {
    Host,
    Provider,
    Unavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtensionUserTabsOrder {
    Host,
    Provider,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtensionHeaderPolicyScope {
    Claim,
    Session,
}
/// Page preparation performed by the provider as part of attachment.
///
/// This reports the selected implementation's behavior, not authorization or
/// a guarantee of full behavioral parity with another provider.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionAttachmentPreparation {
    /// No preparation behavior was reported; callers must not assume purity.
    #[default]
    Unknown,
    /// Attachment queries identity and debugger metadata without page preparation.
    MetadataOnly,
    /// Attachment invokes the provider's session page preparers.
    FullPreparation,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionProviderCapabilities {
    /// Native-host byte staging with actual browser placement; never a filesystem grant.
    #[serde(default)]
    pub upload_staging: bool,
    /// Explicit preparation service; never inferred from attachment metadata.
    #[serde(default)]
    pub session_preparation: ExtensionSessionPreparation,
    #[serde(default)]
    pub attachment_preparation: ExtensionAttachmentPreparation,
    pub user_tabs_order: ExtensionUserTabsOrder,
    pub header_scope: ExtensionHeaderPolicyScope,
    pub created_presentation_owner: ExtensionEffectOwner,
    pub cursor_presentation_owner: ExtensionEffectOwner,
    pub cursor_hide_owner: ExtensionEffectOwner,
    pub turn_lifecycle_owner: ExtensionEffectOwner,
    #[serde(default)]
    pub download_notifications: bool,
    /// The producer preserves actual debuggee source targets on CDP events.
    /// This metadata contract grants no ownership, origin or upload authority.
    #[serde(default)]
    pub cdp_event_source_target: bool,
    /// A separate same-claim upgrade; metadata-only attachment never implies it.
    #[serde(default)]
    pub explicit_claim_preparation: bool,
    /// Explicit captured-session metadata/preparation selector, not an ownership grant.
    #[serde(default)]
    pub session_tab_resolution: bool,
    /// Captured whole-session inventory support, never an ownership grant.
    #[serde(default)]
    pub session_tab_inventory: bool,
    /// Supports the captured-session URL-only purpose, not an ownership grant.
    #[serde(default)]
    pub session_committed_url: bool,
    /// Fixed user-tab reads without a debugger claim or tab preparation.
    #[serde(default)]
    pub user_tab_context_read: bool,
    /// Explicit whole-browser history transport, independent of page consent.
    #[serde(default)]
    pub user_history: bool,
    /// Provider-owned session naming. Host-owned groups use their existing receipts.
    #[serde(default)]
    pub session_naming: bool,
    /// Session inventory active flags are provider logical activity, not OS focus.
    #[serde(default)]
    pub session_logical_active: bool,
}

/// Global observed metadata: no owner, claim or tab is attributed here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionDownloadStatus {
    Started,
    InProgress,
    Complete,
    Failed,
    Canceled,
}
#[derive(Clone, Debug, Deserialize)]
pub struct ExtensionDownloadMetadata {
    pub id: String,
    pub filename: String,
    pub url: String,
    pub status: ExtensionDownloadStatus,
}

/// Select only the exact adapter/extension/directory verified by installation.
/// No model path, foreign descriptor heuristic or second config parser is used.
pub async fn discover_registered_for(
    selection: &ExtensionAdapterSelection,
) -> Result<ExtensionEndpointDiscovery, IpcError> {
    let adapter = selection.adapter_name().to_owned();
    let extension = selection.expected_extension_id().to_owned();
    let directory = selection.runtime_directory().to_path_buf();
    tokio::task::spawn_blocking(move || {
        discover_directory_blocking(&directory, &adapter, Some(&extension))
    })
    .await
    .map_err(|error| {
        IpcError::Io(std::io::Error::other(format!(
            "extension discovery task failed: {error}"
        )))
    })?
}
/// Product convenience entry: reads the same selected sidecar as extension startup.
pub async fn discover_installed_extension_endpoints(
) -> Result<ExtensionEndpointDiscovery, ExtensionProviderError> {
    let installed =
        tokio::task::spawn_blocking(super::extension_process::load_installed_selections)
            .await
            .map_err(|error| protocol(&format!("installed catalog task failed: {error}")))??;
    let mut result = ExtensionEndpointDiscovery {
        endpoints: Vec::new(),
        rejected: installed
            .rejected
            .into_iter()
            .map(|(descriptor_path, reason)| ExtensionEndpointRejection {
                descriptor_path,
                reason,
            })
            .collect(),
    };
    let mut accepted_paths = std::collections::HashSet::new();
    for selection in installed.selections {
        match discover_registered_for(&selection).await {
            Ok(discovered) => {
                for endpoint in &discovered.endpoints {
                    accepted_paths.insert(
                        selection
                            .runtime_directory()
                            .join(format!("{}.json", endpoint.identity().generation)),
                    );
                }
                result.endpoints.extend(discovered.endpoints);
                result.rejected.extend(discovered.rejected);
            }
            Err(error) => result.rejected.push(ExtensionEndpointRejection {
                descriptor_path: selection.runtime_directory().to_owned(),
                reason: format!(
                    "installed adapter {} discovery refused: {error}",
                    selection.adapter_name()
                ),
            }),
        }
    }
    // Shared private directories may contain another configured adapter's valid
    // descriptor. Keep its exact validated endpoint, not a false sibling error.
    result
        .rejected
        .retain(|entry| !accepted_paths.contains(&entry.descriptor_path));
    Ok(result)
}

/// Actual Chrome tab metadata. No activity time or public tab ID is invented.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "ExtensionTabInfoWire")]
pub struct ExtensionTabInfo {
    pub id: u64,
    pub window_id: Option<i64>,
    pub index: Option<i64>,
    pub group_id: Option<i64>,
    #[serde(rename = "titleJson")]
    pub title: Option<super::JsonStringLiteral>,
    pub url: Option<String>,
    #[serde(default)]
    pub last_opened: Option<String>,
    #[serde(default)]
    pub provider_tab_id: Option<String>,
    pub pending_url: Option<String>,
    pub active: Option<bool>,
    pub last_accessed: Option<f64>,
    #[serde(rename = "groupTitleJson")]
    pub group_title: Option<super::JsonStringLiteral>,
}

// Legacy scalar metadata and the new JSON-text fields have distinct keys.
// Never infer an encoding from the contents of a legacy page-controlled title.
#[derive(Default)]
enum MetadataField<T> {
    #[default]
    Missing,
    Present(T),
}
impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for MetadataField<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(Self::Present)
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExtensionTabInfoWire {
    id: u64,
    window_id: Option<i64>,
    index: Option<i64>,
    group_id: Option<i64>,
    #[serde(default)]
    title: MetadataField<Option<String>>,
    #[serde(default)]
    title_json: MetadataField<Option<super::JsonStringLiteral>>,
    url: Option<String>,
    last_opened: Option<String>,
    provider_tab_id: Option<String>,
    pending_url: Option<String>,
    active: Option<bool>,
    last_accessed: Option<f64>,
    #[serde(default)]
    group_title: MetadataField<Option<String>>,
    #[serde(default)]
    group_title_json: MetadataField<Option<super::JsonStringLiteral>>,
}
fn metadata_string(
    encoded: MetadataField<Option<super::JsonStringLiteral>>,
    legacy: MetadataField<Option<String>>,
) -> Result<Option<super::JsonStringLiteral>, serde_json::Error> {
    match (encoded, legacy) {
        (MetadataField::Missing, MetadataField::Missing) => Ok(None),
        (MetadataField::Present(value), MetadataField::Missing) => Ok(value),
        (MetadataField::Missing, MetadataField::Present(value)) => Ok(value.map(Into::into)),
        (MetadataField::Present(_), MetadataField::Present(_)) => {
            Err(<serde_json::Error as serde::de::Error>::custom(
                "metadata supplies both scalar and JSON-text strings",
            ))
        }
    }
}
impl TryFrom<ExtensionTabInfoWire> for ExtensionTabInfo {
    type Error = serde_json::Error;

    fn try_from(wire: ExtensionTabInfoWire) -> Result<Self, Self::Error> {
        Ok(Self {
            id: wire.id,
            window_id: wire.window_id,
            index: wire.index,
            group_id: wire.group_id,
            title: metadata_string(wire.title_json, wire.title)?,
            url: wire.url,
            last_opened: wire.last_opened,
            provider_tab_id: wire.provider_tab_id,
            pending_url: wire.pending_url,
            active: wire.active,
            last_accessed: wire.last_accessed,
            group_title: metadata_string(wire.group_title_json, wire.group_title)?,
        })
    }
}

/// The transport receipt is internal Rust-host data, not model-facing JSON.
#[derive(Clone, Debug)]
pub struct ExtensionPhysicalClaim {
    binding: uuid::Uuid,
    generation: String,
    token: String,
    tab_id: u64,
    target_id: String,
    completion_id: u64,
    cleanup_only: bool,
}
impl ExtensionPhysicalClaim {
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
pub struct ExtensionCreationReceipt {
    binding: uuid::Uuid,
    generation: String,
    token: String,
    tab_id: Option<u64>,
    cleanup_only: bool,
}

impl ExtensionCreationReceipt {
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
pub struct ExtensionCreatedTab {
    pub tab: ExtensionTabInfo,
    receipt: ExtensionCreationReceipt,
    completion_id: u64,
}
impl ExtensionCreatedTab {
    pub fn creation_receipt(&self) -> &ExtensionCreationReceipt {
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
pub struct ExtensionTabAbsenceObservation {
    tab_id: u64,
    extension_request_id: String,
}
impl ExtensionTabAbsenceObservation {
    pub fn tab_id(&self) -> u64 {
        self.tab_id
    }
    pub fn extension_request_id(&self) -> &str {
        &self.extension_request_id
    }
}
#[derive(Clone, Debug)]
pub struct CleanupProof {
    evidence: CleanupEvidence,
    completion_id: u64,
    tab_absence: Option<ExtensionTabAbsenceObservation>,
}
impl CleanupProof {
    pub fn tab_absence_observation(&self) -> Option<&ExtensionTabAbsenceObservation> {
        self.tab_absence.as_ref()
    }
    pub fn evidence(&self) -> CleanupEvidence {
        self.evidence
    }
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionHeaderScope {
    pub claim: String,
    pub generation: String,
    pub owner: String,
    pub tab_id: u64,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionHeaderProof {
    pub state_confirmed: bool,
    pub cleanup_confirmed: bool,
    pub active: bool,
    pub pending_removal: bool,
    pub scope: Option<ExtensionHeaderScope>,
    pub applied: Option<bool>,
    #[serde(skip)]
    completion_id: u64,
}
impl ExtensionHeaderProof {
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionSessionHeaderProof {
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
impl ExtensionSessionHeaderProof {
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
}
/// Acknowledged extension overlay request, not physical pointer/input evidence.
#[derive(Clone, Debug)]
pub struct ExtensionCursorPresentationAck {
    pub requested_x: f64,
    pub requested_y: f64,
    pub wait_for_arrival_requested: Option<bool>,
    completion_id: u64,
}
impl ExtensionCursorPresentationAck {
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
}

#[derive(Clone, Debug)]
pub struct ExtensionPreparedTab {
    pub tab: ExtensionTabInfo,
    pub normalized: bool,
    completion_id: u64,
}
impl ExtensionPreparedTab {
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
}

/// The browser's unmodified last-committed URL field, which may be empty.
/// This is neither a parsed Origin nor permission, membership or liveness proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionCommittedTabUrl(String);
impl ExtensionCommittedTabUrl {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Metadata returned by the session preparer, without inferred normalization state.
/// The extension preparer may collect this snapshot before later preparation effects.
/// It is not proof of the current document, Origin, or tab liveness.
#[derive(Clone, Debug)]
pub struct ExtensionSessionPreparedTab {
    pub tab: ExtensionTabInfo,
    completion_id: u64,
}
impl ExtensionSessionPreparedTab {
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
}

/// A charged immutable view of the issued fixed UI identity, without its label or markup.
#[derive(Clone, Debug)]
pub struct ExtensionFixedUiIdentity(Arc<RetainedFixedUiIdentity>);
#[derive(Debug)]
struct RetainedFixedUiIdentity {
    fields: FixedUiIdentityFields,
    _charge: Arc<ByteCharge>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FixedUiIdentityFields {
    operation: ExtensionFixedUiOperation,
    cursor_id: String,
    owner_epoch: String,
}
impl ExtensionFixedUiIdentity {
    pub fn operation(&self) -> ExtensionFixedUiOperation {
        self.0.fields.operation
    }
    pub fn cursor_id(&self) -> &str {
        &self.0.fields.cursor_id
    }
    pub fn owner_epoch(&self) -> &str {
        &self.0.fields.owner_epoch
    }
}
/// An SDK-issued logical cleanup address, never a debugger or content-read claim.
#[derive(Clone, Debug)]
pub struct ExtensionFixedSessionReceipt {
    binding: uuid::Uuid,
    generation: String,
    scope_id: String,
    tab_id: u64,
    wire_context: ExtensionWireContext,
    ui: ExtensionFixedUiIdentity,
    completion_id: u64,
    cleanup_only: bool,
}
impl ExtensionFixedSessionReceipt {
    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }
    pub fn tab_id(&self) -> u64 {
        self.tab_id
    }
    pub fn generation(&self) -> &str {
        &self.generation
    }
    pub fn wire_context(&self) -> &ExtensionWireContext {
        &self.wire_context
    }
    pub fn ui_identity(&self) -> &ExtensionFixedUiIdentity {
        &self.ui
    }
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
    pub fn is_cleanup_only(&self) -> bool {
        self.cleanup_only
    }
}
/// Matched preparation with individual actual outcomes; false is not blanket failure.
#[derive(Clone, Debug)]
pub struct ExtensionFixedSessionPreparedTab {
    pub tab: ExtensionTabInfo,
    pub receipt: ExtensionFixedSessionReceipt,
    pub foreign_installed: bool,
    pub popup_installed: bool,
    pub headers: ExtensionHeaderProof,
    pub ui: ExtensionFixedUiAck,
}
impl ExtensionFixedSessionPreparedTab {
    pub fn completion_id(&self) -> u64 {
        self.receipt.completion_id
    }
}
/// A matched fixed UI service result, not input, physical custody or cleanup proof.
#[derive(Clone, Debug)]
pub struct ExtensionFixedUiProof {
    pub ui: ExtensionFixedUiAck,
    completion_id: u64,
}
impl ExtensionFixedUiProof {
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
}
/// An exact logical preparation cleanup acknowledgement, not a physical detach.
#[derive(Clone, Debug)]
pub struct ExtensionFixedSessionCleanupProof {
    scope_id: String,
    tab_id: u64,
    completion_id: u64,
}
impl ExtensionFixedSessionCleanupProof {
    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }
    pub fn tab_id(&self) -> u64 {
        self.tab_id
    }
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
}

/// Observed logical popup intent; it supplies no attachment or Host authority.
#[derive(Clone, Debug)]
pub struct ExtensionSessionPopupRequest(Arc<RetainedSessionPopupRequest>);
#[derive(Debug)]
struct RetainedSessionPopupRequest {
    fields: SessionPopupFields,
    _charge: Arc<ByteCharge>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SessionPopupFields {
    generation: String,
    owner: String,
    scope_id: String,
    tab_id: u64,
    wire_context: ExtensionWireContext,
    url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    frame_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    document_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_url: Option<String>,
}
impl ExtensionSessionPopupRequest {
    pub fn generation(&self) -> &str {
        &self.0.fields.generation
    }
    pub fn owner(&self) -> &str {
        &self.0.fields.owner
    }
    pub fn scope_id(&self) -> &str {
        &self.0.fields.scope_id
    }
    pub fn tab_id(&self) -> u64 {
        self.0.fields.tab_id
    }
    pub fn wire_context(&self) -> &ExtensionWireContext {
        &self.0.fields.wire_context
    }
    pub fn url(&self) -> &str {
        &self.0.fields.url
    }
    pub fn frame_id(&self) -> Option<i64> {
        self.0.fields.frame_id
    }
    pub fn document_id(&self) -> Option<&str> {
        self.0.fields.document_id.as_deref()
    }
    pub fn source_url(&self) -> Option<&str> {
        self.0.fields.source_url.as_deref()
    }
}
/// An actual logical cleanup observation, not an SDK-issued cleanup proof.
#[derive(Clone, Debug)]
pub struct ExtensionSessionCleanupObservation(Arc<RetainedSessionCleanup>);
#[derive(Debug)]
struct RetainedSessionCleanup {
    fields: SessionCleanupFields,
    _charge: Arc<ByteCharge>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SessionCleanupFields {
    generation: String,
    owner: String,
    scope_id: String,
    tab_id: u64,
    wire_context: ExtensionWireContext,
    cleanup_confirmed: bool,
}
impl ExtensionSessionCleanupObservation {
    pub fn generation(&self) -> &str {
        &self.0.fields.generation
    }
    pub fn owner(&self) -> &str {
        &self.0.fields.owner
    }
    pub fn scope_id(&self) -> &str {
        &self.0.fields.scope_id
    }
    pub fn tab_id(&self) -> u64 {
        self.0.fields.tab_id
    }
    pub fn wire_context(&self) -> &ExtensionWireContext {
        &self.0.fields.wire_context
    }
    pub fn cleanup_confirmed(&self) -> bool {
        self.0.fields.cleanup_confirmed
    }
}

/// One accounted document payload shared by retained operation views and proofs.
/// It preserves metadata only and creates no document or site authorization.
#[derive(Clone, Debug)]
pub struct ExtensionPreparationDocumentBinding(Arc<RetainedPreparationDocument>);
#[derive(Debug)]
struct RetainedPreparationDocument {
    document: ExtensionPreparationDocument,
    _charge: Arc<ByteCharge>,
}
impl ExtensionPreparationDocumentBinding {
    pub fn document(&self) -> &ExtensionPreparationDocument {
        &self.0.document
    }
}
impl PartialEq for ExtensionPreparationDocumentBinding {
    fn eq(&self, other: &Self) -> bool {
        self.document() == other.document()
    }
}
impl Eq for ExtensionPreparationDocumentBinding {}

/// Metadata from a popup intent observed under an existing physical claim.
/// This is neither a grant nor a causal Host input/service operation. The Host
/// must acquire its current source lease and create a fresh service effect.
#[derive(Clone, Debug)]
pub struct ExtensionPopupRequest(Arc<RetainedPopupRequest>);
#[derive(Debug)]
struct RetainedPopupRequest {
    fields: PopupRequestFields,
    _charge: Arc<ByteCharge>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PopupRequestFields {
    claim: String,
    tab_id: u64,
    url: String,
    wire_context: ExtensionWireContext,
    #[serde(default)]
    frame_id: Option<i64>,
    #[serde(default)]
    document_id: Option<String>,
    #[serde(default)]
    source_url: Option<String>,
}
impl ExtensionPopupRequest {
    pub fn claim_id(&self) -> &str {
        &self.0.fields.claim
    }
    pub fn tab_id(&self) -> u64 {
        self.0.fields.tab_id
    }
    pub fn url(&self) -> &str {
        &self.0.fields.url
    }
    /// Captured preparation scope, never the identity of a causal Host action.
    pub fn wire_context(&self) -> &ExtensionWireContext {
        &self.0.fields.wire_context
    }
    /// Actual Chrome sender frame number; not a CDP document frame ID.
    pub fn frame_id(&self) -> Option<i64> {
        self.0.fields.frame_id
    }
    pub fn document_id(&self) -> Option<&str> {
        self.0.fields.document_id.as_deref()
    }
    pub fn source_url(&self) -> Option<&str> {
        self.0.fields.source_url.as_deref()
    }
}

/// An issued, matched acknowledgement of one same-claim preparation request.
/// Individual installation flags remain observable; this is not a blanket
/// readiness, Chrome-effect, physical-attachment or cleanup proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionClaimPreparationProof {
    claim: String,
    generation: String,
    document: ExtensionPreparationDocumentBinding,
    wire_context: ExtensionWireContext,
    preparation_key: String,
    popup_enabled: bool,
    header_enabled: bool,
    foreign_installed: bool,
    popup_installed: bool,
    completion_id: u64,
    cleanup_only: bool,
}
impl ExtensionClaimPreparationProof {
    pub fn claim_id(&self) -> &str {
        &self.claim
    }
    pub fn generation(&self) -> &str {
        &self.generation
    }
    pub fn document(&self) -> &ExtensionPreparationDocument {
        self.document.document()
    }
    pub fn wire_context(&self) -> &ExtensionWireContext {
        &self.wire_context
    }
    pub fn preparation_key(&self) -> &str {
        &self.preparation_key
    }
    /// Requested Host policy, not an installation acknowledgement.
    pub fn popup_enabled(&self) -> bool {
        self.popup_enabled
    }
    /// Requested Host policy, not an independent DNR or cleanup receipt.
    pub fn header_enabled(&self) -> bool {
        self.header_enabled
    }
    pub fn foreign_installed(&self) -> bool {
        self.foreign_installed
    }
    pub fn popup_installed(&self) -> bool {
        self.popup_installed
    }
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
    pub fn is_cleanup_only(&self) -> bool {
        self.cleanup_only
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClaimPreparationFields {
    claim: String,
    preparation_key: String,
    foreign_installed: bool,
    popup_installed: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionMutationDiagnostic {
    pub attempted: bool,
    pub mutation_acknowledged: bool,
    #[serde(deserialize_with = "required_nullable_bool")]
    pub changed: Option<bool>,
    pub diagnostic: Option<String>,
    pub reason: Option<String>,
    #[serde(skip)]
    completion_id: u64,
}
impl ExtensionMutationDiagnostic {
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtensionGroupColor {
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
pub struct ExtensionGroupPresentation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<ExtensionGroupColor>,
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
pub struct ExtensionManagedGroupReceipt {
    binding: uuid::Uuid,
    wire: ManagedGroupWire,
    cleanup_only: bool,
}
impl ExtensionManagedGroupReceipt {
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
pub struct ExtensionGroupProof {
    pub group: ExtensionManagedGroupReceipt,
    pub grouping_acknowledged: Option<bool>,
    pub presentation_acknowledged: Option<bool>,
    completion_id: u64,
}
impl ExtensionGroupProof {
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtensionGroupReleaseEvidence {
    AlreadyNotMember,
    UngroupAcknowledged,
}
#[derive(Clone, Debug)]
pub struct ExtensionGroupReleaseProof {
    pub evidence: ExtensionGroupReleaseEvidence,
    completion_id: u64,
}
impl ExtensionGroupReleaseProof {
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtensionKeepStatus {
    Handoff,
    Deliverable,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionKeepTab {
    pub tab_id: u64,
    pub status: ExtensionKeepStatus,
}
/// Only a matched logical finish ACK. This is deliberately not CleanupProof.
#[derive(Clone, Debug)]
pub struct ExtensionTurnFinishAck {
    pub host_session_id: String,
    pub host_turn_id: String,
    completion_id: u64,
}
impl ExtensionTurnFinishAck {
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
}

/// One exact-claim extension invocation retained by the existing CDP pending map.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionPendingCdpRequest {
    pub route: u64,
    pub id: u64,
    pub wire_context: Option<ExtensionWireContext>,
    pub unknown_reason: Option<String>,
}

/// A fresh snapshot taken after fencing this claim's future CDP dispatch.
#[derive(Clone, Debug)]
pub struct ExtensionClaimCdpSnapshot {
    provider: ExtensionEndpointIdentity,
    claim: String,
    pending: Vec<ExtensionPendingCdpRequest>,
    observation_id: u64,
}
impl ExtensionClaimCdpSnapshot {
    pub fn claim_id(&self) -> &str {
        &self.claim
    }
    pub fn provider(&self) -> &ExtensionEndpointIdentity {
        &self.provider
    }
    pub fn pending(&self) -> &[ExtensionPendingCdpRequest] {
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

/// Matched extension invocation completion for one fenced CDP claim.
///
/// This does not prove Chrome effect termination, physical detach, clipboard
/// cleanup, input success, or Host operation settlement. In particular, an
/// answered extension error may follow the Chatgpt extension's Chrome timeout
/// while a Chrome effect can still complete later.
#[derive(Clone, Debug)]
pub struct ExtensionClaimCdpDrainProof {
    binding: uuid::Uuid,
    provider: ExtensionEndpointIdentity,
    claim: String,
    observation_id: u64,
}
impl ExtensionClaimCdpDrainProof {
    pub fn claim_id(&self) -> &str {
        &self.claim
    }
    pub fn provider(&self) -> &ExtensionEndpointIdentity {
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
    pending: Vec<ExtensionPendingCdpRequest>,
}

/// Operations describe pending transport receipts, not a second tab ledger.
#[derive(Clone, Debug)]
pub enum ExtensionOperation {
    /// A fixed read; captured logical-session activation may still occur.
    ReadUserTab {
        tab_id: u64,
    },
    UserHistory,
    NameSession {
        name: String,
    },
    BeginUpload {
        claim: String,
        tab_id: u64,
        target_id: String,
        files: Vec<ExtensionUploadFile>,
    },
    WriteUploadChunk {
        stage: ExtensionUploadStage,
        file_index: u32,
        offset: u64,
        bytes: u64,
    },
    RetainUploadForSelection {
        stage: ExtensionUploadStage,
    },
    AbandonUpload {
        stage: ExtensionUploadStage,
    },
    Inventory,
    SessionInventory,
    Resolve {
        raw_id: String,
    },
    ResolveSessionTab {
        raw_id: String,
    },
    CommittedSessionTabUrl {
        raw_id: String,
    },
    Attach {
        tab_id: u64,
    },
    Detach {
        claim: String,
        tab_id: u64,
        target_id: String,
    },
    FenceCdp {
        claim: String,
    },
    RetireClaim {
        claim: String,
        cleanup_id: u64,
    },
    CreateTab {
        preferred_window_id: Option<i64>,
    },
    CreatePopupTab {
        opener_claim: String,
    },
    CreateSessionPopupTab {
        opener: ExtensionFixedSessionReceipt,
    },
    SessionPopupRequested {
        request: ExtensionSessionPopupRequest,
    },
    SessionPreparationCleanup {
        observation: ExtensionSessionCleanupObservation,
    },
    PopupRequested {
        request: ExtensionPopupRequest,
    },
    PrepareClaim {
        claim: String,
        document: ExtensionPreparationDocumentBinding,
        popup_enabled: bool,
        header_enabled: bool,
    },
    CloseTab {
        claim: String,
        tab_id: u64,
        target_id: String,
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
        keep: Option<Vec<ExtensionKeepTab>>,
    },
    PrepareUserTab {
        tab_id: u64,
    },
    PrepareSessionTab {
        tab_id: u64,
    },
    PrepareFixedSessionTab {
        tab_id: u64,
        scope_id: String,
        popup_enabled: bool,
        header_enabled: bool,
        ui: ExtensionFixedUiIdentity,
    },
    SessionUi {
        receipt: ExtensionFixedSessionReceipt,
        ui: ExtensionFixedUiIdentity,
    },
    ClearSessionPreparation {
        receipt: ExtensionFixedSessionReceipt,
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
        event: ExtensionCdpCompletionOutcome,
    },
    EffectsCleanup {
        claim: String,
        effect: String,
        cleanup_confirmed: bool,
        error: Option<String>,
    },
}
impl ExtensionOperation {
    fn method(&self) -> &'static str {
        match self {
            Self::ReadUserTab { .. } => "readUserTab",
            Self::UserHistory => "userHistory",
            Self::NameSession { .. } => "nameSession",
            Self::BeginUpload { .. } => "beginUpload",
            Self::WriteUploadChunk { .. } => "writeUploadChunk",
            Self::RetainUploadForSelection { .. } => "retainUploadForSelection",
            Self::AbandonUpload { .. } => "abandonUpload",
            Self::Inventory | Self::SessionInventory => "inventory",
            Self::Resolve { .. }
            | Self::ResolveSessionTab { .. }
            | Self::CommittedSessionTabUrl { .. } => "resolve",
            Self::Attach { .. } => "attach",
            Self::Detach { .. } => "detach",
            Self::FenceCdp { .. } => "fenceCdp",
            Self::RetireClaim { .. } => "retireClaim",
            Self::CreateTab { .. } => "createTab",
            Self::CreatePopupTab { .. } => "createPopupTab",
            Self::CreateSessionPopupTab { .. } => "createSessionPopupTab",
            Self::SessionPopupRequested { .. } => "sessionPopupRequested",
            Self::SessionPreparationCleanup { .. } => "sessionPreparationCleanup",
            Self::PopupRequested { .. } => "popupRequested",
            Self::PrepareClaim { .. } => "prepareClaim",
            Self::CloseTab { .. } => "closeTab",
            Self::StopCreatedTab { .. } => "stopCreatedTab",
            Self::SetScopedHeaders { .. } => "setScopedHeaders",
            Self::ClearScopedHeaders { .. } => "clearScopedHeaders",
            Self::SetSessionHeaders { .. } => "setSessionHeaders",
            Self::ClearSessionHeaders => "clearSessionHeaders",
            Self::MoveMousePresentation { .. } => "moveMouse",
            Self::FinishTurn { .. } => "finishTurn",
            Self::PrepareUserTab { .. } | Self::PrepareSessionTab { .. } => "prepareUserTab",
            Self::PrepareFixedSessionTab { .. } => "prepareSessionTab",
            Self::SessionUi { .. } => "sessionUi",
            Self::ClearSessionPreparation { .. } => "clearSessionPreparation",
            Self::MuteCreatedTab { .. } => "muteCreatedTab",
            Self::UnmuteCreatedTabIfActive { .. } => "unmuteCreatedTabIfActive",
            Self::EnsureCreatedTabGroup { .. } => "ensureCreatedTabGroup",
            Self::UpdateCreatedTabGroup { .. } => "updateCreatedTabGroup",
            Self::ReleaseCreatedTabGroup { .. } => "releaseCreatedTabGroup",
            Self::OrphanCdpCompletion { .. } => "orphanCdpCompletion",
            Self::EffectsCleanup { .. } => "effectsCleanup",
        }
    }
    fn registers_session_request(&self) -> bool {
        match self {
            // These are Rust-local fences or the direct turn-ended message,
            // not new requests through the logical session client.
            Self::BeginUpload { .. }
            | Self::WriteUploadChunk { .. }
            | Self::RetainUploadForSelection { .. }
            | Self::AbandonUpload { .. }
            | Self::FenceCdp { .. }
            | Self::RetireClaim { .. }
            | Self::FinishTurn { .. }
            | Self::SessionPopupRequested { .. }
            | Self::SessionPreparationCleanup { .. }
            | Self::PopupRequested { .. }
            | Self::OrphanCdpCompletion { .. }
            | Self::EffectsCleanup { .. } => false,
            Self::UserHistory
            | Self::NameSession { .. }
            | Self::ReadUserTab { .. }
            | Self::Inventory
            | Self::SessionInventory
            | Self::Resolve { .. }
            | Self::ResolveSessionTab { .. }
            | Self::CommittedSessionTabUrl { .. }
            | Self::Attach { .. }
            | Self::Detach { .. }
            | Self::CreateTab { .. }
            | Self::CreatePopupTab { .. }
            | Self::CreateSessionPopupTab { .. }
            | Self::PrepareClaim { .. }
            | Self::CloseTab { .. }
            | Self::StopCreatedTab { .. }
            | Self::SetScopedHeaders { .. }
            | Self::ClearScopedHeaders { .. }
            | Self::SetSessionHeaders { .. }
            | Self::ClearSessionHeaders
            | Self::MoveMousePresentation { .. }
            | Self::PrepareUserTab { .. }
            | Self::PrepareSessionTab { .. }
            | Self::PrepareFixedSessionTab { .. }
            | Self::SessionUi { .. }
            | Self::ClearSessionPreparation { .. }
            | Self::MuteCreatedTab { .. }
            | Self::UnmuteCreatedTabIfActive { .. }
            | Self::EnsureCreatedTabGroup { .. }
            | Self::UpdateCreatedTabGroup { .. }
            | Self::ReleaseCreatedTabGroup { .. } => true,
        }
    }
    fn mutation(&self) -> bool {
        !matches!(
            self,
            Self::Inventory
                | Self::ReadUserTab { .. }
                | Self::SessionInventory
                | Self::Resolve { .. }
                | Self::ResolveSessionTab { .. }
                | Self::CommittedSessionTabUrl { .. }
                | Self::FenceCdp { .. }
                | Self::RetireClaim { .. }
        )
    }
    fn pending_budget(&self) -> usize {
        if matches!(
            self,
            Self::FenceCdp { .. } | Self::RetireClaim { .. } | Self::ClearSessionPreparation { .. }
        ) {
            MAX_RETAINED_RECEIPTS
        } else {
            REQUEST_BUDGET
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HostUploadCustodyMarker {
    stage: uuid::Uuid,
    state: HostUploadCustodyState,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum HostUploadCustodyState {
    Begun,
    PartialBegin,
    ChunkWritten,
    Retained,
    Abandoned,
}

fn upload_chunk_ack(
    result: &Value,
    operation: &ExtensionOperation,
    completion_id: u64,
) -> Result<ExtensionUploadChunkAck, ExtensionProviderError> {
    let ExtensionOperation::WriteUploadChunk {
        stage,
        file_index,
        offset,
        bytes,
    } = operation
    else {
        return Err(protocol("upload chunk lost issued operation"));
    };
    if result["stage"].as_str() != Some(stage.id.to_string().as_str())
        || result["fileIndex"].as_u64() != Some(u64::from(*file_index))
        || result["offset"].as_u64() != Some(*offset)
        || result["bytes"].as_u64() != Some(*bytes)
        || result["written"] != true
    {
        return Err(protocol(
            "upload chunk acknowledgement changed its issued range",
        ));
    }
    Ok(ExtensionUploadChunkAck {
        stage_id: stage.id,
        completion_id,
    })
}
fn upload_retained(
    result: &Value,
    stage: &ExtensionUploadStage,
    completion_id: u64,
) -> Result<ExtensionRetainedUpload, ExtensionProviderError> {
    if result["stage"].as_str() != Some(stage.id.to_string().as_str()) || result["retained"] != true
    {
        return Err(protocol(
            "upload retain acknowledgement lacks its issued resource",
        ));
    }
    let paths: Vec<std::path::PathBuf> = decode(result["paths"].clone())?;
    if paths.len() != stage.files.len()
        || paths.iter().zip(&stage.files).any(|(path, file)| {
            !path.is_absolute()
                || path.file_name().and_then(|name| name.to_str()) != Some(file.name())
        })
    {
        return Err(protocol(
            "upload retained paths changed actual file names or cardinality",
        ));
    }
    Ok(ExtensionRetainedUpload {
        stage: stage.clone(),
        paths,
        completion_id,
    })
}
fn upload_abandon_ack(
    result: &Value,
    stage: &ExtensionUploadStage,
    completion_id: u64,
) -> Result<ExtensionUploadAbandonAck, ExtensionProviderError> {
    if result["stage"].as_str() != Some(stage.id.to_string().as_str())
        || result["abandoned"] != true
    {
        return Err(protocol(
            "upload abandon acknowledgement lacks its issued resource",
        ));
    }
    Ok(ExtensionUploadAbandonAck {
        stage_id: stage.id,
        completion_id,
    })
}

fn unacknowledged_retirement_fact(operation: &ExtensionOperation, claim: &str) -> bool {
    match operation {
        ExtensionOperation::EffectsCleanup {
            claim: issued,
            effect,
            cleanup_confirmed: false,
            ..
        } => {
            issued == claim && matches!(effect.as_str(), "extension_cdp_effect" | "upload_backing")
        }
        ExtensionOperation::OrphanCdpCompletion { claim: issued, .. } => issued == claim,
        _ => false,
    }
}

/// The same tagged outcome emitted by the extension broker's control channel.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "camelCase")]
pub enum ExtensionOperationOutcome {
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
    NotDispatched {
        kind: String,
        message: String,
        details: Option<Value>,
    },
    Unknown {
        reason: String,
        details: Option<Value>,
    },
}
impl ExtensionOperationOutcome {
    fn into_result(self, operation: &str) -> Result<Value, ExtensionProviderError> {
        match self {
            Self::Result(value) => Ok(value),
            Self::ChromeRejected { message, details } => {
                Err(ExtensionProviderError::ChromeRejected {
                    operation: operation.to_owned(),
                    message,
                    details,
                })
            }
            Self::ConnectorRejected {
                kind,
                message,
                details,
            }
            | Self::NotDispatched {
                kind,
                message,
                details,
            } => Err(ExtensionProviderError::Refused {
                kind,
                message,
                details,
            }),
            Self::Unknown { reason, details } => Err(ExtensionProviderError::OutcomeUnknown {
                operation: operation.to_owned(),
                reason,
                details,
            }),
        }
    }
}
/// Caller-assigned correlation from the existing trusted Host ledger.
/// It chooses no authorization and is never sent to Chrome or the extension host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionHostOperation {
    pub operation_id: String,
    pub turn_id: String,
}

#[derive(Clone, Debug)]
pub struct ExtensionOperationCompletion {
    pub id: u64,
    pub host_operation: Option<ExtensionHostOperation>,
    pub wire_context: Option<ExtensionWireContext>,
    pub provider: ExtensionEndpointIdentity,
    pub operation: ExtensionOperation,
    pub outcome: ExtensionOperationOutcome,
}

/// FIFO actor snapshot includes admitted in-flight operations and retained ACKs.
#[derive(Clone, Debug)]
pub struct ExtensionPendingOperation {
    pub id: u64,
    pub host_operation: Option<ExtensionHostOperation>,
    pub wire_context: Option<ExtensionWireContext>,
    pub provider: ExtensionEndpointIdentity,
    pub operation: ExtensionOperation,
    pub outcome: Option<ExtensionOperationOutcome>,
}
#[derive(Clone, Debug, Default)]
pub struct ExtensionKnownCustody {
    pub claim: Option<ExtensionPhysicalClaim>,
    pub preparation: Option<ExtensionClaimPreparationProof>,
    pub created: Option<ExtensionCreatedTab>,
    pub creation: Option<ExtensionCreationReceipt>,
    pub group: Option<ExtensionManagedGroupReceipt>,
    pub cleanup: Option<CleanupProof>,
    pub headers: Option<ExtensionHeaderProof>,
    pub turn_finished: Option<ExtensionTurnFinishAck>,
    pub session_headers: Option<ExtensionSessionHeaderProof>,
    pub cursor_presentation: Option<ExtensionCursorPresentationAck>,
    pub fixed_session: Option<ExtensionFixedSessionReceipt>,
    pub upload_stage: Option<ExtensionUploadStage>,
    pub upload_retained: Option<ExtensionRetainedUpload>,
    /// Actual retained backing whose paths could not be represented/delivered.
    /// Cleanup-only resource custody; this cannot authorize or replay a setter.
    pub upload_retained_backing: Option<ExtensionUploadStage>,
    pub upload_abandoned: Option<ExtensionUploadAbandonAck>,
}
/// Capabilities below originate only from the actor's still-retained completion.
/// Unknown positive-ACK capabilities are cleanup-only and remain old-generation.
#[derive(Clone, Debug)]
pub enum ExtensionRecoveredOperation {
    /// Exact positive acknowledgement; the retained operation carries the requested title.
    SessionNamed {
        name: String,
    },
    /// History never mints a tab/claim or a site permission.
    UserHistory,
    UploadBegun(ExtensionUploadStage),
    UploadChunkWritten(ExtensionUploadChunkAck),
    UploadRetained(ExtensionRetainedUpload),
    UploadAbandoned(ExtensionUploadAbandonAck),
    SessionHeaders(ExtensionSessionHeaderProof),
    CursorPresentation(ExtensionCursorPresentationAck),
    TurnFinished(ExtensionTurnFinishAck),
    Claim(ExtensionPhysicalClaim),
    Created(ExtensionCreatedTab),
    Cleanup(CleanupProof),
    Headers(ExtensionHeaderProof),
    Prepared(ExtensionPreparedTab),
    SessionPrepared(ExtensionSessionPreparedTab),
    FixedSessionPrepared(ExtensionFixedSessionPreparedTab),
    FixedUi(ExtensionFixedUiProof),
    FixedSessionCleared(ExtensionFixedSessionCleanupProof),
    ClaimPrepared(ExtensionClaimPreparationProof),
    PopupRequested(ExtensionPopupRequest),
    SessionPopupRequested(ExtensionSessionPopupRequest),
    SessionPreparationCleanup(ExtensionSessionCleanupObservation),
    Presentation(ExtensionMutationDiagnostic),
    Group(ExtensionGroupProof),
    GroupReleased(ExtensionGroupReleaseProof),
    Refused {
        kind: String,
        message: String,
        details: Option<Value>,
    },
    NotDispatched {
        kind: String,
        message: String,
        details: Option<Value>,
    },
    ChromeRejected {
        message: String,
        details: Option<Value>,
    },
    Unknown {
        operation: ExtensionOperation,
        reason: String,
        details: Option<Value>,
        custody: Box<ExtensionKnownCustody>,
    },
    OrphanCdpCompletion {
        route: u64,
        claim: String,
        id: u64,
        event: ExtensionCdpCompletionOutcome,
        wire_context: Option<ExtensionWireContext>,
    },
    EffectsCleanup {
        claim: String,
        effect: String,
        cleanup_confirmed: bool,
        error: Option<String>,
        wire_context: Option<ExtensionWireContext>,
    },
}

#[derive(Clone, Debug, Deserialize)]
pub struct ExtensionMetadataError {
    pub kind: String,
    pub message: String,
}

#[derive(Clone, Debug)]
pub enum ExtensionProviderEvent {
    /// A nonretained control observation reached its terminal and left pending.
    /// Wake only: query the current pending snapshot; this conveys no receipt,
    /// ownership, effect settlement, or permission to replay an operation.
    PendingOperationsChanged,
    PopupRequested {
        request: ExtensionPopupRequest,
    },
    SessionPopupRequested {
        request: ExtensionSessionPopupRequest,
    },
    SessionPreparationCleanup {
        observation: ExtensionSessionCleanupObservation,
    },
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
        outcome: ExtensionCdpCompletionOutcome,
        wire_context: Option<ExtensionWireContext>,
    },
    EffectsCleanup {
        claim: String,
        effect: String,
        cleanup_confirmed: bool,
        error: Option<String>,
        wire_context: Option<ExtensionWireContext>,
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
        error: ExtensionMetadataError,
    },
    DownloadChanged {
        download: ExtensionDownloadMetadata,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum ExtensionProviderError {
    #[error(transparent)]
    Endpoint(#[from] IpcError),
    #[error(transparent)]
    Selection(#[from] ExtensionAdapterSelectionError),
    #[error("extension connector refused ({kind}): {message}")]
    Refused {
        kind: String,
        message: String,
        details: Option<Value>,
    },
    #[error("extension connector refused ({kind}): {message}")]
    NotDispatched {
        kind: String,
        message: String,
        details: Option<Value>,
        proof: Box<ExtensionUndispatchedControl>,
    },
    #[error("Chrome rejected {operation}: {message}")]
    ChromeRejected {
        operation: String,
        message: String,
        details: Option<Value>,
    },
    #[error("extension {operation} outcome is unknown: {reason}")]
    OutcomeUnknown {
        operation: String,
        reason: String,
        details: Option<Value>,
    },
    #[error("extension provider protocol failed: {0}")]
    Protocol(String),
}

/// Rust-produced proof that this exact call never began a native frame.
/// This is independent of logical registration and cannot clear older custody.
/// Constructors remain inside the trusted Rust provider, not native JSON.
#[derive(Clone, Debug)]
pub struct ExtensionUndispatchedControl {
    binding: uuid::Uuid,
    host_operation: Option<ExtensionHostOperation>,
    wire_context: Option<ExtensionWireContext>,
    method: &'static str,
}
impl ExtensionUndispatchedControl {
    /// Semantic operation refused before physical dispatch.
    pub fn method(&self) -> &'static str {
        self.method
    }
}

struct ProviderInner {
    identity: ExtensionEndpointIdentity,
    binding: uuid::Uuid,
    commands: mpsc::Sender<ClientCommand>,
    retained_payload_budget: ByteBudget,
    events: broadcast::Sender<ExtensionProviderEvent>,
    alive: AtomicBool,
}

impl Drop for ProviderInner {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::SeqCst);
        self.retained_payload_budget.close();
        // A full queue already wakes the actor, which rechecks this Weak owner.
        let _ = self.commands.try_send(ClientCommand::OwnerDropped);
    }
}

/// Logical session requests registered by one exact trusted call view.
///
/// Registration precedes transport admission. It proves neither physical dispatch,
/// activation, success, NoEffect nor cleanup. The Host may snapshot the count only
/// after its original call gates drain and its actual turn cleanup is acknowledged.
#[derive(Clone, Debug)]
pub struct ExtensionSessionRequestRegistration {
    inner: Arc<SessionRequestRegistration>,
}
#[derive(Debug)]
struct SessionRequestRegistration {
    binding: uuid::Uuid,
    host_operation: Option<ExtensionHostOperation>,
    wire_context: Option<ExtensionWireContext>,
    count: AtomicUsize,
}
impl ExtensionSessionRequestRegistration {
    /// Number of logical requests registered by the captured call view.
    pub fn count(&self) -> usize {
        self.inner.count.load(Ordering::SeqCst)
    }
    fn matches(&self, provider: &ExtensionBrowserProvider) -> bool {
        self.inner.binding == provider.inner.binding
            && self.inner.host_operation == provider.host_operation
            && self.inner.wire_context == provider.wire_context
    }
    fn register(&self) -> Result<(), ExtensionProviderError> {
        let mut count = self.inner.count.load(Ordering::SeqCst);
        loop {
            let next = count
                .checked_add(1)
                .ok_or_else(|| protocol("session request registration count exhausted"))?;
            match self.inner.count.compare_exchange_weak(
                count,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => count = actual,
            }
        }
    }
}

/// One owner connection, retained by the embedding Driver across extension epochs.
#[derive(Clone)]
pub struct ExtensionBrowserProvider {
    inner: Arc<ProviderInner>,
    host_operation: Option<ExtensionHostOperation>,
    wire_context: Option<ExtensionWireContext>,
    session_request_registration: Option<ExtensionSessionRequestRegistration>,
}
/// Immutable call-scoped provider view sharing the same owner/transport actor.
/// The name is an alias: it carries no extra session or authority store.
pub type ExtensionBrowserOperation = ExtensionBrowserProvider;
impl ExtensionBrowserProvider {
    pub async fn connect(
        endpoint: ValidatedExtensionEndpoint,
    ) -> Result<Self, ExtensionProviderError> {
        let identity = endpoint.identity().clone();
        let stream = endpoint.connect().await?;
        let (commands, incoming) = mpsc::channel(ACTOR_QUEUE);
        let (events, _) = broadcast::channel(EVENT_QUEUE);
        let inner = Arc::new(ProviderInner {
            identity,
            binding: uuid::Uuid::new_v4(),
            commands: commands.clone(),
            retained_payload_budget: ByteBudget::new(),
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
            session_request_registration: None,
        })
    }
    pub fn with_host_operation(
        &self,
        context: ExtensionHostOperation,
    ) -> ExtensionBrowserOperation {
        Self {
            inner: self.inner.clone(),
            host_operation: Some(context),
            wire_context: self.wire_context.clone(),
            session_request_registration: self.session_request_registration.clone(),
        }
    }
    /// Supply exact trusted owner-session/turn metadata for this call view.
    /// A persistent claim/channel never supplies an ambient replacement turn.
    pub fn with_wire_context(&self, context: ExtensionWireContext) -> ExtensionBrowserOperation {
        Self {
            inner: self.inner.clone(),
            host_operation: self.host_operation.clone(),
            wire_context: Some(context),
            session_request_registration: self.session_request_registration.clone(),
        }
    }
    /// Observe logical registration on this same provider, operation and context.
    /// Local argument/capability failures before registration leave the count alone;
    /// every admitted request remains registered even when no frame is written.
    pub fn observe_session_requests(&self) -> (Self, ExtensionSessionRequestRegistration) {
        let registration = ExtensionSessionRequestRegistration {
            inner: Arc::new(SessionRequestRegistration {
                binding: self.inner.binding,
                host_operation: self.host_operation.clone(),
                wire_context: self.wire_context.clone(),
                count: AtomicUsize::new(0),
            }),
        };
        let mut observed = self.clone();
        observed.session_request_registration = Some(registration.clone());
        (observed, registration)
    }
    /// Reuse one call's existing registration observation across its purposes.
    ///
    /// # Errors
    /// Refuses a different provider binding, Host operation or wire context.
    pub fn with_session_request_registration(
        &self,
        registration: &ExtensionSessionRequestRegistration,
    ) -> Result<Self, ExtensionProviderError> {
        if !registration.matches(self) {
            return Err(refused(
                "context_mismatch",
                "session request observation belongs to another captured call view",
            ));
        }
        let mut observed = self.clone();
        observed.session_request_registration = Some(registration.clone());
        Ok(observed)
    }
    pub fn is_closed(&self) -> bool {
        !self.inner.alive.load(Ordering::SeqCst)
    }
    pub fn identity(&self) -> &ExtensionEndpointIdentity {
        &self.inner.identity
    }
    pub fn capabilities(&self) -> Result<ExtensionProviderCapabilities, ExtensionProviderError> {
        decode(self.identity().capabilities.clone())
    }
    /// A lagged receiver must query pending_completions and reconcile its ledger.
    /// Completion data remains in the bounded pending map until explicit ACK.
    pub fn subscribe_events(&self) -> broadcast::Receiver<ExtensionProviderEvent> {
        self.inner.events.subscribe()
    }

    fn preflight_error(
        &self,
        method: &'static str,
        error: ExtensionProviderError,
    ) -> ExtensionProviderError {
        match error {
            ExtensionProviderError::Refused {
                kind,
                message,
                details,
            } => self.undispatched_error(method, kind, message, details),
            error => error,
        }
    }
    fn undispatched_error(
        &self,
        method: &'static str,
        kind: String,
        message: String,
        details: Option<Value>,
    ) -> ExtensionProviderError {
        ExtensionProviderError::NotDispatched {
            kind,
            message,
            details,
            proof: Box::new(ExtensionUndispatchedControl {
                binding: self.inner.binding,
                host_operation: self.host_operation.clone(),
                wire_context: self.wire_context.clone(),
                method,
            }),
        }
    }
    /// Validate a Rust-only no-dispatch proof against this captured call view.
    /// No error text or native reply hint can supply this proof.
    pub fn undispatched_control<'a>(
        &self,
        error: &'a ExtensionProviderError,
    ) -> Option<&'a ExtensionUndispatchedControl> {
        let ExtensionProviderError::NotDispatched { proof, .. } = error else {
            return None;
        };
        (proof.binding == self.inner.binding
            && proof.host_operation == self.host_operation
            && proof.wire_context == self.wire_context)
            .then_some(proof.as_ref())
    }
    async fn control(
        &self,
        operation: ExtensionOperation,
        params: Value,
    ) -> Result<ControlReply, ExtensionProviderError> {
        let name = operation.method();
        self.check_operation_capability(&operation)
            .map_err(|error| self.preflight_error(name, error))?;
        if self
            .host_operation
            .as_ref()
            .zip(self.wire_context.as_ref())
            .is_some_and(|(operation, wire)| operation.turn_id != wire.host_turn_id())
        {
            return Err(self.preflight_error(
                name,
                refused(
                    "context_mismatch",
                    "receipt correlation and wire metadata name different trusted turns",
                ),
            ));
        }
        if let Some(registration) = self
            .session_request_registration
            .as_ref()
            .filter(|_| operation.registers_session_request())
        {
            if !registration.matches(self) {
                return Err(refused(
                    "context_mismatch",
                    "session request observation no longer matches its captured call view",
                ));
            }
            // Mirrors the session client's tracker-before-send boundary. A
            // later owner fence, zero-byte write or remote rejection cannot
            // erase this logical cleanup obligation.
            registration.register()?;
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
        let reply = result
            .await
            .map_err(|_| unknown(name, "runtime actor ended before receipt delivery"))?;
        if let ExtensionOperationOutcome::NotDispatched {
            kind,
            message,
            details,
        } = &reply.outcome
        {
            return Err(self.undispatched_error(
                name,
                kind.clone(),
                message.clone(),
                details.clone(),
            ));
        }
        Ok(reply)
    }
    fn check_operation_capability(
        &self,
        operation: &ExtensionOperation,
    ) -> Result<(), ExtensionProviderError> {
        let supported = match operation {
            ExtensionOperation::ReadUserTab { .. } => self.capabilities()?.user_tab_context_read,
            ExtensionOperation::UserHistory => self.capabilities()?.user_history,
            ExtensionOperation::NameSession { .. } => self.capabilities()?.session_naming,
            ExtensionOperation::BeginUpload { .. }
            | ExtensionOperation::WriteUploadChunk { .. }
            | ExtensionOperation::RetainUploadForSelection { .. }
            | ExtensionOperation::AbandonUpload { .. } => self.capabilities()?.upload_staging,
            ExtensionOperation::SessionInventory => self.capabilities()?.session_tab_inventory,
            ExtensionOperation::CommittedSessionTabUrl { .. } => {
                self.capabilities()?.session_committed_url
            }
            ExtensionOperation::ResolveSessionTab { .. } => {
                self.capabilities()?.session_tab_resolution
            }
            ExtensionOperation::PrepareSessionTab { .. } => {
                self.capabilities()?.session_preparation
                    == ExtensionSessionPreparation::ProviderSession
            }
            ExtensionOperation::PrepareFixedSessionTab { .. }
            | ExtensionOperation::SessionUi { .. }
            | ExtensionOperation::ClearSessionPreparation { .. }
            | ExtensionOperation::CreateSessionPopupTab { .. } => {
                self.capabilities()?.session_preparation
                    == ExtensionSessionPreparation::ExplicitFixed
            }
            ExtensionOperation::PrepareClaim { .. } | ExtensionOperation::CreatePopupTab { .. } => {
                self.capabilities()?.explicit_claim_preparation
            }
            ExtensionOperation::SetSessionHeaders { .. }
            | ExtensionOperation::ClearSessionHeaders => {
                self.capabilities()?.header_scope == ExtensionHeaderPolicyScope::Session
            }
            ExtensionOperation::SetScopedHeaders { .. }
            | ExtensionOperation::ClearScopedHeaders { .. } => {
                self.capabilities()?.header_scope == ExtensionHeaderPolicyScope::Claim
            }
            ExtensionOperation::MoveMousePresentation { .. } => {
                self.capabilities()?.cursor_presentation_owner == ExtensionEffectOwner::Provider
            }
            ExtensionOperation::FinishTurn { .. } => {
                self.capabilities()?.turn_lifecycle_owner == ExtensionEffectOwner::Provider
            }
            ExtensionOperation::MuteCreatedTab { .. }
            | ExtensionOperation::UnmuteCreatedTabIfActive { .. }
            | ExtensionOperation::EnsureCreatedTabGroup { .. }
            | ExtensionOperation::UpdateCreatedTabGroup { .. }
            | ExtensionOperation::ReleaseCreatedTabGroup { .. } => {
                self.capabilities()?.created_presentation_owner == ExtensionEffectOwner::Host
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
    fn check_upload_stage(
        &self,
        stage: &ExtensionUploadStage,
    ) -> Result<(), ExtensionProviderError> {
        if stage.binding != self.inner.binding || self.wire_context.as_ref() != Some(&stage.context)
        {
            return Err(refused(
                "upload_unavailable",
                "upload belongs to another provider or captured scope",
            ));
        }
        Ok(())
    }
    pub async fn begin_upload(
        &self,
        claim: &ExtensionPhysicalClaim,
        files: &[ExtensionUploadFile],
    ) -> Result<ExtensionUploadStage, ExtensionProviderError> {
        self.check_claim(claim)
            .map_err(|error| self.preflight_error("beginUpload", error))?;
        if claim.cleanup_only {
            return Err(self.preflight_error(
                "beginUpload",
                refused("claim_unavailable", "uncertain claim permits cleanup only"),
            ));
        }
        let context = self.wire_context.as_ref().ok_or_else(|| {
            self.preflight_error(
                "beginUpload",
                refused(
                    "context_required",
                    "upload requires captured trusted context",
                ),
            )
        })?;
        let operation = ExtensionOperation::BeginUpload {
            claim: claim.token.clone(),
            tab_id: claim.tab_id,
            target_id: claim.target_id.clone(),
            files: files.to_vec(),
        };
        let reply = self
            .control(
                operation.clone(),
                json!({"claim":claim.token,"files":files}),
            )
            .await?;
        let result = reply.outcome.into_result("beginUpload")?;
        self.upload_stage_from_result(&result, &operation, context, reply.id)
    }
    pub async fn write_upload_chunk(
        &self,
        stage: &ExtensionUploadStage,
        file_index: u32,
        offset: u64,
        bytes: &[u8],
    ) -> Result<ExtensionUploadChunkAck, ExtensionProviderError> {
        use base64::Engine;
        self.check_upload_stage(stage)
            .map_err(|error| self.preflight_error("writeUploadChunk", error))?;
        if stage.cleanup_only {
            return Err(self.preflight_error(
                "writeUploadChunk",
                refused(
                    "upload_cleanup_only",
                    "uncertain upload custody permits cleanup only",
                ),
            ));
        }

        if bytes.is_empty() || bytes.len() > EXTENSION_UPLOAD_CHUNK_BYTES {
            return Err(self.preflight_error(
                "writeUploadChunk",
                refused(
                    "upload_chunk",
                    "upload chunks must contain 1 through 65536 bytes",
                ),
            ));
        }
        let operation = ExtensionOperation::WriteUploadChunk {
            stage: stage.clone(),
            file_index,
            offset,
            bytes: bytes.len() as u64,
        };
        let reply=self.control(operation.clone(),json!({"stage":stage.id,"fileIndex":file_index,"offset":offset,"bytes":base64::engine::general_purpose::STANDARD.encode(bytes)})).await?;
        let result = reply.outcome.into_result("writeUploadChunk")?;
        upload_chunk_ack(&result, &operation, reply.id)
    }
    /// Validate size and digest, then retain backing before exposing any paths.
    /// Main must receive this ACK before issuing its existing DOM/CDP setter.
    pub async fn retain_upload_for_selection(
        &self,
        stage: &ExtensionUploadStage,
    ) -> Result<ExtensionRetainedUpload, ExtensionProviderError> {
        self.check_upload_stage(stage)
            .map_err(|error| self.preflight_error("retainUploadForSelection", error))?;
        if stage.cleanup_only {
            return Err(self.preflight_error(
                "retainUploadForSelection",
                refused(
                    "upload_cleanup_only",
                    "uncertain upload custody permits cleanup only",
                ),
            ));
        }

        let reply = self
            .control(
                ExtensionOperation::RetainUploadForSelection {
                    stage: stage.clone(),
                },
                json!({"stage":stage.id}),
            )
            .await?;
        upload_retained(
            &reply.outcome.into_result("retainUploadForSelection")?,
            stage,
            reply.id,
        )
    }
    /// Abandon only backing whose paths have never been exposed by retain.
    pub async fn abandon_upload(
        &self,
        stage: &ExtensionUploadStage,
    ) -> Result<ExtensionUploadAbandonAck, ExtensionProviderError> {
        self.check_upload_stage(stage)
            .map_err(|error| self.preflight_error("abandonUpload", error))?;
        let reply = self
            .control(
                ExtensionOperation::AbandonUpload {
                    stage: stage.clone(),
                },
                json!({"stage":stage.id}),
            )
            .await?;
        upload_abandon_ack(
            &reply.outcome.into_result("abandonUpload")?,
            stage,
            reply.id,
        )
    }
    fn upload_stage_from_result(
        &self,
        result: &Value,
        operation: &ExtensionOperation,
        context: &ExtensionWireContext,
        completion_id: u64,
    ) -> Result<ExtensionUploadStage, ExtensionProviderError> {
        let ExtensionOperation::BeginUpload {
            claim,
            tab_id,
            target_id,
            files,
        } = operation
        else {
            return Err(protocol("upload stage has no issued begin operation"));
        };
        if result["tabId"].as_u64() != Some(*tab_id)
            || result["targetId"].as_str() != Some(target_id.as_str())
            || decode::<Vec<ExtensionUploadFile>>(result["files"].clone())? != *files
        {
            return Err(protocol(
                "upload stage changed its issued file or tab identity",
            ));
        }
        let id = result["stage"]
            .as_str()
            .and_then(|id| uuid::Uuid::parse_str(id).ok())
            .ok_or_else(|| protocol("upload stage lacks its actual resource address"))?;
        Ok(ExtensionUploadStage {
            binding: self.inner.binding,
            context: context.clone(),
            id,
            tab_id: *tab_id,
            target_id: target_id.clone(),
            claim: claim.clone(),
            files: files.clone(),
            completion_id,
            cleanup_only: false,
        })
    }
    fn check_claim(&self, claim: &ExtensionPhysicalClaim) -> Result<(), ExtensionProviderError> {
        if claim.binding != self.inner.binding || claim.generation != self.inner.identity.generation
        {
            return Err(refused(
                "claim_unavailable",
                "claim belongs to another owner connection or generation",
            ));
        }
        Ok(())
    }
    /// Query browser-wide history after the embedding Host's distinct history consent.
    /// This transport method neither grants permission nor creates tab ownership.
    pub async fn user_history(&self, options: Value) -> Result<Value, ExtensionProviderError> {
        let reply = self
            .control(ExtensionOperation::UserHistory, json!({"options":options}))
            .await?;
        let result = reply.outcome.into_result("userHistory")?;
        let items = result
            .get("items")
            .filter(|value| value.is_array())
            .ok_or_else(|| protocol("history result lacks items"))?;
        for row in items.as_array().expect("checked array") {
            if !row.get("url").is_some_and(Value::is_string)
                || !row.get("dateVisited").is_some_and(Value::is_string)
                || row.get("title").is_some_and(|value| !value.is_string())
            {
                return Err(protocol("history item has invalid fields"));
            }
        }
        Ok(items.clone())
    }
    /// Rename the captured original session; an uncertain result is never replayed.
    pub async fn name_session(&self, name: &str) -> Result<(), ExtensionProviderError> {
        if name.is_empty() {
            return Err(refused("invalid_request", "name_session requires a name"));
        }
        let reply = self
            .control(
                ExtensionOperation::NameSession {
                    name: name.to_owned(),
                },
                json!({"name":name}),
            )
            .await?;
        let result = reply.outcome.into_result("nameSession")?;
        if result.get("renamed") != Some(&Value::Bool(true)) {
            return Err(protocol("session name acknowledgement missing"));
        }
        Ok(())
    }
    /// Run a fixed, URL-guarded read without claiming, preparing or focusing a tab.
    /// Host authorization must retain the exact expected URL throughout this call.
    /// The ChatGPT adapter can activate its logical session; this is not a claim.
    ///
    /// # Errors
    /// Returns an admission/capability refusal, the original read failure, or
    /// transport uncertainty. It never retries through another tab or transport.
    pub async fn read_user_tab(
        &self,
        tab_id: u64,
        expected_url: &str,
        read: super::user_tab_context::BrowserUserTabRead,
    ) -> Result<Value, ExtensionProviderError> {
        self.require_session_tab_context()?;
        if tab_id == 0 || tab_id > 9_007_199_254_740_991 {
            return Err(refused(
                "invalid_request",
                "Tab reads require a positive safe tab ID",
            ));
        }
        let url = url::Url::parse(expected_url)
            .map_err(|_| refused("invalid_request", "Tab reads require an HTTP or HTTPS URL"))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(refused(
                "invalid_request",
                "Tab reads require an HTTP or HTTPS URL",
            ));
        }
        let reply = self
            .control(
                ExtensionOperation::ReadUserTab { tab_id },
                json!({"tabId":tab_id, "expectedUrl":expected_url, "read":read}),
            )
            .await?;
        let result = reply.outcome.into_result("readUserTab")?;
        result
            .get("value")
            .cloned()
            .ok_or_else(|| protocol("user-tab read result lacks its value"))
    }

    pub async fn list_user_tabs(&self) -> Result<Vec<ExtensionTabInfo>, ExtensionProviderError> {
        let reply = self
            .control(ExtensionOperation::Inventory, json!({}))
            .await?;
        let result = reply.outcome.into_result("inventory")?;
        decode(
            result
                .get("tabs")
                .cloned()
                .ok_or_else(|| protocol("inventory result lacks tabs"))?,
        )
    }
    /// Read the captured logical session once, including an empty session.
    /// `known_tab_ids` supplies Host-validated metadata candidates for adapters
    /// whose logical lifecycle belongs to the Host. It grants no tab ownership;
    /// Chatgpt returns its actual GetTabs rows independently of this list.
    /// Session activation can have effects and does not prove Host settlement.
    ///
    /// # Errors
    /// Returns a refusal for missing context, unsupported capability or invalid
    /// candidates, a protocol error for a malformed reply, or the original
    /// transport/activation uncertainty. It never falls back to user inventory.
    pub async fn list_session_tabs(
        &self,
        known_tab_ids: &[u64],
    ) -> Result<Vec<ExtensionTabInfo>, ExtensionProviderError> {
        self.require_session_tab_context()?;
        let mut ids = std::collections::HashSet::new();
        if known_tab_ids
            .iter()
            .any(|id| *id == 0 || *id > 9_007_199_254_740_991 || !ids.insert(*id))
        {
            return Err(refused(
                "invalid_request",
                "session inventory candidates must be unique positive safe tab IDs",
            ));
        }
        let reply = self
            .control(
                ExtensionOperation::SessionInventory,
                json!({"sessionOnly":true,"knownTabIds":known_tab_ids}),
            )
            .await?;
        let result = reply.outcome.into_result("inventory")?;
        require_session_tab_ack(&result)?;
        let tabs: Vec<ExtensionTabInfo> = decode(
            result
                .get("tabs")
                .cloned()
                .ok_or_else(|| protocol("session inventory result lacks tabs"))?,
        )?;
        ids.clear();
        if tabs
            .iter()
            .any(|tab| tab.id == 0 || tab.id > 9_007_199_254_740_991 || !ids.insert(tab.id))
        {
            return Err(protocol(
                "session inventory returned invalid or duplicate tab IDs",
            ));
        }
        Ok(tabs)
    }
    pub async fn resolve_user_tab(
        &self,
        raw_id: &str,
    ) -> Result<ExtensionTabInfo, ExtensionProviderError> {
        let reply = self
            .control(
                ExtensionOperation::Resolve {
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
    /// Resolve through the captured logical session without a user-inventory fallback.
    /// Maka metadata transport still requires the caller's actual Host admission;
    /// the selector and its acknowledgement do not grant ownership.
    /// Chatgpt session activation may have effects even though this observation
    /// has no retained mutation receipt; it proves neither NoEffect nor Host T2 settlement.
    pub async fn resolve_session_tab(
        &self,
        raw_id: &str,
    ) -> Result<ExtensionTabInfo, ExtensionProviderError> {
        self.require_session_tab_context()?;
        let reply = self
            .control(
                ExtensionOperation::ResolveSessionTab {
                    raw_id: raw_id.to_owned(),
                },
                json!({"rawId":raw_id,"sessionOnly":true}),
            )
            .await?;
        let result = reply.outcome.into_result("resolve")?;
        require_session_tab_ack(&result)?;
        decode(
            result
                .get("tab")
                .cloned()
                .ok_or_else(|| protocol("resolve result lacks actual tab"))?,
        )
    }
    /// Read only the last committed URL through the captured logical session.
    /// The value is not an Origin, complete tab metadata, or a liveness proof.
    /// Chatgpt session activation may have effects even though this transport
    /// observation has no retained mutation receipt.
    pub async fn committed_session_tab_url(
        &self,
        raw_id: &str,
    ) -> Result<ExtensionCommittedTabUrl, ExtensionProviderError> {
        self.require_session_tab_context()?;
        let reply = self
            .control(
                ExtensionOperation::CommittedSessionTabUrl {
                    raw_id: raw_id.to_owned(),
                },
                json!({"rawId":raw_id,"sessionOnly":true,"committedUrlOnly":true}),
            )
            .await?;
        let result = reply.outcome.into_result("resolve")?;
        require_session_tab_ack(&result)?;
        if result.get("committedUrlOnly").and_then(Value::as_bool) != Some(true) {
            return Err(protocol(
                "committed URL result lacks its exact selector acknowledgement",
            ));
        }
        let url = result
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| protocol("committed URL result lacks its actual string"))?;
        Ok(ExtensionCommittedTabUrl(url.to_owned()))
    }
    fn require_session_tab_context(&self) -> Result<(), ExtensionProviderError> {
        if self.wire_context.is_none() {
            return Err(refused(
                "context_required",
                "session-only metadata and preparation require captured trusted wire context",
            ));
        }
        Ok(())
    }
    pub async fn attach_tab(
        &self,
        raw_id: u64,
    ) -> Result<ExtensionPhysicalClaim, ExtensionProviderError> {
        let reply = self
            .control(
                ExtensionOperation::Attach { tab_id: raw_id },
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
        Ok(ExtensionPhysicalClaim {
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
        claim: &ExtensionPhysicalClaim,
    ) -> Result<Arc<CdpConnection>, ExtensionProviderError> {
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
    /// accepted invocations remain pending until their actual extension reply.
    /// Missing replies remain Unknown and cannot turn into an empty proof.
    /// Extension reply completion does not settle the underlying Chrome effect.
    ///
    /// # Errors
    /// Refuses foreign bindings and reports an unknown outcome when the current
    /// broker generation, claim custody, or IPC observation cannot be established.
    pub async fn fence_claim_cdp(
        &self,
        claim: &ExtensionPhysicalClaim,
    ) -> Result<ExtensionClaimCdpSnapshot, ExtensionProviderError> {
        self.check_claim(claim)?;
        let reply = self
            .control(
                ExtensionOperation::FenceCdp {
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
        if fields.pending.len() > MAX_PENDING_EXTENSION_CONTEXTS {
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
        Ok(ExtensionClaimCdpSnapshot {
            provider: self.identity().clone(),
            claim: claim.token.clone(),
            pending: fields.pending,
            observation_id: reply.id,
        })
    }

    /// Wait for extension invocation replies after fencing this exact claim.
    ///
    /// Progress notifications only trigger a fresh broker observation. Subscribe
    /// before fencing so a terminal reply racing the first snapshot is not lost.
    /// No extension command is replayed or consumed by this observation API.
    ///
    /// # Errors
    /// A missing extension reply, transport loss or deadline returns Unknown. A
    /// physical detach ACK and an empty control snapshot cannot replace this
    /// observation; an answered error still leaves Host effect outcome Unknown.
    pub async fn wait_claim_cdp_drained(
        &self,
        claim: &ExtensionPhysicalClaim,
        timeout: std::time::Duration,
    ) -> Result<ExtensionClaimCdpDrainProof, ExtensionProviderError> {
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
                        return Ok(ExtensionClaimCdpDrainProof {
                            binding: self.inner.binding,
                            provider: snapshot.provider,
                            claim: snapshot.claim,
                            observation_id: snapshot.observation_id,
                        });
                    }
                    loop {
                        match notifications.recv().await {
                            Ok(ExtensionProviderEvent::ClaimCdpProgress { claim: changed })
                                if changed == claim.token =>
                            {
                                break;
                            }
                            Ok(ExtensionProviderEvent::GenerationClosed { reason }) => {
                                return Err(unknown("drainClaimCdp", &reason));
                            }
                            Ok(ExtensionProviderEvent::ClaimUnavailable {
                                claim: changed, ..
                            }) if changed == claim.token => break,
                            Err(broadcast::error::RecvError::Lagged(_)) => break,
                            Err(broadcast::error::RecvError::Closed) => {
                                return Err(unknown(
                                    "drainClaimCdp",
                                    "extension progress channel closed before CDP settlement",
                                ));
                            }
                            _ => {}
                        }
                    }
                }
            };
        tokio::time::timeout(timeout, drain).await.map_err(|_| {
            unknown(
                "drainClaimCdp",
                "claim extension invocations did not answer before the drain deadline",
            )
        })?
    }

    /// Retire local broker bookkeeping after the Host has applied cleanup effects.
    ///
    /// The caller must first fold its issued extension control/effect facts into the
    /// existing extension custody and acknowledge folded effect/orphan receipts.
    /// Underlying extension CDP effect Unknown independently blocks retirement.
    /// Keep the physical cleanup receipt until this method succeeds, then ACK it.
    /// This checks only extension-local eligibility and raw claim drain. Outer Host
    /// journals and futures retain their maka T1/T2; no aggregate outer T2 query
    /// or wait is required or performed here.
    /// A workflow may remain Unknown while retaining an exact physical cleanup
    /// ACK. Using that separately known proof never changes the workflow outcome
    /// or settles any independent effect Unknown. This performs no Chrome action.
    ///
    /// # Errors
    /// Foreign/stale claims or drain proofs, consumed or unproven cleanup receipts,
    /// and a mismatched broker retirement acknowledgement are rejected. No
    /// cleanup completion is consumed by this method.
    pub async fn retire_claim(
        &self,
        claim: &ExtensionPhysicalClaim,
        cleanup: &CleanupProof,
        drain: &ExtensionClaimCdpDrainProof,
    ) -> Result<(), ExtensionProviderError> {
        async {
            self.check_claim(claim)?;
            if drain.binding != self.inner.binding
                || drain.provider != *self.identity()
                || drain.claim != claim.token
            {
                return Err(refused(
                    "drain_unavailable",
                    "CDP drain proof belongs to another owner, generation or claim",
                ));
            }
            let completions = self.pending_completions().await?;
            if completions
                .iter()
                .any(|entry| unacknowledged_retirement_fact(&entry.operation, &claim.token))
            {
                return Err(refused(
                    "retirement_unsettled",
                    "claim effect or orphan receipts must be folded and acknowledged before retirement",
                ));
            }
            let completion = completions
                .into_iter()
                .find(|completion| completion.id == cleanup.completion_id)
                .ok_or_else(|| {
                    refused(
                        "cleanup_unavailable",
                        "cleanup completion is not currently retained",
                    )
                })?;
            let exact_operation = match &completion.operation {
                ExtensionOperation::Detach {
                    claim: issued,
                    tab_id,
                    target_id,
                }
                | ExtensionOperation::CloseTab {
                    claim: issued,
                    tab_id,
                    target_id,
                } => issued == &claim.token && *tab_id == claim.tab_id && target_id == &claim.target_id,
                ExtensionOperation::StopCreatedTab { tab_id, .. } => *tab_id == Some(claim.tab_id),
                _ => false,
            };
            if !exact_operation {
                return Err(refused(
                    "cleanup_unavailable",
                    "cleanup completion does not belong to this exact claim or Created tab",
                ));
            }
            if let ExtensionOperationOutcome::Unknown {
                details: Some(details),
                ..
            } = &completion.outcome
            {
                if let Some(acknowledged) = details
                    .get("acknowledgedResult")
                    .or_else(|| details.get("physicalProof"))
                {
                    if acknowledged
                        .get("claim")
                        .is_some_and(|issued| issued.as_str() != Some(claim.token.as_str()))
                        || acknowledged
                            .get("tabId")
                            .is_some_and(|issued| issued.as_u64() != Some(claim.tab_id))
                        || acknowledged
                            .get("targetId")
                            .is_some_and(|issued| issued.as_str() != Some(claim.target_id.as_str()))
                    {
                        return Err(refused(
                            "cleanup_unavailable",
                            "acknowledged cleanup changed its issued claim or tab identity",
                        ));
                    }
                }
            }
            let issued = match self.materialize_retained(&completion)? {
                ExtensionRecoveredOperation::Cleanup(issued) => Some(issued),
                ExtensionRecoveredOperation::Unknown { custody, .. } => custody.cleanup,
                _ => None,
            }
            .ok_or_else(|| {
                refused(
                    "cleanup_unavailable",
                    "cleanup completion has no known physical cleanup proof",
                )
            })?;
            let absence_matches = match (&cleanup.tab_absence, &issued.tab_absence) {
                (None, None) => true,
                (Some(actual), Some(expected)) => {
                    actual.tab_id == expected.tab_id
                        && actual.extension_request_id == expected.extension_request_id
                }
                _ => false,
            };
            if cleanup.evidence != issued.evidence || !absence_matches {
                return Err(refused(
                    "cleanup_unavailable",
                    "cleanup proof differs from the currently retained completion",
                ));
            }
            Ok::<(), ExtensionProviderError>(())
        }
        .await
        .map_err(|error| self.preflight_error("retireClaim", error))?;
        let reply = self
            .control(
                ExtensionOperation::RetireClaim {
                    claim: claim.token.clone(),
                    cleanup_id: cleanup.completion_id,
                },
                json!({"claim":claim.token,"cleanupId":cleanup.completion_id}),
            )
            .await?;
        let result = reply.outcome.into_result("retireClaim")?;
        if result["retired"] != true || result["claim"].as_str() != Some(claim.token.as_str()) {
            return Err(protocol(
                "claim retirement acknowledgement changed its exact claim or result",
            ));
        }
        Ok(())
    }

    pub async fn detach_tab(
        &self,
        claim: &ExtensionPhysicalClaim,
    ) -> Result<CleanupProof, ExtensionProviderError> {
        self.check_claim(claim)?;
        let operation = ExtensionOperation::Detach {
            claim: claim.token.clone(),
            tab_id: claim.tab_id,
            target_id: claim.target_id.clone(),
        };
        let reply = self
            .control(operation.clone(), json!({"claim":claim.token}))
            .await?;
        cleanup_proof_for_operation(reply, &operation)
    }
    pub async fn create_tab(
        &self,
        preferred_window_id: Option<i64>,
    ) -> Result<ExtensionCreatedTab, ExtensionProviderError> {
        let params = match preferred_window_id {
            Some(id) => json!({"windowId":id}),
            None => json!({}),
        };
        let reply = self
            .control(
                ExtensionOperation::CreateTab {
                    preferred_window_id,
                },
                params,
            )
            .await?;
        let result = reply.outcome.into_result("createTab")?;
        self.created_from_result(&result, reply.id, false)
    }
    /// Upgrade the same physical claim only after the Host has admitted this
    /// exact current document and expanded its site/opaque-origin policy.
    /// The existing call view must capture both Host operation and wire context.
    pub async fn prepare_claim(
        &self,
        claim: &ExtensionPhysicalClaim,
        document: &ExtensionPreparationDocument,
        policy: &ExtensionPreparationPolicy,
    ) -> Result<ExtensionClaimPreparationProof, ExtensionProviderError> {
        self.check_claim(claim)
            .map_err(|error| self.preflight_error("prepareClaim", error))?;
        if claim.cleanup_only {
            return Err(self.preflight_error(
                "prepareClaim",
                refused(
                    "claim_unavailable",
                    "cleanup-only claim cannot acquire preparation",
                ),
            ));
        }
        let context = self
            .preparation_context()
            .map_err(|error| self.preflight_error("prepareClaim", error))?;
        if !self.capabilities()?.explicit_claim_preparation {
            return Err(self.preflight_error(
                "prepareClaim",
                refused(
                    "unsupported",
                    "selected provider has no explicit same-claim preparation",
                ),
            ));
        }
        let charge = self
            .inner
            .retained_payload_budget
            .try_charge(document)
            .map_err(|error| {
                self.preflight_error(
                    "prepareClaim",
                    refused(
                        "document_budget",
                        &format!("retained document was not admitted: {error}"),
                    ),
                )
            })?;
        let document_binding =
            ExtensionPreparationDocumentBinding(Arc::new(RetainedPreparationDocument {
                document: document.clone(),
                _charge: charge,
            }));
        let operation = ExtensionOperation::PrepareClaim {
            claim: claim.token.clone(),
            document: document_binding,
            popup_enabled: policy.popup_enabled,
            header_enabled: policy.header_enabled,
        };
        let reply = self
            .control(
                operation.clone(),
                json!({"claim":claim.token,"document":document,"policy":policy}),
            )
            .await?;
        let result = reply.outcome.into_result("prepareClaim")?;
        self.preparation_from_result(&result, &operation, context, reply.id, false)
    }

    /// Create one inactive blank child in the actual opener's window. This
    /// reuses Created custody; the Host separately claims the child and navigates.
    pub async fn create_popup_tab(
        &self,
        opener: &ExtensionPhysicalClaim,
    ) -> Result<ExtensionCreatedTab, ExtensionProviderError> {
        self.check_claim(opener)?;
        if opener.cleanup_only {
            return Err(refused(
                "claim_unavailable",
                "cleanup-only claim cannot create a popup",
            ));
        }
        self.preparation_context()?;
        let reply = self
            .control(
                ExtensionOperation::CreatePopupTab {
                    opener_claim: opener.token.clone(),
                },
                json!({"claim":opener.token}),
            )
            .await?;
        let result = reply.outcome.into_result("createPopupTab")?;
        self.created_from_result(&result, reply.id, false)
    }

    /// Create an inactive blank child from an issued logical opener, without attachment.
    pub async fn create_session_popup_tab(
        &self,
        opener: &ExtensionFixedSessionReceipt,
    ) -> Result<ExtensionCreatedTab, ExtensionProviderError> {
        self.check_fixed_receipt(opener, false)?;
        if self.preparation_context()? != opener.wire_context() {
            return Err(refused(
                "context_mismatch",
                "logical popup requires its captured preparation turn",
            ));
        }
        let reply = self
            .control(
                ExtensionOperation::CreateSessionPopupTab {
                    opener: opener.clone(),
                },
                json!({"tabId":opener.tab_id,"scopeId":opener.scope_id}),
            )
            .await?;
        self.created_from_result(
            &reply.outcome.into_result("createSessionPopupTab")?,
            reply.id,
            false,
        )
    }

    fn preparation_context(&self) -> Result<&ExtensionWireContext, ExtensionProviderError> {
        let context = self.wire_context.as_ref().ok_or_else(|| {
            refused(
                "context_required",
                "same-claim preparation requires captured trusted wire context",
            )
        })?;
        let operation = self.host_operation.as_ref().ok_or_else(|| {
            refused(
                "context_required",
                "same-claim preparation requires an issued Host operation",
            )
        })?;
        if operation.turn_id != context.host_turn_id() {
            return Err(refused(
                "context_mismatch",
                "Host operation and captured wire context name different turns",
            ));
        }
        Ok(context)
    }

    fn preparation_from_result(
        &self,
        result: &Value,
        operation: &ExtensionOperation,
        context: &ExtensionWireContext,
        completion_id: u64,
        cleanup_only: bool,
    ) -> Result<ExtensionClaimPreparationProof, ExtensionProviderError> {
        let ExtensionOperation::PrepareClaim {
            claim,
            document,
            popup_enabled,
            header_enabled,
        } = operation
        else {
            return Err(protocol(
                "preparation receipt has no issued preparation operation",
            ));
        };
        let fields: ClaimPreparationFields = decode(result.clone())?;
        if fields.claim != *claim || fields.preparation_key.is_empty() {
            return Err(protocol(
                "preparation acknowledgement changed its claim or lacks its actual key",
            ));
        }
        Ok(ExtensionClaimPreparationProof {
            claim: claim.clone(),
            generation: self.identity().generation.clone(),
            document: document.clone(),
            wire_context: context.clone(),
            preparation_key: fields.preparation_key,
            popup_enabled: *popup_enabled,
            header_enabled: *header_enabled,
            foreign_installed: fields.foreign_installed,
            popup_installed: fields.popup_installed,
            completion_id,
            cleanup_only,
        })
    }

    pub async fn close_tab(
        &self,
        claim: &ExtensionPhysicalClaim,
    ) -> Result<CleanupProof, ExtensionProviderError> {
        self.check_claim(claim)?;
        if claim.cleanup_only {
            return Err(refused(
                "claim_unavailable",
                "uncertain attachment can be detached, not promoted to close authority",
            ));
        }
        let operation = ExtensionOperation::CloseTab {
            claim: claim.token.clone(),
            tab_id: claim.tab_id,
            target_id: claim.target_id.clone(),
        };
        let reply = self
            .control(operation.clone(), json!({"claim":claim.token}))
            .await?;
        cleanup_proof_for_operation(reply, &operation)
    }
    pub async fn stop_created_tab(
        &self,
        receipt: &ExtensionCreationReceipt,
    ) -> Result<CleanupProof, ExtensionProviderError> {
        if receipt.binding != self.inner.binding || receipt.generation != self.identity().generation
        {
            return Err(refused(
                "creation_unavailable",
                "created-tab receipt belongs to another owner or generation",
            ));
        }
        let mut params = json!({"creation":receipt.token});
        if let Some(tab_id) = receipt.tab_id {
            params["tabId"] = json!(tab_id);
        }
        let operation = ExtensionOperation::StopCreatedTab {
            creation: receipt.token.clone(),
            tab_id: receipt.tab_id,
        };
        let reply = self.control(operation.clone(), params).await?;
        cleanup_proof_for_operation(reply, &operation)
    }
    pub async fn set_scoped_headers(
        &self,
        claim: &ExtensionPhysicalClaim,
        session_id: &str,
        headers: Option<&[ExtensionHeader]>,
    ) -> Result<ExtensionHeaderProof, ExtensionProviderError> {
        self.check_claim(claim)?;
        if claim.cleanup_only {
            return Err(refused(
                "claim_unavailable",
                "uncertain attachment permits header cleanup only",
            ));
        }
        let reply = self
            .control(
                ExtensionOperation::SetScopedHeaders {
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
        claim: &ExtensionPhysicalClaim,
    ) -> Result<ExtensionHeaderProof, ExtensionProviderError> {
        self.check_claim(claim)?;
        let reply = self
            .control(
                ExtensionOperation::ClearScopedHeaders {
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
    fn check_creation(
        &self,
        receipt: &ExtensionCreationReceipt,
    ) -> Result<(), ExtensionProviderError> {
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
    fn check_group(
        &self,
        group: &ExtensionManagedGroupReceipt,
    ) -> Result<(), ExtensionProviderError> {
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
    ) -> Result<ExtensionPreparedTab, ExtensionProviderError> {
        let reply = self
            .control(
                ExtensionOperation::PrepareUserTab { tab_id },
                json!({"tabId":tab_id}),
            )
            .await?;
        let result = reply.outcome.into_result("prepareUserTab")?;
        Ok(ExtensionPreparedTab {
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
    /// Run the provider's actual session preparation transaction under captured context.
    /// The result attests its actual tab and receipt, without inventing a
    /// normalization flag that the Chatgpt extension transaction does not expose.
    pub async fn prepare_session_tab(
        &self,
        tab_id: u64,
    ) -> Result<ExtensionSessionPreparedTab, ExtensionProviderError> {
        self.require_session_tab_context()?;
        let reply = self
            .control(
                ExtensionOperation::PrepareSessionTab { tab_id },
                json!({"tabId":tab_id,"sessionOnly":true}),
            )
            .await?;
        let result = reply.outcome.into_result("prepareUserTab")?;
        session_prepared_tab(&result, tab_id, reply.id)
    }
    /// Publish one real fixed-session preparation without acquiring a debugger.
    /// Requires the explicit fixed service and the current issued Host operation.
    pub async fn prepare_fixed_session_tab(
        &self,
        tab_id: u64,
        policy: &ExtensionPreparationPolicy,
        ui: &ExtensionFixedUiRequest,
    ) -> Result<ExtensionFixedSessionPreparedTab, ExtensionProviderError> {
        let context = self.preparation_context()?;
        if tab_id == 0 || tab_id > 9_007_199_254_740_991 {
            return Err(refused(
                "invalid_request",
                "session tab ID is not a positive safe integer",
            ));
        }
        ui.validate_preparation()
            .map_err(|message| refused("invalid_request", message))?;
        if self.capabilities()?.session_preparation != ExtensionSessionPreparation::ExplicitFixed {
            return Err(refused(
                "unsupported",
                "selected provider has no explicit fixed-session preparation",
            ));
        }
        let scope_id = uuid::Uuid::new_v4().to_string();
        let operation = ExtensionOperation::PrepareFixedSessionTab {
            tab_id,
            scope_id: scope_id.clone(),
            popup_enabled: policy.popup_enabled,
            header_enabled: policy.header_enabled,
            ui: self.retain_fixed_ui(ui)?,
        };
        let reply = self
            .control(
                operation.clone(),
                json!({"tabId":tab_id,"scopeId":scope_id,"policy":policy,"ui":ui}),
            )
            .await?;
        let result = reply.outcome.into_result("prepareSessionTab")?;
        self.fixed_preparation_from_result(&result, &operation, context, reply.id)
    }

    /// Send only a fixed UI operation under an SDK-issued logical session receipt.
    /// A later turn may Configure appearance with a higher epoch under its fresh
    /// Host operation. This does not rebind the receipt or permit ordinary UI in
    /// that turn; clear the old scope and prepare a new one for ordinary updates.
    pub async fn session_ui(
        &self,
        receipt: &ExtensionFixedSessionReceipt,
        ui: &ExtensionFixedUiRequest,
    ) -> Result<ExtensionFixedUiProof, ExtensionProviderError> {
        self.check_fixed_receipt(receipt, false)?;
        ui.validate()
            .map_err(|message| refused("invalid_request", message))?;
        let context = self.preparation_context()?;
        if ui.cursor.id != receipt.ui.cursor_id() {
            return Err(refused(
                "preparation_unavailable",
                "fixed UI cursor identity changed",
            ));
        }
        if context != &receipt.wire_context {
            let newer =
                ui.owner_epoch.parse::<u64>().ok() > receipt.ui.owner_epoch().parse::<u64>().ok();
            if ui.operation != ExtensionFixedUiOperation::Configure || !newer {
                return Err(refused(
                    "context_mismatch",
                    "ordinary fixed UI requires the captured preparation turn",
                ));
            }
        }
        let operation = ExtensionOperation::SessionUi {
            receipt: receipt.clone(),
            ui: self.retain_fixed_ui(ui)?,
        };
        let reply = self
            .control(
                operation,
                json!({"tabId":receipt.tab_id,"scopeId":receipt.scope_id,"ui":ui}),
            )
            .await?;
        fixed_ui_proof(&reply.outcome.into_result("sessionUi")?, receipt, reply.id)
    }

    /// Clear the exact old logical scope; never detach or close a user tab.
    pub async fn clear_session_preparation(
        &self,
        receipt: &ExtensionFixedSessionReceipt,
    ) -> Result<ExtensionFixedSessionCleanupProof, ExtensionProviderError> {
        self.check_fixed_receipt(receipt, true)?;
        let reply = self
            .control(
                ExtensionOperation::ClearSessionPreparation {
                    receipt: receipt.clone(),
                },
                json!({"tabId":receipt.tab_id,"scopeId":receipt.scope_id}),
            )
            .await?;
        fixed_cleanup_proof(
            &reply.outcome.into_result("clearSessionPreparation")?,
            receipt,
            reply.id,
        )
    }

    fn check_fixed_receipt(
        &self,
        receipt: &ExtensionFixedSessionReceipt,
        cleanup: bool,
    ) -> Result<(), ExtensionProviderError> {
        if receipt.binding != self.inner.binding
            || receipt.generation != self.identity().generation
            || (!cleanup && receipt.cleanup_only)
        {
            return Err(refused(
                "preparation_unavailable",
                "logical preparation receipt is foreign, stale or cleanup-only",
            ));
        }
        let current = self.preparation_context()?;
        if current.host_session_id() != receipt.wire_context.host_session_id() {
            return Err(refused(
                "context_mismatch",
                "logical preparation belongs to another Host session",
            ));
        }
        Ok(())
    }

    fn retain_fixed_ui(
        &self,
        ui: &ExtensionFixedUiRequest,
    ) -> Result<ExtensionFixedUiIdentity, ExtensionProviderError> {
        let fields = FixedUiIdentityFields {
            operation: ui.operation,
            cursor_id: ui.cursor.id.clone(),
            owner_epoch: ui.owner_epoch.clone(),
        };
        let charge = self
            .inner
            .retained_payload_budget
            .try_charge(&fields)
            .map_err(|error| {
                refused(
                    "preparation_budget",
                    &format!("retained fixed UI identity was not admitted: {error}"),
                )
            })?;
        Ok(ExtensionFixedUiIdentity(Arc::new(
            RetainedFixedUiIdentity {
                fields,
                _charge: charge,
            },
        )))
    }

    fn fixed_receipt_from_operation(
        &self,
        operation: &ExtensionOperation,
        context: &ExtensionWireContext,
        completion_id: u64,
        cleanup_only: bool,
    ) -> Result<ExtensionFixedSessionReceipt, ExtensionProviderError> {
        let ExtensionOperation::PrepareFixedSessionTab {
            tab_id,
            scope_id,
            ui,
            ..
        } = operation
        else {
            return Err(protocol(
                "logical preparation receipt has no issued fixed preparation",
            ));
        };
        Ok(ExtensionFixedSessionReceipt {
            binding: self.inner.binding,
            generation: self.identity().generation.clone(),
            scope_id: scope_id.clone(),
            tab_id: *tab_id,
            wire_context: context.clone(),
            ui: ui.clone(),
            completion_id,
            cleanup_only,
        })
    }

    fn fixed_preparation_from_result(
        &self,
        result: &Value,
        operation: &ExtensionOperation,
        context: &ExtensionWireContext,
        completion_id: u64,
    ) -> Result<ExtensionFixedSessionPreparedTab, ExtensionProviderError> {
        let receipt =
            self.fixed_receipt_from_operation(operation, context, completion_id, false)?;
        require_session_tab_ack(result)?;
        let fields: FixedPreparationFields = decode(result.clone())?;
        if !fields.session_only
            || fields.tab.id != receipt.tab_id
            || fields.preparation.scope_id != receipt.scope_id
        {
            return Err(protocol(
                "fixed preparation changed the issued tab or scope",
            ));
        }
        let mut headers = fields.preparation.headers;
        if let Some(scope) = &headers.scope {
            if scope.claim != receipt.scope_id
                || scope.generation != receipt.generation
                || scope.tab_id != receipt.tab_id
                || scope.owner.is_empty()
            {
                return Err(protocol(
                    "fixed preparation headers name another logical scope",
                ));
            }
        } else if headers.active {
            return Err(protocol(
                "active fixed preparation headers lack their logical scope",
            ));
        }
        headers.completion_id = completion_id;
        Ok(ExtensionFixedSessionPreparedTab {
            tab: fields.tab,
            receipt,
            foreign_installed: fields.preparation.foreign_installed,
            popup_installed: fields.preparation.popup_installed,
            headers,
            ui: fields.preparation.ui,
        })
    }

    async fn presentation_diagnostic(
        &self,
        creation: &ExtensionCreationReceipt,
        unmute: bool,
    ) -> Result<ExtensionMutationDiagnostic, ExtensionProviderError> {
        self.check_creation(creation)?;
        let operation = if unmute {
            ExtensionOperation::UnmuteCreatedTabIfActive {
                creation: creation.token.clone(),
            }
        } else {
            ExtensionOperation::MuteCreatedTab {
                creation: creation.token.clone(),
            }
        };
        let method = operation.method();
        let reply = self
            .control(operation, json!({"creation":creation.token}))
            .await?;
        let mut result: ExtensionMutationDiagnostic = decode(reply.outcome.into_result(method)?)?;
        result.completion_id = reply.id;
        Ok(result)
    }
    pub async fn mute_created_tab(
        &self,
        creation: &ExtensionCreationReceipt,
    ) -> Result<ExtensionMutationDiagnostic, ExtensionProviderError> {
        self.presentation_diagnostic(creation, false).await
    }
    pub async fn unmute_created_tab_if_active(
        &self,
        creation: &ExtensionCreationReceipt,
    ) -> Result<ExtensionMutationDiagnostic, ExtensionProviderError> {
        self.presentation_diagnostic(creation, true).await
    }
    fn group_proof(
        &self,
        reply: ControlReply,
        method: &str,
    ) -> Result<ExtensionGroupProof, ExtensionProviderError> {
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
        Ok(ExtensionGroupProof {
            group: ExtensionManagedGroupReceipt {
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
        creation: &ExtensionCreationReceipt,
        existing_group: Option<&ExtensionManagedGroupReceipt>,
        presentation: &ExtensionGroupPresentation,
    ) -> Result<ExtensionGroupProof, ExtensionProviderError> {
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
                ExtensionOperation::EnsureCreatedTabGroup {
                    creation: creation.token.clone(),
                },
                json!({"creation":creation.token,"presentation":presentation}),
            )
            .await?;
        self.group_proof(reply, "ensureCreatedTabGroup")
    }
    pub async fn update_created_tab_group(
        &self,
        creation: &ExtensionCreationReceipt,
        group: &ExtensionManagedGroupReceipt,
        presentation: &ExtensionGroupPresentation,
    ) -> Result<ExtensionGroupProof, ExtensionProviderError> {
        self.check_creation(creation)?;
        self.check_group(group)?;
        let reply = self
            .control(
                ExtensionOperation::UpdateCreatedTabGroup {
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
        creation: &ExtensionCreationReceipt,
        group: &ExtensionManagedGroupReceipt,
    ) -> Result<ExtensionGroupReleaseProof, ExtensionProviderError> {
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
                ExtensionOperation::ReleaseCreatedTabGroup {
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
            Some("already_not_member") => ExtensionGroupReleaseEvidence::AlreadyNotMember,
            Some("ungroup_ack") => ExtensionGroupReleaseEvidence::UngroupAcknowledged,
            _ => return Err(protocol("unknown group release proof")),
        };
        Ok(ExtensionGroupReleaseProof {
            evidence,
            completion_id: reply.id,
        })
    }
    pub async fn set_session_headers(
        &self,
        headers: &[ExtensionHeader],
    ) -> Result<ExtensionSessionHeaderProof, ExtensionProviderError> {
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
                ExtensionOperation::SetSessionHeaders {
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
    ) -> Result<ExtensionSessionHeaderProof, ExtensionProviderError> {
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
            .control(ExtensionOperation::ClearSessionHeaders, json!({}))
            .await?;
        session_header_proof(reply, &context, &self.identity().generation, false)
    }
    pub async fn move_mouse_presentation(
        &self,
        claim: &ExtensionPhysicalClaim,
        x: f64,
        y: f64,
        wait_for_arrival: Option<bool>,
    ) -> Result<ExtensionCursorPresentationAck, ExtensionProviderError> {
        self.check_claim(claim)?;
        if self.wire_context.is_none() {
            return Err(refused(
                "missing_context",
                "extension cursor presentation requires trusted session and turn metadata",
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
                ExtensionOperation::MoveMousePresentation {
                    claim: claim.token.clone(),
                    x,
                    y,
                    wait_for_arrival,
                },
                params,
            )
            .await?;
        reply.outcome.into_result("moveMouse")?;
        Ok(ExtensionCursorPresentationAck {
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
        keep: Option<&[ExtensionKeepTab]>,
    ) -> Result<ExtensionTurnFinishAck, ExtensionProviderError> {
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
                ExtensionOperation::FinishTurn {
                    keep: keep.map(<[ExtensionKeepTab]>::to_vec),
                },
                json!({"keep":keep}),
            )
            .await?;
        reply.outcome.into_result("finishTurn")?;
        Ok(ExtensionTurnFinishAck {
            host_session_id: context.host_session_id().to_owned(),
            host_turn_id: context.host_turn_id().to_owned(),
            completion_id: reply.id,
        })
    }
    /// FIFO barrier for control operations only (attach/create/preparation/
    /// headers/cleanup). None outcome remains in flight. Absence does not prove
    /// no dispatch: nonretained completed reads and acknowledged mutations are
    /// absent too. Only a Rust-produced NotDispatched phase proves zero dispatch;
    /// the Host retains its independent operation and cleanup responsibilities.
    /// Generic CdpConnection calls have their maka pending/unknown semantics:
    /// this snapshot never authorizes replay of CDP input or JavaScript.
    pub async fn pending_operations(
        &self,
    ) -> Result<Vec<ExtensionPendingOperation>, ExtensionProviderError> {
        let (reply, result) = oneshot::channel();
        self.inner
            .commands
            .send(ClientCommand::Snapshot { reply })
            .await
            .map_err(|_| unknown("pendingOperations", "runtime actor ended"))?;
        result
            .await
            .map_err(|_| unknown("pendingOperations", "runtime actor ended"))?
    }
    /// Effect-free typed recovery from a currently retained, issued receipt.
    /// This performs no extension request and never replays the original mutation.
    pub async fn recover_completion(
        &self,
        receipt_id: u64,
    ) -> Result<ExtensionRecoveredOperation, ExtensionProviderError> {
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
    /// Recover only the exact cleanup address of an issued fixed preparation.
    /// A contradictory fulfilled result does not prove its effects absent. This
    /// never upgrades malformed metadata into ordinary UI or physical custody.
    pub async fn recover_fixed_session_cleanup(
        &self,
        receipt_id: u64,
    ) -> Result<ExtensionFixedSessionReceipt, ExtensionProviderError> {
        let completion = self
            .pending_completions()
            .await?
            .into_iter()
            .find(|entry| entry.id == receipt_id)
            .ok_or_else(|| {
                refused(
                    "completion_unavailable",
                    "issued fixed preparation is not retained",
                )
            })?;
        if completion.provider != *self.identity()
            || !matches!(
                completion.outcome,
                ExtensionOperationOutcome::Result(_) | ExtensionOperationOutcome::Unknown { .. }
            )
        {
            return Err(refused(
                "completion_unavailable",
                "fixed preparation has no uncertain or fulfilled retained receipt",
            ));
        }
        let context = completion
            .wire_context
            .as_ref()
            .ok_or_else(|| protocol("fixed preparation cleanup address lost captured context"))?;
        let host = completion.host_operation.as_ref().ok_or_else(|| {
            protocol("fixed preparation cleanup address lost issued Host operation")
        })?;
        if host.turn_id != context.host_turn_id() {
            return Err(protocol(
                "fixed preparation cleanup address changed its issued Host turn",
            ));
        }
        self.fixed_receipt_from_operation(&completion.operation, context, completion.id, true)
    }

    pub async fn materialize_completion(
        &self,
        completion: &ExtensionOperationCompletion,
    ) -> Result<ExtensionRecoveredOperation, ExtensionProviderError> {
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
        completion: &ExtensionOperationCompletion,
    ) -> Result<ExtensionRecoveredOperation, ExtensionProviderError> {
        if completion.provider != *self.identity() {
            return Err(refused(
                "completion_unavailable",
                "receipt belongs to another provider generation",
            ));
        }
        let result = match &completion.outcome {
            ExtensionOperationOutcome::Result(result) => result.clone(),
            ExtensionOperationOutcome::ChromeRejected { message, details } => {
                return Ok(ExtensionRecoveredOperation::ChromeRejected {
                    message: message.clone(),
                    details: details.clone(),
                });
            }
            ExtensionOperationOutcome::NotDispatched {
                kind,
                message,
                details,
            } => {
                return Ok(ExtensionRecoveredOperation::NotDispatched {
                    kind: kind.clone(),
                    message: message.clone(),
                    details: details.clone(),
                });
            }
            ExtensionOperationOutcome::ConnectorRejected {
                kind,
                message,
                details,
            } => {
                return Ok(ExtensionRecoveredOperation::Refused {
                    kind: kind.clone(),
                    message: message.clone(),
                    details: details.clone(),
                });
            }
            ExtensionOperationOutcome::Unknown { reason, details } => {
                return Ok(ExtensionRecoveredOperation::Unknown {
                    operation: completion.operation.clone(),
                    reason: reason.clone(),
                    details: details.clone(),
                    custody: Box::new(self.recover_known_custody(completion, details.as_ref())?),
                });
            }
        };
        let reply = || ControlReply {
            id: completion.id,
            outcome: ExtensionOperationOutcome::Result(result.clone()),
        };
        Ok(match &completion.operation {
            ExtensionOperation::UserHistory => ExtensionRecoveredOperation::UserHistory,
            ExtensionOperation::NameSession { name } => {
                if result.get("renamed") != Some(&Value::Bool(true)) {
                    return Err(protocol("session name acknowledgement missing"));
                }
                ExtensionRecoveredOperation::SessionNamed { name: name.clone() }
            }
            ExtensionOperation::BeginUpload { .. } => {
                let context = completion
                    .wire_context
                    .as_ref()
                    .ok_or_else(|| protocol("upload begin lost captured context"))?;
                ExtensionRecoveredOperation::UploadBegun(self.upload_stage_from_result(
                    &result,
                    &completion.operation,
                    context,
                    completion.id,
                )?)
            }
            ExtensionOperation::WriteUploadChunk { .. } => {
                ExtensionRecoveredOperation::UploadChunkWritten(upload_chunk_ack(
                    &result,
                    &completion.operation,
                    completion.id,
                )?)
            }
            ExtensionOperation::RetainUploadForSelection { stage } => {
                ExtensionRecoveredOperation::UploadRetained(upload_retained(
                    &result,
                    stage,
                    completion.id,
                )?)
            }
            ExtensionOperation::AbandonUpload { stage } => {
                ExtensionRecoveredOperation::UploadAbandoned(upload_abandon_ack(
                    &result,
                    stage,
                    completion.id,
                )?)
            }
            ExtensionOperation::SetSessionHeaders { .. }
            | ExtensionOperation::ClearSessionHeaders => {
                let context = completion.wire_context.as_ref().ok_or_else(|| {
                    protocol("session header receipt lost immutable wire context")
                })?;
                ExtensionRecoveredOperation::SessionHeaders(session_header_proof(
                    reply(),
                    context,
                    &self.identity().generation,
                    matches!(
                        &completion.operation,
                        ExtensionOperation::SetSessionHeaders { has_headers: true }
                    ),
                )?)
            }
            ExtensionOperation::MoveMousePresentation {
                x,
                y,
                wait_for_arrival,
                ..
            } => ExtensionRecoveredOperation::CursorPresentation(ExtensionCursorPresentationAck {
                requested_x: *x,
                requested_y: *y,
                wait_for_arrival_requested: *wait_for_arrival,
                completion_id: completion.id,
            }),
            ExtensionOperation::FinishTurn { .. } => {
                let context = completion
                    .wire_context
                    .as_ref()
                    .ok_or_else(|| protocol("finish completion lost its immutable wire context"))?;
                ExtensionRecoveredOperation::TurnFinished(ExtensionTurnFinishAck {
                    host_session_id: context.host_session_id().to_owned(),
                    host_turn_id: context.host_turn_id().to_owned(),
                    completion_id: completion.id,
                })
            }
            ExtensionOperation::Attach { tab_id } => ExtensionRecoveredOperation::Claim(
                self.claim_from_result(&result, *tab_id, completion.id, false)?,
            ),
            ExtensionOperation::PopupRequested { request } => {
                ExtensionRecoveredOperation::PopupRequested(request.clone())
            }
            ExtensionOperation::SessionPopupRequested { request } => {
                ExtensionRecoveredOperation::SessionPopupRequested(request.clone())
            }
            ExtensionOperation::SessionPreparationCleanup { observation } => {
                ExtensionRecoveredOperation::SessionPreparationCleanup(observation.clone())
            }
            ExtensionOperation::PrepareClaim { .. } => {
                let context = completion.wire_context.as_ref().ok_or_else(|| {
                    protocol("preparation receipt lost its captured wire context")
                })?;
                ExtensionRecoveredOperation::ClaimPrepared(self.preparation_from_result(
                    &result,
                    &completion.operation,
                    context,
                    completion.id,
                    false,
                )?)
            }
            ExtensionOperation::CreateTab { .. }
            | ExtensionOperation::CreatePopupTab { .. }
            | ExtensionOperation::CreateSessionPopupTab { .. } => {
                ExtensionRecoveredOperation::Created(self.created_from_result(
                    &result,
                    completion.id,
                    false,
                )?)
            }
            ExtensionOperation::Detach { .. }
            | ExtensionOperation::CloseTab { .. }
            | ExtensionOperation::StopCreatedTab { .. } => ExtensionRecoveredOperation::Cleanup(
                cleanup_proof_for_operation(reply(), &completion.operation)?,
            ),
            ExtensionOperation::SetScopedHeaders { claim }
            | ExtensionOperation::ClearScopedHeaders { claim } => {
                ExtensionRecoveredOperation::Headers(header_proof(
                    reply(),
                    completion.operation.method(),
                    claim,
                    &self.identity().generation,
                    None,
                    false,
                )?)
            }
            ExtensionOperation::PrepareFixedSessionTab { .. } => {
                let context = completion
                    .wire_context
                    .as_ref()
                    .ok_or_else(|| protocol("fixed preparation lost its captured wire context"))?;
                ExtensionRecoveredOperation::FixedSessionPrepared(
                    self.fixed_preparation_from_result(
                        &result,
                        &completion.operation,
                        context,
                        completion.id,
                    )?,
                )
            }
            ExtensionOperation::SessionUi { receipt, .. } => ExtensionRecoveredOperation::FixedUi(
                fixed_ui_proof(&result, receipt, completion.id)?,
            ),
            ExtensionOperation::ClearSessionPreparation { receipt } => {
                ExtensionRecoveredOperation::FixedSessionCleared(fixed_cleanup_proof(
                    &result,
                    receipt,
                    completion.id,
                )?)
            }
            ExtensionOperation::PrepareSessionTab { tab_id } => {
                if completion.wire_context.is_none() {
                    return Err(protocol(
                        "session-only preparation receipt lost its captured wire context",
                    ));
                }
                ExtensionRecoveredOperation::SessionPrepared(session_prepared_tab(
                    &result,
                    *tab_id,
                    completion.id,
                )?)
            }
            ExtensionOperation::PrepareUserTab { tab_id } => {
                let tab: ExtensionTabInfo = decode(result["tab"].clone())?;
                if tab.id != *tab_id {
                    return Err(protocol("prepared completion changed tab identity"));
                }
                ExtensionRecoveredOperation::Prepared(ExtensionPreparedTab {
                    tab,
                    normalized: result["normalized"]
                        .as_bool()
                        .ok_or_else(|| protocol("normalization acknowledgement missing"))?,
                    completion_id: completion.id,
                })
            }
            ExtensionOperation::MuteCreatedTab { .. }
            | ExtensionOperation::UnmuteCreatedTabIfActive { .. } => {
                let mut value: ExtensionMutationDiagnostic = decode(result)?;
                value.completion_id = completion.id;
                ExtensionRecoveredOperation::Presentation(value)
            }
            ExtensionOperation::EnsureCreatedTabGroup { .. }
            | ExtensionOperation::UpdateCreatedTabGroup { .. } => {
                ExtensionRecoveredOperation::Group(
                    self.group_proof(reply(), completion.operation.method())?,
                )
            }
            ExtensionOperation::ReleaseCreatedTabGroup { .. } => {
                if result["released"] != true {
                    return Err(protocol("group release acknowledgement missing"));
                }
                let evidence = match result["proof"].as_str() {
                    Some("already_not_member") => ExtensionGroupReleaseEvidence::AlreadyNotMember,
                    Some("ungroup_ack") => ExtensionGroupReleaseEvidence::UngroupAcknowledged,
                    _ => return Err(protocol("unknown group release proof")),
                };
                ExtensionRecoveredOperation::GroupReleased(ExtensionGroupReleaseProof {
                    evidence,
                    completion_id: completion.id,
                })
            }
            ExtensionOperation::OrphanCdpCompletion {
                route,
                claim,
                id,
                event,
            } => ExtensionRecoveredOperation::OrphanCdpCompletion {
                route: *route,
                claim: claim.clone(),
                id: *id,
                event: event.clone(),
                wire_context: completion.wire_context.clone(),
            },
            ExtensionOperation::EffectsCleanup {
                claim,
                effect,
                cleanup_confirmed,
                error,
            } => ExtensionRecoveredOperation::EffectsCleanup {
                claim: claim.clone(),
                effect: effect.clone(),
                cleanup_confirmed: *cleanup_confirmed,
                error: error.clone(),
                wire_context: completion.wire_context.clone(),
            },
            ExtensionOperation::Inventory
            | ExtensionOperation::ReadUserTab { .. }
            | ExtensionOperation::SessionInventory
            | ExtensionOperation::Resolve { .. }
            | ExtensionOperation::ResolveSessionTab { .. }
            | ExtensionOperation::CommittedSessionTabUrl { .. }
            | ExtensionOperation::FenceCdp { .. }
            | ExtensionOperation::RetireClaim { .. } => {
                return Err(refused(
                    "completion_unavailable",
                    "read-only observations are not retained mutation receipts",
                ));
            }
        })
    }
    fn claim_from_result(
        &self,
        result: &Value,
        tab_id: u64,
        completion_id: u64,
        cleanup_only: bool,
    ) -> Result<ExtensionPhysicalClaim, ExtensionProviderError> {
        if result["tabId"].as_u64() != Some(tab_id) {
            return Err(protocol("acknowledged claim changed original tab identity"));
        }
        Ok(ExtensionPhysicalClaim {
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
    ) -> Result<ExtensionCreatedTab, ExtensionProviderError> {
        let tab: ExtensionTabInfo = decode(result["tab"].clone())?;
        let tab_id = Some(tab.id);
        Ok(ExtensionCreatedTab {
            tab,
            receipt: ExtensionCreationReceipt {
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
        completion: &ExtensionOperationCompletion,
        details: Option<&Value>,
    ) -> Result<ExtensionKnownCustody, ExtensionProviderError> {
        let fixed_session = match &completion.operation {
            ExtensionOperation::PrepareFixedSessionTab { .. } => {
                let context = completion.wire_context.as_ref().ok_or_else(|| {
                    protocol("unknown fixed preparation lost its captured context")
                })?;
                Some(self.fixed_receipt_from_operation(
                    &completion.operation,
                    context,
                    completion.id,
                    true,
                )?)
            }
            ExtensionOperation::SessionUi { receipt, .. }
            | ExtensionOperation::ClearSessionPreparation { receipt } => {
                let mut retained = receipt.clone();
                retained.cleanup_only = true;
                Some(retained)
            }
            _ => None,
        };
        let mut custody = ExtensionKnownCustody {
            fixed_session,
            ..ExtensionKnownCustody::default()
        };
        match &completion.operation {
            ExtensionOperation::WriteUploadChunk { stage, .. }
            | ExtensionOperation::RetainUploadForSelection { stage }
            | ExtensionOperation::AbandonUpload { stage } => {
                let mut known = stage.clone();
                known.cleanup_only = true;
                custody.upload_stage = Some(known);
            }
            _ => {}
        }
        let Some(details) = details else {
            return Ok(custody);
        };
        let acknowledged = details.get("acknowledgedResult");
        if let Some(marker_value) = details.get("hostUploadCustody") {
            if let Ok(marker) =
                serde_json::from_value::<HostUploadCustodyMarker>(marker_value.clone())
            {
                if marker_value["stage"].as_str() == Some(marker.stage.to_string().as_str()) {
                    match (&completion.operation, marker.state) {
                        (
                            ExtensionOperation::BeginUpload {
                                claim,
                                tab_id,
                                target_id,
                                files,
                            },
                            HostUploadCustodyState::Begun | HostUploadCustodyState::PartialBegin,
                        ) => {
                            if let Some(context) = completion.wire_context.as_ref() {
                                custody.upload_stage = Some(ExtensionUploadStage {
                                    binding: self.inner.binding,
                                    context: context.clone(),
                                    id: marker.stage,
                                    tab_id: *tab_id,
                                    target_id: target_id.clone(),
                                    claim: claim.clone(),
                                    files: files.clone(),
                                    completion_id: completion.id,
                                    cleanup_only: true,
                                });
                            }
                        }
                        (
                            ExtensionOperation::RetainUploadForSelection { stage },
                            HostUploadCustodyState::Retained,
                        ) if marker.stage == stage.id => {
                            let mut known = stage.clone();
                            known.cleanup_only = true;
                            custody.upload_retained_backing = Some(known.clone());
                            custody.upload_stage = Some(known);
                        }
                        (
                            ExtensionOperation::AbandonUpload { stage },
                            HostUploadCustodyState::Abandoned,
                        ) if marker.stage == stage.id => {
                            custody.upload_abandoned = Some(ExtensionUploadAbandonAck {
                                stage_id: stage.id,
                                completion_id: completion.id,
                            });
                        }
                        // The issued write already contributes its cleanup-only
                        // stage above. No extra permission follows a written fact.
                        (
                            ExtensionOperation::WriteUploadChunk { stage, .. },
                            HostUploadCustodyState::ChunkWritten,
                        ) if marker.stage == stage.id => {}
                        _ => {}
                    }
                }
            }
        }
        match &completion.operation {
            ExtensionOperation::BeginUpload { .. } => {
                if let Some(actual) = details.get("uploadStage").or(acknowledged) {
                    if let Some(context) = completion.wire_context.as_ref() {
                        // An invalid optional subproof never erases the raw Unknown
                        // cause, its address metadata, or independent valid custody.
                        if let Ok(mut stage) = self.upload_stage_from_result(
                            actual,
                            &completion.operation,
                            context,
                            completion.id,
                        ) {
                            stage.cleanup_only = true;
                            custody.upload_stage = Some(stage);
                        }
                    }
                }
            }
            ExtensionOperation::RetainUploadForSelection { stage } => {
                custody.upload_retained = acknowledged
                    .and_then(|actual| upload_retained(actual, stage, completion.id).ok());
            }
            ExtensionOperation::AbandonUpload { stage } => {
                if let Some(proof) = acknowledged
                    .and_then(|actual| upload_abandon_ack(actual, stage, completion.id).ok())
                {
                    custody.upload_abandoned = Some(proof);
                }
            }
            _ => {}
        }
        match &completion.operation {
            ExtensionOperation::SetSessionHeaders { .. }
            | ExtensionOperation::ClearSessionHeaders => {
                if let Some(result) = acknowledged {
                    let context = completion
                        .wire_context
                        .as_ref()
                        .ok_or_else(|| protocol("unknown session header receipt lost metadata"))?;
                    custody.session_headers = Some(session_header_proof(
                        ControlReply {
                            id: completion.id,
                            outcome: ExtensionOperationOutcome::Result(result.clone()),
                        },
                        context,
                        &self.identity().generation,
                        matches!(
                            &completion.operation,
                            ExtensionOperation::SetSessionHeaders { has_headers: true }
                        ),
                    )?);
                }
            }
            ExtensionOperation::MoveMousePresentation {
                x,
                y,
                wait_for_arrival,
                ..
            } => {
                if acknowledged.is_some() {
                    custody.cursor_presentation = Some(ExtensionCursorPresentationAck {
                        requested_x: *x,
                        requested_y: *y,
                        wait_for_arrival_requested: *wait_for_arrival,
                        completion_id: completion.id,
                    });
                }
            }
            ExtensionOperation::FinishTurn { .. } => {
                if acknowledged.is_some() {
                    let context = completion
                        .wire_context
                        .as_ref()
                        .ok_or_else(|| protocol("unknown finish receipt lost wire context"))?;
                    custody.turn_finished = Some(ExtensionTurnFinishAck {
                        host_session_id: context.host_session_id().to_owned(),
                        host_turn_id: context.host_turn_id().to_owned(),
                        completion_id: completion.id,
                    });
                }
            }
            ExtensionOperation::Attach { tab_id } => {
                if let Some(value) = details.get("custody").or(acknowledged) {
                    custody.claim =
                        Some(self.claim_from_result(value, *tab_id, completion.id, true)?);
                }
            }
            ExtensionOperation::PrepareClaim { .. } => {
                if let Some(result) = acknowledged {
                    let context = completion.wire_context.as_ref().ok_or_else(|| {
                        protocol("unknown preparation receipt lost captured wire context")
                    })?;
                    custody.preparation = Some(self.preparation_from_result(
                        result,
                        &completion.operation,
                        context,
                        completion.id,
                        true,
                    )?);
                }
            }
            ExtensionOperation::CreateTab { .. }
            | ExtensionOperation::CreatePopupTab { .. }
            | ExtensionOperation::CreateSessionPopupTab { .. } => {
                if let Some(value) = acknowledged {
                    custody.created = Some(self.created_from_result(value, completion.id, true)?);
                } else if let Some(token) = details
                    .get("creation")
                    .and_then(Value::as_str)
                    .filter(|token| !token.is_empty())
                {
                    custody.creation = Some(ExtensionCreationReceipt {
                        binding: self.inner.binding,
                        generation: self.identity().generation.clone(),
                        token: token.to_owned(),
                        tab_id: None,
                        cleanup_only: true,
                    });
                }
            }
            ExtensionOperation::Detach { .. }
            | ExtensionOperation::CloseTab { .. }
            | ExtensionOperation::StopCreatedTab { .. } => {
                if let Some(result) = acknowledged.or_else(|| details.get("physicalProof")) {
                    // A rejected optional subproof grants no cleanup capability.
                    // Preserve the outer Unknown and its exact raw details so the
                    // Host can retain custody without losing the actual cause.
                    custody.cleanup = cleanup_proof_for_operation(
                        ControlReply {
                            id: completion.id,
                            outcome: ExtensionOperationOutcome::Result(result.clone()),
                        },
                        &completion.operation,
                    )
                    .ok();
                }
            }
            ExtensionOperation::SetScopedHeaders { claim }
            | ExtensionOperation::ClearScopedHeaders { claim } => {
                if let Some(result) = acknowledged {
                    custody.headers = Some(header_proof(
                        ControlReply {
                            id: completion.id,
                            outcome: ExtensionOperationOutcome::Result(result.clone()),
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
            custody.group = Some(ExtensionManagedGroupReceipt {
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
    ) -> Result<Vec<ExtensionOperationCompletion>, ExtensionProviderError> {
        let (reply, result) = oneshot::channel();
        self.inner
            .commands
            .send(ClientCommand::Pending { reply })
            .await
            .map_err(|_| unknown("pendingCompletions", "runtime actor ended"))?;
        result
            .await
            .map_err(|_| unknown("pendingCompletions", "runtime actor ended"))?
    }
    pub async fn acknowledge_completion(&self, id: u64) -> Result<(), ExtensionProviderError> {
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
        self.inner.retained_payload_budget.close();
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
    context: &ExtensionWireContext,
    generation: &str,
    expected_active: bool,
) -> Result<ExtensionSessionHeaderProof, ExtensionProviderError> {
    let mut proof: ExtensionSessionHeaderProof =
        decode(reply.outcome.into_result("sessionHeaders")?)?;
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FixedPreparationFields {
    tab: ExtensionTabInfo,
    session_only: bool,
    preparation: FixedPreparationResult,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FixedPreparationResult {
    scope_id: String,
    foreign_installed: bool,
    popup_installed: bool,
    headers: ExtensionHeaderProof,
    ui: ExtensionFixedUiAck,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FixedUiResult {
    tab_id: u64,
    scope_id: String,
    ui: ExtensionFixedUiAck,
}
fn fixed_ui_proof(
    result: &Value,
    receipt: &ExtensionFixedSessionReceipt,
    completion_id: u64,
) -> Result<ExtensionFixedUiProof, ExtensionProviderError> {
    let fields: FixedUiResult = decode(result.clone())?;
    if fields.tab_id != receipt.tab_id || fields.scope_id != receipt.scope_id {
        return Err(protocol(
            "fixed UI acknowledgement changed its issued logical scope",
        ));
    }
    Ok(ExtensionFixedUiProof {
        ui: fields.ui,
        completion_id,
    })
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FixedCleanupResult {
    tab_id: u64,
    scope_id: String,
    cleanup_confirmed: bool,
}
fn fixed_cleanup_proof(
    result: &Value,
    receipt: &ExtensionFixedSessionReceipt,
    completion_id: u64,
) -> Result<ExtensionFixedSessionCleanupProof, ExtensionProviderError> {
    let fields: FixedCleanupResult = decode(result.clone())?;
    if fields.tab_id != receipt.tab_id || fields.scope_id != receipt.scope_id {
        return Err(protocol(
            "logical preparation cleanup changed its issued scope",
        ));
    }
    if !fields.cleanup_confirmed {
        return Err(unknown(
            "clearSessionPreparation",
            "logical preparation cleanup is not confirmed",
        ));
    }
    Ok(ExtensionFixedSessionCleanupProof {
        scope_id: receipt.scope_id.clone(),
        tab_id: receipt.tab_id,
        completion_id,
    })
}

fn session_prepared_tab(
    result: &Value,
    tab_id: u64,
    completion_id: u64,
) -> Result<ExtensionSessionPreparedTab, ExtensionProviderError> {
    require_session_tab_ack(result)?;
    let tab: ExtensionTabInfo = decode(
        result
            .get("tab")
            .cloned()
            .ok_or_else(|| protocol("prepared tab metadata missing"))?,
    )?;
    if tab.id != tab_id {
        return Err(protocol("prepared completion changed tab identity"));
    }
    Ok(ExtensionSessionPreparedTab { tab, completion_id })
}

fn require_session_tab_ack(result: &Value) -> Result<(), ExtensionProviderError> {
    if result.get("sessionOnly").and_then(Value::as_bool) != Some(true) {
        return Err(protocol(
            "session-only result lacks its exact selector acknowledgement",
        ));
    }
    Ok(())
}

fn required_nullable_bool<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<bool>, D::Error> {
    Option::<bool>::deserialize(deserializer)
}
fn decode<T: for<'de> Deserialize<'de>>(value: Value) -> Result<T, ExtensionProviderError> {
    serde_json::from_value(value).map_err(|error| protocol(&error.to_string()))
}
fn nonempty(value: &Value, field: &str) -> Result<String, ExtensionProviderError> {
    value[field]
        .as_str()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| protocol(&format!("result lacks {field}")))
}
fn protocol(message: &str) -> ExtensionProviderError {
    ExtensionProviderError::Protocol(message.to_owned())
}
fn refused(kind: &str, message: &str) -> ExtensionProviderError {
    ExtensionProviderError::Refused {
        kind: kind.to_owned(),
        message: message.to_owned(),
        details: None,
    }
}
fn unknown(operation: &str, reason: &str) -> ExtensionProviderError {
    ExtensionProviderError::OutcomeUnknown {
        operation: operation.to_owned(),
        reason: reason.to_owned(),
        details: None,
    }
}
struct ControlReply {
    id: u64,
    outcome: ExtensionOperationOutcome,
}
// Every public proof constructor is associated with its issued operation.
// Missing aliases remain legal for the source-backed Chatgpt ACK grammar;
// explicit contradictory aliases never become a known physical cleanup fact.
fn cleanup_proof_for_operation(
    reply: ControlReply,
    operation: &ExtensionOperation,
) -> Result<CleanupProof, ExtensionProviderError> {
    let result = reply.outcome.into_result(operation.method())?;
    let matches_text = |key: &str, expected: &str| {
        result
            .get(key)
            .is_none_or(|actual| actual.as_str() == Some(expected))
    };
    let expected_absence_tab = match operation {
        ExtensionOperation::Detach {
            claim,
            tab_id,
            target_id,
        }
        | ExtensionOperation::CloseTab {
            claim,
            tab_id,
            target_id,
        } => {
            if !matches_text("claim", claim)
                || !matches_text("targetId", target_id)
                || result
                    .get("tabId")
                    .is_some_and(|actual| actual.as_u64() != Some(*tab_id))
            {
                return Err(protocol(
                    "cleanup proof contradicts its issued claim, tab or target identity",
                ));
            }
            None
        }
        ExtensionOperation::StopCreatedTab { creation, tab_id } => {
            if !matches_text("creation", creation)
                || tab_id.is_some_and(|expected| {
                    result
                        .get("tabId")
                        .is_some_and(|actual| actual.as_u64() != Some(expected))
                })
            {
                return Err(protocol(
                    "cleanup proof contradicts its issued Created identity",
                ));
            }
            *tab_id
        }
        _ => return Err(protocol("cleanup proof has no issued cleanup operation")),
    };
    let reply = ControlReply {
        id: reply.id,
        outcome: ExtensionOperationOutcome::Result(result),
    };
    if matches!(operation, ExtensionOperation::Detach { .. }) {
        detach_proof(reply)
    } else {
        close_proof(reply, expected_absence_tab)
    }
}

fn detach_proof(reply: ControlReply) -> Result<CleanupProof, ExtensionProviderError> {
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
) -> Result<CleanupProof, ExtensionProviderError> {
    let result = reply.outcome.into_result("closeTab")?;
    if result["closed"] != true {
        return Err(protocol("close success lacks exact acknowledgement"));
    }
    let (evidence, tab_absence) = match result["proof"].as_str() {
        Some("close_ack") => (CleanupEvidence::CloseAcknowledged, None),
        Some("tab_removed") => (CleanupEvidence::TabRemoved, None),
        Some("tab_absent") => {
            let tab_id = expected_absence_tab.ok_or_else(|| {
                protocol("tab absence requires the original issued Created identity")
            })?;
            if result["tabId"].as_u64() != Some(tab_id) {
                return Err(protocol(
                    "tab absence changed the original Created tab identity",
                ));
            }
            let extension_request_id = nonempty(&result, "observationRequestId")?;
            (
                CleanupEvidence::TabAbsenceObserved,
                Some(ExtensionTabAbsenceObservation {
                    tab_id,
                    extension_request_id,
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
) -> Result<ExtensionHeaderProof, ExtensionProviderError> {
    let mut result: ExtensionHeaderProof = decode(reply.outcome.into_result(operation)?)?;
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
        operation: ExtensionOperation,
        params: Value,
        context: Option<ExtensionHostOperation>,
        wire_context: Option<ExtensionWireContext>,
        reply: oneshot::Sender<ControlReply>,
    },
    OpenCdp {
        claim: String,
        reply: oneshot::Sender<Result<Arc<CdpConnection>, ExtensionProviderError>>,
    },
    Cdp {
        route: u64,
        command: ExtensionCdpCommand,
    },
    CloseCdp {
        route: u64,
    },
    Pending {
        reply: oneshot::Sender<Result<Vec<ExtensionOperationCompletion>, ExtensionProviderError>>,
    },
    Snapshot {
        reply: oneshot::Sender<Result<Vec<ExtensionPendingOperation>, ExtensionProviderError>>,
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
    operation: ExtensionOperation,
    context: Option<ExtensionHostOperation>,
    wire_context: Option<ExtensionWireContext>,
    reply: Option<oneshot::Sender<ControlReply>>,
    outcome: Option<ExtensionOperationOutcome>,
}
struct PendingOpen {
    claim: String,
    replies: Vec<oneshot::Sender<Result<Arc<CdpConnection>, ExtensionProviderError>>>,
}
struct RuntimeRoute {
    claim: String,
    inbound: mpsc::Sender<ExtensionCdpInbound>,
    connection: Arc<CdpConnection>,
    request_contexts: HashMap<u64, ExtensionCdpRequestMetadata>,
}

/// Exact immutable caller scope and intent, captured before serial IPC dispatch.
/// Neither disposition nor receipt state is accepted from extension/Chrome JSON.
struct ExtensionCdpRequestMetadata {
    claim: String,
    wire_context: Option<ExtensionWireContext>,
    reply_disposition: ReplyDisposition,
    write_phase: Option<ExtensionCdpWritePhase>,
    effect: ExtensionCdpEffectCustody,
    atomic_terminal: ExtensionCdpAtomicTerminal,
}
impl ExtensionCdpRequestMetadata {
    fn failure_disposition(&self) -> CdpFailureDisposition {
        match self.effect {
            ExtensionCdpEffectCustody::Clear => CdpFailureDisposition::ReplyFailure,
            ExtensionCdpEffectCustody::NeedsReceipt | ExtensionCdpEffectCustody::Retained => {
                CdpFailureDisposition::ExtensionEffectUnknown
            }
        }
    }
}
/// Delivery bookkeeping belongs to the existing request metadata. A caller
/// terminal is separate from actual extension invocation/drain settlement.
enum ExtensionCdpAtomicTerminal {
    None,
    Undelivered(String),
    // An actual already-emitted reply crossed local route cancellation. Keep
    // its payload charged to this exact old request until Host can retain it.
    UnretainedLate(ExtensionCdpCompletionOutcome),
    LateRetained,
    Delivered,
    OrphanRetained,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum ExtensionCdpEffectCustody {
    Clear,
    NeedsReceipt,
    Retained,
}

#[derive(Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "camelCase")]
enum ControlEvent {
    SessionPopupRequested(SessionPopupFields),
    SessionPreparationCleanup(SessionCleanupFields),
    PopupRequested(PopupRequestFields),
    CdpMessage {
        route: u64,
        claim: String,
        event: ExtensionCdpCompletionOutcome,
        #[serde(default, rename = "wireContext")]
        wire_context: Option<ExtensionWireContext>,
    },
    CdpRouteClosed {
        route: u64,
        claim: String,
        reason: String,
    },
    CdpUnconfirmed {
        claim: String,
        route: u64,
        id: u64,
        #[serde(rename = "writePhase")]
        write_phase: ExtensionCdpWritePhase,
        reason: String,
        #[serde(default)]
        event: Option<ExtensionCdpCompletionOutcome>,
        #[serde(default, rename = "wireContext")]
        wire_context: Option<ExtensionWireContext>,
    },
    ClaimCdpProgress {
        claim: String,
    },
    Reply {
        id: u64,
        outcome: ExtensionOperationOutcome,
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
        event: ExtensionCdpCompletionOutcome,
        #[serde(default, rename = "wireContext")]
        wire_context: Option<ExtensionWireContext>,
    },
    EffectsCleanup {
        claim: String,
        effect: String,
        #[serde(rename = "cleanupConfirmed")]
        cleanup_confirmed: bool,
        error: Option<String>,
        #[serde(default, rename = "wireContext")]
        wire_context: Option<ExtensionWireContext>,
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
        error: ExtensionMetadataError,
    },
    DownloadChanged {
        download: ExtensionDownloadMetadata,
    },
}
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "camelCase")]
pub enum ExtensionCdpCompletionOutcome {
    ChromeMessage(Value),
    ChromeJson(String),
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
    events: broadcast::Sender<ExtensionProviderEvent>,
) {
    let identity = match owner.upgrade() {
        Some(owner) => owner.identity.clone(),
        None => return,
    };
    let event_payload_budget = match owner.upgrade() {
        Some(owner) => owner.retained_payload_budget.clone(),
        None => return,
    };
    let (mut read, write) = tokio::io::split(stream);
    let (reader_events, mut extension) = mpsc::channel(ROUTE_QUEUE);
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
    let mut retired_contexts = HashMap::<(u64, u64), ExtensionCdpRequestMetadata>::new();
    let mut next_id = 0u64;
    loop {
        if owner.upgrade().is_none() {
            break;
        }
        let action = tokio::select! {
            message=extension.recv(),if writer.is_some()=> {
                match message {
                    Some(Ok(value))=>Some((false,value)),
                    Some(Err(reason))=>{disconnect(&reason,&owner,&events,&mut pending,&mut opening,RouteReceipts{routes:&mut routes,retired_contexts:&mut retired_contexts},&mut next_id);writer=None;reader.abort();None},
                    None=>{disconnect("IPC reader ended",&owner,&events,&mut pending,&mut opening,RouteReceipts{routes:&mut routes,retired_contexts:&mut retired_contexts},&mut next_id);writer=None;reader.abort();None},
                }
            }
            command=commands.recv()=>{
                let Some(command)=command else {break;};
                match command {
                    ClientCommand::Pending{reply}=>{
                        let flushed=flush_deferred_effects(RouteReceipts{routes:&mut routes,retired_contexts:&mut retired_contexts},&mut pending,&events,&mut next_id);
                        let completed=pending.iter().filter_map(|(id,entry)|entry.outcome.as_ref().map(|outcome|ExtensionOperationCompletion{id:*id,host_operation:entry.context.clone(),wire_context:entry.wire_context.clone(),provider:identity.clone(),operation:entry.operation.clone(),outcome:outcome.clone()})).collect::<Vec<_>>();
                        // Existing receipts remain readable so Host can fold/ack
                        // them and free capacity for a deferred Unknown fact.
                        let _=reply.send(if completed.is_empty(){flushed.map(|()|completed)}else{Ok(completed)});None
                    },
                    ClientCommand::Snapshot{reply}=>{
                        let snapshot=flush_deferred_effects(RouteReceipts{routes:&mut routes,retired_contexts:&mut retired_contexts},&mut pending,&events,&mut next_id).map(|()|pending.iter().map(|(id,entry)|ExtensionPendingOperation{id:*id,host_operation:entry.context.clone(),wire_context:entry.wire_context.clone(),provider:identity.clone(),operation:entry.operation.clone(),outcome:entry.outcome.clone()}).collect());
                        let _=reply.send(snapshot);None
                    },
                    ClientCommand::Acknowledge{id}=>{if pending.get(&id).is_some_and(|entry|entry.outcome.is_some()){pending.remove(&id);}let _=flush_deferred_effects(RouteReceipts{routes:&mut routes,retired_contexts:&mut retired_contexts},&mut pending,&events,&mut next_id);None},
                    ClientCommand::OwnerDropped=>{break;},
                    ClientCommand::Close{reply}=>{disconnect("logical owner explicitly closed its IPC transport",&owner,&events,&mut pending,&mut opening,RouteReceipts{routes:&mut routes,retired_contexts:&mut retired_contexts},&mut next_id);writer=None;reader.abort();let _=reply.send(());None},
                    ClientCommand::Control{operation,params,context,wire_context,reply}=>{
                        if reply.is_closed(){None}
                        else if !owner_admitting(&owner){let _=reply.send(ControlReply{id:0,outcome:ExtensionOperationOutcome::NotDispatched{kind:"owner_closed".into(),message:"logical owner is closing; control was not dispatched".into(),details:None}});None}
                        else if writer.is_none(){let _=reply.send(ControlReply{id:0,outcome:ExtensionOperationOutcome::Unknown{reason:"owner IPC is closed".into(),details:None}});None}
                        else if matches!(&operation,ExtensionOperation::RetireClaim{claim,..} if claim_retirement_has_debt(claim,&routes,&retired_contexts,&pending)){
                            let _=reply.send(ControlReply{id:0,outcome:ExtensionOperationOutcome::NotDispatched{kind:"retirement_unsettled".into(),message:"claim has deferred or unacknowledged facts before retirement".into(),details:None}});None
                        }
                        else if pending.len()+opening.len()>=operation.pending_budget(){let _=reply.send(ControlReply{id:0,outcome:ExtensionOperationOutcome::NotDispatched{kind:"request_budget".into(),message:"pending receipts must be applied and acknowledged before more requests".into(),details:None}});None}
                        else if let Some(id)=next_id.checked_add(1){next_id=id;let method=operation.method();pending.insert(id,PendingControl{operation,context,wire_context:wire_context.clone(),reply:Some(reply),outcome:None});Some((true,with_wire_context(json!({"kind":"control","request":merge_request(method,id,params)}),wire_context.as_ref())))}
                        else{let _=reply.send(ControlReply{id:0,outcome:ExtensionOperationOutcome::NotDispatched{kind:"request_budget".into(),message:"local request IDs exhausted".into(),details:None}});None}
                    }
                    ClientCommand::OpenCdp{claim,reply}=>{
                        for entry in opening.values_mut(){entry.replies.retain(|reply|!reply.is_closed());}
                        let waiters=opening.values().map(|entry|entry.replies.len()).sum::<usize>();
                        if reply.is_closed(){None}
                        else if !owner_admitting(&owner){let _=reply.send(Err(refused("owner_closed","logical owner is closing; route was not admitted")));None}
                        else if let Some(route)=routes.values().find(|route|route.claim==claim&&!route.connection.is_closed()){let _=reply.send(Ok(route.connection.clone()));None}
                        else if waiters+pending.len()>=REQUEST_BUDGET{let _=reply.send(Err(refused("request_budget","extension open-route waiter budget exhausted")));None}
                        else if let Some(entry)=opening.values_mut().find(|entry|entry.claim==claim){entry.replies.push(reply);None}
                        else if writer.is_none(){let _=reply.send(Err(unknown("openCdp","owner IPC is closed")));None}
                        else if pending.len()+opening.len()>=REQUEST_BUDGET{let _=reply.send(Err(refused("request_budget","extension pending-operation budget exhausted")));None}
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
                                    if let(Some(state),Some(id))=(routes.get(&route),message["id"].as_u64()){let _=state.inbound.try_send(ExtensionCdpInbound::LocalRejected{id,code:"owner_closed".into(),message:"logical owner is closing; command was not dispatched".into()});}
                                    None
                                }else if pending.len()>=REQUEST_BUDGET{
                                    if let(Some(state),Some(id))=(routes.get(&route),message["id"].as_u64()){let _=state.inbound.try_send(ExtensionCdpInbound::LocalRejected{id,code:"request_budget".into(),message:"Host must apply and acknowledge pending receipts before dispatch".into()});}
                                    None
                                }else{
                                    if let Some(id)=message["id"].as_u64(){
                                        let count=retired_contexts.len()+routes.values().map(|state|state.request_contexts.len()).sum::<usize>();
                                        if count>=MAX_PENDING_EXTENSION_CONTEXTS{if let Some(state)=routes.get(&route){let _=state.inbound.try_send(ExtensionCdpInbound::LocalRejected{id,code:"request_budget".into(),message:"pending extension metadata budget exhausted".into()});}return None;}
                                        if let Some(state)=routes.get_mut(&route){state.request_contexts.insert(id,ExtensionCdpRequestMetadata{claim:state.claim.clone(),wire_context:dispatch.wire_context.clone(),reply_disposition:dispatch.reply_disposition,write_phase:None,effect:ExtensionCdpEffectCustody::Clear,atomic_terminal:ExtensionCdpAtomicTerminal::None});}
                                    }
                                    Some((true,with_wire_context(json!({"kind":"cdp","route":route,"message":message}),dispatch.wire_context.as_ref())))
                                }
                            })
                        }else{None}
                    },
                    ClientCommand::CloseCdp{route}=>{
                        if let Some(mut state)=routes.remove(&route){let retained=mark_route_unconfirmed(&mut state,&mut pending,&events,&mut next_id);retire_contexts(route,&mut state,&mut retired_contexts);if retained.is_err(){if let Some(owner)=owner.upgrade(){owner.alive.store(false,Ordering::SeqCst);owner.retained_payload_budget.close();}}let _=state.inbound.try_send(ExtensionCdpInbound::TransportFailure("local CDP route ended; no physical cleanup proof".into()));let _=events.send(ExtensionProviderEvent::RouteUnavailable{claim:state.claim,reason:"local CDP route ended".into()});}
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
                fence_unsent(&frame, &mut pending, &mut opening, &mut routes, &events);
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
                        "extension IPC write deadline expired; dispatched effects are unknown"
                            .into(),
                    ),
                };
                if let Some(reason) = failure {
                    disconnect(
                        &reason,
                        &owner,
                        &events,
                        &mut pending,
                        &mut opening,
                        RouteReceipts {
                            routes: &mut routes,
                            retired_contexts: &mut retired_contexts,
                        },
                        &mut next_id,
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
            ProviderEventContext {
                sender: &sender,
                events: &events,
                payload_budget: &event_payload_budget,
            },
            &mut next_id,
        );
        if let Err(error) = applied {
            disconnect(
                &error.to_string(),
                &owner,
                &events,
                &mut pending,
                &mut opening,
                RouteReceipts {
                    routes: &mut routes,
                    retired_contexts: &mut retired_contexts,
                },
                &mut next_id,
            );
            writer = None;
            reader.abort();
        }
    }
    disconnect(
        "extension provider owner was dropped",
        &owner,
        &events,
        &mut pending,
        &mut opening,
        RouteReceipts {
            routes: &mut routes,
            retired_contexts: &mut retired_contexts,
        },
        &mut next_id,
    );
    reader.abort();
}

fn retire_contexts(
    route: u64,
    state: &mut RuntimeRoute,
    retired: &mut HashMap<(u64, u64), ExtensionCdpRequestMetadata>,
) {
    for (id, context) in state.request_contexts.drain() {
        retired.insert((route, id), context);
    }
}

/// Retention is independent of extension-RPC completion and physical detach. A
/// known complete write is the sole case in which trusted Observation intent
/// can mute an input-effect Unknown. Extension JSON cannot designate Observation.
fn mark_request_unconfirmed(
    metadata: &mut ExtensionCdpRequestMetadata,
    pending: &mut HashMap<u64, PendingControl>,
    events: &broadcast::Sender<ExtensionProviderEvent>,
    next_id: &mut u64,
) -> Result<(), ExtensionProviderError> {
    if metadata.effect == ExtensionCdpEffectCustody::Clear
        && (metadata.reply_disposition == ReplyDisposition::Required
            || metadata.write_phase != Some(ExtensionCdpWritePhase::Written))
    {
        metadata.effect = ExtensionCdpEffectCustody::NeedsReceipt;
    }
    retain_deferred_effect(metadata, pending, events, next_id)
}
fn retain_deferred_effect(
    metadata: &mut ExtensionCdpRequestMetadata,
    pending: &mut HashMap<u64, PendingControl>,
    events: &broadcast::Sender<ExtensionProviderEvent>,
    next_id: &mut u64,
) -> Result<(), ExtensionProviderError> {
    if metadata.effect != ExtensionCdpEffectCustody::NeedsReceipt {
        return Ok(());
    }
    let error = "extension CDP operation lacks a confirmed Chrome terminal result".to_owned();
    retain_event_receipt(
        ExtensionOperation::EffectsCleanup {
            claim: metadata.claim.clone(),
            effect: "extension_cdp_effect".into(),
            cleanup_confirmed: false,
            error: Some(error.clone()),
        },
        pending,
        events,
        next_id,
    )?;
    if let Some(receipt) = pending.get_mut(next_id) {
        receipt.wire_context = metadata.wire_context.clone();
    }
    metadata.effect = ExtensionCdpEffectCustody::Retained;
    let _ = events.send(ExtensionProviderEvent::EffectsCleanup {
        claim: metadata.claim.clone(),
        effect: "extension_cdp_effect".into(),
        cleanup_confirmed: false,
        error: Some(error),
        wire_context: metadata.wire_context.clone(),
    });
    Ok(())
}
fn mark_route_unconfirmed(
    route: &mut RuntimeRoute,
    pending: &mut HashMap<u64, PendingControl>,
    events: &broadcast::Sender<ExtensionProviderEvent>,
    next_id: &mut u64,
) -> Result<(), ExtensionProviderError> {
    let mut result = Ok(());
    // Mark every request even when receipt capacity is exhausted. Deferred
    // facts stay in the existing exact request metadata until Host frees space.
    for metadata in route.request_contexts.values_mut() {
        if let Err(error) = mark_request_unconfirmed(metadata, pending, events, next_id) {
            result = Err(error);
        }
    }
    result
}
fn retain_deferred_atomic_terminal(
    metadata: &mut ExtensionCdpRequestMetadata,
    route: u64,
    id: u64,
    pending: &mut HashMap<u64, PendingControl>,
    events: &broadcast::Sender<ExtensionProviderEvent>,
    next_id: &mut u64,
) -> Result<(), ExtensionProviderError> {
    let (event, actual_late) = match &metadata.atomic_terminal {
        ExtensionCdpAtomicTerminal::Undelivered(reason) => (
            ExtensionCdpCompletionOutcome::TransportFailure(reason.clone()),
            false,
        ),
        ExtensionCdpAtomicTerminal::UnretainedLate(event) => (event.clone(), true),
        _ => return Ok(()),
    };
    // Preserve the actual terminal payload in the existing charged orphan
    // receipt. Capacity exhaustion leaves it in metadata for Host ACK/flush.
    retain_event_receipt(
        ExtensionOperation::OrphanCdpCompletion {
            route,
            claim: metadata.claim.clone(),
            id,
            event: event.clone(),
        },
        pending,
        events,
        next_id,
    )?;
    if let Some(receipt) = pending.get_mut(next_id) {
        receipt.wire_context = metadata.wire_context.clone();
    }
    metadata.atomic_terminal = if actual_late {
        ExtensionCdpAtomicTerminal::LateRetained
    } else {
        ExtensionCdpAtomicTerminal::OrphanRetained
    };
    let _ = events.send(ExtensionProviderEvent::OrphanCdpCompletion {
        route,
        claim: metadata.claim.clone(),
        id,
        outcome: event,
        wire_context: metadata.wire_context.clone(),
    });
    Ok(())
}
fn retain_observed_orphan(
    metadata: &mut ExtensionCdpRequestMetadata,
    route: u64,
    id: u64,
    event: ExtensionCdpCompletionOutcome,
    pending: &mut HashMap<u64, PendingControl>,
    events: &broadcast::Sender<ExtensionProviderEvent>,
    next_id: &mut u64,
) -> Result<(), ExtensionProviderError> {
    let unconfirmed = matches!(event, ExtensionCdpCompletionOutcome::TransportFailure(_));
    // Capture the actual payload BEFORE bounded retention can fail. A known
    // Chrome result or known unsent refusal cannot invent an input Unknown.
    metadata.atomic_terminal = ExtensionCdpAtomicTerminal::UnretainedLate(event);
    if unconfirmed {
        mark_request_unconfirmed(metadata, pending, events, next_id)?;
    } else {
        retain_deferred_effect(metadata, pending, events, next_id)?;
    }
    retain_deferred_atomic_terminal(metadata, route, id, pending, events, next_id)
}

fn flush_request_receipts(
    metadata: &mut ExtensionCdpRequestMetadata,
    route: u64,
    id: u64,
    pending: &mut HashMap<u64, PendingControl>,
    events: &broadcast::Sender<ExtensionProviderEvent>,
    next_id: &mut u64,
) -> Result<(), ExtensionProviderError> {
    retain_deferred_effect(metadata, pending, events, next_id)?;
    retain_deferred_atomic_terminal(metadata, route, id, pending, events, next_id)
}
fn flush_deferred_effects(
    receipts: RouteReceipts<'_>,
    pending: &mut HashMap<u64, PendingControl>,
    events: &broadcast::Sender<ExtensionProviderEvent>,
    next_id: &mut u64,
) -> Result<(), ExtensionProviderError> {
    let mut result = Ok(());
    for (route, state) in receipts.routes.iter_mut() {
        for (id, metadata) in state.request_contexts.iter_mut() {
            if let Err(error) =
                flush_request_receipts(metadata, *route, *id, pending, events, next_id)
            {
                result = Err(error);
            }
        }
    }
    for ((route, id), metadata) in receipts.retired_contexts.iter_mut() {
        if let Err(error) = flush_request_receipts(metadata, *route, *id, pending, events, next_id)
        {
            result = Err(error);
        }
    }
    // An actual terminal retained successfully no longer needs request
    // metadata. Synthetic caller failure alone never grants this pruning.
    receipts.retired_contexts.retain(|_, metadata| {
        !matches!(
            metadata.atomic_terminal,
            ExtensionCdpAtomicTerminal::LateRetained
        )
    });
    result
}
fn request_metadata_mut<'a>(
    route: u64,
    id: u64,
    routes: &'a mut HashMap<u64, RuntimeRoute>,
    retired: &'a mut HashMap<(u64, u64), ExtensionCdpRequestMetadata>,
) -> Option<&'a mut ExtensionCdpRequestMetadata> {
    routes
        .get_mut(&route)
        .and_then(|state| state.request_contexts.get_mut(&id))
        .or_else(|| retired.get_mut(&(route, id)))
}

fn with_wire_context(mut frame: Value, context: Option<&ExtensionWireContext>) -> Value {
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
    routes: &mut HashMap<u64, RuntimeRoute>,
    events: &broadcast::Sender<ExtensionProviderEvent>,
) {
    match frame["kind"].as_str() {
        Some("control") => {
            if let Some(id) = frame["request"]["id"].as_u64() {
                let _ = finish_control(
                    id,
                    ExtensionOperationOutcome::NotDispatched {
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
                if let Some(route) = routes.get_mut(&route) {
                    route.request_contexts.remove(&id);
                    let _ = route.inbound.try_send(ExtensionCdpInbound::LocalRejected {
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
    outcome: ExtensionOperationOutcome,
    pending: &mut HashMap<u64, PendingControl>,
    events: &broadcast::Sender<ExtensionProviderEvent>,
) -> Result<(), ExtensionProviderError> {
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
        let _ = events.send(ExtensionProviderEvent::CompletionReady { id });
    } else {
        pending.remove(&id);
        let _ = events.send(ExtensionProviderEvent::PendingOperationsChanged);
    }
    Ok(())
}
fn retain_event_receipt(
    operation: ExtensionOperation,
    pending: &mut HashMap<u64, PendingControl>,
    events: &broadcast::Sender<ExtensionProviderEvent>,
    next_id: &mut u64,
) -> Result<(), ExtensionProviderError> {
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
            outcome: Some(ExtensionOperationOutcome::Result(Value::Null)),
        },
    );
    let _ = events.send(ExtensionProviderEvent::CompletionReady { id });
    Ok(())
}
/// Live routes and their retired request contexts stay in the same actor.
struct RouteReceipts<'a> {
    routes: &'a mut HashMap<u64, RuntimeRoute>,
    retired_contexts: &'a mut HashMap<(u64, u64), ExtensionCdpRequestMetadata>,
}

fn claim_retirement_has_debt(
    claim: &str,
    routes: &HashMap<u64, RuntimeRoute>,
    retired: &HashMap<(u64, u64), ExtensionCdpRequestMetadata>,
    pending: &HashMap<u64, PendingControl>,
) -> bool {
    routes
        .values()
        .flat_map(|route| route.request_contexts.values())
        .chain(retired.values())
        .any(|metadata| {
            metadata.claim == claim
                && (metadata.effect == ExtensionCdpEffectCustody::NeedsReceipt
                    || matches!(
                        &metadata.atomic_terminal,
                        ExtensionCdpAtomicTerminal::Undelivered(_)
                            | ExtensionCdpAtomicTerminal::UnretainedLate(_)
                    ))
        })
        || pending
            .values()
            .any(|entry| unacknowledged_retirement_fact(&entry.operation, claim))
}

struct ProviderEventContext<'a> {
    sender: &'a mpsc::WeakSender<ClientCommand>,
    events: &'a broadcast::Sender<ExtensionProviderEvent>,
    payload_budget: &'a ByteBudget,
}

fn apply_server(
    frame: Value,
    pending: &mut HashMap<u64, PendingControl>,
    opening: &mut HashMap<u64, PendingOpen>,
    route_receipts: RouteReceipts<'_>,
    event_context: ProviderEventContext<'_>,
    next_id: &mut u64,
) -> Result<(), ExtensionProviderError> {
    let ProviderEventContext {
        sender,
        events,
        payload_budget,
    } = event_context;
    let RouteReceipts {
        routes,
        retired_contexts,
    } = route_receipts;
    match frame["kind"].as_str() {
        Some("controlEvent") => match decode::<ControlEvent>(frame["event"].clone())? {
            ControlEvent::SessionPopupRequested(fields) => {
                let charge = payload_budget.try_charge(&fields).map_err(|error| {
                    unknown(
                        "sessionPopupRequested",
                        &format!("logical popup metadata was not admitted: {error}"),
                    )
                })?;
                let context = fields.wire_context.clone();
                let request = ExtensionSessionPopupRequest(Arc::new(RetainedSessionPopupRequest {
                    fields,
                    _charge: charge,
                }));
                retain_event_receipt(
                    ExtensionOperation::SessionPopupRequested {
                        request: request.clone(),
                    },
                    pending,
                    events,
                    next_id,
                )?;
                if let Some(receipt) = pending.get_mut(next_id) {
                    receipt.wire_context = Some(context);
                }
                let _ = events.send(ExtensionProviderEvent::SessionPopupRequested { request });
            }
            ControlEvent::SessionPreparationCleanup(fields) => {
                let charge = payload_budget.try_charge(&fields).map_err(|error| {
                    unknown(
                        "sessionPreparationCleanup",
                        &format!("logical cleanup observation was not admitted: {error}"),
                    )
                })?;
                let context = fields.wire_context.clone();
                let observation =
                    ExtensionSessionCleanupObservation(Arc::new(RetainedSessionCleanup {
                        fields,
                        _charge: charge,
                    }));
                retain_event_receipt(
                    ExtensionOperation::SessionPreparationCleanup {
                        observation: observation.clone(),
                    },
                    pending,
                    events,
                    next_id,
                )?;
                if let Some(receipt) = pending.get_mut(next_id) {
                    receipt.wire_context = Some(context);
                }
                let _ =
                    events.send(ExtensionProviderEvent::SessionPreparationCleanup { observation });
            }
            ControlEvent::PopupRequested(fields) => {
                let charge = payload_budget.try_charge(&fields).map_err(|error| {
                    unknown(
                        "popupRequested",
                        &format!("popup metadata receipt was not admitted: {error}"),
                    )
                })?;
                let context = fields.wire_context.clone();
                let request = ExtensionPopupRequest(Arc::new(RetainedPopupRequest {
                    fields,
                    _charge: charge,
                }));
                retain_event_receipt(
                    ExtensionOperation::PopupRequested {
                        request: request.clone(),
                    },
                    pending,
                    events,
                    next_id,
                )?;
                if let Some(receipt) = pending.get_mut(next_id) {
                    receipt.wire_context = Some(context);
                }
                let _ = events.send(ExtensionProviderEvent::PopupRequested { request });
            }
            ControlEvent::CdpMessage {
                route,
                claim,
                event,
                wire_context,
            } => {
                // All observable broker frames share this control FIFO. The
                // legacy route handler remains the one CDP demultiplexer.
                let reply_id = match &event {
                    ExtensionCdpCompletionOutcome::ChromeMessage(value) => value["id"].as_u64(),
                    ExtensionCdpCompletionOutcome::ChromeJson(text) => {
                        super::cdp_ws::chrome_json_reply_id(text)
                    }
                    ExtensionCdpCompletionOutcome::LocalRejected { id, .. } => Some(*id),
                    ExtensionCdpCompletionOutcome::TransportFailure(_) => {
                        return Err(protocol(
                            "ordinary ordered CDP frame has an unconfirmed transport terminal",
                        ));
                    }
                };
                if let Some(id) = reply_id {
                    if let Some(metadata) = retired_contexts.get_mut(&(route, id)) {
                        if metadata.claim != claim || metadata.wire_context != wire_context {
                            return Err(protocol(
                                "late ordered CDP reply changed its exact request scope",
                            ));
                        }
                        // Known actual reply retains its exact classification;
                        // any prior Host Unknown remains independent.
                        retain_observed_orphan(
                            metadata, route, id, event, pending, events, next_id,
                        )?;
                        retired_contexts.remove(&(route, id));
                        return Ok(());
                    }
                    if let Some(metadata) = routes
                        .get(&route)
                        .and_then(|state| state.request_contexts.get(&id))
                    {
                        if metadata.claim != claim || metadata.wire_context != wire_context {
                            return Err(protocol(
                                "ordered CDP reply changed its exact request scope",
                            ));
                        }
                    }
                }
                if let Some(state) = routes.get(&route) {
                    if state.claim != claim {
                        return Err(protocol("ordered CDP frame names another route claim"));
                    }
                    // A raw event whose local consumer explicitly ended has
                    // no new recipient or physical ownership grant.
                    return apply_cdp_frame(
                        route,
                        event,
                        RouteReceipts {
                            routes,
                            retired_contexts,
                        },
                        pending,
                        sender,
                        events,
                        next_id,
                    );
                }
            }
            ControlEvent::CdpRouteClosed {
                route,
                claim,
                reason,
            } => {
                // The broker emits this marker on the SAME control FIFO only
                // after every pending request's phase and exact terminal. It
                // closes transport, never the retained physical claim.
                if routes.get(&route).is_some_and(|state| state.claim != claim) {
                    return Err(protocol("closed CDP route names another physical claim"));
                }
                if let Some(mut state) = routes.remove(&route) {
                    let retained = mark_route_unconfirmed(&mut state, pending, events, next_id);
                    retire_contexts(route, &mut state, retired_contexts);
                    retained?;
                    let _ = state
                        .inbound
                        .try_send(ExtensionCdpInbound::TransportFailure(reason.clone()));
                    let _ = events.send(ExtensionProviderEvent::RouteUnavailable { claim, reason });
                }
            }
            ControlEvent::CdpUnconfirmed {
                claim,
                route,
                id,
                write_phase,
                reason,
                event,
                wire_context,
            } => {
                // ONE control lane carries phase plus exact caller terminal.
                // A terminal cannot arrive through a racing raw route task.
                let terminal = match event {
                    Some(ExtensionCdpCompletionOutcome::TransportFailure(reason)) => Some(reason),
                    None => None,
                    Some(_) => {
                        return Err(protocol(
                            "unconfirmed extension terminal is not a transport failure",
                        ));
                    }
                };
                let Some(metadata) = request_metadata_mut(route, id, routes, retired_contexts)
                else {
                    // No local request means no trusted caller scope or intent.
                    return Ok(());
                };
                if metadata.claim != claim || metadata.wire_context != wire_context {
                    return Err(protocol(
                        "unconfirmed extension metadata changed its exact request scope",
                    ));
                }
                if metadata.write_phase != Some(ExtensionCdpWritePhase::Written) {
                    metadata.write_phase = Some(write_phase);
                }
                if let Some(terminal) = terminal {
                    if matches!(metadata.atomic_terminal, ExtensionCdpAtomicTerminal::None) {
                        metadata.atomic_terminal =
                            ExtensionCdpAtomicTerminal::Undelivered(terminal);
                    }
                }
                // Even a capacity failure leaves the captured cause and scope
                // intact. Disconnect then fails callers without erasing debt.
                mark_request_unconfirmed(metadata, pending, events, next_id)?;
                let deliver = matches!(
                    metadata.atomic_terminal,
                    ExtensionCdpAtomicTerminal::Undelivered(_)
                );
                if deliver {
                    if let Some(state) = routes.get_mut(&route) {
                        if let Some(mut metadata) = state.request_contexts.remove(&id) {
                            let reason = match &metadata.atomic_terminal {
                                ExtensionCdpAtomicTerminal::Undelivered(reason) => reason.clone(),
                                _ => {
                                    return Err(protocol(
                                        "extension caller terminal changed before delivery",
                                    ));
                                }
                            };
                            let disposition = metadata.failure_disposition();
                            let inbound = ExtensionCdpInbound::RequestFailure {
                                id,
                                reason,
                                disposition,
                            };
                            if state.inbound.try_send(inbound).is_ok() {
                                metadata.atomic_terminal = ExtensionCdpAtomicTerminal::Delivered;
                            } else {
                                // The intended recipient ended. Keep the actual
                                // terminal in the same owner's orphan sink.
                                let retained = retain_deferred_atomic_terminal(
                                    &mut metadata,
                                    route,
                                    id,
                                    pending,
                                    events,
                                    next_id,
                                );
                                retired_contexts.insert((route, id), metadata);
                                // A full/ended inbound queue fences the whole
                                // route. Preserve every neighbor before its
                                // sender is dropped or the demux closes.
                                let route_retained = if let Some(mut state) = routes.remove(&route)
                                {
                                    let result = mark_route_unconfirmed(
                                        &mut state, pending, events, next_id,
                                    );
                                    retire_contexts(route, &mut state, retired_contexts);
                                    let _=events.send(ExtensionProviderEvent::RouteUnavailable {claim:state.claim,reason:"CDP terminal queue exceeded its bound or consumer ended".into()});
                                    if let Some(sender) = sender.upgrade() {
                                        let _ = sender.try_send(ClientCommand::CloseCdp { route });
                                    }
                                    result
                                } else {
                                    Ok(())
                                };
                                retained?;
                                route_retained?;
                                return Ok(());
                            }
                            retired_contexts.insert((route, id), metadata);
                        }
                    } else if let Some(metadata) = retired_contexts.get_mut(&(route, id)) {
                        retain_deferred_atomic_terminal(
                            metadata, route, id, pending, events, next_id,
                        )?;
                    }
                }
                // Full extension cause lives in the terminal, while effect custody
                // uses a bounded local summary. No peer text changes intent.
                drop(reason);
            }
            ControlEvent::Reply { id, outcome } => {
                if let Some(entry) = pending.get(&id).filter(|entry| entry.outcome.is_none()) {
                    if let (
                        ExtensionOperation::RetireClaim { claim, .. },
                        ExtensionOperationOutcome::Result(result),
                    ) = (&entry.operation, &outcome)
                    {
                        if result["retired"] == true
                            && result["claim"].as_str() == Some(claim.as_str())
                        {
                            if claim_retirement_has_debt(claim, routes, retired_contexts, pending) {
                                // The broker may already have pruned local claim state.
                                // Keep every fact and report Unknown rather than pretend
                                // retirement completed across an unexpected new debt.
                                return finish_control(
                                    id,
                                    ExtensionOperationOutcome::Unknown {
                                        reason:
                                            "new claim facts arrived before retirement completed"
                                                .to_owned(),
                                        details: None,
                                    },
                                    pending,
                                    events,
                                );
                            }
                            for route in routes.values_mut() {
                                route
                                    .request_contexts
                                    .retain(|_, metadata| metadata.claim != *claim);
                            }
                            retired_contexts.retain(|_, metadata| metadata.claim != *claim);
                        }
                    }
                }
                finish_control(id, outcome, pending, events)?;
            }
            ControlEvent::ClaimCdpProgress { claim } => {
                let _ = events.send(ExtensionProviderEvent::ClaimCdpProgress { claim });
            }
            ControlEvent::ClaimUnavailable { claim, reason } => {
                let ids = routes
                    .iter()
                    .filter(|(_, route)| route.claim == claim)
                    .map(|(id, _)| *id)
                    .collect::<Vec<_>>();
                for id in ids {
                    if let Some(mut route) = routes.remove(&id) {
                        let retained = mark_route_unconfirmed(&mut route, pending, events, next_id);
                        retire_contexts(id, &mut route, retired_contexts);
                        retained?;
                        let _ = route
                            .inbound
                            .try_send(ExtensionCdpInbound::TransportFailure(reason.clone()));
                    }
                }
                let _ = events.send(ExtensionProviderEvent::ClaimUnavailable { claim, reason });
            }
            ControlEvent::DownloadChanged { download } => {
                let _ = events.send(ExtensionProviderEvent::DownloadChanged { download });
            }
            ControlEvent::GenerationClosed { reason } => {
                return Err(unknown("extensionGeneration", &reason));
            }
            ControlEvent::OrphanCdpCompletion {
                route,
                claim,
                id,
                event,
                wire_context,
            } => {
                if let Some(metadata) = request_metadata_mut(route, id, routes, retired_contexts) {
                    if metadata.claim != claim
                        || wire_context
                            .as_ref()
                            .is_some_and(|wire| Some(wire) != metadata.wire_context.as_ref())
                    {
                        return Err(protocol(
                            "orphan extension metadata changed its exact request scope",
                        ));
                    }
                    retain_observed_orphan(metadata, route, id, event, pending, events, next_id)?;
                    if let Some(state) = routes.get_mut(&route) {
                        state.request_contexts.remove(&id);
                    }
                    retired_contexts.remove(&(route, id));
                    return Ok(());
                }
                // No local request can borrow a newer ambient turn. Preserve
                // this bounded unmatched diagnostic without granting scope.
                let wire_context = None;
                retain_event_receipt(
                    ExtensionOperation::OrphanCdpCompletion {
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
                let _ = events.send(ExtensionProviderEvent::OrphanCdpCompletion {
                    route,
                    claim,
                    id,
                    outcome: event,
                    wire_context,
                });
                if let Some(state) = routes.get_mut(&route) {
                    state.request_contexts.remove(&id);
                }
                retired_contexts.remove(&(route, id));
            }
            ControlEvent::EffectsCleanup {
                claim,
                effect,
                cleanup_confirmed,
                error,
                wire_context,
            } => {
                retain_event_receipt(
                    ExtensionOperation::EffectsCleanup {
                        claim: claim.clone(),
                        effect: effect.clone(),
                        cleanup_confirmed,
                        error: error.clone(),
                    },
                    pending,
                    events,
                    next_id,
                )?;
                if let Some(receipt) = pending.get_mut(next_id) {
                    receipt.wire_context = wire_context.clone();
                }
                let _ = events.send(ExtensionProviderEvent::EffectsCleanup {
                    claim,
                    effect,
                    cleanup_confirmed,
                    error,
                    wire_context,
                });
            }
            ControlEvent::TabStateChanged {
                claim,
                tab_id,
                window_id,
                active,
            } => {
                let _ = events.send(ExtensionProviderEvent::TabStateChanged {
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
                let _ = events.send(ExtensionProviderEvent::TabStateUnknown {
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
            let connection = Arc::new(CdpConnection::from_extension_channels(
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
            let decoded = decode::<ExtensionCdpCompletionOutcome>(frame["event"].clone())?;
            apply_cdp_frame(
                route,
                decoded,
                RouteReceipts {
                    routes,
                    retired_contexts,
                },
                pending,
                sender,
                events,
                next_id,
            )?;
        }
        _ => return Err(protocol("unexpected extension IPC server frame")),
    }
    Ok(())
}
/// The existing raw-route demultiplexer shared by both wire envelopes.
fn apply_cdp_frame(
    route: u64,
    decoded: ExtensionCdpCompletionOutcome,
    receipts: RouteReceipts<'_>,
    pending: &mut HashMap<u64, PendingControl>,
    sender: &mpsc::WeakSender<ClientCommand>,
    events: &broadcast::Sender<ExtensionProviderEvent>,
    next_id: &mut u64,
) -> Result<(), ExtensionProviderError> {
    let RouteReceipts {
        routes,
        retired_contexts,
    } = receipts;
    let Some(state) = routes.get_mut(&route) else {
        return Ok(());
    };
    let reply_id = match &decoded {
        ExtensionCdpCompletionOutcome::ChromeMessage(value) => value["id"].as_u64(),
        ExtensionCdpCompletionOutcome::ChromeJson(text) => {
            super::cdp_ws::chrome_json_reply_id(text)
        }
        ExtensionCdpCompletionOutcome::LocalRejected { id, .. } => Some(*id),
        ExtensionCdpCompletionOutcome::TransportFailure(_) => None,
    };
    // Keep exact ownership until the local queue actually accepts the frame.
    // An explicit failed send is stronger than the existing no-consumed-ACK
    // limit and must retain the observed actual result for Host reconciliation.
    let completed = reply_id.and_then(|id| {
        state
            .request_contexts
            .remove(&id)
            .map(|metadata| (id, metadata))
    });
    let ended = matches!(decoded, ExtensionCdpCompletionOutcome::TransportFailure(_));
    if ended {
        mark_route_unconfirmed(state, pending, events, next_id)?;
    }
    let inbound = match decoded {
        ExtensionCdpCompletionOutcome::ChromeMessage(value) => {
            if let Some((_, metadata)) = &completed {
                ExtensionCdpInbound::ClassifiedChromeMessage {
                    message: value,
                    disposition: metadata.failure_disposition(),
                }
            } else {
                ExtensionCdpInbound::ChromeMessage(value)
            }
        }
        ExtensionCdpCompletionOutcome::ChromeJson(message_json) => {
            let disposition = completed
                .as_ref()
                .map_or(CdpFailureDisposition::ReplyFailure, |(_, metadata)| {
                    metadata.failure_disposition()
                });
            ExtensionCdpInbound::ChromeJson {
                message_json,
                disposition,
            }
        }
        ExtensionCdpCompletionOutcome::LocalRejected { id, code, message } => {
            ExtensionCdpInbound::LocalRejected { id, code, message }
        }
        ExtensionCdpCompletionOutcome::TransportFailure(reason) => {
            ExtensionCdpInbound::TransportFailure(reason)
        }
    };
    let sent = state.inbound.try_send(inbound);
    let queue_failed = sent.is_err();
    let mut actual_retained = Ok(());
    if let (Err(failed), Some((id, mut metadata))) = (sent, completed) {
        let actual = match failed.into_inner() {
            ExtensionCdpInbound::ChromeMessage(value)
            | ExtensionCdpInbound::ClassifiedChromeMessage { message: value, .. } => {
                ExtensionCdpCompletionOutcome::ChromeMessage(value)
            }
            ExtensionCdpInbound::ChromeJson { message_json, .. } => {
                ExtensionCdpCompletionOutcome::ChromeJson(message_json)
            }
            ExtensionCdpInbound::LocalRejected { id, code, message } => {
                ExtensionCdpCompletionOutcome::LocalRejected { id, code, message }
            }
            ExtensionCdpInbound::RequestFailure { reason, .. }
            | ExtensionCdpInbound::TransportFailure(reason) => {
                ExtensionCdpCompletionOutcome::TransportFailure(reason)
            }
        };
        actual_retained =
            retain_observed_orphan(&mut metadata, route, id, actual, pending, events, next_id);
        // Capture before returning any capacity failure; no payload or trusted
        // old context is lost when the receiver is already gone or full.
        if !matches!(
            metadata.atomic_terminal,
            ExtensionCdpAtomicTerminal::LateRetained
        ) {
            retired_contexts.insert((route, id), metadata);
        }
    }
    if ended || queue_failed {
        let claim = state.claim.clone();
        let route_retained = if let Some(mut state) = routes.remove(&route) {
            let retained = mark_route_unconfirmed(&mut state, pending, events, next_id);
            retire_contexts(route, &mut state, retired_contexts);
            retained
        } else {
            Ok(())
        };
        let _ = events.send(ExtensionProviderEvent::RouteUnavailable {
            claim,
            reason: if ended {
                "extension claim route ended"
            } else {
                "CDP event queue exceeded its bound or consumer ended"
            }
            .into(),
        });
        if let Some(sender) = sender.upgrade() {
            let _ = sender.try_send(ClientCommand::CloseCdp { route });
        }
        actual_retained?;
        route_retained?;
    }
    Ok(())
}

async fn pump_cdp(
    route: u64,
    mut commands: mpsc::Receiver<ExtensionCdpCommand>,
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
    events: &broadcast::Sender<ExtensionProviderEvent>,
    pending: &mut HashMap<u64, PendingControl>,
    opening: &mut HashMap<u64, PendingOpen>,
    receipts: RouteReceipts<'_>,
    next_id: &mut u64,
) {
    let RouteReceipts {
        routes,
        retired_contexts,
    } = receipts;
    if let Some(owner) = owner.upgrade() {
        owner.alive.store(false, Ordering::SeqCst);
        owner.retained_payload_budget.close();
    }
    // Preserve deferred Unknown facts even if bounded receipt storage is full.
    // Pending snapshots then fail closed while readable settled receipts permit
    // Host reconciliation to free space. No caller failure precedes custody.
    for route in routes.values_mut() {
        let _ = mark_route_unconfirmed(route, pending, events, next_id);
    }
    for metadata in retired_contexts.values_mut() {
        let _ = mark_request_unconfirmed(metadata, pending, events, next_id);
    }
    let ids = pending
        .iter()
        .filter(|(_, entry)| entry.outcome.is_none())
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();
    for id in ids {
        let _ = finish_control(
            id,
            ExtensionOperationOutcome::Unknown {
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
    for (id, mut route) in routes.drain() {
        retire_contexts(id, &mut route, retired_contexts);
        let _ = route
            .inbound
            .try_send(ExtensionCdpInbound::TransportFailure(reason.to_owned()));
    }
    let _ = events.send(ExtensionProviderEvent::GenerationClosed {
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
    fn fixture() -> (ExtensionBrowserProvider, tokio::net::UnixStream) {
        fixture_with_capabilities(maka_capabilities())
    }
    fn maka_capabilities() -> Value {
        json!({"metadata":true,"rawTabCdp":true,"attachmentPreparation":"metadata_only","userTabsOrder":"host","headerScope":"claim","createdPresentationOwner":"host","cursorPresentationOwner":"host","cursorHideOwner":"host","turnLifecycleOwner":"host","downloadNotifications":true})
    }
    fn chatgpt_capabilities() -> Value {
        json!({"metadata":true,"rawTabCdp":true,"attachmentPreparation":"full_preparation","userTabsOrder":"provider","headerScope":"session","createdPresentationOwner":"provider","cursorPresentationOwner":"provider","cursorHideOwner":"unavailable","turnLifecycleOwner":"provider","downloadNotifications":true})
    }
    #[cfg(unix)]
    fn fixture_with_capabilities(
        capabilities: Value,
    ) -> (ExtensionBrowserProvider, tokio::net::UnixStream) {
        fixture_with_capabilities_and_budget(capabilities, ByteBudget::new())
    }
    #[cfg(unix)]
    fn fixture_with_capabilities_and_budget(
        capabilities: Value,
        retained_payload_budget: ByteBudget,
    ) -> (ExtensionBrowserProvider, tokio::net::UnixStream) {
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        let (commands, incoming) = mpsc::channel(ACTOR_QUEUE);
        let (events, _) = broadcast::channel(EVENT_QUEUE);
        let inner = Arc::new(ProviderInner {
            identity: ExtensionEndpointIdentity {
                adapter: "org.apache.maka.browser_connector".into(),
                extension_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                instance_id: "fixture-instance".into(),
                generation: uuid::Uuid::new_v4().to_string(),
                capabilities,
                host_pid: std::process::id(),
            },
            binding: uuid::Uuid::new_v4(),
            commands: commands.clone(),
            retained_payload_budget,
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
            ExtensionBrowserProvider {
                inner,
                host_operation: None,
                wire_context: None,
                session_request_registration: None,
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
        provider: &ExtensionBrowserProvider,
        server: &mut tokio::net::UnixStream,
        tab_id: u64,
        token: &str,
    ) -> ExtensionPhysicalClaim {
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
    async fn wait_ready(provider: &ExtensionBrowserProvider) -> Vec<ExtensionOperationCompletion> {
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

    #[cfg(unix)]
    async fn open_fixture(
        provider: &ExtensionBrowserProvider,
        server: &mut tokio::net::UnixStream,
        claim: ExtensionPhysicalClaim,
        route: u64,
    ) -> Arc<CdpConnection> {
        let open = {
            let provider = provider.clone();
            tokio::spawn(async move { provider.open_cdp_channel(&claim).await })
        };
        let sent = request(server).await;
        local_ipc::write_json(
            server,
            &json!({"kind":"cdpOpened","id":sent["id"],"route":route}),
        )
        .await
        .unwrap();
        bounded(open).await.unwrap().unwrap()
    }
    #[cfg(unix)]
    async fn unconfirmed_fixture(
        server: &mut tokio::net::UnixStream,
        route: u64,
        claim: &str,
        id: &Value,
        phase: &str,
        context: Option<&ExtensionWireContext>,
        terminal: Option<&str>,
    ) {
        let mut data = json!({"claim":claim,"route":route,"id":id,"writePhase":phase,"reason":"actual extension invocation lacks Chrome terminal result","observation":true});
        if let Some(context) = context {
            data["wireContext"] = json!(context);
        }
        if let Some(reason) = terminal {
            data["event"] = json!({"kind":"transportFailure","data":reason});
        }
        local_ipc::write_json(
            server,
            &json!({"kind":"controlEvent","event":{"kind":"cdpUnconfirmed","data":data}}),
        )
        .await
        .unwrap();
    }
    #[cfg(unix)]
    async fn transport_failure_fixture(server: &mut tokio::net::UnixStream, route: u64) {
        local_ipc::write_json(server,&json!({"kind":"cdpEvent","route":route,"event":{"kind":"transportFailure","data":"matched extension RPC returned code 1; Chrome effect unconfirmed"}})).await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn trusted_disposition_not_method_or_peer_hint_controls_written_unknown_effect() {
        for disposition in [ReplyDisposition::Required, ReplyDisposition::Observation] {
            let (provider, mut server) = fixture();
            let mut events = provider.subscribe_events();
            let claim = attach_fixture(&provider, &mut server, 91, "effect-claim").await;
            let connection = open_fixture(&provider, &mut server, claim, 81).await;
            // Deliberately identical methods and parameters: only Rust caller
            // disposition differs, including requests with no wire context.
            let call = {
                let connection = connection.clone();
                tokio::spawn(async move {
                    match disposition {
                        ReplyDisposition::Required => {
                            connection
                                .call(None, "Runtime.evaluate", json!({"expression":"1"}))
                                .await
                        }
                        ReplyDisposition::Observation => {
                            connection
                                .call_observation(
                                    None,
                                    "Runtime.evaluate",
                                    json!({"expression":"1"}),
                                )
                                .await
                        }
                    }
                })
            };
            let sent = request(&mut server).await;
            assert!(sent.get("replyDisposition").is_none());
            assert!(sent.get("observation").is_none());
            unconfirmed_fixture(
                &mut server,
                81,
                "effect-claim",
                &sent["message"]["id"],
                "written",
                None,
                None,
            )
            .await;
            transport_failure_fixture(&mut server, 81).await;
            assert!(bounded(call).await.unwrap().is_err());
            let ready = provider.pending_completions().await.unwrap();
            let effects = ready.iter().filter(|entry|matches!(&entry.operation,ExtensionOperation::EffectsCleanup{effect,cleanup_confirmed:false,..} if effect=="extension_cdp_effect")).collect::<Vec<_>>();
            assert_eq!(
                effects.len(),
                usize::from(disposition == ReplyDisposition::Required)
            );
            let mut order = Vec::new();
            while let Ok(event) = events.try_recv() {
                match event {
                    ExtensionProviderEvent::EffectsCleanup { effect, .. }
                        if effect == "extension_cdp_effect" =>
                    {
                        order.push("effect")
                    }
                    ExtensionProviderEvent::RouteUnavailable { .. } => order.push("route"),
                    _ => {}
                }
            }
            if disposition == ReplyDisposition::Required {
                assert_eq!(order, vec!["effect", "route"]);
                assert_eq!(effects[0].wire_context, None);
            } else {
                assert_eq!(order, vec!["route"]);
            }
            provider.close().await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn partial_or_unproven_observation_write_keeps_effect_unknown() {
        for phase in [Some("started"), None] {
            let (provider, mut server) = fixture();
            let claim = attach_fixture(&provider, &mut server, 92, "observation-claim").await;
            let connection = open_fixture(&provider, &mut server, claim, 82).await;
            let call = tokio::spawn(async move {
                connection
                    .call_observation(None, "Runtime.evaluate", json!({"expression":"1"}))
                    .await
            });
            let sent = request(&mut server).await;
            if let Some(phase) = phase {
                unconfirmed_fixture(
                    &mut server,
                    82,
                    "observation-claim",
                    &sent["message"]["id"],
                    phase,
                    None,
                    None,
                )
                .await;
                transport_failure_fixture(&mut server, 82).await;
            } else {
                // A successful client->broker IPC write does not prove the
                // broker's extension frame was ever completely written.
                drop(server);
            }
            assert!(bounded(call).await.unwrap().is_err());
            let ready = provider.pending_completions().await.unwrap();
            assert_eq!(ready.iter().filter(|entry|matches!(&entry.operation,ExtensionOperation::EffectsCleanup{claim,effect,cleanup_confirmed:false,..} if claim=="observation-claim"&&effect=="extension_cdp_effect")).count(),1);
            provider.close().await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn retired_late_native_completion_keeps_original_turn_once_without_replay() {
        let (provider, mut server) = fixture();
        let claim = attach_fixture(&provider, &mut server, 93, "retired-effect-claim").await;
        let connection = open_fixture(&provider, &mut server, claim, 83).await;
        let original = ExtensionWireContext::new("canonical-owner", "turn-A").unwrap();
        let call = {
            let context = original.clone();
            tokio::spawn(async move {
                connection
                    .call_with_extension_context(
                        &context,
                        None,
                        "Runtime.evaluate",
                        json!({"expression":"sideEffect()"}),
                    )
                    .await
            })
        };
        let sent = request(&mut server).await;
        call.abort();
        let _ = call.await;
        let closed = request(&mut server).await;
        assert_eq!(closed["kind"], "closeCdp");
        let _new_view = provider
            .with_wire_context(ExtensionWireContext::new("canonical-owner", "turn-B").unwrap());
        for _ in 0..2 {
            unconfirmed_fixture(
                &mut server,
                83,
                "retired-effect-claim",
                &sent["message"]["id"],
                "written",
                Some(&original),
                None,
            )
            .await;
        }
        local_ipc::write_json(&mut server,&json!({"kind":"controlEvent","event":{"kind":"orphanCdpCompletion","data":{"route":83,"claim":"retired-effect-claim","id":sent["message"]["id"],"wireContext":original,"event":{"kind":"transportFailure","data":"matched extension RPC terminal; Chrome terminal unconfirmed"}}}})).await.unwrap();
        let ready = bounded(async {
            loop {
                let ready = provider.pending_completions().await.unwrap();
                if ready.iter().any(|entry| {
                    matches!(
                        entry.operation,
                        ExtensionOperation::OrphanCdpCompletion { .. }
                    )
                }) {
                    break ready;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        let effects=ready.iter().filter(|entry|matches!(&entry.operation,ExtensionOperation::EffectsCleanup{effect,..} if effect=="extension_cdp_effect")).collect::<Vec<_>>();
        assert_eq!(effects.len(), 1);
        assert_eq!(effects[0].wire_context, Some(original.clone()));
        let orphan = ready
            .iter()
            .find(|entry| {
                matches!(
                    entry.operation,
                    ExtensionOperation::OrphanCdpCompletion { .. }
                )
            })
            .unwrap();
        assert_eq!(orphan.wire_context, Some(original));
        // A metadata snapshot is local; it cannot replay the canceled command.
        assert_eq!(provider.pending_operations().await.unwrap().len(), 2);
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(20),
            local_ipc::read_json(&mut server)
        )
        .await
        .is_err());
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn receipt_capacity_preserves_deferred_effect_and_snapshot_cannot_prove_empty() {
        let (provider, mut server) = fixture();
        let claim = attach_fixture(&provider, &mut server, 94, "capacity-effect-claim").await;
        let connection = open_fixture(&provider, &mut server, claim, 84).await;
        let call = tokio::spawn(async move {
            connection
                .call(
                    None,
                    "Runtime.evaluate",
                    json!({"expression":"sideEffect()"}),
                )
                .await
        });
        let sent = request(&mut server).await;
        for _ in 0..MAX_RETAINED_RECEIPTS {
            local_ipc::write_json(&mut server,&json!({"kind":"controlEvent","event":{"kind":"effectsCleanup","data":{"claim":"existing-host-custody","effect":"cursor","cleanupConfirmed":false,"error":"existing unknown"}}})).await.unwrap();
        }
        bounded(async {
            loop {
                if provider.pending_completions().await.unwrap().len() == MAX_RETAINED_RECEIPTS {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        unconfirmed_fixture(
            &mut server,
            84,
            "capacity-effect-claim",
            &sent["message"]["id"],
            "written",
            None,
            Some("actual extension terminal preserved at capacity"),
        )
        .await;
        assert!(bounded(call).await.unwrap().is_err());
        assert!(provider.is_closed());
        assert!(provider.pending_operations().await.is_err());
        // Host can still read/fold existing receipts, then acknowledge space.
        let ready = provider.pending_completions().await.unwrap();
        assert_eq!(ready.len(), MAX_RETAINED_RECEIPTS);
        provider.acknowledge_completion(ready[0].id).await.unwrap();
        let flushed = provider.pending_completions().await.unwrap();
        assert_eq!(flushed.len(), MAX_RETAINED_RECEIPTS);
        assert_eq!(flushed.iter().filter(|entry|matches!(&entry.operation,ExtensionOperation::EffectsCleanup{claim,effect,..} if claim=="capacity-effect-claim"&&effect=="extension_cdp_effect")).count(),1);
        assert!(
            provider.pending_operations().await.is_err(),
            "one freed slot retained the effect but the actual terminal remains deferred"
        );
        provider
            .acknowledge_completion(flushed[0].id)
            .await
            .unwrap();
        let terminal_ready = provider.pending_completions().await.unwrap();
        assert_eq!(terminal_ready.len(), MAX_RETAINED_RECEIPTS);
        assert!(terminal_ready.iter().any(|entry|matches!(&entry.operation,ExtensionOperation::OrphanCdpCompletion{event:ExtensionCdpCompletionOutcome::TransportFailure(reason),..} if reason=="actual extension terminal preserved at capacity")));
        assert_eq!(
            provider.pending_operations().await.unwrap().len(),
            MAX_RETAINED_RECEIPTS
        );
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn atomic_unknown_terminal_fails_only_its_request_before_neighbor_phase_arrives() {
        let (provider, mut server) = fixture();
        let claim = attach_fixture(&provider, &mut server, 95, "atomic-claim").await;
        let connection = open_fixture(&provider, &mut server, claim, 85).await;
        let required = {
            let connection = connection.clone();
            tokio::spawn(async move {
                connection
                    .call(None, "Runtime.evaluate", json!({"expression":"1"}))
                    .await
            })
        };
        let first = request(&mut server).await;
        let observation = {
            let connection = connection.clone();
            tokio::spawn(async move {
                connection
                    .call_observation(None, "Runtime.evaluate", json!({"expression":"1"}))
                    .await
            })
        };
        let second = request(&mut server).await;
        unconfirmed_fixture(
            &mut server,
            85,
            "atomic-claim",
            &first["message"]["id"],
            "written",
            None,
            Some("exact-required-terminal"),
        )
        .await;
        let error = bounded(required).await.unwrap().unwrap_err();
        assert!(error.to_string().contains("exact-required-terminal"));
        assert!(
            !observation.is_finished(),
            "neighbor cannot fail before receiving its own phase+terminal"
        );
        assert!(!connection.is_closed());
        unconfirmed_fixture(
            &mut server,
            85,
            "atomic-claim",
            &second["message"]["id"],
            "written",
            None,
            Some("exact-observation-terminal"),
        )
        .await;
        let error = bounded(observation).await.unwrap().unwrap_err();
        assert!(error.to_string().contains("exact-observation-terminal"));
        let ready = provider.pending_completions().await.unwrap();
        assert_eq!(ready.iter().filter(|entry|matches!(&entry.operation,ExtensionOperation::EffectsCleanup{effect,..} if effect=="extension_cdp_effect")).count(),1);
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn atomic_retired_terminal_preserves_original_scope_and_actual_cause_once() {
        let (provider, mut server) = fixture();
        let claim = attach_fixture(&provider, &mut server, 96, "atomic-retired-claim").await;
        let connection = open_fixture(&provider, &mut server, claim, 86).await;
        let original = ExtensionWireContext::new("canonical-owner", "old-turn").unwrap();
        let call = {
            let context = original.clone();
            tokio::spawn(async move {
                connection
                    .call_with_extension_context(
                        &context,
                        None,
                        "Runtime.evaluate",
                        json!({"expression":"effect()"}),
                    )
                    .await
            })
        };
        let sent = request(&mut server).await;
        call.abort();
        let _ = call.await;
        assert_eq!(request(&mut server).await["kind"], "closeCdp");
        let _new_view = provider
            .with_wire_context(ExtensionWireContext::new("canonical-owner", "new-turn").unwrap());
        for _ in 0..2 {
            unconfirmed_fixture(
                &mut server,
                86,
                "atomic-retired-claim",
                &sent["message"]["id"],
                "written",
                Some(&original),
                Some("actual-old-turn-cause"),
            )
            .await;
        }
        let ready = bounded(async {
            loop {
                let ready = provider.pending_completions().await.unwrap();
                if ready.iter().any(|entry| {
                    matches!(
                        entry.operation,
                        ExtensionOperation::OrphanCdpCompletion { .. }
                    )
                }) {
                    break ready;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert_eq!(ready.len(), 2);
        assert!(ready
            .iter()
            .all(|entry| entry.wire_context == Some(original.clone())));
        assert_eq!(ready.iter().filter(|entry|matches!(&entry.operation,ExtensionOperation::OrphanCdpCompletion{event:ExtensionCdpCompletionOutcome::TransportFailure(reason),..} if reason=="actual-old-turn-cause")).count(),1);
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn eof_control_lane_records_all_phases_before_generation_close() {
        let (provider, mut server) = fixture();
        let claim = attach_fixture(&provider, &mut server, 97, "atomic-eof-claim").await;
        let connection = open_fixture(&provider, &mut server, claim, 87).await;
        let written = {
            let connection = connection.clone();
            tokio::spawn(async move {
                connection
                    .call_observation(None, "Runtime.evaluate", json!({"expression":"1"}))
                    .await
            })
        };
        let first = request(&mut server).await;
        let partial = {
            let connection = connection.clone();
            tokio::spawn(async move {
                connection
                    .call_observation(None, "Runtime.evaluate", json!({"expression":"1"}))
                    .await
            })
        };
        let second = request(&mut server).await;
        unconfirmed_fixture(
            &mut server,
            87,
            "atomic-eof-claim",
            &first["message"]["id"],
            "written",
            None,
            None,
        )
        .await;
        unconfirmed_fixture(
            &mut server,
            87,
            "atomic-eof-claim",
            &second["message"]["id"],
            "started",
            None,
            None,
        )
        .await;
        local_ipc::write_json(&mut server,&json!({"kind":"controlEvent","event":{"kind":"generationClosed","data":{"reason":"actual EOF after all phase facts"}}})).await.unwrap();
        assert!(bounded(written).await.unwrap().is_err());
        assert!(bounded(partial).await.unwrap().is_err());
        let ready = provider.pending_completions().await.unwrap();
        assert_eq!(ready.iter().filter(|entry|matches!(&entry.operation,ExtensionOperation::EffectsCleanup{effect,..} if effect=="extension_cdp_effect")).count(),1);
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn final_control_route_marker_closes_cache_and_keeps_physical_claim_reopenable() {
        let (provider, mut server) = fixture();
        let mut events = provider.subscribe_events();
        let claim = attach_fixture(&provider, &mut server, 98, "route-marker-claim").await;
        let connection = open_fixture(&provider, &mut server, claim.clone(), 88).await;
        // The zero-pending case must close the cached route too. Claim custody
        // stays valid and a new CDP route may reuse that exact physical claim.
        local_ipc::write_json(&mut server,&json!({"kind":"controlEvent","event":{"kind":"cdpRouteClosed","data":{"route":88,"claim":"route-marker-claim","reason":"extension CDP route ended; physical claim custody is retained"}}})).await.unwrap();
        bounded(async {
            loop {
                if matches!(
                    events.recv().await.unwrap(),
                    ExtensionProviderEvent::RouteUnavailable { .. }
                ) {
                    break;
                }
            }
        })
        .await;
        bounded(async {
            while !connection.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(!provider.is_closed());
        // Closing the demux emits its existing idempotent close notification.
        // Consume that frame before expecting the newly opened route request.
        let closed = request(&mut server).await;
        assert_eq!(closed["kind"], "closeCdp");
        assert_eq!(closed["route"], 88);
        let reopened = open_fixture(&provider, &mut server, claim, 89).await;
        assert!(!Arc::ptr_eq(&connection, &reopened));
        let call = tokio::spawn(async move {
            reopened
                .call_observation(None, "Runtime.evaluate", json!({"expression":"1"}))
                .await
        });
        let sent = request(&mut server).await;
        assert_eq!(sent["route"], 89);
        local_ipc::write_json(&mut server,&json!({"kind":"cdpEvent","route":89,"event":{"kind":"chromeMessage","data":{"id":sent["message"]["id"],"result":{"value":1}}}})).await.unwrap();
        assert_eq!(bounded(call).await.unwrap().unwrap()["value"], 1);
        assert!(provider.pending_operations().await.unwrap().is_empty());
        provider.close().await;
    }

    #[cfg(unix)]
    async fn ordered_message_fixture(
        server: &mut tokio::net::UnixStream,
        route: u64,
        claim: &str,
        event: Value,
        context: Option<&ExtensionWireContext>,
    ) {
        let mut data = json!({"route":route,"claim":claim,"event":event});
        if let Some(context) = context {
            data["wireContext"] = json!(context);
        }
        local_ipc::write_json(
            server,
            &json!({"kind":"controlEvent","event":{"kind":"cdpMessage","data":data}}),
        )
        .await
        .unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn serialized_control_cdp_event_and_reply_precede_final_route_marker() {
        let (provider, mut server) = fixture();
        let claim = attach_fixture(&provider, &mut server, 99, "ordered-claim").await;
        let connection = open_fixture(&provider, &mut server, claim, 90).await;
        let mut seen = connection.subscribe();
        let call = {
            let connection = connection.clone();
            tokio::spawn(async move {
                connection
                    .call_observation(None, "Runtime.evaluate", json!({"expression":"1"}))
                    .await
            })
        };
        let sent = request(&mut server).await;
        ordered_message_fixture(&mut server,90,"ordered-claim",json!({"kind":"chromeMessage","data":{"method":"Page.frameNavigated","params":{"sequence":1}}}),None).await;
        ordered_message_fixture(&mut server,90,"ordered-claim",json!({"kind":"chromeMessage","data":{"id":sent["message"]["id"],"result":{"value":1}}}),None).await;
        local_ipc::write_json(&mut server,&json!({"kind":"controlEvent","event":{"kind":"cdpRouteClosed","data":{"route":90,"claim":"ordered-claim","reason":"route ended after already emitted frames"}}})).await.unwrap();
        assert_eq!(bounded(call).await.unwrap().unwrap()["value"], 1);
        let event = bounded(seen.recv()).await.unwrap();
        assert_eq!(event.method, "Page.frameNavigated");
        assert_eq!(event.params["sequence"], 1);
        assert!(
            provider.pending_operations().await.unwrap().is_empty(),
            "known Chrome reply cannot become effect Unknown when final marker follows it"
        );
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ordered_actual_reply_after_local_close_retains_old_turn_and_payload() {
        let (provider, mut server) = fixture();
        let claim = attach_fixture(&provider, &mut server, 100, "ordered-retired-claim").await;
        let connection = open_fixture(&provider, &mut server, claim, 91).await;
        let original = ExtensionWireContext::new("canonical-owner", "old-ordered-turn").unwrap();
        let call = {
            let context = original.clone();
            tokio::spawn(async move {
                connection
                    .call_with_extension_context(
                        &context,
                        None,
                        "Runtime.evaluate",
                        json!({"expression":"effect()"}),
                    )
                    .await
            })
        };
        let sent = request(&mut server).await;
        call.abort();
        let _ = call.await;
        assert_eq!(request(&mut server).await["kind"], "closeCdp");
        let _new_view = provider.with_wire_context(
            ExtensionWireContext::new("canonical-owner", "new-ordered-turn").unwrap(),
        );
        ordered_message_fixture(&mut server,91,"ordered-retired-claim",json!({"kind":"chromeMessage","data":{"id":sent["message"]["id"],"result":{"actual":"already emitted before local closure"}}}),Some(&original)).await;
        let ready = bounded(async {
            loop {
                let ready = provider.pending_completions().await.unwrap();
                if ready.iter().any(|entry| {
                    matches!(
                        entry.operation,
                        ExtensionOperation::OrphanCdpCompletion { .. }
                    )
                }) {
                    break ready;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        let orphan = ready
            .iter()
            .find(|entry| {
                matches!(
                    entry.operation,
                    ExtensionOperation::OrphanCdpCompletion { .. }
                )
            })
            .unwrap();
        assert_eq!(orphan.wire_context, Some(original));
        assert!(
            matches!(&orphan.operation,ExtensionOperation::OrphanCdpCompletion{event:ExtensionCdpCompletionOutcome::ChromeMessage(value),..} if value["result"]["actual"]=="already emitted before local closure")
        );
        assert_eq!(ready.iter().filter(|entry|matches!(&entry.operation,ExtensionOperation::EffectsCleanup{effect,cleanup_confirmed:false,..} if effect=="extension_cdp_effect")).count(),1,"late actual result cannot silently clear Host Unknown effect");
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ordered_retired_actual_payload_survives_receipt_capacity_until_host_ack() {
        let (provider, mut server) = fixture();
        let claim = attach_fixture(&provider, &mut server, 101, "ordered-capacity-claim").await;
        let connection = open_fixture(&provider, &mut server, claim, 92).await;
        let original = ExtensionWireContext::new("canonical-owner", "capacity-old-turn").unwrap();
        let call = {
            let context = original.clone();
            tokio::spawn(async move {
                connection
                    .call_with_extension_context(
                        &context,
                        None,
                        "Runtime.evaluate",
                        json!({"expression":"effect()"}),
                    )
                    .await
            })
        };
        let sent = request(&mut server).await;
        call.abort();
        let _ = call.await;
        assert_eq!(request(&mut server).await["kind"], "closeCdp");
        for _ in 1..MAX_RETAINED_RECEIPTS {
            local_ipc::write_json(&mut server,&json!({"kind":"controlEvent","event":{"kind":"effectsCleanup","data":{"claim":"existing-custody","effect":"cursor","cleanupConfirmed":false,"error":"existing unknown"}}})).await.unwrap();
        }
        bounded(async {
            loop {
                if provider.pending_completions().await.unwrap().len() == MAX_RETAINED_RECEIPTS {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        ordered_message_fixture(&mut server,92,"ordered-capacity-claim",json!({"kind":"chromeMessage","data":{"id":sent["message"]["id"],"result":{"actual":"payload retained under full ledger"}}}),Some(&original)).await;
        bounded(async {
            while !provider.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(provider.pending_operations().await.is_err());
        let ready = provider.pending_completions().await.unwrap();
        provider.acknowledge_completion(ready[0].id).await.unwrap();
        let flushed = provider.pending_completions().await.unwrap();
        let orphan = flushed
            .iter()
            .find(|entry| {
                matches!(
                    entry.operation,
                    ExtensionOperation::OrphanCdpCompletion { .. }
                )
            })
            .unwrap();
        assert_eq!(orphan.wire_context, Some(original));
        assert!(
            matches!(&orphan.operation,ExtensionOperation::OrphanCdpCompletion{event:ExtensionCdpCompletionOutcome::ChromeMessage(value),..} if value["result"]["actual"]=="payload retained under full ledger")
        );
        assert_eq!(
            provider.pending_operations().await.unwrap().len(),
            MAX_RETAINED_RECEIPTS
        );
        provider.close().await;
    }

    #[tokio::test]
    async fn known_failed_local_send_retains_actual_result_and_scope_without_invented_effect() {
        for preexisting_unknown in [false, true] {
            let (outbound, mut commands) = mpsc::channel(4);
            let (inbound, incoming) = mpsc::channel(4);
            let (close, _closed) = oneshot::channel();
            let connection = Arc::new(CdpConnection::from_extension_channels(
                outbound, incoming, close,
            ));
            let original =
                ExtensionWireContext::new("canonical-owner", "closed-reader-turn").unwrap();
            let call = {
                let connection = connection.clone();
                let context = original.clone();
                tokio::spawn(async move {
                    connection
                        .call_with_extension_context(
                            &context,
                            None,
                            "Runtime.evaluate",
                            json!({"expression":"effect()"}),
                        )
                        .await
                })
            };
            let dispatch = bounded(commands.recv())
                .await
                .unwrap()
                .into_dispatch_if_live()
                .unwrap();
            let id = dispatch.message["id"].as_u64().unwrap();
            call.abort();
            let _ = call.await;
            bounded(inbound.closed()).await;
            // Deterministic actor boundary: demux already ended, but the actor
            // has not yet selected the pending CloseCdp command.
            let (events, _) = broadcast::channel(EVENT_QUEUE);
            let mut pending = HashMap::new();
            let mut next_id = 0;
            let mut metadata = ExtensionCdpRequestMetadata {
                claim: "failed-send-claim".into(),
                wire_context: Some(original.clone()),
                reply_disposition: ReplyDisposition::Required,
                write_phase: Some(ExtensionCdpWritePhase::Written),
                effect: ExtensionCdpEffectCustody::Clear,
                atomic_terminal: ExtensionCdpAtomicTerminal::None,
            };
            if preexisting_unknown {
                mark_request_unconfirmed(&mut metadata, &mut pending, &events, &mut next_id)
                    .unwrap();
            }
            let mut routes = HashMap::from([(
                93,
                RuntimeRoute {
                    claim: "failed-send-claim".into(),
                    inbound,
                    connection,
                    request_contexts: HashMap::from([(id, metadata)]),
                },
            )]);
            let mut retired = HashMap::new();
            let (sender, _receiver) = mpsc::channel::<ClientCommand>(4);
            apply_cdp_frame(
                93,
                ExtensionCdpCompletionOutcome::ChromeMessage(
                    json!({"id":id,"result":{"actual":"known result survived failed send"}}),
                ),
                RouteReceipts {
                    routes: &mut routes,
                    retired_contexts: &mut retired,
                },
                &mut pending,
                &sender.downgrade(),
                &events,
                &mut next_id,
            )
            .unwrap();
            assert!(routes.is_empty());
            assert!(retired.is_empty());
            let orphan = pending
                .values()
                .find(|entry| {
                    matches!(
                        entry.operation,
                        ExtensionOperation::OrphanCdpCompletion { .. }
                    )
                })
                .unwrap();
            assert_eq!(orphan.wire_context, Some(original));
            assert!(
                matches!(&orphan.operation,ExtensionOperation::OrphanCdpCompletion{event:ExtensionCdpCompletionOutcome::ChromeMessage(value),..} if value["result"]["actual"]=="known result survived failed send")
            );
            assert_eq!(pending.values().filter(|entry|matches!(&entry.operation,ExtensionOperation::EffectsCleanup{effect,cleanup_confirmed:false,..} if effect=="extension_cdp_effect")).count(),usize::from(preexisting_unknown));
        }
    }

    #[test]
    fn actual_generic_orphan_error_debt_survives_full_ledger_with_original_cause() {
        let (events, _) = broadcast::channel(EVENT_QUEUE);
        let mut pending = HashMap::new();
        let mut next_id = 0;
        for _ in 0..MAX_RETAINED_RECEIPTS {
            retain_event_receipt(
                ExtensionOperation::EffectsCleanup {
                    claim: "existing-custody".into(),
                    effect: "cursor".into(),
                    cleanup_confirmed: false,
                    error: Some("existing unknown".into()),
                },
                &mut pending,
                &events,
                &mut next_id,
            )
            .unwrap();
        }
        let original =
            ExtensionWireContext::new("canonical-owner", "generic-orphan-old-turn").unwrap();
        let metadata = ExtensionCdpRequestMetadata {
            claim: "actual-native-error-claim".into(),
            wire_context: Some(original.clone()),
            reply_disposition: ReplyDisposition::Required,
            write_phase: Some(ExtensionCdpWritePhase::Written),
            effect: ExtensionCdpEffectCustody::Clear,
            atomic_terminal: ExtensionCdpAtomicTerminal::Delivered,
        };
        let mut routes = HashMap::new();
        let mut retired = HashMap::from([((94, 42), metadata)]);
        let mut opening = HashMap::new();
        let (sender, _receiver) = mpsc::channel::<ClientCommand>(4);
        let actual = json!({"kind":"controlEvent","event":{"kind":"orphanCdpCompletion","data":{"route":94,"claim":"actual-native-error-claim","id":42,"wireContext":original,"event":{"kind":"transportFailure","data":"actual code1 timeout cause survives full ledger"}}}});
        assert!(apply_server(
            actual,
            &mut pending,
            &mut opening,
            RouteReceipts {
                routes: &mut routes,
                retired_contexts: &mut retired
            },
            ProviderEventContext {
                sender: &sender.downgrade(),
                events: &events,
                payload_budget: &ByteBudget::new()
            },
            &mut next_id
        )
        .is_err());
        assert!(
            matches!(&retired[&(94,42)].atomic_terminal,ExtensionCdpAtomicTerminal::UnretainedLate(ExtensionCdpCompletionOutcome::TransportFailure(reason)) if reason=="actual code1 timeout cause survives full ledger")
        );
        pending.remove(&1);
        assert!(flush_deferred_effects(
            RouteReceipts {
                routes: &mut routes,
                retired_contexts: &mut retired
            },
            &mut pending,
            &events,
            &mut next_id
        )
        .is_err());
        pending.remove(&2);
        flush_deferred_effects(
            RouteReceipts {
                routes: &mut routes,
                retired_contexts: &mut retired,
            },
            &mut pending,
            &events,
            &mut next_id,
        )
        .unwrap();
        assert!(retired.is_empty());
        let orphan = pending
            .values()
            .find(|entry| {
                matches!(
                    entry.operation,
                    ExtensionOperation::OrphanCdpCompletion { .. }
                )
            })
            .unwrap();
        assert_eq!(orphan.wire_context, Some(original));
        assert!(
            matches!(&orphan.operation,ExtensionOperation::OrphanCdpCompletion{event:ExtensionCdpCompletionOutcome::TransportFailure(reason),..} if reason=="actual code1 timeout cause survives full ledger")
        );
        assert_eq!(pending.len(), MAX_RETAINED_RECEIPTS);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn trusted_effect_custody_sets_reply_disposition_and_preserves_actual_code() {
        for disposition in [ReplyDisposition::Required, ReplyDisposition::Observation] {
            let (provider, mut server) = fixture();
            let claim = attach_fixture(&provider, &mut server, 102, "typed-error-claim").await;
            let connection = open_fixture(&provider, &mut server, claim, 95).await;
            let call = tokio::spawn(async move {
                match disposition {
                    ReplyDisposition::Required => {
                        connection
                            .call(None, "Runtime.evaluate", json!({"expression":"1"}))
                            .await
                    }
                    ReplyDisposition::Observation => {
                        connection
                            .call_observation(None, "Runtime.evaluate", json!({"expression":"1"}))
                            .await
                    }
                }
            });
            let sent = request(&mut server).await;
            // Same code/message/method and contradictory peer hints in both
            // cases: only Rust's already captured caller intent differs.
            unconfirmed_fixture(
                &mut server,
                95,
                "typed-error-claim",
                &sent["message"]["id"],
                "written",
                None,
                None,
            )
            .await;
            ordered_message_fixture(&mut server,95,"typed-error-claim",json!({"kind":"chromeMessage","data":{"id":sent["message"]["id"],"disposition":"notDispatched","error":{"code":1,"message":"actual fixture error","disposition":"replyFailure","observation":true}}}),None).await;
            let error = bounded(call).await.unwrap().unwrap_err();
            let typed = error
                .downcast_ref::<super::super::cdp_ws::CdpReplyError>()
                .unwrap();
            assert_eq!(typed.method(), "Runtime.evaluate");
            assert_eq!(typed.code(), Some(1));
            assert_eq!(typed.message(), "actual fixture error");
            assert_eq!(
                typed.disposition(),
                if disposition == ReplyDisposition::Required {
                    CdpFailureDisposition::ExtensionEffectUnknown
                } else {
                    CdpFailureDisposition::ReplyFailure
                }
            );
            assert_eq!(
                error.to_string(),
                "CDP Runtime.evaluate failed (1): actual fixture error"
            );
            provider.close().await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn extension_request_terminal_has_typed_disposition_without_invented_chrome_code() {
        for (disposition, phase, expected) in [
            (
                ReplyDisposition::Required,
                "written",
                CdpFailureDisposition::ExtensionEffectUnknown,
            ),
            (
                ReplyDisposition::Observation,
                "written",
                CdpFailureDisposition::ReplyFailure,
            ),
            (
                ReplyDisposition::Observation,
                "started",
                CdpFailureDisposition::ExtensionEffectUnknown,
            ),
        ] {
            let (provider, mut server) = fixture();
            let claim = attach_fixture(&provider, &mut server, 103, "typed-native-claim").await;
            let connection = open_fixture(&provider, &mut server, claim, 96).await;
            let call = tokio::spawn(async move {
                match disposition {
                    ReplyDisposition::Required => {
                        connection
                            .call(None, "Runtime.evaluate", json!({"expression":"1"}))
                            .await
                    }
                    ReplyDisposition::Observation => {
                        connection
                            .call_observation(None, "Runtime.evaluate", json!({"expression":"1"}))
                            .await
                    }
                }
            });
            let sent = request(&mut server).await;
            unconfirmed_fixture(
                &mut server,
                96,
                "typed-native-claim",
                &sent["message"]["id"],
                phase,
                None,
                Some("actual matched extension timeout"),
            )
            .await;
            let error = bounded(call).await.unwrap().unwrap_err();
            let typed = error
                .downcast_ref::<super::super::cdp_ws::CdpReplyError>()
                .unwrap();
            assert_eq!(typed.code(), None);
            assert_eq!(typed.method(), "Runtime.evaluate");
            assert_eq!(typed.message(), "actual matched extension timeout");
            assert_eq!(typed.disposition(), expected);
            assert_eq!(
                error.to_string(),
                "CDP transport failed during Runtime.evaluate: actual matched extension timeout"
            );
            provider.close().await;
        }
    }

    #[test]
    fn actual_metadata_is_optional_and_mutation_diagnostic_requires_nullable_changed() {
        let tab: ExtensionTabInfo =
            decode(json!({"id":0,"lastAccessed":1234.5,"active":false,"pendingUrl":"about:blank"}))
                .unwrap();
        assert_eq!(tab.id, 0);
        assert_eq!(tab.last_accessed, Some(1234.5));
        assert_eq!(tab.active, Some(false));
        assert!(tab.title.is_none());
        let diagnostic: ExtensionMutationDiagnostic =
            decode(json!({"attempted":true,"mutationAcknowledged":false,"changed":null})).unwrap();
        assert_eq!(diagnostic.changed, None);
        assert!(decode::<ExtensionMutationDiagnostic>(
            json!({"attempted":true,"mutationAcknowledged":false})
        )
        .is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn canceled_attach_keeps_original_context_and_recovers_cleanup_without_replay() {
        let (provider, mut server) = fixture();
        let context = ExtensionHostOperation {
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
        let ExtensionRecoveredOperation::Claim(claim) = recovered else {
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
        let ExtensionRecoveredOperation::Created(recovered) =
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
            Err(ExtensionProviderError::OutcomeUnknown { .. })
        ));
        let ExtensionRecoveredOperation::Unknown { custody, .. } =
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
                Some(&[ExtensionHeader {
                    name: "x-browser-agent".into(),
                    value: "Maka/trusted-session".into(),
                }]),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, ExtensionProviderError::Refused { .. }));
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
                ExtensionRecoveredOperation::OrphanCdpCompletion { route, id, .. } => {
                    assert_eq!((route, id), (7, 5));
                    saw_orphan = true;
                }
                ExtensionRecoveredOperation::EffectsCleanup {
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
            matches!(first,Err(ExtensionProviderError::Refused{ref kind,..})if kind=="request_budget")
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
                operation: ExtensionOperation::Attach { tab_id: 51 },
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
            matches!(response.outcome,ExtensionOperationOutcome::NotDispatched{ref kind,..}if kind=="owner_closed")
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
        let wire = ExtensionWireContext::new("existing-canonical-owner", "turn-A").unwrap();
        let context = ExtensionHostOperation {
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
            ExtensionWireContext::new("existing-canonical-owner", "turn-B").unwrap(),
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
        let ExtensionRecoveredOperation::Claim(claim) =
            provider.recover_completion(id).await.unwrap()
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
            let context = ExtensionWireContext::new("existing-owner", turn).unwrap();
            let call = {
                let connection = connection.clone();
                tokio::spawn(async move {
                    connection
                        .call_with_extension_context(
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
        let (provider, mut server) = fixture_with_capabilities(chatgpt_capabilities());
        assert!(
            matches!(provider.finish_turn(None).await,Err(ExtensionProviderError::Refused{ref kind,..})if kind=="missing_context")
        );
        let context = ExtensionWireContext::new("existing-owner", "finishing-turn").unwrap();
        let scoped = provider.with_wire_context(context);
        let call = tokio::spawn(async move {
            scoped
                .finish_turn(Some(&[ExtensionKeepTab {
                    tab_id: 72,
                    status: ExtensionKeepStatus::Deliverable,
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
            ExtensionRecoveredOperation::TurnFinished(_)
        ));
        provider.close().await;
    }

    #[test]
    fn original_tab_strings_are_preserved_without_date_or_id_invention() {
        let tab:ExtensionTabInfo=decode(json!({"id":82,"providerTabId":"actual-opaque-provider-id","lastOpened":"2026-10-27T01:02:03.004Z","groupTitle":"actual-group"})).unwrap();
        assert_eq!(tab.last_opened.as_deref(), Some("2026-10-27T01:02:03.004Z"));
        assert_eq!(
            tab.provider_tab_id.as_deref(),
            Some("actual-opaque-provider-id")
        );
        assert!(tab.last_accessed.is_none());
        assert!(tab.window_id.is_none());
    }
    #[test]
    fn event_source_target_capability_is_explicit_and_never_inferred() {
        let mut capabilities = maka_capabilities();
        assert!(
            !decode::<ExtensionProviderCapabilities>(capabilities.clone())
                .unwrap()
                .cdp_event_source_target
        );
        capabilities["cdpEventSourceTarget"] = json!(true);
        assert!(
            decode::<ExtensionProviderCapabilities>(capabilities.clone())
                .unwrap()
                .cdp_event_source_target
        );
        capabilities["cdpEventSourceTarget"] = json!("true");
        assert!(decode::<ExtensionProviderCapabilities>(capabilities).is_err());
    }

    #[test]
    fn routing_metadata_preserves_provider_scope_and_refuses_missing_lifecycle_fact() {
        let maka: ExtensionProviderCapabilities = decode(maka_capabilities()).unwrap();
        assert_eq!(
            maka.attachment_preparation,
            ExtensionAttachmentPreparation::MetadataOnly
        );
        assert_eq!(maka.header_scope, ExtensionHeaderPolicyScope::Claim);
        assert_eq!(maka.created_presentation_owner, ExtensionEffectOwner::Host);
        let original: ExtensionProviderCapabilities = decode(chatgpt_capabilities()).unwrap();
        assert_eq!(
            original.attachment_preparation,
            ExtensionAttachmentPreparation::FullPreparation
        );
        assert_eq!(original.user_tabs_order, ExtensionUserTabsOrder::Provider);
        assert_eq!(original.header_scope, ExtensionHeaderPolicyScope::Session);
        assert_eq!(
            original.cursor_hide_owner,
            ExtensionEffectOwner::Unavailable
        );
        assert_eq!(
            original.turn_lifecycle_owner,
            ExtensionEffectOwner::Provider
        );
        let mut legacy = maka_capabilities();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("attachmentPreparation");
        assert_eq!(
            decode::<ExtensionProviderCapabilities>(legacy)
                .unwrap()
                .attachment_preparation,
            ExtensionAttachmentPreparation::Unknown,
            "older providers must not acquire an implicit preparation guarantee"
        );
        let mut invalid = maka_capabilities();
        invalid["attachmentPreparation"] = json!("bare_attach");
        assert!(decode::<ExtensionProviderCapabilities>(invalid).is_err());
        let mut incomplete = maka_capabilities();
        incomplete
            .as_object_mut()
            .unwrap()
            .remove("turnLifecycleOwner");
        assert!(decode::<ExtensionProviderCapabilities>(incomplete).is_err());
    }

    #[test]
    fn tab_absence_is_bound_to_created_identity_and_distinct_from_logical_acknowledgement() {
        let result = json!({"closed":true,"proof":"tab_absent","tabId":81,"observationRequestId":"actual-native-request"});
        let reply = |value| ControlReply {
            id: 9,
            outcome: ExtensionOperationOutcome::Result(value),
        };
        let proof = close_proof(reply(result.clone()), Some(81)).unwrap();
        assert_eq!(proof.evidence(), CleanupEvidence::TabAbsenceObserved);
        assert_ne!(proof.evidence(), CleanupEvidence::CloseAcknowledged);
        assert_eq!(
            proof
                .tab_absence_observation()
                .unwrap()
                .extension_request_id(),
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
        let context = ExtensionWireContext::new("stable-session", "old-turn").unwrap();
        let proof = json!({"hostSessionId":"stable-session","hostTurnId":"old-turn","generation":"generation","owner":"owner","stateConfirmed":true,"active":false,"cleanupConfirmed":true});
        let reply = |value| ControlReply {
            id: 15,
            outcome: ExtensionOperationOutcome::Result(value),
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
        let (provider, mut server) = fixture_with_capabilities(chatgpt_capabilities());
        let context =
            ExtensionWireContext::new("stable-browser-owner", "captured-old-turn").unwrap();
        let scoped =
            provider
                .with_wire_context(context)
                .with_host_operation(ExtensionHostOperation {
                    operation_id: "existing-host-operation".into(),
                    turn_id: "captured-old-turn".into(),
                });
        let call = tokio::spawn(async move {
            scoped
                .set_session_headers(&[ExtensionHeader {
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
        let _later_view = provider.with_wire_context(
            ExtensionWireContext::new("stable-browser-owner", "new-turn").unwrap(),
        );
        control_result(&mut server,id,json!({"hostSessionId":"stable-browser-owner","hostTurnId":"captured-old-turn","generation":provider.identity().generation,"owner":"broker-owner","stateConfirmed":true,"active":true,"cleanupConfirmed":false})).await;
        let ready = wait_ready(&provider).await;
        assert_eq!(ready.len(), 1);
        assert_eq!(
            ready[0].host_operation.as_ref().unwrap().operation_id,
            "existing-host-operation"
        );
        let ExtensionRecoveredOperation::SessionHeaders(proof) =
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
    async fn maka_capabilities_refuse_original_only_methods_before_dispatch() {
        let (provider, mut server) = fixture();
        let claim = attach_fixture(&provider, &mut server, 91, "own-claim").await;
        let scoped =
            provider.with_wire_context(ExtensionWireContext::new("owner", "turn").unwrap());
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
                matches!(result,Err(ExtensionProviderError::NotDispatched{ref kind,..})if kind=="unsupported")
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
    async fn extension_cursor_ack_is_only_presentation_and_rejects_uncertain_claim_and_nan() {
        let (provider, mut server) = fixture_with_capabilities(chatgpt_capabilities());
        let claim = attach_fixture(&provider, &mut server, 92, "original-claim").await;
        let scoped =
            provider.with_wire_context(ExtensionWireContext::new("owner", "cursor-turn").unwrap());
        let mut uncertain = claim.clone();
        uncertain.cleanup_only = true;
        assert!(
            matches!(scoped.move_mouse_presentation(&uncertain,1.0,2.0,None).await,Err(ExtensionProviderError::Refused{ref kind,..})if kind=="claim_unavailable")
        );
        assert!(
            matches!(scoped.move_mouse_presentation(&claim,f64::NAN,2.0,None).await,Err(ExtensionProviderError::Refused{ref kind,..})if kind=="invalid_request")
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
            ExtensionRecoveredOperation::CursorPresentation(_)
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
        let ExtensionProviderEvent::DownloadChanged { download } =
            bounded(events.recv()).await.unwrap()
        else {
            panic!("expected global metadata event")
        };
        assert_eq!(download.id, "actual-download");
        assert_eq!(download.filename, "");
        assert_eq!(download.status, ExtensionDownloadStatus::InProgress);
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
                unknown_outcome.then_some("extension RPC timed out without its matched reply");
            control_result(&mut server, fence["request"]["id"].as_u64().unwrap(), json!({"claim":"drain-unknown","generation":provider.identity().generation,"fenced":true,"pending":[{"route":7,"id":11,"wireContext":null,"unknownReason":reason}]})).await;
            if !unknown_outcome {
                drop(server);
            }
            let failure = bounded(waiting).await.unwrap().unwrap_err();
            assert!(
                matches!(failure, ExtensionProviderError::OutcomeUnknown { operation, .. } if operation == "drainClaimCdp")
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
            matches!(bounded(waiting).await.unwrap(), Err(ExtensionProviderError::OutcomeUnknown { reason, .. }) if reason == "claim extension invocations did not answer before the drain deadline")
        );
        let observing = {
            let provider = provider.clone();
            let claim = claim.clone();
            tokio::spawn(async move { provider.fence_claim_cdp(&claim).await })
        };
        let fence = request(&mut server).await;
        control_result(&mut server, fence["request"]["id"].as_u64().unwrap(), json!({"claim":"foreign-claim","generation":provider.identity().generation,"fenced":true,"pending":[]})).await;
        assert!(
            matches!(bounded(observing).await.unwrap(), Err(ExtensionProviderError::Protocol(reason)) if reason == "CDP fence snapshot changed its exact claim or generation")
        );
        provider.close().await;
    }

    #[cfg(unix)]
    async fn drained_fixture(
        provider: &ExtensionBrowserProvider,
        server: &mut tokio::net::UnixStream,
        claim: &ExtensionPhysicalClaim,
    ) -> ExtensionClaimCdpDrainProof {
        let call = {
            let provider = provider.clone();
            let claim = claim.clone();
            tokio::spawn(async move {
                provider
                    .wait_claim_cdp_drained(&claim, std::time::Duration::from_secs(1))
                    .await
            })
        };
        let sent = request(server).await;
        assert_eq!(sent["request"]["method"], "fenceCdp");
        control_result(server, sent["request"]["id"].as_u64().unwrap(), json!({
            "claim":claim.token,"generation":provider.identity().generation,"fenced":true,"pending":[]
        })).await;
        bounded(call).await.unwrap().unwrap()
    }

    #[cfg(unix)]
    async fn detached_fixture(
        provider: &ExtensionBrowserProvider,
        server: &mut tokio::net::UnixStream,
        claim: &ExtensionPhysicalClaim,
    ) -> CleanupProof {
        let call = {
            let provider = provider.clone();
            let claim = claim.clone();
            tokio::spawn(async move { provider.detach_tab(&claim).await })
        };
        let sent = request(server).await;
        assert_eq!(sent["request"]["method"], "detach");
        assert_eq!(sent["request"]["claim"], claim.token);
        control_result(
            server,
            sent["request"]["id"].as_u64().unwrap(),
            json!({
                "detached":true,"proof":"detach_ack"
            }),
        )
        .await;
        bounded(call).await.unwrap().unwrap()
    }

    #[cfg(unix)]
    async fn inventory_barrier(
        provider: &ExtensionBrowserProvider,
        server: &mut tokio::net::UnixStream,
    ) {
        let call = {
            let provider = provider.clone();
            tokio::spawn(async move { provider.list_user_tabs().await })
        };
        let sent = request(server).await;
        assert_eq!(
            sent["request"]["method"], "inventory",
            "a refused retirement must emit no IPC request"
        );
        control_result(
            server,
            sent["request"]["id"].as_u64().unwrap(),
            json!({"tabs":[]}),
        )
        .await;
        assert!(bounded(call).await.unwrap().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn retirement_has_cleanup_headroom_and_preserves_completion_until_explicit_host_ack() {
        let (provider, mut server) = fixture();
        let claim = attach_fixture(&provider, &mut server, 23, "retire-owned").await;
        let drain = drained_fixture(&provider, &mut server, &claim).await;
        let cleanup = detached_fixture(&provider, &mut server, &claim).await;
        // Unrelated completed controls fill the ordinary admission budget. Retirement
        // is the local cleanup step that permits the caller to release its maka receipt.
        for index in 0..REQUEST_BUDGET - 1 {
            let call = {
                let provider = provider.clone();
                tokio::spawn(async move { provider.create_tab(None).await })
            };
            let sent = request(&mut server).await;
            assert_eq!(sent["request"]["method"], "createTab");
            control_result(
                &mut server,
                sent["request"]["id"].as_u64().unwrap(),
                json!({
                    "creation":format!("unrelated-created-{index}"),"tab":{"id":100+index}
                }),
            )
            .await;
            bounded(call).await.unwrap().unwrap();
        }
        assert_eq!(
            provider.pending_completions().await.unwrap().len(),
            REQUEST_BUDGET
        );
        let call = {
            let provider = provider.clone();
            let claim = claim.clone();
            let cleanup = cleanup.clone();
            tokio::spawn(async move { provider.retire_claim(&claim, &cleanup, &drain).await })
        };
        let sent = request(&mut server).await;
        assert_eq!(sent["kind"], "control");
        assert_eq!(sent["request"]["method"], "retireClaim");
        assert_eq!(sent["request"]["claim"], claim.token);
        assert_eq!(sent["request"]["cleanupId"], cleanup.completion_id);
        control_result(
            &mut server,
            sent["request"]["id"].as_u64().unwrap(),
            json!({
                "retired":true,"claim":claim.token
            }),
        )
        .await;
        bounded(call).await.unwrap().unwrap();
        let retained = provider.pending_completions().await.unwrap();
        assert_eq!(
            retained.len(),
            REQUEST_BUDGET,
            "local retirement adds no retained mutation receipt"
        );
        assert!(retained
            .iter()
            .any(|entry| entry.id == cleanup.completion_id));
        assert!(retained
            .iter()
            .all(|entry| !matches!(&entry.operation, ExtensionOperation::RetireClaim { .. })));
        provider
            .acknowledge_completion(cleanup.completion_id)
            .await
            .unwrap();
        assert_eq!(
            provider.pending_completions().await.unwrap().len(),
            REQUEST_BUDGET - 1
        );
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn retirement_rejects_foreign_claim_drain_and_cleanup_before_ipc() {
        let (provider, mut server) = fixture();
        let claim = attach_fixture(&provider, &mut server, 23, "retire-exact").await;
        let other = attach_fixture(&provider, &mut server, 24, "retire-other").await;
        let drain = drained_fixture(&provider, &mut server, &claim).await;
        let cleanup = detached_fixture(&provider, &mut server, &claim).await;
        let other_cleanup = detached_fixture(&provider, &mut server, &other).await;
        let mut foreign_claim = claim.clone();
        foreign_claim.binding = uuid::Uuid::new_v4();
        assert!(
            matches!(bounded(provider.retire_claim(&foreign_claim, &cleanup, &drain)).await,
            Err(ExtensionProviderError::NotDispatched { kind, .. }) if kind == "claim_unavailable")
        );
        let mut foreign_drain = drain.clone();
        foreign_drain.binding = uuid::Uuid::new_v4();
        assert!(
            matches!(bounded(provider.retire_claim(&claim, &cleanup, &foreign_drain)).await,
            Err(ExtensionProviderError::NotDispatched { kind, .. }) if kind == "drain_unavailable")
        );
        foreign_drain = drain.clone();
        foreign_drain.provider.generation = uuid::Uuid::new_v4().to_string();
        assert!(
            matches!(bounded(provider.retire_claim(&claim, &cleanup, &foreign_drain)).await,
            Err(ExtensionProviderError::NotDispatched { kind, .. }) if kind == "drain_unavailable")
        );
        foreign_drain = drain.clone();
        foreign_drain.claim = other.token.clone();
        assert!(
            matches!(bounded(provider.retire_claim(&claim, &cleanup, &foreign_drain)).await,
            Err(ExtensionProviderError::NotDispatched { kind, .. }) if kind == "drain_unavailable")
        );
        let mut foreign_cleanup = cleanup.clone();
        foreign_cleanup.completion_id += 1000;
        for proof in [&foreign_cleanup, &other_cleanup] {
            assert!(
                matches!(bounded(provider.retire_claim(&claim, proof, &drain)).await,
                Err(ExtensionProviderError::NotDispatched { kind, .. }) if kind == "cleanup_unavailable")
            );
        }
        assert_eq!(provider.pending_completions().await.unwrap().len(), 2);
        inventory_barrier(&provider, &mut server).await;
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn retirement_distinguishes_known_physical_subproof_from_unproven_unknown_cleanup() {
        for case in 0..7 {
            let (provider, mut server) = fixture();
            let claim = attach_fixture(&provider, &mut server, 23, "retire-unconfirmed").await;
            let drain = drained_fixture(&provider, &mut server, &claim).await;
            let known = detached_fixture(&provider, &mut server, &claim).await;
            let other = attach_fixture(&provider, &mut server, 24, "unrelated-retained").await;
            let unrelated = detached_fixture(&provider, &mut server, &other).await;
            let context = ExtensionHostOperation {
                operation_id: "actual-unknown-cleanup-operation".into(),
                turn_id: "actual-unknown-cleanup-turn".into(),
            };
            let wire =
                ExtensionWireContext::new("actual-unknown-cleanup-session", &context.turn_id)
                    .unwrap();
            let call = {
                let scoped = provider
                    .with_host_operation(context.clone())
                    .with_wire_context(wire.clone());
                let claim = claim.clone();
                tokio::spawn(async move { scoped.detach_tab(&claim).await })
            };
            let sent = request(&mut server).await;
            let id = sent["request"]["id"].as_u64().unwrap();
            let acknowledged = match case {
                3 => json!({"detached":true,"proof":"detach_ack","claim":"foreign-claim"}),
                4 => json!({"detached":true,"proof":"detach_ack","tabId":24}),
                5 => json!({"detached":true,"proof":"not-a-native-cleanup-proof"}),
                6 => json!({"detached":true,"proof":"detach_ack","targetId":"foreign-target"}),
                _ => json!({"detached":true,"proof":"detach_ack"}),
            };
            let outcome = match case {
                0 => json!({"kind":"unknown","data":{"reason":"no matched cleanup ACK","details":{
                    "foreignNested":{"acknowledgedResult":acknowledged}
                }}}),
                1 => {
                    json!({"kind":"connectorRejected","data":{"kind":"claim_unavailable","message":"local refusal"}})
                }
                _ => {
                    json!({"kind":"unknown","data":{"reason":"cancelled after physical cleanup ACK","details":{
                        "acknowledgedResult":acknowledged
                    }}})
                }
            };
            local_ipc::write_json(
                &mut server,
                &json!({"kind":"controlEvent","event":{
                    "kind":"reply","data":{"id":id,"outcome":outcome.clone()}
                }}),
            )
            .await
            .unwrap();
            let direct = bounded(call).await.unwrap();
            if case == 1 {
                assert!(
                    matches!(direct, Err(ExtensionProviderError::Refused { kind, .. }) if kind == "claim_unavailable")
                );
            } else {
                assert!(
                    matches!(direct, Err(ExtensionProviderError::OutcomeUnknown { reason, details, .. })
                    if Some(reason.as_str()) == outcome["data"]["reason"].as_str()
                        && details.as_ref() == outcome["data"].get("details")),
                    "overall extension workflow must retain its exact Unknown cause"
                );
            }
            let mut known_subproof = None;
            for _ in 0..2 {
                let retained = provider.pending_completions().await.unwrap();
                assert_eq!(retained.len(), 3, "recovery must not consume any receipt");
                let completion = retained.iter().find(|entry| entry.id == id).unwrap();
                assert_eq!(completion.provider, *provider.identity());
                assert_eq!(completion.host_operation.as_ref(), Some(&context));
                assert_eq!(completion.wire_context.as_ref(), Some(&wire));
                assert!(matches!(&completion.operation,
                    ExtensionOperation::Detach { claim: token, tab_id: 23, target_id }
                        if token == claim.claim_id() && target_id == claim.target_id()));
                if case == 1 {
                    assert!(matches!(provider.recover_completion(id).await.unwrap(),
                        ExtensionRecoveredOperation::Refused { kind, .. } if kind == "claim_unavailable"));
                } else {
                    assert!(matches!(&completion.outcome,
                        ExtensionOperationOutcome::Unknown { reason, details }
                            if Some(reason.as_str()) == outcome["data"]["reason"].as_str()
                                && details.as_ref() == outcome["data"].get("details")));
                    for recovered in [
                        provider.recover_completion(id).await.unwrap(),
                        provider.materialize_completion(completion).await.unwrap(),
                    ] {
                        let ExtensionRecoveredOperation::Unknown {
                            operation,
                            reason,
                            details,
                            custody,
                        } = recovered
                        else {
                            panic!("optional cleanup rejection must not hide the outer Unknown");
                        };
                        assert_eq!(Some(reason.as_str()), outcome["data"]["reason"].as_str());
                        assert_eq!(details.as_ref(), outcome["data"].get("details"));
                        assert!(
                            matches!(operation, ExtensionOperation::Detach { claim: token, tab_id: 23, target_id }
                            if token == claim.claim_id() && target_id == claim.target_id())
                        );
                        if case == 2 {
                            known_subproof = Some(
                                custody
                                    .cleanup
                                    .expect("actual matched physical ACK survives"),
                            );
                        } else {
                            assert!(
                                custody.cleanup.is_none(),
                                "case {case} grants no physical cleanup proof"
                            );
                        }
                    }
                }
                for receipt in [&known, &unrelated] {
                    let ExtensionRecoveredOperation::Cleanup(recovered) = provider
                        .recover_completion(receipt.completion_id())
                        .await
                        .unwrap()
                    else {
                        panic!(
                            "rejected optional evidence must not affect other retained receipts"
                        );
                    };
                    assert_eq!(recovered.completion_id(), receipt.completion_id());
                    assert_eq!(recovered.evidence(), receipt.evidence());
                }
            }
            let proof = known_subproof.unwrap_or_else(|| {
                // A number in an unrelated typed proof cannot authorize missing,
                // noncanonical nested, locally refused, or malformed cleanup.
                CleanupProof {
                    completion_id: id,
                    ..known.clone()
                }
            });
            if case == 2 {
                let retire = {
                    let provider = provider.clone();
                    let claim = claim.clone();
                    let drain = drain.clone();
                    tokio::spawn(async move { provider.retire_claim(&claim, &proof, &drain).await })
                };
                let sent = request(&mut server).await;
                assert_eq!(sent["request"]["method"], "retireClaim");
                assert_eq!(sent["request"]["cleanupId"], id);
                control_result(
                    &mut server,
                    sent["request"]["id"].as_u64().unwrap(),
                    json!({"retired":true,"claim":claim.token}),
                )
                .await;
                bounded(retire).await.unwrap().unwrap();
                assert!(
                    matches!(
                        provider.recover_completion(id).await.unwrap(),
                        ExtensionRecoveredOperation::Unknown { .. }
                    ),
                    "local physical retirement must not rewrite overall T2/effect Unknown as success"
                );
            } else {
                assert!(
                    bounded(provider.retire_claim(&claim, &proof, &drain))
                        .await
                        .is_err(),
                    "unproven/foreign cleanup case {case}"
                );
            }
            assert_eq!(provider.pending_completions().await.unwrap().len(), 3);
            provider
                .acknowledge_completion(known.completion_id)
                .await
                .unwrap();
            assert!(
                matches!(bounded(provider.retire_claim(&claim, &known, &drain)).await,
                Err(ExtensionProviderError::NotDispatched { kind, .. }) if kind == "cleanup_unavailable")
            );
            let retained = provider.pending_completions().await.unwrap();
            assert_eq!(retained.len(), 2);
            assert!(retained.iter().any(|entry| entry.id == id));
            assert!(retained
                .iter()
                .any(|entry| entry.id == unrelated.completion_id()));
            let mut bytes = [0_u8; 4];
            assert_eq!(
                server.try_read(&mut bytes).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock,
                "reads and rejected retirement must never replay a extension mutation"
            );
            inventory_barrier(&provider, &mut server).await;
            provider.close().await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn retirement_requires_exact_local_result_and_retains_cleanup_after_malformed_reply() {
        let (provider, mut server) = fixture();
        let claim = attach_fixture(&provider, &mut server, 23, "retire-matched-reply").await;
        let drain = drained_fixture(&provider, &mut server, &claim).await;
        let cleanup = detached_fixture(&provider, &mut server, &claim).await;
        let call = {
            let provider = provider.clone();
            let claim = claim.clone();
            let cleanup = cleanup.clone();
            tokio::spawn(async move { provider.retire_claim(&claim, &cleanup, &drain).await })
        };
        let sent = request(&mut server).await;
        assert_eq!(sent["request"]["method"], "retireClaim");
        control_result(
            &mut server,
            sent["request"]["id"].as_u64().unwrap(),
            json!({
                "retired":true,"claim":"different-claim"
            }),
        )
        .await;
        assert!(matches!(
            bounded(call).await.unwrap(),
            Err(ExtensionProviderError::Protocol(_))
        ));
        assert_eq!(provider.pending_completions().await.unwrap().len(), 1);
        assert!(matches!(
            provider
                .recover_completion(cleanup.completion_id)
                .await
                .unwrap(),
            ExtensionRecoveredOperation::Cleanup(_)
        ));
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn retirement_accepts_created_cleanup_only_with_its_issued_raw_tab_identity() {
        for (wire_proof, expected_evidence) in [
            ("close_ack", CleanupEvidence::CloseAcknowledged),
            ("tab_removed", CleanupEvidence::TabRemoved),
        ] {
            let (provider, mut server) = fixture();
            let create = {
                let provider = provider.clone();
                tokio::spawn(async move { provider.create_tab(None).await })
            };
            let sent = request(&mut server).await;
            control_result(
                &mut server,
                sent["request"]["id"].as_u64().unwrap(),
                json!({
                    "creation":"retire-created","tab":{"id":23}
                }),
            )
            .await;
            let created = bounded(create).await.unwrap().unwrap();
            provider
                .acknowledge_completion(created.completion_id())
                .await
                .unwrap();
            let claim = attach_fixture(&provider, &mut server, 23, "retire-created-claim").await;
            let drain = drained_fixture(&provider, &mut server, &claim).await;
            let stop = {
                let provider = provider.clone();
                let receipt = created.creation_receipt().clone();
                tokio::spawn(async move { provider.stop_created_tab(&receipt).await })
            };
            let sent = request(&mut server).await;
            assert_eq!(sent["request"]["method"], "stopCreatedTab");
            assert_eq!(sent["request"]["tabId"], 23);
            control_result(
                &mut server,
                sent["request"]["id"].as_u64().unwrap(),
                json!({
                    "closed":true,"proof":wire_proof
                }),
            )
            .await;
            let cleanup = bounded(stop).await.unwrap().unwrap();
            assert_eq!(cleanup.evidence(), expected_evidence);
            let retire = {
                let provider = provider.clone();
                let claim = claim.clone();
                let cleanup = cleanup.clone();
                let drain = drain.clone();
                tokio::spawn(async move { provider.retire_claim(&claim, &cleanup, &drain).await })
            };
            let sent = request(&mut server).await;
            assert_eq!(sent["request"]["method"], "retireClaim");
            assert_eq!(sent["request"]["cleanupId"], cleanup.completion_id);
            control_result(
                &mut server,
                sent["request"]["id"].as_u64().unwrap(),
                json!({
                    "retired":true,"claim":claim.token
                }),
            )
            .await;
            bounded(retire).await.unwrap().unwrap();
            let mut unknown_identity = created.creation_receipt().clone();
            unknown_identity.tab_id = None;
            let stop = {
                let provider = provider.clone();
                tokio::spawn(async move { provider.stop_created_tab(&unknown_identity).await })
            };
            let sent = request(&mut server).await;
            assert!(sent["request"].get("tabId").is_none());
            control_result(
                &mut server,
                sent["request"]["id"].as_u64().unwrap(),
                json!({
                    "closed":true,"proof":"close_ack"
                }),
            )
            .await;
            let unknown_identity_cleanup = bounded(stop).await.unwrap().unwrap();
            assert!(
                matches!(bounded(provider.retire_claim(&claim, &unknown_identity_cleanup, &drain)).await,
            Err(ExtensionProviderError::NotDispatched { kind, .. }) if kind == "cleanup_unavailable")
            );
            inventory_barrier(&provider, &mut server).await;
            assert_eq!(provider.pending_completions().await.unwrap().len(), 2);
            provider.close().await;
        }
    }

    fn retirement_gc_metadata(claim: &str) -> ExtensionCdpRequestMetadata {
        ExtensionCdpRequestMetadata {
            claim: claim.to_owned(),
            wire_context: Some(ExtensionWireContext::new("folded-owner", "folded-turn").unwrap()),
            reply_disposition: ReplyDisposition::Observation,
            write_phase: Some(ExtensionCdpWritePhase::Written),
            effect: ExtensionCdpEffectCustody::Clear,
            atomic_terminal: ExtensionCdpAtomicTerminal::Delivered,
        }
    }

    fn retirement_gc_route(claim: &str) -> RuntimeRoute {
        let (outbound, _commands) = mpsc::channel(1);
        let (inbound, incoming) = mpsc::channel(1);
        let (close, _closed) = oneshot::channel();
        RuntimeRoute {
            claim: claim.to_owned(),
            inbound,
            connection: Arc::new(CdpConnection::from_extension_channels(
                outbound, incoming, close,
            )),
            request_contexts: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn matched_retirement_reclaims_130_turns_of_observation_metadata_only_for_that_claim() {
        let (sender, _commands) = mpsc::channel(ACTOR_QUEUE);
        let (events, _) = broadcast::channel(EVENT_QUEUE);
        let mut opening = HashMap::new();
        let mut routes = HashMap::from([(7, retirement_gc_route("unrelated-claim"))]);
        routes
            .get_mut(&7)
            .unwrap()
            .request_contexts
            .insert(1, retirement_gc_metadata("unrelated-claim"));
        let mut retired = HashMap::from([((8, 1), retirement_gc_metadata("unrelated-claim"))]);
        let mut pending = HashMap::new();
        let mut next_id = 1000;
        for turn in 0..130 {
            let claim = format!("observed-retire-turn-{turn}");
            let cleanup_id = 10 + turn * 2;
            let retire_id = cleanup_id + 1;
            // Written observations may have answered extension errors, leaving only
            // the already-delivered caller metadata after Host folds its error.
            routes
                .get_mut(&7)
                .unwrap()
                .request_contexts
                .insert(retire_id, retirement_gc_metadata(&claim));
            retired.insert((8, retire_id), retirement_gc_metadata(&claim));
            pending.insert(
                cleanup_id,
                PendingControl {
                    operation: ExtensionOperation::Detach {
                        claim: claim.clone(),
                        tab_id: 11,
                        target_id: "recorded-gc-target".into(),
                    },
                    context: None,
                    wire_context: None,
                    reply: None,
                    outcome: Some(ExtensionOperationOutcome::Result(
                        json!({"detached":true,"proof":"detach_ack"}),
                    )),
                },
            );
            let (reply, mut received) = oneshot::channel();
            pending.insert(
                retire_id,
                PendingControl {
                    operation: ExtensionOperation::RetireClaim {
                        claim: claim.clone(),
                        cleanup_id,
                    },
                    context: None,
                    wire_context: None,
                    reply: Some(reply),
                    outcome: None,
                },
            );
            apply_server(
                json!({"kind":"controlEvent","event":{"kind":"reply","data":{
                    "id":retire_id,"outcome":{"kind":"result","data":{"retired":true,"claim":claim}}
                }}}),
                &mut pending,
                &mut opening,
                RouteReceipts {
                    routes: &mut routes,
                    retired_contexts: &mut retired,
                },
                ProviderEventContext {
                    sender: &sender.downgrade(),
                    events: &events,
                    payload_budget: &ByteBudget::new(),
                },
                &mut next_id,
            )
            .unwrap();
            let reply = received.try_recv().unwrap();
            assert!(matches!(
                reply.outcome,
                ExtensionOperationOutcome::Result(_)
            ));
            assert_eq!(
                routes[&7].request_contexts.len(),
                1,
                "live metadata must not accumulate across turn {turn}"
            );
            assert_eq!(
                retired.len(),
                1,
                "retired metadata must not accumulate across turn {turn}"
            );
            assert!(routes[&7].request_contexts.contains_key(&1));
            assert!(retired.contains_key(&(8, 1)));
            assert!(!pending.contains_key(&retire_id));
            assert!(
                pending.contains_key(&cleanup_id),
                "GC must not acknowledge physical cleanup"
            );
            pending.remove(&cleanup_id); // Existing Host ACK happens after matched retirement.
        }
    }

    #[tokio::test]
    async fn malformed_unknown_and_new_debt_retirement_replies_keep_request_metadata() {
        for case in 0..10 {
            let (sender, _commands) = mpsc::channel(ACTOR_QUEUE);
            let (events, _) = broadcast::channel(EVENT_QUEUE);
            let (reply, mut received) = oneshot::channel();
            let mut pending = HashMap::new();
            pending.insert(
                2,
                PendingControl {
                    operation: if case == 6 {
                        ExtensionOperation::FenceCdp {
                            claim: "exact".into(),
                        }
                    } else {
                        ExtensionOperation::RetireClaim {
                            claim: "exact".into(),
                            cleanup_id: 1,
                        }
                    },
                    context: None,
                    wire_context: None,
                    reply: Some(reply),
                    outcome: None,
                },
            );
            let mut opening = HashMap::new();
            let mut routes = HashMap::from([(7, retirement_gc_route("exact"))]);
            routes
                .get_mut(&7)
                .unwrap()
                .request_contexts
                .insert(1, retirement_gc_metadata("exact"));
            let mut metadata = retirement_gc_metadata("exact");
            if case == 3 {
                metadata.effect = ExtensionCdpEffectCustody::NeedsReceipt;
            }
            if case == 4 {
                metadata.atomic_terminal =
                    ExtensionCdpAtomicTerminal::Undelivered("actual cause".into());
            }
            if case == 9 {
                metadata.atomic_terminal = ExtensionCdpAtomicTerminal::UnretainedLate(
                    ExtensionCdpCompletionOutcome::TransportFailure(
                        "actual late cause awaits Host receipt".into(),
                    ),
                );
            }
            let mut retired = HashMap::from([((8, 1), metadata)]);
            if case == 5 {
                pending.insert(
                    3,
                    PendingControl {
                        operation: ExtensionOperation::EffectsCleanup {
                            claim: "exact".into(),
                            effect: "extension_cdp_effect".into(),
                            cleanup_confirmed: false,
                            error: Some("unfolded effect".into()),
                        },
                        context: None,
                        wire_context: None,
                        reply: None,
                        outcome: Some(ExtensionOperationOutcome::Result(Value::Null)),
                    },
                );
            }
            if case == 7 {
                pending.remove(&2);
            }
            if case == 8 {
                pending.get_mut(&2).unwrap().outcome =
                    Some(ExtensionOperationOutcome::Result(Value::Null));
            }
            let outcome = match case {
                0 => json!({"kind":"unknown","data":{"reason":"unconfirmed retire"}}),
                1 => json!({"kind":"result","data":{"retired":false,"claim":"exact"}}),
                2 => json!({"kind":"result","data":{"retired":true,"claim":"foreign"}}),
                _ => json!({"kind":"result","data":{"retired":true,"claim":"exact"}}),
            };
            let mut next_id = 10;
            let result = apply_server(
                json!({"kind":"controlEvent","event":{"kind":"reply","data":{"id":2,"outcome":outcome}}}),
                &mut pending,
                &mut opening,
                RouteReceipts {
                    routes: &mut routes,
                    retired_contexts: &mut retired,
                },
                ProviderEventContext {
                    sender: &sender.downgrade(),
                    events: &events,
                    payload_budget: &ByteBudget::new(),
                },
                &mut next_id,
            );
            assert_eq!(routes[&7].request_contexts.len(), 1, "case {case}");
            assert_eq!(retired.len(), 1, "case {case}");
            if (7..=8).contains(&case) {
                assert!(result.is_err());
            } else {
                result.unwrap();
                let reply = received.try_recv().unwrap();
                if (3..=5).contains(&case) || case == 9 {
                    assert!(
                        matches!(reply.outcome, ExtensionOperationOutcome::Unknown { .. }),
                        "post-wire debt must not produce known success"
                    );
                }
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn retirement_refuses_unacknowledged_effect_and_orphan_facts_before_local_wire() {
        for effect in [true, false] {
            let (provider, mut server) = fixture();
            let claim = attach_fixture(&provider, &mut server, 23, "retire-unfolded").await;
            let drain = drained_fixture(&provider, &mut server, &claim).await;
            let cleanup = detached_fixture(&provider, &mut server, &claim).await;
            let event = if effect {
                json!({"kind":"effectsCleanup","data":{"claim":"retire-unfolded","effect":"extension_cdp_effect","cleanupConfirmed":false,"error":"actual retained effect"}})
            } else {
                json!({"kind":"orphanCdpCompletion","data":{"route":7,"claim":"retire-unfolded","id":9,"event":{"kind":"chromeMessage","data":{"id":9,"error":{"code":-32000,"message":"actual extension observation error"}}},"wireContext":null}})
            };
            local_ipc::write_json(&mut server, &json!({"kind":"controlEvent","event":event}))
                .await
                .unwrap();
            bounded(async {
                loop {
                    if provider.pending_completions().await.unwrap().len() == 2 {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await;
            assert!(
                matches!(bounded(provider.retire_claim(&claim,&cleanup,&drain)).await,
                Err(ExtensionProviderError::NotDispatched{kind,..})if kind=="retirement_unsettled")
            );
            assert_eq!(provider.pending_completions().await.unwrap().len(), 2);
            inventory_barrier(&provider, &mut server).await;
            provider.close().await;
        }
    }
    #[cfg(unix)]
    fn preparation_fixture() -> (ExtensionBrowserProvider, tokio::net::UnixStream) {
        let mut capabilities = maka_capabilities();
        capabilities["explicitClaimPreparation"] = json!(true);
        fixture_with_capabilities(capabilities)
    }

    #[cfg(unix)]
    fn preparation_view(
        provider: &ExtensionBrowserProvider,
        turn: &str,
    ) -> ExtensionBrowserProvider {
        provider
            .with_host_operation(ExtensionHostOperation {
                operation_id: format!("actual-host-operation-{turn}"),
                turn_id: turn.to_owned(),
            })
            .with_wire_context(ExtensionWireContext::new("actual-host-session", turn).unwrap())
    }

    #[cfg(unix)]
    fn preparation_document() -> ExtensionPreparationDocument {
        ExtensionPreparationDocument {
            frame_id: "actual-cdp-frame".into(),
            loader_id: "actual-cdp-loader".into(),
            url: "https://fixture.invalid/current?document=1".into(),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn explicit_preparation_requires_scope_capability_and_same_provider_before_dispatch() {
        let (provider, mut server) = preparation_fixture();
        let claim = attach_fixture(&provider, &mut server, 11, "scope-claim").await;
        let document = preparation_document();
        let policy = ExtensionPreparationPolicy::default();
        for view in [
            provider.clone(),
            provider.with_wire_context(ExtensionWireContext::new("session", "turn").unwrap()),
            provider.with_host_operation(ExtensionHostOperation {
                operation_id: "issued".into(),
                turn_id: "turn".into(),
            }),
        ] {
            assert!(
                matches!(view.prepare_claim(&claim,&document,&policy).await, Err(ExtensionProviderError::NotDispatched{kind,..}) if kind=="context_required")
            );
            assert!(
                matches!(view.create_popup_tab(&claim).await, Err(ExtensionProviderError::Refused{kind,..}) if kind=="context_required")
            );
        }
        let (legacy, mut legacy_wire) = fixture();
        let legacy_claim = attach_fixture(&legacy, &mut legacy_wire, 12, "legacy-claim").await;
        let legacy_view = preparation_view(&legacy, "legacy-turn");
        assert!(
            matches!(legacy_view.prepare_claim(&legacy_claim,&document,&policy).await, Err(ExtensionProviderError::NotDispatched{kind,..}) if kind=="unsupported")
        );
        let scoped = preparation_view(&provider, "new-turn");
        assert!(
            matches!(scoped.prepare_claim(&legacy_claim,&document,&policy).await, Err(ExtensionProviderError::NotDispatched{kind,..}) if kind=="claim_unavailable")
        );
        assert!(
            matches!(scoped.create_popup_tab(&legacy_claim).await, Err(ExtensionProviderError::Refused{kind,..}) if kind=="claim_unavailable")
        );
        provider.inner.retained_payload_budget.close();
        assert!(
            matches!(scoped.prepare_claim(&claim,&document,&policy).await, Err(ExtensionProviderError::NotDispatched{kind,..}) if kind=="document_budget")
        );
        assert!(provider.pending_operations().await.unwrap().is_empty());
        assert!(legacy.pending_operations().await.unwrap().is_empty());
        let mut bytes = [0_u8; 4];
        assert_eq!(
            server.try_read(&mut bytes).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(
            legacy_wire.try_read(&mut bytes).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        provider.close().await;
        legacy.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn preparation_wire_keeps_partial_flags_and_charged_document_until_last_proof_drops() {
        let (provider, mut server) = preparation_fixture();
        let claim = attach_fixture(&provider, &mut server, 11, "prepared-claim").await;
        let baseline = provider.inner.retained_payload_budget.available_bytes();
        let mut document = preparation_document();
        document.url.push_str(&"long-observed-query".repeat(1024));
        let policy = ExtensionPreparationPolicy {
            popup_enabled: true,
            header_enabled: false,
            headers: Vec::new(),
        };
        let scoped = preparation_view(&provider, "captured-turn");
        let expected_context = scoped.wire_context.clone().unwrap();
        let expected_operation = scoped.host_operation.clone().unwrap();
        let call = {
            let scoped = scoped.clone();
            let claim = claim.clone();
            let document = document.clone();
            let policy = policy.clone();
            tokio::spawn(async move { scoped.prepare_claim(&claim, &document, &policy).await })
        };
        let sent = request(&mut server).await;
        assert_eq!(sent["request"]["method"], "prepareClaim");
        assert_eq!(sent["request"]["claim"], claim.claim_id());
        assert_eq!(sent["request"]["document"], json!(document));
        assert_eq!(sent["request"]["policy"], json!(policy));
        assert_eq!(sent["wireContext"], json!(expected_context));
        assert!(sent["request"].get("wireContext").is_none());
        let id = sent["request"]["id"].as_u64().unwrap();
        control_result(&mut server,id,json!({"claim":claim.claim_id(),"preparationKey":"actual-provider-key","foreignInstalled":true,"popupInstalled":false})).await;
        let proof = bounded(call).await.unwrap().unwrap();
        assert_eq!(proof.document(), &document);
        assert_eq!(proof.wire_context(), &expected_context);
        assert!(proof.foreign_installed());
        assert!(
            !proof.popup_installed(),
            "partial actual flags must not become full readiness"
        );
        assert!(proof.popup_enabled());
        assert!(!proof.header_enabled());
        assert!(!proof.is_cleanup_only());
        let snapshot = provider.pending_operations().await.unwrap();
        assert_eq!(
            snapshot[0].host_operation.as_ref(),
            Some(&expected_operation)
        );
        assert_eq!(snapshot[0].wire_context.as_ref(), Some(&expected_context));
        assert!(
            matches!(&snapshot[0].operation, ExtensionOperation::PrepareClaim{document:binding,..} if binding.document()==&document)
        );
        let recovered = provider.recover_completion(id).await.unwrap();
        let ExtensionRecoveredOperation::ClaimPrepared(recovered) = recovered else {
            panic!("actual retained prep ACK must recover typed proof");
        };
        assert_eq!(recovered, proof);
        let charged = provider.inner.retained_payload_budget.available_bytes();
        assert!(charged < baseline);
        provider.acknowledge_completion(id).await.unwrap();
        assert!(provider.pending_operations().await.unwrap().is_empty());
        drop(proof);
        drop(snapshot);
        assert_eq!(
            provider.inner.retained_payload_budget.available_bytes(),
            charged,
            "last recovered binding still owns its permit"
        );
        drop(recovered);
        assert_eq!(
            provider.inner.retained_payload_budget.available_bytes(),
            baseline
        );
        assert_eq!(
            claim.tab_id(),
            11,
            "preparation upgrades the same physical claim"
        );
        let mut bytes = [0_u8; 4];
        assert_eq!(
            server.try_read(&mut bytes).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancelled_preparation_recovers_only_real_ack_under_original_document_and_turn() {
        let (provider, mut server) = preparation_fixture();
        let claim = attach_fixture(&provider, &mut server, 11, "late-prep-claim").await;
        let document = preparation_document();
        let scoped = preparation_view(&provider, "old-prep-turn");
        let old_operation = scoped.host_operation.clone();
        let old_context = scoped.wire_context.clone();
        let call = {
            let claim = claim.clone();
            let document = document.clone();
            tokio::spawn(async move {
                scoped
                    .prepare_claim(&claim, &document, &ExtensionPreparationPolicy::default())
                    .await
            })
        };
        let sent = request(&mut server).await;
        let id = sent["request"]["id"].as_u64().unwrap();
        call.abort();
        let _ = call.await;
        let _new_view = preparation_view(&provider, "new-current-turn");
        local_ipc::write_json(&mut server,&json!({"kind":"controlEvent","event":{"kind":"reply","data":{"id":id,"outcome":{"kind":"unknown","data":{"reason":"owner ended after actual prep acknowledgement","details":{"acknowledgedResult":{"claim":"late-prep-claim","preparationKey":"actual-late-prep-key","foreignInstalled":false,"popupInstalled":false}}}}}}})).await.unwrap();
        let ready = wait_ready(&provider).await;
        assert_eq!(ready[0].host_operation, old_operation);
        assert_eq!(ready[0].wire_context, old_context);
        let ExtensionRecoveredOperation::Unknown { custody, .. } =
            provider.recover_completion(id).await.unwrap()
        else {
            panic!("extension unknown remains unknown")
        };
        let proof = custody
            .preparation
            .expect("only actual acknowledgedResult can preserve prep proof");
        assert_eq!(proof.document(), &document);
        assert_eq!(Some(proof.wire_context()), old_context.as_ref());
        assert!(proof.is_cleanup_only());
        assert!(
            custody.claim.is_none(),
            "preparation cannot mint another physical acquisition"
        );
        assert!(!proof.foreign_installed() && !proof.popup_installed());
        let mut bytes = [0_u8; 4];
        assert_eq!(
            server.try_read(&mut bytes).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn popup_creation_late_unknown_keeps_existing_created_custody_without_replay() {
        for actual_tab in [false, true] {
            let (provider, mut server) = preparation_fixture();
            let claim = attach_fixture(&provider, &mut server, 11, "popup-opener").await;
            let scoped = preparation_view(&provider, "popup-service-turn");
            let original_context = scoped.wire_context.clone();
            let call = {
                let claim = claim.clone();
                tokio::spawn(async move { scoped.create_popup_tab(&claim).await })
            };
            let sent = request(&mut server).await;
            assert_eq!(sent["request"]["method"], "createPopupTab");
            assert_eq!(sent["request"]["claim"], claim.claim_id());
            assert!(
                sent["request"].get("url").is_none(),
                "Host navigates only after child claim"
            );
            let id = sent["request"]["id"].as_u64().unwrap();
            call.abort();
            let _ = call.await;
            let details = if actual_tab {
                json!({"acknowledgedResult":{"creation":"actual-popup-receipt","tab":{"id":55,"windowId":7,"url":"about:blank","active":false}}})
            } else {
                json!({"creation":"pending-popup-receipt"})
            };
            local_ipc::write_json(&mut server,&json!({"kind":"controlEvent","event":{"kind":"reply","data":{"id":id,"outcome":{"kind":"unknown","data":{"reason":"actual popup creation remains uncertain","details":details}}}}})).await.unwrap();
            let ready = wait_ready(&provider).await;
            assert_eq!(ready[0].wire_context, original_context);
            assert!(
                matches!(&ready[0].operation,ExtensionOperation::CreatePopupTab{opener_claim} if opener_claim==claim.claim_id())
            );
            let ExtensionRecoveredOperation::Unknown { custody, .. } =
                provider.recover_completion(id).await.unwrap()
            else {
                panic!("popup unknown never becomes successful creation")
            };
            if actual_tab {
                let created = custody.created.expect("actual acknowledged Created tab");
                assert_eq!(created.tab.id, 55);
                assert!(created.creation_receipt().is_cleanup_only());
            } else {
                let creation = custody.creation.expect("pending actual creation identity");
                assert_eq!(creation.tab_id(), None);
                assert!(creation.is_cleanup_only());
            }
            let mut bytes = [0_u8; 4];
            assert_eq!(
                server.try_read(&mut bytes).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            provider.close().await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn popup_metadata_and_fixed_cleanup_keep_captured_context_without_causal_host_operation()
    {
        let (provider, mut server) = preparation_fixture();
        let initial = provider.inner.retained_payload_budget.available_bytes();
        let mut events = provider.subscribe_events();
        let captured =
            ExtensionWireContext::new("actual-source-session", "old-prepared-turn").unwrap();
        local_ipc::write_json(&mut server,&json!({"kind":"controlEvent","event":{"kind":"popupRequested","data":{"claim":"issued-source","tabId":11,"url":"https://popup.invalid/path","wireContext":captured,"frameId":0,"documentId":"chrome-document-uuid","sourceUrl":"https://source.invalid/actual"}}})).await.unwrap();
        let ready = wait_ready(&provider).await;
        assert_eq!(ready[0].wire_context, Some(captured.clone()));
        assert!(
            ready[0].host_operation.is_none(),
            "metadata is not a causal Host input/service operation"
        );
        let ExtensionRecoveredOperation::PopupRequested(request) =
            provider.recover_completion(ready[0].id).await.unwrap()
        else {
            panic!("popup metadata remains typed metadata")
        };
        assert_eq!(request.tab_id(), 11);
        assert_eq!(request.frame_id(), Some(0));
        assert_eq!(request.document_id(), Some("chrome-document-uuid"));
        assert_eq!(request.source_url(), Some("https://source.invalid/actual"));
        assert_eq!(request.wire_context(), &captured);
        let received = bounded(async {
            loop {
                if let ExtensionProviderEvent::PopupRequested { request } =
                    events.recv().await.unwrap()
                {
                    break request;
                }
            }
        })
        .await;
        assert!(Arc::ptr_eq(&request.0, &received.0));
        provider.acknowledge_completion(ready[0].id).await.unwrap();
        assert!(provider.pending_operations().await.unwrap().is_empty());
        drop(ready);
        drop(received);
        assert!(
            provider.inner.retained_payload_budget.available_bytes() < initial,
            "last metadata clone keeps bytes charged"
        );
        drop(request);
        assert_eq!(
            provider.inner.retained_payload_budget.available_bytes(),
            initial
        );
        local_ipc::write_json(&mut server,&json!({"kind":"controlEvent","event":{"kind":"effectsCleanup","data":{"claim":"issued-source","effect":"fixed_preparation","cleanupConfirmed":false,"error":"actual cleanup unknown","wireContext":captured}}})).await.unwrap();
        let ready = wait_ready(&provider).await;
        assert_eq!(ready[0].wire_context, Some(captured.clone()));
        assert!(ready[0].host_operation.is_none());
        assert!(
            matches!(provider.recover_completion(ready[0].id).await.unwrap(),ExtensionRecoveredOperation::EffectsCleanup{wire_context:Some(actual),cleanup_confirmed:false,..} if actual==captured)
        );
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn prep_ack_must_keep_issued_claim_and_required_actual_flags() {
        for invalid in [
            json!({"claim":"foreign","preparationKey":"key","foreignInstalled":true,"popupInstalled":true}),
            json!({"claim":"claim-a","preparationKey":"key","foreignInstalled":true}),
        ] {
            let (provider, mut server) = preparation_fixture();
            let claim = attach_fixture(&provider, &mut server, 11, "claim-a").await;
            let scoped = preparation_view(&provider, "validation-turn");
            let call = tokio::spawn(async move {
                scoped
                    .prepare_claim(
                        &claim,
                        &preparation_document(),
                        &ExtensionPreparationPolicy::default(),
                    )
                    .await
            });
            let sent = request(&mut server).await;
            let id = sent["request"]["id"].as_u64().unwrap();
            control_result(&mut server, id, invalid).await;
            assert!(matches!(
                bounded(call).await.unwrap(),
                Err(ExtensionProviderError::Protocol(_))
            ));
            assert!(matches!(
                provider.recover_completion(id).await,
                Err(ExtensionProviderError::Protocol(_))
            ));
            assert_eq!(
                provider.pending_completions().await.unwrap().len(),
                1,
                "malformed ACK remains retained, never replayed or accepted"
            );
            provider.close().await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn actual_physical_cleanup_proof_survives_unknown_fixed_preparation_cleanup() {
        let (provider, mut server) = preparation_fixture();
        let claim = attach_fixture(&provider, &mut server, 11, "cleanup-claim").await;
        let scoped = preparation_view(&provider, "cleanup-turn");
        let call = {
            let claim = claim.clone();
            tokio::spawn(async move { scoped.detach_tab(&claim).await })
        };
        let sent = request(&mut server).await;
        let id = sent["request"]["id"].as_u64().unwrap();
        local_ipc::write_json(&mut server,&json!({"kind":"controlEvent","event":{"kind":"reply","data":{"id":id,"outcome":{"kind":"unknown","data":{"reason":"fixed preparation cleanup unknown","details":{"physicalProof":{"claim":"cleanup-claim","tabId":11,"detached":true,"proof":"detach_ack"}}}}}}})).await.unwrap();
        assert!(
            matches!(
                bounded(call).await.unwrap(),
                Err(ExtensionProviderError::OutcomeUnknown { .. })
            ),
            "whole cleanup remains unknown"
        );
        let ExtensionRecoveredOperation::Unknown { custody, .. } =
            provider.recover_completion(id).await.unwrap()
        else {
            panic!("fixed preparation Unknown must remain distinct")
        };
        let proof = custody
            .cleanup
            .expect("actual typed physical ACK is preserved");
        assert_eq!(proof.evidence(), CleanupEvidence::DetachAcknowledged);
        assert_eq!(proof.completion_id(), id);
        assert!(custody.preparation.is_none());
        assert!(
            custody.claim.is_none(),
            "physical cleanup is not another acquisition"
        );
        provider.close().await;
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn saturated_retained_document_budget_refuses_without_waiting_or_dispatching() {
        let mut capabilities = maka_capabilities();
        capabilities["explicitClaimPreparation"] = json!(true);
        let (provider, mut server) =
            fixture_with_capabilities_and_budget(capabilities, ByteBudget::test_with_capacity(8));
        let claim = attach_fixture(&provider, &mut server, 11, "budget-claim").await;
        let scoped = preparation_view(&provider, "budget-turn");
        assert!(
            matches!(bounded(scoped.prepare_claim(&claim,&preparation_document(),&ExtensionPreparationPolicy::default())).await,
            Err(ExtensionProviderError::NotDispatched{kind,..}) if kind=="document_budget")
        );
        assert!(provider.pending_operations().await.unwrap().is_empty());
        assert_eq!(
            provider.inner.retained_payload_budget.available_bytes(),
            8,
            "failed admission retains no permit"
        );
        let mut bytes = [0_u8; 4];
        assert_eq!(
            server.try_read(&mut bytes).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(!provider.is_closed());
        provider.close().await;
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn cleanup_constructor_checks_issued_identity_on_direct_and_retained_outcomes() {
        for method in ["detach", "closeTab"] {
            for wrapper in ["result", "acknowledgedResult", "physicalProof"] {
                for alias in ["claim", "tabId", "targetId", "absent"] {
                    let (provider, mut server) = preparation_fixture();
                    let claim = attach_fixture(&provider, &mut server, 11, "identity-claim").await;
                    let scoped = preparation_view(&provider, "cleanup-identity-turn");
                    let issued = claim.clone();
                    let call = tokio::spawn(async move {
                        if method == "detach" {
                            scoped.detach_tab(&issued).await
                        } else {
                            scoped.close_tab(&issued).await
                        }
                    });
                    let sent = request(&mut server).await;
                    let id = sent["request"]["id"].as_u64().unwrap();
                    let mut proof = if method == "detach" {
                        json!({"detached":true,"proof":"detach_ack"})
                    } else {
                        json!({"closed":true,"proof":"close_ack"})
                    };
                    if alias != "absent" {
                        proof[alias] = if alias == "tabId" {
                            json!(22)
                        } else {
                            json!("explicit-foreign-identity")
                        };
                    }
                    let outcome = if wrapper == "result" {
                        json!({"kind":"result","data":proof})
                    } else {
                        let mut details = json!({});
                        details[wrapper] = proof;
                        json!({"kind":"unknown","data":{"reason":"fixed effect cleanup remains unknown","details":details}})
                    };
                    local_ipc::write_json(&mut server,&json!({"kind":"controlEvent","event":{"kind":"reply","data":{"id":id,"outcome":outcome.clone()}}})).await.unwrap();
                    let direct = bounded(call).await.unwrap();
                    if wrapper == "result" && alias == "absent" {
                        assert!(
                            direct.is_ok(),
                            "source-backed ACK may omit redundant aliases"
                        );
                    } else if wrapper == "result" {
                        assert!(
                            matches!(direct, Err(ExtensionProviderError::Protocol(_))),
                            "{method}/{wrapper}/{alias} direct proof must not be constructed"
                        );
                    } else {
                        assert!(
                            matches!(direct, Err(ExtensionProviderError::OutcomeUnknown { .. })),
                            "whole cleanup Unknown remains Unknown"
                        );
                    }
                    let recovered = provider.recover_completion(id).await;
                    if alias == "absent" {
                        let proof = match recovered.unwrap() {
                            ExtensionRecoveredOperation::Cleanup(proof) => proof,
                            ExtensionRecoveredOperation::Unknown { custody, .. } => {
                                custody.cleanup.expect("real ACK remains available")
                            }
                            _ => panic!("unexpected recovered cleanup"),
                        };
                        assert_eq!(proof.completion_id(), id);
                    } else if wrapper == "result" {
                        assert!(
                            matches!(recovered, Err(ExtensionProviderError::Protocol(_))),
                            "{method}/{wrapper}/{alias} recovery cannot expose KnownCleanup before retirement"
                        );
                    } else {
                        let ExtensionRecoveredOperation::Unknown {
                            reason,
                            details,
                            custody,
                            ..
                        } = recovered.unwrap()
                        else {
                            panic!("invalid optional cleanup must preserve the overall Unknown");
                        };
                        assert_eq!(reason, "fixed effect cleanup remains unknown");
                        assert_eq!(details.as_ref(), outcome["data"].get("details"));
                        assert!(
                            custody.cleanup.is_none(),
                            "{method}/{wrapper}/{alias} cannot expose KnownCleanup before retirement"
                        );
                    }
                    let ready = provider.pending_completions().await.unwrap();
                    assert!(
                        matches!(&ready[0].operation,ExtensionOperation::Detach{claim:token,tab_id:11,target_id}|ExtensionOperation::CloseTab{claim:token,tab_id:11,target_id} if token==claim.claim_id()&&target_id==claim.target_id())
                    );
                    assert_eq!(
                        ready.len(),
                        1,
                        "actual invalid or unknown fact remains retained"
                    );
                    let mut bytes = [0_u8; 4];
                    assert_eq!(
                        server.try_read(&mut bytes).unwrap_err().kind(),
                        std::io::ErrorKind::WouldBlock
                    );
                    provider.close().await;
                }
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn created_cleanup_constructor_rejects_contradictory_known_creation_or_tab() {
        for alias in ["creation", "tabId"] {
            let (provider, mut server) = preparation_fixture();
            let create = {
                let provider = provider.clone();
                tokio::spawn(async move { provider.create_tab(None).await })
            };
            let sent = request(&mut server).await;
            control_result(
                &mut server,
                sent["request"]["id"].as_u64().unwrap(),
                json!({"creation":"issued-created","tab":{"id":55,"url":"about:blank"}}),
            )
            .await;
            let created = bounded(create).await.unwrap().unwrap();
            provider
                .acknowledge_completion(created.completion_id())
                .await
                .unwrap();
            let stop = {
                let provider = provider.clone();
                let receipt = created.creation_receipt().clone();
                tokio::spawn(async move { provider.stop_created_tab(&receipt).await })
            };
            let sent = request(&mut server).await;
            let id = sent["request"]["id"].as_u64().unwrap();
            let mut proof = json!({"closed":true,"proof":"close_ack"});
            proof[alias] = if alias == "creation" {
                json!("foreign-created")
            } else {
                json!(56)
            };
            control_result(&mut server, id, proof).await;
            assert!(matches!(
                bounded(stop).await.unwrap(),
                Err(ExtensionProviderError::Protocol(_))
            ));
            assert!(matches!(
                provider.recover_completion(id).await,
                Err(ExtensionProviderError::Protocol(_))
            ));
            provider.close().await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn session_tab_selector_requires_captured_context_and_supported_contract_without_dispatch(
    ) {
        for supported in [false, true] {
            let mut capabilities = maka_capabilities();
            if supported {
                capabilities["sessionTabResolution"] = json!(true);
                capabilities["sessionPreparation"] = json!("provider_session");
            }
            let (provider, mut server) = fixture_with_capabilities(capabilities);
            assert!(
                matches!(provider.resolve_session_tab("2001").await,Err(ExtensionProviderError::Refused{kind,..}) if kind=="context_required")
            );
            assert!(
                matches!(provider.prepare_session_tab(2001).await,Err(ExtensionProviderError::Refused{kind,..}) if kind=="context_required")
            );
            if !supported {
                let scoped = provider.with_wire_context(
                    ExtensionWireContext::new("managed-owner", "turn-current").unwrap(),
                );
                assert!(
                    matches!(scoped.resolve_session_tab("2001").await,Err(ExtensionProviderError::NotDispatched{kind,..}) if kind=="unsupported")
                );
                assert!(
                    matches!(scoped.prepare_session_tab(2001).await,Err(ExtensionProviderError::NotDispatched{kind,..}) if kind=="unsupported")
                );
            }
            let mut bytes = [0u8; 1];
            assert_eq!(
                server.try_read(&mut bytes).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            assert!(provider.pending_completions().await.unwrap().is_empty());
            // The ordinary metadata method stays compatible with the old contract.
            let plain = provider.clone();
            let call = tokio::spawn(async move { plain.resolve_user_tab("2001").await });
            let sent = request(&mut server).await;
            assert!(sent["request"].get("sessionOnly").is_none());
            control_result(
                &mut server,
                sent["request"]["id"].as_u64().unwrap(),
                json!({"tab":{"id":2001}}),
            )
            .await;
            assert_eq!(bounded(call).await.unwrap().unwrap().id, 2001);
            provider.close().await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn session_tab_selector_uses_existing_methods_and_preserves_original_request_context() {
        let mut capabilities = maka_capabilities();
        capabilities["sessionTabResolution"] = json!(true);
        capabilities["sessionPreparation"] = json!("provider_session");
        let (provider, mut server) = fixture_with_capabilities(capabilities);
        let wire = ExtensionWireContext::new("managed-owner", "turn-A").unwrap();
        let scoped = provider.with_wire_context(wire.clone());
        let resolving = scoped.clone();
        let call = tokio::spawn(async move { resolving.resolve_session_tab("2001").await });
        let sent = request(&mut server).await;
        let id = sent["request"]["id"].as_u64().unwrap();
        assert_eq!(
            sent["request"],
            json!({"method":"resolve","id":id,"rawId":"2001","sessionOnly":true})
        );
        assert_eq!(sent["wireContext"], serde_json::to_value(&wire).unwrap());
        let _other_view = provider
            .with_wire_context(ExtensionWireContext::new("managed-owner", "turn-B").unwrap());
        control_result(
            &mut server,
            id,
            json!({"tab":{"id":2001},"sessionOnly":true}),
        )
        .await;
        assert_eq!(bounded(call).await.unwrap().unwrap().id, 2001);
        assert!(
            provider.pending_completions().await.unwrap().is_empty(),
            "metadata never mints a retained mutation or claim"
        );
        let preparing = scoped.clone();
        let call = tokio::spawn(async move { preparing.prepare_session_tab(2001).await });
        let sent = request(&mut server).await;
        let id = sent["request"]["id"].as_u64().unwrap();
        assert_eq!(
            sent["request"],
            json!({"method":"prepareUserTab","id":id,"tabId":2001,"sessionOnly":true})
        );
        assert_eq!(sent["wireContext"], serde_json::to_value(&wire).unwrap());
        control_result(
            &mut server,
            id,
            json!({"tab":{"id":2001},"sessionOnly":true}),
        )
        .await;
        let prepared = bounded(call).await.unwrap().unwrap();
        assert_eq!(prepared.tab.id, 2001);
        assert_eq!(prepared.completion_id(), id);
        let snapshot = provider.pending_completions().await.unwrap();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].wire_context, Some(wire));
        assert!(matches!(
            snapshot[0].operation,
            ExtensionOperation::PrepareSessionTab { tab_id: 2001 }
        ));
        assert!(
            matches!(provider.recover_completion(id).await.unwrap(),ExtensionRecoveredOperation::SessionPrepared(value) if value.tab.id==2001)
        );
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn session_tab_selector_never_accepts_an_ordinary_success_as_purpose_confirmation() {
        for prepare in [false, true] {
            for echo in [None, Some(json!(false)), Some(json!("true"))] {
                let mut capabilities = maka_capabilities();
                capabilities["sessionTabResolution"] = json!(true);
                capabilities["sessionPreparation"] = json!("provider_session");
                let (provider, mut server) = fixture_with_capabilities(capabilities);
                let scoped = provider
                    .with_wire_context(ExtensionWireContext::new("managed-owner", "turn").unwrap());
                let call = tokio::spawn(async move {
                    if prepare {
                        scoped.prepare_session_tab(2001).await.map(|tab| tab.tab.id)
                    } else {
                        scoped.resolve_session_tab("2001").await.map(|tab| tab.id)
                    }
                });
                let sent = request(&mut server).await;
                let id = sent["request"]["id"].as_u64().unwrap();
                let mut result = json!({"tab":{"id":2001},"normalized":false});
                if let Some(echo) = echo {
                    result["sessionOnly"] = echo;
                }
                control_result(&mut server, id, result).await;
                assert!(
                    matches!(bounded(call).await.unwrap(),Err(ExtensionProviderError::Protocol(message)) if message=="session-only result lacks its exact selector acknowledgement")
                );
                if prepare {
                    for _ in 0..2 {
                        assert!(
                            matches!(provider.recover_completion(id).await,Err(ExtensionProviderError::Protocol(message)) if message=="session-only result lacks its exact selector acknowledgement")
                        );
                    }
                    let snapshot = provider.pending_completions().await.unwrap();
                    assert_eq!(snapshot.len(), 1);
                    assert!(matches!(
                        snapshot[0].operation,
                        ExtensionOperation::PrepareSessionTab { tab_id: 2001 }
                    ));
                } else {
                    assert!(provider.pending_completions().await.unwrap().is_empty());
                }
                let mut bytes = [0u8; 1];
                assert_eq!(
                    server.try_read(&mut bytes).unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock,
                    "receipt inspection never replays preparation"
                );
                provider.close().await;
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn session_preparation_unknown_is_retained_as_unknown_under_its_original_scope() {
        let mut capabilities = chatgpt_capabilities();
        capabilities["sessionTabResolution"] = json!(true);
        capabilities["sessionPreparation"] = json!("provider_session");
        let (provider, mut server) = fixture_with_capabilities(capabilities);
        let wire = ExtensionWireContext::new("managed-owner", "unknown-turn").unwrap();
        let scoped = provider.with_wire_context(wire.clone());
        let call = tokio::spawn(async move { scoped.prepare_session_tab(2001).await });
        let sent = request(&mut server).await;
        let id = sent["request"]["id"].as_u64().unwrap();
        let details = json!({"remoteCode":1,"remoteMessage":"mixed activation or Chrome failure"});
        local_ipc::write_json(&mut server,&json!({"kind":"controlEvent","event":{"kind":"reply","data":{"id":id,"outcome":{"kind":"unknown","data":{"reason":"actual managed failure","details":details}}}}})).await.unwrap();
        assert!(
            matches!(bounded(call).await.unwrap(),Err(ExtensionProviderError::OutcomeUnknown{reason,..}) if reason=="actual managed failure")
        );
        let snapshot = provider.pending_completions().await.unwrap();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].wire_context, Some(wire));
        assert!(
            matches!(provider.recover_completion(id).await.unwrap(),ExtensionRecoveredOperation::Unknown{operation:ExtensionOperation::PrepareSessionTab{tab_id:2001},reason,details:Some(actual),..} if reason=="actual managed failure" && actual==details)
        );
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn committed_url_requires_captured_context_and_its_supported_contract_without_dispatch() {
        for supported in [false, true] {
            let mut capabilities = maka_capabilities();
            capabilities["sessionCommittedUrl"] = json!(supported);
            let (provider, server) = fixture_with_capabilities(capabilities);
            assert!(
                matches!(provider.committed_session_tab_url("2001").await,Err(ExtensionProviderError::Refused{kind,..}) if kind=="context_required")
            );
            if !supported {
                let scoped = provider
                    .with_wire_context(ExtensionWireContext::new("url-owner", "url-turn").unwrap());
                assert!(
                    matches!(scoped.committed_session_tab_url("2001").await,Err(ExtensionProviderError::NotDispatched{kind,..}) if kind=="unsupported")
                );
            }
            let mut bytes = [0u8; 1];
            assert_eq!(
                server.try_read(&mut bytes).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            assert!(provider.pending_completions().await.unwrap().is_empty());
            provider.close().await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn committed_url_preserves_only_actual_string_including_empty_and_old_call_context() {
        for actual in ["https://committed.test/path", "chrome://newtab/", ""] {
            let mut capabilities = maka_capabilities();
            capabilities["sessionCommittedUrl"] = json!(true);
            let (provider, mut server) = fixture_with_capabilities(capabilities);
            let wire = ExtensionWireContext::new("url-owner", "turn-A").unwrap();
            let scoped = provider.with_wire_context(wire.clone());
            let call = tokio::spawn(async move { scoped.committed_session_tab_url("2001").await });
            let sent = request(&mut server).await;
            let id = sent["request"]["id"].as_u64().unwrap();
            assert_eq!(
                sent["request"],
                json!({"method":"resolve","id":id,"rawId":"2001","sessionOnly":true,"committedUrlOnly":true})
            );
            assert_eq!(sent["wireContext"], serde_json::to_value(&wire).unwrap());
            let _later_view = provider
                .with_wire_context(ExtensionWireContext::new("url-owner", "turn-B").unwrap());
            control_result(&mut server,id,json!({"url":actual,"pendingUrl":"https://not-committed.test/","tab":{"id":2001,"title":"not-returned","url":"https://not-actual.test/"},"sessionOnly":true,"committedUrlOnly":true})).await;
            let value = bounded(call).await.unwrap().unwrap();
            assert_eq!(value.as_str(), actual);
            // No retained transport receipt does not prove Chatgpt activation was effect-free.
            assert!(provider.pending_completions().await.unwrap().is_empty());
            provider.close().await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn committed_url_never_substitutes_pending_or_full_metadata_or_ignores_purpose() {
        for value in [
            json!({"url":"https://actual.test/","sessionOnly":true}),
            json!({"url":"https://actual.test/","sessionOnly":false,"committedUrlOnly":true}),
            json!({"url":"https://actual.test/","sessionOnly":true,"committedUrlOnly":"true"}),
            json!({"pendingUrl":"https://pending.test/","tab":{"url":"https://not-field.test/"},"sessionOnly":true,"committedUrlOnly":true}),
            json!({"url":null,"pendingUrl":"https://pending.test/","sessionOnly":true,"committedUrlOnly":true}),
            json!({"url":17,"sessionOnly":true,"committedUrlOnly":true}),
        ] {
            let mut capabilities = maka_capabilities();
            capabilities["sessionCommittedUrl"] = json!(true);
            let (provider, mut server) = fixture_with_capabilities(capabilities);
            let scoped =
                provider.with_wire_context(ExtensionWireContext::new("url-owner", "turn").unwrap());
            let call = tokio::spawn(async move { scoped.committed_session_tab_url("2001").await });
            let sent = request(&mut server).await;
            control_result(&mut server, sent["request"]["id"].as_u64().unwrap(), value).await;
            assert!(matches!(
                bounded(call).await.unwrap(),
                Err(ExtensionProviderError::Protocol(_))
            ));
            let mut bytes = [0u8; 1];
            assert_eq!(
                server.try_read(&mut bytes).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock,
                "no getter or preparer fallback"
            );
            provider.close().await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn committed_url_activation_unknown_keeps_typed_unknown_instead_of_chrome_rejection() {
        let mut capabilities = chatgpt_capabilities();
        capabilities["sessionCommittedUrl"] = json!(true);
        let (provider, mut server) = fixture_with_capabilities(capabilities);
        let scoped = provider
            .with_wire_context(ExtensionWireContext::new("url-owner", "uncertain-turn").unwrap());
        let call = tokio::spawn(async move { scoped.committed_session_tab_url("2001").await });
        let sent = request(&mut server).await;
        let id = sent["request"]["id"].as_u64().unwrap();
        let details = json!({"remoteMethod":"getCommittedTabUrl","remoteCode":1});
        local_ipc::write_json(&mut server,&json!({"kind":"controlEvent","event":{"kind":"reply","data":{"id":id,"outcome":{"kind":"unknown","data":{"reason":"actual activation remains uncertain","details":details}}}}})).await.unwrap();
        assert!(
            matches!(bounded(call).await.unwrap(),Err(ExtensionProviderError::OutcomeUnknown{reason,details:Some(actual),..}) if reason=="actual activation remains uncertain" && actual==details)
        );
        // The Chatgpt adapter and Host retain session/effect custody independently.
        assert!(provider.pending_completions().await.unwrap().is_empty());
        provider.close().await;
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn session_inventory_requires_its_captured_context_capability_and_valid_candidates() {
        let (provider, server) = fixture_with_capabilities(maka_capabilities());
        assert!(matches!(provider.list_session_tabs(&[]).await,
            Err(ExtensionProviderError::Refused{kind,..}) if kind=="context_required"));
        let scoped = provider
            .with_wire_context(ExtensionWireContext::new("inventory-owner", "turn-A").unwrap());
        assert!(matches!(scoped.list_session_tabs(&[]).await,
            Err(ExtensionProviderError::NotDispatched{kind,..}) if kind=="unsupported"));
        let mut bytes = [0u8; 1];
        assert_eq!(
            server.try_read(&mut bytes).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        provider.close().await;
        let mut caps = maka_capabilities();
        caps["sessionTabInventory"] = json!(true);
        let (provider, server) = fixture_with_capabilities(caps);
        let scoped = provider
            .with_wire_context(ExtensionWireContext::new("inventory-owner", "turn-A").unwrap());
        for ids in [vec![0], vec![9_007_199_254_740_992], vec![2, 2]] {
            assert!(matches!(scoped.list_session_tabs(&ids).await,
                Err(ExtensionProviderError::Refused{kind,..}) if kind=="invalid_request"));
        }
        assert_eq!(
            server.try_read(&mut bytes).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn session_inventory_is_one_existing_inventory_request_even_empty_and_keeps_real_rows() {
        let mut caps = maka_capabilities();
        caps["sessionTabInventory"] = json!(true);
        let (provider, mut server) = fixture_with_capabilities(caps);
        let wire = ExtensionWireContext::new("inventory-owner", "turn-A").unwrap();
        for ids in [vec![], vec![2001, 51]] {
            let scoped = provider.with_wire_context(wire.clone());
            let expected = ids.clone();
            let call = tokio::spawn(async move { scoped.list_session_tabs(&ids).await });
            let sent = request(&mut server).await;
            let id = sent["request"]["id"].as_u64().unwrap();
            assert_eq!(
                sent["request"],
                json!({"method":"inventory","id":id,"sessionOnly":true,"knownTabIds":expected})
            );
            assert_eq!(sent["wireContext"], serde_json::to_value(&wire).unwrap());
            let _next = provider
                .with_wire_context(ExtensionWireContext::new("inventory-owner", "turn-B").unwrap());
            let rows: Vec<_> = (1..=1002)
                .rev()
                .map(|id| json!({"id":id,"title":format!("actual-{id}")}))
                .collect();
            control_result(&mut server, id, json!({"tabs":rows,"sessionOnly":true})).await;
            let actual = bounded(call).await.unwrap().unwrap();
            assert_eq!(actual.len(), 1002);
            assert_eq!(actual[0].id, 1002);
            assert_eq!(actual[1001].id, 1);
            assert!(
                provider.pending_completions().await.unwrap().is_empty(),
                "metadata is not acquisition or retained mutation"
            );
        }
        provider.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn session_inventory_rejects_wrong_purpose_and_malformed_rows_without_fallback() {
        for result in [
            json!({"tabs":[]}),
            json!({"tabs":[],"sessionOnly":false}),
            json!({"tabs":[],"sessionOnly":"true"}),
            json!({"tabs":[{"id":2},{"id":2}],"sessionOnly":true}),
            json!({"tabs":[{"id":0}],"sessionOnly":true}),
            json!({"tabs":{},"sessionOnly":true}),
        ] {
            let mut caps = maka_capabilities();
            caps["sessionTabInventory"] = json!(true);
            let (provider, mut server) = fixture_with_capabilities(caps);
            let scoped = provider
                .with_wire_context(ExtensionWireContext::new("inventory-owner", "turn-A").unwrap());
            let call = tokio::spawn(async move { scoped.list_session_tabs(&[]).await });
            let sent = request(&mut server).await;
            control_result(&mut server, sent["request"]["id"].as_u64().unwrap(), result).await;
            assert!(matches!(
                bounded(call).await.unwrap(),
                Err(ExtensionProviderError::Protocol(_))
            ));
            let mut bytes = [0u8; 1];
            assert_eq!(
                server.try_read(&mut bytes).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            provider.close().await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dropped_inventory_observer_keeps_original_pending_until_its_terminal_wake() {
        let mut caps = chatgpt_capabilities();
        caps["sessionTabInventory"] = json!(true);
        let (provider, mut server) = fixture_with_capabilities(caps);
        let mut events = provider.subscribe_events();
        let operation = ExtensionHostOperation {
            operation_id: "held-inventory".into(),
            turn_id: "captured-turn".into(),
        };
        let wire = ExtensionWireContext::new("inventory-owner", "captured-turn").unwrap();
        let scoped = provider
            .with_host_operation(operation.clone())
            .with_wire_context(wire.clone());
        let observer = tokio::spawn(async move { scoped.list_session_tabs(&[]).await });
        let sent = request(&mut server).await;
        let id = sent["request"]["id"].as_u64().unwrap();
        assert_eq!(
            sent["request"],
            json!({"method":"inventory","id":id,"sessionOnly":true,"knownTabIds":[]})
        );
        observer.abort();
        assert!(bounded(observer).await.unwrap_err().is_cancelled());
        let pending = provider.pending_operations().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, id);
        assert!(matches!(
            pending[0].operation,
            ExtensionOperation::SessionInventory
        ));
        assert_eq!(pending[0].host_operation.as_ref(), Some(&operation));
        assert_eq!(pending[0].wire_context.as_ref(), Some(&wire));
        assert!(
            pending[0].outcome.is_none(),
            "observer Drop is not extension terminal"
        );
        assert!(matches!(
            events.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));

        // A different real observation can wake the same subscriber. It cannot
        // retire the held operation or replace its captured context/turn.
        let unrelated = {
            let provider = provider.clone();
            tokio::spawn(async move { provider.list_user_tabs().await })
        };
        let other = request(&mut server).await;
        let other_id = other["request"]["id"].as_u64().unwrap();
        assert_ne!(other_id, id);
        assert_eq!(
            other["request"],
            json!({"method":"inventory","id":other_id})
        );
        control_result(&mut server, other_id, json!({"tabs":[]})).await;
        assert!(bounded(unrelated).await.unwrap().unwrap().is_empty());
        assert!(matches!(
            bounded(events.recv()).await.unwrap(),
            ExtensionProviderEvent::PendingOperationsChanged
        ));
        let pending = provider.pending_operations().await.unwrap();
        assert_eq!(pending.len(), 1, "unrelated wake cannot authorize Finish");
        assert_eq!(pending[0].id, id);
        assert_eq!(pending[0].host_operation.as_ref(), Some(&operation));
        assert_eq!(pending[0].wire_context.as_ref(), Some(&wire));
        assert!(pending[0].outcome.is_none());

        // Complete the original written ID exactly once. No observer is left,
        // but the actor must still publish a wake after removing this pending.
        control_result(&mut server, id, json!({"tabs":[],"sessionOnly":true})).await;
        assert!(matches!(
            bounded(events.recv()).await.unwrap(),
            ExtensionProviderEvent::PendingOperationsChanged
        ));
        assert!(provider.pending_operations().await.unwrap().is_empty());
        provider.close().await;
        assert!(
            bounded(local_ipc::read_json(&mut server))
                .await
                .unwrap()
                .is_none(),
            "one held request plus one unrelated observation; no resend or Finish"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn observation_terminal_wake_does_not_clear_a_retained_mutation_unknown() {
        let mut caps = chatgpt_capabilities();
        caps["sessionTabInventory"] = json!(true);
        let (provider, mut server) = fixture_with_capabilities(caps);
        let mut events = provider.subscribe_events();
        let operation = ExtensionHostOperation {
            operation_id: "unknown-created-effect".into(),
            turn_id: "captured-turn".into(),
        };
        let wire = ExtensionWireContext::new("inventory-owner", "captured-turn").unwrap();
        let scoped = provider
            .with_host_operation(operation.clone())
            .with_wire_context(wire.clone());
        let mutation = tokio::spawn(async move { scoped.create_tab(None).await });
        let sent = request(&mut server).await;
        let id = sent["request"]["id"].as_u64().unwrap();
        assert_eq!(sent["request"]["method"], "createTab");
        let details = json!({"cause":"fixture-effect-still-unknown"});
        local_ipc::write_json(
            &mut server,
            &json!({
                "kind":"controlEvent","event":{"kind":"reply","data":{
                    "id":id,"outcome":{"kind":"unknown","data":{
                        "reason":"actual mutation remains unknown","details":details
                    }}
                }}
            }),
        )
        .await
        .unwrap();
        assert!(matches!(bounded(mutation).await.unwrap(),
            Err(ExtensionProviderError::OutcomeUnknown { reason, .. })
                if reason == "actual mutation remains unknown"));
        assert!(matches!(bounded(events.recv()).await.unwrap(),
            ExtensionProviderEvent::CompletionReady { id: ready } if ready == id));

        let scoped = provider
            .with_host_operation(ExtensionHostOperation {
                operation_id: "independent-observation".into(),
                turn_id: "captured-turn".into(),
            })
            .with_wire_context(wire.clone());
        let observation = tokio::spawn(async move { scoped.list_session_tabs(&[]).await });
        let sent = request(&mut server).await;
        let observed_id = sent["request"]["id"].as_u64().unwrap();
        assert_ne!(observed_id, id);
        assert_eq!(sent["request"]["method"], "inventory");
        control_result(
            &mut server,
            observed_id,
            json!({"tabs":[],"sessionOnly":true}),
        )
        .await;
        assert!(bounded(observation).await.unwrap().unwrap().is_empty());
        assert!(matches!(
            bounded(events.recv()).await.unwrap(),
            ExtensionProviderEvent::PendingOperationsChanged
        ));
        let pending = provider.pending_operations().await.unwrap();
        assert_eq!(
            pending.len(),
            1,
            "wake does not ACK or clear mutation custody"
        );
        assert_eq!(pending[0].id, id);
        assert_eq!(pending[0].host_operation.as_ref(), Some(&operation));
        assert_eq!(pending[0].wire_context.as_ref(), Some(&wire));
        assert!(matches!(&pending[0].outcome,
            Some(ExtensionOperationOutcome::Unknown { reason, details: Some(actual) })
                if reason == "actual mutation remains unknown" && actual == &details));
        assert!(matches!(provider.recover_completion(id).await.unwrap(),
            ExtensionRecoveredOperation::Unknown { reason, details: Some(actual), .. }
                if reason == "actual mutation remains unknown" && actual == details));
        provider.close().await;
        assert!(
            bounded(local_ipc::read_json(&mut server))
                .await
                .unwrap()
                .is_none(),
            "an observation wake must not send mutation replay or Finish"
        );
    }

    include!("extension_fixed_session_tests.rs");

    #[cfg(unix)]
    #[tokio::test]
    async fn trusted_no_dispatch_is_bound_retained_and_independent_of_registration() {
        for trusted in [false, true] {
            let (provider, mut server) = preparation_fixture();
            let claim = attach_fixture(&provider, &mut server, 11, "phase-claim").await;
            let base = preparation_view(&provider, "phase-turn");
            let (scoped, registration) = base.observe_session_requests();
            let actual = scoped.clone();
            let document = preparation_document();
            let call = tokio::spawn(async move {
                actual
                    .prepare_claim(&claim, &document, &ExtensionPreparationPolicy::default())
                    .await
            });
            let sent = request(&mut server).await;
            let id = sent["request"]["id"].as_u64().unwrap();
            assert_eq!(sent["request"]["method"], "prepareClaim");
            local_ipc::write_json(
                &mut server,
                &json!({
                    "kind":"controlEvent", "event":{"kind":"reply", "data":{
                        "id":id, "outcome":{
                            "kind":if trusted {"notDispatched"} else {"connectorRejected"},
                            "data":{"kind":"not_dispatched","message":"not sent",
                                "details":{"provenance":"local_refusal"}}
                        }
                    }}
                }),
            )
            .await
            .unwrap();
            let error = bounded(call).await.unwrap().unwrap_err();
            assert_eq!(
                registration.count(),
                1,
                "physical NoDispatch never refunds an already registered logical request"
            );
            let proof = scoped.undispatched_control(&error);
            assert_eq!(proof.is_some(), trusted);
            if let Some(proof) = proof {
                assert_eq!(proof.method(), "prepareClaim");
                assert!(preparation_view(&provider, "other-turn")
                    .undispatched_control(&error)
                    .is_none());
            } else {
                assert!(
                    matches!(error, ExtensionProviderError::Refused {ref kind,..} if kind == "not_dispatched")
                );
            }
            let ready = provider.pending_completions().await.unwrap();
            assert_eq!(ready.len(), 1);
            assert_eq!(ready[0].id, id);
            let recovered = provider.recover_completion(id).await.unwrap();
            if trusted {
                assert!(
                    matches!(recovered, ExtensionRecoveredOperation::NotDispatched {kind,..} if kind == "not_dispatched")
                );
            } else {
                assert!(
                    matches!(recovered, ExtensionRecoveredOperation::Refused {kind,..} if kind == "not_dispatched")
                );
            }
            assert_eq!(
                provider.pending_completions().await.unwrap().len(),
                1,
                "reading phase proof never acknowledges the actual operation receipt"
            );
            provider.acknowledge_completion(id).await.unwrap();
            inventory_barrier(&provider, &mut server).await;
            assert!(provider.pending_operations().await.unwrap().is_empty());
            provider.close().await;
        }
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn ordered_raw_metadata_reply_crosses_the_existing_ipc_and_exact_context() {
        let (provider, mut server) = fixture();
        let claim = attach_fixture(&provider, &mut server, 170, "raw-metadata-claim").await;
        let connection = open_fixture(&provider, &mut server, claim, 170).await;
        let original = ExtensionWireContext::new("raw-owner", "raw-turn").unwrap();
        let call = {
            let context = original.clone();
            tokio::spawn(async move {
                connection
                    .call_metadata_observation_with_extension_context(
                        &context,
                        None,
                        super::super::cdp_ws::CdpMetadataRead::DescribeNode,
                        json!({"objectId":"element"}),
                    )
                    .await
            })
        };
        let sent = request(&mut server).await;
        let body = r#"{"node":{"backendNodeId":17,"attributes":["title","\ud800"]}}"#;
        let text = format!(r#"{{"id":{},"result":{body}}}"#, sent["message"]["id"]);
        ordered_message_fixture(
            &mut server,
            170,
            "raw-metadata-claim",
            json!({"kind":"chromeJson","data":text}),
            Some(&original),
        )
        .await;
        assert_eq!(bounded(call).await.unwrap().unwrap(), body);
        assert!(provider.pending_operations().await.unwrap().is_empty());
        provider.close().await;
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn raw_actual_reply_after_required_close_retains_original_context_and_sticky_unknown() {
        let (provider, mut server) = fixture();
        let claim = attach_fixture(&provider, &mut server, 171, "raw-retired-claim").await;
        let connection = open_fixture(&provider, &mut server, claim, 171).await;
        let original = ExtensionWireContext::new("raw-owner", "old-raw-turn").unwrap();
        let call = {
            let context = original.clone();
            tokio::spawn(async move {
                connection
                    .call_with_extension_context(
                        &context,
                        None,
                        "DOM.describeNode",
                        json!({"objectId":"original-element"}),
                    )
                    .await
            })
        };
        let sent = request(&mut server).await;
        call.abort();
        let _ = call.await;
        assert_eq!(request(&mut server).await["kind"], "closeCdp");
        let _new_view = provider
            .with_wire_context(ExtensionWireContext::new("raw-owner", "new-raw-turn").unwrap());
        let text = format!(
            r#"{{"id":{},"result":{{"node":{{"backendNodeId":17,"attributes":["title","\ud800"]}}}}}}"#,
            sent["message"]["id"]
        );
        ordered_message_fixture(
            &mut server,
            171,
            "raw-retired-claim",
            json!({"kind":"chromeJson","data":text}),
            Some(&original),
        )
        .await;
        let ready = bounded(async {
            loop {
                let ready = provider.pending_completions().await.unwrap();
                if ready.iter().any(|entry| {
                    matches!(
                        &entry.operation,
                        ExtensionOperation::OrphanCdpCompletion { .. }
                    )
                }) {
                    break ready;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        let orphan = ready
            .iter()
            .find(|entry| {
                matches!(
                    &entry.operation,
                    ExtensionOperation::OrphanCdpCompletion { .. }
                )
            })
            .unwrap();
        assert_eq!(orphan.wire_context, Some(original));
        assert!(
            matches!(&orphan.operation, ExtensionOperation::OrphanCdpCompletion { event:ExtensionCdpCompletionOutcome::ChromeJson(actual), .. } if actual == &text)
        );
        assert_eq!(ready.iter().filter(|entry| matches!(&entry.operation, ExtensionOperation::EffectsCleanup { effect,cleanup_confirmed:false,.. } if effect == "extension_cdp_effect")).count(), 1, "actual raw result does not clear original Unknown cleanup debt");
        provider.close().await;
    }
    #[cfg(unix)]
    async fn upload_stage_fixture(
        provider: &ExtensionBrowserProvider,
        server: &mut tokio::net::UnixStream,
    ) -> ExtensionUploadStage {
        use sha2::Digest;
        let claim = attach_fixture(provider, server, 7, "upload-claim").await;
        let files = vec![ExtensionUploadFile::new(
            "Café 日本語 🐧.txt".into(),
            4,
            sha2::Sha256::digest(b"data").into(),
        )
        .unwrap()];
        let call = {
            let view = provider.clone();
            let files = files.clone();
            tokio::spawn(async move { view.begin_upload(&claim, &files).await })
        };
        let sent = request(server).await;
        assert_eq!(sent["request"]["method"], "beginUpload");
        assert_eq!(
            sent["request"]["files"],
            serde_json::to_value(&files).unwrap()
        );
        let stage = uuid::Uuid::new_v4();
        control_result(
            server,
            sent["request"]["id"].as_u64().unwrap(),
            json!({"stage":stage,"tabId":7,"targetId":"target-7","files":files}),
        )
        .await;
        bounded(call).await.unwrap().unwrap()
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn upload_contract_context_and_foreign_stage_refuse_before_dispatch() {
        use sha2::Digest;
        let (provider, mut server) = fixture();
        let claim = attach_fixture(&provider, &mut server, 7, "upload-claim").await;
        let files = vec![ExtensionUploadFile::new(
            "file.txt".into(),
            4,
            sha2::Sha256::digest(b"data").into(),
        )
        .unwrap()];
        assert!(
            matches!(provider.begin_upload(&claim,&files).await,Err(ExtensionProviderError::NotDispatched{kind,..})if kind=="context_required")
        );
        let view = provider
            .with_wire_context(ExtensionWireContext::new("upload-owner", "upload-turn").unwrap());
        assert!(
            matches!(view.begin_upload(&claim,&files).await,Err(ExtensionProviderError::NotDispatched{kind,..})if kind=="unsupported")
        );
        let mut byte = [0];
        assert_eq!(
            server.try_read(&mut byte).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(provider.pending_completions().await.unwrap().is_empty());
        provider.close().await;
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn cancelled_upload_retain_ack_is_recoverable_without_replaying_a_setter() {
        let mut capabilities = maka_capabilities();
        capabilities["uploadStaging"] = json!(true);
        let (provider, mut server) = fixture_with_capabilities(capabilities);
        let view = provider
            .with_wire_context(ExtensionWireContext::new("upload-owner", "upload-turn").unwrap());
        let stage = upload_stage_fixture(&view, &mut server).await;
        view.acknowledge_completion(stage.completion_id())
            .await
            .unwrap();
        let call = {
            let view = view.clone();
            let stage = stage.clone();
            tokio::spawn(async move { view.retain_upload_for_selection(&stage).await })
        };
        let sent = request(&mut server).await;
        let id = sent["request"]["id"].as_u64().unwrap();
        call.abort();
        let _ = call.await;
        let path = std::env::temp_dir()
            .join("maka-unit-upload-late-no-file")
            .join(stage.files[0].name());
        control_result(
            &mut server,
            id,
            json!({"stage":stage.id,"retained":true,"paths":[path]}),
        )
        .await;
        let ready = wait_ready(&view).await;
        assert_eq!(ready.len(), 1);
        assert!(
            matches!(view.recover_completion(id).await.unwrap(),ExtensionRecoveredOperation::UploadRetained(proof)if proof.stage_id()==stage.id)
        );
        let mut byte = [0];
        assert_eq!(
            server.try_read(&mut byte).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        view.acknowledge_completion(id).await.unwrap();
        provider.close().await;
    }
}

#[cfg(test)]
mod metadata_string_tests {
    use super::*;

    #[test]
    fn scalar_legacy_titles_and_explicit_json_text_have_one_lossless_authority() {
        let legacy: ExtensionTabInfo =
            serde_json::from_value(json!({"id":17,"title":"\"quoted\"","groupTitle":" group "}))
                .unwrap();
        assert_eq!(legacy.title.unwrap().json(), r#""\"quoted\"""#);
        assert_eq!(legacy.group_title.unwrap().json(), r#"" group ""#);
        let encoded: ExtensionTabInfo = serde_json::from_value(
            json!({"id":17,"titleJson":r#""\ud800""#,"groupTitleJson":r#""\udc00""#}),
        )
        .unwrap();
        assert_eq!(encoded.title.as_ref().unwrap().json(), r#""\ud800""#);
        assert_eq!(encoded.group_title.as_ref().unwrap().json(), r#""\udc00""#);
        let wire = serde_json::to_value(encoded).unwrap();
        assert_eq!(wire["titleJson"], r#""\ud800""#);
        assert!(wire.get("title").is_none());
        for conflicting in [
            json!({"id":17,"title":"old","titleJson":"\"new\""}),
            json!({"id":17,"title":null,"titleJson":"\"new\""}),
            json!({"id":17,"groupTitle":"old","groupTitleJson":null}),
        ] {
            let error = serde_json::from_value::<ExtensionTabInfo>(conflicting).unwrap_err();
            assert!(
                error.to_string().contains("both scalar and JSON-text"),
                "{error}"
            );
        }
    }
}
