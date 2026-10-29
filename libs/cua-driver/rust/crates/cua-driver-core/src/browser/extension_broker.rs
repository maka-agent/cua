// SPDX-License-Identifier: MIT

//! Extension-host owner and claim routing, independent of OS listener creation.
//!
//! The IPC adapter must verify the current-user peer before admission and must
//! associate decoded input with the returned connection, never a client-supplied
//! owner. The extension writer is serial. It consumes each outbound exactly once.
//! No CDP demultiplexer, desktop runtime, selector or input implementation lives here.

use super::broker_delivery::{
    ByteBudget, ByteCharge, DeliveryError, Queued, IPC_SHUTDOWN_DRAIN_TIMEOUT,
};
use super::extension_upload::{
    ExtensionUploadFile, UploadError, UploadOwner, EXTENSION_UPLOAD_CHUNK_BYTES,
};
use super::extension_upload_placement::UploadPlacement;
use super::extension_upload_worker::{
    cancel_queued, UploadCompletion, UploadEvent, UploadJob, UploadWork, UploadWorkResult,
    UploadWorker, UploadWorkerError, UploadWorkerOwner, JOB_CANCELLED, JOB_COMPLETED, JOB_QUEUED,
};
use super::extension_wire::{
    ExtensionCdpWritePhase, ExtensionFixedUiRequest, ExtensionPreparationDocument,
    ExtensionPreparationPolicy, ExtensionReplyProvenance, ExtensionWireContext,
};
use super::{
    extension_framing::{self, Direction, FrameError},
    extension_host::ExtensionOrigin,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::Write,
    sync::{
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
        Arc,
    },
};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

const MAX_CLIENTS: usize = 32;
const MAX_NORMAL_PENDING: usize = 64;
// Cleanup headroom bounds concurrent pending work, never total claim lifetime.
const MAX_CLEANUP_PENDING: usize = MAX_CLIENTS * (MAX_NORMAL_PENDING + 1);
const EVENT_CAPACITY: usize = 64;
const MAX_BUFFERED_EVENTS: usize = 64;
const MAX_BUFFERED_EVENT_BYTES: usize = 1024 * 1024;
const CHUNK_BYTES: usize = 192 * 1024;
const NATIVE_HOST_FRAME_BYTES: usize = 1024 * 1024;
const QUEUED: u8 = 0;
const STARTED: u8 = 1;
const WRITTEN: u8 = 2;
const SKIPPED: u8 = 3;
const UNKNOWN_CDP_REASON: &str =
    "extension CDP outcome remains unknown; see its retained completion receipt";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LocalPrincipal {
    #[cfg(any(unix, test))]
    UnixUid(u32),
    #[cfg(windows)]
    WindowsSid(String),
}

impl LocalPrincipal {
    fn matches(&self, other: &Self) -> bool {
        match (self, other) {
            #[cfg(any(unix, test))]
            (Self::UnixUid(left), Self::UnixUid(right)) => left == right,
            #[cfg(windows)]
            (Self::WindowsSid(left), Self::WindowsSid(right)) => left.eq_ignore_ascii_case(right),
            #[cfg(all(windows, test))]
            _ => false,
        }
    }
}

/// Construct only after the IPC adapter checked socket credentials or pipe token.
pub(crate) struct CheckedLocalPeer {
    principal: LocalPrincipal,
}

impl CheckedLocalPeer {
    pub(crate) fn from_checked_principal(principal: LocalPrincipal) -> Self {
        Self { principal }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum BrokerError {
    #[error("extension broker is closed")]
    Closed,
    #[error("browser extension handshake is not ready")]
    NotReady,
    #[error("local peer principal differs from the host user")]
    WrongPrincipal,
    #[error("extension broker client or owner budget exhausted")]
    ClientBudget,
    #[error("extension claim is unavailable or already has a CDP route")]
    ClaimUnavailable,
    #[error("extension broker route identity exhausted or event backlog unavailable")]
    RouteBudget,
    #[error("extension protocol failed: {0}")]
    Protocol(String),
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error(transparent)]
    Delivery(#[from] DeliveryError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ClientId(u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct RouteId(u64);

// Absence keeps legacy inventory serialization unchanged; an explicitly present
// null or wrong type must not erase the selector/candidate purpose.
fn present_control_field<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// No owner, generation, arbitrary operation or root-target authority is decoded.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "method", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum ControlRequest {
    ReadUserTab {
        id: u64,
        #[serde(rename = "tabId")]
        tab_id: u64,
        #[serde(rename = "expectedUrl")]
        expected_url: String,
        read: super::user_tab_context::BrowserUserTabRead,
    },
    BeginUpload {
        id: u64,
        claim: String,
        files: Vec<ExtensionUploadFile>,
    },
    WriteUploadChunk {
        id: u64,
        stage: Uuid,
        #[serde(rename = "fileIndex")]
        file_index: u32,
        offset: u64,
        bytes: String,
    },
    RetainUploadForSelection {
        id: u64,
        stage: Uuid,
    },
    AbandonUpload {
        id: u64,
        stage: Uuid,
    },
    Inventory {
        id: u64,
        #[serde(
            default,
            rename = "sessionOnly",
            deserialize_with = "present_control_field",
            skip_serializing_if = "Option::is_none"
        )]
        session_only: Option<bool>,
        #[serde(
            default,
            rename = "knownTabIds",
            deserialize_with = "present_control_field",
            skip_serializing_if = "Option::is_none"
        )]
        known_tab_ids: Option<Vec<u64>>,
    },
    Resolve {
        id: u64,
        #[serde(rename = "rawId")]
        raw_id: String,
        #[serde(default, rename = "sessionOnly")]
        session_only: bool,
        #[serde(default, rename = "committedUrlOnly")]
        committed_url_only: bool,
    },
    Attach {
        id: u64,
        #[serde(rename = "tabId")]
        tab_id: u64,
    },
    Detach {
        id: u64,
        claim: String,
    },
    FenceCdp {
        id: u64,
        claim: String,
    },
    RetireClaim {
        id: u64,
        claim: String,
        #[serde(rename = "cleanupId")]
        cleanup_id: u64,
    },
    PrepareClaim {
        id: u64,
        claim: String,
        document: ExtensionPreparationDocument,
        policy: ExtensionPreparationPolicy,
    },
    MarkTab {
        id: u64,
        claim: String,
        status: ExtensionKeepStatus,
    },
    CreatePopupTab {
        id: u64,
        claim: String,
    },
    CreateTab {
        id: u64,
        #[serde(rename = "windowId")]
        #[serde(skip_serializing_if = "Option::is_none")]
        window_id: Option<i64>,
    },
    CloseTab {
        id: u64,
        claim: String,
    },
    StopCreatedTab {
        id: u64,
        creation: String,
        #[serde(rename = "tabId", default, skip_serializing_if = "Option::is_none")]
        tab_id: Option<u64>,
    },
    SetScopedHeaders {
        id: u64,
        claim: String,
        #[serde(rename = "sessionId")]
        session_id: String,
        headers: Option<Vec<ScopedHeader>>,
    },
    ClearScopedHeaders {
        id: u64,
        claim: String,
    },
    CreateSessionPopupTab {
        id: u64,
        #[serde(rename = "tabId")]
        tab_id: u64,
        #[serde(rename = "scopeId")]
        scope_id: String,
    },
    PrepareSessionTab {
        id: u64,
        #[serde(rename = "tabId")]
        tab_id: u64,
        #[serde(rename = "scopeId")]
        scope_id: String,
        policy: ExtensionPreparationPolicy,
        ui: ExtensionFixedUiRequest,
    },
    SessionUi {
        id: u64,
        #[serde(rename = "tabId")]
        tab_id: u64,
        #[serde(rename = "scopeId")]
        scope_id: String,
        ui: ExtensionFixedUiRequest,
    },
    ClearSessionPreparation {
        id: u64,
        #[serde(rename = "tabId")]
        tab_id: u64,
        #[serde(rename = "scopeId")]
        scope_id: String,
    },
    PrepareUserTab {
        id: u64,
        #[serde(rename = "tabId")]
        tab_id: u64,
        #[serde(default, rename = "sessionOnly")]
        session_only: bool,
    },
    MuteCreatedTab {
        id: u64,
        creation: String,
    },
    UnmuteCreatedTabIfActive {
        id: u64,
        creation: String,
    },
    EnsureCreatedTabGroup {
        id: u64,
        creation: String,
        presentation: Value,
    },
    UpdateCreatedTabGroup {
        id: u64,
        creation: String,
        group: Value,
        presentation: Value,
    },
    ReleaseCreatedTabGroup {
        id: u64,
        creation: String,
        group: Value,
    },
    FinishTurn {
        id: u64,
        keep: Option<Vec<ExtensionKeepTab>>,
    },
    UserHistory {
        id: u64,
        options: Value,
    },
    NameSession {
        id: u64,
        name: String,
    },
    SetSessionHeaders {
        id: u64,
        headers: Vec<ScopedHeader>,
    },
    ClearSessionHeaders {
        id: u64,
    },
    MoveMouse {
        id: u64,
        claim: String,
        x: f64,
        y: f64,
        #[serde(rename = "waitForArrival")]
        #[serde(skip_serializing_if = "Option::is_none")]
        wait_for_arrival: Option<bool>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ExtensionKeepTab {
    pub(crate) tab_id: u64,
    pub(crate) status: ExtensionKeepStatus,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ExtensionKeepStatus {
    Handoff,
    Deliverable,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScopedHeader {
    pub(crate) name: String,
    pub(crate) value: String,
}

fn canonical_scope(value: &str) -> bool {
    uuid::Uuid::parse_str(value)
        .ok()
        .is_some_and(|id| id.to_string() == value)
}

impl ControlRequest {
    fn is_cleanup(&self) -> bool {
        matches!(
            self,
            Self::Detach { .. }
                | Self::FenceCdp { .. }
                | Self::RetireClaim { .. }
                | Self::StopCreatedTab { .. }
                | Self::FinishTurn { .. }
                | Self::ClearSessionPreparation { .. }
        )
    }
    fn bounded_cleanup(&self) -> bool {
        match self {
            Self::Detach { claim, .. }
            | Self::FenceCdp { claim, .. }
            | Self::RetireClaim { claim, .. } => !claim.is_empty() && claim.len() <= 128,
            Self::StopCreatedTab { creation, .. } => !creation.is_empty() && creation.len() <= 128,
            Self::ClearSessionPreparation {
                tab_id, scope_id, ..
            } => *tab_id > 0 && *tab_id <= 9_007_199_254_740_991 && canonical_scope(scope_id),
            Self::FinishTurn { keep, .. } => keep.as_ref().is_none_or(|items| {
                items.len() <= 1000
                    && items
                        .iter()
                        .all(|item| item.tab_id <= 9_007_199_254_740_991)
            }),
            _ => false,
        }
    }
    fn id(&self) -> u64 {
        match self {
            Self::BeginUpload { id, .. }
            | Self::WriteUploadChunk { id, .. }
            | Self::RetainUploadForSelection { id, .. }
            | Self::AbandonUpload { id, .. } => *id,
            Self::ReadUserTab { id, .. }
            | Self::Inventory { id, .. }
            | Self::Resolve { id, .. }
            | Self::Attach { id, .. }
            | Self::Detach { id, .. }
            | Self::FenceCdp { id, .. }
            | Self::RetireClaim { id, .. }
            | Self::CreateTab { id, .. }
            | Self::PrepareClaim { id, .. }
            | Self::MarkTab { id, .. }
            | Self::CreatePopupTab { id, .. }
            | Self::CloseTab { id, .. }
            | Self::StopCreatedTab { id, .. }
            | Self::SetScopedHeaders { id, .. }
            | Self::ClearScopedHeaders { id, .. } => *id,
            Self::CreateSessionPopupTab { id, .. }
            | Self::PrepareSessionTab { id, .. }
            | Self::SessionUi { id, .. }
            | Self::ClearSessionPreparation { id, .. }
            | Self::PrepareUserTab { id, .. }
            | Self::MuteCreatedTab { id, .. }
            | Self::UnmuteCreatedTabIfActive { id, .. }
            | Self::EnsureCreatedTabGroup { id, .. }
            | Self::UpdateCreatedTabGroup { id, .. }
            | Self::ReleaseCreatedTabGroup { id, .. } => *id,
            Self::UserHistory { id, .. } | Self::NameSession { id, .. } => *id,
            Self::FinishTurn { id, .. }
            | Self::SetSessionHeaders { id, .. }
            | Self::ClearSessionHeaders { id }
            | Self::MoveMouse { id, .. } => *id,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "camelCase")]
pub(crate) enum ControlOutcome {
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        details: Option<Value>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "camelCase")]
pub(crate) enum ControlEvent {
    SessionPopupRequested {
        generation: String,
        owner: String,
        #[serde(rename = "scopeId")]
        scope_id: String,
        #[serde(rename = "tabId")]
        tab_id: u64,
        #[serde(rename = "wireContext")]
        wire_context: ExtensionWireContext,
        url: String,
        #[serde(rename = "frameId", skip_serializing_if = "Option::is_none")]
        frame_id: Option<i64>,
        #[serde(rename = "documentId", skip_serializing_if = "Option::is_none")]
        document_id: Option<String>,
        #[serde(rename = "sourceUrl", skip_serializing_if = "Option::is_none")]
        source_url: Option<String>,
    },
    SessionPreparationCleanup {
        generation: String,
        owner: String,
        #[serde(rename = "scopeId")]
        scope_id: String,
        #[serde(rename = "tabId")]
        tab_id: u64,
        #[serde(rename = "wireContext")]
        wire_context: ExtensionWireContext,
        #[serde(rename = "cleanupConfirmed")]
        cleanup_confirmed: bool,
    },
    DownloadChanged {
        download: SharedDownload,
    },
    Reply {
        id: u64,
        outcome: ControlOutcome,
    },
    ClaimUnavailable {
        claim: String,
        reason: String,
    },
    ClaimCdpProgress {
        claim: String,
    },
    CdpUnconfirmed {
        claim: String,
        route: u64,
        id: u64,
        #[serde(rename = "writePhase")]
        write_phase: ExtensionCdpWritePhase,
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        event: Option<BrokerCdpEvent>,
        #[serde(
            rename = "wireContext",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        wire_context: Option<ExtensionWireContext>,
    },
    CdpOpened {
        id: u64,
        route: u64,
    },
    CdpMessage {
        route: u64,
        claim: String,
        event: BrokerCdpEvent,
        #[serde(
            rename = "wireContext",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        wire_context: Option<ExtensionWireContext>,
    },
    CdpRouteClosed {
        route: u64,
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
        event: BrokerCdpEvent,
        #[serde(
            rename = "wireContext",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        wire_context: Option<ExtensionWireContext>,
    },
    PopupRequested {
        claim: String,
        #[serde(rename = "tabId")]
        tab_id: u64,
        url: String,
        #[serde(rename = "wireContext")]
        wire_context: ExtensionWireContext,
        #[serde(rename = "frameId", skip_serializing_if = "Option::is_none")]
        frame_id: Option<i64>,
        #[serde(rename = "documentId", skip_serializing_if = "Option::is_none")]
        document_id: Option<String>,
        #[serde(rename = "sourceUrl", skip_serializing_if = "Option::is_none")]
        source_url: Option<String>,
    },
    EffectsCleanup {
        claim: String,
        effect: String,
        #[serde(rename = "cleanupConfirmed")]
        cleanup_confirmed: bool,
        error: Option<String>,
        #[serde(
            rename = "wireContext",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        wire_context: Option<ExtensionWireContext>,
    },
    TabStateChanged {
        claim: String,
        #[serde(rename = "tabId")]
        tab_id: u64,
        #[serde(rename = "windowId")]
        #[serde(skip_serializing_if = "Option::is_none")]
        window_id: Option<i64>,
        active: bool,
    },
    TabStateUnknown {
        claim: String,
        #[serde(rename = "tabId")]
        tab_id: u64,
        error: Value,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExtensionDownloadInfo {
    pub(crate) id: String,
    pub(crate) filename: String,
    pub(crate) url: String,
    pub(crate) status: ExtensionDownloadStatus,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExtensionDownloadStatus {
    Started,
    InProgress,
    Complete,
    Failed,
    Canceled,
}
/// All owner views share one immutable payload and its one queue reservation.
#[derive(Clone, Debug)]
pub(crate) struct SharedDownload(Arc<ExtensionDownloadInfo>);
impl Serialize for SharedDownload {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for SharedDownload {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self(Arc::new(ExtensionDownloadInfo::deserialize(
            deserializer,
        )?)))
    }
}

/// The runtime pump maps these into the existing ExtensionCdpInbound variants.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "camelCase")]
pub(crate) enum BrokerCdpEvent {
    ChromeMessage(Value),
    /// Full Chrome frame JSON text; serialized as an ordinary String through IPC.
    ChromeJson(String),
    LocalRejected {
        id: u64,
        code: String,
        message: String,
    },
    TransportFailure(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExtensionIdentity {
    pub(crate) extension_id: String,
    pub(crate) instance_id: String,
    pub(crate) generation: String,
    pub(crate) capabilities: Value,
}

#[derive(Clone)]
pub(crate) struct BrokerHandle {
    input: mpsc::Sender<Input>,
    budget: ByteBudget,
}

impl BrokerHandle {
    pub(crate) async fn identity(&self) -> Result<ExtensionIdentity, BrokerError> {
        let (reply, result) = oneshot::channel();
        self.input
            .send(Input::Identity(reply))
            .await
            .map_err(|_| BrokerError::Closed)?;
        result.await.map_err(|_| BrokerError::Closed)?
    }
    pub(crate) async fn admit_peer(
        &self,
        peer: CheckedLocalPeer,
    ) -> Result<ClientConnection, BrokerError> {
        let (reply, result) = oneshot::channel();
        self.input
            .send(Input::Admit { peer, reply })
            .await
            .map_err(|_| BrokerError::Closed)?;
        result.await.map_err(|_| BrokerError::Closed)?
    }

    /// Called only by the extension-framing reader, never a local IPC peer.
    pub(crate) async fn extension_message(&self, value: Value) -> Result<(), BrokerError> {
        self.extension_adapter_message(value, ExtensionReplyProvenance::DirectExtension)
            .await
    }

    /// The selected in-process translator supplies typed, non-wire provenance.
    pub(crate) async fn extension_adapter_message(
        &self,
        value: Value,
        provenance: ExtensionReplyProvenance,
    ) -> Result<(), BrokerError> {
        let charge = self.budget.charge(&value).await?;
        self.input
            .send(Input::Extension {
                value,
                charge,
                provenance,
            })
            .await
            .map_err(|_| BrokerError::Closed)
    }

    pub(crate) async fn extension_eof(&self, reason: &str) {
        let _ = self
            .input
            .send(Input::ExtensionEof(reason.to_owned()))
            .await;
    }

    /// Call after a socket writer drains an event; never blocks the writer.
    pub(crate) fn delivery_progress(&self) {
        let _ = self.input.try_send(Input::DeliveryProgress);
    }

    /// Forward a serial writer outcome; it never authorizes a retransmission.
    pub(crate) async fn write_report(&self, report: WriteReport) {
        let _ = self.input.send(Input::Written(report)).await;
    }
}

// Counts only controls admitted to the existing input channel, never requests
// still waiting for the byte budget. The guard is the queued input's lifetime.
struct ControlIngress {
    count: Arc<AtomicUsize>,
    progress: mpsc::Sender<Input>,
}
impl Drop for ControlIngress {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::SeqCst);
        let _ = self.progress.try_send(Input::DeliveryProgress);
    }
}

struct ClientLease {
    id: ClientId,
    controls_in_flight: Arc<AtomicUsize>,
    alive: Arc<AtomicBool>,
    input: mpsc::Sender<Input>,
    budget: ByteBudget,
}
impl Drop for ClientLease {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::SeqCst);
        // Full means the actor has queued work and will reap the fence before
        // its next input. Closed means the extension generation already ended.
        let _ = self.input.try_send(Input::ClientClosed(self.id));
    }
}

#[derive(Clone)]
pub(crate) struct ClientSender {
    lease: Arc<ClientLease>,
}
pub(crate) struct ClientConnection {
    pub(crate) sender: ClientSender,
    pub(crate) events: mpsc::Receiver<Queued<ControlEvent>>,
}

impl ClientSender {
    pub(crate) async fn control_with_context(
        &self,
        request: ControlRequest,
        wire_context: Option<ExtensionWireContext>,
    ) -> Result<(), BrokerError> {
        if !self.lease.alive.load(Ordering::SeqCst) {
            return Err(BrokerError::Closed);
        }
        let charge = if request.is_cleanup() {
            if !request.bounded_cleanup() {
                return Err(BrokerError::Protocol(
                    "cleanup token exceeds its fixed transport bound".to_owned(),
                ));
            }
            None
        } else {
            Some(self.lease.budget.charge(&request).await?)
        };
        // Publish the reservation before the second alive check. A concurrent
        // closure either sees this finite input or this request returns Closed;
        // no control can enter behind the owner's final EOF receipt.
        self.lease.controls_in_flight.fetch_add(1, Ordering::SeqCst);
        let ingress = ControlIngress {
            count: self.lease.controls_in_flight.clone(),
            progress: self.lease.input.clone(),
        };
        if !self.lease.alive.load(Ordering::SeqCst) {
            return Err(BrokerError::Closed);
        }
        self.lease
            .input
            .send(Input::Control {
                client: self.lease.id,
                charge,
                wire_context,
                request,
                ingress,
            })
            .await
            .map_err(|_| BrokerError::Closed)
    }

    pub(crate) async fn open_cdp_route_ordered(
        &self,
        claim: &str,
        open_local_id: u64,
    ) -> Result<CdpRoute, BrokerError> {
        if open_local_id == 0 {
            return Err(BrokerError::ClaimUnavailable);
        }
        self.open_cdp_route_with_delivery(
            claim,
            RouteDelivery::Ordered {
                open_id: open_local_id,
            },
        )
        .await
    }

    async fn open_cdp_route_with_delivery(
        &self,
        claim: &str,
        delivery: RouteDelivery,
    ) -> Result<CdpRoute, BrokerError> {
        if claim.is_empty() || claim.len() > 128 {
            return Err(BrokerError::ClaimUnavailable);
        }
        if !self.lease.alive.load(Ordering::SeqCst) {
            return Err(BrokerError::Closed);
        }
        let (reply, result) = oneshot::channel();
        self.lease
            .input
            .send(Input::BindRoute {
                client: self.lease.id,
                claim: claim.to_owned(),
                delivery,
                reply,
            })
            .await
            .map_err(|_| BrokerError::Closed)?;
        result.await.map_err(|_| BrokerError::Closed)?
    }

    /// A real control-IPC EOF must call this even if joined CDP streams remain.
    pub(crate) async fn close(&self) {
        self.lease.alive.store(false, Ordering::SeqCst);
        let _ = self
            .lease
            .input
            .send(Input::ClientClosed(self.lease.id))
            .await;
    }
}

struct RouteLease {
    id: RouteId,
    client: ClientId,
    claim: String,
    alive: Arc<AtomicBool>,
    client_alive: Arc<AtomicBool>,
    input: mpsc::Sender<Input>,
    budget: ByteBudget,
}
impl Drop for RouteLease {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::SeqCst);
        let _ = self.input.try_send(Input::RouteClosed(self.id));
    }
}

#[derive(Clone)]
pub(crate) struct RouteSender {
    lease: Arc<RouteLease>,
}
pub(crate) struct CdpRoute {
    pub(crate) sender: RouteSender,
    pub(crate) events: mpsc::Receiver<Queued<BrokerCdpEvent>>,
}

impl RouteSender {
    /// Opaque transport route identity, scoped by its authenticated IPC owner.
    pub(crate) fn wire_id(&self) -> u64 {
        self.lease.id.0
    }
    /// Already released by runtime ExtensionCdpCommand immediately before IPC write.
    pub(crate) async fn send_json_with_context(
        &self,
        message: Value,
        wire_context: Option<ExtensionWireContext>,
    ) -> Result<(), BrokerError> {
        if !self.lease.client_alive.load(Ordering::SeqCst) {
            return Err(BrokerError::Closed);
        }
        self.lease
            .input
            .send(Input::Cdp {
                client: self.lease.client,
                route: self.lease.id,
                claim: self.lease.claim.clone(),
                charge: self.lease.budget.charge(&message).await?,
                wire_context,
                message,
            })
            .await
            .map_err(|_| BrokerError::Closed)
    }

    pub(crate) async fn close(&self) {
        self.lease.alive.store(false, Ordering::SeqCst);
        let _ = self
            .lease
            .input
            .send(Input::RouteClosed(self.lease.id))
            .await;
    }
}

enum Input {
    Identity(oneshot::Sender<Result<ExtensionIdentity, BrokerError>>),
    Admit {
        peer: CheckedLocalPeer,
        reply: oneshot::Sender<Result<ClientConnection, BrokerError>>,
    },
    BindRoute {
        client: ClientId,
        claim: String,
        delivery: RouteDelivery,
        reply: oneshot::Sender<Result<CdpRoute, BrokerError>>,
    },
    Control {
        client: ClientId,
        request: ControlRequest,
        charge: Option<Arc<ByteCharge>>,
        wire_context: Option<ExtensionWireContext>,
        ingress: ControlIngress,
    },
    Cdp {
        client: ClientId,
        route: RouteId,
        claim: String,
        message: Value,
        charge: Arc<ByteCharge>,
        wire_context: Option<ExtensionWireContext>,
    },
    ClientClosed(ClientId),
    RouteClosed(RouteId),
    Extension {
        value: Value,
        charge: Arc<ByteCharge>,
        provenance: ExtensionReplyProvenance,
    },
    ExtensionEof(String),
    Written(WriteReport),
    Upload {
        event: UploadEvent,
        charge: Option<Arc<ByteCharge>>,
    },
    DeliveryProgress,
}

impl Input {
    fn wire_context(&self) -> Option<ExtensionWireContext> {
        match self {
            Self::Control { wire_context, .. } | Self::Cdp { wire_context, .. } => {
                wire_context.clone()
            }
            _ => None,
        }
    }

    fn charge(&self) -> Option<Arc<ByteCharge>> {
        match self {
            Self::Extension { charge, .. } | Self::Cdp { charge, .. } => Some(charge.clone()),
            Self::Control { charge, .. } | Self::Upload { charge, .. } => charge.clone(),
            _ => None,
        }
    }
}

enum Delivery {
    Control {
        client: ClientId,
        sender: mpsc::Sender<Queued<ControlEvent>>,
        event: Queued<ControlEvent>,
    },
    #[cfg(test)]
    Cdp {
        route: RouteId,
        client: ClientId,
        claim: String,
        sender: mpsc::Sender<Queued<BrokerCdpEvent>>,
        event: Queued<BrokerCdpEvent>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OwnerCleanup {
    Unrequested,
    // The attempt remains known after an Unknown/error removes its Pending;
    // it is never inferred from logical admission closure or retried.
    Requested { outer_id: u64 },
    Confirmed,
}

struct ClientState {
    owner: String,
    alive: Arc<AtomicBool>,
    events: mpsc::Sender<Queued<ControlEvent>>,
    delivery_blocked: bool,
    undelivered: VecDeque<Queued<ControlEvent>>,
    high_water: u64,
    closing: bool,
    extension_cleanup: OwnerCleanup,
    controls_in_flight: Arc<AtomicUsize>,
    // One already-created EOF receipt, held only while local job custody is
    // pending. This is transport egress, never another owner/session registry.
    deferred_generation_close: Option<Queued<ControlEvent>>,
    attaching: HashSet<u64>,
    early: HashMap<String, BufferedEvents>,
}
#[derive(Default)]
struct BufferedEvents {
    events: VecDeque<BrokerCdpEvent>,
    charges: VecDeque<Option<Arc<ByteCharge>>>,
    bytes: usize,
    revoked: Option<String>,
}
struct ClaimState {
    client: ClientId,
    tab_id: u64,
    target_id: String,
    alive: Arc<AtomicBool>,
    route: Option<RouteId>,
    early: BufferedEvents,
    cleanup_only: bool,
    // Only an observer of this existing claim's drain; not cleanup authority.
    cdp_fenced: bool,
    // Exact known physical cleanup receipt, retained until Host folding retires it.
    cleanup_id: Option<u64>,
}
#[derive(Clone, Copy)]
enum RouteDelivery {
    Ordered {
        open_id: u64,
    },
    #[cfg(test)]
    Direct,
}

struct RouteState {
    client: ClientId,
    claim: String,
    alive: Arc<AtomicBool>,
    delivery: RouteDelivery,
    #[cfg(test)]
    events: mpsc::Sender<Queued<BrokerCdpEvent>>,
    high_water: u64,
}
#[derive(Clone, Debug)]
struct ClosingClaim {
    claim: String,
    tab_id: u64,
    target_id: String,
}

#[derive(Clone, Debug)]
enum ControlKind {
    Inventory,
    Resolve,
    Attach(u64),
    Detach(String),
    Close(ClosingClaim),
    StopCreated(Option<u64>),
    Other,
}
#[derive(Clone, Copy)]
enum UploadCustodyFact {
    Begun(Uuid),
    PartialBegin(Uuid),
    ChunkWritten(Uuid),
    Retained(Uuid),
    Abandoned(Uuid),
}
impl UploadCustodyFact {
    fn value(self) -> Value {
        let (stage, state) = match self {
            Self::Begun(stage) => (stage, "begun"),
            Self::PartialBegin(stage) => (stage, "partialBegin"),
            Self::ChunkWritten(stage) => (stage, "chunkWritten"),
            Self::Retained(stage) => (stage, "retained"),
            Self::Abandoned(stage) => (stage, "abandoned"),
        };
        json!({"stage":stage,"state":state})
    }
}

enum UploadControl {
    Begin {
        owner: UploadOwner,
        files: Arc<Vec<ExtensionUploadFile>>,
    },
    Write {
        stage: Uuid,
        file_index: u32,
        offset: u64,
        bytes: u64,
    },
    Retain {
        stage: Uuid,
    },
    Abandon {
        stage: Uuid,
    },
    RetireTab {
        owner: UploadOwner,
        outcome: Box<ControlOutcome>,
    },
}
impl UploadControl {
    fn cleanup(&self) -> bool {
        matches!(self, Self::Abandon { .. } | Self::RetireTab { .. })
    }
}
struct UploadAdmission {
    client: ClientId,
    local_id: u64,
    operation: UploadControl,
    work: UploadWork,
    claim: Option<String>,
    gates: Vec<Arc<AtomicBool>>,
    context: Option<ExtensionWireContext>,
}
struct UploadRetirementReply {
    client: ClientId,
    id: u64,
    claim: Option<String>,
    wire_context: Option<ExtensionWireContext>,
    outcome: ControlOutcome,
    cleanup: Result<(), String>,
}
struct PendingUpload {
    local_id: u64,
    operation: UploadControl,
    claim: Option<String>,
    phase: Arc<AtomicU8>,
    interrupted: Option<&'static str>,
    _charge: Option<Arc<ByteCharge>>,
}

enum PendingKind {
    Upload(PendingUpload),
    Control {
        local_id: u64,
        operation: ControlKind,
    },
    Cdp {
        route: RouteId,
        claim: String,
        inner_id: u64,
        // The full extension cause is in the charged completion event. Retain
        // only this fixed classification in bounded Pending bookkeeping.
        unknown: Option<&'static str>,
    },
    CloseOwner,
}
// Transient view into the existing Pending association, never stored.
struct UnconfirmedCdp<'a> {
    client: ClientId,
    route: RouteId,
    claim: &'a str,
    id: u64,
    dispatch: &'a AtomicU8,
    wire_context: Option<&'a ExtensionWireContext>,
}

struct Pending {
    client: ClientId,
    kind: PendingKind,
    dispatch: Arc<AtomicU8>,
    wire_context: Option<ExtensionWireContext>,
    // Per-existing-operation execution gate, not a lifetime ended-turn registry.
    // Its clones follow extension phases even after the adapter has emitted them.
    scope_fence: Option<Arc<AtomicBool>>,
}

/// One extension-port lifetime. Construct a new broker rather than reconnect it.
pub(crate) struct ExtensionHostBroker {
    expected_extension: ExtensionOrigin,
    principal: LocalPrincipal,
    generation: String,
    generation_alive: Arc<AtomicBool>,
    identity: Option<ExtensionIdentity>,
    bound: bool,
    stopped: bool,
    clients: HashMap<ClientId, ClientState>,
    owners: HashMap<String, ClientId>,
    claims: HashMap<String, ClaimState>,
    routes: HashMap<RouteId, RouteState>,
    pending: HashMap<u64, Pending>,
    next_client: u64,
    next_route: u64,
    next_outer: u64,
    budget: ByteBudget,
    current_charge: Option<Arc<ByteCharge>>,
    input_context: Option<ExtensionWireContext>,
    deliveries: VecDeque<Delivery>,
    input: mpsc::Receiver<Input>,
    input_sender: mpsc::Sender<Input>,
    extension_output: Option<mpsc::Sender<ExtensionOutbound>>,
    uploads: Option<UploadWorker>,
    closing_uploads: Option<String>,
}

impl ExtensionHostBroker {
    pub(crate) fn channels(
        expected_extension: ExtensionOrigin,
        principal: LocalPrincipal,
    ) -> (BrokerHandle, Self, mpsc::Receiver<ExtensionOutbound>) {
        let (input_sender, input) = mpsc::channel(128);
        let (extension_output, output) = mpsc::channel(64);
        let budget = ByteBudget::new();
        let handle = BrokerHandle {
            input: input_sender.clone(),
            budget: budget.clone(),
        };
        let broker = Self {
            expected_extension,
            principal,
            generation: uuid::Uuid::new_v4().to_string(),
            generation_alive: Arc::new(AtomicBool::new(true)),
            identity: None,
            bound: false,
            stopped: false,
            clients: HashMap::new(),
            owners: HashMap::new(),
            claims: HashMap::new(),
            routes: HashMap::new(),
            pending: HashMap::new(),
            next_client: 0,
            next_route: 0,
            next_outer: 0,
            budget,
            current_charge: None,
            input_context: None,
            deliveries: VecDeque::new(),
            input,
            input_sender,
            extension_output: Some(extension_output),
            uploads: None,
            closing_uploads: None,
        };
        (handle, broker, output)
    }

    /// Install only from the validated registered native-host process entry.
    /// The worker confirms placement on its own actual execution thread.
    pub(super) fn install_native_uploads(
        &mut self,
        placement: UploadPlacement,
    ) -> std::io::Result<UploadWorkerOwner> {
        if self.bound || self.uploads.is_some() {
            return Err(std::io::Error::other(
                "upload service must be installed before handshake",
            ));
        }
        let input = self.input_sender.clone();
        let budget = self.budget.clone();
        let (worker, owner) = UploadWorker::start(placement, move |event| {
            let (event, charge) = match event {
                UploadEvent::Completed(completion) => {
                    let (completion, charge) = prepare_upload_completion(completion, &budget);
                    (UploadEvent::Completed(completion), charge)
                }
                event => (event, None),
            };
            input.blocking_send(Input::Upload { event, charge }).is_ok()
        })?;
        self.uploads = Some(worker);
        Ok(owner)
    }

    pub(crate) fn generation(&self) -> &str {
        &self.generation
    }

    /// The host owns this task and the blocking framed reader/writer lifetimes.
    pub(crate) async fn run(mut self) {
        let mut extension_backlog = VecDeque::new();
        while let Some(input) = self.input.recv().await {
            let mut output = Vec::new();
            self.current_charge = input.charge();
            self.input_context = input.wire_context();
            self.reap_fences(&mut output);
            match input {
                Input::Identity(reply) => {
                    let _ = reply.send(self.identity.clone().ok_or(BrokerError::NotReady));
                }
                Input::Admit { peer, reply } => {
                    let _ = reply.send(self.admit(peer));
                }
                Input::BindRoute {
                    client,
                    claim,
                    delivery,
                    reply,
                } => {
                    let _ = reply.send(self.bind_route_with_delivery(client, &claim, delivery));
                }
                Input::Control {
                    client,
                    request,
                    charge: _,
                    wire_context: _,
                    ingress,
                } => {
                    drop(ingress);
                    self.control(client, request, &mut output);
                }
                Input::Cdp {
                    client,
                    route,
                    claim,
                    message,
                    charge: _,
                    wire_context: _,
                } => self.cdp_input(client, route, &claim, message, &mut output),
                Input::ClientClosed(client) => self.close_client(client, &mut output),
                Input::RouteClosed(route) => {
                    self.close_route(route, "CDP connection ended", &mut output)
                }
                Input::Extension {
                    value,
                    charge: _,
                    provenance,
                } => {
                    if let Err(error) =
                        self.extension_with_provenance(value, provenance, &mut output)
                    {
                        self.end_generation(&error.to_string());
                    }
                }
                Input::ExtensionEof(reason) => self.end_generation(&reason),
                Input::DeliveryProgress => {}
                Input::Written(report) => self.written(report, &mut output),
                Input::Upload { event, charge: _ } => self.upload_event(event),
            }
            self.finish_upload_generation();
            self.current_charge = None;
            self.input_context = None;
            self.flush_deliveries();
            if self.stopped {
                break;
            }
            extension_backlog.extend(output);
            while let Some(frame) = extension_backlog.pop_front() {
                match self
                    .extension_output
                    .as_ref()
                    .expect("active generation retains its extension output lane")
                    .try_send(frame)
                {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(frame)) => {
                        extension_backlog.push_front(frame);
                        break;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        self.end_generation("extension writer ended before settlement");
                        break;
                    }
                }
            }

            if self.stopped {
                break;
            }
        }
        self.end_generation("extension broker input ended");
        self.drain_stopped_deliveries().await;
    }

    fn written(&mut self, report: WriteReport, output: &mut Vec<ExtensionOutbound>) {
        match report {
            WriteReport::LocalRejected {
                outer,
                code,
                message,
            } => {
                let before_write = self.pending.get(&outer).is_some_and(|pending| {
                    pending.dispatch.load(Ordering::SeqCst) == SKIPPED
                        && !matches!(
                            &pending.kind,
                            PendingKind::Cdp {
                                unknown: Some(_),
                                ..
                            }
                        )
                });
                if before_write {
                    if let Some(pending) = self.pending.remove(&outer) {
                        self.local_rejection(pending, code, message, output);
                    }
                }
            }
            WriteReport::Skipped { outer } => {
                if let Some(pending) = self.pending.remove(&outer) {
                    let partial = pending.dispatch.load(Ordering::SeqCst) != SKIPPED;
                    self.write_not_settled(outer, pending, partial, output);
                }
            }
            WriteReport::Abandoned { outer } => {
                if let Some(pending) = self.pending.remove(&outer) {
                    self.write_not_settled(outer, pending, true, output);
                }
            }
            WriteReport::Written { outer } => {
                tracing::trace!(
                    request_id = outer,
                    awaiting_reply = self.pending.contains_key(&outer),
                    "extension browser wire write acknowledged"
                );
            }
        }
        self.finish_upload_generation();
    }

    async fn drain_stopped_deliveries(&mut self) {
        let deadline = tokio::time::sleep(IPC_SHUTDOWN_DRAIN_TIMEOUT);
        tokio::pin!(deadline);
        loop {
            self.finish_upload_generation();
            self.flush_deliveries();
            if self.deliveries.is_empty() && self.closing_uploads.is_none() {
                return;
            }
            tokio::select! {
                _ = &mut deadline => {
                    let pending_ids=self.pending.iter().filter_map(|(id,pending)|matches!(pending.kind,PendingKind::Upload(_)).then_some(*id)).collect::<Vec<_>>();
                    for id in pending_ids {
                        if let Some(Pending{client,kind:PendingKind::Upload(upload),wire_context,..})=self.pending.remove(&id) {
                            if let UploadControl::RetireTab{outcome,..}=upload.operation {
                                self.upload_retirement_reply(UploadRetirementReply {
                                    client,
                                    id: upload.local_id,
                                    claim: upload.claim,
                                    wire_context,
                                    outcome: *outcome,
                                    cleanup: Err("host upload cleanup remained unresolved at shutdown deadline".into()),
                                });
                            } else {
                                // Running filesystem work cannot be declared unsent.
                                // Fixed receipt contains no guessed stage/path.
                                self.queue_control_delivery(client,Queued::new(ControlEvent::Reply{id:upload.local_id,outcome:ControlOutcome::Unknown{reason:"host upload I/O remained unresolved at the existing shutdown deadline".into(),details:None}},None));
                            }
                        }
                    }
                    self.finish_upload_generation();
                    self.flush_deliveries();
                    return;
                },
                input = self.input.recv() => match input {
                    Some(Input::Identity(reply)) => { let _ = reply.send(Err(BrokerError::Closed)); }
                    Some(Input::Admit { reply, .. }) => { let _ = reply.send(Err(BrokerError::Closed)); }
                    Some(Input::BindRoute { reply, .. }) => { let _ = reply.send(Err(BrokerError::Closed)); }
                    Some(Input::Upload {event,charge:_}) => self.upload_event(event),
                    Some(Input::Control {client,request,ingress,..}) => {
                        drop(ingress);
                        // Already-admitted uploads receive a known unsent
                        // terminal before the generation's final EOF.
                        self.control(client, request, &mut Vec::new());
                        self.finish_upload_generation();
                    }
                    Some(Input::ClientClosed(client)) => {
                        if let Some(state) = self.clients.get_mut(&client) {
                            state.closing = true;
                            state.alive.store(false, Ordering::SeqCst);
                        }
                    }
                    Some(_) => {
                        // Existing progress/drop inputs wake the same egress
                        // queue. No command, new owner or extension effect can be
                        // admitted after the generation fence became false.
                    }
                    None => return,
                }
            }
        }
    }

    fn admit(&mut self, peer: CheckedLocalPeer) -> Result<ClientConnection, BrokerError> {
        if !self.bound {
            return Err(BrokerError::NotReady);
        }
        if !self.principal.matches(&peer.principal) {
            return Err(BrokerError::WrongPrincipal);
        }
        if self.clients.len() >= MAX_CLIENTS {
            return Err(BrokerError::ClientBudget);
        }
        self.next_client = self
            .next_client
            .checked_add(1)
            .ok_or(BrokerError::ClientBudget)?;
        let id = ClientId(self.next_client);
        let owner = format!("{}:{}", uuid::Uuid::new_v4(), self.next_client);
        let alive = Arc::new(AtomicBool::new(true));
        let controls_in_flight = Arc::new(AtomicUsize::new(0));
        let (events, receiver) = mpsc::channel(EVENT_CAPACITY);
        self.owners.insert(owner.clone(), id);
        self.clients.insert(
            id,
            ClientState {
                owner,
                alive: alive.clone(),
                events,
                delivery_blocked: false,
                undelivered: VecDeque::new(),
                high_water: 0,
                closing: false,
                extension_cleanup: OwnerCleanup::Unrequested,
                controls_in_flight: controls_in_flight.clone(),
                deferred_generation_close: None,
                attaching: HashSet::new(),
                early: HashMap::new(),
            },
        );
        let lease = Arc::new(ClientLease {
            id,
            controls_in_flight,
            alive,
            input: self.input_sender.clone(),
            budget: self.budget.clone(),
        });
        Ok(ClientConnection {
            sender: ClientSender { lease },
            events: receiver,
        })
    }

    #[cfg(test)]
    fn bind_route(&mut self, client: ClientId, token: &str) -> Result<CdpRoute, BrokerError> {
        self.bind_route_with_delivery(client, token, RouteDelivery::Direct)
    }

    fn bind_route_with_delivery(
        &mut self,
        client: ClientId,
        token: &str,
        delivery: RouteDelivery,
    ) -> Result<CdpRoute, BrokerError> {
        let owner = self
            .clients
            .get(&client)
            .filter(|state| {
                state.alive.load(Ordering::SeqCst) && !state.closing && !state.delivery_blocked
            })
            .ok_or(BrokerError::Closed)?;
        let client_alive = owner.alive.clone();
        let claim = self
            .claims
            .get_mut(token)
            .filter(|claim| {
                claim.client == client
                    && claim.alive.load(Ordering::SeqCst)
                    && !claim.cleanup_only
                    && !claim.cdp_fenced
                    && claim.route.is_none()
            })
            .ok_or(BrokerError::ClaimUnavailable)?;
        self.next_route = self
            .next_route
            .checked_add(1)
            .ok_or(BrokerError::RouteBudget)?;
        let id = RouteId(self.next_route);
        let alive = Arc::new(AtomicBool::new(true));
        let (events, receiver) = mpsc::channel(EVENT_CAPACITY);
        let mut early = std::mem::take(&mut claim.early);
        claim.route = Some(id);
        self.routes.insert(
            id,
            RouteState {
                client,
                claim: token.to_owned(),
                alive: alive.clone(),
                delivery,
                #[cfg(test)]
                events,
                high_water: 0,
            },
        );
        #[cfg(not(test))]
        drop(events);
        match delivery {
            RouteDelivery::Ordered { open_id } => self.queue_cdp_control(
                client,
                ControlEvent::CdpOpened {
                    id: open_id,
                    route: id.0,
                },
            ),
            #[cfg(test)]
            RouteDelivery::Direct => {}
        }
        while let Some(event) = early.events.pop_front() {
            let prior_charge = self.current_charge.take();
            self.current_charge = early.charges.pop_front().unwrap_or(None);
            self.emit_cdp_with_context(id, event, None);
            self.current_charge = prior_charge;
        }
        let lease = Arc::new(RouteLease {
            id,
            client,
            claim: token.to_owned(),
            alive,
            client_alive,
            input: self.input_sender.clone(),
            budget: self.budget.clone(),
        });
        Ok(CdpRoute {
            sender: RouteSender { lease },
            events: receiver,
        })
    }

    fn reject_control(
        &mut self,
        client: ClientId,
        id: u64,
        kind: &str,
        message: &str,
        output: &mut Vec<ExtensionOutbound>,
    ) {
        self.emit_control(
            client,
            ControlEvent::Reply {
                id,
                outcome: ControlOutcome::NotDispatched {
                    kind: kind.to_owned(),
                    message: message.to_owned(),
                    details: None,
                },
            },
            output,
        );
    }

    fn upload_control(
        &mut self,
        client: ClientId,
        request: ControlRequest,
        output: &mut Vec<ExtensionOutbound>,
    ) {
        let id = request.id();
        if self.uploads.is_none() {
            self.reject_control(
                client,
                id,
                "unsupported",
                "actual native-host upload placement is unavailable",
                output,
            );
            return;
        }
        let Some(context) = self.input_context.clone() else {
            self.reject_control(
                client,
                id,
                "context_required",
                "upload requires captured trusted context",
                output,
            );
            return;
        };
        if self.normal_pending() >= MAX_NORMAL_PENDING {
            self.reject_control(
                client,
                id,
                "request_budget",
                "host upload work shares the normal pending budget",
                output,
            );
            return;
        }
        let (operation, work, claim, claim_gate) = match request {
            ControlRequest::BeginUpload { claim, files, .. } => {
                let Some(record) = self.claims.get(&claim).filter(|record| {
                    record.client == client
                        && record.alive.load(Ordering::SeqCst)
                        && !record.cleanup_only
                        && !record.cdp_fenced
                }) else {
                    self.reject_control(
                        client,
                        id,
                        "claim_unavailable",
                        "upload requires this connection's current physical claim",
                        output,
                    );
                    return;
                };
                let owner = UploadOwner {
                    session_id: context.host_session_id().to_owned(),
                    tab_id: record.tab_id,
                    target_id: record.target_id.clone(),
                };
                let files = Arc::new(files);
                (
                    UploadControl::Begin {
                        owner: owner.clone(),
                        files: files.clone(),
                    },
                    UploadWork::Begin { owner, files },
                    Some(claim),
                    Some(record.alive.clone()),
                )
            }
            ControlRequest::WriteUploadChunk {
                stage,
                file_index,
                offset,
                bytes,
                ..
            } => {
                let bytes = match decode_upload_chunk(&bytes) {
                    Ok(bytes) => bytes,
                    Err(message) => {
                        self.reject_control(client, id, "upload_chunk", message, output);
                        return;
                    }
                };
                (
                    UploadControl::Write {
                        stage,
                        file_index,
                        offset,
                        bytes: bytes.len() as u64,
                    },
                    UploadWork::Write {
                        session_id: context.host_session_id().to_owned(),
                        stage,
                        file_index,
                        offset,
                        bytes,
                    },
                    None,
                    None,
                )
            }
            ControlRequest::RetainUploadForSelection { stage, .. } => (
                UploadControl::Retain { stage },
                UploadWork::Retain {
                    session_id: context.host_session_id().to_owned(),
                    stage,
                },
                None,
                None,
            ),
            ControlRequest::AbandonUpload { stage, .. } => (
                UploadControl::Abandon { stage },
                UploadWork::Abandon {
                    session_id: context.host_session_id().to_owned(),
                    stage,
                },
                None,
                None,
            ),
            _ => unreachable!("upload_control receives only the four local upload operations"),
        };
        let mut gates = vec![
            self.generation_alive.clone(),
            self.clients[&client].alive.clone(),
        ];
        if let Some(gate) = claim_gate {
            gates.push(gate);
        }
        self.queue_upload(UploadAdmission {
            client,
            local_id: id,
            operation,
            work,
            claim,
            gates,
            context: Some(context),
        });
    }

    fn queue_upload(&mut self, admission: UploadAdmission) {
        let UploadAdmission {
            client,
            local_id,
            operation,
            work,
            claim,
            mut gates,
            context,
        } = admission;
        let Some(outer) = self.next_outer.checked_add(1) else {
            self.end_generation("host upload ID exhausted");
            return;
        };
        self.next_outer = outer;
        let phase = Arc::new(AtomicU8::new(JOB_QUEUED));
        let scope_fence = (!operation.cleanup()).then(|| Arc::new(AtomicBool::new(true)));
        if let Some(gate) = &scope_fence {
            gates.push(gate.clone());
        }
        let charge = self.current_charge.clone();
        self.pending.insert(
            outer,
            Pending {
                client,
                kind: PendingKind::Upload(PendingUpload {
                    local_id,
                    operation,
                    claim,
                    phase: phase.clone(),
                    interrupted: None,
                    _charge: charge.clone(),
                }),
                dispatch: Arc::new(AtomicU8::new(QUEUED)),
                wire_context: context,
                scope_fence,
            },
        );
        let job = UploadJob {
            id: outer,
            work,
            phase,
            gates,
            _charge: charge,
        };
        let submitted = self
            .uploads
            .as_ref()
            .expect("upload service was checked")
            .try_submit(job);
        if let Err(error) = submitted {
            let rejected = error.into_job();
            let Some(pending) = self.pending.remove(&outer) else {
                return;
            };
            let PendingKind::Upload(upload) = pending.kind else {
                unreachable!()
            };
            // The queue returned this exact job; no filesystem effect can start.
            let _ = cancel_queued(&rejected.phase);
            if let UploadControl::RetireTab { outcome, .. } = upload.operation {
                self.upload_retirement_reply(UploadRetirementReply {
                    client,
                    id: local_id,
                    claim: upload.claim,
                    wire_context: pending.wire_context,
                    outcome: *outcome,
                    cleanup: Err("host upload cleanup worker did not admit work".into()),
                });
                return;
            }
            self.upload_reply(
                client,
                local_id,
                ControlOutcome::NotDispatched {
                    kind: "request_budget".into(),
                    message: "host upload worker did not admit this operation".into(),
                    details: None,
                },
            );
        }
    }

    fn upload_reply(&mut self, client: ClientId, id: u64, outcome: ControlOutcome) {
        self.upload_reply_custody(client, id, outcome, None);
    }

    fn upload_reply_custody(
        &mut self,
        client: ClientId,
        id: u64,
        mut outcome: ControlOutcome,
        fact: Option<UploadCustodyFact>,
    ) {
        if let (Some(fact), ControlOutcome::Unknown { details, .. }) = (fact, &mut outcome) {
            let details = details.get_or_insert_with(|| json!({}));
            details["hostUploadCustody"] = fact.value();
        }
        let event = ControlEvent::Reply { id, outcome };
        match self.budget.try_charge(&event) {
            Ok(charge) => self.queue_control_delivery(client, Queued::new(event, Some(charge))),
            Err(_) => {
                // Fixed source-derived custody survives a full variable byte
                // budget. The client has its exact issued operation/context;
                // this marker grants no paths or usable new upload stage.
                let known_unsent = matches!(
                    &event,
                    ControlEvent::Reply {
                        outcome: ControlOutcome::NotDispatched { .. },
                        ..
                    }
                );
                let details = fact.map(|fact| json!({"hostUploadCustody":fact.value()}));
                let outcome = if known_unsent {
                    ControlOutcome::NotDispatched {
                        kind: "upload_not_dispatched".into(),
                        message: "local upload did not enter filesystem work".into(),
                        details: None,
                    }
                } else {
                    ControlOutcome::Unknown{reason:"host upload variable receipt was not admitted; resource custody remains unknown".into(),details}
                };
                self.queue_control_delivery(
                    client,
                    Queued::new(ControlEvent::Reply { id, outcome }, None),
                );
                self.fence_upload_delivery_owner(client);
            }
        }
    }

    fn fence_upload_delivery_owner(&mut self, client: ClientId) {
        let Some(state) = self.clients.get_mut(&client) else {
            return;
        };
        let first = !state.closing;
        state.closing = true;
        state.alive.store(false, Ordering::SeqCst);
        if first {
            state.deferred_generation_close=Some(Queued::new(ControlEvent::GenerationClosed{reason:"owner upload delivery admission closed; existing resource custody is retained".into()},None));
            // Logical admission closure adds no native effect or early EOF.
            // Other running jobs retain their sole custody terminal; only
            // actual IPC EOF invokes the existing native CloseOwner route.
            self.interrupt_uploads(
                Some(client),
                "upload I/O completed after delivery admission closed",
            );
        }
    }

    fn upload_event(&mut self, event: UploadEvent) {
        match event {
            UploadEvent::Authorize { id, owner, reply } => {
                let answer = self.authorize_upload(id, &owner);
                let _ = reply.send(answer);
            }
            UploadEvent::Completed(completion) => self.upload_completed(completion),
        }
    }

    fn authorize_upload(
        &mut self,
        id: u64,
        owner: &UploadOwner,
    ) -> Result<Vec<Arc<AtomicBool>>, &'static str> {
        let pending = self
            .pending
            .get_mut(&id)
            .ok_or("upload operation is no longer pending")?;
        let PendingKind::Upload(upload) = &mut pending.kind else {
            return Err("upload operation identity changed");
        };
        let context = pending
            .wire_context
            .as_ref()
            .ok_or("upload context is unavailable")?;
        if self.stopped
            || !self.generation_alive.load(Ordering::SeqCst)
            || owner.session_id != context.host_session_id()
        {
            return Err("upload owner or generation is unavailable");
        }
        let client = self
            .clients
            .get(&pending.client)
            .filter(|state| state.alive.load(Ordering::SeqCst) && !state.closing)
            .ok_or("upload connection is closed")?;
        let mut gates = vec![self.generation_alive.clone(), client.alive.clone()];
        if !upload.operation.cleanup() {
            let (token, claim) = self
                .claims
                .iter()
                .find(|(_, claim)| {
                    claim.client == pending.client
                        && claim.tab_id == owner.tab_id
                        && claim.target_id == owner.target_id
                        && claim.alive.load(Ordering::SeqCst)
                        && !claim.cleanup_only
                        && !claim.cdp_fenced
                })
                .ok_or("upload's actual physical claim is unavailable")?;
            upload.claim = Some(token.clone());
            gates.push(claim.alive.clone());
            if let Some(scope) = &pending.scope_fence {
                gates.push(scope.clone());
            }
        }
        Ok(gates)
    }

    fn upload_completed(&mut self, completion: UploadCompletion) {
        let Some(pending) = self.pending.remove(&completion.id) else {
            return;
        };
        if !matches!(&pending.kind, PendingKind::Upload(_)) {
            self.pending.insert(completion.id, pending);
            return;
        }
        let PendingKind::Upload(upload) = pending.kind else {
            unreachable!("upload kind was checked")
        };
        if completion.phase != upload.phase.load(Ordering::SeqCst)
            || !matches!(completion.phase, JOB_COMPLETED | JOB_CANCELLED)
        {
            if let UploadControl::RetireTab { outcome, .. } = upload.operation {
                self.upload_retirement_reply(UploadRetirementReply {
                    client: pending.client,
                    id: upload.local_id,
                    claim: upload.claim,
                    wire_context: pending.wire_context,
                    outcome: *outcome,
                    cleanup: Err("host upload cleanup completion phase is unavailable".into()),
                });
                self.finish_upload_generation();
                return;
            }
            self.upload_reply(
                pending.client,
                upload.local_id,
                ControlOutcome::Unknown {
                    reason: "host upload completion phase is unavailable".into(),
                    details: None,
                },
            );
            return;
        }
        let fact = match (&upload.operation, &completion.result) {
            (UploadControl::Begin { .. }, Ok(UploadWorkResult::Begun(stage))) => {
                Some(UploadCustodyFact::Begun(*stage))
            }
            (
                UploadControl::Begin { .. },
                Err(UploadWorkerError::Resource(UploadError::BeginIo { stage, .. })),
            ) => Some(UploadCustodyFact::PartialBegin(*stage)),
            (UploadControl::Write { stage, .. }, Ok(UploadWorkResult::Written)) => {
                Some(UploadCustodyFact::ChunkWritten(*stage))
            }
            (
                UploadControl::Retain { stage },
                Ok(UploadWorkResult::Retained(_) | UploadWorkResult::RetainedUnexposed),
            ) => Some(UploadCustodyFact::Retained(*stage)),
            (UploadControl::Retain { stage }, Err(UploadWorkerError::RetainedPlacement { .. })) => {
                Some(UploadCustodyFact::Retained(*stage))
            }
            (UploadControl::Abandon { stage }, Ok(UploadWorkResult::Abandoned)) => {
                Some(UploadCustodyFact::Abandoned(*stage))
            }
            _ => None,
        };
        let owner_ended = self
            .clients
            .get(&pending.client)
            .is_none_or(|state| state.closing || !state.alive.load(Ordering::SeqCst));
        let interrupted = upload
            .interrupted
            .or(owner_ended.then_some("upload I/O completed after its owner admission ended"))
            .or_else(|| {
                pending
                    .scope_fence
                    .as_ref()
                    .filter(|gate| !gate.load(Ordering::SeqCst))
                    .map(|_| "upload I/O completed after its captured execution scope ended")
            });
        if let UploadControl::RetireTab { owner, outcome } = upload.operation {
            if pending
                .wire_context
                .as_ref()
                .is_none_or(|context| owner.session_id != context.host_session_id())
            {
                self.upload_retirement_reply(UploadRetirementReply {
                    client: pending.client,
                    id: upload.local_id,
                    claim: upload.claim,
                    wire_context: pending.wire_context,
                    outcome: *outcome,
                    cleanup: Err("host upload cleanup lost its captured session identity".into()),
                });
                self.finish_upload_generation();
                return;
            }
            let cleanup = match completion.result {
                Ok(UploadWorkResult::TabRetired) => Ok(()),
                Ok(_) => Err("host upload cleanup result changed".into()),
                Err(error) => Err(error.to_string()),
            };
            self.upload_retirement_reply(UploadRetirementReply {
                client: pending.client,
                id: upload.local_id,
                claim: upload.claim,
                wire_context: pending.wire_context,
                outcome: *outcome,
                cleanup,
            });
            self.finish_upload_generation();
            return;
        }
        let outcome = match completion.result {
            Ok(result) => {
                let result = match (&upload.operation, result) {
                    (UploadControl::Begin { owner, files }, UploadWorkResult::Begun(stage)) => {
                        json!({"stage":stage,"tabId":owner.tab_id,"targetId":owner.target_id,"files":files.as_ref()})
                    }
                    (
                        UploadControl::Write {
                            stage,
                            file_index,
                            offset,
                            bytes,
                        },
                        UploadWorkResult::Written,
                    ) => {
                        json!({"stage":stage,"fileIndex":file_index,"offset":offset,"bytes":bytes,"written":true})
                    }
                    (UploadControl::Retain { .. }, UploadWorkResult::RetainedUnexposed) => {
                        self.upload_reply_custody(pending.client,upload.local_id,ControlOutcome::Unknown{reason:"actual retained backing paths were not admitted to this transport".into(),details:None},fact);
                        self.finish_upload_generation();
                        return;
                    }
                    (UploadControl::Retain { stage }, UploadWorkResult::Retained(paths)) => {
                        let paths = match serde_json::to_value(paths) {
                            Ok(paths) => paths,
                            Err(_) => {
                                self.upload_reply_custody(pending.client,upload.local_id,ControlOutcome::Unknown{reason:"retained upload backing paths cannot be represented by this JSON transport".into(),details:None},fact);
                                self.finish_upload_generation();
                                return;
                            }
                        };
                        json!({"stage":stage,"retained":true,"paths":paths})
                    }
                    (UploadControl::Abandon { stage }, UploadWorkResult::Abandoned) => {
                        json!({"stage":stage,"abandoned":true})
                    }
                    _ => {
                        self.upload_reply(
                            pending.client,
                            upload.local_id,
                            ControlOutcome::Unknown {
                                reason: "host upload result changed its issued operation".into(),
                                details: None,
                            },
                        );
                        self.finish_upload_generation();
                        return;
                    }
                };
                if let Some(reason) = interrupted {
                    ControlOutcome::Unknown {
                        reason: reason.into(),
                        details: Some(json!({"acknowledgedResult":result})),
                    }
                } else {
                    ControlOutcome::Result(result)
                }
            }
            Err(error) => {
                if completion.phase == JOB_CANCELLED {
                    ControlOutcome::NotDispatched {
                        kind: "upload_not_dispatched".into(),
                        message: error.to_string(),
                        details: None,
                    }
                } else {
                    let details = match (&upload.operation, &error) {
                        (
                            UploadControl::Begin { owner, files },
                            UploadWorkerError::Resource(UploadError::BeginIo { stage, .. }),
                        ) => Some(
                            json!({"uploadStage":{"stage":stage,"tabId":owner.tab_id,"targetId":owner.target_id,"files":files.as_ref()}}),
                        ),
                        _ => None,
                    };
                    match error {
                        UploadWorkerError::Resource(UploadError::Refused(reason))
                            if interrupted.is_none() =>
                        {
                            ControlOutcome::ConnectorRejected {
                                kind: "upload_refused".into(),
                                message: reason.into(),
                                details,
                            }
                        }
                        error => ControlOutcome::Unknown {
                            reason: error.to_string(),
                            details,
                        },
                    }
                }
            }
        };
        self.upload_reply_custody(pending.client, upload.local_id, outcome, fact);
        self.finish_upload_generation();
    }

    fn interrupt_uploads(&mut self, client: Option<ClientId>, reason: &'static str) {
        let ids = self
            .pending
            .iter()
            .filter_map(|(id, pending)| {
                (client.is_none_or(|client| client == pending.client)
                    && matches!(pending.kind, PendingKind::Upload(_)))
                .then_some(*id)
            })
            .collect::<Vec<_>>();
        for id in ids {
            let Some(mut pending) = self.pending.remove(&id) else {
                continue;
            };
            let PendingKind::Upload(upload) = &mut pending.kind else {
                unreachable!()
            };
            // Tab retirement is host-resource cleanup, not client-owned work.
            if client.is_some() && matches!(upload.operation, UploadControl::RetireTab { .. }) {
                self.pending.insert(id, pending);
                continue;
            }
            if cancel_queued(&upload.phase) {
                let PendingKind::Upload(upload) = pending.kind else {
                    unreachable!()
                };
                if let UploadControl::RetireTab { outcome, .. } = upload.operation {
                    self.upload_retirement_reply(UploadRetirementReply {
                        client: pending.client,
                        id: upload.local_id,
                        claim: upload.claim,
                        wire_context: pending.wire_context,
                        outcome: *outcome,
                        cleanup: Err(
                            "host upload cleanup was cancelled before filesystem work".into()
                        ),
                    });
                    continue;
                }
                self.upload_reply(
                    pending.client,
                    upload.local_id,
                    ControlOutcome::NotDispatched {
                        kind: "upload_not_dispatched".into(),
                        message: "queued upload was cancelled before filesystem work".into(),
                        details: None,
                    },
                );
            } else {
                upload.interrupted = Some(reason);
                self.pending.insert(id, pending);
            }
        }
    }

    fn upload_retirement_reply(&mut self, reply: UploadRetirementReply) {
        let UploadRetirementReply {
            client,
            id,
            claim,
            wire_context,
            outcome,
            cleanup,
        } = reply;
        let confirmed = cleanup.is_ok();
        let error = cleanup.err();
        if let Some(claim) = claim {
            let event = ControlEvent::EffectsCleanup {
                claim: claim.clone(),
                effect: "upload_backing".into(),
                cleanup_confirmed: confirmed,
                error,
                wire_context: wire_context.clone(),
            };
            match self.budget.try_charge(&event) {
                Ok(charge) => self.queue_control_delivery(client, Queued::new(event, Some(charge))),
                Err(_) => {
                    self.queue_control_delivery(client,Queued::new(ControlEvent::EffectsCleanup{claim,effect:"upload_backing".into(),cleanup_confirmed:confirmed,error:(!confirmed).then(||"upload backing cleanup remains unconfirmed; variable receipt was not admitted".into()),wire_context},None));
                    self.fence_upload_delivery_owner(client);
                }
            }
        }
        let physical = match &outcome {
            ControlOutcome::Result(result) => Some(result),
            ControlOutcome::Unknown {
                details: Some(details),
                ..
            } => details
                .get("acknowledgedResult")
                .or_else(|| details.get("physicalProof")),
            _ => None,
        }
        .filter(|result| result["closed"] == true)
        .and_then(|result| match result["proof"].as_str() {
            Some("close_ack") => Some(json!({"closed":true,"proof":"close_ack"})),
            Some("tab_removed") => Some(json!({"closed":true,"proof":"tab_removed"})),
            _ => None,
        });
        let event = ControlEvent::Reply { id, outcome };
        match self.budget.try_charge(&event) {
            Ok(charge) => self.queue_control_delivery(client, Queued::new(event, Some(charge))),
            Err(_) => {
                self.queue_control_delivery(client,Queued::new(ControlEvent::Reply{id,outcome:ControlOutcome::Unknown{reason:"actual Chrome close acknowledged; variable resource cleanup receipt was not admitted".into(),details:physical.map(|physical|json!({"physicalProof":physical}))}},None));
                self.fence_upload_delivery_owner(client);
            }
        }
    }

    fn resource_work_pending(&self, client: ClientId) -> bool {
        self.pending.values().any(|pending| {
            pending.client == client
                && matches!(
                    pending.kind,
                    PendingKind::Upload(_)
                        | PendingKind::Control {
                            operation: ControlKind::Close(_),
                            ..
                        }
                )
        })
    }

    fn finish_upload_generation(&mut self) {
        if !self.stopped {
            let ready = self
                .clients
                .keys()
                .copied()
                .filter(|client| {
                    self.clients[client]
                        .controls_in_flight
                        .load(Ordering::SeqCst)
                        == 0
                        && !self.pending.values().any(|pending| {
                            pending.client == *client
                                && matches!(pending.kind, PendingKind::Upload(_))
                        })
                })
                .collect::<Vec<_>>();
            for client in ready {
                if let Some(event) = self
                    .clients
                    .get_mut(&client)
                    .and_then(|state| state.deferred_generation_close.take())
                {
                    self.queue_control_delivery(client, event);
                }
            }

            let retired = self
                .clients
                .iter()
                .filter_map(|(id, state)| {
                    (state.closing
                        && matches!(state.extension_cleanup, OwnerCleanup::Confirmed)
                        && state.controls_in_flight.load(Ordering::SeqCst) == 0
                        && !self.resource_work_pending(*id))
                    .then_some(*id)
                })
                .collect::<Vec<_>>();
            for id in retired {
                if let Some(client) = self.clients.remove(&id) {
                    self.owners.remove(&client.owner);
                }
            }
        }
        if self
            .pending
            .values()
            .any(|pending| matches!(pending.kind, PendingKind::Upload(_)))
            || self
                .clients
                .values()
                .any(|state| state.controls_in_flight.load(Ordering::SeqCst) != 0)
        {
            return;
        }
        if let Some(reason) = self.closing_uploads.take() {
            self.generation_closed_receipts(&reason);
        }
    }

    fn generation_closed_receipts(&mut self, reason: &str) {
        for client in self.clients.keys().copied().collect::<Vec<_>>() {
            if let Some(state) = self.clients.get_mut(&client) {
                state.deferred_generation_close = None;
            }
            self.queue_control_delivery(
                client,
                Queued::new(
                    ControlEvent::GenerationClosed {
                        reason: reason.to_owned(),
                    },
                    None,
                ),
            );
        }
        self.budget.close();
    }

    fn control(
        &mut self,
        client: ClientId,
        request: ControlRequest,
        output: &mut Vec<ExtensionOutbound>,
    ) {
        let id = request.id();
        let cleanup = request.is_cleanup();
        let Some(state) = self.clients.get_mut(&client) else {
            return;
        };
        if !state.alive.load(Ordering::SeqCst)
            || state.closing
            || (state.delivery_blocked && !cleanup)
        {
            if matches!(
                &request,
                ControlRequest::BeginUpload { .. }
                    | ControlRequest::WriteUploadChunk { .. }
                    | ControlRequest::RetainUploadForSelection { .. }
                    | ControlRequest::AbandonUpload { .. }
            ) {
                let outcome = if id == 0 || id <= state.high_water {
                    ControlOutcome::ConnectorRejected {
                        kind: "duplicate_local_id".into(),
                        message: "local upload IDs cannot alias an earlier request".into(),
                        details: None,
                    }
                } else {
                    state.high_water = id;
                    ControlOutcome::NotDispatched{kind:"owner_closed".into(),message:"upload admission closed before this queued request entered filesystem work".into(),details:None}
                };
                self.queue_control_delivery(
                    client,
                    Queued::new(ControlEvent::Reply { id, outcome }, None),
                );
                return;
            }
            if matches!(
                request,
                ControlRequest::FenceCdp { .. } | ControlRequest::RetireClaim { .. }
            ) {
                self.emit_control(
                    client,
                    ControlEvent::Reply {
                        id,
                        outcome: ControlOutcome::Unknown {
                            reason: "claim CDP snapshot is unavailable after its owner closed"
                                .to_owned(),
                            details: None,
                        },
                    },
                    output,
                );
            }
            return;
        }
        if id == 0 || id <= state.high_water {
            if matches!(
                request,
                ControlRequest::FenceCdp { .. } | ControlRequest::RetireClaim { .. }
            ) {
                self.fence_cdp_reply(
                    client,
                    id,
                    ControlOutcome::ConnectorRejected {
                        kind: "duplicate_local_id".to_owned(),
                        message: "local control IDs cannot be replayed".to_owned(),
                        details: None,
                    },
                    output,
                );
            } else {
                // The echoed ID can alias an older still-live request. The
                // duplicate itself did not dispatch, but this reply cannot prove
                // that the older request named by the same ID had no effect.
                self.emit_control(
                    client,
                    ControlEvent::Reply {
                        id,
                        outcome: ControlOutcome::ConnectorRejected {
                            kind: "duplicate_local_id".to_owned(),
                            message: "local control IDs cannot be replayed".to_owned(),
                            details: None,
                        },
                    },
                    output,
                );
            }
            return;
        }
        state.high_water = id;
        if let ControlRequest::FenceCdp { claim, .. } = &request {
            self.fence_cdp(client, id, claim, output);
            return;
        }
        if let ControlRequest::RetireClaim {
            claim, cleanup_id, ..
        } = &request
        {
            self.retire_claim(client, id, claim, *cleanup_id, output);
            return;
        }
        if !cleanup && self.normal_pending() >= MAX_NORMAL_PENDING {
            self.reject_control(
                client,
                id,
                "request_budget",
                "extension broker request budget exhausted",
                output,
            );
            return;
        }
        if cleanup && (self.pending.len() >= MAX_NORMAL_PENDING + MAX_CLEANUP_PENDING) {
            self.reject_control(
                client,
                id,
                "cleanup_budget",
                "extension cleanup control budget exhausted; connection EOF still reserves closeOwner",
                output,
            );
            return;
        }
        if matches!(
            &request,
            ControlRequest::BeginUpload { .. }
                | ControlRequest::WriteUploadChunk { .. }
                | ControlRequest::RetainUploadForSelection { .. }
                | ControlRequest::AbandonUpload { .. }
        ) {
            self.upload_control(client, request, output);
            return;
        }
        let fixed_session = matches!(
            &request,
            ControlRequest::PrepareSessionTab { .. }
                | ControlRequest::CreateSessionPopupTab { .. }
                | ControlRequest::SessionUi { .. }
                | ControlRequest::ClearSessionPreparation { .. }
        );
        if fixed_session {
            if self.input_context.is_none() {
                self.reject_control(
                    client,
                    id,
                    "context_required",
                    "fixed-session operations require captured trusted wire context",
                    output,
                );
                return;
            }
            if !self.identity.as_ref().is_some_and(|identity| {
                identity.capabilities["sessionPreparation"] == "explicit_fixed"
            }) {
                self.reject_control(
                    client,
                    id,
                    "unsupported",
                    "selected provider has no explicit fixed-session service",
                    output,
                );
                return;
            }
            let valid = match &request {
                ControlRequest::PrepareSessionTab {
                    tab_id,
                    scope_id,
                    ui,
                    ..
                } => {
                    *tab_id > 0
                        && *tab_id <= 9_007_199_254_740_991
                        && canonical_scope(scope_id)
                        && ui.validate_preparation().is_ok()
                }
                ControlRequest::SessionUi {
                    tab_id,
                    scope_id,
                    ui,
                    ..
                } => {
                    *tab_id > 0
                        && *tab_id <= 9_007_199_254_740_991
                        && canonical_scope(scope_id)
                        && ui.validate().is_ok()
                }
                ControlRequest::CreateSessionPopupTab {
                    tab_id, scope_id, ..
                }
                | ControlRequest::ClearSessionPreparation {
                    tab_id, scope_id, ..
                } => *tab_id > 0 && *tab_id <= 9_007_199_254_740_991 && canonical_scope(scope_id),
                _ => false,
            };
            if !valid {
                self.reject_control(
                    client,
                    id,
                    "invalid_request",
                    "fixed-session request has invalid scope, tab or closed UI input",
                    output,
                );
                return;
            }
        }
        if matches!(
            &request,
            ControlRequest::PrepareClaim { .. }
                | ControlRequest::CreatePopupTab { .. }
                | ControlRequest::MarkTab { .. }
        ) && self.input_context.is_none()
        {
            self.reject_control(
                client,
                id,
                "context_required",
                "same-claim preparation requires captured trusted wire context",
                output,
            );
            return;
        }
        if let ControlRequest::ReadUserTab {
            tab_id,
            expected_url,
            ..
        } = &request
        {
            let valid = *tab_id > 0
                && *tab_id <= 9_007_199_254_740_991
                && url::Url::parse(expected_url)
                    .is_ok_and(|url| matches!(url.scheme(), "http" | "https"));
            if !valid {
                self.reject_control(
                    client,
                    id,
                    "invalid_request",
                    "Tab reads require a positive safe tab ID and HTTP or HTTPS URL",
                    output,
                );
                return;
            }
            if self.input_context.is_none() {
                self.reject_control(
                    client,
                    id,
                    "context_required",
                    "user-tab reads require captured trusted wire context",
                    output,
                );
                return;
            }
            if !self.identity.as_ref().is_some_and(|identity| {
                identity.capabilities["userTabContextRead"].as_bool() == Some(true)
            }) {
                self.reject_control(
                    client,
                    id,
                    "unsupported",
                    "selected provider does not support fixed user-tab context reads",
                    output,
                );
                return;
            }
        }

        let session_inventory = matches!(
            &request,
            ControlRequest::Inventory {
                session_only: Some(true),
                ..
            }
        );
        if let ControlRequest::Inventory { known_tab_ids, .. } = &request {
            let mut ids = HashSet::new();
            let valid = if session_inventory {
                known_tab_ids.as_ref().is_some_and(|values| {
                    values
                        .iter()
                        .all(|id| *id > 0 && *id <= 9_007_199_254_740_991 && ids.insert(*id))
                })
            } else {
                known_tab_ids.is_none()
            };
            if !valid {
                self.reject_control(client, id, "invalid_request", "session inventory requires unique positive safe candidate IDs and sessionOnly:true", output);
                return;
            }
        }
        let session_only = session_inventory
            || matches!(
                &request,
                ControlRequest::Resolve {
                    session_only: true,
                    ..
                } | ControlRequest::PrepareUserTab {
                    session_only: true,
                    ..
                }
            );
        let committed_url_only = matches!(
            &request,
            ControlRequest::Resolve {
                committed_url_only: true,
                ..
            }
        );
        if committed_url_only && !session_only {
            self.reject_control(
                client,
                id,
                "invalid_request",
                "committed URL selection requires the captured session-only purpose",
                output,
            );
            return;
        }
        if session_only && self.input_context.is_none() {
            self.reject_control(
                client,
                id,
                "context_required",
                "session-only metadata and preparation require captured trusted wire context",
                output,
            );
            return;
        }
        if session_only
            && !self.identity.as_ref().is_some_and(|identity| {
                let capability = if session_inventory {
                    "sessionTabInventory"
                } else if committed_url_only {
                    "sessionCommittedUrl"
                } else {
                    "sessionTabResolution"
                };
                identity.capabilities[capability].as_bool() == Some(true)
            })
        {
            self.reject_control(
                client,
                id,
                "unsupported",
                "selected provider does not support the session-only selector",
                output,
            );
            return;
        }
        if matches!(
            &request,
            ControlRequest::PrepareUserTab {
                session_only: true,
                ..
            }
        ) && !self.identity.as_ref().is_some_and(|identity| {
            identity.capabilities["sessionPreparation"] == "provider_session"
        }) {
            self.reject_control(
                client,
                id,
                "unsupported",
                "session preparation is not a metadata selector acknowledgement",
                output,
            );
            return;
        }
        let (method, params, operation) = match request {
            ControlRequest::CreateSessionPopupTab {
                tab_id, scope_id, ..
            } => (
                "createSessionPopupTab",
                json!({"tabId":tab_id,"scopeId":scope_id}),
                ControlKind::Other,
            ),
            ControlRequest::PrepareSessionTab {
                tab_id,
                scope_id,
                policy,
                ui,
                ..
            } => (
                "prepareSessionTab",
                json!({"tabId":tab_id,"scopeId":scope_id,"policy":policy,"ui":ui}),
                ControlKind::Other,
            ),
            ControlRequest::SessionUi {
                tab_id,
                scope_id,
                ui,
                ..
            } => (
                "sessionUi",
                json!({"tabId":tab_id,"scopeId":scope_id,"ui":ui}),
                ControlKind::Other,
            ),
            ControlRequest::ClearSessionPreparation {
                tab_id, scope_id, ..
            } => (
                "clearSessionPreparation",
                json!({"tabId":tab_id,"scopeId":scope_id}),
                ControlKind::Other,
            ),
            ControlRequest::PrepareClaim {
                claim,
                document,
                policy,
                ..
            } => {
                if !self.owns_active_claim(client, &claim) {
                    self.reject_control(
                        client,
                        id,
                        "claim_unavailable",
                        "preparation claim is not active for this connection",
                        output,
                    );
                    return;
                }
                (
                    "prepareClaim",
                    json!({"claim":claim,"document":document,"policy":policy}),
                    ControlKind::Other,
                )
            }
            ControlRequest::MarkTab { claim, status, .. } => {
                if claim.is_empty() || claim.len() > 128 || !self.owns_active_claim(client, &claim)
                {
                    self.reject_control(
                        client,
                        id,
                        "claim_unavailable",
                        "mark claim is not active for this connection",
                        output,
                    );
                    return;
                }
                (
                    "markTab",
                    json!({"claim":claim,"status":status}),
                    ControlKind::Other,
                )
            }
            ControlRequest::CreatePopupTab { claim, .. } => {
                if !self.owns_active_claim(client, &claim) {
                    self.reject_control(
                        client,
                        id,
                        "claim_unavailable",
                        "popup opener claim is not active for this connection",
                        output,
                    );
                    return;
                }
                ("createPopupTab", json!({"claim":claim}), ControlKind::Other)
            }
            ControlRequest::ReadUserTab {
                tab_id,
                expected_url,
                read,
                ..
            } => (
                "readUserTab",
                json!({"tabId":tab_id,"expectedUrl":expected_url,"read":read}),
                ControlKind::Other,
            ),
            ControlRequest::Inventory { known_tab_ids, .. } => {
                let params = if session_inventory {
                    json!({"sessionOnly":true,"knownTabIds":known_tab_ids.expect("validated session inventory candidates")})
                } else {
                    json!({})
                };
                ("inventory", params, ControlKind::Inventory)
            }
            ControlRequest::Resolve {
                raw_id,
                session_only,
                committed_url_only,
                ..
            } if !raw_id.is_empty() => {
                let mut params = json!({"rawId":raw_id});
                if session_only {
                    params["sessionOnly"] = json!(true);
                }
                if committed_url_only {
                    params["committedUrlOnly"] = json!(true);
                }
                ("resolve", params, ControlKind::Resolve)
            }
            ControlRequest::CreateTab { window_id, .. } => (
                "createTab",
                window_id.map_or_else(|| json!({}), |window_id| json!({"windowId":window_id})),
                ControlKind::Other,
            ),
            ControlRequest::PrepareUserTab {
                tab_id,
                session_only,
                ..
            } if tab_id <= 9_007_199_254_740_991 => {
                let mut params = json!({"tabId":tab_id});
                if session_only {
                    params["sessionOnly"] = json!(true);
                }
                ("prepareUserTab", params, ControlKind::Other)
            }
            ControlRequest::MuteCreatedTab { creation, .. } => (
                "muteCreatedTab",
                json!({"creation":creation}),
                ControlKind::Other,
            ),
            ControlRequest::UnmuteCreatedTabIfActive { creation, .. } => (
                "unmuteCreatedTabIfActive",
                json!({"creation":creation}),
                ControlKind::Other,
            ),
            ControlRequest::EnsureCreatedTabGroup {
                creation,
                presentation,
                ..
            } => (
                "ensureCreatedTabGroup",
                json!({"creation":creation,"presentation":presentation}),
                ControlKind::Other,
            ),
            ControlRequest::UpdateCreatedTabGroup {
                creation,
                group,
                presentation,
                ..
            } => (
                "updateCreatedTabGroup",
                json!({"creation":creation,"group":group,"presentation":presentation}),
                ControlKind::Other,
            ),
            ControlRequest::ReleaseCreatedTabGroup {
                creation, group, ..
            } => (
                "releaseCreatedTabGroup",
                json!({"creation":creation,"group":group}),
                ControlKind::Other,
            ),
            ControlRequest::StopCreatedTab {
                creation, tab_id, ..
            } if !creation.is_empty()
                && creation.len() <= 128
                && tab_id.is_none_or(|id| id <= 9_007_199_254_740_991) =>
            {
                (
                    "stopCreatedTab",
                    json!({"creation":creation}),
                    ControlKind::StopCreated(tab_id),
                )
            }
            ControlRequest::FinishTurn { keep, .. } => {
                if let Some(context) = self.input_context.as_ref() {
                    self.fence_existing_scope(client, context);
                }
                ("finishTurn", json!({"keep":keep}), ControlKind::Other)
            }
            ControlRequest::UserHistory { options, .. } if options.is_object() => {
                ("userHistory", options, ControlKind::Other)
            }
            ControlRequest::NameSession { name, .. } if !name.is_empty() => {
                ("nameSession", json!({"name":name}), ControlKind::Other)
            }
            ControlRequest::SetSessionHeaders { headers, .. } => (
                "setSessionHeaders",
                json!({"headers":headers}),
                ControlKind::Other,
            ),
            ControlRequest::ClearSessionHeaders { .. } => {
                ("clearSessionHeaders", json!({}), ControlKind::Other)
            }
            ControlRequest::MoveMouse {
                claim,
                x,
                y,
                wait_for_arrival,
                ..
            } if x.is_finite() && y.is_finite() => {
                if !self.owns_active_claim(client, &claim) {
                    self.reject_control(
                        client,
                        id,
                        "claim_unavailable",
                        "claim is not owned by this connection",
                        output,
                    );
                    return;
                }
                let mut params = json!({"claim":claim,"x":x,"y":y});
                if let Some(wait_for_arrival) = wait_for_arrival {
                    params["waitForArrival"] = json!(wait_for_arrival);
                }
                ("moveMouse", params, ControlKind::Other)
            }
            ControlRequest::CloseTab { claim, .. } => {
                if !self.owns_active_claim(client, &claim) {
                    self.reject_control(
                        client,
                        id,
                        "claim_unavailable",
                        "claim is not owned by this connection",
                        output,
                    );
                    return;
                }
                let record = &self.claims[&claim];
                let identity = ClosingClaim {
                    claim: claim.clone(),
                    tab_id: record.tab_id,
                    target_id: record.target_id.clone(),
                };
                (
                    "closeTab",
                    json!({"claim":claim}),
                    ControlKind::Close(identity),
                )
            }
            ControlRequest::ClearScopedHeaders { claim, .. } => {
                if !self.owns_active_claim(client, &claim) {
                    self.reject_control(
                        client,
                        id,
                        "claim_unavailable",
                        "claim is not owned by this connection",
                        output,
                    );
                    return;
                }
                (
                    "clearScopedHeaders",
                    json!({"claim":claim}),
                    ControlKind::Other,
                )
            }
            ControlRequest::SetScopedHeaders {
                claim,
                session_id,
                headers,
                ..
            } => {
                if !self.owns_active_claim(client, &claim) {
                    self.reject_control(
                        client,
                        id,
                        "claim_unavailable",
                        "claim is not owned by this connection",
                        output,
                    );
                    return;
                }
                let mut params = json!({"claim":claim,"sessionId":session_id});
                if let Some(headers) = headers {
                    params["headers"] = json!(headers);
                }
                ("setScopedHeaders", params, ControlKind::Other)
            }
            ControlRequest::Attach { tab_id, .. } if tab_id <= 9_007_199_254_740_991 => {
                let state = self
                    .clients
                    .get_mut(&client)
                    .expect("client was checked above");
                if !state.attaching.insert(tab_id) {
                    self.reject_control(
                        client,
                        id,
                        "attach_pending",
                        "this tab already has an attach pending",
                        output,
                    );
                    return;
                }
                (
                    "attach",
                    json!({"tabId":tab_id}),
                    ControlKind::Attach(tab_id),
                )
            }
            ControlRequest::Detach { claim, .. } => {
                let Some(record) = self
                    .claims
                    .get_mut(&claim)
                    .filter(|record| record.client == client)
                else {
                    self.reject_control(
                        client,
                        id,
                        "claim_unavailable",
                        "claim is not owned by this connection",
                        output,
                    );
                    return;
                };
                record.alive.store(false, Ordering::SeqCst);
                if let Some(route) = record.route {
                    self.retire_route(route, "owned claim is detaching");
                }
                ("detach", json!({"claim":claim}), ControlKind::Detach(claim))
            }
            _ => {
                self.reject_control(
                    client,
                    id,
                    "invalid_request",
                    "invalid control request",
                    output,
                );
                return;
            }
        };
        self.enqueue(
            client,
            method,
            params,
            PendingKind::Control {
                local_id: id,
                operation,
            },
            None,
            output,
        );
    }

    fn retire_claim(
        &mut self,
        client: ClientId,
        id: u64,
        claim: &str,
        cleanup_id: u64,
        output: &mut Vec<ExtensionOutbound>,
    ) {
        let exact_cleanup = self.claims.get(claim).is_some_and(|record| {
            record.client == client
                && record.cdp_fenced
                && record.cleanup_id == Some(cleanup_id)
                && cleanup_id != 0
                && !record.alive.load(Ordering::SeqCst)
        });
        let raw_pending = self.pending.values().any(|pending| {
            pending.client == client
                && matches!(&pending.kind, PendingKind::Cdp { claim: token, .. } if token == claim)
        });
        if !exact_cleanup || raw_pending {
            self.fence_cdp_reply(
                client,
                id,
                ControlOutcome::Unknown {
                    reason: "claim retirement requires its exact known cleanup and empty fenced CDP custody".to_owned(),
                    details: None,
                },
                output,
            );
            return;
        }
        // The caller retains the opaque cleanup receipt until Host effects
        // have folded. This local operation never invokes extension cleanup.
        self.claims.remove(claim);
        self.fence_cdp_reply(
            client,
            id,
            ControlOutcome::Result(json!({"retired":true,"claim":claim})),
            output,
        );
    }

    fn fence_cdp(
        &mut self,
        client: ClientId,
        id: u64,
        claim: &str,
        output: &mut Vec<ExtensionOutbound>,
    ) {
        let Some(record) = self
            .claims
            .get_mut(claim)
            .filter(|record| record.client == client)
        else {
            self.fence_cdp_reply(
                client,
                id,
                ControlOutcome::Unknown {
                    reason: "exact claim CDP custody is unavailable; absence is not drain proof"
                        .to_owned(),
                    details: None,
                },
                output,
            );
            return;
        };
        // Keep exact physical cleanup admissible. Every pending CDP write
        // already owns its route's atomic gate, so retiring those routes and
        // refusing future binds fences CDP without revoking header cleanup.
        record.cdp_fenced = true;
        for pending in self.pending.values() {
            if let PendingKind::Upload(upload) = &pending.kind {
                if upload.claim.as_deref() == Some(claim) && !upload.operation.cleanup() {
                    if let Some(gate) = &pending.scope_fence {
                        gate.store(false, Ordering::SeqCst);
                    }
                }
            }
        }
        let routes = self
            .routes
            .iter()
            .filter(|(_, record)| record.client == client && record.claim == claim)
            .map(|(route, _)| *route)
            .collect::<Vec<_>>();
        for route in routes {
            self.retire_route(route, "claim CDP is fenced for settlement");
        }
        // Queued records remain until a real writer report. A writer racing
        // the route's atomic fence can never vanish from this snapshot.
        let mut pending = self.pending.iter().filter_map(|(outer, record)| {
            if record.client != client {
                return None;
            }
            let PendingKind::Cdp { route, claim: pending_claim, inner_id, unknown } = &record.kind else {
                return None;
            };
            if pending_claim != claim {
                return None;
            }
            Some((*outer, json!({"route":route.0,"id":inner_id,"wireContext":record.wire_context,"unknownReason":unknown})))
        }).collect::<Vec<_>>();
        pending.sort_unstable_by_key(|(outer, _)| *outer);
        let pending = pending
            .into_iter()
            .map(|(_, value)| value)
            .collect::<Vec<_>>();
        self.fence_cdp_reply(
            client,
            id,
            ControlOutcome::Result(
                json!({"claim":claim,"generation":self.generation,"fenced":true,"pending":pending}),
            ),
            output,
        );
    }

    fn fence_cdp_reply(
        &mut self,
        client: ClientId,
        id: u64,
        outcome: ControlOutcome,
        output: &mut Vec<ExtensionOutbound>,
    ) {
        let event = ControlEvent::Reply { id, outcome };
        match self.budget.try_charge(&event) {
            Ok(charge) => self.queue_control_delivery(client, Queued::new(event, Some(charge))),
            Err(_) => {
                // The fence and Pending custody survive. Closing this exact
                // peer prevents an unbounded tail of uncharged failure replies.
                self.emit_control(
                    client,
                    ControlEvent::Reply {
                        id,
                        outcome: ControlOutcome::Unknown {
                            reason: "claim CDP snapshot could not enter the bounded delivery queue"
                                .to_owned(),
                            details: None,
                        },
                    },
                    output,
                );
                self.close_client(client, output);
            }
        }
    }

    fn claim_cdp_progress(
        &mut self,
        client: ClientId,
        claim: &str,
        output: &mut Vec<ExtensionOutbound>,
    ) {
        if self
            .claims
            .get(claim)
            .is_some_and(|record| record.client == client && record.cdp_fenced)
        {
            self.emit_control(
                client,
                ControlEvent::ClaimCdpProgress {
                    claim: claim.to_owned(),
                },
                output,
            );
        }
    }

    fn cdp_input(
        &mut self,
        client: ClientId,
        route: RouteId,
        claim: &str,
        message: Value,
        output: &mut Vec<ExtensionOutbound>,
    ) {
        if self.routes.get(&route).is_some_and(|record| {
            record.client == client && record.claim == claim && record.alive.load(Ordering::SeqCst)
        }) {
            self.cdp(client, route, message, output);
            return;
        }
        // RouteSender captured these IDs before input admission. Retirement
        // can race the actor dequeue, but cannot turn unsent work into a hang
        // or a extension dispatch. No new claim record is needed to refuse it.
        if !self.clients.contains_key(&client) {
            return;
        }
        if let Some(id) = message["id"].as_u64().filter(|id| *id != 0) {
            self.queue_cdp_control(
                client,
                ControlEvent::CdpMessage {
                    route: route.0,
                    claim: claim.to_owned(),
                    event: BrokerCdpEvent::LocalRejected {
                        id,
                        code: "not_dispatched".to_owned(),
                        message: "CDP route ended before extension dispatch".to_owned(),
                    },
                    wire_context: self.input_context.clone(),
                },
            );
        }
    }

    fn cdp(
        &mut self,
        client: ClientId,
        route: RouteId,
        message: Value,
        output: &mut Vec<ExtensionOutbound>,
    ) {
        let Some(route_state) = self
            .routes
            .get_mut(&route)
            .filter(|route| route.client == client && route.alive.load(Ordering::SeqCst))
        else {
            return;
        };
        let Some(object) = message.as_object() else {
            self.close_route(route, "malformed local CDP envelope", output);
            return;
        };
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "id" | "method" | "params" | "sessionId"))
        {
            self.close_route(
                route,
                "local CDP envelope contains transport authority fields",
                output,
            );
            return;
        }
        let Some(inner_id) = message["id"].as_u64().filter(|id| *id != 0) else {
            self.close_route(route, "local CDP ID is invalid", output);
            return;
        };
        if inner_id <= route_state.high_water {
            self.emit_cdp(
                route,
                BrokerCdpEvent::LocalRejected {
                    id: inner_id,
                    code: "duplicate_local_id".to_owned(),
                    message: "CDP IDs cannot replay within a claim route".to_owned(),
                },
                output,
            );
            return;
        }
        route_state.high_water = inner_id;
        let claim = route_state.claim.clone();
        let route_fence = route_state.alive.clone();
        let Some(method) = message["method"]
            .as_str()
            .filter(|method| !method.is_empty())
        else {
            self.close_route(route, "local CDP method is invalid", output);
            return;
        };
        if self.normal_pending() >= MAX_NORMAL_PENDING {
            self.emit_cdp(
                route,
                BrokerCdpEvent::LocalRejected {
                    id: inner_id,
                    code: "request_budget".to_owned(),
                    message: "extension broker request budget exhausted".to_owned(),
                },
                output,
            );
            return;
        }
        let Some(claim_state) = self.claims.get(&claim).filter(|record| {
            record.client == client && record.alive.load(Ordering::SeqCst) && !record.cdp_fenced
        }) else {
            self.close_route(route, "physical claim ended or CDP was fenced", output);
            return;
        };
        let claim_fence = claim_state.alive.clone();
        let mut params = json!({"claim":claim,"method":method,"params":message.get("params").cloned().unwrap_or_else(||json!({}))});
        if let Some(session) = message.get("sessionId") {
            if !session.is_string() {
                self.close_route(route, "local child session is invalid", output);
                return;
            }
            params["sessionId"] = session.clone();
        }
        self.enqueue(
            client,
            "cdp",
            params,
            PendingKind::Cdp {
                route,
                claim,
                inner_id,
                unknown: None,
            },
            Some(vec![route_fence, claim_fence]),
            output,
        );
    }

    fn normal_pending(&self) -> usize {
        self.pending
            .values()
            .filter(|pending| {
                matches!(
                    pending.kind,
                    PendingKind::Upload(_)
                        | PendingKind::Cdp { .. }
                        | PendingKind::Control {
                            operation: ControlKind::Inventory
                                | ControlKind::Resolve
                                | ControlKind::Attach(_)
                                | ControlKind::Close(_)
                                | ControlKind::Other,
                            ..
                        }
                )
            })
            .count()
    }

    fn owns_active_claim(&self, client: ClientId, claim: &str) -> bool {
        self.claims.get(claim).is_some_and(|record| {
            record.client == client && record.alive.load(Ordering::SeqCst) && !record.cleanup_only
        })
    }

    /// Fence only work already admitted for this exact trusted Host scope.
    /// Main's existing epoch/turn admission owns post-Stop authorization; no
    /// broker tombstone, session registry or physical cleanup proof is created.
    fn fence_existing_scope(&self, client: ClientId, context: &ExtensionWireContext) {
        for pending in self.pending.values().filter(|pending| {
            pending.client == client && pending.wire_context.as_ref() == Some(context)
        }) {
            if let Some(fence) = &pending.scope_fence {
                fence.store(false, Ordering::SeqCst);
            }
        }
    }

    fn enqueue(
        &mut self,
        client: ClientId,
        method: &str,
        params: Value,
        kind: PendingKind,
        extra_fences: Option<Vec<Arc<AtomicBool>>>,
        output: &mut Vec<ExtensionOutbound>,
    ) {
        let Some(state) = self.clients.get(&client) else {
            return;
        };
        let cleanup = matches!(kind, PendingKind::CloseOwner);
        let Some(outer) = self.next_outer.checked_add(1) else {
            self.end_generation("extension request ID exhausted");
            return;
        };
        self.next_outer = outer;
        let mut fences = vec![self.generation_alive.clone()];
        if !cleanup {
            fences.push(state.alive.clone());
        }
        fences.extend(extra_fences.unwrap_or_default());
        let scope_cleanup = matches!(
            method,
            "closeOwner" | "detach" | "stopCreatedTab" | "finishTurn" | "clearSessionPreparation"
        );
        let scope_fence = (!scope_cleanup && self.input_context.is_some())
            .then(|| Arc::new(AtomicBool::new(true)));
        if let Some(fence) = &scope_fence {
            fences.push(fence.clone());
        }
        let dispatch = Arc::new(AtomicU8::new(QUEUED));
        let value = json!({"kind":"request","protocol":1,"generation":self.generation,"id":outer.to_string(),"owner":state.owner,"method":method,"params":params});
        self.pending.insert(
            outer,
            Pending {
                client,
                kind,
                dispatch: dispatch.clone(),
                scope_fence,
                wire_context: if cleanup {
                    None
                } else {
                    self.input_context.clone()
                },
            },
        );
        output.push(ExtensionOutbound {
            value,
            generation: self.generation.clone(),
            owner: Some(state.owner.clone()),
            outer: Some(outer),
            fences,
            dispatch,
            _charge: self.current_charge.clone(),
            wire_context: if cleanup {
                None
            } else {
                self.input_context.clone()
            },
        });
    }

    fn reap_fences(&mut self, output: &mut Vec<ExtensionOutbound>) {
        let clients = self
            .clients
            .iter()
            .filter(|(_, state)| !state.closing && !state.alive.load(Ordering::SeqCst))
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for client in clients {
            self.close_client(client, output);
        }
        let routes = self
            .routes
            .iter()
            .filter(|(_, route)| !route.alive.load(Ordering::SeqCst))
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for route in routes {
            self.close_route(route, "CDP route was dropped", output);
        }
    }

    fn cdp_unconfirmed(&mut self, receipt: UnconfirmedCdp<'_>, event: Option<BrokerCdpEvent>) {
        let write_phase = match receipt.dispatch.load(Ordering::SeqCst) {
            QUEUED => ExtensionCdpWritePhase::Queued,
            STARTED => ExtensionCdpWritePhase::Started,
            WRITTEN => ExtensionCdpWritePhase::Written,
            SKIPPED => ExtensionCdpWritePhase::Skipped,
            _ => ExtensionCdpWritePhase::Unknown,
        };
        let event = ControlEvent::CdpUnconfirmed {
            claim: receipt.claim.to_owned(),
            route: receipt.route.0,
            id: receipt.id,
            write_phase,
            reason: UNKNOWN_CDP_REASON.to_owned(),
            event,
            wire_context: receipt.wire_context.cloned(),
        };
        // Phase and its exact terminal share the control FIFO. Each new
        // payload owns its actual bytes, including captured context copies.
        self.queue_cdp_control(receipt.client, event);
    }

    fn queue_cdp_control(&mut self, client: ClientId, event: ControlEvent) {
        match self.budget.try_charge(&event) {
            Ok(charge) => self.queue_control_delivery(client, Queued::new(event, Some(charge))),
            Err(_) => self.fail_client_cdp_delivery(client),
        }
    }

    fn fail_client_cdp_delivery(&mut self, client: ClientId) {
        let Some(state) = self.clients.get_mut(&client) else {
            return;
        };
        let first_failure = !state.closing;
        state.closing = true;
        state.alive.store(false, Ordering::SeqCst);
        for claim in self.claims.values().filter(|claim| claim.client == client) {
            claim.alive.store(false, Ordering::SeqCst);
        }
        for route in self.routes.values().filter(|route| route.client == client) {
            route.alive.store(false, Ordering::SeqCst);
        }
        // This fixed local-lifetime diagnostic carries no phase or cleanup
        // proof. Do not recurse through route cleanup or extension EOF while
        // emitting EOF metadata under an exhausted byte budget.
        if first_failure {
            let event=Queued::new(ControlEvent::GenerationClosed{reason:"owner CDP delivery budget exhausted; invocation and effect settlement remain unknown".to_owned()},None);
            if self.clients[&client]
                .controls_in_flight
                .load(Ordering::SeqCst)
                != 0
                || self.pending.values().any(|pending| {
                    pending.client == client && matches!(pending.kind, PendingKind::Upload(_))
                })
            {
                if let Some(state) = self.clients.get_mut(&client) {
                    state.deferred_generation_close = Some(event);
                }
                self.interrupt_uploads(
                    Some(client),
                    "upload I/O completed after CDP delivery admission ended",
                );
            } else {
                self.queue_control_delivery(client, event);
            }
        }
    }

    fn route_unconfirmed(&mut self, route: RouteId, reason: Option<&str>) {
        let mut requests = self
            .pending
            .iter()
            .filter_map(|(outer, pending)| {
                let PendingKind::Cdp {
                    route: actual,
                    claim,
                    inner_id,
                    ..
                } = &pending.kind
                else {
                    return None;
                };
                if *actual != route {
                    return None;
                }
                Some((*outer, pending.client, claim.clone(), *inner_id))
            })
            .collect::<Vec<_>>();
        requests.sort_unstable_by_key(|(outer, ..)| *outer);
        for (outer, client, claim, inner_id) in requests {
            // Pending remains in the original store; no completion registry
            // or consumed acknowledgement is introduced for notification.
            let Some(pending) = self.pending.remove(&outer) else {
                continue;
            };
            self.cdp_unconfirmed(
                UnconfirmedCdp {
                    client,
                    route,
                    claim: &claim,
                    id: inner_id,
                    dispatch: &pending.dispatch,
                    wire_context: pending.wire_context.as_ref(),
                },
                // The initiating extension cause remains in its original charged
                // receipt. Do not clone an arbitrary cause for each neighbor.
                reason.map(|_| BrokerCdpEvent::TransportFailure(UNKNOWN_CDP_REASON.to_owned())),
            );
            self.pending.insert(outer, pending);
        }
    }

    fn retire_route(&mut self, route: RouteId, reason: &str) {
        let Some(record) = self.routes.remove(&route) else {
            return;
        };
        record.alive.store(false, Ordering::SeqCst);
        if !self.stopped {
            self.route_unconfirmed(route, Some(reason));
            self.queue_cdp_control(
                record.client,
                ControlEvent::CdpRouteClosed {
                    route: route.0,
                    claim: record.claim.clone(),
                    reason: "extension CDP route ended; physical claim custody is retained"
                        .to_owned(),
                },
            );
        }
        // Unknown terminals travel once through the same owner control FIFO
        // as their dispatch phase. Dropping a route grants no physical cleanup.
        if let Some(claim) = self.claims.get_mut(&record.claim) {
            if claim.route == Some(route) {
                claim.route = None;
            }
        }
    }

    fn close_route(&mut self, route: RouteId, reason: &str, output: &mut Vec<ExtensionOutbound>) {
        self.retire_route(route, reason);
        // Closing a CdpConnection after cancellation/lost ACK is not Stop or
        // authority to detach. Physical cleanup uses explicit Detach/closeOwner.
        let _ = output;
    }

    fn close_client(&mut self, client: ClientId, output: &mut Vec<ExtensionOutbound>) {
        let Some(state) = self.clients.get_mut(&client) else {
            return;
        };
        if !matches!(state.extension_cleanup, OwnerCleanup::Unrequested) {
            return;
        }
        state.closing = true;
        state.alive.store(false, Ordering::SeqCst);
        state.early.clear();
        self.interrupt_uploads(Some(client), "upload I/O completed after its owner ended");
        for claim in self.claims.values().filter(|claim| claim.client == client) {
            claim.alive.store(false, Ordering::SeqCst);
        }
        let routes = self
            .routes
            .iter()
            .filter(|(_, route)| route.client == client)
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for route in routes {
            self.retire_route(
                route,
                "owner connection ended; prior dispatched work is unknown",
            );
        }
        let ids = self
            .pending
            .iter()
            .filter(|(_, pending)| {
                pending.client == client
                    && matches!(pending.kind, PendingKind::Control { .. })
                    && !(self.uploads.is_some()
                        && matches!(
                            pending.kind,
                            PendingKind::Control {
                                operation: ControlKind::Close(_),
                                ..
                            }
                        ))
            })
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for outer in ids {
            if let Some(Pending {
                kind: PendingKind::Control { local_id, .. },
                ..
            }) = self.pending.remove(&outer)
            {
                self.emit_control(
                    client,
                    ControlEvent::Reply {
                        id: local_id,
                        outcome: ControlOutcome::Unknown {
                            reason: "owner ended before reply settlement".to_owned(),
                            details: None,
                        },
                    },
                    output,
                );
            }
        }
        let previous_outer = self.next_outer;
        self.enqueue(
            client,
            "closeOwner",
            json!({}),
            PendingKind::CloseOwner,
            None,
            output,
        );
        // Set Requested only after the actual existing Pending/outbound was
        // created. A failed/unknown later attempt remains Requested, not retry.
        if self.next_outer > previous_outer
            && self.pending.get(&self.next_outer).is_some_and(|pending| {
                pending.client == client && matches!(pending.kind, PendingKind::CloseOwner)
            })
        {
            if let Some(state) = self.clients.get_mut(&client) {
                state.extension_cleanup = OwnerCleanup::Requested {
                    outer_id: self.next_outer,
                };
            }
        }
    }

    fn emit_control(
        &mut self,
        client: ClientId,
        event: ControlEvent,
        output: &mut Vec<ExtensionOutbound>,
    ) {
        self.queue_control_delivery(client, Queued::new(event, self.current_charge.clone()));
        let _ = output;
    }

    fn emit_cdp(
        &mut self,
        route: RouteId,
        event: BrokerCdpEvent,
        output: &mut Vec<ExtensionOutbound>,
    ) {
        self.emit_cdp_with_context(route, event, self.input_context.clone());
        let _ = output;
    }

    fn emit_cdp_with_context(
        &mut self,
        route: RouteId,
        event: BrokerCdpEvent,
        wire_context: Option<ExtensionWireContext>,
    ) {
        let Some(state) = self.routes.get(&route) else {
            return;
        };
        match state.delivery {
            RouteDelivery::Ordered { .. } => {
                self.queue_cdp_control(
                    state.client,
                    ControlEvent::CdpMessage {
                        route: route.0,
                        claim: state.claim.clone(),
                        event,
                        wire_context,
                    },
                );
            }
            #[cfg(test)]
            RouteDelivery::Direct => self.queue_cdp_delivery(
                route,
                state.client,
                state.claim.clone(),
                state.events.clone(),
                Queued::new(event, self.current_charge.clone()),
            ),
        }
    }

    fn queue_control_delivery(&mut self, client: ClientId, event: Queued<ControlEvent>) {
        let Some(state) = self.clients.get_mut(&client) else {
            return;
        };
        if state.delivery_blocked {
            state.undelivered.push_back(event);
            return;
        }
        if self
            .deliveries
            .iter()
            .any(|item| matches!(item,Delivery::Control{client:id,..} if *id==client))
        {
            self.deliveries.push_back(Delivery::Control {
                client,
                sender: state.events.clone(),
                event,
            });
            return;
        }
        match state.events.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(event)) => {
                self.deliveries.push_back(Delivery::Control {
                    client,
                    sender: state.events.clone(),
                    event,
                })
            }
            Err(mpsc::error::TrySendError::Closed(event)) => {
                state.delivery_blocked = true;
                state.undelivered.push_back(event);
            }
        }
    }

    #[cfg(test)]
    fn queue_cdp_delivery(
        &mut self,
        route: RouteId,
        client: ClientId,
        claim: String,
        sender: mpsc::Sender<Queued<BrokerCdpEvent>>,
        event: Queued<BrokerCdpEvent>,
    ) {
        if self
            .deliveries
            .iter()
            .any(|item| matches!(item,Delivery::Cdp{route:id,..} if *id==route))
        {
            self.deliveries.push_back(Delivery::Cdp {
                route,
                client,
                claim,
                sender,
                event,
            });
            return;
        }
        match sender.try_send(event) {
            Ok(()) => {}
            Err(error) => self.deliveries.push_back(Delivery::Cdp {
                route,
                client,
                claim,
                sender,
                event: error.into_inner(),
            }),
        }
    }

    fn flush_deliveries(&mut self) {
        // Never await a slow reader in the broker actor: EOF/Stop and other
        // clients still need admission. A drained receiver notifies progress.
        let count = self.deliveries.len();
        let mut blocked_clients = HashSet::new();
        #[cfg(test)]
        let mut blocked_routes = HashSet::new();
        for _ in 0..count {
            let Some(delivery) = self.deliveries.pop_front() else {
                break;
            };
            match delivery {
                Delivery::Control {
                    client,
                    sender,
                    event,
                } => {
                    if blocked_clients.contains(&client) {
                        self.deliveries.push_back(Delivery::Control {
                            client,
                            sender,
                            event,
                        });
                        continue;
                    }
                    match sender.clone().try_reserve_owned() {
                        Ok(permit) => {
                            permit.send(event);
                        }
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            blocked_clients.insert(client);
                            self.deliveries.push_back(Delivery::Control {
                                client,
                                sender,
                                event,
                            });
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            if let Some(state) = self.clients.get_mut(&client) {
                                state.delivery_blocked = true;
                                state.undelivered.push_back(event);
                            }
                        }
                    }
                }
                #[cfg(test)]
                Delivery::Cdp {
                    route,
                    client,
                    claim,
                    sender,
                    event,
                } => {
                    if blocked_routes.contains(&route) {
                        self.deliveries.push_back(Delivery::Cdp {
                            route,
                            client,
                            claim,
                            sender,
                            event,
                        });
                        continue;
                    }
                    match sender.clone().try_reserve_owned() {
                        Ok(permit) => {
                            permit.send(event);
                        }
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            blocked_routes.insert(route);
                            self.deliveries.push_back(Delivery::Cdp {
                                route,
                                client,
                                claim,
                                sender,
                                event,
                            });
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            let (event, charge) = event.into_parts();
                            let id = match &event {
                                BrokerCdpEvent::ChromeMessage(value) => value["id"].as_u64(),
                                BrokerCdpEvent::ChromeJson(text) => {
                                    super::cdp_ws::chrome_json_reply_id(text)
                                }
                                BrokerCdpEvent::LocalRejected { id, .. } => Some(*id),
                                BrokerCdpEvent::TransportFailure(_) => None,
                            };
                            let control = if let Some(id) = id {
                                ControlEvent::OrphanCdpCompletion {
                                    route: route.0,
                                    claim: claim.clone(),
                                    id,
                                    event,
                                    wire_context: None,
                                }
                            } else {
                                ControlEvent::ClaimUnavailable{claim:claim.clone(),reason:"CDP reader ended; physical custody remains until explicit cleanup".to_owned()}
                            };
                            self.queue_control_delivery(client, Queued::new(control, charge));
                            if let Some(record) = self.routes.remove(&route) {
                                record.alive.store(false, Ordering::SeqCst);
                                if let Some(claim) = self.claims.get_mut(&record.claim) {
                                    claim.route = None;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(test)]
    fn extension(
        &mut self,
        value: Value,
        output: &mut Vec<ExtensionOutbound>,
    ) -> Result<(), BrokerError> {
        self.extension_with_provenance(value, ExtensionReplyProvenance::DirectExtension, output)
    }

    fn extension_with_provenance(
        &mut self,
        value: Value,
        provenance: ExtensionReplyProvenance,
        output: &mut Vec<ExtensionOutbound>,
    ) -> Result<(), BrokerError> {
        if !self.bound {
            if value["kind"] != "hello"
                || value["protocol"] != 1
                || value["instanceId"]
                    .as_str()
                    .is_none_or(|id| id.is_empty() || id.len() > 128)
            {
                return Err(BrokerError::Protocol("invalid extension hello".to_owned()));
            }
            self.expected_extension
                .validate_hello_id(value["extensionId"].as_str().unwrap_or(""))
                .map_err(|_| {
                    BrokerError::Protocol(
                        "registered extension-origin claim disagrees with hello".to_owned(),
                    )
                })?;
            if !value["capabilities"].is_object() {
                return Err(BrokerError::Protocol(
                    "extension hello lacks actual capability flags".to_owned(),
                ));
            }
            let mut capabilities = value["capabilities"].clone();
            capabilities["uploadStaging"] = json!(self.uploads.is_some());
            self.identity = Some(ExtensionIdentity {
                extension_id: value["extensionId"]
                    .as_str()
                    .expect("hello id was checked")
                    .to_owned(),
                instance_id: value["instanceId"]
                    .as_str()
                    .expect("hello instance was checked")
                    .to_owned(),
                generation: self.generation.clone(),
                capabilities,
            });
            self.bound = true;
            output.push(ExtensionOutbound {
                value: json!({"kind":"bound","protocol":1,"generation":self.generation}),
                generation: self.generation.clone(),
                owner: None,
                outer: None,
                fences: vec![self.generation_alive.clone()],
                dispatch: Arc::new(AtomicU8::new(QUEUED)),
                _charge: self.current_charge.clone(),
                wire_context: None,
            });
            return Ok(());
        }
        if value["protocol"] != 1 || value["generation"].as_str() != Some(self.generation.as_str())
        {
            return Err(BrokerError::Protocol(
                "extension generation or protocol changed".to_owned(),
            ));
        }
        match value["kind"].as_str() {
            Some("response") => self.response(value, provenance, output),
            Some("download_changed") => self.download_changed(value, output),
            Some(
                "event"
                | "revoked"
                | "effects_cleanup"
                | "tab_state_changed"
                | "tab_state_unknown"
                | "popup_requested"
                | "session_popup_requested"
                | "session_preparation_cleanup",
            ) => self.event(value, output),
            _ => Err(BrokerError::Protocol(
                "unexpected extension message kind".to_owned(),
            )),
        }
    }

    fn download_changed(
        &mut self,
        value: Value,
        output: &mut Vec<ExtensionOutbound>,
    ) -> Result<(), BrokerError> {
        let download: ExtensionDownloadInfo = serde_json::from_value(value["download"].clone())
            .map_err(|error| {
                BrokerError::Protocol(format!("download metadata is invalid: {error}"))
            })?;
        if download.id.is_empty()
            || !download.id.bytes().all(|byte| byte.is_ascii_digit())
            || download.id.parse::<u64>().is_err()
        {
            return Err(BrokerError::Protocol(
                "download metadata lacks actual numeric Chrome ID".to_owned(),
            ));
        }
        let shared = SharedDownload(Arc::new(download));
        let clients = self
            .clients
            .iter()
            .filter(|(_, state)| {
                !state.closing && !state.delivery_blocked && state.alive.load(Ordering::SeqCst)
            })
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for client in clients {
            self.emit_control(
                client,
                ControlEvent::DownloadChanged {
                    download: shared.clone(),
                },
                output,
            );
        }
        Ok(())
    }

    fn response(
        &mut self,
        value: Value,
        provenance: ExtensionReplyProvenance,
        output: &mut Vec<ExtensionOutbound>,
    ) -> Result<(), BrokerError> {
        let outer = canonical_id(value["id"].as_str())
            .ok_or_else(|| BrokerError::Protocol("invalid outer response ID".to_owned()))?;
        if self
            .pending
            .get(&outer)
            .is_some_and(|pending| matches!(pending.kind, PendingKind::Upload(_)))
        {
            return Err(BrokerError::Protocol(
                "extension reply cannot settle host-local upload work".to_owned(),
            ));
        }
        if let ExtensionReplyProvenance::Matched(proof) = &provenance {
            if let Some(pending) = self.pending.get(&outer) {
                let owner = self
                    .clients
                    .get(&pending.client)
                    .map(|client| client.owner.as_str());
                if !owner.is_some_and(|owner| {
                    proof.matches(
                        &self.generation,
                        owner,
                        &outer.to_string(),
                        pending.wire_context.as_ref(),
                    )
                }) {
                    return Err(BrokerError::Protocol(
                        "matched extension reply changed its pending association".to_owned(),
                    ));
                }
            }
        }
        if !matches!(provenance, ExtensionReplyProvenance::DirectExtension)
            && self.pending.get(&outer).is_some_and(|pending| {
                matches!(
                    &pending.kind,
                    PendingKind::Cdp {
                        unknown: Some(_),
                        ..
                    }
                )
            })
        {
            return Ok(());
        }
        let Some(pending) = self.pending.remove(&outer) else {
            return if outer <= self.next_outer {
                Ok(())
            } else {
                Err(BrokerError::Protocol(
                    "response names an unissued ID".to_owned(),
                ))
            };
        };
        if !matches!(pending.dispatch.load(Ordering::SeqCst), STARTED | WRITTEN) {
            return Err(BrokerError::Protocol(
                "reply arrived for a command never released to the extension writer".to_owned(),
            ));
        }
        if value.get("result").is_some() == value.get("error").is_some() {
            return Err(BrokerError::Protocol(
                "extension response must contain one outcome".to_owned(),
            ));
        }
        match pending.kind {
            PendingKind::Upload(_) => {
                unreachable!("local upload completions use typed worker input")
            }
            PendingKind::Cdp {
                route,
                claim,
                inner_id,
                unknown: previous_unknown,
            } => {
                let event = if let Some(error) = value.get("error") {
                    let (kind, message) = error_fields(error)?;
                    if kind == "chrome_rejected" {
                        BrokerCdpEvent::ChromeMessage(
                            json!({"id":inner_id,"error":{"message":message}}),
                        )
                    } else if matches!(
                        kind,
                        "invalid_request"
                            | "unsupported"
                            | "claim_required"
                            | "claim_unavailable"
                            | "child_session_unavailable"
                            | "request_budget"
                    ) || error["provenance"] == "local_refusal"
                    {
                        BrokerCdpEvent::LocalRejected {
                            id: inner_id,
                            code: kind.to_owned(),
                            message: message.to_owned(),
                        }
                    } else {
                        BrokerCdpEvent::TransportFailure(format!(
                            "extension claim request ended: {kind}: {message}"
                        ))
                    }
                } else {
                    match (
                        value["result"].get("result"),
                        value["result"].get("resultJson"),
                    ) {
                        (Some(result), None) => {
                            BrokerCdpEvent::ChromeMessage(json!({"id":inner_id,"result":result}))
                        }
                        (None, Some(Value::String(text))) => {
                            BrokerCdpEvent::ChromeJson(chrome_result_json(inner_id, text)?)
                        }
                        _ => {
                            return Err(BrokerError::Protocol(
                                "CDP success lacks one exact Chrome result representation"
                                    .to_owned(),
                            ))
                        }
                    }
                };
                // A response parsed from the selected Maka extension port proves
                // its exact issued frame reached that peer, even if the serial
                // writer has not resumed after flush. Generation, issued ID,
                // released dispatch and complete outcome were checked above.
                // Chatgpt Matched can represent an earlier activation phase
                // and therefore never supplies this direct-frame write proof.
                if matches!(provenance, ExtensionReplyProvenance::DirectExtension) {
                    let _ = pending.dispatch.compare_exchange(
                        STARTED,
                        WRITTEN,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    );
                }
                let raw_terminal = matches!(
                    provenance,
                    ExtensionReplyProvenance::DirectExtension
                        | ExtensionReplyProvenance::Matched(_)
                );
                let unknown = match &event {
                    BrokerCdpEvent::TransportFailure(_) if !raw_terminal => {
                        Some(UNKNOWN_CDP_REASON)
                    }
                    _ => None,
                };
                if let BrokerCdpEvent::TransportFailure(reason) = event {
                    let active_route =
                        previous_unknown.is_none() && self.routes.contains_key(&route);
                    self.cdp_unconfirmed(
                        UnconfirmedCdp {
                            client: pending.client,
                            route,
                            claim: &claim,
                            id: inner_id,
                            dispatch: &pending.dispatch,
                            wire_context: pending.wire_context.as_ref(),
                        },
                        active_route.then(|| BrokerCdpEvent::TransportFailure(reason.clone())),
                    );
                    if active_route {
                        self.retire_route(route, &reason);
                    } else {
                        // A late actual raw receipt remains distinguishable
                        // from the earlier synthetic route-close terminal.
                        self.emit_control(
                            pending.client,
                            ControlEvent::OrphanCdpCompletion {
                                route: route.0,
                                claim: claim.clone(),
                                id: inner_id,
                                event: BrokerCdpEvent::TransportFailure(reason),
                                wire_context: pending.wire_context.clone(),
                            },
                            output,
                        );
                    }
                } else if previous_unknown.is_none() && self.routes.contains_key(&route) {
                    self.emit_cdp_with_context(route, event, pending.wire_context.clone());
                } else {
                    self.emit_control(
                        pending.client,
                        ControlEvent::OrphanCdpCompletion {
                            route: route.0,
                            claim: claim.clone(),
                            id: inner_id,
                            event,
                            wire_context: pending.wire_context.clone(),
                        },
                        output,
                    );
                }
                if let Some(reason) = unknown {
                    self.pending.insert(
                        outer,
                        Pending {
                            client: pending.client,
                            kind: PendingKind::Cdp {
                                route,
                                claim: claim.clone(),
                                inner_id,
                                unknown: Some(reason),
                            },
                            dispatch: pending.dispatch,
                            wire_context: pending.wire_context,
                            scope_fence: pending.scope_fence,
                        },
                    );
                }
                self.claim_cdp_progress(pending.client, &claim, output);
            }
            PendingKind::Control {
                local_id,
                operation,
            } => {
                if let ControlKind::Attach(tab_id) = &operation {
                    if let Some(client) = self.clients.get_mut(&pending.client) {
                        client.attaching.remove(tab_id);
                    }
                }
                let outcome = if let Some(error) = value.get("error") {
                    let (kind, message) = error_fields(error)?;
                    if let Some(result) = error.get("details").and_then(|details| {
                        details
                            .get("acknowledgedResult")
                            .or_else(|| details.get("physicalProof"))
                    }) {
                        self.record_known_cleanup(pending.client, local_id, &operation, result);
                    }
                    if let ControlKind::Attach(tab_id) = &operation {
                        if let Some(custody) = error
                            .get("details")
                            .and_then(|details| {
                                details
                                    .get("custody")
                                    .or_else(|| details.get("acknowledgedResult"))
                            })
                            .filter(|result| result.get("claim").is_some())
                        {
                            self.record_claim(pending.client, *tab_id, custody, true, output)?;
                        }
                    }
                    if kind == "chrome_rejected" {
                        ControlOutcome::ChromeRejected {
                            message: message.to_owned(),
                            details: error.get("details").cloned(),
                        }
                    } else if matches!(
                        kind,
                        "outcome_unknown"
                            | "generation_lost"
                            | "owner_closed"
                            | "connector_failure"
                    ) {
                        ControlOutcome::Unknown {
                            reason: format!("{kind}: {message}"),
                            details: error.get("details").cloned(),
                        }
                    } else {
                        ControlOutcome::ConnectorRejected {
                            kind: kind.to_owned(),
                            message: message.to_owned(),
                            details: error.get("details").cloned(),
                        }
                    }
                } else {
                    let result = value["result"].clone();
                    let revoked = if let ControlKind::Attach(tab_id) = &operation {
                        self.record_claim(pending.client, *tab_id, &result, false, output)?
                    } else {
                        None
                    };
                    if matches!(operation, ControlKind::Detach(_)) && result["detached"] != true {
                        return Err(BrokerError::Protocol(
                            "detach success lacks acknowledgement".to_owned(),
                        ));
                    }
                    self.record_known_cleanup(pending.client, local_id, &operation, &result);
                    if let Some(reason) = revoked {
                        ControlOutcome::Unknown {
                            reason: format!(
                                "physical claim was revoked before its reply: {reason}; do not replay"
                            ),
                            details: Some(json!({"acknowledgedResult":result,"revoked":true})),
                        }
                    } else {
                        ControlOutcome::Result(result)
                    }
                };
                let cleanup_owner = match (&operation, pending.wire_context.as_ref()) {
                    (ControlKind::Close(issued), Some(context))
                        if self.uploads.is_some() && known_upload_close(&outcome, issued) =>
                    {
                        Some((
                            UploadOwner {
                                session_id: context.host_session_id().to_owned(),
                                tab_id: issued.tab_id,
                                target_id: issued.target_id.clone(),
                            },
                            issued.claim.clone(),
                        ))
                    }
                    _ => None,
                };
                if let Some((owner, claim)) = cleanup_owner {
                    self.queue_upload(UploadAdmission {
                        client: pending.client,
                        local_id,
                        operation: UploadControl::RetireTab {
                            owner: owner.clone(),
                            outcome: Box::new(outcome),
                        },
                        work: UploadWork::RetireTab { owner },
                        claim: Some(claim),
                        gates: vec![self.generation_alive.clone()],
                        context: pending.wire_context.clone(),
                    });
                } else {
                    self.emit_control(
                        pending.client,
                        ControlEvent::Reply {
                            id: local_id,
                            outcome,
                        },
                        output,
                    );
                }
                if let Some(client) = self.clients.get_mut(&pending.client) {
                    if client.attaching.is_empty() {
                        client.early.clear();
                    }
                }
            }
            PendingKind::CloseOwner => {
                if value["result"]["cleanupConfirmed"] == true
                    && self.clients.get(&pending.client).is_some_and(|client| {
                        matches!(client.extension_cleanup, OwnerCleanup::Requested {outer_id} if outer_id==outer)
                    })
                {
                    if let Some(client) = self.clients.get_mut(&pending.client) {
                        client.extension_cleanup = OwnerCleanup::Confirmed;
                    }
                    self.claims.retain(|_, claim| claim.client != pending.client);
                    self.finish_upload_generation();
                }
                // A rejection or cleanupConfirmed=false retains the closed-owner
                // tombstone. No retry or fabricated successful cleanup occurs.
            }
        }
        self.finish_upload_generation();
        Ok(())
    }

    fn record_known_cleanup(
        &mut self,
        client: ClientId,
        local_id: u64,
        operation: &ControlKind,
        result: &Value,
    ) {
        let exact_claim = match operation {
            ControlKind::Detach(claim)
                if result["detached"] == true
                    && matches!(
                        result["proof"].as_str(),
                        Some("detach_ack" | "detach_event" | "tab_removed")
                    ) =>
            {
                Some(claim)
            }
            ControlKind::Close(issued)
                if result["closed"] == true
                    && matches!(result["proof"].as_str(), Some("close_ack" | "tab_removed")) =>
            {
                Some(&issued.claim)
            }
            _ => None,
        };
        if let Some(claim) = exact_claim {
            if let Some(record) = self.claims.get_mut(claim).filter(|record| {
                record.client == client
                    && result
                        .get("claim")
                        .is_none_or(|value| value.as_str() == Some(claim.as_str()))
                    && result
                        .get("tabId")
                        .is_none_or(|value| value.as_u64() == Some(record.tab_id))
                    && result
                        .get("targetId")
                        .is_none_or(|value| value.as_str() == Some(record.target_id.as_str()))
            }) {
                record.alive.store(false, Ordering::SeqCst);
                record.cleanup_id = Some(local_id);
            }
        }
        if let ControlKind::StopCreated(Some(tab_id)) = operation {
            let known_closed = result["closed"] == true
                && (result["proof"] == "close_ack"
                    || result["proof"] == "tab_removed"
                    || (result["proof"] == "tab_absent"
                        && result["tabId"].as_u64() == Some(*tab_id)
                        && result["observationRequestId"]
                            .as_str()
                            .is_some_and(|id| !id.is_empty())));
            if known_closed
                && result
                    .get("tabId")
                    .is_none_or(|value| value.as_u64() == Some(*tab_id))
            {
                for (_, record) in self.claims.iter_mut().filter(|(claim, record)| {
                    record.client == client
                        && record.tab_id == *tab_id
                        && result
                            .get("claim")
                            .is_none_or(|value| value.as_str() == Some(claim.as_str()))
                        && result
                            .get("targetId")
                            .is_none_or(|value| value.as_str() == Some(record.target_id.as_str()))
                }) {
                    record.alive.store(false, Ordering::SeqCst);
                    record.cleanup_id = Some(local_id);
                }
            }
        }
    }

    fn record_claim(
        &mut self,
        client: ClientId,
        tab_id: u64,
        result: &Value,
        cleanup_only: bool,
        output: &mut Vec<ExtensionOutbound>,
    ) -> Result<Option<String>, BrokerError> {
        let token = result["claim"]
            .as_str()
            .filter(|token| !token.is_empty() && token.len() <= 128)
            .ok_or_else(|| {
                BrokerError::Protocol("attach success lacks a bounded claim".to_owned())
            })?;
        let target_id = result["targetId"]
            .as_str()
            .filter(|target| !target.is_empty() && target.len() <= 256)
            .ok_or_else(|| {
                BrokerError::Protocol("attach success lacks an opaque target ID".to_owned())
            })?;
        if result["tabId"].as_u64() != Some(tab_id) {
            return Err(BrokerError::Protocol(
                "attach success changed raw tab ID".to_owned(),
            ));
        }
        if let Some(existing) = self.claims.get_mut(token) {
            return if existing.client == client
                && existing.tab_id == tab_id
                && existing.target_id == target_id
            {
                if cleanup_only {
                    existing.cleanup_only = true;
                    existing.alive.store(false, Ordering::SeqCst);
                    Ok(None)
                } else if existing.cleanup_only || !existing.alive.load(Ordering::SeqCst) {
                    Err(BrokerError::Protocol(
                        "attach reply cannot revive a cleanup-only claim".to_owned(),
                    ))
                } else {
                    Ok(None)
                }
            } else {
                Err(BrokerError::Protocol(
                    "physical claim token was reused across identities".to_owned(),
                ))
            };
        }
        let early = self
            .clients
            .get_mut(&client)
            .and_then(|state| state.early.remove(token))
            .unwrap_or_default();
        if let Some(reason) = early.revoked.as_ref() {
            let reason = reason.clone();
            self.emit_control(
                client,
                ControlEvent::ClaimUnavailable {
                    claim: token.to_owned(),
                    reason: reason.clone(),
                },
                output,
            );
            return Ok(Some(reason));
        }
        self.claims.insert(
            token.to_owned(),
            ClaimState {
                client,
                tab_id,
                target_id: target_id.to_owned(),
                alive: Arc::new(AtomicBool::new(!cleanup_only)),
                route: None,
                early,
                cleanup_only,
                cdp_fenced: false,
                cleanup_id: None,
            },
        );
        Ok(None)
    }

    fn event(
        &mut self,
        value: Value,
        output: &mut Vec<ExtensionOutbound>,
    ) -> Result<(), BrokerError> {
        let owner = value["owner"]
            .as_str()
            .ok_or_else(|| BrokerError::Protocol("event lacks owner".to_owned()))?;
        let Some(client) = self.owners.get(owner).copied() else {
            return Ok(());
        };
        if self.clients.get(&client).is_none_or(|state| state.closing) {
            return Ok(());
        }
        if matches!(
            value["kind"].as_str(),
            Some("session_popup_requested" | "session_preparation_cleanup")
        ) {
            let scope_id = value["scopeId"]
                .as_str()
                .filter(|scope| canonical_scope(scope))
                .ok_or_else(|| {
                    BrokerError::Protocol("logical event lacks canonical scope identity".into())
                })?
                .to_owned();
            let tab_id = value["tabId"]
                .as_u64()
                .filter(|id| *id > 0 && *id <= 9_007_199_254_740_991)
                .ok_or_else(|| {
                    BrokerError::Protocol("logical event lacks a positive safe tab ID".into())
                })?;
            let wire_context: ExtensionWireContext =
                serde_json::from_value(value["wireContext"].clone()).map_err(|error| {
                    BrokerError::Protocol(format!("logical event lacks captured context: {error}"))
                })?;
            let event = if value["kind"] == "session_preparation_cleanup" {
                ControlEvent::SessionPreparationCleanup {
                    generation: self.generation.clone(),
                    owner: owner.to_owned(),
                    scope_id,
                    tab_id,
                    wire_context,
                    cleanup_confirmed: value["cleanupConfirmed"].as_bool().ok_or_else(|| {
                        BrokerError::Protocol(
                            "logical cleanup observation lacks actual outcome".into(),
                        )
                    })?,
                }
            } else {
                let optional_text = |key: &str| -> Result<Option<String>, BrokerError> {
                    value
                        .get(key)
                        .map(|field| {
                            field.as_str().map(str::to_owned).ok_or_else(|| {
                                BrokerError::Protocol(format!("logical popup {key} is not text"))
                            })
                        })
                        .transpose()
                };
                let frame_id = value
                    .get("frameId")
                    .map(|field| {
                        field
                            .as_i64()
                            .filter(|id| {
                                (-9_007_199_254_740_991..=9_007_199_254_740_991).contains(id)
                            })
                            .ok_or_else(|| {
                                BrokerError::Protocol(
                                    "logical popup frame is not a safe integer".into(),
                                )
                            })
                    })
                    .transpose()?;
                ControlEvent::SessionPopupRequested {
                    generation: self.generation.clone(),
                    owner: owner.to_owned(),
                    scope_id,
                    tab_id,
                    wire_context,
                    url: value["url"]
                        .as_str()
                        .ok_or_else(|| {
                            BrokerError::Protocol("logical popup lacks actual URL".into())
                        })?
                        .to_owned(),
                    frame_id,
                    document_id: optional_text("documentId")?,
                    source_url: optional_text("sourceUrl")?,
                }
            };
            self.emit_control(client, event, output);
            return Ok(());
        }
        let token = value["claim"]
            .as_str()
            .filter(|token| !token.is_empty() && token.len() <= 128)
            .ok_or_else(|| BrokerError::Protocol("event lacks bounded claim".to_owned()))?
            .to_owned();
        if value["kind"] == "popup_requested" {
            let Some(record) = self.claims.get(&token).filter(|record| {
                record.client == client
                    && record.alive.load(Ordering::SeqCst)
                    && !record.cleanup_only
            }) else {
                return Ok(());
            };
            if value["tabId"].as_u64() != Some(record.tab_id) {
                return Err(BrokerError::Protocol(
                    "popup metadata changed its exact claimed tab".to_owned(),
                ));
            }
            let wire_context: ExtensionWireContext =
                serde_json::from_value(value["wireContext"].clone()).map_err(|error| {
                    BrokerError::Protocol(format!(
                        "popup metadata lacks captured wire context: {error}"
                    ))
                })?;
            let url = value["url"]
                .as_str()
                .ok_or_else(|| BrokerError::Protocol("popup metadata lacks actual URL".to_owned()))?
                .to_owned();
            let frame_id = value
                .get("frameId")
                .map(|id| {
                    id.as_i64()
                        .filter(|id| (-9_007_199_254_740_991..=9_007_199_254_740_991).contains(id))
                        .ok_or_else(|| {
                            BrokerError::Protocol(
                                "popup sender frame ID is not a Chrome safe integer".to_owned(),
                            )
                        })
                })
                .transpose()?;
            let optional_text = |key: &str| -> Result<Option<String>, BrokerError> {
                value
                    .get(key)
                    .map(|field| {
                        field.as_str().map(str::to_owned).ok_or_else(|| {
                            BrokerError::Protocol(format!("popup sender {key} is not text"))
                        })
                    })
                    .transpose()
            };
            let tab_id = record.tab_id;
            self.emit_control(
                client,
                ControlEvent::PopupRequested {
                    claim: token,
                    tab_id,
                    url,
                    wire_context,
                    frame_id,
                    document_id: optional_text("documentId")?,
                    source_url: optional_text("sourceUrl")?,
                },
                output,
            );
            return Ok(());
        }
        if value["kind"] == "effects_cleanup" {
            if self
                .claims
                .get(&token)
                .is_some_and(|claim| claim.client != client)
            {
                return Err(BrokerError::Protocol(
                    "effect cleanup owner disagrees with live claim".to_owned(),
                ));
            }
            let effect = value["effect"].as_str().ok_or_else(|| {
                BrokerError::Protocol("effect cleanup lacks effect identity".to_owned())
            })?;
            let confirmed = value["cleanupConfirmed"].as_bool().ok_or_else(|| {
                BrokerError::Protocol("effect cleanup lacks an actual result".to_owned())
            })?;
            let error = value
                .get("error")
                .filter(|value| !value.is_null())
                .map(|error| -> Result<String, BrokerError> {
                    if let Some(message) = error.as_str() {
                        return Ok(message.to_owned());
                    }
                    // Maka reports structured cleanup diagnostics. Preserve their
                    // complete fields through the existing text-only IPC DTO.
                    // This does not turn a failed effect into physical cleanup.
                    error_fields(error)?;
                    Ok(error.to_string())
                })
                .transpose()?;
            self.emit_control(
                client,
                ControlEvent::EffectsCleanup {
                    claim: token,
                    effect: effect.to_owned(),
                    cleanup_confirmed: confirmed,
                    error,
                    wire_context: value
                        .get("wireContext")
                        .cloned()
                        .map(serde_json::from_value)
                        .transpose()
                        .map_err(|error| {
                            BrokerError::Protocol(format!(
                                "effect cleanup wire context is invalid: {error}"
                            ))
                        })?,
                },
                output,
            );
            return Ok(());
        }
        if matches!(
            value["kind"].as_str(),
            Some("tab_state_changed" | "tab_state_unknown")
        ) {
            let Some(record) = self
                .claims
                .get(&token)
                .filter(|claim| claim.client == client)
            else {
                return Ok(());
            };
            if value["tabId"].as_u64() != Some(record.tab_id) {
                return Err(BrokerError::Protocol(
                    "tab-state metadata changed claimed tab identity".to_owned(),
                ));
            }
            let event = if value["kind"] == "tab_state_changed" {
                let active = value["active"].as_bool().ok_or_else(|| {
                    BrokerError::Protocol("tab-state metadata lacks actual active flag".to_owned())
                })?;
                let window_id = value
                    .get("windowId")
                    .map(|id| {
                        id.as_i64().ok_or_else(|| {
                            BrokerError::Protocol("tab-state window ID is invalid".to_owned())
                        })
                    })
                    .transpose()?;
                ControlEvent::TabStateChanged {
                    claim: token,
                    tab_id: record.tab_id,
                    window_id,
                    active,
                }
            } else {
                error_fields(&value["error"])?;
                ControlEvent::TabStateUnknown {
                    claim: token,
                    tab_id: record.tab_id,
                    error: value["error"].clone(),
                }
            };
            self.emit_control(client, event, output);
            return Ok(());
        }
        let revoked = value["kind"] == "revoked";
        let event = if revoked {
            None
        } else {
            let method = value["method"]
                .as_str()
                .filter(|method| !method.is_empty())
                .ok_or_else(|| BrokerError::Protocol("event lacks CDP method".to_owned()))?;
            if value.get("params").is_some() && value.get("paramsJson").is_some() {
                return Err(BrokerError::Protocol(
                    "CDP event contains two params representations".to_owned(),
                ));
            }
            let mut event = json!({"method":method,"params":value.get("params").cloned().unwrap_or_else(||json!({}))});
            if let Some(session) = value.get("sessionId") {
                if !session.is_string() {
                    return Err(BrokerError::Protocol(
                        "event child session is invalid".to_owned(),
                    ));
                }
                event["sessionId"] = session.clone();
            }
            if let Some(target) = value.get("sourceTargetId") {
                if !target.is_string() {
                    return Err(BrokerError::Protocol(
                        "event source target is invalid".to_owned(),
                    ));
                }
                event["sourceTargetId"] = target.clone();
            }
            Some(if let Some(text) = value.get("paramsJson") {
                let text = text.as_str().ok_or_else(|| {
                    BrokerError::Protocol("raw CDP event params are not JSON text".to_owned())
                })?;
                if method != "Target.attachedToTarget" {
                    return Err(BrokerError::Protocol(
                        "event has no closed JSON-text params grammar".to_owned(),
                    ));
                }
                BrokerCdpEvent::ChromeJson(chrome_event_json(
                    method,
                    text,
                    event.get("sessionId").and_then(Value::as_str),
                    event.get("sourceTargetId").and_then(Value::as_str),
                )?)
            } else {
                BrokerCdpEvent::ChromeMessage(event)
            })
        };
        if let Some(record) = self.claims.get(&token) {
            if record.client != client {
                return Err(BrokerError::Protocol(
                    "event owner disagrees with claim custody".to_owned(),
                ));
            }
            if !record.alive.load(Ordering::SeqCst) && !revoked {
                return Ok(());
            }
            if revoked {
                let reason = value["reason"]
                    .as_str()
                    .ok_or_else(|| {
                        BrokerError::Protocol("revocation lacks its Chrome reason".to_owned())
                    })?
                    .to_owned();
                record.alive.store(false, Ordering::SeqCst);
                let preserve_cdp = record.cdp_fenced || self.pending.values().any(|pending| {
                    pending.client == client && matches!(&pending.kind, PendingKind::Cdp { claim, .. } if claim == &token)
                });
                if let Some(route) = record.route {
                    self.retire_route(route, &format!("Chrome revoked physical claim: {reason}"));
                }
                if !preserve_cdp {
                    self.claims.remove(&token);
                }
                self.emit_control(
                    client,
                    ControlEvent::ClaimUnavailable {
                        claim: token,
                        reason,
                    },
                    output,
                );
            } else if let Some(route) = record.route {
                self.emit_cdp(route, event.expect("non-revoked event was built"), output);
            } else if let Some(record) = self.claims.get_mut(&token) {
                if !buffer_event(
                    &mut record.early,
                    event.expect("non-revoked event was built"),
                    self.current_charge.clone(),
                ) {
                    record.alive.store(false, Ordering::SeqCst);
                    self.emit_control(client, ControlEvent::ClaimUnavailable { claim:token, reason:"event buffer exceeded before a CDP route was opened; physical custody retained for explicit cleanup".to_owned() }, output);
                }
            }
        } else if let Some(state) = self.clients.get_mut(&client) {
            if state.attaching.is_empty() {
                return Ok(());
            }
            if state.early.len() >= MAX_NORMAL_PENDING && !state.early.contains_key(&token) {
                self.close_client(client, output);
                return Ok(());
            }
            let early = state.early.entry(token).or_default();
            if revoked {
                early.revoked = Some(
                    value["reason"]
                        .as_str()
                        .ok_or_else(|| {
                            BrokerError::Protocol("early revocation lacks reason".to_owned())
                        })?
                        .to_owned(),
                );
            } else if !buffer_event(
                early,
                event.expect("non-revoked event was built"),
                self.current_charge.clone(),
            ) {
                self.close_client(client, output);
            }
        }
        Ok(())
    }

    fn end_generation(&mut self, reason: &str) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        self.generation_alive.store(false, Ordering::SeqCst);
        // Close the extension writer scope before emitting or draining local
        // receipts. Already queued frames observe this generation fence.
        drop(self.extension_output.take());
        let routes_with_pending = self
            .pending
            .values()
            .filter_map(|pending| match &pending.kind {
                PendingKind::Cdp { route, .. } => Some(*route),
                _ => None,
            })
            .collect::<HashSet<_>>();
        for route in routes_with_pending {
            self.route_unconfirmed(route, None);
        }
        self.interrupt_uploads(
            None,
            "upload I/O completed after its extension generation ended",
        );
        let routes = self.routes.keys().copied().collect::<Vec<_>>();
        for route in routes {
            self.retire_route(
                route,
                &format!("extension generation ended: {reason}; do not replay"),
            );
        }
        for state in self.clients.values() {
            state.alive.store(false, Ordering::SeqCst);
        }
        self.pending
            .retain(|_, pending| matches!(pending.kind, PendingKind::Upload(_)));
        self.closing_uploads = Some(reason.to_owned());
        self.finish_upload_generation();
        for claim in self.claims.values() {
            claim.alive.store(false, Ordering::SeqCst);
        }
    }

    fn write_not_settled(
        &mut self,
        outer: u64,
        pending: Pending,
        partial: bool,
        output: &mut Vec<ExtensionOutbound>,
    ) {
        if matches!(
            &pending.kind,
            PendingKind::Cdp {
                unknown: Some(_),
                ..
            }
        ) {
            self.pending.insert(outer, pending);
            return;
        }
        let reason = if partial {
            "extension logical request was fenced between fragments; no replay"
        } else {
            "extension command was fenced before any write"
        };
        match pending.kind {
            PendingKind::Upload(_) => {
                unreachable!("filesystem jobs never enter the extension writer")
            }
            PendingKind::Cdp {
                route,
                claim,
                inner_id,
                unknown: _,
            } => {
                if partial {
                    let active_route = self.routes.contains_key(&route);
                    self.cdp_unconfirmed(
                        UnconfirmedCdp {
                            client: pending.client,
                            route,
                            claim: &claim,
                            id: inner_id,
                            dispatch: &pending.dispatch,
                            wire_context: pending.wire_context.as_ref(),
                        },
                        active_route.then(|| BrokerCdpEvent::TransportFailure(reason.to_owned())),
                    );
                    if !active_route {
                        self.emit_control(
                            pending.client,
                            ControlEvent::OrphanCdpCompletion {
                                route: route.0,
                                claim: claim.clone(),
                                id: inner_id,
                                event: BrokerCdpEvent::TransportFailure(reason.to_owned()),
                                wire_context: pending.wire_context.clone(),
                            },
                            output,
                        );
                    }
                } else {
                    let event = BrokerCdpEvent::LocalRejected {
                        id: inner_id,
                        code: "not_dispatched".to_owned(),
                        message: reason.to_owned(),
                    };
                    if self.routes.contains_key(&route) {
                        self.emit_cdp_with_context(route, event, pending.wire_context.clone());
                    } else {
                        self.emit_control(
                            pending.client,
                            ControlEvent::OrphanCdpCompletion {
                                route: route.0,
                                claim: claim.clone(),
                                id: inner_id,
                                event,
                                wire_context: pending.wire_context.clone(),
                            },
                            output,
                        );
                    }
                }
                if partial {
                    self.pending.insert(
                        outer,
                        Pending {
                            client: pending.client,
                            kind: PendingKind::Cdp {
                                route,
                                claim: claim.clone(),
                                inner_id,
                                unknown: Some(UNKNOWN_CDP_REASON),
                            },
                            dispatch: pending.dispatch,
                            wire_context: pending.wire_context,
                            scope_fence: pending.scope_fence,
                        },
                    );
                }
                self.claim_cdp_progress(pending.client, &claim, output);
            }
            PendingKind::Control { local_id, .. } => self.emit_control(
                pending.client,
                ControlEvent::Reply {
                    id: local_id,
                    outcome: if partial {
                        ControlOutcome::Unknown {
                            reason: reason.to_owned(),
                            details: None,
                        }
                    } else {
                        ControlOutcome::NotDispatched {
                            kind: "not_dispatched".to_owned(),
                            message: reason.to_owned(),
                            details: None,
                        }
                    },
                },
                output,
            ),
            PendingKind::CloseOwner => {}
        }
    }

    fn local_rejection(
        &mut self,
        pending: Pending,
        code: String,
        message: String,
        output: &mut Vec<ExtensionOutbound>,
    ) {
        match pending.kind {
            PendingKind::Upload(_) => {
                unreachable!("filesystem jobs never enter the extension writer")
            }
            PendingKind::Cdp {
                route,
                claim,
                inner_id,
                unknown: _,
            } => {
                let event = BrokerCdpEvent::LocalRejected {
                    id: inner_id,
                    code,
                    message,
                };
                if self.routes.contains_key(&route) {
                    self.emit_cdp_with_context(route, event, pending.wire_context.clone());
                } else {
                    self.emit_control(
                        pending.client,
                        ControlEvent::OrphanCdpCompletion {
                            route: route.0,
                            claim: claim.clone(),
                            id: inner_id,
                            event,
                            wire_context: pending.wire_context,
                        },
                        output,
                    );
                }
                self.claim_cdp_progress(pending.client, &claim, output);
            }
            PendingKind::Control { local_id, .. } => self.emit_control(
                pending.client,
                ControlEvent::Reply {
                    id: local_id,
                    outcome: ControlOutcome::NotDispatched {
                        kind: code,
                        message,
                        details: None,
                    },
                },
                output,
            ),
            PendingKind::CloseOwner => {}
        }
    }
}

fn prepare_upload_completion(
    mut completion: UploadCompletion,
    budget: &ByteBudget,
) -> (UploadCompletion, Option<Arc<ByteCharge>>) {
    // Never wait for a second permit while the original request's Pending/job
    // still owns the budget. A fixed Unknown preserves host resource custody.
    let charge = upload_completion_payload(&completion)
        .ok()
        .and_then(|payload| budget.try_charge(&payload).ok());
    if charge.is_none() {
        bound_undelivered_upload_completion(&mut completion);
    }
    (completion, charge)
}

fn upload_completion_payload(completion: &UploadCompletion) -> Result<Value, serde_json::Error> {
    let payload = match &completion.result {
        Ok(UploadWorkResult::Retained(paths)) => {
            json!({"kind":"retained","paths":serde_json::to_value(paths)?})
        }
        Ok(UploadWorkResult::RetainedUnexposed) => json!({"kind":"retainedUnexposed"}),
        Ok(UploadWorkResult::Begun(stage)) => json!({"kind":"begun","stage":stage}),
        Ok(UploadWorkResult::Written) => json!({"kind":"written"}),
        Ok(UploadWorkResult::Abandoned) => json!({"kind":"abandoned"}),
        Ok(UploadWorkResult::TabRetired) => json!({"kind":"tabRetired"}),
        Err(error) => json!({"kind":"unknown","error":error.to_string()}),
    };
    Ok(json!({"id":completion.id,"phase":completion.phase,"result":payload}))
}

fn bound_undelivered_upload_completion(completion: &mut UploadCompletion) {
    let error =
        || std::io::Error::other("host upload completion was not admitted to the bounded queue");
    completion.result = match std::mem::replace(
        &mut completion.result,
        Err(UploadWorkerError::StateUnavailable),
    ) {
        // Preserve fixed positive addresses; no variable paths may bypass a
        // closed/saturated byte budget and no later setter is authorized.
        Ok(UploadWorkResult::Begun(stage)) => Ok(UploadWorkResult::Begun(stage)),
        Ok(UploadWorkResult::Retained(_) | UploadWorkResult::RetainedUnexposed)
        | Err(UploadWorkerError::RetainedPlacement { .. }) => {
            Ok(UploadWorkResult::RetainedUnexposed)
        }
        Ok(UploadWorkResult::Written) => Ok(UploadWorkResult::Written),
        Ok(UploadWorkResult::Abandoned) => Ok(UploadWorkResult::Abandoned),
        Ok(UploadWorkResult::TabRetired) => Ok(UploadWorkResult::TabRetired),
        Err(UploadWorkerError::Resource(UploadError::BeginIo { stage, .. })) => {
            Err(UploadWorkerError::Resource(UploadError::BeginIo {
                stage,
                error: error(),
            }))
        }
        _ => Err(UploadWorkerError::Resource(UploadError::Io(error()))),
    };
}

fn decode_upload_chunk(encoded: &str) -> Result<Vec<u8>, &'static str> {
    if encoded.len() > EXTENSION_UPLOAD_CHUNK_BYTES.div_ceil(3) * 4 {
        return Err("encoded upload chunk exceeds 64 KiB");
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "upload chunk is not valid base64")?;
    if bytes.is_empty() || bytes.len() > EXTENSION_UPLOAD_CHUNK_BYTES {
        return Err("upload chunk must contain 1 through 65536 bytes");
    }
    Ok(bytes)
}

fn known_upload_close(outcome: &ControlOutcome, issued: &ClosingClaim) -> bool {
    let result = match outcome {
        ControlOutcome::Result(result) => Some(result),
        ControlOutcome::Unknown {
            details: Some(details),
            ..
        } => details
            .get("acknowledgedResult")
            .or_else(|| details.get("physicalProof")),
        _ => None,
    };
    result.is_some_and(|result| {
        result["closed"] == true
            && matches!(result["proof"].as_str(), Some("close_ack" | "tab_removed"))
            && result
                .get("claim")
                .is_none_or(|value| value.as_str() == Some(issued.claim.as_str()))
            && result
                .get("tabId")
                .is_none_or(|value| value.as_u64() == Some(issued.tab_id))
            && result
                .get("targetId")
                .is_none_or(|value| value.as_str() == Some(issued.target_id.as_str()))
    })
}

pub(crate) fn canonical_id(value: Option<&str>) -> Option<u64> {
    let text = value?;
    if text.is_empty() || text.starts_with('0') || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn error_fields(value: &Value) -> Result<(&str, &str), BrokerError> {
    match (value["kind"].as_str(), value["message"].as_str()) {
        (Some(kind), Some(message)) if !kind.is_empty() => Ok((kind, message)),
        _ => Err(BrokerError::Protocol(
            "malformed connector error".to_owned(),
        )),
    }
}

fn chrome_result_json(id: u64, text: &str) -> Result<String, BrokerError> {
    #[derive(Serialize)]
    struct Reply<'a> {
        id: u64,
        result: &'a serde_json::value::RawValue,
    }
    let raw = serde_json::from_str(text).map_err(|error| {
        BrokerError::Protocol(format!("raw CDP result is invalid JSON: {error}"))
    })?;
    serde_json::to_string(&Reply { id, result: raw })
        .map_err(|error| BrokerError::Protocol(error.to_string()))
}

fn chrome_event_json(
    method: &str,
    text: &str,
    session_id: Option<&str>,
    source_target_id: Option<&str>,
) -> Result<String, BrokerError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Event<'a> {
        method: &'a str,
        params: &'a serde_json::value::RawValue,
        #[serde(skip_serializing_if = "Option::is_none")]
        session_id: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        source_target_id: Option<&'a str>,
    }
    let params = serde_json::from_str(text).map_err(|error| {
        BrokerError::Protocol(format!("raw CDP event params are invalid JSON: {error}"))
    })?;
    serde_json::to_string(&Event {
        method,
        params,
        session_id,
        source_target_id,
    })
    .map_err(|error| BrokerError::Protocol(error.to_string()))
}

fn buffer_event(
    buffer: &mut BufferedEvents,
    value: BrokerCdpEvent,
    charge: Option<Arc<ByteCharge>>,
) -> bool {
    let Ok(bytes) = extension_framing::encode_json(&value, Direction::HostToChrome) else {
        return false;
    };
    if buffer.events.len() >= MAX_BUFFERED_EVENTS
        || buffer.bytes.saturating_add(bytes.len()) > MAX_BUFFERED_EVENT_BYTES
    {
        return false;
    }
    buffer.bytes += bytes.len();
    buffer.events.push_back(value);
    buffer.charges.push_back(charge);
    true
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WriteReport {
    LocalRejected {
        outer: u64,
        code: String,
        message: String,
    },
    Written {
        outer: u64,
    },
    Skipped {
        outer: u64,
    },
    Abandoned {
        outer: u64,
    },
}

/// Shared by all extension protocol phases of one semantic request, never a token
/// that a local peer can select. It contains no page payload or queue charge.
#[derive(Clone)]
pub(crate) struct ExtensionDispatchGuard {
    fences: Vec<Arc<AtomicBool>>,
    dispatch: Arc<AtomicU8>,
    outer: Option<u64>,
    reported: Arc<AtomicBool>,
}
impl ExtensionDispatchGuard {
    pub(crate) fn is_live(&self) -> bool {
        self.fences.iter().all(|fence| fence.load(Ordering::SeqCst))
    }
    pub(crate) fn was_started(&self) -> bool {
        matches!(self.dispatch.load(Ordering::SeqCst), STARTED | WRITTEN)
    }
    /// Call immediately before a real extension frame write, not queue admission.
    pub(crate) fn start_write(&self) -> bool {
        if !self.is_live() {
            return false;
        }
        match self
            .dispatch
            .compare_exchange(QUEUED, STARTED, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => true,
            Err(STARTED | WRITTEN) => true,
            Err(_) => false,
        }
    }
    pub(crate) fn frame_written(&self) {
        self.dispatch.store(WRITTEN, Ordering::SeqCst);
    }
    pub(crate) fn written_report(&self) -> Option<WriteReport> {
        let outer = self.outer?;
        if self.dispatch.load(Ordering::SeqCst) == WRITTEN
            && !self.reported.swap(true, Ordering::SeqCst)
        {
            Some(WriteReport::Written { outer })
        } else {
            None
        }
    }
    pub(crate) fn reject_before_write(&self, code: String, message: String) -> Option<WriteReport> {
        let outer = self.outer?;
        if self
            .dispatch
            .compare_exchange(QUEUED, SKIPPED, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            Some(WriteReport::LocalRejected {
                outer,
                code,
                message,
            })
        } else {
            None
        }
    }
}

/// Adapter-owned input; retain the charge only while this payload is retained.
/// Multi-phase adapters must not hold a large outgoing charge until final ACK.
pub(crate) struct ExtensionAdapterRequest {
    pub(crate) message: Queued<Value>,
    pub(crate) semantic_id: Option<String>,
    pub(crate) wire_context: Option<ExtensionWireContext>,
    pub(crate) guard: ExtensionDispatchGuard,
}

/// An owned, non-cloneable dispatch permit. Queue admission is not Chrome ACK.
pub(crate) struct ExtensionOutbound {
    value: Value,
    generation: String,
    owner: Option<String>,
    outer: Option<u64>,
    fences: Vec<Arc<AtomicBool>>,
    dispatch: Arc<AtomicU8>,
    _charge: Option<Arc<ByteCharge>>,
    wire_context: Option<ExtensionWireContext>,
}

impl ExtensionOutbound {
    pub(crate) fn dispatch_guard(&self) -> ExtensionDispatchGuard {
        ExtensionDispatchGuard {
            fences: self.fences.clone(),
            dispatch: self.dispatch.clone(),
            outer: self.outer,
            reported: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn outer_id(&self) -> Option<u64> {
        self.outer
    }

    /// Borrowed only by the trusted transport's reserved-cleanup classifier.
    pub(crate) fn payload_for_transport(&self) -> &Value {
        &self.value
    }

    pub(crate) fn into_adapter_request(self) -> ExtensionAdapterRequest {
        let guard = self.dispatch_guard();
        ExtensionAdapterRequest {
            message: Queued::new(self.value, self._charge),
            semantic_id: self.outer.map(|id| id.to_string()),
            wire_context: self.wire_context,
            guard,
        }
    }
    #[cfg(test)]
    pub(crate) fn wire_context(&self) -> Option<&ExtensionWireContext> {
        self.wire_context.as_ref()
    }

    fn live(&self) -> bool {
        self.fences.iter().all(|fence| fence.load(Ordering::SeqCst))
    }

    /// Run on the host's one blocking extension-writer thread, never concurrently.
    /// Each logical request completes its fragment sequence before a higher ID.
    /// Errors after any bytes require extension-port retirement, never a retry.
    pub(crate) fn write_to(
        mut self,
        writer: &mut impl Write,
    ) -> Result<Option<WriteReport>, BrokerError> {
        // The direct Maka writer serializes this original captured context.
        // Chatgpt adapters retain the separate into_adapter_request sidechannel.
        if let Some(context) = &self.wire_context {
            self.value["wireContext"] = serde_json::to_value(context)
                .map_err(|error| BrokerError::Protocol(error.to_string()))?;
        }
        let payload = match extension_framing::encode_json(&self.value, Direction::ChromeToHost) {
            Ok(value) => value,
            Err(error @ FrameError::TooLarge { .. }) => {
                self.dispatch.store(SKIPPED, Ordering::SeqCst);
                return Ok(self.outer.map(|outer| WriteReport::LocalRejected {
                    outer,
                    code: "extension_message_budget".to_owned(),
                    message: error.to_string(),
                }));
            }
            Err(error) => return Err(error.into()),
        };
        if !self.live() {
            self.dispatch.store(SKIPPED, Ordering::SeqCst);
            return Ok(self.outer.map(|outer| WriteReport::Skipped { outer }));
        }
        if payload.len() <= NATIVE_HOST_FRAME_BYTES {
            self.dispatch.store(STARTED, Ordering::SeqCst);
            extension_framing::write_frame(writer, &self.value, Direction::HostToChrome)?;
        } else {
            let outer = self.outer.ok_or_else(|| {
                BrokerError::Protocol("only requests may be fragmented".to_owned())
            })?;
            let owner = self
                .owner
                .as_deref()
                .ok_or_else(|| BrokerError::Protocol("chunked request lacks owner".to_owned()))?;
            let parts = payload.len().div_ceil(CHUNK_BYTES);
            let mut started = false;
            for (part, data) in payload.chunks(CHUNK_BYTES).enumerate() {
                if !self.live() {
                    if started && self.fences[0].load(Ordering::SeqCst) {
                        extension_framing::write_frame(
                            writer,
                            &json!({"kind":"cancelChunk","protocol":1,"generation":self.generation,"owner":owner,"logicalId":outer.to_string()}),
                            Direction::HostToChrome,
                        )?;
                    }
                    if !started {
                        self.dispatch.store(SKIPPED, Ordering::SeqCst);
                    }
                    return Ok(Some(if started {
                        WriteReport::Abandoned { outer }
                    } else {
                        WriteReport::Skipped { outer }
                    }));
                }
                self.dispatch.store(STARTED, Ordering::SeqCst);
                started = true;
                let frame = json!({"kind":"chunk","protocol":1,"generation":self.generation,"owner":owner,"logicalId":outer.to_string(),"part":part,"parts":parts,"bytes":payload.len(),"data":base64::engine::general_purpose::STANDARD.encode(data)});
                extension_framing::write_frame(writer, &frame, Direction::HostToChrome)?;
            }
        }
        self.dispatch.store(WRITTEN, Ordering::SeqCst);
        Ok(self.outer.map(|outer| WriteReport::Written { outer }))
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "extension_fixed_session_broker_tests.rs"]
mod fixed_session_tests;
