//! Platform-agnostic browser-tool v1 core.
//!
//! Typed browser inspection, preparation, navigation, input, dialog, upload,
//! and download tools over an exact-or-refused binding model:
//!
//! - The extension entrypoint is `pid + window_id`. Browser target ids,
//!   tab ids, and page refs (`p<snapshot>:<index>`) are opaque,
//!   session-scoped capabilities minted by core.
//! - Mutation is permitted only for **exact** bindings (unique
//!   bounds-correlated, optionally title-tie-broken). Heuristic
//!   bindings are read-only; everything else is a structured refusal
//!   with a stable code (see [`refusal::BrowserRefusalCode`]).
//! - Core owns schemas, semantics, CDP target handling, the target/ref
//!   store, lifecycle cleanup and correlation. Platform adapters
//!   implement [`platform::BrowserPlatform`] for process identity,
//!   endpoint ownership, extension window metadata, classification and
//!   explicit setup — without depending on core internals.
//!
//! Wiring (per platform crate):
//! ```ignore
//! let engine = BrowserEngine::new(Arc::new(MyPlatformAdapter::new()));
//! register_browser_tools(&engine, &mut registry);
//! ```
//!
//! The legacy `crate::page` contract remains separate because its first-page
//! and URL-hint semantics predate exact browser capabilities. Its CDP paths
//! nevertheless reuse the pooled, loopback-validated WebSocket transport in
//! [`cdp_ws`] so the repository has one event-capable demultiplexer.
//!
//! v2 DOM-ref slice: snapshots compose shadow DOM (piercing, minus
//! user-agent roots), same-process iframes (via `contentDocument`),
//! and — only when the capability is proven live — OOPIF child targets
//! auto-attached beneath the bound tab's maka session. Every ref
//! carries its frame's document identity (frame id + loader id), which
//! is re-proven before any mutation; frames whose identity or
//! capability cannot be proven are omitted or refused, never guessed.

mod adapter_support;
pub mod binding;
mod broker_delivery;
pub mod cdp_ws;
pub use cdp_ws::CdpFailureDisposition;
mod browser_ui;
pub mod download;
pub mod engine;
mod extension_adapter_factory;
mod extension_adapter_process;
mod extension_broker;
mod extension_catalog;
mod extension_framing;
mod extension_host;
mod extension_install;
pub mod extension_process;
mod extension_provider;
mod user_tab_context;
pub use user_tab_context::{BrowserUserTabRead, BrowserWorkspaceExportFormat};
mod extension_upload;
mod extension_upload_placement;
mod extension_upload_worker;
mod extension_wire;
mod grant;
mod js_string;
pub use js_string::JsonStringLiteral;
mod keyed_gates;
mod local_ipc;
#[cfg(test)]
pub(crate) mod mock_cdp;
mod mutation;
pub use browser_ui::FIXED_BROWSER_UI_SCRIPT;
mod chatgpt_adapter;
mod chatgpt_inventory;
mod chatgpt_rpc_v2;
mod chatgpt_tab_id;
pub use chatgpt_tab_id::parse_browser_tab_id;
pub mod platform;
pub mod pointer;
mod prepare;
mod reconnect;
pub mod refusal;
mod semantic;
mod setup_descriptor;
pub mod store;
pub mod tools;
pub mod types;
#[cfg(test)]
mod v2_tests;

pub use adapter_support::{
    is_firefox, loopback_websocket_port, parse_devtools_active_port, BrowserCursorTracker,
};
pub use engine::BrowserEngine;
pub use platform::{
    BrowserConsentOutcome, BrowserConsentRequest, BrowserPlatform, BrowserVisualAction,
    BrowserVisualActionKind, ExistingProfileSetupOutcome, ExistingProfileSetupRequest,
    IsolatedBrowserProcess, PrepareAction, PrepareAttachment, PrepareAttachmentKind,
    PrepareOutcome, PrepareProfile, PrepareProfileMode, PrepareRequest, PrepareSideEffects,
    PrepareStrategy,
};
pub use refusal::{BrowserRefusal, BrowserRefusalCode};
pub use semantic::{semantic_ax_tree, SEMANTIC_COMPUTED_STYLES};
pub use setup_descriptor::{
    existing_profile_setup_descriptor, BrowserSetupDescriptor, EXISTING_PROFILE_SETUP_READY_TIMEOUT,
};
pub use tools::register_browser_tools;
pub use types::{
    BindingQuality, BrowserClassification, BrowserEngineFamily, BrowserProduct,
    EndpointOwnershipMethod, EndpointOwnershipProof, NativeOwnershipMethod, NativeOwnershipProof,
    NativeWindowInfo, OwnedEndpoint, ProcessFingerprint, Rect,
};

pub(crate) fn session_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "string",
        "description": format!(
            "{} Browser targets, tabs, and refs belong to the resolved lifecycle session.",
            cua_driver_contract::MULTI_CALL_SESSION_DESCRIPTION
        )
    })
}

pub(crate) fn required_session_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "string",
        "description": "For multi-call work, prefer a short public session label and repeat it on every call that accepts it. This tool requires the label that owns its browser target, tab, and refs."
    })
}

pub use extension_provider::{
    discover_installed_extension_endpoints, discover_registered, discover_registered_endpoints,
    discover_registered_for, CleanupEvidence, CleanupProof, ExtensionAttachmentPreparation,
    ExtensionBrowserOperation, ExtensionBrowserProvider, ExtensionCdpCompletionOutcome,
    ExtensionClaimPreparationProof, ExtensionCommittedTabUrl, ExtensionCreatedTab,
    ExtensionCreationReceipt, ExtensionCursorPresentationAck, ExtensionDownloadMetadata,
    ExtensionDownloadStatus, ExtensionEffectOwner, ExtensionEndpointDiscovery,
    ExtensionEndpointRejection, ExtensionFixedSessionCleanupProof,
    ExtensionFixedSessionPreparedTab, ExtensionFixedSessionReceipt, ExtensionFixedUiAck,
    ExtensionFixedUiAction, ExtensionFixedUiColor, ExtensionFixedUiCursor,
    ExtensionFixedUiIdentity, ExtensionFixedUiOperation, ExtensionFixedUiProof,
    ExtensionFixedUiRenderState, ExtensionFixedUiRenderStatus, ExtensionFixedUiRequest,
    ExtensionGroupColor, ExtensionGroupPresentation, ExtensionGroupProof,
    ExtensionGroupReleaseEvidence, ExtensionGroupReleaseProof, ExtensionHeader,
    ExtensionHeaderPolicyScope, ExtensionHeaderProof, ExtensionHeaderScope, ExtensionHostOperation,
    ExtensionKnownCustody, ExtensionManagedGroupReceipt, ExtensionMetadataError,
    ExtensionMutationDiagnostic, ExtensionOperation, ExtensionOperationCompletion,
    ExtensionOperationOutcome, ExtensionPendingOperation, ExtensionPhysicalClaim,
    ExtensionPopupRequest, ExtensionPreparationDocument, ExtensionPreparationDocumentBinding,
    ExtensionPreparationPolicy, ExtensionPreparedTab, ExtensionProviderCapabilities,
    ExtensionProviderError, ExtensionProviderEvent, ExtensionRecoveredOperation,
    ExtensionSessionCleanupObservation, ExtensionSessionHeaderProof, ExtensionSessionPopupRequest,
    ExtensionSessionPreparation, ExtensionSessionPreparedTab, ExtensionSessionRequestRegistration,
    ExtensionTabInfo, ExtensionUserTabsOrder,
};
pub use extension_provider::{
    ExtensionRetainedUpload, ExtensionUploadAbandonAck, ExtensionUploadChunkAck,
    ExtensionUploadDescriptorError, ExtensionUploadFile, ExtensionUploadModifiedTime,
    ExtensionUploadStage, EXTENSION_UPLOAD_CHUNK_BYTES,
};
pub use local_ipc::{ExtensionEndpointIdentity, IpcError, ValidatedExtensionEndpoint};

pub use extension_provider::ExtensionTabAbsenceObservation;

pub use extension_provider::{ExtensionKeepStatus, ExtensionKeepTab, ExtensionTurnFinishAck};

pub use extension_wire::{ExtensionWireContext, ExtensionWireContextError};

pub use extension_process::{
    ExtensionAdapterMode, ExtensionAdapterSelection, ExtensionAdapterSelectionError,
};

pub use extension_provider::{
    ExtensionClaimCdpDrainProof, ExtensionClaimCdpSnapshot, ExtensionPendingCdpRequest,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_session_schema_keeps_naming_and_capability_guidance_together() {
        let schema = session_schema();
        let description = schema["description"]
            .as_str()
            .expect("browser session description");
        assert!(description.contains("prefer a short public session label"));
        assert!(description.contains("repeat it on every call that accepts it"));
        assert!(description.contains("Browser targets, tabs, and refs"));
    }

    #[test]
    fn required_browser_session_schema_does_not_suggest_omission() {
        let schema = required_session_schema();
        let description = schema["description"]
            .as_str()
            .expect("required browser session description");
        assert!(description.contains("prefer a short public session label"));
        assert!(description.contains("repeat it on every call that accepts it"));
        assert!(description.contains("requires the label"));
        assert!(!description.contains("Omit it"));
    }
}
