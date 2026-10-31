// SPDX-License-Identifier: MIT

//! Finite Chrome-extension-host process entry and broker/IPC composition.
//!
//! The embedding executable calls bootstrap before application logging and
//! immediately returns its ExitCode when selected. Rust byte-oriented stdin and
//! stdout carry only extension frames; no text console or line-ending adapter is used.
//! The process ends with this Chrome extension port, without starting a daemon.

use super::{
    broker_delivery::{DeliveryError, Queued, IPC_SHUTDOWN_DRAIN_TIMEOUT},
    extension_broker::{
        BrokerError, BrokerHandle, ClientConnection, ControlEvent, ControlRequest,
        ExtensionHostBroker, RouteSender,
    },
    extension_catalog,
    extension_framing::{self, Direction, FrameError},
    extension_host::{
        AdapterRegistration, ExtensionInvocation, ExtensionOrigin, HostError, InstalledHostConfig,
        Platform, MAKA_HOST_NAME,
    },
    extension_upload_placement::UploadPlacement,
    extension_upload_worker::UploadWorkerOwner,
    extension_wire::ExtensionWireContext,
    local_ipc::{self, ExtensionEndpointIdentity, IpcError, PublishedEndpoint},
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::HashMap, io, path::PathBuf, process::ExitCode};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::{JoinHandle, JoinSet},
};

const MAX_CONNECTIONS: usize = 32;

pub(crate) const CHATGPT_HOST_NAME: &str = "com.openai.codexextension";

/// A supported adapter selected by setup or discovered native registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtensionAdapterMode {
    Maka,
    Chatgpt,
}

impl ExtensionAdapterMode {
    /// Recognize an exact registered host identity; never accept display aliases.
    pub fn from_host_name(host_name: &str) -> Option<Self> {
        match host_name {
            MAKA_HOST_NAME => Some(Self::Maka),
            CHATGPT_HOST_NAME => Some(Self::Chatgpt),
            _ => None,
        }
    }

    /// Stable public provider selector used by browser APIs and setup commands.
    pub const fn selector(self) -> &'static str {
        match self {
            Self::Maka => "maka",
            Self::Chatgpt => "chatgpt",
        }
    }

    /// Human-readable name of the selected browser extension provider.
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Maka => "Maka",
            Self::Chatgpt => "ChatGPT",
        }
    }
}

/// Selection cannot be constructed from tool/model JSON or an ambient origin.
/// It retains the same installed configuration that extension startup verifies.
pub struct ExtensionAdapterSelection {
    config: ExtensionProcessConfig,
    mode: ExtensionAdapterMode,
}

impl std::fmt::Debug for ExtensionAdapterSelection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExtensionAdapterSelection")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("installed extension browser selection refused: {message}")]
pub struct ExtensionAdapterSelectionError {
    message: String,
    missing: bool,
}

impl ExtensionAdapterSelection {
    /// Load the sole validated entry beside this canonical installed executable.
    ///
    /// The file ownership, ACL/mode, executable and selected adapter identity are
    /// checked by the same parser used for extension startup. No search or fallback
    /// selects a foreign extension. No file or browser configuration is written.
    pub fn load_installed() -> Result<Self, ExtensionAdapterSelectionError> {
        let mut installed = load_installed_selections()?;
        if installed.selections.len() == 1 && installed.rejected.is_empty() {
            return Ok(installed.selections.remove(0));
        }
        Err(ExtensionAdapterSelectionError {
            missing: installed.selections.is_empty() && installed.rejected.is_empty(),
            message: if installed.selections.is_empty() && installed.rejected.is_empty() {
                "no extension adapter is installed".to_owned()
            } else if installed.rejected.is_empty() {
                "installed catalog requires an exact origin when multiple entries are present"
                    .to_owned()
            } else {
                "installed catalog includes rejected entries; no default selection is permitted"
                    .to_owned()
            },
        })
    }

    fn from_config(config: ExtensionProcessConfig) -> Result<Self, ProcessError> {
        let mode = ExtensionAdapterMode::from_host_name(config.registration.host_name())
            .ok_or_else(|| {
                ProcessError::Lifecycle("installed adapter is unsupported".to_owned())
            })?;
        if config.runtime_directory.is_none() {
            return Err(ProcessError::Lifecycle(
                "installed adapter lacks its private runtime directory".to_owned(),
            ));
        }
        Ok(Self { config, mode })
    }

    pub fn mode(&self) -> ExtensionAdapterMode {
        self.mode
    }
    pub(crate) fn adapter_name(&self) -> &str {
        self.config.registration.host_name()
    }
    pub(crate) fn expected_extension_id(&self) -> &str {
        self.config.expected_extension.id()
    }
    pub(crate) fn runtime_directory(&self) -> &std::path::Path {
        self.config
            .runtime_directory
            .as_deref()
            .expect("installed selection checked private directory")
    }
}

impl ExtensionAdapterSelectionError {
    /// Only an empty verified installation catalog is optional setup. Rejected
    /// entries, changed paths and ambiguous default selection remain errors.
    pub fn is_missing(&self) -> bool {
        self.missing
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProcessError {
    #[error("extension host I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("extension host frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("extension host JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("extension host registration failed: {0}")]
    Host(#[from] HostError),
    #[error("extension host IPC failed: {0}")]
    Ipc(#[from] IpcError),
    #[error("extension host broker failed: {0}")]
    Broker(#[from] BrokerError),
    #[error("extension adapter process failed: {0}")]
    Adapter(#[from] super::extension_adapter_process::AdapterProcessError),
    #[error(transparent)]
    Catalog(#[from] extension_catalog::CatalogError),
    #[error("extension host lifecycle failed: {0}")]
    Lifecycle(String),
}

/// Supplied by maka package configuration, never by model/tool arguments.
pub(crate) struct ExtensionProcessConfig {
    registration: AdapterRegistration,
    expected_extension: ExtensionOrigin,
    runtime_directory: Option<PathBuf>,
}

impl ExtensionProcessConfig {
    #[cfg(test)]
    pub(crate) fn maka(
        extension_id: &str,
        runtime_directory: Option<PathBuf>,
    ) -> Result<Self, HostError> {
        let expected_extension = ExtensionOrigin::from_id(extension_id)?;
        Ok(Self {
            registration: AdapterRegistration::maka(expected_extension.clone()),
            expected_extension,
            runtime_directory,
        })
    }

    /// Retain the exact adapter and origin selected by installation configuration.
    pub(crate) fn selected_adapter(
        registration: AdapterRegistration,
        expected_extension: ExtensionOrigin,
        runtime_directory: Option<PathBuf>,
    ) -> Self {
        Self {
            registration,
            expected_extension,
            runtime_directory,
        }
    }
}

fn extension_origin_candidate(argument: Option<&std::ffi::OsStr>) -> bool {
    argument
        .and_then(|argument| argument.to_str())
        .is_some_and(|argument| argument.starts_with("chrome-extension://"))
}

fn process_config(config: &InstalledHostConfig) -> Result<ExtensionProcessConfig, ProcessError> {
    let extension = ExtensionOrigin::from_id(&config.expected_extension_id)?;
    let registration = if config.adapter == MAKA_HOST_NAME {
        AdapterRegistration::maka(extension.clone())
    } else {
        AdapterRegistration::selected_adapter(&config.adapter, extension.clone())?
    };
    Ok(ExtensionProcessConfig::selected_adapter(
        registration,
        extension,
        Some(config.private_state_directory.clone()),
    ))
}

pub(crate) struct InstalledSelections {
    pub(crate) selections: Vec<ExtensionAdapterSelection>,
    pub(crate) rejected: Vec<(PathBuf, String)>,
}

/// Discovery consumes exact validated entries and reports invalid siblings.
pub(crate) fn load_installed_selections(
) -> Result<InstalledSelections, ExtensionAdapterSelectionError> {
    let load = || -> Result<InstalledSelections, ProcessError> {
        let executable = std::env::current_exe()?;
        let catalog = extension_catalog::load(&executable)?;
        let explicit_chatgpt = catalog
            .entries
            .iter()
            .any(|entry| entry.config.adapter == CHATGPT_HOST_NAME)
            || catalog
                .rejected
                .iter()
                .any(|entry| entry.adapter == CHATGPT_HOST_NAME);
        let mut result = InstalledSelections {
            selections: Vec::new(),
            rejected: catalog
                .rejected
                .into_iter()
                .map(|entry| (entry.path, entry.reason))
                .collect(),
        };
        for entry in catalog.entries {
            match process_config(&entry.config).and_then(ExtensionAdapterSelection::from_config) {
                Ok(selection) => result.selections.push(selection),
                Err(error) => result.rejected.push((entry.path, error.to_string())),
            }
        }
        if !explicit_chatgpt {
            match super::host_handoff::ConfiguredHandoff::load() {
                Ok(Some(config)) => match config.selection() {
                    Ok(selection) => result.selections.push(selection),
                    Err(error) => result
                        .rejected
                        .push((executable.clone(), error.to_string())),
                },
                Ok(None) => {}
                Err(error) => result
                    .rejected
                    .push((executable.clone(), error.to_string())),
            }
        }
        Ok(result)
    };
    load().map_err(|error| ExtensionAdapterSelectionError {
        missing: false,
        message: error.to_string(),
    })
}

fn installed_config(
    current_executable: &std::path::Path,
    origin: &std::ffi::OsStr,
) -> Result<ExtensionProcessConfig, ProcessError> {
    let origin = origin.to_str().ok_or_else(|| {
        ProcessError::Lifecycle("extension invocation origin is not Unicode".into())
    })?;
    let catalog = extension_catalog::load(current_executable)?;
    let entry = catalog.origin(origin)?;
    if entry.config.handoff.is_some() {
        return Err(ProcessError::Lifecycle(
            "on-demand native host requires supervisor admission".into(),
        ));
    }
    process_config(&entry.config)
}

pub(crate) fn handoff_selection(
    config: &InstalledHostConfig,
) -> Result<ExtensionAdapterSelection, ProcessError> {
    ExtensionAdapterSelection::from_config(process_config(config)?)
}

pub(crate) fn bootstrap_handoff(
    config: &InstalledHostConfig,
) -> Result<Option<ExitCode>, ProcessError> {
    Ok(bootstrap(process_config(config)?))
}

/// Binary startup hook: ordinary CLI invocations do not probe installation data.
///
/// A extension-origin candidate requires an explicit, privately owned sidecar from
/// connector setup. Its ID is never inferred from argv or a browser profile.
pub fn bootstrap_installed() -> Option<ExitCode> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if let Some(exit) = super::extension_install::bootstrap_setup(&arguments) {
        return Some(exit);
    }
    let origin = arguments.first()?;
    if !extension_origin_candidate(Some(origin.as_os_str())) {
        return None;
    }
    let config = std::env::current_exe()
        .map_err(ProcessError::Io)
        .and_then(|path| installed_config(&path, origin));
    match config {
        Ok(config) => match bootstrap(config) {
            Some(exit) => Some(exit),
            None => {
                eprintln!(
                    "Maka extension host refused an origin outside its explicit registration"
                );
                Some(ExitCode::FAILURE)
            }
        },
        Err(error) => {
            eprintln!("Maka extension host requires explicit connector setup: {error}");
            Some(ExitCode::FAILURE)
        }
    }
}

/// Return `None` on the ordinary app path, before touching runtime files or stdio.
pub(crate) fn bootstrap(config: ExtensionProcessConfig) -> Option<ExitCode> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let platform = match std::env::consts::OS {
        "linux" => Platform::Linux,
        "macos" => Platform::Macos,
        "windows" => Platform::Windows,
        _ => {
            eprintln!("Maka extension host does not support this platform");
            return Some(ExitCode::FAILURE);
        }
    };
    let invocation = match config.registration.invocation(&arguments, platform) {
        Ok(None) => return None,
        Ok(Some(invocation)) => invocation,
        Err(error) => {
            eprintln!("Maka extension host refused invocation: {error}");
            return Some(ExitCode::FAILURE);
        }
    };
    let result = if config.registration.host_name() == MAKA_HOST_NAME {
        run_extension_host(
            invocation,
            config.expected_extension,
            config.runtime_directory,
        )
    } else {
        ExtensionAdapterSelection::from_config(config)
            .and_then(|selection| run_adapted_extension_host(invocation, selection))
    };
    Some(match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Maka extension host ended: {error}");
            ExitCode::FAILURE
        }
    })
}

// Called only after registration selected this process's native-host entry.
// This is placement evidence, never an added browser identity or file grant.
fn native_upload_service(broker: &mut ExtensionHostBroker) -> Option<UploadWorkerOwner> {
    let placement = match UploadPlacement::capture_native_launch() {
        Ok(placement) => placement,
        Err(error) => {
            eprintln!("Maka native upload placement is unavailable: {error}");
            return None;
        }
    };
    match broker.install_native_uploads(placement) {
        Ok(owner) => Some(owner),
        Err(error) => {
            eprintln!("Maka native upload worker is unavailable: {error}");
            None
        }
    }
}

fn finish_native_uploads(
    owner: Option<UploadWorkerOwner>,
    outcome: Result<(), ProcessError>,
) -> Result<(), ProcessError> {
    let Some(owner) = owner else {
        return outcome;
    };
    // This joins the sole host resource owner outside the broker/runtime actor.
    let cleanup = match owner.shutdown() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(ProcessError::Lifecycle(format!(
            "native upload backing cleanup remains unconfirmed: {error}"
        ))),
        Err(_) => Err(ProcessError::Lifecycle(
            "native upload worker ended without final cleanup proof".into(),
        )),
    };
    if let Err(error) = &cleanup {
        eprintln!("{error}");
    }
    match (outcome, cleanup) {
        (Ok(()), cleanup) => cleanup,
        (Err(outcome), Ok(())) => Err(outcome),
        (Err(outcome), Err(cleanup)) => {
            Err(ProcessError::Lifecycle(format!("{outcome}; {cleanup}")))
        }
    }
}

/// The reviewed foreign protocol starts itself (getInfo), then supplies the
/// same broker's normalized actual hello. No Maka hello/bound frame is imposed.
fn run_adapted_extension_host(
    invocation: ExtensionInvocation,
    selection: ExtensionAdapterSelection,
) -> Result<(), ProcessError> {
    let principal = local_ipc::current_user_principal()?;
    let directory = selection.runtime_directory().to_owned();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let (handle, mut broker, outgoing) =
        ExtensionHostBroker::channels(selection.config.expected_extension.clone(), principal);
    let upload_owner = native_upload_service(&mut broker);
    let outcome=runtime.block_on(async move {
        let adapter=super::extension_adapter_factory::for_installed(&selection,broker.generation().to_owned())
            .map_err(|error|ProcessError::Lifecycle(error.to_string()))?;
        let mut broker_task=tokio::spawn(broker.run());
        let (ready_send,ready)=oneshot::channel();
        let actor_handle=handle.clone();
        let mut actor_task=tokio::spawn(super::extension_adapter_process::run(adapter,actor_handle,outgoing,ready_send));
        let readiness=tokio::select! {
            _=tokio::time::sleep(std::time::Duration::from_secs(30))=>Err(ProcessError::Lifecycle("extension adapter startup did not complete within its bounded handshake interval".to_owned())),
            ready=ready=>ready.map_err(|_|ProcessError::Lifecycle("extension adapter startup acknowledgement was lost".to_owned()))?.map_err(ProcessError::Lifecycle),
            result=&mut actor_task=>Err(ProcessError::Lifecycle(format!("extension adapter ended during startup: {result:?}"))),
            _=&mut broker_task=>Err(ProcessError::Lifecycle("extension broker ended before adapter startup".to_owned())),
        };
        if let Err(error)=readiness {
            handle.extension_eof("extension adapter startup failed").await;
            if !broker_task.is_finished(){let _=broker_task.await;}
            actor_task.abort();return Err(error);
        }
        let actual=handle.identity().await?;
        let identity=ExtensionEndpointIdentity{adapter:invocation.host_name,extension_id:actual.extension_id,instance_id:actual.instance_id,generation:actual.generation,capabilities:actual.capabilities,host_pid:std::process::id()};
        let endpoint=match PublishedEndpoint::publish(&directory,identity).await {
            Ok(endpoint)=>endpoint,
            Err(error)=>{handle.extension_eof("private adapter endpoint publication failed").await;actor_task.abort();let _=broker_task.await;return Err(error.into());}
        };
        let (stop,stop_receive)=watch::channel(false);
        let mut server_task=tokio::spawn(serve_until(endpoint,handle.clone(),stop_receive));
        let result=tokio::select! {
            result=&mut actor_task=>match result {Ok(result)=>result.map_err(ProcessError::from),Err(error)=>Err(ProcessError::Lifecycle(format!("extension adapter actor ended: {error}")))},
            _=&mut broker_task=>Ok(()),
            result=&mut server_task=>match result {Ok(result)=>result,Err(error)=>Err(ProcessError::Lifecycle(format!("private adapter server ended: {error}")))},
        };
        stop.send_replace(true);
        handle.extension_eof("extension adapter process lifetime ended").await;
        if !server_task.is_finished(){let _=server_task.await;}
        if !broker_task.is_finished(){let _=broker_task.await;}
        if !actor_task.is_finished(){actor_task.abort();}
        result
     });
    finish_native_uploads(upload_owner, outcome)
}

fn read_initial_hello(expected: &ExtensionOrigin) -> Result<Value, ProcessError> {
    let input = std::io::stdin();
    let payload = extension_framing::read_frame(&mut input.lock(), Direction::ChromeToHost)?
        .ok_or_else(|| ProcessError::Lifecycle("Chrome closed before hello".to_owned()))?;
    let hello: Value = serde_json::from_slice(&payload)?;
    if hello["kind"] != "hello" || hello["protocol"] != 1 {
        return Err(ProcessError::Lifecycle(
            "first extension message is not protocol1 hello".to_owned(),
        ));
    }
    expected.validate_hello_id(hello["extensionId"].as_str().unwrap_or(""))?;
    Ok(hello)
}

/// This is the selected executable mode; the caller must exit after it returns.
fn run_extension_host(
    invocation: ExtensionInvocation,
    expected: ExtensionOrigin,
    directory: Option<PathBuf>,
) -> Result<(), ProcessError> {
    let hello = read_initial_hello(&expected)?;
    let principal = local_ipc::current_user_principal()?;
    let directory = directory.map_or_else(local_ipc::current_user_runtime_directory, Ok)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let (handle, mut broker, mut outgoing) = ExtensionHostBroker::channels(expected, principal);
    let upload_owner = native_upload_service(&mut broker);
    let outcome=runtime.block_on(async move {
        let mut broker_task=tokio::spawn(broker.run());
        let (report_send,mut reports)=mpsc::channel(128);
        let (failure_send,mut failures)=watch::channel::<Option<String>>(None);
        let (ready_send,ready)=oneshot::channel::<Result<(),String>>();
        let writer_failure=failure_send.clone();
        // These are the binary adapter's stdio threads, not another process or
        // library-owned executor. They never perform desktop operations.
        std::thread::Builder::new().name("maka-extension-writer".to_owned()).spawn(move || {
            let output=std::io::stdout(); let mut output=output.lock(); let mut ready_send=Some(ready_send);
            while let Some(frame)=outgoing.blocking_recv() {
                match frame.write_to(&mut output) {
                    Ok(report)=>{
                        if let Some(ready)=ready_send.take() { let _=ready.send(Ok(())); }
                        if let Some(report)=report {
                            // Never block this serial writer on the actor's input
                            // queue: input/output backpressure could otherwise cycle.
                            if report_send.try_send(report).is_err() { writer_failure.send_replace(Some("extension writer report budget exhausted".to_owned())); return; }
                        }
                    }
                    Err(error)=>{
                        let reason=error.to_string(); if let Some(ready)=ready_send.take() { let _=ready.send(Err(reason.clone())); }
                        writer_failure.send_replace(Some(reason)); return;
                    }
                }
            }
            if let Some(ready)=ready_send.take() { let _=ready.send(Err("extension writer ended before bound".to_owned())); }
        })?;
        let reporter_handle=handle.clone();
        let report_task=tokio::spawn(async move { while let Some(report)=reports.recv().await { reporter_handle.write_report(report).await; } });
        handle.extension_message(hello).await?;
        let actual=handle.identity().await?;
        match ready.await { Ok(Ok(()))=>{},Ok(Err(reason))=>{ handle.extension_eof(&reason).await; let _=broker_task.await; report_task.abort(); return Err(ProcessError::Lifecycle(reason)); },Err(_)=>{ handle.extension_eof("extension writer readiness was lost").await; let _=broker_task.await; report_task.abort(); return Err(ProcessError::Lifecycle("extension writer readiness was lost".to_owned())); } }
        let identity=ExtensionEndpointIdentity { adapter:invocation.host_name,extension_id:actual.extension_id,instance_id:actual.instance_id,generation:actual.generation,capabilities:actual.capabilities,host_pid:std::process::id() };
        let endpoint=match PublishedEndpoint::publish(&directory,identity).await {
            Ok(endpoint)=>endpoint,
            Err(error)=>{ handle.extension_eof("private endpoint publication failed").await; let _=broker_task.await; report_task.abort(); return Err(error.into()); }
        };
        let reader_runtime=tokio::runtime::Handle::current(); let reader_handle=handle.clone(); let reader_failure=failure_send.clone();
        let reader_start=std::thread::Builder::new().name("maka-extension-reader".to_owned()).spawn(move || {
            let input=std::io::stdin(); let mut input=input.lock();
            loop {
                let value=match extension_framing::read_frame(&mut input,Direction::ChromeToHost) {
                    Ok(Some(bytes))=>match serde_json::from_slice(&bytes) { Ok(value)=>value,Err(error)=>{ reader_failure.send_replace(Some(error.to_string())); return; } },
                    Ok(None)=>{ reader_runtime.block_on(reader_handle.extension_eof("Chrome extension stdin EOF")); return; },
                    Err(error)=>{ reader_failure.send_replace(Some(error.to_string())); return; }
                };
                if reader_runtime.block_on(reader_handle.extension_message(value)).is_err() { return; }
            }
        });
        if let Err(error)=reader_start {
            let _=endpoint.cleanup(); handle.extension_eof("extension reader thread could not start").await;
            let _=broker_task.await; report_task.abort(); return Err(error.into());
        }
        let (stop,stop_receive)=watch::channel(false);
        let server_handle=handle.clone();
        let mut server_task=tokio::spawn(serve_until(endpoint,server_handle,stop_receive));
        let outcome=tokio::select! {
            result=&mut broker_task=>{ stop.send_replace(true); match result { Ok(())=>Ok(()),Err(error)=>Err(ProcessError::Lifecycle(format!("extension broker task ended: {error}"))) } }
            result=&mut server_task=>{ handle.extension_eof("local IPC server ended").await; match result { Ok(result)=>result,Err(error)=>Err(ProcessError::Lifecycle(format!("local IPC server task ended: {error}"))) } }
            _=wait_failure(&mut failures)=>{ let reason=failures.borrow().clone().unwrap_or_else(||"extension I/O failure signal ended".to_owned()); stop.send_replace(true); handle.extension_eof(&reason).await; Err(ProcessError::Lifecycle(reason)) }
        };
        stop.send_replace(true);
        if !server_task.is_finished() { let _=server_task.await; }
        if !broker_task.is_finished() { let _=broker_task.await; }
        report_task.abort();
        outcome
     });
    finish_native_uploads(upload_owner, outcome)
}

async fn wait_failure(receiver: &mut watch::Receiver<Option<String>>) {
    loop {
        if receiver.borrow().is_some() {
            return;
        }
        if receiver.changed().await.is_err() {
            return;
        }
    }
}

async fn wait_stop(receiver: &mut watch::Receiver<bool>) {
    loop {
        if *receiver.borrow() {
            return;
        }
        if receiver.changed().await.is_err() {
            return;
        }
    }
}

async fn serve_until(
    mut endpoint: PublishedEndpoint,
    broker: BrokerHandle,
    mut stop: watch::Receiver<bool>,
) -> Result<(), ProcessError> {
    let mut clients = JoinSet::new();
    let outcome: Result<(), ProcessError> = loop {
        tokio::select! {
            _=wait_stop(&mut stop)=>break Ok(()),
            accepted=endpoint.accept()=>{
                let (mut stream,peer)=match accepted { Ok(accepted)=>accepted,Err(error)=>break Err(error.into()) };
                if clients.len()>=MAX_CONNECTIONS { drop(stream); continue; }
                let admitted=tokio::select! { _=wait_stop(&mut stop)=>break Ok(()),result=endpoint.handshake(&mut stream)=>result };
                if admitted.is_err() { drop(stream); continue; }
                let client=match broker.admit_peer(peer).await { Ok(client)=>client,Err(_)=>{ drop(stream); continue; } };
                clients.spawn(serve_connection(stream,client,broker.clone(),stop.clone()));
            }
            Some(_)=clients.join_next(),if !clients.is_empty()=>{}
        }
    };
    // Stop discovery/admission first. Existing owners retain their ordered
    // output until the final extension generation receipt reaches the socket.
    let cleanup = endpoint.cleanup();
    if outcome.is_err() {
        broker.extension_eof("local IPC listener ended").await;
    }
    drain_connections(&mut clients).await;
    outcome?;
    cleanup?;
    Ok(())
}

async fn drain_connections(clients: &mut JoinSet<Result<(), ProcessError>>) {
    if tokio::time::timeout(IPC_SHUTDOWN_DRAIN_TIMEOUT, async {
        while clients.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        clients.abort_all();
        while clients.join_next().await.is_some() {}
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum ClientWire {
    Control {
        request: ControlRequest,
        #[serde(rename = "wireContext", default)]
        wire_context: Option<ExtensionWireContext>,
    },
    OpenCdp {
        id: u64,
        claim: String,
    },
    Cdp {
        route: u64,
        message: Value,
        #[serde(rename = "wireContext", default)]
        wire_context: Option<ExtensionWireContext>,
    },
    CloseCdp {
        route: u64,
    },
}

enum ServerOutbound {
    Plain(Value),
    Control(Queued<ControlEvent>),
    End,
}

impl ServerOutbound {
    fn json(&self) -> Option<Value> {
        match self {
            Self::Plain(value) => Some(value.clone()),
            Self::Control(event) => Some(match event.event() {
                ControlEvent::CdpOpened { id, route } => {
                    json!({"kind":"cdpOpened","id":id,"route":route})
                }
                _ => json!({"kind":"controlEvent","event":event}),
            }),
            Self::End => None,
        }
    }
}

struct ConnectionTasks {
    writer: JoinHandle<Result<(), IpcError>>,
    control_forward: JoinHandle<()>,
    stop: watch::Receiver<bool>,
}

impl ConnectionTasks {
    async fn next_frame<R: tokio::io::AsyncRead + Unpin>(
        &mut self,
        input: &mut R,
    ) -> Result<Option<Value>, ProcessError> {
        let read = local_ipc::read_json(input);
        tokio::pin!(read);
        tokio::select! {
            biased;
            _=wait_stop(&mut self.stop)=>{
                // Admission ends at stop; queued extension receipts still precede
                // the writer's End. The server bounds nonreading peers outside.
                match (&mut self.writer).await {
                    Ok(Ok(()))=>Ok(None),
                    Ok(Err(error))=>Err(error.into()),
                    Err(error)=>Err(ProcessError::Lifecycle(format!("IPC writer ended: {error}"))),
                }
            },
            result=&mut self.writer=>match result {
                Ok(Ok(()))=>Ok(None),
                Ok(Err(error))=>Err(error.into()),
                Err(error)=>Err(ProcessError::Lifecycle(format!("IPC writer ended: {error}"))),
            },
            value=&mut read=>value.map_err(Into::into),
        }
    }
}

async fn serve_connection<S>(
    stream: S,
    connection: ClientConnection,
    broker: BrokerHandle,
    stop: watch::Receiver<bool>,
) -> Result<(), ProcessError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let ClientConnection {
        sender: control,
        events: mut controls,
    } = connection;
    let (mut input, mut output) = tokio::io::split(stream);
    let (send, mut messages) = mpsc::channel::<ServerOutbound>(8);
    let writer_progress = broker.clone();
    let writer = tokio::spawn(async move {
        while let Some(message) = messages.recv().await {
            let Some(value) = message.json() else {
                return Ok::<(), IpcError>(());
            };
            local_ipc::write_json(&mut output, &value).await?;
            drop(value);
            drop(message);
            writer_progress.delivery_progress();
        }
        Ok::<(), IpcError>(())
    });
    let control_output = send.clone();
    let control_progress = broker.clone();
    let control_forward = tokio::spawn(async move {
        while let Some(event) = controls.recv().await {
            control_progress.delivery_progress();
            if control_output
                .send(ServerOutbound::Control(event))
                .await
                .is_err()
            {
                return;
            }
        }
        // The writer consumes this only after every prior FIFO item reached
        // the socket. Control EOF must not abort its final generation receipt.
        let _ = control_output.send(ServerOutbound::End).await;
    });
    let mut routes: HashMap<u64, RouteSender> = HashMap::new();
    let mut tasks = ConnectionTasks {
        writer,
        control_forward,
        stop,
    };
    let mut open_high_water = 0_u64;
    let mut drain_before_owner_close = false;
    let result = loop {
        let value = match tasks.next_frame(&mut input).await {
            Ok(Some(value)) => value,
            Ok(None) => break Ok(()),
            Err(error) => break Err(error),
        };
        let request: ClientWire = match serde_json::from_value(value) {
            Ok(request) => request,
            Err(error) => break Err(error.into()),
        };
        match request {
            ClientWire::Control {
                request,
                wire_context,
            } => {
                if let Err(error) = control.control_with_context(request, wire_context).await {
                    drain_before_owner_close = matches!(
                        &error,
                        BrokerError::Closed | BrokerError::Delivery(DeliveryError::Closed(_))
                    );
                    break Err(error.into());
                }
            }
            ClientWire::OpenCdp { id, claim } => {
                if id == 0 || id <= open_high_water {
                    let _=send.send(ServerOutbound::Plain(json!({"kind":"cdpOpenRejected","id":id,"code":"duplicate_local_id","message":"openCdp IDs cannot be replayed"}))).await;
                    continue;
                }
                open_high_water = id;
                match control.open_cdp_route_ordered(&claim, id).await {
                    Ok(route) => {
                        let id_route = route.sender.wire_id();
                        // The broker puts the open acknowledgement before all
                        // buffered CDP data on the same owner output FIFO.
                        drop(route.events);
                        routes.insert(id_route, route.sender);
                    }
                    Err(error) => {
                        if matches!(
                            &error,
                            BrokerError::Closed | BrokerError::Delivery(DeliveryError::Closed(_))
                        ) {
                            drain_before_owner_close = true;
                            break Err(error.into());
                        }
                        if send.send(ServerOutbound::Plain(json!({"kind":"cdpOpenRejected","id":id,"code":"claim_unavailable","message":error.to_string()}))).await.is_err() {
                            break Ok(());
                        }
                    }
                }
            }

            ClientWire::Cdp {
                route,
                message,
                wire_context,
            } => {
                let Some(binding) = routes.get(&route) else {
                    break Err(ProcessError::Lifecycle(
                        "CDP input names an unavailable local route".to_owned(),
                    ));
                };
                if let Err(error) = binding.send_json_with_context(message, wire_context).await {
                    drain_before_owner_close = matches!(
                        &error,
                        BrokerError::Closed | BrokerError::Delivery(DeliveryError::Closed(_))
                    );
                    break Err(error.into());
                }
            }
            ClientWire::CloseCdp { route } => {
                if let Some(binding) = routes.remove(&route) {
                    binding.close().await;
                }
            }
        }
    };
    // Valid input may meet extension EOF with final owner receipts still queued.
    // ClientClosed and route-drop must follow that drain; local socket EOF and
    // malformed input still close the owner promptly.
    if drain_before_owner_close && !tasks.writer.is_finished() {
        let _ = tokio::time::timeout(IPC_SHUTDOWN_DRAIN_TIMEOUT, &mut tasks.writer).await;
    }
    control.close().await;
    drop(routes);
    tasks.control_forward.abort();
    tasks.writer.abort();
    result
}

#[cfg(test)]
mod tests {

    #[test]
    fn provider_names_accept_only_exact_registered_host_identities() {
        for (host, mode, selector, display) in [
            (MAKA_HOST_NAME, ExtensionAdapterMode::Maka, "maka", "Maka"),
            (
                CHATGPT_HOST_NAME,
                ExtensionAdapterMode::Chatgpt,
                "chatgpt",
                "ChatGPT",
            ),
        ] {
            assert_eq!(ExtensionAdapterMode::from_host_name(host), Some(mode));
            assert_eq!(mode.selector(), selector);
            assert_eq!(mode.display_name(), display);
        }
        for unsupported in ["maka", "chatgpt", "original", "opencli", "foreign.host"] {
            assert_eq!(ExtensionAdapterMode::from_host_name(unsupported), None);
        }
    }
    use super::super::extension_broker::BrokerCdpEvent;
    use super::*;

    #[test]
    fn local_wire_rejects_owner_generation_and_unknown_operations() {
        for value in [
            json!({"kind":"control","owner":"foreign","request":{"method":"inventory","id":1}}),
            json!({"kind":"cdp","route":1,"generation":"foreign","message":{"id":1,"method":"Runtime.evaluate"}}),
            json!({"kind":"closeOwner"}),
        ] {
            assert!(serde_json::from_value::<ClientWire>(value).is_err());
        }
    }

    #[test]
    fn claim_route_close_has_no_tab_or_owner_authority() {
        let request: ClientWire =
            serde_json::from_value(json!({"kind":"closeCdp","route":5})).unwrap();
        assert!(matches!(request, ClientWire::CloseCdp { route: 5 }));
        assert!(serde_json::from_value::<ClientWire>(
            json!({"kind":"closeCdp","route":5,"claim":"foreign","owner":"foreign"})
        )
        .is_err());
    }

    #[test]
    fn registration_configuration_never_invents_an_extension_id() {
        assert!(ExtensionProcessConfig::maka("", None).is_err());
        assert!(ExtensionProcessConfig::maka("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", None).is_ok());
    }

    #[test]
    fn installed_selection_uses_supported_adapter_identity_and_private_directory() {
        let extension = ExtensionOrigin::from_id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let config = |host, directory| {
            ExtensionProcessConfig::selected_adapter(
                AdapterRegistration::selected_adapter(host, extension.clone()).unwrap(),
                extension.clone(),
                directory,
            )
        };
        let directory = std::env::temp_dir().join("maka-selection-fixture");
        let original = ExtensionAdapterSelection::from_config(config(
            CHATGPT_HOST_NAME,
            Some(directory.clone()),
        ))
        .unwrap();
        assert_eq!(original.mode(), ExtensionAdapterMode::Chatgpt);
        assert_eq!(original.expected_extension_id(), extension.id());
        assert_eq!(original.runtime_directory(), directory);
        assert!(ExtensionAdapterSelection::from_config(config(CHATGPT_HOST_NAME, None)).is_err());
        assert!(ExtensionAdapterSelection::from_config(config(
            "unsupported.adapter",
            Some(directory),
        ))
        .is_err());
    }

    #[test]
    fn removed_custom_adapter_is_not_a_native_process_selection() {
        let extension = ExtensionOrigin::from_id("cccccccccccccccccccccccccccccccc").unwrap();
        let config = ExtensionProcessConfig::selected_adapter(
            AdapterRegistration::selected_adapter(
                "org.apache.maka.opencli_connector",
                extension.clone(),
            )
            .unwrap(),
            extension,
            Some(std::env::temp_dir().join("unsupported-custom-selection")),
        );
        assert!(matches!(
            ExtensionAdapterSelection::from_config(config),
            Err(ProcessError::Lifecycle(message)) if message == "installed adapter is unsupported"
        ));
    }

    #[test]
    fn ordinary_startup_is_not_a_native_registration_probe() {
        assert!(!extension_origin_candidate(None));
        assert!(!extension_origin_candidate(Some(std::ffi::OsStr::new(
            "--help"
        ))));
        assert!(extension_origin_candidate(Some(std::ffi::OsStr::new(
            "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"
        ))));
    }

    #[tokio::test]
    async fn ipc_routes_preserve_more_than_sixty_four_active_claims() {
        use super::super::extension_broker::{CheckedLocalPeer, ExtensionOutbound, LocalPrincipal};
        use std::{future::Future, io::Cursor, time::Duration};

        async fn bounded<T>(future: impl Future<Output = T>) -> T {
            tokio::time::timeout(Duration::from_secs(1), future)
                .await
                .expect("hermetic process channel operation must complete")
        }

        async fn extension_frame(
            frames: &mut mpsc::Receiver<ExtensionOutbound>,
            broker: &BrokerHandle,
        ) -> Value {
            let frame = bounded(frames.recv())
                .await
                .expect("actual extension request");
            let mut bytes = Vec::new();
            if let Some(report) = frame.write_to(&mut bytes).unwrap() {
                broker.write_report(report).await;
            }
            let mut input = Cursor::new(bytes);
            let body = extension_framing::read_frame(&mut input, Direction::HostToChrome)
                .unwrap()
                .expect("one written extension request");
            assert!(
                extension_framing::read_frame(&mut input, Direction::HostToChrome)
                    .unwrap()
                    .is_none()
            );
            serde_json::from_slice(&body).unwrap()
        }

        async fn local_frame(stream: &mut tokio::io::DuplexStream) -> Value {
            bounded(local_ipc::read_json(stream))
                .await
                .unwrap()
                .expect("actual local server response")
        }

        let origin = ExtensionOrigin::from_id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let principal = LocalPrincipal::UnixUid(123);
        let (broker, actor, mut extension) =
            ExtensionHostBroker::channels(origin, principal.clone());
        let generation = actor.generation().to_owned();
        let actor = tokio::spawn(actor.run());
        broker.extension_message(json!({"kind":"hello","protocol":1,"extensionId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","instanceId":"process-route-fixture","capabilities":{"metadata":true,"rawTabCdp":true,"nativeWindowProof":false}})).await.unwrap();
        assert_eq!(
            extension_frame(&mut extension, &broker).await["kind"],
            "bound"
        );
        let client = broker
            .admit_peer(CheckedLocalPeer::from_checked_principal(principal))
            .await
            .unwrap();
        let (mut wire, stream) = tokio::io::duplex(4096);
        let (_stop_send, stop) = watch::channel(false);
        let server = tokio::spawn(serve_connection(stream, client, broker.clone(), stop));
        let mut routes = Vec::new();
        // Each claim comes from the real attach/reply path. Keep every route
        // open while exercising the next one, including the 65th.
        for id in 1..=65_u64 {
            local_ipc::write_json(
                &mut wire,
                &json!({"kind":"control","request":{"method":"attach","id":id,"tabId":id}}),
            )
            .await
            .unwrap();
            let attach = extension_frame(&mut extension, &broker).await;
            assert_eq!(attach["method"], "attach");
            assert_eq!(attach["params"]["tabId"], id);
            let claim = format!("process-claim-{id}");
            broker.extension_message(json!({"kind":"response","protocol":1,"generation":generation,"id":attach["id"],"result":{"claim":claim,"tabId":id,"targetId":format!("opaque-target-{id}")}})).await.unwrap();
            let attached = local_frame(&mut wire).await;
            assert_eq!(attached["kind"], "controlEvent");
            assert_eq!(attached["event"]["kind"], "reply");
            assert_eq!(attached["event"]["data"]["id"], id);
            assert_eq!(attached["event"]["data"]["outcome"]["kind"], "result");
            assert_eq!(attached["event"]["data"]["outcome"]["data"]["claim"], claim);
            local_ipc::write_json(&mut wire, &json!({"kind":"openCdp","id":id,"claim":claim}))
                .await
                .unwrap();
            let opened = local_frame(&mut wire).await;
            assert_eq!(opened["kind"], "cdpOpened", "open attempt {id}: {opened}");
            assert_eq!(opened["id"], id);
            let route = opened["route"].as_u64().expect("issued route identity");
            assert!(routes.iter().all(|(existing, _)| *existing != route));
            routes.push((route, claim));
        }
        // Reusing the same inner CDP id on every still-open route must retain
        // its exact physical claim and recipient, including the first and last.
        for (route, claim) in &routes {
            local_ipc::write_json(
                &mut wire,
                &json!({"kind":"cdp","route":route,"message":{"id":1,"method":"Runtime.evaluate","params":{"expression":"1"}}}),
            )
            .await
            .unwrap();
            let command = extension_frame(&mut extension, &broker).await;
            assert_eq!(command["method"], "cdp");
            assert_eq!(command["params"]["claim"], *claim);
            assert_eq!(command["params"]["method"], "Runtime.evaluate");
            broker.extension_message(json!({"kind":"response","protocol":1,"generation":generation,"id":command["id"],"result":{"result":{"recipient":claim}}})).await.unwrap();
            let response = local_frame(&mut wire).await;
            assert_eq!(response["kind"], "controlEvent");
            assert_eq!(response["event"]["kind"], "cdpMessage");
            let delivered = &response["event"]["data"];
            assert_eq!(delivered["route"], *route);
            assert_eq!(delivered["claim"], *claim);
            assert_eq!(delivered["event"]["kind"], "chromeMessage");
            assert_eq!(delivered["event"]["data"]["id"], 1);
            assert_eq!(delivered["event"]["data"]["result"]["recipient"], *claim);
        }
        let (retired_route, retired_claim) = &routes[0];
        local_ipc::write_json(
            &mut wire,
            &json!({"kind":"cdp","route":retired_route,"message":{"id":2,"method":"Runtime.evaluate","params":{"expression":"2"}}}),
        ).await.unwrap();
        let last_command = extension_frame(&mut extension, &broker).await;
        broker.extension_message(json!({"kind":"event","protocol":1,"generation":generation,"owner":last_command["owner"],"claim":retired_claim,"method":"Runtime.consoleAPICalled","params":{"fixture":"before-close"}})).await.unwrap();
        broker.extension_message(json!({"kind":"response","protocol":1,"generation":generation,"id":last_command["id"],"result":{"result":{"beforeClose":true}}})).await.unwrap();
        local_ipc::write_json(
            &mut wire,
            &json!({"kind":"control","request":{"method":"detach","id":1000,"claim":retired_claim}}),
        ).await.unwrap();
        let detach = extension_frame(&mut extension, &broker).await;
        assert_eq!(detach["method"], "detach");
        broker.extension_message(json!({"kind":"response","protocol":1,"generation":generation,"id":detach["id"],"result":{"detached":true,"proof":"detach_ack"}})).await.unwrap();
        // No local output has been consumed since the real event and reply.
        // Both must precede route closure even if the socket writer is delayed.
        let event = local_frame(&mut wire).await;
        assert_eq!(event["event"]["kind"], "cdpMessage");
        assert_eq!(
            event["event"]["data"]["event"]["data"]["method"],
            "Runtime.consoleAPICalled"
        );
        let reply = local_frame(&mut wire).await;
        assert_eq!(reply["event"]["kind"], "cdpMessage");
        assert_eq!(reply["event"]["data"]["event"]["data"]["id"], 2);
        assert_eq!(
            reply["event"]["data"]["event"]["data"]["result"]["beforeClose"],
            true
        );
        let ended = local_frame(&mut wire).await;
        assert_eq!(ended["event"]["kind"], "cdpRouteClosed");
        assert_eq!(ended["event"]["data"]["route"], *retired_route);
        let cleanup = local_frame(&mut wire).await;
        assert_eq!(cleanup["event"]["kind"], "reply");
        assert_eq!(cleanup["event"]["data"]["id"], 1000);
        assert_eq!(cleanup["event"]["data"]["outcome"]["kind"], "result");
        // A request racing client-side route retirement is known unsent and
        // follows the same broker FIFO; it cannot close other owner routes.
        local_ipc::write_json(
            &mut wire,
            &json!({"kind":"cdp","route":retired_route,"message":{"id":3,"method":"Runtime.evaluate","params":{"expression":"3"}}}),
        ).await.unwrap();
        let refused = local_frame(&mut wire).await;
        assert_eq!(refused["event"]["kind"], "cdpMessage");
        assert_eq!(refused["event"]["data"]["route"], *retired_route);
        assert_eq!(refused["event"]["data"]["event"]["kind"], "localRejected");
        assert_eq!(refused["event"]["data"]["event"]["data"]["id"], 3);
        assert_eq!(
            refused["event"]["data"]["event"]["data"]["code"],
            "not_dispatched"
        );
        assert!(matches!(
            extension.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        let (live_route, live_claim) = routes.last().unwrap();
        local_ipc::write_json(
            &mut wire,
            &json!({"kind":"cdp","route":live_route,"message":{"id":2,"method":"Runtime.evaluate","params":{"expression":"2"}}}),
        ).await.unwrap();
        let live_command = extension_frame(&mut extension, &broker).await;
        assert_eq!(live_command["params"]["claim"], *live_claim);
        broker.extension_message(json!({"kind":"response","protocol":1,"generation":generation,"id":live_command["id"],"result":{"result":{"ownerStillLive":true}}})).await.unwrap();
        let live = local_frame(&mut wire).await;
        assert_eq!(live["event"]["data"]["route"], *live_route);
        assert_eq!(
            live["event"]["data"]["event"]["data"]["result"]["ownerStillLive"],
            true
        );
        local_ipc::write_json(
            &mut wire,
            &json!({"kind":"openCdp","id":66,"claim":"foreign-unissued-claim"}),
        )
        .await
        .unwrap();
        let refused = local_frame(&mut wire).await;
        assert_eq!(refused["kind"], "cdpOpenRejected");
        assert_eq!(refused["code"], "claim_unavailable");
        drop(wire);
        bounded(server).await.unwrap().unwrap();
        broker.extension_eof("process route fixture ended").await;
        bounded(actor).await.unwrap();
    }

    #[tokio::test]
    async fn queued_cdp_receipt_keeps_budget_through_owner_fifo_projection() {
        let budget = super::super::broker_delivery::ByteBudget::new();
        let initial = budget.available_bytes();
        let event = ControlEvent::CdpMessage {
            route: 9,
            claim: "actual-issued-token-fixture".to_owned(),
            event: BrokerCdpEvent::ChromeMessage(json!({"id":3,"result":{"text":"receipt"}})),
            wire_context: None,
        };
        let charge = budget.charge(&event).await.unwrap();
        let message = ServerOutbound::Control(Queued::new(event, Some(charge)));
        let value = message.json().unwrap();
        assert_eq!(value["event"]["kind"], "cdpMessage");
        assert_eq!(value["event"]["data"]["route"], 9);
        assert_eq!(value["event"]["data"]["event"]["data"]["id"], 3);
        assert!(
            budget.available_bytes() < initial,
            "serialization must retain queued byte ownership"
        );
        drop(value);
        drop(message);
        assert_eq!(budget.available_bytes(), initial);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn extension_eof_flushes_final_receipt_with_stop_and_inflight_valid_input() {
        use super::super::extension_broker::{CheckedLocalPeer, LocalPrincipal};
        use std::{
            pin::Pin,
            task::{Context, Poll},
            time::Duration,
        };
        use tokio::io::{AsyncRead, ReadBuf};

        struct SignalAfterFrameRead<R> {
            inner: R,
            remaining: usize,
            consumed: Option<oneshot::Sender<()>>,
        }
        impl<R: AsyncRead + Unpin> AsyncRead for SignalAfterFrameRead<R> {
            fn poll_read(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buffer: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                let this = self.get_mut();
                let before = buffer.filled().len();
                let result = Pin::new(&mut this.inner).poll_read(cx, buffer);
                if let Poll::Ready(Ok(())) = &result {
                    let received = buffer.filled().len() - before;
                    if this.remaining > 0 {
                        assert!(received <= this.remaining, "read crossed the fixture frame");
                        this.remaining -= received;
                        if this.remaining == 0 {
                            let _ = this.consumed.take().unwrap().send(());
                        }
                    }
                }
                result
            }
        }
        for in_flight_input in [false, true] {
            let origin = ExtensionOrigin::from_id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
            let principal = LocalPrincipal::UnixUid(123);
            let (broker, actor, _native) = ExtensionHostBroker::channels(origin, principal.clone());
            let actor = tokio::spawn(actor.run());
            broker.extension_message(json!({"kind":"hello","protocol":1,"extensionId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","instanceId":"eof-fixture","capabilities":{"metadata":true,"rawTabCdp":true,"nativeWindowProof":false}})).await.unwrap();
            let client = broker
                .admit_peer(CheckedLocalPeer::from_checked_principal(principal))
                .await
                .unwrap();
            // Smaller than the final frame: writer blocks until our read.
            let (mut wire, stream) = tokio::io::duplex(64);
            let request = json!({"kind":"control",
                "request":{"method":"inventory","id":7},
                "wireContext":{"hostSessionId":"550e8400-e29b-41d4-a716-446655440000",
                    "hostTurnId":"inflight-native-eof-".repeat(32)}});
            let frame_bytes = std::mem::size_of::<u32>()
                + extension_framing::encode_json(&request, Direction::ChromeToHost)
                    .unwrap()
                    .len();
            let (consumed, request_consumed) = oneshot::channel();
            let (read, write) = tokio::io::split(stream);
            let stream = tokio::io::join(
                SignalAfterFrameRead {
                    inner: read,
                    remaining: frame_bytes,
                    consumed: Some(consumed),
                },
                write,
            );
            let (stop_send, stop) = watch::channel(false);
            let (finished, observed) = oneshot::channel();
            let mut clients = JoinSet::new();
            let server_broker = broker.clone();
            clients.spawn(async move {
                let result = serve_connection(stream, client, server_broker, stop).await;
                let known_closed = matches!(
                    &result,
                    Err(ProcessError::Broker(BrokerError::Closed))
                        | Err(ProcessError::Broker(BrokerError::Delivery(
                            DeliveryError::Closed(_)
                        )))
                );
                let _ = finished.send(known_closed);
                result
            });
            broker.extension_eof("actual extension EOF fixture").await;
            assert!(
                broker.identity().await.is_err(),
                "generation closure barrier"
            );
            if in_flight_input {
                local_ipc::write_json(&mut wire, &request).await.unwrap();
                // A completed write may leave the final bytes in the duplex
                // buffer. Wait for the server's actual final body read. On
                // this current-thread runtime, parsing and the already-Closed
                // sender check then finish in that same poll before we can stop.
                tokio::time::timeout(Duration::from_secs(1), request_consumed)
                    .await
                    .unwrap()
                    .expect("server consumed the complete valid request frame");
            }
            stop_send.send_replace(true);
            let draining = tokio::spawn(async move { drain_connections(&mut clients).await });
            let frame =
                tokio::time::timeout(Duration::from_secs(1), local_ipc::read_json(&mut wire))
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            assert_eq!(frame["kind"], "controlEvent");
            assert_eq!(frame["event"]["kind"], "generationClosed");
            assert_eq!(
                frame["event"]["data"]["reason"],
                "actual extension EOF fixture"
            );
            assert!(
                tokio::time::timeout(Duration::from_secs(1), local_ipc::read_json(&mut wire))
                    .await
                    .unwrap()
                    .unwrap()
                    .is_none()
            );
            tokio::time::timeout(Duration::from_secs(1), draining)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), observed)
                    .await
                    .unwrap()
                    .unwrap(),
                in_flight_input,
                "exercise handler-error separately from supervisor-stop branch"
            );
            tokio::time::timeout(Duration::from_secs(1), actor)
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[test]
    fn transport_failure_event_keeps_distinct_provenance() {
        let value = serde_json::to_value(BrokerCdpEvent::TransportFailure(
            "extension pipe ended".to_owned(),
        ))
        .unwrap();
        assert_eq!(
            value,
            json!({"kind":"transportFailure","data":"extension pipe ended"})
        );
        assert!(value.get("error").is_none());
    }
}
