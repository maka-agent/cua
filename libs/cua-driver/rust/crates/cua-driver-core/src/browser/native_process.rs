// SPDX-License-Identifier: MIT

//! Finite Chrome-native-host process entry and broker/IPC composition.
//!
//! The embedding executable calls bootstrap before application logging and
//! immediately returns its ExitCode when selected. Rust byte-oriented stdin and
//! stdout carry only native frames; no text console or line-ending adapter is used.
//! The process ends with this Chrome native port, without starting a daemon.

use super::{
    broker_delivery::Queued,
    local_ipc::{self, IpcError, LocalStream, NativeEndpointIdentity, PublishedEndpoint},
    native_broker::{
        BrokerCdpEvent, BrokerError, BrokerHandle, ClientConnection, ControlEvent, ControlRequest,
        NativeHostBroker, RouteSender,
    },
    native_framing::{self, Direction, FrameError},
    native_host::{
        self, AdapterRegistration, ExtensionOrigin, HostError, InstalledHostConfig,
        NativeInvocation, Platform, OWN_HOST_NAME,
    },
    native_wire::NativeWireContext,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    io,
    path::PathBuf,
    process::ExitCode,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::{JoinHandle, JoinSet},
};

const MAX_CONNECTIONS: usize = 32;
const MAX_ROUTES_PER_CONNECTION: usize = 64;

pub(crate) const ORIGINAL_HOST_NAME: &str = "com.openai.codexextension";

/// A supported adapter selected by an exact private installation sidecar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeAdapterMode {
    Own,
    Original,
}

/// Selection cannot be constructed from tool/model JSON or an ambient origin.
/// It retains the same installed configuration that native startup verifies.
pub struct NativeAdapterSelection {
    config: NativeProcessConfig,
    mode: NativeAdapterMode,
}

impl std::fmt::Debug for NativeAdapterSelection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeAdapterSelection")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("installed native browser selection refused: {message}")]
pub struct NativeAdapterSelectionError {
    message: String,
    missing: bool,
}

impl NativeAdapterSelection {
    /// Load the exact sidecar adjacent to this canonical installed executable.
    ///
    /// The file ownership, ACL/mode, executable and selected adapter identity are
    /// checked by the same parser used for native startup. No search or fallback
    /// selects a foreign extension. No file or browser configuration is written.
    pub fn load_installed() -> Result<Self, NativeAdapterSelectionError> {
        let result = std::env::current_exe()
            .map_err(ProcessError::Io)
            .and_then(|path| installed_config(&path))
            .and_then(Self::from_config);
        result.map_err(|error| NativeAdapterSelectionError {
            missing: matches!(&error, ProcessError::Ipc(IpcError::MissingInstallationFile)),
            message: error.to_string(),
        })
    }

    fn from_config(config: NativeProcessConfig) -> Result<Self, ProcessError> {
        let mode = match config.registration.host_name() {
            OWN_HOST_NAME => NativeAdapterMode::Own,
            ORIGINAL_HOST_NAME => NativeAdapterMode::Original,
            _ => {
                return Err(ProcessError::Lifecycle(
                    "installed adapter is unsupported".to_owned(),
                ));
            }
        };
        if config.runtime_directory.is_none() {
            return Err(ProcessError::Lifecycle(
                "installed adapter lacks its private runtime directory".to_owned(),
            ));
        }
        Ok(Self { config, mode })
    }

    pub fn mode(&self) -> NativeAdapterMode {
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

impl NativeAdapterSelectionError {
    /// Only absence from the verified sidecar file-open is optional setup.
    /// Invalid metadata, changed paths and malformed configuration remain errors.
    pub fn is_missing(&self) -> bool {
        self.missing
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProcessError {
    #[error("native host I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("native host frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("native host JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("native host registration failed: {0}")]
    Host(#[from] HostError),
    #[error("native host IPC failed: {0}")]
    Ipc(#[from] IpcError),
    #[error("native host broker failed: {0}")]
    Broker(#[from] BrokerError),
    #[error("native adapter process failed: {0}")]
    Adapter(#[from] super::native_adapter_process::AdapterProcessError),
    #[error("native host lifecycle failed: {0}")]
    Lifecycle(String),
}

/// Supplied by own package configuration, never by model/tool arguments.
pub(crate) struct NativeProcessConfig {
    registration: AdapterRegistration,
    expected_extension: ExtensionOrigin,
    runtime_directory: Option<PathBuf>,
}

impl NativeProcessConfig {
    #[cfg(test)]
    pub(crate) fn own(
        extension_id: &str,
        runtime_directory: Option<PathBuf>,
    ) -> Result<Self, HostError> {
        let expected_extension = ExtensionOrigin::from_id(extension_id)?;
        Ok(Self {
            registration: AdapterRegistration::own(expected_extension.clone()),
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

fn native_origin_candidate(argument: Option<&std::ffi::OsStr>) -> bool {
    argument
        .and_then(|argument| argument.to_str())
        .is_some_and(|argument| argument.starts_with("chrome-extension://"))
}

fn installed_config(
    current_executable: &std::path::Path,
) -> Result<NativeProcessConfig, ProcessError> {
    let current = std::fs::canonicalize(current_executable)?;
    let sidecar = native_host::installed_sidecar_path(&current)?;
    let bytes = local_ipc::load_private_installation_config(&sidecar)?;
    let config: InstalledHostConfig = serde_json::from_slice(&bytes)?;
    if config.protocol != 1
        || !config.private_state_directory.is_absolute()
        || std::fs::canonicalize(&config.executable)? != current
    {
        return Err(ProcessError::Lifecycle(
            "installed sidecar disagrees with executable or private state path".to_owned(),
        ));
    }
    let extension = ExtensionOrigin::from_id(&config.expected_extension_id)?;
    let registration = if config.adapter == OWN_HOST_NAME {
        AdapterRegistration::own(extension.clone())
    } else {
        AdapterRegistration::selected_adapter(&config.adapter, extension.clone())?
    };
    Ok(NativeProcessConfig::selected_adapter(
        registration,
        extension,
        Some(config.private_state_directory),
    ))
}

/// Binary startup hook: ordinary CLI invocations do not probe installation data.
///
/// A native-origin candidate requires an explicit, privately owned sidecar from
/// connector setup. Its ID is never inferred from argv or a browser profile.
pub fn bootstrap_installed() -> Option<ExitCode> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if let Some(exit) = super::native_install::bootstrap_setup(&arguments) {
        return Some(exit);
    }
    if !native_origin_candidate(std::env::args_os().nth(1).as_deref()) {
        return None;
    }
    let config = std::env::current_exe()
        .map_err(ProcessError::Io)
        .and_then(|path| installed_config(&path));
    match config {
        Ok(config) => match bootstrap(config) {
            Some(exit) => Some(exit),
            None => {
                eprintln!("Maka native host refused an origin outside its explicit registration");
                Some(ExitCode::FAILURE)
            }
        },
        Err(error) => {
            eprintln!("Maka native host requires explicit connector setup: {error}");
            Some(ExitCode::FAILURE)
        }
    }
}

/// Return `None` on the ordinary app path, before touching runtime files or stdio.
pub(crate) fn bootstrap(config: NativeProcessConfig) -> Option<ExitCode> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let platform = match std::env::consts::OS {
        "linux" => Platform::Linux,
        "macos" => Platform::Macos,
        "windows" => Platform::Windows,
        _ => {
            eprintln!("Maka native host does not support this platform");
            return Some(ExitCode::FAILURE);
        }
    };
    let invocation = match config.registration.invocation(&arguments, platform) {
        Ok(None) => return None,
        Ok(Some(invocation)) => invocation,
        Err(error) => {
            eprintln!("Maka native host refused invocation: {error}");
            return Some(ExitCode::FAILURE);
        }
    };
    let result = if config.registration.host_name() == OWN_HOST_NAME {
        run_native_host(
            invocation,
            config.expected_extension,
            config.runtime_directory,
        )
    } else {
        NativeAdapterSelection::from_config(config)
            .and_then(|selection| run_adapted_native_host(invocation, selection))
    };
    Some(match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Maka native host ended: {error}");
            ExitCode::FAILURE
        }
    })
}

/// The reviewed foreign protocol starts itself (getInfo), then supplies the
/// same broker's normalized actual hello. No Own hello/bound frame is imposed.
fn run_adapted_native_host(
    invocation: NativeInvocation,
    selection: NativeAdapterSelection,
) -> Result<(), ProcessError> {
    let principal = local_ipc::current_user_principal()?;
    let directory = selection.runtime_directory().to_owned();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let (handle,broker,outgoing)=NativeHostBroker::channels(selection.config.expected_extension.clone(),principal);
        let adapter=super::native_adapter_factory::for_installed(&selection,broker.generation().to_owned())
            .map_err(|error|ProcessError::Lifecycle(error.to_string()))?;
        let mut broker_task=tokio::spawn(broker.run());
        let (ready_send,ready)=oneshot::channel();
        let actor_handle=handle.clone();
        let mut actor_task=tokio::spawn(super::native_adapter_process::run(adapter,actor_handle,outgoing,ready_send));
        let readiness=tokio::select! {
            _=tokio::time::sleep(std::time::Duration::from_secs(30))=>Err(ProcessError::Lifecycle("native adapter startup did not complete within its bounded handshake interval".to_owned())),
            ready=ready=>ready.map_err(|_|ProcessError::Lifecycle("native adapter startup acknowledgement was lost".to_owned()))?.map_err(ProcessError::Lifecycle),
            result=&mut actor_task=>Err(ProcessError::Lifecycle(format!("native adapter ended during startup: {result:?}"))),
            _=&mut broker_task=>Err(ProcessError::Lifecycle("native broker ended before adapter startup".to_owned())),
        };
        if let Err(error)=readiness {
            handle.native_eof("native adapter startup failed").await;
            if !broker_task.is_finished(){let _=broker_task.await;}
            actor_task.abort();return Err(error);
        }
        let actual=handle.identity().await?;
        let identity=NativeEndpointIdentity{adapter:invocation.host_name,extension_id:actual.extension_id,instance_id:actual.instance_id,generation:actual.generation,capabilities:actual.capabilities,host_pid:std::process::id()};
        let endpoint=match PublishedEndpoint::publish(&directory,identity).await {
            Ok(endpoint)=>endpoint,
            Err(error)=>{handle.native_eof("private adapter endpoint publication failed").await;actor_task.abort();let _=broker_task.await;return Err(error.into());}
        };
        let (stop,stop_receive)=watch::channel(false);
        let mut server_task=tokio::spawn(serve_until(endpoint,handle.clone(),stop_receive));
        let result=tokio::select! {
            result=&mut actor_task=>match result {Ok(result)=>result.map_err(ProcessError::from),Err(error)=>Err(ProcessError::Lifecycle(format!("native adapter actor ended: {error}")))},
            _=&mut broker_task=>Ok(()),
            result=&mut server_task=>match result {Ok(result)=>result,Err(error)=>Err(ProcessError::Lifecycle(format!("private adapter server ended: {error}")))},
        };
        stop.send_replace(true);
        handle.native_eof("native adapter process lifetime ended").await;
        if !server_task.is_finished(){let _=server_task.await;}
        if !broker_task.is_finished(){let _=broker_task.await;}
        if !actor_task.is_finished(){actor_task.abort();}
        result
    })
}

fn read_initial_hello(expected: &ExtensionOrigin) -> Result<Value, ProcessError> {
    let input = std::io::stdin();
    let payload = native_framing::read_frame(&mut input.lock(), Direction::ChromeToHost)?
        .ok_or_else(|| ProcessError::Lifecycle("Chrome closed before hello".to_owned()))?;
    let hello: Value = serde_json::from_slice(&payload)?;
    if hello["kind"] != "hello" || hello["protocol"] != 1 {
        return Err(ProcessError::Lifecycle(
            "first native message is not protocol1 hello".to_owned(),
        ));
    }
    expected.validate_hello_id(hello["extensionId"].as_str().unwrap_or(""))?;
    Ok(hello)
}

/// This is the selected executable mode; the caller must exit after it returns.
fn run_native_host(
    invocation: NativeInvocation,
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
    runtime.block_on(async move {
        let (handle,broker,mut outgoing)=NativeHostBroker::channels(expected,principal);
        let mut broker_task=tokio::spawn(broker.run());
        let (report_send,mut reports)=mpsc::channel(128);
        let (failure_send,mut failures)=watch::channel::<Option<String>>(None);
        let (ready_send,ready)=oneshot::channel::<Result<(),String>>();
        let writer_failure=failure_send.clone();
        // These are the binary adapter's stdio threads, not another process or
        // library-owned executor. They never perform desktop operations.
        std::thread::Builder::new().name("maka-native-writer".to_owned()).spawn(move || {
            let output=std::io::stdout(); let mut output=output.lock(); let mut ready_send=Some(ready_send);
            while let Some(frame)=outgoing.blocking_recv() {
                match frame.write_to(&mut output) {
                    Ok(report)=>{
                        if let Some(ready)=ready_send.take() { let _=ready.send(Ok(())); }
                        if let Some(report)=report {
                            // Never block this serial writer on the actor's input
                            // queue: input/output backpressure could otherwise cycle.
                            if report_send.try_send(report).is_err() { writer_failure.send_replace(Some("native writer report budget exhausted".to_owned())); return; }
                        }
                    }
                    Err(error)=>{
                        let reason=error.to_string(); if let Some(ready)=ready_send.take() { let _=ready.send(Err(reason.clone())); }
                        writer_failure.send_replace(Some(reason)); return;
                    }
                }
            }
            if let Some(ready)=ready_send.take() { let _=ready.send(Err("native writer ended before bound".to_owned())); }
        })?;
        let reporter_handle=handle.clone();
        let report_task=tokio::spawn(async move { while let Some(report)=reports.recv().await { reporter_handle.write_report(report).await; } });
        handle.native_message(hello).await?;
        let actual=handle.identity().await?;
        match ready.await { Ok(Ok(()))=>{},Ok(Err(reason))=>{ handle.native_eof(&reason).await; let _=broker_task.await; report_task.abort(); return Err(ProcessError::Lifecycle(reason)); },Err(_)=>{ handle.native_eof("native writer readiness was lost").await; let _=broker_task.await; report_task.abort(); return Err(ProcessError::Lifecycle("native writer readiness was lost".to_owned())); } }
        let identity=NativeEndpointIdentity { adapter:invocation.host_name,extension_id:actual.extension_id,instance_id:actual.instance_id,generation:actual.generation,capabilities:actual.capabilities,host_pid:std::process::id() };
        let endpoint=match PublishedEndpoint::publish(&directory,identity).await {
            Ok(endpoint)=>endpoint,
            Err(error)=>{ handle.native_eof("private endpoint publication failed").await; let _=broker_task.await; report_task.abort(); return Err(error.into()); }
        };
        let reader_runtime=tokio::runtime::Handle::current(); let reader_handle=handle.clone(); let reader_failure=failure_send.clone();
        let reader_start=std::thread::Builder::new().name("maka-native-reader".to_owned()).spawn(move || {
            let input=std::io::stdin(); let mut input=input.lock();
            loop {
                let value=match native_framing::read_frame(&mut input,Direction::ChromeToHost) {
                    Ok(Some(bytes))=>match serde_json::from_slice(&bytes) { Ok(value)=>value,Err(error)=>{ reader_failure.send_replace(Some(error.to_string())); return; } },
                    Ok(None)=>{ reader_runtime.block_on(reader_handle.native_eof("Chrome native stdin EOF")); return; },
                    Err(error)=>{ reader_failure.send_replace(Some(error.to_string())); return; }
                };
                if reader_runtime.block_on(reader_handle.native_message(value)).is_err() { return; }
            }
        });
        if let Err(error)=reader_start {
            let _=endpoint.cleanup(); handle.native_eof("native reader thread could not start").await;
            let _=broker_task.await; report_task.abort(); return Err(error.into());
        }
        let (stop,stop_receive)=watch::channel(false);
        let server_handle=handle.clone();
        let mut server_task=tokio::spawn(serve_until(endpoint,server_handle,stop_receive));
        let outcome=tokio::select! {
            result=&mut broker_task=>{ stop.send_replace(true); match result { Ok(())=>Ok(()),Err(error)=>Err(ProcessError::Lifecycle(format!("native broker task ended: {error}"))) } }
            result=&mut server_task=>{ handle.native_eof("local IPC server ended").await; match result { Ok(result)=>result,Err(error)=>Err(ProcessError::Lifecycle(format!("local IPC server task ended: {error}"))) } }
            _=wait_failure(&mut failures)=>{ let reason=failures.borrow().clone().unwrap_or_else(||"native I/O failure signal ended".to_owned()); stop.send_replace(true); handle.native_eof(&reason).await; Err(ProcessError::Lifecycle(reason)) }
        };
        stop.send_replace(true);
        if !server_task.is_finished() { let _=server_task.await; }
        if !broker_task.is_finished() { let _=broker_task.await; }
        report_task.abort();
        outcome
    })
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
    clients.abort_all();
    while clients.join_next().await.is_some() {}
    let cleanup = endpoint.cleanup();
    outcome?;
    cleanup?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum ClientWire {
    Control {
        request: ControlRequest,
        #[serde(rename = "wireContext", default)]
        wire_context: Option<NativeWireContext>,
    },
    OpenCdp {
        id: u64,
        claim: String,
    },
    Cdp {
        route: u64,
        message: Value,
        #[serde(rename = "wireContext", default)]
        wire_context: Option<NativeWireContext>,
    },
    CloseCdp {
        route: u64,
    },
}

struct RouteBinding {
    sender: RouteSender,
    live: Arc<AtomicBool>,
}

enum ServerOutbound {
    Plain(Value),
    Control(Queued<ControlEvent>),
    Cdp {
        route: u64,
        claim: String,
        live: Arc<AtomicBool>,
        event: Queued<BrokerCdpEvent>,
    },
}

impl ServerOutbound {
    fn json(&self) -> Value {
        match self {
            Self::Plain(value) => value.clone(),
            Self::Control(event) => json!({"kind":"controlEvent","event":event}),
            Self::Cdp {
                route,
                claim,
                live,
                event,
            } => {
                let id = match event.event() {
                    BrokerCdpEvent::ChromeMessage(value) => value["id"].as_u64(),
                    BrokerCdpEvent::LocalRejected { id, .. } => Some(*id),
                    BrokerCdpEvent::TransportFailure(_) => None,
                };
                if !live.load(Ordering::SeqCst) {
                    if let Some(id) = id {
                        // The same Queued permit remains held by self through the
                        // final socket write, including this orphan projection.
                        return json!({"kind":"controlEvent","event":{"kind":"orphanCdpCompletion","data":{"route":route,"claim":claim,"id":id,"event":event}}});
                    }
                }
                json!({"kind":"cdpEvent","route":route,"event":event})
            }
        }
    }
}

struct ConnectionTasks {
    writer: JoinHandle<Result<(), IpcError>>,
    control_forward: JoinHandle<()>,
    forwarders: JoinSet<()>,
    stop: watch::Receiver<bool>,
}

impl ConnectionTasks {
    async fn next_frame<R: tokio::io::AsyncRead + Unpin>(
        &mut self,
        input: &mut R,
    ) -> Result<Option<Value>, ProcessError> {
        // Keep this exact parser future alive across nonterminal completions.
        // There is no extra queue of uncharged decoded client payloads.
        let read = local_ipc::read_json(input);
        tokio::pin!(read);
        loop {
            tokio::select! {
                biased;
                _=wait_stop(&mut self.stop)=>return Ok(None),
                _=&mut self.control_forward=>return Ok(None),
                result=&mut self.writer=>return match result { Ok(Ok(()))=>Ok(None),Ok(Err(error))=>Err(error.into()),Err(error)=>Err(ProcessError::Lifecycle(format!("IPC writer ended: {error}"))) },
                Some(_)=self.forwarders.join_next(),if !self.forwarders.is_empty()=>{},
                value=&mut read=>return value.map_err(Into::into),
            }
        }
    }
}

async fn serve_connection(
    stream: LocalStream,
    connection: ClientConnection,
    broker: BrokerHandle,
    stop: watch::Receiver<bool>,
) -> Result<(), ProcessError> {
    let ClientConnection {
        sender: control,
        events: mut controls,
    } = connection;
    let (mut input, mut output) = tokio::io::split(stream);
    let (send, mut messages) = mpsc::channel::<ServerOutbound>(8);
    let writer_progress = broker.clone();
    let writer = tokio::spawn(async move {
        while let Some(message) = messages.recv().await {
            let value = message.json();
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
    });
    let mut routes: HashMap<u64, RouteBinding> = HashMap::new();
    let mut tasks = ConnectionTasks {
        writer,
        control_forward,
        forwarders: JoinSet::new(),
        stop,
    };
    let mut open_high_water = 0_u64;
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
                    break Err(error.into());
                }
            }
            ClientWire::OpenCdp { id, claim } => {
                if id == 0 || id <= open_high_water {
                    let _=send.send(ServerOutbound::Plain(json!({"kind":"cdpOpenRejected","id":id,"code":"duplicate_local_id","message":"openCdp IDs cannot be replayed"}))).await;
                    continue;
                }
                open_high_water = id;
                if routes.len() >= MAX_ROUTES_PER_CONNECTION {
                    let _=send.send(ServerOutbound::Plain(json!({"kind":"cdpOpenRejected","id":id,"code":"route_budget","message":"IPC route budget exhausted"}))).await;
                    continue;
                }
                match control.open_cdp_route(&claim).await {
                            Ok(route)=>{
                                let id_route=route.sender.wire_id();
                                if send.send(ServerOutbound::Plain(json!({"kind":"cdpOpened","id":id,"route":id_route}))).await.is_err() { break Ok(()); }
                                // Open acknowledgement precedes buffered events, so
                                // the runtime has installed this route when events arrive.
                                let route_output=send.clone(); let mut events=route.events;
                                let route_progress=broker.clone();
                                let live=Arc::new(AtomicBool::new(true)); let delivery_live=live.clone();
                                tasks.forwarders.spawn(async move { while let Some(event)=events.recv().await { route_progress.delivery_progress(); if route_output.send(ServerOutbound::Cdp{route:id_route,claim:claim.clone(),live:delivery_live.clone(),event}).await.is_err() { return; } } });
                                routes.insert(id_route,RouteBinding{sender:route.sender,live});
                            }
                            Err(error)=>{ if send.send(ServerOutbound::Plain(json!({"kind":"cdpOpenRejected","id":id,"code":"claim_unavailable","message":error.to_string()}))).await.is_err() { break Ok(()); } }
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
                if let Err(error) = binding
                    .sender
                    .send_json_with_context(message, wire_context)
                    .await
                {
                    break Err(error.into());
                }
            }
            ClientWire::CloseCdp { route } => {
                if let Some(binding) = routes.remove(&route) {
                    binding.live.store(false, Ordering::SeqCst);
                    binding.sender.close().await;
                }
            }
        }
    };
    // Local EOF ends this owner, not the shared native host or another owner.
    control.close().await;
    for (_, binding) in routes {
        binding.live.store(false, Ordering::SeqCst);
    }
    tasks.forwarders.abort_all();
    tasks.control_forward.abort();
    tasks.writer.abort();
    result
}

#[cfg(test)]
mod tests {
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
        assert!(NativeProcessConfig::own("", None).is_err());
        assert!(NativeProcessConfig::own("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", None).is_ok());
    }

    #[test]
    fn installed_selection_uses_supported_adapter_identity_and_private_directory() {
        let extension = ExtensionOrigin::from_id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let config = |host, directory| {
            NativeProcessConfig::selected_adapter(
                AdapterRegistration::selected_adapter(host, extension.clone()).unwrap(),
                extension.clone(),
                directory,
            )
        };
        let directory = std::env::temp_dir().join("maka-selection-fixture");
        let original = NativeAdapterSelection::from_config(config(
            ORIGINAL_HOST_NAME,
            Some(directory.clone()),
        ))
        .unwrap();
        assert_eq!(original.mode(), NativeAdapterMode::Original);
        assert_eq!(original.expected_extension_id(), extension.id());
        assert_eq!(original.runtime_directory(), directory);
        assert!(NativeAdapterSelection::from_config(config(ORIGINAL_HOST_NAME, None)).is_err());
        assert!(NativeAdapterSelection::from_config(config(
            "unsupported.adapter",
            Some(directory),
        ))
        .is_err());
    }

    #[test]
    fn ordinary_startup_is_not_a_native_registration_probe() {
        assert!(!native_origin_candidate(None));
        assert!(!native_origin_candidate(Some(std::ffi::OsStr::new(
            "--help"
        ))));
        assert!(native_origin_candidate(Some(std::ffi::OsStr::new(
            "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"
        ))));
    }

    #[tokio::test]
    async fn queued_receipt_keeps_budget_through_orphan_projection() {
        let budget = super::super::broker_delivery::ByteBudget::new();
        let initial = budget.available_bytes();
        let event = BrokerCdpEvent::ChromeMessage(json!({"id":3,"result":{"text":"receipt"}}));
        let charge = budget.charge(&event).await.unwrap();
        let message = ServerOutbound::Cdp {
            route: 9,
            claim: "actual-issued-token-fixture".to_owned(),
            live: Arc::new(AtomicBool::new(false)),
            event: Queued::new(event, Some(charge)),
        };
        let value = message.json();
        assert_eq!(value["event"]["kind"], "orphanCdpCompletion");
        assert_eq!(value["event"]["data"]["route"], 9);
        assert_eq!(value["event"]["data"]["id"], 3);
        assert!(
            budget.available_bytes() < initial,
            "serializing must not release queued byte ownership"
        );
        drop(value);
        drop(message);
        assert_eq!(budget.available_bytes(), initial);
    }

    #[tokio::test]
    async fn partial_frame_survives_nonterminal_forwarder_completion() {
        use std::{
            pin::Pin,
            task::{Context, Poll},
        };
        use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};
        let (mut wire, input) = tokio::io::duplex(128);
        struct PrefixProbe {
            input: tokio::io::DuplexStream,
            seen: usize,
            notify: Option<oneshot::Sender<()>>,
        }
        impl AsyncRead for PrefixProbe {
            fn poll_read(
                self: Pin<&mut Self>,
                context: &mut Context<'_>,
                buffer: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                let this = self.get_mut();
                let before = buffer.filled().len();
                let result = Pin::new(&mut this.input).poll_read(context, buffer);
                if matches!(result, Poll::Ready(Ok(()))) {
                    this.seen += buffer.filled().len() - before;
                    if this.seen >= 2 {
                        if let Some(notify) = this.notify.take() {
                            let _ = notify.send(());
                        }
                    }
                }
                result
            }
        }
        let (prefix_send, prefix_seen) = oneshot::channel();
        let (forward_send, forward_done) = oneshot::channel();
        let mut input = PrefixProbe {
            input,
            seen: 0,
            notify: Some(prefix_send),
        };
        let (_stop_send, stop) = watch::channel(false);
        let mut tasks = ConnectionTasks {
            writer: tokio::spawn(std::future::pending::<Result<(), IpcError>>()),
            control_forward: tokio::spawn(std::future::pending::<()>()),
            forwarders: JoinSet::new(),
            stop,
        };
        tasks.forwarders.spawn(async move {
            let _ = prefix_seen.await;
            let _ = forward_send.send(());
        });
        let task = tokio::spawn(async move {
            let frame = tasks.next_frame(&mut input).await;
            tasks.writer.abort();
            tasks.control_forward.abort();
            frame
        });
        let payload = br#"{"kind":"control","request":{"method":"inventory","id":7}}"#;
        let header = (payload.len() as u32).to_ne_bytes();
        wire.write_all(&header[..2]).await.unwrap();
        forward_done.await.unwrap();
        wire.write_all(&header[2..]).await.unwrap();
        wire.write_all(payload).await.unwrap();
        let frame = task.await.unwrap().unwrap().unwrap();
        assert_eq!(frame["request"]["id"], 7);
        assert_eq!(frame["request"]["method"], "inventory");
    }

    #[test]
    fn transport_failure_event_keeps_distinct_provenance() {
        let value = serde_json::to_value(BrokerCdpEvent::TransportFailure(
            "native pipe ended".to_owned(),
        ))
        .unwrap();
        assert_eq!(
            value,
            json!({"kind":"transportFailure","data":"native pipe ended"})
        );
        assert!(value.get("error").is_none());
    }
}
