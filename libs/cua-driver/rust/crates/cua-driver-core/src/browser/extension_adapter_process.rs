// SPDX-License-Identifier: MIT

//! Finite, serialized extension-wire adapter actor. Maka v1 keeps its direct writer.
//!
//! This is a separate source delta, not a replacement extension CDP engine. Raw
//! input and normalized delivery each have a separate bounded byte domain so
//! a queued outgoing payload cannot reserve the bytes needed for its phase ACK.
//! Adapter-private bounded notification buffers are a separate accounting domain.

use super::{
    broker_delivery::{ByteBudget, ByteCharge, Queued},
    extension_broker::{
        BrokerError, BrokerHandle, ExtensionAdapterRequest, ExtensionDispatchGuard,
        ExtensionOutbound,
    },
    extension_framing::{self, Direction, FrameError},
    extension_wire::{
        ExtensionReplyProvenance, ExtensionRpcTrace, ExtensionWireAction, ExtensionWireAdapter,
        ExtensionWireError, MAX_ACTION_BATCH,
    },
};
use serde_json::Value;
use std::{
    collections::{HashMap, VecDeque},
    io::{self, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot, watch};

const MAX_SEMANTICS: usize = 128;
const MAX_DEFERRED_CLEANUP: usize = 32;
const MAX_CLEANUP_BYTES: usize = 64 * 1024;
const DRAIN_DEADLINE: Duration = Duration::from_secs(10);
pub(crate) const NORMALIZED_QUEUE_CAPACITY: usize = 16;

#[derive(Debug, thiserror::Error)]
pub(crate) enum AdapterProcessError {
    #[error("extension adapter I/O: {0}")]
    Io(#[from] io::Error),
    #[error("extension adapter framing: {0}")]
    Frame(#[from] FrameError),
    #[error("extension adapter protocol: {0}")]
    Wire(#[from] ExtensionWireError),
    #[error("extension adapter broker: {0}")]
    Broker(#[from] BrokerError),
    #[error("extension adapter process ended: {0}")]
    Ended(String),
}

struct Semantic {
    guard: ExtensionDispatchGuard,
    payload: Option<Arc<ByteCharge>>,
    cancelled: bool,
}

struct RawFrameWrite {
    payload: Vec<u8>,
    trace: Option<ExtensionRpcTrace>,
    guard: Option<ExtensionDispatchGuard>,
    // The input Value has moved into a extension phase. Retain its charge through
    // the physical write/drop even when the adapter releases its maka payload.
    _charge: Option<Arc<ByteCharge>>,
}

struct RawWrite {
    body: RawFrameWrite,
    port_live: Arc<AtomicBool>,
    started: oneshot::Sender<oneshot::Sender<Result<(), String>>>,
    completion: oneshot::Sender<Result<RawWriteOutcome, String>>,
}

#[derive(Debug, PartialEq, Eq)]
enum RawWriteOutcome {
    Written,
    FencedBeforeWrite,
    FencedAfterEarlierWrite,
}

/// One actual protocol frame; no Maka chunk envelopes are invented here.
fn write_raw(
    writer: &mut impl Write,
    request: &RawFrameWrite,
    port_live: &AtomicBool,
    before_bytes: impl FnOnce() -> Result<(), String>,
) -> Result<RawWriteOutcome, String> {
    // This is the physical dispatch release point. EOF/error fences it even
    // while an async actor branch or admission future was already ready.
    if !port_live.load(Ordering::SeqCst) {
        return Ok(
            if request
                .guard
                .as_ref()
                .is_some_and(ExtensionDispatchGuard::was_started)
            {
                RawWriteOutcome::FencedAfterEarlierWrite
            } else {
                RawWriteOutcome::FencedBeforeWrite
            },
        );
    }
    if let Some(guard) = &request.guard {
        if !guard.start_write() {
            return Ok(if guard.was_started() {
                RawWriteOutcome::FencedAfterEarlierWrite
            } else {
                RawWriteOutcome::FencedBeforeWrite
            });
        }
    }
    before_bytes()?;
    let length = u32::try_from(request.payload.len()).map_err(|error| error.to_string())?;
    writer
        .write_all(&length.to_ne_bytes())
        .and_then(|()| writer.write_all(&request.payload))
        .and_then(|()| writer.flush())
        .map_err(|error| error.to_string())?;
    if let Some(guard) = &request.guard {
        guard.frame_written();
    }
    if let Some(trace) = &request.trace {
        trace.frame_written();
    } else {
        // Reverse extension requests have no locally minted RPC correlation.
        // Never log their untrusted IDs, methods or params as Host metadata.
        tracing::trace!(
            target: "maka::extension_rpc_phase",
            extension_host_pid = std::process::id(),
            phase = "frame_written_unattributed",
            "extension RPC phase"
        );
    }
    Ok(RawWriteOutcome::Written)
}

fn write_owned(writer: &mut impl Write, request: RawWrite) -> Option<String> {
    let RawWrite {
        body,
        port_live,
        started,
        completion,
    } = request;
    let result = write_raw(writer, &body, &port_live, || {
        let (commit, acknowledged) = oneshot::channel();
        started
            .send(commit)
            .map_err(|_| "extension write owner ended after dispatch started".to_owned())?;
        acknowledged
            .blocking_recv()
            .map_err(|_| "extension write commit acknowledgement was lost".to_owned())?
    });
    let failed = result.as_ref().err().cloned();
    let _ = completion.send(result);
    failed
}

enum RawInput {
    Message(Queued<Box<serde_json::value::RawValue>>),
    Eof,
}

struct ExtensionIo {
    input: mpsc::Receiver<RawInput>,
    output: mpsc::Sender<RawWrite>,
    failure: watch::Receiver<Option<String>>,
    port_live: Arc<AtomicBool>,
}

fn spawn_extension_io() -> Result<ExtensionIo, AdapterProcessError> {
    let runtime = tokio::runtime::Handle::current();
    let (input_send, input) = mpsc::channel(8);
    let (output, mut writes) = mpsc::channel::<RawWrite>(1);
    let (failure_send, failure) = watch::channel(None);
    let port_live = Arc::new(AtomicBool::new(true));
    let writer_live = port_live.clone();
    let reader_live = port_live.clone();
    let writer_failure = failure_send.clone();
    std::thread::Builder::new()
        .name("maka-extension-adapter-writer".to_owned())
        .spawn(move || {
            let stdout = std::io::stdout();
            let mut stdout = stdout.lock();
            while let Some(request) = writes.blocking_recv() {
                if let Some(reason) = write_owned(&mut stdout, request) {
                    writer_live.store(false, Ordering::SeqCst);
                    writer_failure.send_replace(Some(reason));
                    return;
                }
            }
        })?;
    std::thread::Builder::new()
        .name("maka-extension-adapter-reader".to_owned())
        .spawn(move || {
            let stdin = std::io::stdin();
            let mut stdin = stdin.lock();
            let raw_budget = ByteBudget::new();
            loop {
                let value = match extension_framing::read_frame(&mut stdin, Direction::ChromeToHost)
                {
                    Ok(Some(bytes)) => {
                        match serde_json::from_slice::<Box<serde_json::value::RawValue>>(&bytes) {
                            Ok(value) => value,
                            Err(error) => {
                                reader_live.store(false, Ordering::SeqCst);
                                failure_send.send_replace(Some(error.to_string()));
                                return;
                            }
                        }
                    }
                    Ok(None) => {
                        reader_live.store(false, Ordering::SeqCst);
                        // Liveness never waits for raw queue admission. The actor
                        // separately settles already accepted frames with a bound.
                        failure_send.send_replace(Some("Chrome extension stdin EOF".to_owned()));
                        let _ = input_send.try_send(RawInput::Eof);
                        return;
                    }
                    Err(error) => {
                        reader_live.store(false, Ordering::SeqCst);
                        failure_send.send_replace(Some(error.to_string()));
                        return;
                    }
                };
                let charge = match runtime.block_on(raw_budget.charge(&value)) {
                    Ok(charge) => charge,
                    Err(error) => {
                        reader_live.store(false, Ordering::SeqCst);
                        failure_send.send_replace(Some(error.to_string()));
                        return;
                    }
                };
                if input_send
                    .blocking_send(RawInput::Message(Queued::new(value, Some(charge))))
                    .is_err()
                {
                    return;
                }
            }
        })?;
    Ok(ExtensionIo {
        input,
        output,
        failure,
        port_live,
    })
}

// The payload reservation follows the JSON value. Reply identity metadata is
// separately bounded by the existing wire-context/owner/ID limits and this
// fixed-capacity queue; it contains no copied page payload or JSON authority.
struct NormalizedMessage {
    value: Value,
    provenance: ExtensionReplyProvenance,
}

/// Pending raw ACKs are not serialized behind a blocked broker admission call.
struct Normalizer {
    budget: ByteBudget,
    sender: mpsc::Sender<Queued<NormalizedMessage>>,
    task: Option<tokio::task::JoinHandle<Result<(), String>>>,
}

impl Normalizer {
    fn new(broker: BrokerHandle) -> Self {
        let (sender, mut input) =
            mpsc::channel::<Queued<NormalizedMessage>>(NORMALIZED_QUEUE_CAPACITY);
        let task = tokio::spawn(async move {
            while let Some(message) = input.recv().await {
                let (message, charge) = message.into_parts();
                // This pump can wait for the broker's shared budget without
                // blocking the serialized adapter or its raw phase input.
                broker
                    .extension_adapter_message(message.value, message.provenance)
                    .await
                    .map_err(|error| error.to_string())?;
                drop(charge);
            }
            Ok(())
        });
        Self {
            budget: ByteBudget::new(),
            sender,
            task: Some(task),
        }
    }
}

struct Actor {
    adapter: Box<dyn ExtensionWireAdapter>,
    broker: BrokerHandle,
    outgoing: mpsc::Receiver<ExtensionOutbound>,
    io: ExtensionIo,
    normalizer: Normalizer,
    pending: HashMap<String, Semantic>,
    cleanup: VecDeque<ExtensionOutbound>,
    ready: Option<oneshot::Sender<Result<(), String>>>,
    retiring: bool,
}

fn cleanup_method(value: &Value) -> bool {
    matches!(
        value["method"].as_str(),
        Some(
            "closeOwner"
                | "detach"
                | "stopCreatedTab"
                | "finishTurn"
                | "clearScopedHeaders"
                | "clearSessionHeaders"
                | "clearSessionPreparation"
        )
    )
}

impl Actor {
    async fn reject_unadmitted(
        &mut self,
        frame: ExtensionOutbound,
    ) -> Result<(), AdapterProcessError> {
        let guard = frame.dispatch_guard();
        // This path is BEFORE adapter.on_semantic and before any frame can be
        // generated. Never turn an already-started dispatch into local refusal.
        if let Some(report) = guard.reject_before_write(
            "adapter_backpressure".to_owned(),
            "extension adapter admission is temporarily backpressured".to_owned(),
        ) {
            drop(frame);
            self.broker.write_report(report).await;
            Ok(())
        } else {
            Err(AdapterProcessError::Ended(
                "backpressured request was already started; outcome remains unknown".to_owned(),
            ))
        }
    }

    async fn pressure_input(
        &mut self,
        frame: ExtensionOutbound,
    ) -> Result<(), AdapterProcessError> {
        if cleanup_method(frame.payload_for_transport()) {
            let bytes = extension_framing::encode_json(
                frame.payload_for_transport(),
                Direction::ChromeToHost,
            )?;
            if bytes.len() > MAX_CLEANUP_BYTES || self.cleanup.len() >= MAX_DEFERRED_CLEANUP {
                return Err(AdapterProcessError::Ended(
                    "reserved extension cleanup admission exceeded its bounded domain".to_owned(),
                ));
            }
            // Exact original context and guard move with this trusted cleanup.
            self.cleanup.push_back(frame);
            Ok(())
        } else {
            self.reject_unadmitted(frame).await
        }
    }

    async fn failure(&mut self) -> AdapterProcessError {
        AdapterProcessError::Ended(
            self.io
                .failure
                .borrow()
                .clone()
                .unwrap_or_else(|| "extension stdio worker ended".to_owned()),
        )
    }

    async fn forward(
        &mut self,
        value: Value,
        provenance: ExtensionReplyProvenance,
    ) -> Result<(), AdapterProcessError> {
        // A separate charged domain and pump, not an inline broker budget wait.
        // Retirement still drains fully read records. An unread EOF notification
        // must not discard them while they await either delivery reservation.
        let budget = self.normalizer.budget.clone();
        let deadline = tokio::time::sleep(DRAIN_DEADLINE);
        tokio::pin!(deadline);
        let charge = {
            let admission = budget.charge(&value);
            tokio::pin!(admission);
            loop {
                tokio::select! {
                    _=&mut deadline=>return Err(AdapterProcessError::Ended("normalized admission deadline expired; delivery remains unknown".to_owned())),
                    result=&mut admission=>break result.map_err(|error|AdapterProcessError::Ended(error.to_string()))?,
                    _=self.io.failure.changed(), if !self.retiring=>return Err(self.failure().await),
                    frame=self.outgoing.recv()=>match frame {Some(frame)=>self.pressure_input(frame).await?,None=>return Err(AdapterProcessError::Ended("broker output ended during normalized delivery".to_owned()))},
                }
            }
        };
        let sender = self.normalizer.sender.clone();
        let reserve = sender.reserve_owned();
        tokio::pin!(reserve);
        let permit = loop {
            tokio::select! {
                _=&mut deadline=>return Err(AdapterProcessError::Ended("normalized queue deadline expired; delivery remains unknown".to_owned())),
                result=&mut reserve=>break result.map_err(|_|AdapterProcessError::Ended("normalizer ended".to_owned()))?,
                _=self.io.failure.changed(), if !self.retiring=>return Err(self.failure().await),
                frame=self.outgoing.recv()=>match frame {Some(frame)=>self.pressure_input(frame).await?,None=>return Err(AdapterProcessError::Ended("broker output ended during normalized delivery".to_owned()))},
            }
        };
        permit.send(Queued::new(
            NormalizedMessage { value, provenance },
            Some(charge),
        ));
        Ok(())
    }

    async fn write_phase(
        &mut self,
        message: Value,
        id: Option<&str>,
        charge: Option<Arc<ByteCharge>>,
        trace: Option<ExtensionRpcTrace>,
        phase: Option<super::chatgpt_rpc_v2::RequestId>,
    ) -> Result<(), AdapterProcessError> {
        let guard = match id {
            Some(id) => Some(
                self.pending
                    .get(id)
                    .ok_or_else(|| {
                        AdapterProcessError::Ended(
                            "extension phase names a finished semantic request".to_owned(),
                        )
                    })?
                    .guard
                    .clone(),
            ),
            None => None,
        };
        if self.retiring {
            if let Some(guard) = guard {
                if let Some(report) = guard.reject_before_write(
                    "not_dispatched".to_owned(),
                    "extension port ended before this phase".to_owned(),
                ) {
                    self.broker.write_report(report).await;
                    self.discard_unwritten_phase(phase.as_ref(), id).await?;
                } else if let Some(id) = id {
                    self.cancel_semantic(id).await?;
                }
            } else {
                self.discard_unwritten_phase(phase.as_ref(), id).await?;
            }
            return Ok(());
        }
        let payload = match extension_framing::encode_json(&message, Direction::HostToChrome) {
            Ok(payload) => payload,
            Err(FrameError::TooLarge { .. }) => {
                if let Some(guard) = &guard {
                    if let Some(report)=guard.reject_before_write("extension_message_budget".to_owned(),"selected extension protocol cannot encode this frame within Chrome's host-to-browser limit".to_owned()) {
                        self.broker.write_report(report).await;
                        self.discard_unwritten_phase(phase.as_ref(), id).await?;
                        return Ok(());
                    }
                }
                return Err(AdapterProcessError::Ended("extension frame exceeds its protocol limit after an earlier phase; outcome remains unknown".to_owned()));
            }
            Err(error) => return Err(error.into()),
        };
        drop(message);
        let (started, mut start) = oneshot::channel();
        let (completion, done) = oneshot::channel();
        let request = RawWrite {
            body: RawFrameWrite {
                payload,
                trace,
                guard: guard.clone(),
                _charge: charge,
            },
            port_live: self.io.port_live.clone(),
            started,
            completion,
        };
        let sender = self.io.output.clone();
        let deadline = tokio::time::sleep(DRAIN_DEADLINE);
        tokio::pin!(deadline);
        tokio::select! { result=sender.send(request)=>result.map_err(|_|AdapterProcessError::Ended("extension writer ended".to_owned()))?, _=self.io.failure.changed()=>return Err(self.failure().await), _=&mut deadline=>return Err(AdapterProcessError::Ended("extension writer admission deadline expired; outcome remains unknown".to_owned())) };
        tokio::pin!(done);
        let mut awaiting_start = true;
        let result = loop {
            tokio::select! { result= &mut start, if awaiting_start => {
                    awaiting_start = false;
                    if let Ok(acknowledge) = result {
                        let committed = phase.as_ref().map_or(Ok(()), |phase| self.adapter.commit_write(phase));
                        let failed = committed.as_ref().err().map(ToString::to_string);
                        let _ = acknowledge.send(committed.map_err(|error| error.to_string()));
                        if let Some(reason) = failed {
                            return Err(AdapterProcessError::Ended(reason));
                        }
                    }
                }
                result = &mut done => break result.map_err(|_|AdapterProcessError::Ended("extension write completion was lost; outcome remains unknown".to_owned()))?.map_err(AdapterProcessError::Ended)?, _=self.io.failure.changed()=>return Err(self.failure().await), _=&mut deadline=>return Err(AdapterProcessError::Ended("extension write deadline expired; outcome remains unknown".to_owned())),
            }
        };
        match result {
            RawWriteOutcome::Written => {
                if let Some(guard) = guard {
                    if let Some(report) = guard.written_report() {
                        self.broker.write_report(report).await;
                    }
                }
            }
            RawWriteOutcome::FencedBeforeWrite => {
                if let Some(guard) = guard {
                    if let Some(report) = guard.reject_before_write(
                        "not_dispatched".to_owned(),
                        "extension execution fence closed before dispatch".to_owned(),
                    ) {
                        self.broker.write_report(report).await;
                    }
                }
                self.discard_unwritten_phase(phase.as_ref(), id).await?;
            }
            RawWriteOutcome::FencedAfterEarlierWrite => {
                if let Some(id) = id {
                    // A follow-up fence may follow an actual custody ACK.
                    // Retain Pending and guard until terminal ACK/Unknown with
                    // custody, or EOF/expiry; Maka incomplete chunks differ.
                    self.cancel_semantic(id).await?;
                }
            }
        }
        Ok(())
    }

    async fn discard_unwritten_phase(
        &mut self,
        phase: Option<&super::chatgpt_rpc_v2::RequestId>,
        semantic: Option<&str>,
    ) -> Result<(), AdapterProcessError> {
        if let Some(phase) = phase {
            let actions = self.adapter.discard_unwritten(phase)?;
            self.actions(actions).await?;
        } else if let Some(semantic) = semantic {
            self.finish_semantic(semantic).await;
        }
        Ok(())
    }

    async fn finish_semantic(&mut self, id: &str) {
        self.pending.remove(id);
    }

    async fn cancel_semantic(&mut self, id: &str) -> Result<(), AdapterProcessError> {
        let notify = if let Some(entry) = self.pending.get_mut(id) {
            if entry.cancelled {
                false
            } else {
                entry.cancelled = true;
                true
            }
        } else {
            false
        };
        if notify {
            let actions = self.adapter.on_cancel(id);
            self.actions(actions).await?;
        }
        Ok(())
    }

    #[cfg(test)]
    async fn extension(&mut self, value: Value) -> Result<(), AdapterProcessError> {
        let json = serde_json::value::to_raw_value(&value)
            .map_err(|error| AdapterProcessError::Ended(error.to_string()))?;
        self.extension_json(&json).await
    }

    async fn extension_json(
        &mut self,
        frame: &serde_json::value::RawValue,
    ) -> Result<(), AdapterProcessError> {
        let actions = self.adapter.on_extension_json(frame, Instant::now())?;
        self.actions(actions).await
    }

    // Recursive action emission is boxed only because cancel may emit actions;
    // the concrete adapter never recursively invokes the host actor.
    fn actions<'a>(
        &'a mut self,
        actions: Vec<ExtensionWireAction>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), AdapterProcessError>> + Send + 'a>,
    > {
        Box::pin(async move {
            if actions.len() > MAX_ACTION_BATCH {
                return Err(AdapterProcessError::Ended(
                    "adapter action batch exceeds its bound".to_owned(),
                ));
            }
            let mut frames: HashMap<String, usize> = HashMap::new();
            let mut payloads: HashMap<String, Arc<ByteCharge>> = HashMap::new();
            for action in &actions {
                if let ExtensionWireAction::ExtensionFrame {
                    semantic_id: Some(id),
                    ..
                } = action
                {
                    *frames.entry(id.clone()).or_default() += 1;
                    if let Some(Semantic {
                        payload: Some(charge),
                        ..
                    }) = self.pending.get(id)
                    {
                        payloads.insert(id.clone(), charge.clone());
                    }
                }
            }
            let mut finished = Vec::new();
            let mut terminal_reason = None;
            for action in actions {
                match action {
                    ExtensionWireAction::ExtensionFrame {
                        message,
                        semantic_id,
                        trace,
                        phase,
                    } => {
                        if terminal_reason.is_some() {
                            // A malformed adapter tail cannot release more
                            // extension effects after a protocol-ending marker.
                            continue;
                        }
                        let charge = semantic_id
                            .as_ref()
                            .and_then(|id| payloads.get(id).cloned());
                        self.write_phase(message, semantic_id.as_deref(), charge, trace, phase)
                            .await?;
                        if let Some(id) = semantic_id {
                            if let Some(left) = frames.get_mut(&id) {
                                *left -= 1;
                                if *left == 0 {
                                    payloads.remove(&id);
                                }
                            }
                        }
                    }
                    ExtensionWireAction::SemanticPayloadReleased { semantic_id } => {
                        if let Some(entry) = self.pending.get_mut(&semantic_id) {
                            entry.payload = None;
                        }
                    }
                    ExtensionWireAction::SemanticFinished { semantic_id } => {
                        finished.push(semantic_id)
                    }
                    ExtensionWireAction::BrokerMessage(value) => {
                        self.forward(value, ExtensionReplyProvenance::Adapted)
                            .await?
                    }
                    ExtensionWireAction::MatchedBrokerMessage { message, terminal } => {
                        self.forward(message, ExtensionReplyProvenance::Matched(terminal))
                            .await?
                    }
                    ExtensionWireAction::Diagnostic {
                        semantic_id,
                        message,
                    } => {
                        tracing::debug!(semantic_id = ?semantic_id, diagnostic = %message, "extension browser adapter diagnostic");
                    }
                    ExtensionWireAction::TransportEnded { reason } => {
                        self.io.port_live.store(false, Ordering::SeqCst);
                        if terminal_reason.is_none() {
                            terminal_reason = Some(reason);
                        }
                    }
                }
            }
            for id in finished {
                self.finish_semantic(&id).await;
            }
            match terminal_reason {
                Some(reason) => Err(AdapterProcessError::Ended(reason)),
                None => Ok(()),
            }
        })
    }

    async fn semantic(&mut self, frame: ExtensionOutbound) -> Result<(), AdapterProcessError> {
        let preflight_guard = frame.dispatch_guard();
        if !preflight_guard.is_live() {
            if let Some(report) = preflight_guard.reject_before_write(
                "not_dispatched".to_owned(),
                "extension execution fence closed before adapter admission".to_owned(),
            ) {
                self.broker.write_report(report).await;
            }
            return Ok(());
        }
        let preflight_id = frame.outer_id().map(|id| id.to_string());
        if self.pending.len() >= MAX_SEMANTICS && preflight_id.is_some() {
            return self.reject_unadmitted(frame).await;
        }
        let bound = frame.payload_for_transport()["kind"] == "bound";
        let ExtensionAdapterRequest {
            message,
            semantic_id,
            wire_context,
            guard,
        } = frame.into_adapter_request();
        let (value, payload) = message.into_parts();
        if let Some(id) = &semantic_id {
            if self.pending.contains_key(id) {
                return Err(AdapterProcessError::Ended(
                    "semantic IDs cannot be replayed within extension generation".to_owned(),
                ));
            }
            self.pending.insert(
                id.clone(),
                Semantic {
                    guard: guard.clone(),
                    payload,
                    cancelled: false,
                },
            );
        }
        match self
            .adapter
            .on_semantic(value, wire_context.as_ref(), Instant::now())
        {
            Ok(actions) => self.actions(actions).await?,
            Err(ExtensionWireError::LocalRefusal { code, message }) => {
                // The selected adapter contract guarantees errors retain no
                // input Value. No ExtensionFrame was returned on this path.
                if let Some(id) = &semantic_id {
                    if let Some(entry) = self.pending.get_mut(id) {
                        entry.payload = None;
                    }
                }
                if let Some(report) = guard.reject_before_write(code, message) {
                    self.broker.write_report(report).await;
                } else {
                    return Err(AdapterProcessError::Ended(
                        "adapter refusal followed an earlier extension phase; outcome remains unknown"
                            .to_owned(),
                    ));
                }
                if let Some(id) = semantic_id {
                    // Initial LocalRefusal has no queued adapter RPC by the
                    // selected adapter contract; no reply can finish it later.
                    self.pending.remove(&id);
                }
            }
            Err(error) => {
                if let Some(id) = semantic_id {
                    self.pending.remove(&id);
                }
                return Err(error.into());
            }
        }
        if bound {
            if let Some(ready) = self.ready.take() {
                let _ = ready.send(Ok(()));
            }
        }
        Ok(())
    }

    async fn cancel_dead(&mut self) -> Result<(), AdapterProcessError> {
        let ids = self
            .pending
            .iter_mut()
            .filter_map(|(id, entry)| {
                if !entry.cancelled && !entry.guard.is_live() {
                    entry.cancelled = true;
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for id in ids {
            let actions = self.adapter.on_cancel(&id);
            self.actions(actions).await?;
        }
        Ok(())
    }

    async fn drive(&mut self) -> Result<(), AdapterProcessError> {
        let actions = self.adapter.start(Instant::now())?;
        self.actions(actions).await?;
        let mut expiry = tokio::time::interval(Duration::from_millis(50));
        loop {
            if !self.io.port_live.load(Ordering::SeqCst) {
                return Err(self.failure().await);
            }
            if let Some(request) = self.cleanup.pop_front() {
                self.semantic(request).await?;
                continue;
            }
            tokio::select! {
                _=self.io.failure.changed()=>return Err(self.failure().await),
                _=expiry.tick()=>{self.cancel_dead().await?;let actions=self.adapter.expire(Instant::now());self.actions(actions).await?;},
                frame=self.outgoing.recv()=>match frame {Some(frame)=>self.semantic(frame).await?,None=>return Ok(())},
                raw=self.io.input.recv()=>match raw {
                    Some(RawInput::Message(raw))=>{let (value,charge)=raw.into_parts();self.extension_json(&value).await?;drop(charge);},
                    Some(RawInput::Eof)|None=>return Ok(()),
                }
            }
        }
    }
}

/// Run only for an explicitly installed/reviewed non-Maka adapter selection.
pub(crate) async fn run(
    adapter: Box<dyn ExtensionWireAdapter>,
    broker: BrokerHandle,
    outgoing: mpsc::Receiver<ExtensionOutbound>,
    ready: oneshot::Sender<Result<(), String>>,
) -> Result<(), AdapterProcessError> {
    let io = spawn_extension_io()?;
    let normalizer = Normalizer::new(broker.clone());
    let mut actor = Actor {
        adapter,
        broker: broker.clone(),
        outgoing,
        io,
        normalizer,
        pending: HashMap::new(),
        cleanup: VecDeque::new(),
        ready: Some(ready),
        retiring: false,
    };
    let result = actor.drive().await;
    actor.retiring = true;
    // Preserve already accepted raw replies before adapter EOF normalization.
    // No new extension phase may be sent after the liveness fence.
    let settlement = async {
        while let Ok(RawInput::Message(raw)) = actor.io.input.try_recv() {
            let (value, charge) = raw.into_parts();
            let _ = actor.extension_json(&value).await;
            drop(charge);
        }
    };
    let _ = tokio::time::timeout(DRAIN_DEADLINE, settlement).await;
    let reason = result
        .as_ref()
        .err()
        .map_or("Chrome extension stdin EOF".to_owned(), ToString::to_string);
    let actions = actor.adapter.on_eof(&reason);
    let _ = actor.actions(actions).await;
    if let Some(ready) = actor.ready.take() {
        let _ = ready.send(Err(reason.clone()));
    }
    // Close normalization in FIFO order before the broker EOF fence. A timeout
    // is an unknown delivery outcome; it never synthesizes Chrome rejection.
    let (closed_sender, closed_receiver) = mpsc::channel(1);
    drop(closed_receiver);
    drop(std::mem::replace(
        &mut actor.normalizer.sender,
        closed_sender,
    ));
    let mut drain_task = actor.normalizer.task.take().expect("owned normalizer task");
    let deadline = tokio::time::sleep(DRAIN_DEADLINE);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => { drain_task.abort(); break; },
            _ = &mut drain_task => break,
            frame = actor.outgoing.recv() => if let Some(frame) = frame {
                // The raw port ended. A not-yet-admitted queued request has
                // definitely not run; rejecting it releases bytes needed to
                // deliver earlier actual extension replies before the EOF fence.
                let _ = actor.reject_unadmitted(frame).await;
            } else { break; },
        }
    }
    broker.extension_eof(&reason).await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn raw_writer_uses_native_endian_header_and_exact_json_bytes() {
        let payload = br#"{"jsonrpc":"2.0","id":1,"method":"getInfo"}"#.to_vec();
        let request = RawFrameWrite {
            trace: None,
            payload: payload.clone(),
            guard: None,
            _charge: None,
        };
        let mut writer = Cursor::new(Vec::new());
        assert_eq!(
            write_raw(&mut writer, &request, &AtomicBool::new(true), || Ok(())).unwrap(),
            RawWriteOutcome::Written
        );
        let bytes = writer.into_inner();
        assert_eq!(&bytes[..4], &(payload.len() as u32).to_ne_bytes());
        assert_eq!(&bytes[4..], payload);
    }

    #[test]
    fn passive_frame_trace_requires_complete_flush_and_contains_only_captured_metadata() {
        use super::super::extension_wire::{rpc_phase_test::Capture, ExtensionWireContext};
        struct FlushFailure;
        impl Write for FlushFailure {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::other("flush failed"))
            }
        }
        let capture = Capture::default();
        let context = ExtensionWireContext::new("session-old", "turn-old").unwrap();
        let request = RawFrameWrite {
            payload: br#"{"params":{"url":"PAYLOAD_URL_SENTINEL","headers":"HEADER_SENTINEL"}}"#
                .to_vec(),
            trace: Some(ExtensionRpcTrace::captured(
                "generation-old",
                "maka-original-compat:generation-old:9",
                "claimUserTab",
                Some("42"),
                Some("owner-old"),
                Some(&context),
            )),
            guard: None,
            _charge: None,
        };
        let port_live = AtomicBool::new(false);
        tracing::subscriber::with_default(capture.clone(), || {
            assert_eq!(
                write_raw(
                    &mut Cursor::new(Vec::new()),
                    &request,
                    &port_live,
                    || Ok(())
                )
                .unwrap(),
                RawWriteOutcome::FencedBeforeWrite
            );
            assert!(
                capture.rows().is_empty(),
                "a fence cannot produce write completion"
            );
            port_live.store(true, Ordering::SeqCst);
            assert!(write_raw(&mut FlushFailure, &request, &port_live, || Ok(())).is_err());
            assert!(
                capture.rows().is_empty(),
                "a partial write/failed flush cannot produce write completion"
            );
            let mut bytes = Cursor::new(Vec::new());
            assert_eq!(
                write_raw(&mut bytes, &request, &port_live, || Ok(())).unwrap(),
                RawWriteOutcome::Written
            );
            assert_eq!(&bytes.get_ref()[4..], request.payload);
        });
        let rows = capture.rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["phase"], "frame_written");
        assert_eq!(rows[0]["extension_method"], "claimUserTab");
        assert_eq!(
            rows[0]["extension_rpc_id"],
            "maka-original-compat:generation-old:9"
        );
        assert_eq!(
            rows[0]["extension_host_pid"],
            std::process::id().to_string()
        );
        assert_eq!(rows[0]["host_turn_id"], "Some(\"turn-old\")");
        let fields = format!("{rows:?}");
        assert!(!fields.contains("PAYLOAD_URL_SENTINEL") && !fields.contains("HEADER_SENTINEL"));
    }

    #[test]
    fn selected_protocol_large_frame_refuses_before_native_io() {
        let message = serde_json::json!({"params":{"data":"x".repeat(1024*1024)}});
        assert!(matches!(
            extension_framing::encode_json(&message, Direction::HostToChrome),
            Err(FrameError::TooLarge {
                direction: Direction::HostToChrome,
                ..
            })
        ));
    }

    #[test]
    fn port_eof_fences_an_already_queued_raw_frame() {
        let live = Arc::new(AtomicBool::new(true));
        let request = RawFrameWrite {
            trace: None,
            payload: br#"{"id":1,"method":"getInfo"}"#.to_vec(),
            guard: None,
            _charge: None,
        };
        live.store(false, Ordering::SeqCst);
        let mut writer = Cursor::new(Vec::new());
        assert_eq!(
            write_raw(&mut writer, &request, &live, || Ok(())).unwrap(),
            RawWriteOutcome::FencedBeforeWrite
        );
        assert!(writer.into_inner().is_empty());
    }

    #[test]
    fn cleanup_reserve_excludes_tab_stop_from_whole_turn_finish() {
        assert!(cleanup_method(&serde_json::json!({"method":"finishTurn"})));
        assert!(cleanup_method(
            &serde_json::json!({"method":"stopCreatedTab"})
        ));
        assert!(!cleanup_method(
            &serde_json::json!({"method":"cdp","params":{"method":"turnEnded"}})
        ));
        assert!(!cleanup_method(&serde_json::json!({"method":"inventory"})));
    }

    #[tokio::test]
    async fn terminal_marker_keeps_every_pending_custody_receipt_before_transport_end() {
        use super::super::{
            extension_broker::{ExtensionHostBroker, LocalPrincipal},
            extension_host::ExtensionOrigin,
            extension_wire::{ExtensionWireContext, MakaWireAdapter, MatchedExtensionReply},
        };
        use serde_json::json;

        let origin = ExtensionOrigin::from_id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let (handle, broker, mut outgoing) =
            ExtensionHostBroker::channels(origin, LocalPrincipal::UnixUid(123));
        let broker_task = tokio::spawn(broker.run());
        handle.extension_message(json!({"kind":"hello","protocol":1,"extensionId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","instanceId":"terminal-fixture","capabilities":{"metadata":true,"rawTabCdp":true}})).await.unwrap();
        let bound = tokio::time::timeout(Duration::from_secs(5), outgoing.recv())
            .await
            .unwrap()
            .unwrap()
            .into_adapter_request();
        let (_input_sender, input) = mpsc::channel(1);
        let (output, mut raw_writes) = mpsc::channel(1);
        let (_failure_sender, failure) = watch::channel(None);
        let port_live = Arc::new(AtomicBool::new(true));
        let (normalized, mut normalized_receipts) = mpsc::channel(MAX_SEMANTICS);
        let mut actor = Actor {
            adapter: Box::new(MakaWireAdapter::default()),
            broker: handle.clone(),
            outgoing,
            io: ExtensionIo {
                input,
                output,
                failure,
                port_live: port_live.clone(),
            },
            normalizer: Normalizer {
                budget: ByteBudget::new(),
                sender: normalized,
                task: None,
            },
            pending: HashMap::new(),
            cleanup: VecDeque::new(),
            ready: None,
            retiring: false,
        };
        let mut actions = Vec::new();
        let mut expected = Vec::new();
        for index in 0..MAX_SEMANTICS {
            let id = format!("fixture-terminal-{index}");
            actor.pending.insert(
                id.clone(),
                Semantic {
                    guard: bound.guard.clone(),
                    payload: None,
                    cancelled: false,
                },
            );
            let custody = json!({"kind":"response","protocol":1,"id":id,"error":{"kind":"outcome_unknown","message":"extension protocol ended after attach acknowledgement","details":{"remoteAcknowledged":true,"remoteReplyMatched":true,"custody":{"claim":format!("actual-attach-receipt-{index}"),"tabId":index,"acquisitionConfirmed":true}}}});
            expected.push(custody.clone());
            actions.push(ExtensionWireAction::SemanticPayloadReleased {
                semantic_id: id.clone(),
            });
            if index == 0 {
                actions.push(ExtensionWireAction::MatchedBrokerMessage {
                    message: custody,
                    terminal: MatchedExtensionReply::from_matched_rpc(
                        "fixture-generation".to_owned(),
                        "fixture-owner".to_owned(),
                        id.clone(),
                        Some(ExtensionWireContext::new("fixture-session", "fixture-turn").unwrap()),
                    ),
                });
            } else {
                // A JSON flag cannot upgrade a source-unknown completion.
                actions.push(ExtensionWireAction::BrokerMessage(custody));
            }
            actions.push(ExtensionWireAction::SemanticFinished { semantic_id: id });
        }
        actions.push(ExtensionWireAction::TransportEnded {
            reason: "matched protocol violation".to_owned(),
        });
        actions.push(ExtensionWireAction::ExtensionFrame {
            message: json!({"method":"must-not-dispatch"}),
            semantic_id: None,
            trace: None,
            phase: None,
        });
        assert!(
            actions.len() > MAX_SEMANTICS,
            "terminal normalization must cover a whole pending generation"
        );
        let result = actor.actions(actions).await;
        assert!(
            matches!(result, Err(AdapterProcessError::Ended(reason)) if reason == "matched protocol violation")
        );
        assert!(
            actor.pending.is_empty(),
            "terminal bookkeeping must finish after its custody receipts are queued"
        );
        for (index, custody) in expected.into_iter().enumerate() {
            let normalized = normalized_receipts.try_recv().unwrap().into_parts().0;
            assert_eq!(normalized.value, custody);
            if index == 0 {
                let ExtensionReplyProvenance::Matched(evidence) = normalized.provenance else {
                    panic!("actual matcher evidence must survive terminal normalization");
                };
                assert!(evidence.matches(
                    "fixture-generation",
                    "fixture-owner",
                    "fixture-terminal-0",
                    Some(&ExtensionWireContext::new("fixture-session", "fixture-turn").unwrap()),
                ));
            } else {
                assert!(
                    matches!(normalized.provenance, ExtensionReplyProvenance::Adapted),
                    "extension/page JSON fields cannot manufacture a matched Rust reply"
                );
            }
        }
        assert!(normalized_receipts.try_recv().is_err());
        assert!(
            !port_live.load(Ordering::SeqCst),
            "protocol ending must fence the physical writer"
        );
        assert!(
            raw_writes.try_recv().is_err(),
            "a terminal batch cannot release a later extension frame"
        );
        broker_task.abort();
        let _ = broker_task.await;
    }

    #[cfg(unix)]
    use super::super::{
        extension_broker::{ExtensionHostBroker, LocalPrincipal},
        extension_host::ExtensionOrigin,
        extension_wire::ExtensionWireContext,
    };
    #[cfg(unix)]
    use serde_json::json;

    #[cfg(unix)]
    struct RetirementAdapter;

    #[cfg(unix)]
    impl ExtensionWireAdapter for RetirementAdapter {
        fn start(&mut self, _now: Instant) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
            Ok(Vec::new())
        }
        fn on_semantic(
            &mut self,
            _envelope: Value,
            _context: Option<&ExtensionWireContext>,
            _now: Instant,
        ) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
            Ok(Vec::new())
        }
        fn on_extension(
            &mut self,
            frame: Value,
            _now: Instant,
        ) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
            Ok(vec![
                ExtensionWireAction::BrokerMessage(frame),
                ExtensionWireAction::ExtensionFrame {
                    message: json!({"method":"must-not-dispatch-after-retirement"}),
                    semantic_id: None,
                    trace: None,
                    phase: None,
                },
            ])
        }
        fn on_cancel(&mut self, _semantic_id: &str) -> Vec<ExtensionWireAction> {
            Vec::new()
        }
        fn on_eof(&mut self, _reason: &str) -> Vec<ExtensionWireAction> {
            Vec::new()
        }
        fn expire(&mut self, _now: Instant) -> Vec<ExtensionWireAction> {
            Vec::new()
        }
    }

    #[cfg(unix)]
    struct TranslatedFixture {
        actor: Actor,
        writes: mpsc::Receiver<RawWrite>,
        normalized: mpsc::Receiver<Queued<NormalizedMessage>>,
        _input: mpsc::Sender<RawInput>,
        _failure: watch::Sender<Option<String>>,
        broker_task: tokio::task::JoinHandle<()>,
    }

    #[cfg(unix)]
    impl Drop for TranslatedFixture {
        fn drop(&mut self) {
            self.broker_task.abort();
        }
    }

    #[cfg(unix)]
    async fn translated_fixture() -> TranslatedFixture {
        let origin = ExtensionOrigin::from_id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let (broker, service, mut outgoing) =
            ExtensionHostBroker::channels(origin, LocalPrincipal::UnixUid(123));
        let broker_task = tokio::spawn(service.run());
        broker
            .extension_message(json!({
                "kind":"hello","protocol":1,
                "extensionId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "instanceId":"translated-actor-fixture","capabilities":{"metadata":true}
            }))
            .await
            .unwrap();
        drop(
            tokio::time::timeout(Duration::from_secs(5), outgoing.recv())
                .await
                .expect("fixture channel deadline")
                .expect("fixture channel closed"),
        );
        let (input_sender, input) = mpsc::channel(1);
        let (output, writes) = mpsc::channel(1);
        let (failure_sender, failure) = watch::channel(None);
        let (normalized_sender, normalized) = mpsc::channel(8);
        let actor = Actor {
            adapter: Box::new(RetirementAdapter),
            broker,
            outgoing,
            io: ExtensionIo {
                input,
                output,
                failure,
                port_live: Arc::new(AtomicBool::new(true)),
            },
            normalizer: Normalizer {
                budget: ByteBudget::new(),
                sender: normalized_sender,
                task: None,
            },
            pending: HashMap::new(),
            cleanup: VecDeque::new(),
            ready: None,
            retiring: false,
        };
        TranslatedFixture {
            actor,
            writes,
            normalized,
            _input: input_sender,
            _failure: failure_sender,
            broker_task,
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn retiring_actor_drains_an_already_read_raw_reply_after_unread_failure() {
        use std::{future::Future, task::Poll};

        for queue_blocked in [false, true] {
            let mut fixture = translated_fixture().await;
            let expected = json!({
                "kind":"response","protocol":1,"generation":"actual-generation","id":"1",
                "result":{"result":{
                    "result":{"type":"object","objectId":"actual-old-reply"},
                    "exceptionDetails":{"exceptionId":19,"text":"preserve actual reply"}
                }}
            });
            let expected_bytes = serde_json::to_vec(&expected).unwrap().len();
            if !queue_blocked {
                fixture.actor.normalizer.budget = ByteBudget::test_with_capacity(expected_bytes);
            }
            let budget = fixture.actor.normalizer.budget.clone();
            let available = budget.available_bytes();
            let held_charge = if queue_blocked {
                None
            } else {
                Some(budget.try_charge(&expected).unwrap())
            };
            let slots = if queue_blocked {
                let slots = fixture.actor.normalizer.sender.capacity();
                for index in 0..slots {
                    fixture
                        .actor
                        .forward(json!({"buffered":index}), ExtensionReplyProvenance::Adapted)
                        .await
                        .unwrap();
                }
                assert_eq!(fixture.actor.normalizer.sender.capacity(), 0);
                slots
            } else {
                assert_eq!(budget.available_bytes(), 0);
                0
            };

            fixture
                ._failure
                .send_replace(Some("unread extension EOF".to_owned()));
            fixture.actor.retiring = true;
            fixture.actor.io.port_live.store(false, Ordering::SeqCst);
            let mut drain = Box::pin(fixture.actor.extension(expected.clone()));
            std::future::poll_fn(|context| match drain.as_mut().poll(context) {
                Poll::Pending => Poll::Ready(()),
                Poll::Ready(result) => {
                    panic!("retiring drain must wait for pressure release despite unread failure (queue_blocked={queue_blocked}): {result:?}")
                }
            })
            .await;
            assert!(
                fixture.writes.try_recv().is_err(),
                "retirement must fence subsequent extension frames"
            );

            if let Some(held_charge) = held_charge {
                drop(held_charge);
            } else {
                let first = fixture.normalized.try_recv().unwrap();
                assert_eq!(first.event().value, json!({"buffered":0}));
                drop(first);
            }
            tokio::time::timeout(Duration::from_secs(5), drain)
                .await
                .expect("retiring drain did not resume after pressure was released")
                .unwrap();

            for index in 1..slots {
                let buffered = fixture.normalized.try_recv().unwrap();
                assert_eq!(buffered.event().value, json!({"buffered":index}));
            }
            let (reply, charge) = fixture.normalized.try_recv().unwrap().into_parts();
            assert_eq!(reply.value, expected);
            assert!(reply.value.get("error").is_none());
            assert!(matches!(
                reply.provenance,
                ExtensionReplyProvenance::Adapted
            ));
            let charge = charge.expect("actual retiring reply must retain its delivery charge");
            assert_eq!(charge.bytes(), expected_bytes);
            assert_eq!(budget.available_bytes(), available - expected_bytes);
            assert!(
                fixture.normalized.try_recv().is_err(),
                "actual reply must be forwarded once"
            );
            assert!(
                fixture.writes.try_recv().is_err(),
                "retiring drain must not emit the subsequent extension frame"
            );
            drop(charge);
            assert_eq!(budget.available_bytes(), available);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn owned_writer_commits_before_bytes_and_never_refunds_a_started_failure() {
        use std::sync::atomic::AtomicUsize;

        struct ObservedWriter {
            written: Arc<AtomicUsize>,
            remaining: Option<usize>,
        }
        impl Write for ObservedWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.remaining == Some(0) {
                    return Err(io::Error::other("actual partial writer failure"));
                }
                let length = self
                    .remaining
                    .map_or(bytes.len(), |left| left.min(bytes.len()));
                if let Some(left) = &mut self.remaining {
                    *left -= length;
                }
                self.written.fetch_add(length, Ordering::SeqCst);
                Ok(length)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        for case in ["fenced", "ack_lost", "partial", "written"] {
            let origin = ExtensionOrigin::from_id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
            let (broker, service, mut outgoing) =
                ExtensionHostBroker::channels(origin, LocalPrincipal::UnixUid(123));
            let broker_task = tokio::spawn(service.run());
            broker.extension_message(json!({"kind":"hello","protocol":1,"extensionId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","instanceId":"first-write-fixture","capabilities":{"metadata":true}})).await.unwrap();
            let bound = tokio::time::timeout(Duration::from_secs(5), outgoing.recv())
                .await
                .unwrap()
                .unwrap()
                .into_adapter_request();
            let guard = bound.guard;
            let port_live = Arc::new(AtomicBool::new(case != "fenced"));
            let bytes = Arc::new(AtomicUsize::new(0));
            let (started, start) = oneshot::channel();
            let (completion, done) = oneshot::channel();
            let request = RawWrite {
                body: RawFrameWrite {
                    payload:
                        br#"{"jsonrpc":"2.0","id":"owned-phase","method":"getInfo","params":{}}"#
                            .to_vec(),
                    trace: None,
                    guard: Some(guard.clone()),
                    _charge: None,
                },
                port_live,
                started,
                completion,
            };
            let written = bytes.clone();
            let writer = std::thread::spawn(move || {
                write_owned(
                    &mut ObservedWriter {
                        written,
                        remaining: (case == "partial").then_some(2),
                    },
                    request,
                )
            });
            let start = tokio::time::timeout(Duration::from_secs(5), start)
                .await
                .unwrap();
            assert_eq!(
                bytes.load(Ordering::SeqCst),
                0,
                "no header byte precedes the owner ACK: {case}"
            );
            if case == "fenced" {
                assert!(start.is_err());
                assert!(!guard.was_started());
            } else {
                assert!(
                    guard.was_started(),
                    "the actual guard wins before notifying its owner"
                );
                let acknowledge = start.unwrap();
                if case == "ack_lost" {
                    drop(acknowledge);
                } else {
                    acknowledge.send(Ok(())).unwrap();
                }
            }
            let result = tokio::time::timeout(Duration::from_secs(5), done)
                .await
                .unwrap()
                .unwrap();
            let failed = writer.join().unwrap();
            match case {
                "fenced" => {
                    assert_eq!(result.unwrap(), RawWriteOutcome::FencedBeforeWrite);
                    assert!(failed.is_none());
                    assert_eq!(bytes.load(Ordering::SeqCst), 0);
                }
                "written" => {
                    assert_eq!(result.unwrap(), RawWriteOutcome::Written);
                    assert!(failed.is_none());
                    assert!(bytes.load(Ordering::SeqCst) > 4);
                }
                _ => {
                    assert!(result.is_err());
                    assert!(failed.is_some());
                    assert!(
                        guard.was_started(),
                        "ACK loss/partial failure never becomes an unwritten phase"
                    );
                    assert_eq!(
                        bytes.load(Ordering::SeqCst),
                        if case == "partial" { 2 } else { 0 }
                    );
                }
            }
            broker_task.abort();
            let _ = broker_task.await;
        }
    }
}
