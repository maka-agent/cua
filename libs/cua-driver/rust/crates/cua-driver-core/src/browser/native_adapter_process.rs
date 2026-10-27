// SPDX-License-Identifier: MIT

//! Finite, serialized native-wire adapter actor. Own v1 keeps its direct writer.
//!
//! This is a separate source delta, not a replacement native CDP engine. Raw
//! input and normalized delivery each have a separate bounded byte domain so
//! a queued outgoing payload cannot reserve the bytes needed for its phase ACK.
//! Adapter-private bounded notification buffers are a separate accounting domain.

use super::{
    broker_delivery::{ByteBudget, ByteCharge, Queued},
    native_broker::{BrokerHandle, NativeAdapterRequest, NativeDispatchGuard, NativeOutbound},
    native_framing::{self, Direction, FrameError},
    native_wire::{
        NativeReplyProvenance, NativeRpcTrace, NativeWireAction, NativeWireAdapter,
        NativeWireError, MAX_ACTION_BATCH,
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

#[derive(Debug, thiserror::Error)]
pub(crate) enum AdapterProcessError {
    #[error("native adapter I/O: {0}")]
    Io(#[from] io::Error),
    #[error("native adapter framing: {0}")]
    Frame(#[from] FrameError),
    #[error("native adapter protocol: {0}")]
    Wire(#[from] NativeWireError),
    #[error("native adapter process ended: {0}")]
    Ended(String),
}

struct Semantic {
    guard: NativeDispatchGuard,
    payload: Option<Arc<ByteCharge>>,
    cancelled: bool,
}

struct RawWrite {
    payload: Vec<u8>,
    trace: Option<NativeRpcTrace>,
    guard: Option<NativeDispatchGuard>,
    port_live: Arc<AtomicBool>,
    // The input Value has moved into a native phase. Retain its charge through
    // the physical write/drop even when the adapter releases its own payload.
    _charge: Option<Arc<ByteCharge>>,
    completion: oneshot::Sender<Result<RawWriteOutcome, String>>,
}

#[derive(Debug, PartialEq, Eq)]
enum RawWriteOutcome {
    Written,
    FencedBeforeWrite,
    FencedAfterEarlierWrite,
}

/// One actual protocol frame; no Own chunk envelopes are invented here.
fn write_raw(writer: &mut impl Write, request: &RawWrite) -> Result<RawWriteOutcome, String> {
    // This is the physical dispatch release point. EOF/error fences it even
    // while an async actor branch or admission future was already ready.
    if !request.port_live.load(Ordering::SeqCst) {
        return Ok(
            if request
                .guard
                .as_ref()
                .is_some_and(NativeDispatchGuard::was_started)
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
        // Reverse native requests have no locally minted RPC correlation.
        // Never log their untrusted IDs, methods or params as Host metadata.
        tracing::trace!(
            target: "maka::native_rpc_phase",
            native_host_pid = std::process::id(),
            phase = "frame_written_unattributed",
            "native RPC phase"
        );
    }
    Ok(RawWriteOutcome::Written)
}

enum RawInput {
    Message(Queued<Value>),
    Eof,
}

struct NativeIo {
    input: mpsc::Receiver<RawInput>,
    output: mpsc::Sender<RawWrite>,
    failure: watch::Receiver<Option<String>>,
    port_live: Arc<AtomicBool>,
}

fn spawn_native_io() -> Result<NativeIo, AdapterProcessError> {
    let runtime = tokio::runtime::Handle::current();
    let (input_send, input) = mpsc::channel(8);
    let (output, mut writes) = mpsc::channel::<RawWrite>(1);
    let (failure_send, failure) = watch::channel(None);
    let port_live = Arc::new(AtomicBool::new(true));
    let writer_live = port_live.clone();
    let reader_live = port_live.clone();
    let writer_failure = failure_send.clone();
    std::thread::Builder::new()
        .name("maka-native-adapter-writer".to_owned())
        .spawn(move || {
            let stdout = std::io::stdout();
            let mut stdout = stdout.lock();
            while let Some(request) = writes.blocking_recv() {
                let result = write_raw(&mut stdout, &request);
                let failed = result.as_ref().err().cloned();
                let _ = request.completion.send(result);
                if let Some(reason) = failed {
                    writer_live.store(false, Ordering::SeqCst);
                    writer_failure.send_replace(Some(reason));
                    return;
                }
            }
        })?;
    std::thread::Builder::new()
        .name("maka-native-adapter-reader".to_owned())
        .spawn(move || {
            let stdin = std::io::stdin();
            let mut stdin = stdin.lock();
            let raw_budget = ByteBudget::new();
            loop {
                let value = match native_framing::read_frame(&mut stdin, Direction::ChromeToHost) {
                    Ok(Some(bytes)) => match serde_json::from_slice::<Value>(&bytes) {
                        Ok(value) => value,
                        Err(error) => {
                            reader_live.store(false, Ordering::SeqCst);
                            failure_send.send_replace(Some(error.to_string()));
                            return;
                        }
                    },
                    Ok(None) => {
                        reader_live.store(false, Ordering::SeqCst);
                        // Liveness never waits for raw queue admission. The actor
                        // separately settles already accepted frames with a bound.
                        failure_send.send_replace(Some("Chrome native stdin EOF".to_owned()));
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
    Ok(NativeIo {
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
    provenance: NativeReplyProvenance,
}

/// Pending raw ACKs are not serialized behind a blocked broker admission call.
struct Normalizer {
    budget: ByteBudget,
    sender: mpsc::Sender<Queued<NormalizedMessage>>,
    task: Option<tokio::task::JoinHandle<Result<(), String>>>,
}

impl Normalizer {
    fn new(broker: BrokerHandle) -> Self {
        let (sender, mut input) = mpsc::channel::<Queued<NormalizedMessage>>(16);
        let task = tokio::spawn(async move {
            while let Some(message) = input.recv().await {
                let (message, charge) = message.into_parts();
                // This pump can wait for the broker's shared budget without
                // blocking the serialized adapter or its raw phase input.
                broker
                    .native_adapter_message(message.value, message.provenance)
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
    adapter: Box<dyn NativeWireAdapter>,
    broker: BrokerHandle,
    outgoing: mpsc::Receiver<NativeOutbound>,
    io: NativeIo,
    normalizer: Normalizer,
    pending: HashMap<String, Semantic>,
    cleanup: VecDeque<NativeAdapterRequest>,
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
        )
    )
}

impl Actor {
    async fn reject_unadmitted(
        &mut self,
        request: NativeAdapterRequest,
    ) -> Result<(), AdapterProcessError> {
        let NativeAdapterRequest { message, guard, .. } = request;
        // This path is BEFORE adapter.on_semantic and before any frame can be
        // generated. Never turn an already-started dispatch into local refusal.
        if let Some(report) = guard.reject_before_write(
            "adapter_backpressure".to_owned(),
            "native adapter admission is temporarily backpressured".to_owned(),
        ) {
            drop(message);
            self.broker.write_report(report).await;
            Ok(())
        } else {
            Err(AdapterProcessError::Ended(
                "backpressured request was already started; outcome remains unknown".to_owned(),
            ))
        }
    }

    async fn pressure_input(&mut self, frame: NativeOutbound) -> Result<(), AdapterProcessError> {
        let request = frame.into_adapter_request();
        if cleanup_method(request.message.event()) {
            let bytes =
                native_framing::encode_json(request.message.event(), Direction::ChromeToHost)?;
            if bytes.len() > MAX_CLEANUP_BYTES || self.cleanup.len() >= MAX_DEFERRED_CLEANUP {
                return Err(AdapterProcessError::Ended(
                    "reserved native cleanup admission exceeded its bounded domain".to_owned(),
                ));
            }
            // Exact original context and guard move with this trusted cleanup.
            self.cleanup.push_back(request);
            Ok(())
        } else {
            self.reject_unadmitted(request).await
        }
    }

    async fn failure(&mut self) -> AdapterProcessError {
        AdapterProcessError::Ended(
            self.io
                .failure
                .borrow()
                .clone()
                .unwrap_or_else(|| "native stdio worker ended".to_owned()),
        )
    }

    async fn forward(
        &mut self,
        value: Value,
        provenance: NativeReplyProvenance,
    ) -> Result<(), AdapterProcessError> {
        // A separate charged domain and pump, not an inline broker budget wait.
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
                    _=self.io.failure.changed()=>return Err(self.failure().await),
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
                _=self.io.failure.changed()=>return Err(self.failure().await),
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
        trace: Option<NativeRpcTrace>,
    ) -> Result<(), AdapterProcessError> {
        let guard = match id {
            Some(id) => Some(
                self.pending
                    .get(id)
                    .ok_or_else(|| {
                        AdapterProcessError::Ended(
                            "native phase names a finished semantic request".to_owned(),
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
                    "native port ended before this phase".to_owned(),
                ) {
                    self.broker.write_report(report).await;
                } else if let Some(id) = id {
                    self.cancel_semantic(id).await?;
                }
            }
            return Ok(());
        }
        let payload = match native_framing::encode_json(&message, Direction::HostToChrome) {
            Ok(payload) => payload,
            Err(FrameError::TooLarge { .. }) => {
                if let Some(guard) = &guard {
                    if let Some(report)=guard.reject_before_write("native_message_budget".to_owned(),"selected native protocol cannot encode this frame within Chrome's host-to-browser limit".to_owned()) {
                        self.broker.write_report(report).await;
                        if let Some(id)=id { let actions=self.adapter.on_cancel(id); self.actions(actions).await?; }
                        return Ok(());
                    }
                }
                return Err(AdapterProcessError::Ended("native frame exceeds its protocol limit after an earlier phase; outcome remains unknown".to_owned()));
            }
            Err(error) => return Err(error.into()),
        };
        drop(message);
        let (completion, done) = oneshot::channel();
        let request = RawWrite {
            payload,
            trace,
            guard: guard.clone(),
            port_live: self.io.port_live.clone(),
            _charge: charge,
            completion,
        };
        let sender = self.io.output.clone();
        let deadline = tokio::time::sleep(DRAIN_DEADLINE);
        tokio::pin!(deadline);
        tokio::select! { result=sender.send(request)=>result.map_err(|_|AdapterProcessError::Ended("native writer ended".to_owned()))?, _=self.io.failure.changed()=>return Err(self.failure().await), _=&mut deadline=>return Err(AdapterProcessError::Ended("native writer admission deadline expired; outcome remains unknown".to_owned())) };
        let result = tokio::select! { result=done=>result.map_err(|_|AdapterProcessError::Ended("native write completion was lost; outcome remains unknown".to_owned()))?.map_err(AdapterProcessError::Ended)?, _=self.io.failure.changed()=>return Err(self.failure().await), _=&mut deadline=>return Err(AdapterProcessError::Ended("native write deadline expired; outcome remains unknown".to_owned())) };
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
                        "native execution fence closed before dispatch".to_owned(),
                    ) {
                        self.broker.write_report(report).await;
                    }
                }
            }
            RawWriteOutcome::FencedAfterEarlierWrite => {
                if let Some(id) = id {
                    // A follow-up fence may follow an actual custody ACK.
                    // Retain Pending and guard until terminal ACK/Unknown with
                    // custody, or EOF/expiry; Own incomplete chunks differ.
                    self.cancel_semantic(id).await?;
                }
            }
        }
        Ok(())
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

    // Recursive action emission is boxed only because cancel may emit actions;
    // the concrete adapter never recursively invokes the host actor.
    fn actions<'a>(
        &'a mut self,
        actions: Vec<NativeWireAction>,
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
                if let NativeWireAction::NativeFrame {
                    semantic_id: Some(id),
                    ..
                } = action
                {
                    *frames.entry(id.clone()).or_default() += 1;
                    if let Some(charge) =
                        self.pending.get(id).and_then(|entry| entry.payload.clone())
                    {
                        payloads.insert(id.clone(), charge);
                    }
                }
            }
            let mut finished = Vec::new();
            let mut terminal_reason = None;
            for action in actions {
                match action {
                    NativeWireAction::NativeFrame {
                        message,
                        semantic_id,
                        trace,
                    } => {
                        if terminal_reason.is_some() {
                            // A malformed adapter tail cannot release more
                            // native effects after a protocol-ending marker.
                            continue;
                        }
                        let charge = semantic_id
                            .as_ref()
                            .and_then(|id| payloads.get(id).cloned());
                        self.write_phase(message, semantic_id.as_deref(), charge, trace)
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
                    NativeWireAction::SemanticPayloadReleased { semantic_id } => {
                        if let Some(entry) = self.pending.get_mut(&semantic_id) {
                            entry.payload = None;
                        }
                    }
                    NativeWireAction::SemanticFinished { semantic_id } => {
                        finished.push(semantic_id)
                    }
                    NativeWireAction::BrokerMessage(value) => {
                        self.forward(value, NativeReplyProvenance::Adapted).await?
                    }
                    NativeWireAction::MatchedBrokerMessage { message, terminal } => {
                        self.forward(message, NativeReplyProvenance::Matched(terminal))
                            .await?
                    }
                    NativeWireAction::Diagnostic {
                        semantic_id,
                        message,
                    } => {
                        tracing::debug!(semantic_id = ?semantic_id, diagnostic = %message, "native browser adapter diagnostic");
                    }
                    NativeWireAction::TransportEnded { reason } => {
                        self.io.port_live.store(false, Ordering::SeqCst);
                        if terminal_reason.is_none() {
                            terminal_reason = Some(reason);
                        }
                    }
                }
            }
            for id in finished {
                self.pending.remove(&id);
            }
            match terminal_reason {
                Some(reason) => Err(AdapterProcessError::Ended(reason)),
                None => Ok(()),
            }
        })
    }

    async fn semantic(&mut self, request: NativeAdapterRequest) -> Result<(), AdapterProcessError> {
        let NativeAdapterRequest {
            message,
            semantic_id,
            wire_context,
            guard,
        } = request;
        if !guard.is_live() {
            if let Some(report) = guard.reject_before_write(
                "not_dispatched".to_owned(),
                "native execution fence closed before adapter admission".to_owned(),
            ) {
                self.broker.write_report(report).await;
            }
            return Ok(());
        }
        if self.pending.len() >= MAX_SEMANTICS && semantic_id.is_some() {
            return self
                .reject_unadmitted(NativeAdapterRequest {
                    message,
                    semantic_id,
                    wire_context,
                    guard,
                })
                .await;
        }
        let bound = message.event()["kind"] == "bound";
        let (value, charge) = message.into_parts();
        if let Some(id) = &semantic_id {
            if self.pending.contains_key(id) {
                return Err(AdapterProcessError::Ended(
                    "semantic IDs cannot be replayed within native generation".to_owned(),
                ));
            }
            self.pending.insert(
                id.clone(),
                Semantic {
                    guard: guard.clone(),
                    payload: charge,
                    cancelled: false,
                },
            );
        } else {
            drop(charge);
        }
        match self
            .adapter
            .on_semantic(value, wire_context.as_ref(), Instant::now())
        {
            Ok(actions) => self.actions(actions).await?,
            Err(NativeWireError::LocalRefusal { code, message }) => {
                // The selected adapter contract guarantees errors retain no
                // input Value. No NativeFrame was returned on this path.
                if let Some(id) = &semantic_id {
                    if let Some(entry) = self.pending.get_mut(id) {
                        entry.payload = None;
                    }
                }
                if let Some(report) = guard.reject_before_write(code, message) {
                    self.broker.write_report(report).await;
                } else {
                    return Err(AdapterProcessError::Ended(
                        "adapter refusal followed an earlier native phase; outcome remains unknown"
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
                frame=self.outgoing.recv()=>match frame {Some(frame)=>self.semantic(frame.into_adapter_request()).await?,None=>return Ok(())},
                raw=self.io.input.recv()=>match raw {
                    Some(RawInput::Message(raw))=>{let (value,charge)=raw.into_parts();let actions=self.adapter.on_native(value,Instant::now())?;self.actions(actions).await?;drop(charge);},
                    Some(RawInput::Eof)|None=>return Ok(()),
                }
            }
        }
    }
}

/// Run only for an explicitly installed/reviewed non-Own adapter selection.
pub(crate) async fn run(
    adapter: Box<dyn NativeWireAdapter>,
    broker: BrokerHandle,
    outgoing: mpsc::Receiver<NativeOutbound>,
    ready: oneshot::Sender<Result<(), String>>,
) -> Result<(), AdapterProcessError> {
    let io = spawn_native_io()?;
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
    // No new native phase may be sent after the liveness fence.
    let settlement = async {
        while let Ok(RawInput::Message(raw)) = actor.io.input.try_recv() {
            let (value, charge) = raw.into_parts();
            if let Ok(actions) = actor.adapter.on_native(value, Instant::now()) {
                let _ = actor.actions(actions).await;
            }
            drop(charge);
        }
    };
    let _ = tokio::time::timeout(DRAIN_DEADLINE, settlement).await;
    let reason = result
        .as_ref()
        .err()
        .map_or("Chrome native stdin EOF".to_owned(), ToString::to_string);
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
                // deliver earlier actual native replies before the EOF fence.
                let _ = actor.reject_unadmitted(frame.into_adapter_request()).await;
            } else { break; },
        }
    }
    broker.native_eof(&reason).await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn raw_writer_uses_native_endian_header_and_exact_json_bytes() {
        let payload = br#"{"jsonrpc":"2.0","id":1,"method":"getInfo"}"#.to_vec();
        let (completion, _) = oneshot::channel();
        let request = RawWrite {
            trace: None,
            payload: payload.clone(),
            guard: None,
            port_live: Arc::new(AtomicBool::new(true)),
            _charge: None,
            completion,
        };
        let mut writer = Cursor::new(Vec::new());
        assert_eq!(
            write_raw(&mut writer, &request).unwrap(),
            RawWriteOutcome::Written
        );
        let bytes = writer.into_inner();
        assert_eq!(&bytes[..4], &(payload.len() as u32).to_ne_bytes());
        assert_eq!(&bytes[4..], payload);
    }

    #[test]
    fn passive_frame_trace_requires_complete_flush_and_contains_only_captured_metadata() {
        use super::super::native_wire::{rpc_phase_test::Capture, NativeWireContext};
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
        let context = NativeWireContext::new("session-old", "turn-old").unwrap();
        let (completion, _) = oneshot::channel();
        let request = RawWrite {
            payload: br#"{"params":{"url":"PAYLOAD_URL_SENTINEL","headers":"HEADER_SENTINEL"}}"#
                .to_vec(),
            trace: Some(NativeRpcTrace::captured(
                "generation-old",
                "maka-original-compat:generation-old:9",
                "claimUserTab",
                Some("42"),
                Some("owner-old"),
                Some(&context),
            )),
            guard: None,
            port_live: Arc::new(AtomicBool::new(false)),
            _charge: None,
            completion,
        };
        tracing::subscriber::with_default(capture.clone(), || {
            assert_eq!(
                write_raw(&mut Cursor::new(Vec::new()), &request).unwrap(),
                RawWriteOutcome::FencedBeforeWrite
            );
            assert!(
                capture.rows().is_empty(),
                "a fence cannot produce write completion"
            );
            request.port_live.store(true, Ordering::SeqCst);
            assert!(write_raw(&mut FlushFailure, &request).is_err());
            assert!(
                capture.rows().is_empty(),
                "a partial write/failed flush cannot produce write completion"
            );
            let mut bytes = Cursor::new(Vec::new());
            assert_eq!(
                write_raw(&mut bytes, &request).unwrap(),
                RawWriteOutcome::Written
            );
            assert_eq!(&bytes.get_ref()[4..], request.payload);
        });
        let rows = capture.rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["phase"], "frame_written");
        assert_eq!(rows[0]["native_method"], "claimUserTab");
        assert_eq!(
            rows[0]["native_rpc_id"],
            "maka-original-compat:generation-old:9"
        );
        assert_eq!(rows[0]["native_host_pid"], std::process::id().to_string());
        assert_eq!(rows[0]["host_turn_id"], "Some(\"turn-old\")");
        let fields = format!("{rows:?}");
        assert!(!fields.contains("PAYLOAD_URL_SENTINEL") && !fields.contains("HEADER_SENTINEL"));
    }

    #[test]
    fn selected_protocol_large_frame_refuses_before_native_io() {
        let message = serde_json::json!({"params":{"data":"x".repeat(1024*1024)}});
        assert!(matches!(
            native_framing::encode_json(&message, Direction::HostToChrome),
            Err(FrameError::TooLarge {
                direction: Direction::HostToChrome,
                ..
            })
        ));
    }

    #[test]
    fn port_eof_fences_an_already_queued_raw_frame() {
        let live = Arc::new(AtomicBool::new(true));
        let (completion, _) = oneshot::channel();
        let request = RawWrite {
            trace: None,
            payload: br#"{"id":1,"method":"getInfo"}"#.to_vec(),
            guard: None,
            port_live: live.clone(),
            _charge: None,
            completion,
        };
        live.store(false, Ordering::SeqCst);
        let mut writer = Cursor::new(Vec::new());
        assert_eq!(
            write_raw(&mut writer, &request).unwrap(),
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
            native_broker::{LocalPrincipal, NativeHostBroker},
            native_host::ExtensionOrigin,
            native_wire::{MatchedNativeReply, NativeWireContext, OwnWireAdapter},
        };
        use serde_json::json;

        let origin = ExtensionOrigin::from_id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let (handle, broker, mut outgoing) =
            NativeHostBroker::channels(origin, LocalPrincipal::UnixUid(123));
        let broker_task = tokio::spawn(broker.run());
        handle.native_message(json!({"kind":"hello","protocol":1,"extensionId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","instanceId":"terminal-fixture","capabilities":{"metadata":true,"rawTabCdp":true}})).await.unwrap();
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
            adapter: Box::new(OwnWireAdapter::default()),
            broker: handle.clone(),
            outgoing,
            io: NativeIo {
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
            let custody = json!({"kind":"response","protocol":1,"id":id,"error":{"kind":"outcome_unknown","message":"native protocol ended after attach acknowledgement","details":{"nativeAcknowledged":true,"nativeReplyMatched":true,"custody":{"claim":format!("actual-attach-receipt-{index}"),"tabId":index,"acquisitionConfirmed":true}}}});
            expected.push(custody.clone());
            actions.push(NativeWireAction::SemanticPayloadReleased {
                semantic_id: id.clone(),
            });
            if index == 0 {
                actions.push(NativeWireAction::MatchedBrokerMessage {
                    message: custody,
                    terminal: MatchedNativeReply::from_matched_rpc(
                        "fixture-generation".to_owned(),
                        "fixture-owner".to_owned(),
                        id.clone(),
                        Some(NativeWireContext::new("fixture-session", "fixture-turn").unwrap()),
                    ),
                });
            } else {
                // A JSON flag cannot upgrade a source-unknown completion.
                actions.push(NativeWireAction::BrokerMessage(custody));
            }
            actions.push(NativeWireAction::SemanticFinished { semantic_id: id });
        }
        actions.push(NativeWireAction::TransportEnded {
            reason: "matched protocol violation".to_owned(),
        });
        actions.push(NativeWireAction::NativeFrame {
            message: json!({"method":"must-not-dispatch"}),
            semantic_id: None,
            trace: None,
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
                let NativeReplyProvenance::Matched(evidence) = normalized.provenance else {
                    panic!("actual matcher evidence must survive terminal normalization");
                };
                assert!(evidence.matches(
                    "fixture-generation",
                    "fixture-owner",
                    "fixture-terminal-0",
                    Some(&NativeWireContext::new("fixture-session", "fixture-turn").unwrap()),
                ));
            } else {
                assert!(
                    matches!(normalized.provenance, NativeReplyProvenance::Adapted),
                    "native/page JSON fields cannot manufacture a matched Rust reply"
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
            "a terminal batch cannot release a later native frame"
        );
        broker_task.abort();
        let _ = broker_task.await;
    }
}
