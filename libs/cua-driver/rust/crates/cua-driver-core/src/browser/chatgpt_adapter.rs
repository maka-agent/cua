// SPDX-License-Identifier: MIT

//! ChatGPT extension wire adapter for the finite Host and Cua provider.
//!
//! This translates transport operations. Host authorization, origin/turn policy,
//! selectors, input, screenshots, CDP pending calls and engine state stay in the
//! Host/Cua implementation.

use super::chatgpt_inventory::{
    self, AbsenceEvidence, Caller, EndpointIdentity, InventoryFreshness, KnownCreated,
};
use super::chatgpt_rpc_v2::{
    Completion, LossCause, Method, Outbound, Reply, RequestId, RpcCodec, RpcError, RpcEvent,
};
use super::chatgpt_tab_id::parse_browser_tab_id;
use super::extension_wire::{
    ExtensionRpcTrace, ExtensionWireAction, ExtensionWireAdapter, ExtensionWireContext,
    ExtensionWireError, MatchedExtensionReply,
};
use serde_json::{json, value::RawValue, Map, Value};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(20);
const MAX_TASKS: usize = 192;
const _: () = assert!(3 * MAX_TASKS < super::extension_wire::MAX_ACTION_BATCH);
const MAX_NORMAL_TASKS: usize = 64;
const MAX_CLAIMS: usize = 256;
const MAX_CHILDREN: usize = 1024;
const MAX_EARLY_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug)]
struct Call {
    outer: String,
    owner: String,
    context: Option<ExtensionWireContext>,
    cancelled: bool,
    payload_released: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AttachmentIdentity {
    Confirmed,
    ReconciliationRequired,
}

#[derive(Clone, Debug)]
struct Claim {
    owner: String,
    session: String,
    turn: String,
    tab: u64,
    target: String,
    live: bool,
    identity: AttachmentIdentity,
}

#[derive(Clone, Debug)]
struct ChildSession {
    parent: Option<String>,
    target: Option<String>,
    state: ChildState,
    attach_order: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChildState {
    Live,
    AwaitingAttachAck,
    DetachedWhileAttachPending,
}

#[derive(Clone, Debug)]
struct CdpScope {
    claim: String,
    tab: u64,
    method: String,
    parent: Option<String>,
    target: Option<String>,
    child: Option<String>,
    attach_revoked: bool,
}

#[derive(Clone, Debug)]
struct Attaching {
    owner: String,
    session: String,
    turn: String,
    revoked: bool,
    events: Vec<(String, Value, Option<String>)>,
    event_bytes: usize,
}

#[derive(Clone, Debug)]
struct Creation {
    owner: String,
    session: String,
    turn: String,
    tab_id: u64,
    endpoint: EndpointIdentity,
    finish_observed: bool,
}

#[derive(Clone, Debug)]
struct CloseScope {
    claim: String,
    tab: u64,
    target: String,
    creations: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TurnPhase {
    Active,
    Finishing,
    Finished,
    ActivationUnknown,
    FinishUnknown,
}

#[derive(Clone, Debug)]
struct SessionTurn {
    owner: String,
    turn: String,
    epoch: u64,
    phase: TurnPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InventorySource {
    User,
    ManagedSession,
}

#[derive(Clone, Debug)]
enum PreparationPurpose {
    UserObserved { normalize_candidate: bool },
    Session,
}

#[derive(Clone, Debug)]
enum Stage {
    Bootstrap,
    UserHistory,
    NameSession,
    Inventory,
    SessionInventory,
    UserTabRead,
    Resolve {
        tab: u64,
        source: InventorySource,
        session_only: bool,
    },
    CommittedUrl {
        tab: u64,
    },
    PrepareBefore(u64),
    PrepareClaim {
        tab: u64,
        purpose: PreparationPurpose,
    },
    Create,
    ClaimForAttach(u64),
    PreTargets(u64),
    Attach(u64),
    Probe(u64),
    Targets(u64),
    Cdp(CdpScope),
    Detach(String),
    Close(CloseScope),
    Finish,
    Mark {
        tab: u64,
        status: String,
    },
    ObserveCreated(String),
    SessionHeaders {
        active: bool,
    },
    MoveMouse {
        arrival_requested: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WritePhase {
    Unwritten,
    AfterEarlierWrite,
    Started,
}

#[derive(Clone, Debug)]
struct Task {
    call: Option<Call>,
    stage: Stage,
    candidate_target: Option<String>,
    attach_acknowledged: bool,
    finish_observed: bool,
    activation_epoch: Option<u64>,
    write_phase: WritePhase,
    initial_attach: Option<u64>,
}

/// One extension-port generation; the host serializes all trait calls.
pub(crate) struct ChatgptWireAdapter {
    generation: String,
    expected_extension: String,
    rpc: RpcCodec,
    tasks: HashMap<RequestId, Task>,
    leases: HashMap<u64, (String, String)>,
    claims: HashMap<String, Claim>,
    current_claim: HashMap<u64, String>,
    creations: HashMap<String, Creation>,
    children: HashMap<(u64, String), ChildSession>,
    session_turns: HashMap<String, SessionTurn>,
    next_session_epoch: u64,
    attaching: HashMap<u64, Attaching>,
    started: bool,
    ready: bool,
    ended: bool,
    extension_instance: Option<String>,
    early_bytes: usize,
}

impl ChatgptWireAdapter {
    pub(crate) fn new(
        generation: String,
        expected_extension: String,
    ) -> Result<Self, ExtensionWireError> {
        let rpc = RpcCodec::new(generation.clone(), 256)
            .map_err(|error| ExtensionWireError::Protocol(error.to_string()))?;
        Ok(Self {
            generation,
            expected_extension,
            rpc,
            tasks: HashMap::new(),
            leases: HashMap::new(),
            claims: HashMap::new(),
            current_claim: HashMap::new(),
            creations: HashMap::new(),
            children: HashMap::new(),
            session_turns: HashMap::new(),
            next_session_epoch: 0,
            attaching: HashMap::new(),
            started: false,
            ready: false,
            ended: false,
            extension_instance: None,
            early_bytes: 0,
        })
    }

    fn queue(
        &mut self,
        mut task: Task,
        method: Method,
        params: Value,
        now: Instant,
    ) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
        if let Some(call) = task.call.as_ref() {
            if activates_session(method) {
                let context = self.context(call)?;
                if matches!(task.stage, Stage::SessionHeaders { active: false })
                    && self
                        .session_turns
                        .get(context.host_session_id())
                        .is_some_and(|turn| turn.phase == TurnPhase::Finished)
                {
                    return Err(ExtensionWireError::LocalRefusal {
                        code: "turn_finished".to_owned(),
                        message: "Header cleanup cannot reactivate a finished browser usage"
                            .to_owned(),
                    });
                }
                self.validate_activation(call)?;
            } else if matches!(task.stage, Stage::Finish) {
                self.validate_finish(call)?;
            }
        }
        let Outbound { id, message } =
            self.rpc
                .begin(method, params, now + DEADLINE)
                .map_err(|error| ExtensionWireError::LocalRefusal {
                    code: "request_budget".to_owned(),
                    message: error.to_string(),
                })?;
        if task.write_phase == WritePhase::Started {
            task.write_phase = WritePhase::AfterEarlierWrite;
        }
        let semantic_id = task.call.as_ref().map(|call| call.outer.clone());
        let released = task
            .call
            .as_mut()
            .filter(|call| !call.payload_released)
            .map(|call| {
                call.payload_released = true;
                call.outer.clone()
            });
        let trace = tracing::enabled!(target: "maka::extension_rpc_phase", tracing::Level::TRACE)
            .then(|| {
                ExtensionRpcTrace::captured(
                    &self.generation,
                    id.as_str(),
                    method.as_str(),
                    semantic_id.as_deref(),
                    task.call.as_ref().map(|call| call.owner.as_str()),
                    task.call.as_ref().and_then(|call| call.context.as_ref()),
                )
            });
        self.tasks.insert(id.clone(), task);
        let mut actions = vec![ExtensionWireAction::ExtensionFrame {
            message,
            semantic_id,
            trace,
            phase: Some(id),
        }];
        if let Some(semantic_id) = released {
            actions.push(ExtensionWireAction::SemanticPayloadReleased { semantic_id });
        }
        Ok(actions)
    }

    fn success(&self, call: &Call, result: Value) -> Vec<ExtensionWireAction> {
        let mut actions = Vec::new();
        if !call.payload_released {
            actions.push(ExtensionWireAction::SemanticPayloadReleased {
                semantic_id: call.outer.clone(),
            });
        }
        actions.push(ExtensionWireAction::BrokerMessage(json!({
            "kind":"response","protocol":1,"generation":self.generation,"id":call.outer,"result":result
        })));
        actions.push(ExtensionWireAction::SemanticFinished {
            semantic_id: call.outer.clone(),
        });
        actions
    }

    fn failure(
        &self,
        call: &Call,
        kind: &str,
        message: &str,
        details: Value,
    ) -> Vec<ExtensionWireAction> {
        let mut actions = Vec::new();
        if !call.payload_released {
            actions.push(ExtensionWireAction::SemanticPayloadReleased {
                semantic_id: call.outer.clone(),
            });
        }
        actions.push(ExtensionWireAction::BrokerMessage(json!({
            "kind":"response","protocol":1,"generation":self.generation,"id":call.outer,
            "error":{"kind":kind,"message":message,"details":details}
        })));
        actions.push(ExtensionWireAction::SemanticFinished {
            semantic_id: call.outer.clone(),
        });
        actions
    }

    fn context<'a>(
        &mut self,
        call: &'a Call,
    ) -> Result<&'a ExtensionWireContext, ExtensionWireError> {
        let context = call
            .context
            .as_ref()
            .ok_or_else(|| ExtensionWireError::LocalRefusal {
                code: "wire_context_required".to_owned(),
                message: "ChatGPT mutation requires immutable trusted Host session and turn"
                    .to_owned(),
            })?;
        // Canonical identity comes from Main SessionOwner.browser_owner().
        let session = uuid::Uuid::parse_str(context.host_session_id()).map_err(|_| {
            ExtensionWireError::LocalRefusal {
                code: "wire_context_invalid".to_owned(),
                message: "Host session must be its canonical UUID".to_owned(),
            }
        })?;
        if session.to_string() != context.host_session_id() {
            return Err(ExtensionWireError::LocalRefusal {
                code: "wire_context_invalid".to_owned(),
                message: "Host session UUID must be standard hyphenated form".to_owned(),
            });
        }
        let foreign_claim = self
            .claims
            .values()
            .any(|value| value.session == context.host_session_id() && value.owner != call.owner);
        let foreign_creation = self
            .creations
            .values()
            .any(|value| value.session == context.host_session_id() && value.owner != call.owner);
        let foreign_lease = self
            .leases
            .values()
            .any(|(owner, session)| session == context.host_session_id() && owner != &call.owner);
        let foreign_pending =
            self.tasks
                .values()
                .filter_map(|task| task.call.as_ref())
                .any(|value| {
                    value.owner != call.owner
                        && value.context.as_ref().is_some_and(|scope| {
                            scope.host_session_id() == context.host_session_id()
                        })
                });
        let foreign_transition = self
            .session_turns
            .get(context.host_session_id())
            .is_some_and(|current| {
                current.owner != call.owner && current.phase != TurnPhase::Finished
            });
        if foreign_claim
            || foreign_creation
            || foreign_lease
            || foreign_pending
            || foreign_transition
        {
            return Err(ExtensionWireError::LocalRefusal {
                code: "session_has_foreign_custody".to_owned(),
                message: "Canonical Host session still has another connection's unresolved custody"
                    .to_owned(),
            });
        }
        Ok(context)
    }

    fn params(&mut self, call: &Call, fields: Value) -> Result<Value, ExtensionWireError> {
        let context = self.context(call)?;
        let Value::Object(mut params) = fields else {
            return Err(ExtensionWireError::Protocol(
                "ChatGPT method parameters must be an object".to_owned(),
            ));
        };
        for reserved in [
            "session_id",
            "turn_id",
            "session_context",
            "agent_request_header_enabled",
            "request_headers",
        ] {
            if params.contains_key(reserved) {
                return Err(ExtensionWireError::Protocol(
                    "Method fields attempted to override trusted context/header policy".to_owned(),
                ));
            }
        }
        params.insert("session_id".to_owned(), json!(context.host_session_id()));
        params.insert("turn_id".to_owned(), json!(context.host_turn_id()));
        params.insert("session_context".to_owned(), json!("live"));
        Ok(Value::Object(params))
    }

    fn owned_claim(&self, call: &Call, token: &str) -> Result<Claim, ExtensionWireError> {
        let claim = self.cleanup_claim(call, token)?;
        if !claim.live || claim.identity != AttachmentIdentity::Confirmed {
            return Err(ExtensionWireError::LocalRefusal {
                code: "claim_unavailable".to_owned(),
                message: "ChatGPT claim is not executable".to_owned(),
            });
        }
        Ok(claim)
    }
    fn claim_record(&self, call: &Call, token: &str) -> Result<Claim, ExtensionWireError> {
        let session = call
            .context
            .as_ref()
            .map(ExtensionWireContext::host_session_id);
        self.claims
            .get(token)
            .filter(|claim| claim.owner == call.owner && Some(claim.session.as_str()) == session)
            .cloned()
            .ok_or_else(|| ExtensionWireError::LocalRefusal {
                code: "claim_unavailable".to_owned(),
                message: "ChatGPT claim is foreign, revoked or outside this Host session"
                    .to_owned(),
            })
    }

    fn cleanup_claim(&self, call: &Call, token: &str) -> Result<Claim, ExtensionWireError> {
        let claim = self.claim_record(call, token)?;
        if self.current_claim.get(&claim.tab).map(String::as_str) != Some(token) {
            return Err(ExtensionWireError::LocalRefusal {
                code: "claim_unavailable".to_owned(),
                message: "Unsettled claim is not the current raw-tab epoch".to_owned(),
            });
        }
        Ok(claim)
    }
    fn partial_attachment(&mut self, task: &Task, call: &Call) -> Option<Value> {
        if !task.attach_acknowledged {
            return None;
        }
        let tab = match task.stage {
            Stage::Attach(tab) | Stage::Probe(tab) | Stage::Targets(tab) => tab,
            _ => return None,
        };
        let target = task.candidate_target.as_ref()?.clone();
        let context = call.context.as_ref()?;
        let existing = self.current_claim.get(&tab).and_then(|token| {
            self.claims
                .get(token)
                .filter(|claim| {
                    claim.owner == call.owner
                        && claim.session == context.host_session_id()
                        && claim.target == target
                })
                .map(|_| token.clone())
        });
        let token = existing.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        self.claims.insert(
            token.clone(),
            Claim {
                owner: call.owner.clone(),
                session: context.host_session_id().to_owned(),
                turn: context.host_turn_id().to_owned(),
                tab,
                target: target.clone(),
                live: false,
                identity: AttachmentIdentity::ReconciliationRequired,
            },
        );
        self.current_claim.insert(tab, token.clone());
        Some(json!({"claim":token,"tabId":tab,"targetId":target,"acquisitionConfirmed":false}))
    }
    fn session_slot(&self, call: &Call) -> Result<(), ExtensionWireError> {
        let context = call.context.as_ref().ok_or_else(|| {
            ExtensionWireError::Protocol(
                "ChatGPT session operation lost its trusted context".to_owned(),
            )
        })?;
        if !self.session_turns.contains_key(context.host_session_id())
            && self.session_turns.len() >= MAX_CLAIMS
        {
            return Err(ExtensionWireError::LocalRefusal {
                code: "session_budget".to_owned(),
                message: "ChatGPT extension session custody budget is exhausted".to_owned(),
            });
        }
        if self.next_session_epoch == u64::MAX {
            return Err(ExtensionWireError::LocalRefusal {
                code: "session_budget".to_owned(),
                message: "ChatGPT extension session epoch is exhausted".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_activation(&mut self, call: &Call) -> Result<(), ExtensionWireError> {
        let context = self.context(call)?;
        if let Some(current) = self.session_turns.get(context.host_session_id()) {
            if matches!(
                current.phase,
                TurnPhase::ActivationUnknown | TurnPhase::FinishUnknown | TurnPhase::Finishing
            ) {
                return Err(ExtensionWireError::LocalRefusal {
                    code: "session_unavailable".to_owned(),
                    message: "ChatGPT session has an unresolved transition or finish".to_owned(),
                });
            }
        }
        self.session_slot(call)
    }

    fn validate_finish(&mut self, call: &Call) -> Result<(), ExtensionWireError> {
        let context = self.context(call)?;
        if let Some(current) = self.session_turns.get(context.host_session_id()) {
            if current.turn != context.host_turn_id()
                || !matches!(
                    current.phase,
                    TurnPhase::Active | TurnPhase::ActivationUnknown
                )
            {
                return Err(ExtensionWireError::LocalRefusal {
                    code: "turn_finish_unavailable".to_owned(),
                    message: "ChatGPT turn finish is stale or has already been admitted; it is not replayed".to_owned(),
                });
            }
        }
        self.session_slot(call)
    }

    fn admit_activation(&mut self, call: &Call) -> u64 {
        let context = call
            .context
            .as_ref()
            .expect("validated ChatGPT session context");
        let session = context.host_session_id();
        let turn = context.host_turn_id();
        if let Some(current) = self.session_turns.get(session) {
            if current.turn == turn && current.phase == TurnPhase::Active {
                return current.epoch;
            }
        }
        self.next_session_epoch += 1;
        let epoch = self.next_session_epoch;
        self.session_turns.insert(
            session.to_owned(),
            SessionTurn {
                owner: call.owner.clone(),
                turn: turn.to_owned(),
                epoch,
                phase: TurnPhase::Active,
            },
        );
        // Chatgpt activateTurn moves the whole logical session's leases. The
        // immutable Host context is canonical; reply arrival cannot move it back.
        for claim in self
            .claims
            .values_mut()
            .filter(|claim| claim.owner == call.owner && claim.session == session)
        {
            claim.turn = turn.to_owned();
        }
        for creation in self
            .creations
            .values_mut()
            .filter(|creation| creation.owner == call.owner && creation.session == session)
        {
            creation.turn = turn.to_owned();
            creation.finish_observed = false;
        }
        for task in self.tasks.values_mut() {
            if let Some(pending) = task.call.as_mut() {
                if pending.owner == call.owner
                    && pending.context.as_ref().is_some_and(|scope| {
                        scope.host_session_id() == session && scope.host_turn_id() != turn
                    })
                {
                    pending.cancelled = true;
                }
            }
        }
        for pending in self.attaching.values_mut().filter(|pending| {
            pending.owner == call.owner && pending.session == session && pending.turn != turn
        }) {
            pending.revoked = true;
        }
        epoch
    }

    fn admit_finish(&mut self, call: &Call) -> u64 {
        let context = call
            .context
            .as_ref()
            .expect("validated ChatGPT finish context");
        let session = context.host_session_id();
        let turn = context.host_turn_id();
        let epoch = if let Some(current) = self.session_turns.get_mut(session) {
            current.phase = TurnPhase::Finishing;
            current.epoch
        } else {
            self.next_session_epoch += 1;
            let epoch = self.next_session_epoch;
            self.session_turns.insert(
                session.to_owned(),
                SessionTurn {
                    owner: call.owner.clone(),
                    turn: turn.to_owned(),
                    epoch,
                    phase: TurnPhase::Finishing,
                },
            );
            epoch
        };
        for task in self.tasks.values_mut() {
            if let Some(pending) = task.call.as_mut() {
                if pending.owner == call.owner
                    && pending
                        .context
                        .as_ref()
                        .is_some_and(|scope| scope.host_session_id() == session)
                {
                    pending.cancelled = true;
                }
            }
        }
        for pending in self
            .attaching
            .values_mut()
            .filter(|pending| pending.owner == call.owner && pending.session == session)
        {
            pending.revoked = true;
        }
        for claim in self
            .claims
            .values_mut()
            .filter(|claim| claim.owner == call.owner && claim.session == session)
        {
            claim.live = false;
        }
        let tabs: HashSet<_> = self
            .claims
            .values()
            .filter(|claim| claim.owner == call.owner && claim.session == session)
            .map(|claim| claim.tab)
            .collect();
        self.children.retain(|(root, _), _| !tabs.contains(root));
        epoch
    }

    fn finish_observed(&mut self, call: &Call, epoch: Option<u64>) {
        if let Some(scope) = call.context.as_ref() {
            if let Some(current) = self.session_turns.get_mut(scope.host_session_id()) {
                if Some(current.epoch) == epoch && current.turn == scope.host_turn_id() {
                    current.phase = TurnPhase::Finished;
                }
            }
            self.leases.retain(|_, (owner, session)| {
                owner != &call.owner || session != scope.host_session_id()
            });
            for creation in self.creations.values_mut().filter(|value| {
                value.owner == call.owner
                    && value.session == scope.host_session_id()
                    && value.turn == scope.host_turn_id()
            }) {
                creation.finish_observed = true;
            }
            for task in self.tasks.values_mut() {
                if task.call.as_ref().is_some_and(|value| {
                    value.owner == call.owner
                        && value.context.as_ref().is_some_and(|value| {
                            value.host_session_id() == scope.host_session_id()
                                && value.host_turn_id() == scope.host_turn_id()
                        })
                }) {
                    task.finish_observed = true;
                }
            }
        }
    }

    fn retire_claim(&mut self, token: &str) -> Option<Claim> {
        let claim = self.claims.remove(token)?;
        if self.current_claim.get(&claim.tab).map(String::as_str) == Some(token) {
            self.current_claim.remove(&claim.tab);
            self.children.retain(|(root, _), _| *root != claim.tab);
            self.retire_attaching(claim.tab);
        }
        Some(claim)
    }

    fn retire_closed_scope(&mut self, call: &Call, scope: &CloseScope, epoch: Option<u64>) {
        let Some(context) = call.context.as_ref() else {
            return;
        };
        if self.claims.get(&scope.claim).is_some_and(|claim| {
            claim.owner != call.owner
                || claim.session != context.host_session_id()
                || claim.tab != scope.tab
                || claim.target != scope.target
        }) {
            return;
        }
        let newer_claim = self
            .current_claim
            .get(&scope.tab)
            .is_some_and(|token| token != &scope.claim);
        self.retire_claim(&scope.claim);
        let generation = self.generation.as_str();
        let instance = self.extension_instance.as_deref();
        self.creations.retain(|token, creation| {
            !scope.creations.contains(token)
                || creation.owner != call.owner
                || creation.session != context.host_session_id()
                || creation.tab_id != scope.tab
                || creation.endpoint.generation.as_str() != generation
                || Some(creation.endpoint.extension_instance_id.as_str()) != instance
        });
        let same_epoch = self
            .session_turns
            .get(context.host_session_id())
            .is_some_and(|turn| {
                Some(turn.epoch) == epoch
                    && turn.owner == call.owner
                    && turn.turn == context.host_turn_id()
            });
        if !newer_claim
            && same_epoch
            && self.leases.get(&scope.tab).is_some_and(|(owner, session)| {
                owner == &call.owner && session == context.host_session_id()
            })
        {
            self.leases.remove(&scope.tab);
        }
    }

    fn uncertain_activation(&mut self, call: &Call, epoch: Option<u64>, expected: TurnPhase) {
        let Some(context) = call.context.as_ref() else {
            return;
        };
        let Some(current) = self.session_turns.get_mut(context.host_session_id()) else {
            return;
        };
        // An older in-flight response must not rewrite a newer admitted turn.
        if Some(current.epoch) != epoch
            || current.turn != context.host_turn_id()
            || current.phase != expected
        {
            return;
        }
        current.phase = if expected == TurnPhase::Finishing {
            TurnPhase::FinishUnknown
        } else {
            TurnPhase::ActivationUnknown
        };
        for claim in self
            .claims
            .values_mut()
            .filter(|claim| claim.owner == call.owner && claim.session == context.host_session_id())
        {
            claim.live = false;
        }
        for pending in self.attaching.values_mut().filter(|pending| {
            pending.owner == call.owner && pending.session == context.host_session_id()
        }) {
            pending.revoked = true;
        }
        for pending in self
            .tasks
            .values_mut()
            .filter_map(|task| task.call.as_mut())
        {
            if pending.owner == call.owner
                && pending
                    .context
                    .as_ref()
                    .is_some_and(|scope| scope.host_session_id() == context.host_session_id())
            {
                pending.cancelled = true;
            }
        }
    }

    fn complete(
        &mut self,
        completion: Completion,
        now: Instant,
    ) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
        let Some(mut retained) = self.tasks.remove(&completion.id) else {
            return Ok(Vec::new());
        };
        // A completion also arises from expiry/EOF/protocol drain. Only the
        // codec's separate exact-ID event establishes an incoming matched reply.
        let category = match &completion.outcome {
            Ok(Reply::Value(_) | Reply::JsonText(_)) => "result",
            Ok(Reply::Void(_)) => "void_result",
            Err(RpcError::Remote(_)) => "extension_error",
            Err(RpcError::Protocol { .. }) => "protocol_error",
            Err(
                RpcError::ReadUnavailable { cause, .. } | RpcError::OutcomeUnknown { cause, .. },
            ) => match cause {
                LossCause::Timeout => "timeout",
                LossCause::Eof => "eof",
                LossCause::Protocol => "protocol_error",
                #[cfg(test)]
                LossCause::WriteFailed => "write_failed",
            },
        };
        if tracing::enabled!(target: "maka::extension_rpc_phase", tracing::Level::TRACE) {
            ExtensionRpcTrace::captured(
                &self.generation,
                completion.id.as_str(),
                completion.method.as_str(),
                retained.call.as_ref().map(|call| call.outer.as_str()),
                retained.call.as_ref().map(|call| call.owner.as_str()),
                retained
                    .call
                    .as_ref()
                    .and_then(|call| call.context.as_ref()),
            )
            .completion(category);
        }
        if matches!(retained.stage, Stage::Attach(_)) && completion.outcome.is_ok() {
            retained.attach_acknowledged = true;
        }
        // This current completion is correlated by its exact extension pending ID.
        // A handler answer does not prove Chrome effect settlement or rollback.
        let extension_answered = matches!(&completion.outcome, Ok(_) | Err(RpcError::Remote(_)));
        let method = completion.method;
        let result = self.complete_task(retained.clone(), completion, now);
        if let Stage::Cdp(scope) = &retained.stage {
            if matches!(
                scope.method.as_str(),
                "Target.attachToTarget" | "Target.detachFromTarget"
            ) {
                self.prune_inactive_children(scope.tab);
            }
        }
        let Some(call) = retained.call.as_ref() else {
            return result;
        };
        let mut actions = match result {
            Ok(actions) => actions,
            Err(error) => {
                if activates_session(method) || matches!(retained.stage, Stage::Finish) {
                    self.uncertain_activation(
                        call,
                        retained.activation_epoch,
                        if matches!(retained.stage, Stage::Finish) {
                            TurnPhase::Finishing
                        } else {
                            TurnPhase::Active
                        },
                    );
                }
                let mut details =
                    json!({"remoteMethod":method.as_str(),"adapterFailure":error.to_string()});
                if let Some(custody) = self.partial_attachment(&retained, call) {
                    details["custody"] = custody;
                }
                self.failure(call, "outcome_unknown", &error.to_string(), details)
            }
        };
        // Any local later-phase refusal must retain an acknowledged attach,
        // just as extension rejection, expiry, EOF and caller cancellation do.
        let needs_custody = actions.iter().any(|action| {
            matches!(action,
            ExtensionWireAction::BrokerMessage(value) if value["kind"] == "response"
                && value["id"] == call.outer && value.get("error").is_some()
                && value["error"]["details"].get("custody").is_none())
        });
        if needs_custody {
            if let Some(custody) = self.partial_attachment(&retained, call) {
                for action in &mut actions {
                    if let ExtensionWireAction::BrokerMessage(value) = action {
                        if value["kind"] == "response"
                            && value["id"] == call.outer
                            && value.get("error").is_some()
                        {
                            if !value["error"]["details"].is_object() {
                                value["error"]["details"] = json!({});
                            }
                            value["error"]["details"]["custody"] = custody.clone();
                        }
                    }
                }
            }
        }
        if extension_answered {
            let terminal = MatchedExtensionReply::from_matched_rpc(
                self.generation.clone(),
                call.owner.clone(),
                call.outer.clone(),
                call.context.clone(),
            );
            actions = actions
                .into_iter()
                .map(|action| match action {
                    ExtensionWireAction::BrokerMessage(message)
                        if message["kind"] == "response" && message["id"] == call.outer =>
                    {
                        ExtensionWireAction::MatchedBrokerMessage {
                            message,
                            terminal: terminal.clone(),
                        }
                    }
                    other => other,
                })
                .collect();
        }
        Ok(actions)
    }

    fn complete_task(
        &mut self,
        mut task: Task,
        completion: Completion,
        now: Instant,
    ) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
        let reply = match completion.outcome {
            Ok(reply) => reply,
            Err(error) => {
                let Some(call) = task.call.clone() else {
                    return Err(ExtensionWireError::Protocol(error.to_string()));
                };
                // Code1 merges Chatgpt validation, policy and Chrome failures.
                // No synthetic raw CDP error or ChromeRejected marker is emitted.
                let (kind, mut detail) = match &error {
                    RpcError::Remote(remote)
                        if matches!(
                            task.stage,
                            Stage::Inventory
                                | Stage::Resolve {
                                    source: InventorySource::User,
                                    ..
                                }
                        ) =>
                    {
                        (
                            "original_rpc_rejected",
                            json!({"remoteCode":remote.code,"remoteMessage":remote.message,"remoteData":remote.data,"provenance":"mixed_extension_or_chrome"}),
                        )
                    }
                    RpcError::Remote(remote) => (
                        "outcome_unknown",
                        json!({"remoteCode":remote.code,"remoteMessage":remote.message,"remoteData":remote.data,"provenance":"mixed_extension_or_chrome"}),
                    ),
                    _ => (
                        "outcome_unknown",
                        json!({"remoteMethod":completion.method.as_str(),"cause":error.to_string()}),
                    ),
                };
                if activates_session(completion.method) {
                    self.uncertain_activation(&call, task.activation_epoch, TurnPhase::Active);
                }
                if matches!(task.stage, Stage::Finish) {
                    self.uncertain_activation(&call, task.activation_epoch, TurnPhase::Finishing);
                }

                if let Some(custody) = self.partial_attachment(&task, &call) {
                    detail["custody"] = custody;
                }
                return Ok(self.failure(&call, kind, &error.to_string(), detail));
            }
        };
        let value = match reply {
            Reply::JsonText(text) => {
                let raw: &RawValue = serde_json::from_str(&text)
                    .map_err(|error| ExtensionWireError::Protocol(error.to_string()))?;
                let value = match completion.method {
                    Method::GetUserTabs | Method::GetTabs => super::js_string::normalize_chatgpt_tabs(raw),
                    Method::CreateTab | Method::ClaimUserTab => super::js_string::normalize_chatgpt_tab(raw),
                    Method::ExecuteCdp if matches!(&task.stage, Stage::Cdp(scope) if matches!(scope.method.as_str(), "DOM.describeNode" | "Runtime.getProperties" | "Target.getTargets")) => {
                        return self.complete_cdp_json(task, completion.method, text);
                    }
                    Method::ExecuteCdp if matches!(task.stage, Stage::PreTargets(_) | Stage::Targets(_)) => super::js_string::normalize_cdp_targets(raw),
                    _ => serde_json::from_str(raw.get()),
                }.map_err(|error| ExtensionWireError::Protocol(error.to_string()))?;
                value
            }
            Reply::Value(value) => match completion.method {
                Method::GetUserTabs | Method::GetTabs => {
                    let raw = serde_json::value::to_raw_value(&value)
                        .map_err(|error| ExtensionWireError::Protocol(error.to_string()))?;
                    super::js_string::normalize_chatgpt_tabs(&raw)
                        .map_err(|error| ExtensionWireError::Protocol(error.to_string()))?
                }
                Method::CreateTab | Method::ClaimUserTab => {
                    let raw = serde_json::value::to_raw_value(&value)
                        .map_err(|error| ExtensionWireError::Protocol(error.to_string()))?;
                    super::js_string::normalize_chatgpt_tab(&raw)
                        .map_err(|error| ExtensionWireError::Protocol(error.to_string()))?
                }
                _ => value,
            },
            Reply::Void(_) => Value::Null,
        };
        if matches!(task.stage, Stage::Attach(_)) {
            task.attach_acknowledged = true;
        }

        if matches!(task.stage, Stage::Bootstrap) {
            if value["type"] != "extension"
                || value["metadata"]["extensionId"].as_str()
                    != Some(self.expected_extension.as_str())
                || value["metadata"]["extensionInstanceId"]
                    .as_str()
                    .is_none_or(str::is_empty)
            {
                return Err(ExtensionWireError::Protocol(
                    "ChatGPT getInfo identity differs from registered extension".to_owned(),
                ));
            }
            self.ready = true;
            self.extension_instance = value["metadata"]["extensionInstanceId"]
                .as_str()
                .map(str::to_owned);
            return Ok(vec![ExtensionWireAction::BrokerMessage(json!({
                "kind":"hello","protocol":1,"extensionId":self.expected_extension,
                "instanceId":value["metadata"]["extensionInstanceId"],
                "capabilities":{"metadata":true,"physicalClaims":true,"orderedCdpEvents":true,"flatChildSessions":true,
                    "browserManagement":false,"nativeWindowProof":false,"adapter":"chatgpt_jsonrpc", "observedVersion":value["version"],"userTabsOrder":"provider","headerScope":"session","presentationOwner":"provider","cursorMovePresentation":true,"cursorHidePresentation":false,"createdPresentationOwner":"provider","cursorPresentationOwner":"provider","cursorHideOwner":"unavailable","turnLifecycleOwner":"provider","attachmentPreparation":"full_preparation","downloadNotifications":true,"sessionTabResolution":true,"sessionTabInventory":true,"sessionCommittedUrl":true,"userTabContextRead":value["apiSupportOverrides"]["BrowserUser.getTabContext"]==true,"sessionPreparation":"provider_session","sessionNaming":true,"userHistory":true,"sessionLogicalActive":true}
            }))]);
        }
        let call = task
            .call
            .as_ref()
            .ok_or_else(|| {
                ExtensionWireError::Protocol("Session task lost its semantic request".to_owned())
            })?
            .clone();
        if call.cancelled {
            if let Stage::Mark { tab, status } = &task.stage {
                return Ok(self.failure(
                    &call,
                    "outcome_unknown",
                    "Tab mark ACK arrived after caller cancellation",
                    json!({"acknowledgedResult":{"marked":true,"tabId":tab,"status":status}}),
                ));
            }
        }
        // A late positively acknowledged cleanup still retires execution and
        // carries exact cleanup evidence into existing retained-completion code.
        if call.cancelled {
            let acknowledged = match &task.stage {
                Stage::Detach(token) => {
                    self.retire_claim(token);
                    Some(json!({"detached":true,"proof":"detach_ack"}))
                }
                Stage::Close(scope) if known_close_ack(&value, scope) => {
                    self.retire_closed_scope(&call, scope, task.activation_epoch);
                    Some(json!({"closed":true,"proof":"close_ack"}))
                }
                Stage::Finish => {
                    self.finish_observed(&call, task.activation_epoch);
                    let context = self.context(&call)?;
                    Some(
                        json!({"turnFinished":true,"hostSessionId":context.host_session_id(),"hostTurnId":context.host_turn_id()}),
                    )
                }
                _ => None,
            };
            if let Some(result) = acknowledged {
                return Ok(self.failure(
                    &call,
                    "outcome_unknown",
                    "Cleanup acknowledgement arrived after caller cancellation",
                    json!({"acknowledgedResult":result}),
                ));
            }
        }
        // A late positive create still gets a retained exact creation receipt.
        if matches!(task.stage, Stage::Create) {
            if self.creations.len() >= MAX_CLAIMS {
                return Ok(self.failure(&call,"outcome_unknown","Creation receipt budget exhausted after actual create; turn scope cleanup remains required",json!({"originalCreatedTab":value})));
            }
            let tab = checked_tab(value)?;
            let context = self.context(&call)?.clone();
            let token = uuid::Uuid::new_v4().to_string();
            let tab_id = tab["id"].as_u64().ok_or_else(|| {
                ExtensionWireError::Protocol("Created tab has no raw ID".to_owned())
            })?;
            if tab_id == 0 {
                return Ok(self.failure(&call,"outcome_unknown","Extension create did not return a positive raw ID; scope cleanup remains required",json!({"originalCreatedTab":tab})));
            }
            if self.leases.contains_key(&tab_id)
                || self.claims.values().any(|claim| claim.tab == tab_id)
            {
                return Ok(self.failure(&call,"outcome_unknown","Extension create returned a previously tracked raw identity; no receipt was reassigned",json!({"originalCreatedTab":tab})));
            }
            self.leases.insert(
                tab_id,
                (call.owner.clone(), context.host_session_id().to_owned()),
            );
            let endpoint = self.endpoint()?;
            self.creations.insert(
                token.clone(),
                Creation {
                    owner: call.owner.clone(),
                    session: context.host_session_id().to_owned(),
                    turn: context.host_turn_id().to_owned(),
                    tab_id,
                    endpoint,
                    finish_observed: task.finish_observed,
                },
            );
            let result = json!({"tab":tab,"creation":token});
            return Ok(if call.cancelled {
                self.failure(
                    &call,
                    "outcome_unknown",
                    "Create completed after cancellation; cleanup receipt retained",
                    json!({"acknowledgedResult":result}),
                )
            } else {
                self.success(&call, result)
            });
        }
        if call.cancelled {
            if let Stage::PrepareClaim {
                tab,
                purpose: PreparationPurpose::Session,
            } = &task.stage
            {
                let actual = checked_tab(value)?;
                if actual["id"].as_u64() != Some(*tab) {
                    return Err(ExtensionWireError::Protocol(
                        "ChatGPT session preparation changed raw tab identity".to_owned(),
                    ));
                }
                return Ok(self.failure(
                    &call,
                    "outcome_unknown",
                    "Session preparation completed after cancellation; actual tab metadata retained",
                    json!({"acknowledgedResult":{"tab":actual,"sessionOnly":true},"remoteMethod":completion.method.as_str()}),
                ));
            }
        }
        if call.cancelled {
            if let Stage::CommittedUrl { tab } = &task.stage {
                let url = value.as_str().ok_or_else(|| {
                    ExtensionWireError::Protocol(format!(
                        "ChatGPT committed URL for raw tab {tab} is not a string"
                    ))
                })?;
                return Ok(self.failure(
                    &call,
                    "outcome_unknown",
                    "Committed URL completed after cancellation; actual URL metadata retained",
                    json!({"acknowledgedResult":{"url":url,"sessionOnly":true,"committedUrlOnly":true},"remoteMethod":completion.method.as_str()}),
                ));
            }
        }
        if call.cancelled
            && !matches!(
                task.stage,
                Stage::Create | Stage::ObserveCreated(_) | Stage::NameSession | Stage::UserHistory
            )
        {
            if let Some(custody) = self.partial_attachment(&task, &call) {
                return Ok(self.failure(
                    &call,
                    "outcome_unknown",
                    "Attach chain completed after cancellation; cleanup-only receipt retained",
                    json!({"custody":custody}),
                ));
            }
            return Ok(self.failure(&call,"outcome_unknown","ChatGPT operation completed after cancellation; no follow-up mutation was replayed",json!({"remoteAcknowledged":true,"remoteMethod":completion.method.as_str()})));
        }
        match task.stage {
            Stage::UserTabRead => Ok(self.success(&call, json!({"value":value}))),
            Stage::Inventory => Ok(self.success(&call, json!({"tabs":project_inventory(value, InventorySource::User)?}))),
            Stage::SessionInventory => Ok(self.success(&call, json!({"tabs":project_inventory(value, InventorySource::ManagedSession)?,"sessionOnly":true}))),
            Stage::Resolve { tab: tab_id, source, session_only } => {
                let tabs = project_inventory(value, source)?;
                let truncated = source == InventorySource::User && tabs.len() == 1000;
                let tab = tabs
                    .into_iter()
                    .find(|tab| tab["id"].as_u64() == Some(tab_id));
                Ok(match tab {
                    Some(tab) => {
                        let mut result = json!({"tab":tab});
                        if session_only {
                            result["sessionOnly"] = json!(true);
                        }
                        self.success(&call, result)
                    },
                    None if truncated => self.failure(
                        &call,
                        "inventory_truncated",
                        "Capped ChatGPT user-tab inventory cannot determine this raw ID's absence",
                        json!({"tabId":tab_id,"observedCount":1000,"cap":1000}),
                    ),
                    None => self.failure(
                        &call,
                        "tab_unavailable",
                        if source == InventorySource::ManagedSession {
                            "Raw Chrome tab was not returned by this session's visible tab inventory"
                        } else {
                            "Raw Chrome tab is absent from the complete observed user-tab inventory"
                        },
                        json!({"tabId":tab_id}),
                    ),
                })
            }
            Stage::CommittedUrl { tab } => {
                let url = value.as_str().ok_or_else(|| ExtensionWireError::Protocol(
                    format!("ChatGPT committed URL for raw tab {tab} is not a string"),
                ))?;
                Ok(self.success(&call, json!({"url":url,"sessionOnly":true,"committedUrlOnly":true})))
            }
            Stage::PrepareBefore(tab) => {
                let tabs = project_inventory(value, InventorySource::User)?;
                let old = tabs
                    .iter()
                    .find(|row| row["id"].as_u64() == Some(tab))
                    .ok_or_else(|| ExtensionWireError::LocalRefusal {
                        code: "tab_unavailable".to_owned(),
                        message: "ChatGPT user tab was not observed".to_owned(),
                    })?;
                task.stage = Stage::PrepareClaim {
                    tab,
                    purpose: PreparationPurpose::UserObserved {
                        normalize_candidate: old["url"].as_str().is_some_and(normalizable_chrome_url),
                    },
                };
                let params = self.params(&call, json!({"tabId":tab}))?;
                self.queue(task, Method::ClaimUserTab, params, now)
            }
            Stage::PrepareClaim { tab, purpose } => {
                let tab_value = checked_tab(value)?;
                if tab_value["id"].as_u64() != Some(tab) {
                    return Err(ExtensionWireError::Protocol(
                        "ChatGPT claim changed raw tab identity".to_owned(),
                    ));
                }
                let context = self.context(&call)?;
                self.leases.insert(
                    tab,
                    (call.owner.clone(), context.host_session_id().to_owned()),
                );
                let mut result = json!({"tab":tab_value});
                match purpose {
                    PreparationPurpose::UserObserved { normalize_candidate } => {
                        let normalized = normalize_candidate && result["tab"]["url"] == "about:blank";
                        result["normalized"] = json!(normalized);
                    },
                    PreparationPurpose::Session => {
                        result["sessionOnly"] = json!(true);
                    },
                }
                Ok(self.success(&call, result))
            }
            Stage::ClaimForAttach(tab) => {
                if value["id"].as_u64() != Some(tab) {
                    return Err(ExtensionWireError::Protocol(
                        "ChatGPT claim changed raw tab identity".to_owned(),
                    ));
                }
                let context = self.context(&call)?;
                self.leases.insert(
                    tab,
                    (call.owner.clone(), context.host_session_id().to_owned()),
                );
                task.stage = Stage::PreTargets(tab);
                let params = self.params(
                    &call,
                    json!({"target":{},"method":"Target.getTargets","commandParams":{}}),
                )?;
                self.queue(task, Method::ExecuteCdp, params, now)
            }
            Stage::PreTargets(tab) => {
                let target = target_info(&value, tab)?;
                if target["attached"] != false {
                    return Ok(self.failure(&call,"outcome_unknown","Actual target is already attached after ChatGPT logical claim; no physical claim was adopted",json!({"tabId":tab,"originalLease":true})));
                }
                task.candidate_target = Some(required_string(&target, "targetId")?);
                task.stage = Stage::Attach(tab);
                let params = self.params(&call, json!({"tabId":tab}))?;
                self.queue(task, Method::Attach, params, now)
            }
            Stage::Attach(tab) => {
                task.stage = Stage::Probe(tab);
                let params=self.params(&call,json!({"target":{"tabId":tab},"method":"Runtime.evaluate","commandParams":{"expression":"0","returnByValue":true},"timeoutMs":10000}))?;
                self.queue(task, Method::ExecuteCdp, params, now)
            }
            Stage::Probe(tab) => {
                if value["result"]["value"] != 0 || value.get("exceptionDetails").is_some() {
                    return Err(ExtensionWireError::Protocol(
                        "Actual readonly post-attach CDP probe did not return0".to_owned(),
                    ));
                }
                task.stage = Stage::Targets(tab);
                let params = self.params(
                    &call,
                    json!({"target":{"tabId":tab},"method":"Target.getTargets","commandParams":{}}),
                )?;
                self.queue(task, Method::ExecuteCdp, params, now)
            }
            Stage::Targets(tab) => {
                let reservation = self.attaching.get(&tab).ok_or_else(|| {
                    ExtensionWireError::Protocol("Attach reservation was lost".to_owned())
                })?;
                if reservation.revoked {
                    return Ok(self.failure(
                        &call,
                        "outcome_unknown",
                        "ChatGPT debugger was revoked during attach; no executable claim minted",
                        json!({"tabId":tab}),
                    ));
                }
                let target = unique_target(&value, tab)?;
                if task.candidate_target.as_deref() != Some(target.as_str()) {
                    return Ok(self.failure(
                        &call,
                        "outcome_unknown",
                        "Actual target identity changed during attachment",
                        json!({"tabId":tab}),
                    ));
                }
                let context = self.context(&call)?.clone();
                let token = uuid::Uuid::new_v4().to_string();
                self.claims.insert(
                    token.clone(),
                    Claim {
                        owner: call.owner.clone(),
                        session: context.host_session_id().to_owned(),
                        turn: context.host_turn_id().to_owned(),
                        tab,
                        target: target.clone(),
                        live: true,
                        identity: AttachmentIdentity::Confirmed,
                        },
                );
                self.current_claim.insert(tab,token.clone());
                let early = self.retire_attaching(tab).map(|entry| entry.events)
                    .unwrap_or_default();
                let mut actions =
                    self.success(&call, json!({"tabId":tab,"targetId":target,"claim":token}));
                for (method, params, params_json) in early {
                    actions.extend(self.notification_with_json(&method, params, params_json)?);
                }
                Ok(actions)
            }
            Stage::Cdp(scope) => self.cdp_completed(&call, scope, value),
            Stage::Detach(token)=>{self.retire_claim(&token);Ok(self.success(&call,json!({"detached":true,"proof":"detach_ack"})))},
            Stage::Close(scope) => {
                if !known_close_ack(&value, &scope) {
                    return Ok(self.failure(
                        &call,
                        "outcome_unknown",
                        "ChatGPT Target.closeTarget did not confirm success",
                        json!({"remoteResult":value}),
                    ));
                }
                self.retire_closed_scope(&call, &scope, task.activation_epoch);
                Ok(self.success(&call, json!({"closed":true,"proof":"close_ack"})))
            }
            Stage::Mark { tab, status } => Ok(self.success(&call,json!({"marked":true,"tabId":tab,"status":status}))),
            Stage::Finish=>{self.finish_observed(&call, task.activation_epoch);let context=self.context(&call)?;Ok(self.success(&call,json!({"turnFinished":true,"hostSessionId":context.host_session_id(),"hostTurnId":context.host_turn_id()})))},
            Stage::ObserveCreated(token) => {
                let inventory = match chatgpt_inventory::authoritative_inventory(value) {
                    Ok(value) => value,
                    Err(error) => {
                        return Ok(self.failure(
                            &call,
                            "outcome_unknown",
                            &error.to_string(),
                            Value::Null,
                        ));
                    }
                };
                let creation = self.creations.get(&token).ok_or_else(|| {
                    ExtensionWireError::Protocol(
                        "Created receipt disappeared during observation".to_owned(),
                    )
                })?;
                let context = call.context.as_ref().ok_or_else(|| {
                    ExtensionWireError::Protocol("Created observation lost trusted scope".to_owned())
                })?;
                let raw_tab = creation.tab_id;
                let observed = self.endpoint()?;
                let evidence = AbsenceEvidence {
                    expected_endpoint: &creation.endpoint,
                    observed_endpoint: &observed,
                    known_created: KnownCreated {
                        owner: &creation.owner,
                        host_session_id: &creation.session,
                        raw_tab_id: raw_tab,
                        endpoint: &creation.endpoint,
                    },
                    caller: Caller {
                        owner: &call.owner,
                        host_session_id: context.host_session_id(),
                        raw_tab_id: raw_tab,
                    },
                    freshness: Some(InventoryFreshness { extension_request_id: completion.id.as_str(),
                    }),
                };
                match chatgpt_inventory::prove_created_absent(&inventory, evidence) {
                    Ok(proof) => {
                        let tokens:Vec<_>=self.claims.iter().filter(|(_,claim)|claim.tab==raw_tab&&claim.owner==call.owner&&claim.session==context.host_session_id()).map(|(token,_)|token.clone()).collect();
                        for token in tokens{self.retire_claim(&token);}self.leases.remove(&raw_tab);self.retire_attaching(raw_tab);self.creations.remove(&token);
                        let result = json!({"closed":true,"proof":"tab_absent","tabId":proof.raw_tab_id(),"observationRequestId":proof.extension_request_id(),"observation":{"evidence":proof.evidence_name(),"owner":proof.owner(),"hostSessionId":proof.host_session_id(),"generation":proof.endpoint().generation,"extensionInstanceId":proof.endpoint().extension_instance_id,"count":inventory.len(),"empty":inventory.is_empty()}});
                        Ok(if call.cancelled {
                            self.failure(
                                &call,
                                "outcome_unknown",
                                "Fresh absence observation arrived after caller cancellation",
                                json!({"acknowledgedResult":result}),
                            )
                        } else {
                            self.success(&call, result)
                        })
                    }
                    Err(error) => Ok(self.failure(
                        &call,
                        "outcome_unknown",
                        &error.to_string(),
                        json!({"tabId":raw_tab}),
                    )),
                }
            }
            Stage::UserHistory => {
                if call.cancelled { Ok(self.failure(&call, "outcome_unknown",
                    "History observation ended after caller cancellation", Value::Null)) }
                else { Ok(self.success(&call, json!({"items":value}))) }
            }
            Stage::NameSession => {
                if call.cancelled { Ok(self.failure(&call, "outcome_unknown",
                    "Session naming acknowledgement arrived after caller cancellation",
                    json!({"acknowledgedResult":{"renamed":true}}))) }
                else { Ok(self.success(&call, json!({"renamed":true}))) }
            }
            Stage::SessionHeaders { active }=>{
                let context=self.context(&call)?;
                Ok(self.success(&call,json!({"stateConfirmed":true,"cleanupConfirmed":!active,"active":active,"pendingRemoval":false,"hostSessionId":context.host_session_id(),"hostTurnId":context.host_turn_id(),"generation":self.generation,"owner":call.owner})))
            }
            Stage::MoveMouse { arrival_requested }=>Ok(self.success(&call,json!({"presentationAcknowledged":true,"arrivalRequested":arrival_requested,"arrivalConfirmed":null}))),
            Stage::Bootstrap | Stage::Create => Err(ExtensionWireError::Protocol(
                "Unexpected completed workflow stage".to_owned(),
            )),
        }
    }
}

impl ExtensionWireAdapter for ChatgptWireAdapter {
    fn start(&mut self, now: Instant) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
        if self.started {
            return Err(ExtensionWireError::Protocol(
                "ChatGPT adapter was started twice".to_owned(),
            ));
        }
        self.started = true;
        self.queue(
            Task {
                call: None,
                stage: Stage::Bootstrap,
                candidate_target: None,
                attach_acknowledged: false,
                finish_observed: false,
                activation_epoch: None,
                write_phase: WritePhase::Unwritten,
                initial_attach: None,
            },
            Method::GetInfo,
            json!({}),
            now,
        )
    }
    fn on_semantic(
        &mut self,
        envelope: Value,
        context: Option<&ExtensionWireContext>,
        now: Instant,
    ) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
        let actions = self.semantic_request(envelope, context, now)?;
        if !actions
            .iter()
            .any(|action| matches!(action, ExtensionWireAction::ExtensionFrame { .. }))
        {
            if let Some(error) = actions.iter().find_map(|action| match action {
                ExtensionWireAction::BrokerMessage(value) => value.get("error"),
                _ => None,
            }) {
                return Err(ExtensionWireError::LocalRefusal {
                    code: error["kind"].as_str().unwrap_or("local_refusal").to_owned(),
                    message: error["message"]
                        .as_str()
                        .unwrap_or("ChatGPT semantic request was refused before extension dispatch")
                        .to_owned(),
                });
            }
        }
        Ok(actions)
    }
    fn on_extension(
        &mut self,
        frame: Value,
        now: Instant,
    ) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
        let events = self.rpc.receive(frame, now);
        self.extension_events(events, now)
    }
    fn on_extension_json(
        &mut self,
        frame: &RawValue,
        now: Instant,
    ) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
        let events = self.rpc.receive_json(frame, now);
        self.extension_events(events, now)
    }
    fn on_cancel(&mut self, outer: &str) -> Vec<ExtensionWireAction> {
        for task in self.tasks.values_mut() {
            if let Some(call) = &mut task.call {
                if call.outer == outer {
                    call.cancelled = true;
                }
            }
        }
        Vec::new()
    }
    fn commit_write(&mut self, phase: &RequestId) -> Result<(), ExtensionWireError> {
        let method = self.rpc.pending_method(phase).ok_or_else(|| {
            ExtensionWireError::Protocol("write phase lost its exact pending RPC".to_owned())
        })?;
        let mut task = self.tasks.remove(phase).ok_or_else(|| {
            ExtensionWireError::Protocol("write phase lost its exact adapter task".to_owned())
        })?;
        if task.write_phase == WritePhase::Started {
            self.tasks.insert(phase.clone(), task);
            return Err(ExtensionWireError::Protocol(
                "local write phase was committed twice".to_owned(),
            ));
        }
        task.write_phase = WritePhase::Started;
        if let Some(call) = task.call.as_ref() {
            task.activation_epoch = if activates_session(method) {
                Some(self.admit_activation(call))
            } else if matches!(task.stage, Stage::Finish) {
                Some(self.admit_finish(call))
            } else {
                task.activation_epoch
            };
            if let Some(tab) = task.initial_attach.take() {
                let context = call.context.as_ref().expect("validated attach context");
                self.attaching.insert(
                    tab,
                    Attaching {
                        owner: call.owner.clone(),
                        session: context.host_session_id().to_owned(),
                        turn: context.host_turn_id().to_owned(),
                        revoked: false,
                        events: Vec::new(),
                        event_bytes: 0,
                    },
                );
                self.children.retain(|(root, _), _| *root != tab);
            }
        }
        self.tasks.insert(phase.clone(), task);
        Ok(())
    }
    fn discard_unwritten(
        &mut self,
        phase: &RequestId,
    ) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
        let task = self.tasks.get(phase).ok_or_else(|| {
            ExtensionWireError::Protocol("unwritten phase lost its exact adapter task".to_owned())
        })?;
        if task.write_phase != WritePhase::Unwritten || self.rpc.pending_method(phase).is_none() {
            return Err(ExtensionWireError::Protocol(
                "unwritten phase was already committed or lost its pending RPC".to_owned(),
            ));
        }
        let task = self.tasks.remove(phase).expect("validated pending task");
        self.rpc
            .discard_unwritten(phase)
            .expect("validated pending RPC");
        let mut actions = Vec::new();
        if let Some(call) = task.call {
            if !call.payload_released {
                actions.push(ExtensionWireAction::SemanticPayloadReleased {
                    semantic_id: call.outer.clone(),
                });
            }
            actions.push(ExtensionWireAction::SemanticFinished {
                semantic_id: call.outer,
            });
        }
        Ok(actions)
    }
    fn on_eof(&mut self, reason: &str) -> Vec<ExtensionWireAction> {
        self.ended = true;
        self.ready = false;
        for claim in self.claims.values_mut() {
            claim.live = false;
        }
        self.children.clear();
        let mut actions = Vec::new();
        for completion in self.rpc.eof(reason) {
            if let Ok(value) = self.complete(completion, Instant::now()) {
                actions.extend(value);
            }
        }
        actions
    }
    fn expire(&mut self, now: Instant) -> Vec<ExtensionWireAction> {
        let mut actions = Vec::new();
        for completion in self.rpc.expire(now) {
            match self.complete(completion, now) {
                Ok(value) => actions.extend(value),
                Err(error) => {
                    let reason = error.to_string();
                    actions.extend(self.on_eof(&reason));
                    actions.push(ExtensionWireAction::TransportEnded { reason });
                    break;
                }
            }
        }
        actions
    }
}

impl ChatgptWireAdapter {
    fn extension_events(
        &mut self,
        events: Vec<RpcEvent>,
        now: Instant,
    ) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
        let mut output = Vec::new();
        for event in events {
            let result = match event {
                RpcEvent::Reply(completion) => self.complete(completion, now),
                RpcEvent::Send(message) => Ok(vec![ExtensionWireAction::ExtensionFrame {
                    message,
                    semantic_id: None,
                    trace: None,
                    phase: None,
                }]),
                RpcEvent::Notification(notification) => self.notification(
                    &notification.method,
                    notification.params.unwrap_or(Value::Null),
                ),
                RpcEvent::JsonNotification {
                    method,
                    params_json,
                    ..
                } => self.notification_json(&method, params_json.as_deref().unwrap_or("null")),
                RpcEvent::IgnoredReply { .. } => Ok(Vec::new()),
                RpcEvent::ProtocolViolation { message } => {
                    Err(ExtensionWireError::Protocol(message))
                }
            };
            match result {
                Ok(actions) => output.extend(actions),
                Err(error) => {
                    let reason = error.to_string();
                    // The codec may have produced terminal custody before a
                    // generation violation. Flush it before ending the actor.
                    output.extend(self.on_eof(&reason));
                    output.push(ExtensionWireAction::TransportEnded { reason });
                    break;
                }
            }
        }
        Ok(output)
    }

    fn complete_cdp_json(
        &mut self,
        task: Task,
        method: Method,
        text: String,
    ) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
        let call = task.call.as_ref().ok_or_else(|| {
            ExtensionWireError::Protocol("CDP task lost its semantic request".to_owned())
        })?;
        if call.cancelled {
            return Ok(self.failure(call,"outcome_unknown","ChatGPT operation completed after cancellation; no follow-up mutation was replayed",json!({"remoteAcknowledged":true,"remoteMethod":method.as_str()})));
        }
        Ok(self.success(call, json!({"resultJson":text})))
    }

    fn notification_json(
        &mut self,
        method: &str,
        text: &str,
    ) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
        let raw: &RawValue = serde_json::from_str(text)
            .map_err(|error| ExtensionWireError::Protocol(error.to_string()))?;
        let mut fields: std::collections::BTreeMap<String, Box<RawValue>> =
            match serde_json::from_str(raw.get()) {
                Ok(fields) => fields,
                Err(_) => {
                    let value = serde_json::from_str(raw.get())
                        .map_err(|error| ExtensionWireError::Protocol(error.to_string()))?;
                    return self.notification(method, value);
                }
            };
        let event_method = fields
            .get("method")
            .and_then(|field| serde_json::from_str::<String>(field.get()).ok());
        if method != "onCDPEvent" || event_method.as_deref() != Some("Target.attachedToTarget") {
            let value = serde_json::from_str(raw.get())
                .map_err(|error| ExtensionWireError::Protocol(error.to_string()))?;
            return self.notification(method, value);
        }
        let Some(original) = fields.remove("params") else {
            let value = serde_json::from_str(raw.get())
                .map_err(|error| ExtensionWireError::Protocol(error.to_string()))?;
            return self.notification(method, value);
        };
        let projected = super::cdp_ws::chrome_json_attached_params(original.get())
            .map_err(|error| ExtensionWireError::Protocol(error.to_string()))?;
        let mut params = Map::new();
        for (key, value) in fields {
            params.insert(
                key,
                serde_json::from_str(value.get())
                    .map_err(|error| ExtensionWireError::Protocol(error.to_string()))?,
            );
        }
        params.insert("params".to_owned(), projected);
        self.notification_with_json(
            method,
            Value::Object(params),
            Some(original.get().to_owned()),
        )
    }

    fn notification(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
        self.notification_with_json(method, params, None)
    }

    fn notification_with_json(
        &mut self,
        method: &str,
        params: Value,
        params_json: Option<String>,
    ) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
        if method == "onDownloadChange" {
            // Chatgpt notifications are global extension download metadata. They
            // carry no tab/session ownership, approval or file-byte evidence.
            let id = required_string(&params, "id")?;
            let valid_id = id
                .parse::<u64>()
                .ok()
                .filter(|value| *value <= 9_007_199_254_740_991)
                .is_some_and(|value| value.to_string() == id);
            if !valid_id
                || !params["filename"].is_string()
                || !params["url"].is_string()
                || !matches!(
                    params["status"].as_str(),
                    Some("started" | "in_progress" | "complete" | "failed" | "canceled")
                )
            {
                return Err(ExtensionWireError::Protocol(
                    "Malformed ChatGPT extension download metadata".to_owned(),
                ));
            }
            return Ok(vec![ExtensionWireAction::BrokerMessage(json!({
                "kind":"download_changed","protocol":1,"generation":self.generation,
                "download":{"id":id,"filename":params["filename"],"url":params["url"],"status":params["status"]}
            }))]);
        }
        let (source, event_method, event_params) = match method {
            "onCDPEvent" => (
                params["source"].clone(),
                params["method"].as_str().map(str::to_owned),
                params["params"].clone(),
            ),
            "onCDPDetach" => (params.clone(), None, Value::Null),
            _ => {
                return Ok(vec![ExtensionWireAction::Diagnostic {
                    semantic_id: None,
                    message: format!("ChatGPT notification {method} has no scoped CDP route"),
                }]);
            }
        };
        let Some(tab) = source["tabId"].as_u64() else {
            return Ok(Vec::new());
        };
        if method == "onCDPEvent" {
            if let Some(pending) = self.attaching.get_mut(&tab) {
                let bytes = serde_json::to_vec(&(&params, &params_json))
                    .map_err(|error| ExtensionWireError::Protocol(error.to_string()))?
                    .len();
                if pending.events.len() >= 64
                    || self.early_bytes.saturating_add(bytes) > MAX_EARLY_BYTES
                {
                    return Err(ExtensionWireError::Protocol(
                        "ChatGPT early CDP event budget exhausted".to_owned(),
                    ));
                }
                pending.event_bytes += bytes;
                self.early_bytes += bytes;
                pending
                    .events
                    .push((method.to_owned(), params, params_json));
                return Ok(Vec::new());
            }
        }
        if method == "onCDPDetach" {
            if source.get("sessionId").is_some() || source.get("targetId").is_some() {
                return Ok(vec![ExtensionWireAction::Diagnostic {
                    semantic_id: None,
                    message:
                        "ChatGPT child/direct-target detach does not prove root physical detach"
                            .to_owned(),
                }]);
            }
            if let Some(pending) = self.attaching.get_mut(&tab) {
                pending.revoked = true;
            }
            let candidates: Vec<_> = self
                .claims
                .iter()
                .filter(|(_, claim)| claim.tab == tab)
                .map(|(token, claim)| (token.clone(), claim.clone()))
                .collect();
            let unambiguous = false;
            let mut actions = Vec::new();
            for (token, claim) in candidates {
                if let Some(record) = self.claims.get_mut(&token) {
                    record.live = false;
                }
                // Tokenless events after reuse cannot identify an epoch. They
                // retire execution but never produce a detach_event proof.
                let reason = if unambiguous {
                    "ChatGPT debugger detach event"
                } else {
                    "Unattributed ChatGPT detach event after tab epoch reuse; physical custody remains unknown"
                };
                actions.push(ExtensionWireAction::BrokerMessage(json!({"kind":"revoked","protocol":1,"generation":self.generation,"owner":claim.owner,"claim":token,"reason":reason})));
            }
            self.children.retain(|(root, _), _| *root != tab);
            return Ok(actions);
        }
        let Some((token, claim)) = self
            .claims
            .iter()
            .find(|(_, claim)| claim.tab == tab && claim.live)
            .map(|(token, claim)| (token.clone(), claim.clone()))
        else {
            return Ok(Vec::new());
        };
        let Some(event_method) = event_method else {
            return Ok(Vec::new());
        };
        if let Some(parent) = source["sessionId"].as_str() {
            if !self
                .children
                .get(&(tab, parent.to_owned()))
                .is_some_and(|child| child.state == ChildState::Live)
            {
                return Ok(Vec::new());
            }
        }
        if event_method == "Target.attachedToTarget" {
            let child = required_string(&event_params, "sessionId")?;
            let target = required_string(&event_params["targetInfo"], "targetId")?;
            let parent = source["sessionId"].as_str().map(str::to_owned);
            let key = (tab, child.clone());
            let known_order = self.children.get(&key).and_then(|entry| entry.attach_order);
            if self
                .children
                .get(&key)
                .is_some_and(|entry| entry.state == ChildState::DetachedWhileAttachPending)
            {
                return Ok(Vec::new());
            }
            let needs_ack = self.tasks.values().any(|task| {
                let Stage::Cdp(pending) = &task.stage else {
                    return false;
                };
                if pending.claim != token
                    || pending.tab != tab
                    || pending.parent != parent
                    || pending.target.as_deref() != Some(target.as_str())
                {
                    return false;
                }
                if pending.method == "Target.attachToTarget" && pending.attach_revoked {
                    return known_order.is_none();
                }
                if pending.method == "Target.detachFromTarget" && pending.child.is_none() {
                    let cleanup_order = task
                        .call
                        .as_ref()
                        .and_then(|call| call.outer.parse::<u64>().ok());
                    return known_order
                        .zip(cleanup_order)
                        .is_none_or(|(attached, cleanup)| attached <= cleanup);
                }
                false
            });
            if !self.children.contains_key(&key) && self.children.len() >= MAX_CHILDREN {
                return Err(ExtensionWireError::Protocol(
                    "ChatGPT child-session budget exhausted".to_owned(),
                ));
            }
            self.children.insert(
                key,
                ChildSession {
                    parent,
                    target: Some(target),
                    attach_order: known_order,
                    state: if needs_ack {
                        ChildState::AwaitingAttachAck
                    } else {
                        ChildState::Live
                    },
                },
            );
        }
        if event_method == "Target.detachedFromTarget" {
            if let Some(child) = event_params["sessionId"].as_str() {
                self.remove_children(tab, child, source["sessionId"].as_str())?;
            }
        }
        let mut event = json!({"kind":"event","protocol":1,"generation":self.generation,"owner":claim.owner,"claim":token,"method":event_method,"params":event_params});
        if let Some(text) = params_json {
            event
                .as_object_mut()
                .expect("fixed event object")
                .remove("params");
            event["paramsJson"] = Value::String(text);
        }
        if let Some(session) = source.get("sessionId").and_then(Value::as_str) {
            event["sessionId"] = json!(session);
        }
        if let Some(target) = source.get("targetId").filter(|target| !target.is_null()) {
            let target = target.as_str().ok_or_else(|| {
                ExtensionWireError::Protocol(
                    "ChatGPT CDP event source target is invalid".to_owned(),
                )
            })?;
            event["sourceTargetId"] = json!(target);
        }
        Ok(vec![ExtensionWireAction::BrokerMessage(event)])
    }
    fn has_pending_child_lifecycle(&self, tab: u64) -> bool {
        self.tasks.values().any(|task| {
            matches!(&task.stage,
            Stage::Cdp(scope) if scope.tab == tab && matches!(scope.method.as_str(), "Target.attachToTarget" | "Target.detachFromTarget"))
        })
    }

    fn prune_inactive_children(&mut self, tab: u64) {
        if !self.has_pending_child_lifecycle(tab) {
            self.children
                .retain(|(root, _), child| *root != tab || child.state == ChildState::Live);
        }
    }

    fn remove_children(
        &mut self,
        tab: u64,
        child: &str,
        parent: Option<&str>,
    ) -> Result<(), ExtensionWireError> {
        let mut removed = HashSet::from([child.to_owned()]);
        loop {
            let descendants: Vec<_> = self
                .children
                .iter()
                .filter(|((root, id), entry)| {
                    *root == tab
                        && !removed.contains(id)
                        && entry
                            .parent
                            .as_ref()
                            .is_some_and(|value| removed.contains(value))
                })
                .map(|((_, id), _)| id.clone())
                .collect();
            if descendants.is_empty() {
                break;
            }
            removed.extend(descendants);
        }
        let retain_detach = self.has_pending_child_lifecycle(tab);
        if retain_detach {
            for id in &removed {
                if let Some(entry) = self.children.get_mut(&(tab, id.clone())) {
                    entry.state = ChildState::DetachedWhileAttachPending;
                }
            }
            if !self.children.contains_key(&(tab, child.to_owned())) {
                if self.children.len() >= MAX_CHILDREN {
                    return Err(ExtensionWireError::Protocol(
                        "Child revocation receipt budget is exhausted".to_owned(),
                    ));
                }
                // This is revocation only. Unknown pre-ACK session IDs gain no
                // authority and live only until the pending attach calls settle.
                self.children.insert(
                    (tab, child.to_owned()),
                    ChildSession {
                        parent: parent.map(str::to_owned),
                        target: None,
                        state: ChildState::DetachedWhileAttachPending,
                        attach_order: None,
                    },
                );
            }
        } else {
            self.children
                .retain(|(root, id), _| *root != tab || !removed.contains(id));
        }
        Ok(())
    }

    fn cdp_completed(
        &mut self,
        call: &Call,
        scope: CdpScope,
        value: Value,
    ) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
        if !matches!(
            scope.method.as_str(),
            "Target.attachToTarget" | "Target.detachFromTarget"
        ) {
            return Ok(self.success(call, json!({"result":value})));
        }
        let current = self.current_claim.get(&scope.tab).map(String::as_str)
            == Some(scope.claim.as_str())
            && self
                .claims
                .get(&scope.claim)
                .is_some_and(|claim| claim.live);
        if scope.method == "Target.detachFromTarget" {
            if !value.is_object() {
                return Err(ExtensionWireError::Protocol(
                    "Child detach acknowledgement is not a CDP result object".to_owned(),
                ));
            }
            if current {
                if let Some(child) = scope.child.as_deref() {
                    // Chromium gives sessionId precedence over deprecated targetId.
                    self.remove_children(scope.tab, child, scope.parent.as_deref())?;
                } else if scope.target.is_some() {
                    // Target-id ACK means the addressed handler found exactly
                    // one live session and detached it. Previously known IDs
                    // for that target can no longer authorize execution.
                    let detach_order = call.outer.parse::<u64>().map_err(|_| {
                        ExtensionWireError::Protocol(
                            "Host semantic ordinal changed after admission".to_owned(),
                        )
                    })?;
                    let children: Vec<_> = self
                        .children
                        .iter()
                        .filter(|((root, _), child)| {
                            *root == scope.tab
                                && child.parent == scope.parent
                                && child.target == scope.target
                                && child.attach_order.is_none_or(|order| order < detach_order)
                        })
                        .map(|((_, id), _)| id.clone())
                        .collect();
                    for child in children {
                        self.remove_children(scope.tab, &child, scope.parent.as_deref())?;
                    }

                    for pending in self.tasks.values_mut() {
                        if let Stage::Cdp(attach) = &mut pending.stage {
                            let earlier = pending
                                .call
                                .as_ref()
                                .and_then(|value| value.outer.parse::<u64>().ok())
                                .is_some_and(|order| order < detach_order);
                            if earlier
                                && attach.method == "Target.attachToTarget"
                                && attach.claim == scope.claim
                                && attach.parent == scope.parent
                                && attach.target == scope.target
                            {
                                attach.attach_revoked = true;
                            }
                        }
                    }
                }
            }
            return Ok(self.success(call, json!({"result":value})));
        }
        if !current {
            return Ok(self.failure(
                call,
                "outcome_unknown",
                "Child lifecycle acknowledgement belongs to a retired root claim",
                json!({"remoteAcknowledgedResult":value}),
            ));
        }
        if let Some(parent) = scope.parent.as_ref() {
            if !self
                .children
                .get(&(scope.tab, parent.clone()))
                .is_some_and(|entry| entry.state == ChildState::Live)
            {
                return Ok(self.failure(
                    call,
                    "outcome_unknown",
                    "Parent child-session ended before lifecycle acknowledgement",
                    json!({"remoteAcknowledgedResult":value}),
                ));
            }
        }
        if scope.attach_revoked {
            return Ok(self.failure(
                call,
                "outcome_unknown",
                "Target cleanup acknowledged before this earlier attach settled",
                json!({"remoteAcknowledgedResult":value}),
            ));
        }
        let id = required_string(&value, "sessionId")?;
        if scope.target.is_none() {
            return Err(ExtensionWireError::Protocol(
                "Child attach acknowledgement has no exact requested target identity".to_owned(),
            ));
        }
        let key = (scope.tab, id.clone());
        if let Some(existing) = self.children.get(&key) {
            if existing.state == ChildState::DetachedWhileAttachPending {
                return Ok(self.failure(
                    call,
                    "outcome_unknown",
                    "Child detached before its matched attach acknowledgement",
                    json!({"remoteAcknowledgedResult":value}),
                ));
            }
            if existing.parent != scope.parent
                || (existing.target.is_some() && existing.target != scope.target)
            {
                return Err(ExtensionWireError::Protocol(
                    "Child attach acknowledgement changed its observed identity".to_owned(),
                ));
            }
        } else if self.children.len() >= MAX_CHILDREN {
            return Ok(self.failure(
                call,
                "outcome_unknown",
                "Child receipt budget exhausted after attach acknowledgement",
                json!({"remoteAcknowledgedResult":value}),
            ));
        }
        self.children.insert(
            key,
            ChildSession {
                parent: scope.parent,
                target: scope.target,
                state: ChildState::Live,
                attach_order: call.outer.parse::<u64>().ok(),
            },
        );
        Ok(self.success(call, json!({"result":value})))
    }

    fn retire_attaching(&mut self, tab: u64) -> Option<Attaching> {
        let entry = self.attaching.remove(&tab)?;
        self.early_bytes = self.early_bytes.saturating_sub(entry.event_bytes);
        Some(entry)
    }
    fn endpoint(&self) -> Result<EndpointIdentity, ExtensionWireError> {
        Ok(EndpointIdentity {
            generation: self.generation.clone(),
            extension_instance_id: self.extension_instance.clone().ok_or_else(|| {
                ExtensionWireError::Protocol("ChatGPT endpoint instance is not ready".to_owned())
            })?,
        })
    }
}

fn required_string(value: &Value, key: &str) -> Result<String, ExtensionWireError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| ExtensionWireError::Protocol(format!("Missing bounded string field {key}")))
}
fn required_tab(value: &Value) -> Result<u64, ExtensionWireError> {
    value["tabId"]
        .as_u64()
        .filter(|id| *id > 0 && *id <= 9_007_199_254_740_991)
        .ok_or_else(|| ExtensionWireError::Protocol("Invalid actual Chrome tab ID".to_owned()))
}
fn known_close_ack(value: &Value, scope: &CloseScope) -> bool {
    value["success"] == true
        && value
            .get("claim")
            .is_none_or(|claim| claim.as_str() == Some(scope.claim.as_str()))
        && value
            .get("tabId")
            .is_none_or(|tab| tab.as_u64() == Some(scope.tab))
        && value
            .get("targetId")
            .is_none_or(|target| target.as_str() == Some(scope.target.as_str()))
}

fn requested_committed_url_only(fields: &Value) -> Result<bool, ExtensionWireError> {
    match fields.get("committedUrlOnly") {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(ExtensionWireError::LocalRefusal {
            code: "invalid_request".to_owned(),
            message: "committedUrlOnly must be a boolean".to_owned(),
        }),
    }
}

fn requested_session_only(fields: &Value) -> Result<bool, ExtensionWireError> {
    match fields.get("sessionOnly") {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(ExtensionWireError::LocalRefusal {
            code: "invalid_request".to_owned(),
            message: "sessionOnly must be a boolean".to_owned(),
        }),
    }
}
fn checked_tab(value: Value) -> Result<Value, ExtensionWireError> {
    let id = value["id"]
        .as_u64()
        .filter(|id| *id <= 9_007_199_254_740_991)
        .ok_or_else(|| {
            ExtensionWireError::Protocol("Extension tab metadata lacks actual Chrome ID".to_owned())
        })?;
    let mut tab = Map::new();
    tab.insert("id".to_owned(), json!(id));
    for key in [
        "titleJson",
        "groupTitleJson",
        "url",
        "active",
        "faviconUrl",
        "lastOpened",
        "providerTabId",
    ] {
        if let Some(value) = value.get(key) {
            tab.insert(key.to_owned(), value.clone());
        }
    }
    Ok(Value::Object(tab))
}
fn project_inventory(
    value: Value,
    source: InventorySource,
) -> Result<Vec<Value>, ExtensionWireError> {
    let rows = value.as_array().ok_or_else(|| {
        ExtensionWireError::Protocol("ChatGPT inventory is not an array".to_owned())
    })?;
    if source == InventorySource::User && rows.len() > 1000 {
        return Err(ExtensionWireError::Protocol(
            "ChatGPT full inventory exceeded source cap1000".to_owned(),
        ));
    }
    let mut ids = HashSet::new();
    rows.iter()
        .map(|row| {
            let tab = checked_tab(row.clone())?;
            let id = tab["id"]
                .as_u64()
                .ok_or_else(|| ExtensionWireError::Protocol("Missing tab ID".to_owned()))?;
            if !ids.insert(id) {
                return Err(ExtensionWireError::Protocol(
                    "ChatGPT inventory duplicated raw tab ID".to_owned(),
                ));
            }
            Ok(tab)
        })
        .collect()
}
fn unique_target(value: &Value, tab: u64) -> Result<String, ExtensionWireError> {
    let targets = value["targetInfos"].as_array().ok_or_else(|| {
        ExtensionWireError::Protocol("ChatGPT Target.getTargets lacks targetInfos".to_owned())
    })?;
    let mut found = targets.iter().filter(|target| {
        target["tabId"].as_u64() == Some(tab)
            && target["type"] == "page"
            && target["attached"] == true
    });
    let target = found.next().ok_or_else(|| {
        ExtensionWireError::Protocol(
            "No actual attached page target matches the raw Chrome tab".to_owned(),
        )
    })?;
    if found.next().is_some() {
        return Err(ExtensionWireError::Protocol(
            "Raw Chrome tab has ambiguous actual target identity".to_owned(),
        ));
    }
    required_string(target, "targetId")
}
fn normalizable_chrome_url(url: &str) -> bool {
    matches!(
        url,
        "chrome://newtab/" | "chrome://new-tab-page/" | "chrome://new-tab-page-third-party/"
    )
}
fn target_info(value: &Value, tab: u64) -> Result<Value, ExtensionWireError> {
    let targets = value["targetInfos"].as_array().ok_or_else(|| {
        ExtensionWireError::Protocol("ChatGPT Target.getTargets lacks targetInfos".to_owned())
    })?;
    let matches: Vec<_> = targets
        .iter()
        .filter(|target| target["tabId"].as_u64() == Some(tab) && target["type"] == "page")
        .collect();
    if matches.len() != 1 {
        return Err(ExtensionWireError::Protocol(
            "Raw Chrome tab target identity is absent or ambiguous".to_owned(),
        ));
    }
    Ok(matches[0].clone())
}

#[cfg(test)]
#[path = "chatgpt_adapter_tests.rs"]
mod tests;

impl ChatgptWireAdapter {
    fn semantic_request(
        &mut self,
        mut envelope: Value,
        context: Option<&ExtensionWireContext>,
        now: Instant,
    ) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
        if envelope["kind"] == "bound" {
            return Ok(Vec::new());
        }
        if !self.ready
            || self.ended
            || envelope["kind"] != "request"
            || envelope["protocol"] != 1
            || envelope["generation"] != self.generation
        {
            return Err(ExtensionWireError::Protocol(
                "ChatGPT semantic request is outside its live generation".to_owned(),
            ));
        }
        let outer = required_string(&envelope, "id")?;
        if outer
            .parse::<u64>()
            .ok()
            .filter(|id| *id > 0)
            .map(|id| id.to_string())
            .as_deref()
            != Some(outer.as_str())
        {
            return Err(ExtensionWireError::Protocol(
                "Invalid semantic request ID".to_owned(),
            ));
        }
        let call = Call {
            outer,
            owner: required_string(&envelope, "owner")?,
            context: context.cloned(),
            cancelled: false,
            payload_released: false,
        };
        if self.tasks.len() >= MAX_TASKS {
            return Ok(self.failure(
                &call,
                "request_budget",
                "ChatGPT workflow budget exhausted",
                Value::Null,
            ));
        }
        let fields = envelope
            .get_mut("params")
            .map_or_else(|| json!({}), Value::take);
        let method = required_string(&envelope, "method")?;
        let cleanup = matches!(
            method.as_str(),
            "detach" | "finishTurn" | "stopCreatedTab" | "clearSessionHeaders" | "closeOwner"
        );
        if !cleanup
            && self
                .tasks
                .values()
                .filter(|task| {
                    !matches!(
                        task.stage,
                        Stage::Detach(_)
                            | Stage::Finish
                            | Stage::ObserveCreated(_)
                            | Stage::SessionHeaders { active: false }
                    )
                })
                .count()
                >= MAX_NORMAL_TASKS
        {
            return Ok(self.failure(
                &call,
                "request_budget",
                "Normal ChatGPT operation budget is exhausted; cleanup remains reserved",
                Value::Null,
            ));
        }
        let reserved_resources = self
            .tasks
            .values()
            .filter(|task| {
                matches!(
                    task.stage,
                    Stage::Create
                        | Stage::PrepareBefore(_)
                        | Stage::PrepareClaim { .. }
                        | Stage::ClaimForAttach(_)
                        | Stage::PreTargets(_)
                        | Stage::Attach(_)
                        | Stage::Probe(_)
                        | Stage::Targets(_)
                )
            })
            .count();
        if matches!(method.as_str(), "prepareUserTab" | "createTab" | "attach")
            && (self.leases.len().saturating_add(reserved_resources) >= MAX_CLAIMS
                || self
                    .claims
                    .len()
                    .saturating_add(self.attaching.len())
                    .saturating_add(self.creations.len())
                    .saturating_add(reserved_resources)
                    >= MAX_CLAIMS)
        {
            return Ok(self.failure(
                &call,
                "custody_budget",
                "Pending and uncertain ChatGPT resources already reserve the custody budget",
                Value::Null,
            ));
        }
        if matches!(method.as_str(), "prepareUserTab" | "createTab" | "attach")
            && (self.leases.len() >= MAX_CLAIMS
                || self
                    .claims
                    .len()
                    .saturating_add(self.attaching.len())
                    .saturating_add(self.creations.len())
                    >= MAX_CLAIMS)
        {
            return Ok(self.failure(&call,"custody_budget","Retained ChatGPT custody budget is exhausted; reconcile before admitting new mutations",Value::Null));
        }
        let (stage,extension,params)=match method.as_str() {
            "readUserTab" => {
                let tab = required_tab(&fields)?;
                let expected = required_string(&fields, "expectedUrl")?;
                let url = url::Url::parse(&expected).map_err(|_| ExtensionWireError::LocalRefusal {
                    code: "invalid_request".to_owned(), message: "Tab reads require an HTTP or HTTPS URL".to_owned(),
                })?;
                if !matches!(url.scheme(), "http" | "https") {
                    return Err(ExtensionWireError::LocalRefusal {code:"invalid_request".to_owned(),message:"Tab reads require an HTTP or HTTPS URL".to_owned()});
                }
                let read: super::user_tab_context::BrowserUserTabRead = serde_json::from_value(fields["read"].clone())
                    .map_err(|error| ExtensionWireError::LocalRefusal {code:"invalid_request".to_owned(), message:format!("Invalid fixed user-tab read: {error}")})?;
                let context = self.context(&call)?;
                if self.leases.get(&tab).is_some_and(|(owner, session)| owner != &call.owner || session != context.host_session_id())
                    || self.attaching.get(&tab).is_some_and(|entry| entry.owner != call.owner || entry.session != context.host_session_id())
                    || self.claims.values().any(|claim| claim.tab == tab && claim.live && (claim.owner != call.owner || claim.session != context.host_session_id()))
                {
                    return Ok(self.failure(&call,"claim_unavailable","User-tab reads cannot cross another logical owner's raw tab",Value::Null));
                }
                let params = self.params(&call, json!({"tabId":tab,"expectedUrl":expected,"read":read}))?;
                (Stage::UserTabRead, Method::ExecuteTabRead, params)
            },
            "userHistory" => {
                let params = self.params(&call, fields.clone())?;
                (Stage::UserHistory, Method::GetUserHistory, params)
            }
            "nameSession" => {
                let name = required_string(&fields, "name")?;
                if name.is_empty() {
                    return Err(ExtensionWireError::LocalRefusal { code: "invalid_request".to_owned(),
                        message: "name_session requires a name".to_owned() });
                }
                let params = self.params(&call, json!({"name":name}))?;
                (Stage::NameSession, Method::NameSession, params)
            }
            "inventory"=>{
                if requested_session_only(&fields)? {
                    let candidates=fields.get("knownTabIds").and_then(Value::as_array).ok_or_else(||ExtensionWireError::LocalRefusal {code:"invalid_request".to_owned(),message:"session inventory requires candidate IDs".to_owned()})?;
                    let mut ids=HashSet::new();
                    if candidates.iter().any(|value|value.as_u64().is_none_or(|id|id==0||id>9_007_199_254_740_991||!ids.insert(id))) {
                        return Err(ExtensionWireError::LocalRefusal {code:"invalid_request".to_owned(),message:"session inventory candidates must be unique positive safe IDs".to_owned()});
                    }
                    // Candidates never replace the actual Chatgpt session view.
                    let params=self.params(&call,json!({}))?;
                    (Stage::SessionInventory,Method::GetTabs,params)
                } else {
                    if fields.get("knownTabIds").is_some() {
                        return Err(ExtensionWireError::LocalRefusal {code:"invalid_request".to_owned(),message:"candidate IDs require sessionOnly:true".to_owned()});
                    }
                    (Stage::Inventory,Method::GetUserTabs,json!({}))
                }
            },
            // Preserve the public extension Number(rawId) grammar at this input
            // boundary; transport only its actual canonical Chrome integer.
            "resolve"=>{
                let id=parse_browser_tab_id(&required_string(&fields,"rawId")?).ok_or_else(||ExtensionWireError::LocalRefusal {code:"invalid_request".to_owned(),message:"Extension tab ID must convert to a positive safe integer".to_owned()})?;
                let session_only=requested_session_only(&fields)?;
                let committed_url_only=requested_committed_url_only(&fields)?;
                if committed_url_only && !session_only {
                    return Err(ExtensionWireError::LocalRefusal {code:"invalid_request".to_owned(),message:"committedUrlOnly requires sessionOnly".to_owned()});
                }
                if session_only {
                    let context=self.context(&call)?;
                    if self.leases.get(&id).is_some_and(|(owner,session)|owner!=&call.owner||session!=context.host_session_id()) {
                        return Ok(self.failure(&call,"claim_unavailable","Session metadata cannot reassign another logical owner's raw tab",Value::Null));
                    }
                }
                let owned=call.context.as_ref().is_some_and(|context| self.leases.get(&id).is_some_and(|(owner,session)|owner==&call.owner&&session==context.host_session_id()));
                if committed_url_only {
                    let params=self.params(&call,json!({"tabId":id}))?;
                    (Stage::CommittedUrl {tab:id},Method::GetCommittedTabUrl,params)
                } else if session_only || owned {
                    let params=self.params(&call,json!({}))?;
                    (Stage::Resolve {tab:id,source:InventorySource::ManagedSession,session_only},Method::GetTabs,params)
                } else {
                    (Stage::Resolve {tab:id,source:InventorySource::User,session_only:false},Method::GetUserTabs,json!({}))
                }
            },
            "prepareUserTab"=>{
                let tab=required_tab(&fields)?;let session_only=requested_session_only(&fields)?;let context=self.context(&call)?.clone();
                if self.leases.get(&tab).is_some_and(|(owner,session)|owner!=&call.owner||session!=context.host_session_id())||self.attaching.get(&tab).is_some_and(|entry|entry.owner!=call.owner||entry.session!=context.host_session_id())||self.tasks.values().any(|task|task.initial_attach==Some(tab)&&task.call.as_ref().is_some_and(|pending|pending.owner!=call.owner||pending.context.as_ref().is_some_and(|scope|scope.host_session_id()!=context.host_session_id())))||self.claims.values().any(|claim|claim.tab==tab&&claim.live&&(claim.owner!=call.owner||claim.session!=context.host_session_id())){return Ok(self.failure(&call,"claim_unavailable","Preparation cannot reassign another owner's raw tab",Value::Null));}
                if session_only {
                    let params=self.params(&call,json!({"tabId":tab}))?;
                    (Stage::PrepareClaim {tab,purpose:PreparationPurpose::Session},Method::ClaimUserTab,params)
                } else {
                    (Stage::PrepareBefore(tab),Method::GetUserTabs,json!({}))
                }
            },
            "createTab"=>{
                let params=self.params(&call,fields.get("windowId").map_or_else(||json!({}),|value|json!({"preferredWindowId":value})))?;
                (Stage::Create,Method::CreateTab,params)
            }
            "attach"=>{
                if self.claims.len()>=MAX_CLAIMS {return Ok(self.failure(&call,"claim_budget","ChatGPT claim budget exhausted",Value::Null));}
                let tab=required_tab(&fields)?;
                let context=self.context(&call)?.clone();
                if self.claims.values().any(|claim|claim.tab==tab) {return Ok(self.failure(&call,"claim_unavailable","Tab already has a live host claim",Value::Null));}
                if self.attaching.contains_key(&tab)||self.tasks.values().any(|task|task.initial_attach==Some(tab)) {return Ok(self.failure(&call,"claim_unavailable","Raw tab has an admitted or uncertain attach reservation",Value::Null));}
                let lease=self.leases.get(&tab);
                if lease.is_some_and(|(owner,session)|owner!=&call.owner||session!=context.host_session_id()) {return Ok(self.failure(&call,"claim_unavailable","Tab belongs to another host owner/session",Value::Null));}
                let has_lease=lease.is_some();
                let params=self.params(&call,if has_lease{json!({"target":{},"method":"Target.getTargets","commandParams":{}})}else{json!({"tabId":tab})})?;
                if has_lease {(Stage::PreTargets(tab),Method::ExecuteCdp,params)}else{(Stage::ClaimForAttach(tab),Method::ClaimUserTab,params)}
            }
            "cdp"=>{
                let token=required_string(&fields,"claim")?;
                let claim=self.owned_claim(&call,&token)?;
                let cdp_method=required_string(&fields,"method")?;
                // The Chatgpt transport forwards CDP methods. Host ownership
                // still prevents an explicit target/session parameter escaping
                // this exact root and its actually observed flat children.
                if let Some(target_id)=fields["params"].get("targetId").filter(|_| !(cdp_method=="Target.detachFromTarget"&&fields["params"]["sessionId"].is_string())) {
                    let root_matches=target_id.as_str()==Some(claim.target.as_str());
                    let child_matches=self.children.iter().any(|((root,_),child)|*root==claim.tab&&child.state==ChildState::Live&&child.target.as_deref()==target_id.as_str()&&target_id.is_string());
                    if !root_matches&&!child_matches{return Ok(self.failure(&call,"claim_unavailable","CDP target is outside the exact observed root/child claim",Value::Null));}
                }
                if let Some(child_id)=fields["params"].get("sessionId") {
                    if !child_id.as_str().is_some_and(|id|self.children.get(&(claim.tab,id.to_owned())).is_some_and(|entry|entry.state==ChildState::Live)){return Ok(self.failure(&call,"child_session_unavailable","CDP child parameter was not observed under this root",Value::Null));}
                }
                let mut target=json!({"tabId":claim.tab});
                if let Some(child)=fields.get("sessionId").and_then(Value::as_str) {
                    if !self.children.get(&(claim.tab,child.to_owned())).is_some_and(|entry|entry.state==ChildState::Live) {return Ok(self.failure(&call,"child_session_unavailable","Child was not observed under this exact root",Value::Null));}
                    target["sessionId"]=json!(child);
                }
                let params=self.params(&call,json!({"target":target,"method":cdp_method,"commandParams":fields.get("params").cloned().unwrap_or_else(||json!({}))}))?;
                let parent=fields.get("sessionId").and_then(Value::as_str).map(str::to_owned);
                let requested_target=fields["params"].get("targetId").and_then(Value::as_str).map(str::to_owned);
                let requested_child=fields["params"].get("sessionId").and_then(Value::as_str).map(str::to_owned);
                let scope=CdpScope {claim:token,tab:claim.tab,method:cdp_method,parent,target:requested_target,child:requested_child,attach_revoked:false};
                (Stage::Cdp(scope),Method::ExecuteCdp,params)
            }
            "detach"=>{let token=required_string(&fields,"claim")?;let current=self.cleanup_claim(&call,&token)?;let params=self.params(&call,json!({"tabId":current.tab}))?;(Stage::Detach(token),Method::Detach,params)},
            "closeTab"=>{
                let token=required_string(&fields,"claim")?;let claim=self.owned_claim(&call,&token)?;
                // Matches Chatgpt closeTab's preferred branch after actual
                // Target.getTargets correlation. Never replaces it with tabs.remove.
                let context=self.context(&call)?;
                // Capture existing receipt IDs before the effect; a late ACK cannot collect later raw-ID reuse.
                let creations=self.creations.iter().filter(|(_,creation)|creation.owner==call.owner&&creation.session==context.host_session_id()&&creation.tab_id==claim.tab&&creation.endpoint.generation==self.generation&&Some(creation.endpoint.extension_instance_id.as_str())==self.extension_instance.as_deref()).map(|(token,_)|token.clone()).collect();
                let scope=CloseScope {claim:token,tab:claim.tab,target:claim.target.clone(),creations};
                let params=self.params(&call,json!({"target":{"tabId":claim.tab},"method":"Target.closeTarget","commandParams":{"targetId":claim.target}}))?;
                (Stage::Close(scope),Method::ExecuteCdp,params)
            }
            "markTab"=>{
                if fields.as_object().is_none_or(|fields| fields.len()!=2 || !fields.contains_key("claim") || !fields.contains_key("status")) {
                    return Err(ExtensionWireError::LocalRefusal {code:"invalid_request".into(),message:"Tab marking requires only claim and status".into()});
                }
                let token=required_string(&fields,"claim")?;
                let claim=self.owned_claim(&call,&token)?;
                let status=required_string(&fields,"status")?;
                if !matches!(status.as_str(),"handoff"|"deliverable") {
                    return Err(ExtensionWireError::LocalRefusal {code:"invalid_request".into(),message:"Tab mark must be handoff or deliverable".into()});
                }
                let params=self.params(&call,json!({"tabId":claim.tab,"status":status}))?;
                (Stage::Mark {tab:claim.tab,status},Method::MarkTab,params)
            }
            "finishTurn"=>{
                self.validate_finish(&call)?;
                match fields.get("keep").filter(|value|!value.is_null()) {
                    Some(keep)=>{if !keep.is_array(){return Err(ExtensionWireError::Protocol("Finish keep plan must be an array".to_owned()));}let params=self.params(&call,json!({"keep":keep}))?;(Stage::Finish,Method::FinalizeTabs,params)},
                    None=>{let params=self.params(&call,json!({}))?;(Stage::Finish,Method::TurnEnded,params)}
                }
            }
            "setSessionHeaders"|"clearSessionHeaders"=>{
                let headers=if method=="clearSessionHeaders"{json!([])}else{fields.get("headers").cloned().ok_or_else(||ExtensionWireError::LocalRefusal {code:"invalid_request".to_owned(),message:"Session header policy is missing".to_owned()})?};
                let Some(entries)=headers.as_array()else{return Err(ExtensionWireError::LocalRefusal {code:"invalid_request".to_owned(),message:"Session header policy must be an array".to_owned()});};
                if entries.len()>16{return Err(ExtensionWireError::LocalRefusal {code:"invalid_request".to_owned(),message:"ChatGPT session header policy cap is16".to_owned()});}
                let active=!entries.is_empty();
                let mut params=self.params(&call,json!({}))?;
                // This policy is supplied by the trusted Host's session-level
                // coalescer; it is deliberately not represented as per-claim proof.
                params["request_headers"]=headers;
                (Stage::SessionHeaders {active},Method::GetTabs,params)
            }
            "moveMouse"=>{
                let token=required_string(&fields,"claim")?;let claim=self.owned_claim(&call,&token)?;
                let x=fields.get("x").and_then(Value::as_f64).filter(|x|x.is_finite()).ok_or_else(||ExtensionWireError::LocalRefusal {code:"invalid_request".to_owned(),message:"Cursor x must be finite".to_owned()})?;
                let y=fields.get("y").and_then(Value::as_f64).filter(|y|y.is_finite()).ok_or_else(||ExtensionWireError::LocalRefusal {code:"invalid_request".to_owned(),message:"Cursor y must be finite".to_owned()})?;
                let wait=fields.get("waitForArrival").and_then(Value::as_bool).unwrap_or(true);
                let params=self.params(&call,json!({"tabId":claim.tab,"x":x,"y":y,"waitForArrival":wait}))?;
                (Stage::MoveMouse {arrival_requested:wait},Method::MoveMouse,params)
            }
            "stopCreatedTab"=>{
                let token=required_string(&fields,"creation")?;let context=self.context(&call)?.clone();
                let Some(creation)=self.creations.get(&token).filter(|value|value.owner==call.owner&&value.session==context.host_session_id())else{return Ok(self.failure(&call,"creation_unavailable","Created receipt is not owned by this exact endpoint/session",Value::Null));};
                if !creation.finish_observed{return Ok(self.failure(&call,"turn_finish_required","Automatic Created cleanup requires the trusted once-per-turn finish plan first",json!({"creation":token,"createdTurn":creation.turn})));}
                (Stage::ObserveCreated(token),Method::GetUserTabs,json!({}))
            },
            "closeOwner"=>return Ok(self.failure(&call,"outcome_unknown","Owner EOF is not cleanup proof; trusted Host turn finish must supply exact contexts",Value::Null)),
            _=>return Ok(self.failure(&call,"unsupported","This ChatGPT semantic adaptation has no source-proven mapping yet",json!({"method":method}))),
        };
        let initial_attach = match &stage {
            Stage::ClaimForAttach(tab) | Stage::PreTargets(tab) => Some(*tab),
            _ => None,
        };
        self.queue(
            Task {
                call: Some(call),
                stage,
                candidate_target: None,
                attach_acknowledged: false,
                finish_observed: false,
                activation_epoch: None,
                write_phase: WritePhase::Unwritten,
                initial_attach,
            },
            extension,
            params,
            now,
        )
    }
}

fn activates_session(method: Method) -> bool {
    matches!(
        method,
        Method::GetTabs
            | Method::GetCommittedTabUrl
            | Method::CreateTab
            | Method::ClaimUserTab
            | Method::Attach
            | Method::ExecuteCdp
            | Method::ExecuteTabRead
            | Method::MoveMouse
            | Method::NameSession
            | Method::GetUserHistory
            | Method::MarkTab
    )
}

#[cfg(test)]
mod passive_phase_tests {
    use super::super::extension_wire::rpc_phase_test::Capture;
    use super::*;

    #[test]
    fn queued_and_out_of_order_canceled_phases_keep_their_original_metadata() {
        let capture = Capture::default();
        let now = Instant::now();
        let mut adapter = ChatgptWireAdapter::new(
            "trace-generation".to_owned(),
            "hehggadaopoacecdllhhajmbjkdcmajg".to_owned(),
        )
        .unwrap();
        let mut ids = Vec::new();
        tracing::subscriber::with_default(capture.clone(), || {
            for (outer, turn) in [("41", "turn-old"), ("42", "turn-new")] {
                let actions = adapter
                    .queue(
                        Task {
                            call: Some(Call {
                                outer: outer.to_owned(),
                                owner: "fixture-owner".to_owned(),
                                context: Some(
                                    ExtensionWireContext::new("fixture-session", turn).unwrap(),
                                ),
                                cancelled: false,
                                payload_released: false,
                            }),
                            stage: Stage::Inventory,
                            candidate_target: None,
                            attach_acknowledged: false,
                            finish_observed: false,
                            activation_epoch: None,
                            write_phase: WritePhase::Unwritten,
                            initial_attach: None,
                        },
                        Method::GetUserTabs,
                        json!({"headers":"HEADER_SENTINEL"}),
                        now,
                    )
                    .unwrap();
                let id = actions
                    .into_iter()
                    .find_map(|action| match action {
                        ExtensionWireAction::ExtensionFrame {
                            message,
                            trace: Some(_),
                            ..
                        } => message["id"].as_str().map(str::to_owned),
                        _ => None,
                    })
                    .expect("each actual phase carries typed captured metadata");
                ids.push(id);
            }
            assert!(
                capture.rows().is_empty(),
                "queue is not actual frame completion"
            );
            let _ = adapter.on_cancel("41");
            for id in [ids[1].clone(), ids[0].clone()] {
                adapter
                    .on_extension(json!({"jsonrpc":"2.0","id":id,"result":[]}), now)
                    .unwrap();
            }
        });
        let rows = capture.rows();
        assert_eq!(rows.len(), 4);
        for (pair, id, semantic, turn) in [
            (&rows[..2], &ids[1], "42", "turn-new"),
            (&rows[2..], &ids[0], "41", "turn-old"),
        ] {
            assert_eq!(pair[0]["phase"], "reply_id_matched");
            assert_eq!(pair[1]["phase"], "rpc_completion");
            assert_eq!(pair[0]["extension_rpc_id"], *id);
            assert_eq!(pair[1]["extension_rpc_id"], *id);
            assert_eq!(pair[1]["semantic_id"], format!("Some({semantic:?})"));
            assert_eq!(pair[1]["host_turn_id"], format!("Some({turn:?})"));
            assert_eq!(pair[0]["extension_host_pid"], pair[1]["extension_host_pid"]);
        }
        assert!(!format!("{rows:?}").contains("HEADER_SENTINEL"));
    }
}

#[cfg(test)]
#[path = "chatgpt_fixed_session_profile_tests.rs"]
mod fixed_session_profile_tests;
