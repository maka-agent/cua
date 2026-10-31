// SPDX-License-Identifier: MIT

use super::*;

const GEN: &str = "11111111-1111-4111-8111-111111111111";
const SID: &str = "22222222-2222-4222-8222-222222222222";
const EXT: &str = "hehggadaopoacecdllhhajmbjkdcmajg";

// Translator unit fixtures explicitly cross the local first-write boundary before
// delivering replies. These synchronous hooks do not prove OS bytes or Chrome.
impl ChatgptWireAdapter {
    fn written_actions(
        &mut self,
        actions: Vec<ExtensionWireAction>,
    ) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
        for action in &actions {
            if let ExtensionWireAction::ExtensionFrame {
                phase: Some(phase), ..
            } = action
            {
                self.commit_write(phase)?;
            }
        }
        Ok(actions)
    }
    fn written_start(
        &mut self,
        now: Instant,
    ) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
        let actions = ExtensionWireAdapter::start(self, now)?;
        self.written_actions(actions)
    }
    fn written_semantic(
        &mut self,
        envelope: Value,
        context: Option<&ExtensionWireContext>,
        now: Instant,
    ) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
        let actions = ExtensionWireAdapter::on_semantic(self, envelope, context, now)?;
        self.written_actions(actions)
    }
    fn written_extension_json(
        &mut self,
        frame: &RawValue,
        now: Instant,
    ) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
        let actions = ExtensionWireAdapter::on_extension_json(self, frame, now)?;
        self.written_actions(actions)
    }
    fn written_extension(
        &mut self,
        frame: Value,
        now: Instant,
    ) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
        let actions = ExtensionWireAdapter::on_extension(self, frame, now)?;
        self.written_actions(actions)
    }
}

fn frame(actions: &[ExtensionWireAction]) -> Value {
    actions
        .iter()
        .find_map(|action| match action {
            ExtensionWireAction::ExtensionFrame { message, .. } => Some(message.clone()),
            _ => None,
        })
        .expect("one actual extension request")
}
fn response(actions: &[ExtensionWireAction]) -> Value {
    actions
        .iter()
        .find_map(|action| match action {
            ExtensionWireAction::BrokerMessage(value)
            | ExtensionWireAction::MatchedBrokerMessage { message: value, .. }
                if value["kind"] == "response" =>
            {
                Some(value.clone())
            }
            _ => None,
        })
        .expect("one semantic terminal response")
}
fn boot() -> (ChatgptWireAdapter, ExtensionWireContext, Instant) {
    let now = Instant::now();
    let mut adapter =
        ChatgptWireAdapter::new(GEN.to_owned(), EXT.to_owned()).expect("valid adapter");
    let request = frame(&adapter.written_start(now).expect("bootstrap"));
    let info = json!({"type":"extension","version":"observed","metadata":{"extensionId":EXT,"extensionInstanceId":"instance"}});
    let actions = adapter
        .written_extension(
            json!({"jsonrpc":"2.0","id":request["id"],"result":info}),
            now,
        )
        .expect("matched getInfo");
    assert!(actions.iter().any(|action| matches!(action, ExtensionWireAction::BrokerMessage(value) if value["capabilities"]["userTabsOrder"] == "provider")));
    assert!(actions.iter().any(|action| matches!(action, ExtensionWireAction::BrokerMessage(value) if value["capabilities"]["attachmentPreparation"] == "full_preparation")));
    assert!(actions.iter().any(|action| matches!(action, ExtensionWireAction::BrokerMessage(value) if value["capabilities"]["sessionCommittedUrl"] == true)));
    (
        adapter,
        ExtensionWireContext::new(SID, "turn1").expect("trusted context"),
        now,
    )
}
fn semantic(id: &str, method: &str, params: Value) -> Value {
    json!({"kind":"request","protocol":1,"generation":GEN,"id":id,"owner":"owner","method":method,"params":params})
}
fn reply(
    adapter: &mut ChatgptWireAdapter,
    request: &Value,
    result: Value,
    now: Instant,
) -> Vec<ExtensionWireAction> {
    adapter
        .written_extension(
            json!({"jsonrpc":"2.0","id":request["id"],"result":result}),
            now,
        )
        .expect("matched extension result")
}

#[test]
fn metadata_preserves_provider_order_iso_and_opaque_id_without_clock_facts() {
    let (mut adapter, _, now) = boot();
    let request = frame(
        &adapter
            .written_semantic(semantic("1", "inventory", json!({})), None, now)
            .expect("metadata"),
    );
    let actions = reply(
        &mut adapter,
        &request,
        json!([{"id":9,"lastOpened":"2026-10-27T00:00:00.000Z","providerTabId":"opaque","tabGroup":"actual"},{"id":1}]),
        now,
    );
    let value = response(&actions);
    assert_eq!(value["result"]["tabs"][0]["id"], 9);
    assert_eq!(
        value["result"]["tabs"][0]["lastOpened"],
        "2026-10-27T00:00:00.000Z"
    );
    assert_eq!(value["result"]["tabs"][0]["providerTabId"], "opaque");
    assert_eq!(value["result"]["tabs"][0]["groupTitleJson"], "\"actual\"");
    assert!(value["result"]["tabs"][0].get("lastAccessed").is_none());
}

#[test]
fn mutation_without_trusted_context_has_no_native_dispatch() {
    let (mut adapter, _, now) = boot();
    assert!(matches!(
        adapter.written_semantic(semantic("1", "createTab", json!({})), None, now),
        Err(ExtensionWireError::LocalRefusal { .. })
    ));
    assert_eq!(adapter.rpc.pending_len(), 0);
}

#[test]
fn cancelled_attach_keeps_only_cleanup_receipt_after_exact_void_ack() {
    let (mut adapter, context, now) = boot();
    let claim = frame(
        &adapter
            .written_semantic(
                semantic("1", "attach", json!({"tabId":7})),
                Some(&context),
                now,
            )
            .expect("attach"),
    );
    assert_eq!(claim["method"], "claimUserTab");
    assert_eq!(claim["params"]["session_id"], SID);
    assert_eq!(claim["params"]["turn_id"], "turn1");
    let target = frame(&reply(
        &mut adapter,
        &claim,
        json!({"id":7,"url":"about:blank"}),
        now,
    ));
    let attach = frame(&reply(
        &mut adapter,
        &target,
        json!({"targetInfos":[{"tabId":7,"type":"page","targetId":"actual-target","attached":false}]}),
        now,
    ));
    adapter.on_cancel("1");
    let actions = adapter
        .written_extension(json!({"jsonrpc":"2.0","id":attach["id"]}), now)
        .expect("void ack");
    assert!(!actions
        .iter()
        .any(|action| matches!(action, ExtensionWireAction::ExtensionFrame { .. })));
    let value = response(&actions);
    assert_eq!(value["error"]["kind"], "outcome_unknown");
    let token = value["error"]["details"]["custody"]["claim"]
        .as_str()
        .expect("cleanup receipt");
    assert!(!adapter.claims[token].live);
    assert!(adapter
        .written_semantic(
            semantic(
                "2",
                "cdp",
                json!({"claim":token,"method":"Input.insertText","params":{"text":"never"}})
            ),
            Some(&context),
            now
        )
        .is_err());
}

#[test]
fn finish_cancels_pending_attach_and_cannot_resume_it_after_stop() {
    let (mut adapter, context, now) = boot();
    let request = frame(
        &adapter
            .written_semantic(
                semantic("1", "attach", json!({"tabId":7})),
                Some(&context),
                now,
            )
            .expect("attach"),
    );
    let finish = frame(
        &adapter
            .written_semantic(
                semantic("2", "finishTurn", json!({"keep":null})),
                Some(&context),
                now,
            )
            .expect("finish"),
    );
    assert_eq!(finish["method"], "turnEnded");
    let actions = reply(&mut adapter, &request, json!({"id":7}), now);
    assert!(!actions
        .iter()
        .any(|action| matches!(action, ExtensionWireAction::ExtensionFrame { .. })));
    assert_eq!(response(&actions)["error"]["kind"], "outcome_unknown");
    assert!(adapter.claims.values().all(|claim| !claim.live));
}

#[test]
fn created_stop_observes_absence_only_after_logical_finish_ack() {
    let (mut adapter, context, now) = boot();
    let create = frame(
        &adapter
            .written_semantic(semantic("1", "createTab", json!({})), Some(&context), now)
            .expect("create"),
    );
    let created = response(&reply(
        &mut adapter,
        &create,
        json!({"id":7,"url":"about:blank"}),
        now,
    ));
    let creation = created["result"]["creation"].clone();
    assert!(adapter
        .written_semantic(
            semantic("2", "stopCreatedTab", json!({"creation":creation})),
            Some(&context),
            now
        )
        .is_err());
    let finish = frame(
        &adapter
            .written_semantic(
                semantic("3", "finishTurn", json!({"keep":null})),
                Some(&context),
                now,
            )
            .expect("finish"),
    );
    let ack = adapter
        .written_extension(json!({"jsonrpc":"2.0","id":finish["id"]}), now)
        .expect("void ack");
    let logical = response(&ack);
    assert_eq!(logical["result"]["turnFinished"], true);
    assert!(logical["result"].get("closed").is_none());
    let observe = frame(
        &adapter
            .written_semantic(
                semantic("4", "stopCreatedTab", json!({"creation":creation})),
                Some(&context),
                now,
            )
            .expect("fresh observation"),
    );
    assert_eq!(observe["method"], "getUserTabs");
    assert_eq!(observe["params"], json!({}));
    let observed = response(&reply(&mut adapter, &observe, json!([]), now));
    assert_eq!(observed["result"]["proof"], "tab_absent");
    assert_eq!(observed["result"]["closed"], true);
    assert_eq!(observed["result"]["observation"]["owner"], "owner");
    assert_eq!(observed["result"]["observation"]["hostSessionId"], SID);
    assert_eq!(observed["result"]["observation"]["generation"], GEN);
    assert_eq!(
        observed["result"]["observation"]["extensionInstanceId"],
        "instance"
    );
    assert_eq!(observed["result"]["observation"]["count"], 0);
    assert_eq!(observed["result"]["observation"]["empty"], true);
}

fn before_attach_ack(
    adapter: &mut ChatgptWireAdapter,
    context: &ExtensionWireContext,
    id: &str,
    tab: u64,
    now: Instant,
) -> Value {
    let mut request = frame(
        &adapter
            .written_semantic(
                semantic(id, "attach", json!({"tabId":tab})),
                Some(context),
                now,
            )
            .expect("admit exact owned raw tab"),
    );
    if request["method"] == "claimUserTab" {
        request = frame(&reply(
            adapter,
            &request,
            json!({"id":tab,"url":"about:blank"}),
            now,
        ));
    }
    assert_eq!(request["method"], "executeCdp");
    let attach = frame(&reply(
        adapter,
        &request,
        json!({"targetInfos":[{"tabId":tab,"type":"page","targetId":format!("target-{tab}"),"attached":false}]}),
        now,
    ));
    assert_eq!(attach["method"], "attach");
    attach
}

fn attached(
    adapter: &mut ChatgptWireAdapter,
    context: &ExtensionWireContext,
    id: &str,
    tab: u64,
    now: Instant,
) -> String {
    let attach = before_attach_ack(adapter, context, id, tab, now);
    let probe = frame(
        &adapter
            .written_extension(json!({"jsonrpc":"2.0","id":attach["id"]}), now)
            .expect("exact void attach acknowledgement"),
    );
    let targets = frame(&reply(adapter, &probe, json!({"result":{"value":0}}), now));
    let output = response(&reply(
        adapter,
        &targets,
        json!({"targetInfos":[{"tabId":tab,"type":"page","targetId":format!("target-{tab}"),"attached":true}]}),
        now,
    ));
    output["result"]["claim"]
        .as_str()
        .expect("actual matched claim")
        .to_owned()
}

#[test]
fn settled_old_token_never_detaches_a_new_raw_tab_epoch() {
    let (mut adapter, context, now) = boot();
    let old = attached(&mut adapter, &context, "1", 7, now);
    let detach = frame(
        &adapter
            .written_semantic(
                semantic("2", "detach", json!({"claim":old})),
                Some(&context),
                now,
            )
            .expect("owned detach"),
    );
    let ack = adapter
        .written_extension(json!({"jsonrpc":"2.0","id":detach["id"]}), now)
        .expect("detach acknowledgement");
    assert_eq!(response(&ack)["result"]["proof"], "detach_ack");
    let new = attached(&mut adapter, &context, "3", 7, now);
    assert_ne!(new, old);
    assert!(adapter
        .written_semantic(
            semantic("4", "detach", json!({"claim":old})),
            Some(&context),
            now
        )
        .is_err());
    assert_eq!(
        adapter.rpc.pending_len(),
        0,
        "old token must not dispatch any extension request"
    );
    assert!(adapter.claims[&new].live);
    assert_eq!(adapter.current_claim[&7], new);
}

#[test]
fn move_and_header_turn_activation_retire_the_whole_session_at_finish() {
    for operation in ["moveMouse", "setSessionHeaders"] {
        let (mut adapter, turn1, now) = boot();
        let first = attached(&mut adapter, &turn1, "1", 7, now);
        let second = attached(&mut adapter, &turn1, "2", 8, now);
        let turn2 = ExtensionWireContext::new(SID, "turn2").expect("next trusted turn");
        let params = if operation == "moveMouse" {
            json!({"claim":first,"x":1,"y":2,"waitForArrival":false})
        } else {
            json!({"headers":[{"name":"x-browser-agent","value":"Maka/test"}]})
        };
        let activation = frame(
            &adapter
                .written_semantic(semantic("3", operation, params), Some(&turn2), now)
                .expect("admit source-proven session activation"),
        );
        let extension_result = if operation == "moveMouse" {
            Value::Null
        } else {
            json!([])
        };
        reply(&mut adapter, &activation, extension_result, now);
        let finish = frame(
            &adapter
                .written_semantic(
                    semantic("4", "finishTurn", json!({"keep":null})),
                    Some(&turn2),
                    now,
                )
                .expect("finish the moved session"),
        );
        adapter
            .written_extension(json!({"jsonrpc":"2.0","id":finish["id"]}), now)
            .expect("finish acknowledgement");
        for token in [&first, &second] {
            assert!(
                !adapter.claims[token].live,
                "{operation} must retire every matching physical claim"
            );
            assert!(adapter.written_semantic(semantic("5", "cdp", json!({"claim":token,"method":"Input.insertText","params":{"text":"forbidden"}})), Some(&turn2), now).is_err());
        }
        assert!(
            adapter
                .written_semantic(semantic("6", "finishTurn", json!({})), Some(&turn2), now)
                .is_err(),
            "finish ACK does not authorize replay"
        );
        assert_eq!(adapter.rpc.pending_len(), 0);
    }
}

#[test]
fn locally_refused_cdp_does_not_activate_a_different_turn() {
    let (mut adapter, context, now) = boot();
    let token = attached(&mut adapter, &context, "1", 7, now);
    let turn2 = ExtensionWireContext::new(SID, "turn2").expect("next trusted turn");
    assert!(adapter
        .written_semantic(
            semantic(
                "2",
                "cdp",
                json!({"claim":token,"method":"Target.getTargetInfo","params":{"targetId":"foreign-target"}})
            ),
            Some(&turn2),
            now
        )
        .is_err());
    assert_eq!(adapter.rpc.pending_len(), 0);
    assert_eq!(adapter.session_turns[SID].turn, "turn1");
    assert_eq!(adapter.claims[&token].turn, "turn1");
    let finish = frame(
        &adapter
            .written_semantic(semantic("3", "finishTurn", json!({})), Some(&context), now)
            .expect("original admitted turn remains current"),
    );
    assert_eq!(finish["params"]["turn_id"], "turn1");
}

#[test]
fn late_old_turn_acknowledgement_cannot_rewind_the_current_turn() {
    let (mut adapter, turn1, now) = boot();
    let token = attached(&mut adapter, &turn1, "1", 7, now);
    let old = frame(
        &adapter
            .written_semantic(
                semantic(
                    "2",
                    "cdp",
                    json!({"claim":token,"method":"Page.enable","params":{}}),
                ),
                Some(&turn1),
                now,
            )
            .expect("old extension command"),
    );
    let turn2 = ExtensionWireContext::new(SID, "turn2").expect("next trusted turn");
    let new = frame(
        &adapter
            .written_semantic(
                semantic("3", "moveMouse", json!({"claim":token,"x":1,"y":2})),
                Some(&turn2),
                now,
            )
            .expect("new admitted activation"),
    );
    reply(&mut adapter, &new, Value::Null, now);
    let epoch = adapter.session_turns[SID].epoch;
    let old_reply = reply(&mut adapter, &old, json!({}), now);
    assert_eq!(response(&old_reply)["error"]["kind"], "outcome_unknown");
    assert_eq!(adapter.session_turns[SID].epoch, epoch);
    assert_eq!(adapter.session_turns[SID].turn, "turn2");
    assert_eq!(adapter.claims[&token].turn, "turn2");
    assert!(adapter
        .written_semantic(semantic("4", "finishTurn", json!({})), Some(&turn1), now)
        .is_err());
    assert_eq!(adapter.rpc.pending_len(), 0);
}

#[test]
fn unknown_finish_is_consumed_and_never_replayed() {
    let (mut adapter, context, now) = boot();
    let token = attached(&mut adapter, &context, "1", 7, now);
    adapter
        .written_semantic(semantic("2", "finishTurn", json!({})), Some(&context), now)
        .expect("single finish dispatch");
    let expired = adapter.expire(now + DEADLINE + Duration::from_millis(1));
    assert_eq!(response(&expired)["error"]["kind"], "outcome_unknown");
    assert!(adapter
        .written_semantic(semantic("3", "finishTurn", json!({})), Some(&context), now)
        .is_err());
    let turn2 = ExtensionWireContext::new(SID, "turn2").expect("next trusted turn");
    assert!(adapter
        .written_semantic(
            semantic("4", "moveMouse", json!({"claim":token,"x":1,"y":2})),
            Some(&turn2),
            now
        )
        .is_err());
    assert_eq!(adapter.rpc.pending_len(), 0);
}

#[test]
fn post_attach_probe_protocol_failure_keeps_non_executable_cleanup_custody() {
    let (mut adapter, context, now) = boot();
    let attach = before_attach_ack(&mut adapter, &context, "1", 7, now);
    let probe = frame(
        &adapter
            .written_extension(json!({"jsonrpc":"2.0","id":attach["id"]}), now)
            .expect("attach acknowledgement"),
    );
    let output = reply(&mut adapter, &probe, json!({"result":{"value":99}}), now);
    assert!(!output
        .iter()
        .any(|action| matches!(action, ExtensionWireAction::ExtensionFrame { .. })));
    let terminal = response(&output);
    let custody = &terminal["error"]["details"]["custody"];
    let token = custody["claim"]
        .as_str()
        .expect("exact positive-ACK receipt retained");
    assert_eq!(custody["tabId"], 7);
    assert_eq!(custody["acquisitionConfirmed"], false);
    assert!(!adapter.claims[token].live);
    let detach = frame(
        &adapter
            .written_semantic(
                semantic("2", "detach", json!({"claim":token})),
                Some(&context),
                now,
            )
            .expect("existing source-proven ChatGPT cleanup semantic"),
    );
    assert_eq!(detach["method"], "detach");
    assert_eq!(detach["params"]["tabId"], 7);
    assert_eq!(detach["params"]["session_id"], SID);
    assert_eq!(adapter.rpc.pending_len(), 1);
    assert!(
        matches!(output.last(), Some(ExtensionWireAction::SemanticFinished { semantic_id }) if semantic_id == "1")
    );
}

#[test]
fn changed_post_attach_target_keeps_receipt_without_claiming_new_identity() {
    let (mut adapter, context, now) = boot();
    let attach = before_attach_ack(&mut adapter, &context, "1", 7, now);
    let probe = frame(
        &adapter
            .written_extension(json!({"jsonrpc":"2.0","id":attach["id"]}), now)
            .expect("attach acknowledgement"),
    );
    let targets = frame(&reply(
        &mut adapter,
        &probe,
        json!({"result":{"value":0}}),
        now,
    ));
    let output = reply(
        &mut adapter,
        &targets,
        json!({"targetInfos":[{"tabId":7,"type":"page","targetId":"different-target","attached":true}]}),
        now,
    );
    let terminal = response(&output);
    let custody = &terminal["error"]["details"]["custody"];
    assert_eq!(
        custody["targetId"], "target-7",
        "new identity must not be adopted"
    );
    let token = custody["claim"]
        .as_str()
        .expect("prior positive attach custody");
    assert!(!adapter.claims[token].live);
    assert!(!output
        .iter()
        .any(|action| matches!(action, ExtensionWireAction::ExtensionFrame { .. })));
    assert_eq!(adapter.rpc.pending_len(), 0);
}

#[test]
fn clearing_headers_after_finish_does_not_reactivate_the_turn() {
    let (mut adapter, context, now) = boot();
    attached(&mut adapter, &context, "1", 7, now);
    let finish = frame(
        &adapter
            .written_semantic(semantic("2", "finishTurn", json!({})), Some(&context), now)
            .expect("finish"),
    );
    adapter
        .written_extension(json!({"jsonrpc":"2.0","id":finish["id"]}), now)
        .expect("finish acknowledgement");
    assert!(adapter
        .written_semantic(
            semantic("3", "clearSessionHeaders", json!({})),
            Some(&context),
            now
        )
        .is_err());
    assert_eq!(
        adapter.rpc.pending_len(),
        0,
        "GetTabs would reactivate the finished turn"
    );
}

#[test]
fn target_and_browser_domain_names_are_forwarded_without_invented_capability_refusals() {
    for method in ["Target.getTargetInfo", "Browser.getVersion"] {
        let (mut adapter, context, now) = boot();
        let token = attached(&mut adapter, &context, "1", 7, now);
        let request = frame(
            &adapter
                .written_semantic(
                    semantic(
                        "2",
                        "cdp",
                        json!({"claim":token,"method":method,"params":{}}),
                    ),
                    Some(&context),
                    now,
                )
                .expect("ChatGPT forwards the named CDP method"),
        );
        assert_eq!(request["method"], "executeCdp");
        assert_eq!(request["params"]["target"]["tabId"], 7);
        assert_eq!(request["params"]["method"], method);
        assert_eq!(request["params"]["commandParams"], json!({}));
        let error = adapter.written_extension(json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":1,"message":"actual extension rejection"}}), now).expect("matched ChatGPT rejection");
        assert_eq!(response(&error)["error"]["kind"], "outcome_unknown");
        assert_eq!(
            response(&error)["error"]["details"]["provenance"],
            "mixed_extension_or_chrome"
        );
        assert!(!error
            .iter()
            .any(|action| matches!(action, ExtensionWireAction::ExtensionFrame { .. })));
    }
}

#[test]
fn extension_download_metadata_preserves_actual_id_without_fabricating_ownership() {
    let (mut adapter, _, now) = boot();
    let event = json!({"id":"0","filename":"/native/fixture.file","url":"https://fixture.invalid/file","status":"complete"});
    let output = adapter
        .written_extension(
            json!({"jsonrpc":"2.0","method":"onDownloadChange","params":event}),
            now,
        )
        .expect("extension metadata notification");
    let normalized = output
        .iter()
        .find_map(|action| match action {
            ExtensionWireAction::BrokerMessage(value) if value["kind"] == "download_changed" => {
                Some(value)
            }
            _ => None,
        })
        .expect("existing extension download metadata event");
    assert_eq!(normalized["download"], event);
    for key in ["owner", "claim", "sessionId", "tabId", "approved", "bytes"] {
        assert!(
            normalized.get(key).is_none(),
            "global metadata must not invent {key}"
        );
    }
    assert_eq!(adapter.rpc.pending_len(), 0);
}

#[test]
fn protocol_end_flushes_prior_positive_attach_custody_before_actor_shutdown() {
    let (mut adapter, context, now) = boot();
    let attach = before_attach_ack(&mut adapter, &context, "1", 7, now);
    let _probe = frame(
        &adapter
            .written_extension(json!({"jsonrpc":"2.0","id":attach["id"]}), now)
            .expect("positive attach ACK"),
    );
    let actions = adapter
        .written_extension(json!({"jsonrpc":"bad"}), now)
        .expect("ordered terminal normalization");
    let terminal = response(&actions);
    assert_eq!(terminal["error"]["details"]["custody"]["tabId"], 7);
    assert_eq!(
        terminal["error"]["details"]["custody"]["acquisitionConfirmed"],
        false
    );
    let finished = actions.iter().position(|action| matches!(action, ExtensionWireAction::SemanticFinished { semantic_id } if semantic_id == "1")).expect("semantic bookkeeping terminal");
    let end = actions
        .iter()
        .position(|action| matches!(action, ExtensionWireAction::TransportEnded { .. }))
        .expect("generation shutdown after custody");
    assert!(finished < end);
    assert_eq!(adapter.rpc.pending_len(), 0);
    assert!(adapter.ended);
}

#[test]
fn tokenless_detach_uses_the_existing_revocation_envelope_without_cleanup_proof() {
    let (mut adapter, context, now) = boot();
    let token = attached(&mut adapter, &context, "1", 7, now);
    let actions = adapter
        .written_extension(
            json!({"jsonrpc":"2.0","method":"onCDPDetach","params":{"tabId":7}}),
            now,
        )
        .expect("original root detach notification");
    let event = actions
        .iter()
        .find_map(|action| match action {
            ExtensionWireAction::BrokerMessage(value) if value["kind"] == "revoked" => Some(value),
            _ => None,
        })
        .expect("canonical existing broker revocation kind");
    assert_eq!(event["claim"], token);
    assert_eq!(event["owner"], "owner");
    assert!(event.get("proof").is_none());
    assert!(!adapter.claims[&token].live);
}

#[test]
fn old_same_turn_failure_cannot_reopen_an_acknowledged_finish() {
    let (mut adapter, turn1, now) = boot();
    let token = attached(&mut adapter, &turn1, "1", 7, now);
    let old = frame(
        &adapter
            .written_semantic(
                semantic(
                    "2",
                    "cdp",
                    json!({"claim":token,"method":"Page.enable","params":{}}),
                ),
                Some(&turn1),
                now,
            )
            .expect("old accepted extension call"),
    );
    let finish = frame(
        &adapter
            .written_semantic(semantic("3", "finishTurn", json!({})), Some(&turn1), now)
            .expect("exact turn finish"),
    );
    adapter
        .written_extension(json!({"jsonrpc":"2.0","id":finish["id"]}), now)
        .expect("finish acknowledgement");
    adapter
        .written_extension(
            json!({"jsonrpc":"2.0","id":old["id"],"error":{"code":1,"message":"late old failure"}}),
            now,
        )
        .expect("matched older extension failure");
    assert_eq!(adapter.session_turns[SID].phase, TurnPhase::Finished);
    assert!(adapter
        .written_semantic(semantic("4", "finishTurn", json!({})), Some(&turn1), now)
        .is_err());
    let turn2 = ExtensionWireContext::new(SID, "turn2").expect("next trusted turn");
    let next = frame(
        &adapter
            .written_semantic(semantic("5", "createTab", json!({})), Some(&turn2), now)
            .expect("new trusted turn remains available"),
    );
    assert_eq!(next["method"], "createTab");
    assert_eq!(next["params"]["turn_id"], "turn2");
}

#[test]
fn activation_uncertainty_preserves_the_single_original_turn_cleanup_attempt() {
    let (mut adapter, context, now) = boot();
    let token = attached(&mut adapter, &context, "1", 7, now);
    let request = frame(
        &adapter
            .written_semantic(
                semantic(
                    "2",
                    "cdp",
                    json!({"claim":token,"method":"Page.enable","params":{}}),
                ),
                Some(&context),
                now,
            )
            .expect("accepted extension call"),
    );
    adapter.written_extension(json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":1,"message":"uncertain activation"}}), now).expect("matched extension failure");
    let finish = frame(
        &adapter
            .written_semantic(semantic("3", "finishTurn", json!({})), Some(&context), now)
            .expect("unknown activation must not forbid cleanup"),
    );
    assert_eq!(finish["method"], "turnEnded");
    adapter
        .written_extension(json!({"jsonrpc":"2.0","id":finish["id"]}), now)
        .expect("actual cleanup acknowledgement");
    assert_eq!(adapter.session_turns[SID].phase, TurnPhase::Finished);
    assert!(adapter
        .written_semantic(semantic("4", "finishTurn", json!({})), Some(&context), now)
        .is_err());
}

#[test]
fn bootstrap_timeout_ends_the_native_generation_without_retry_or_fabricated_hello() {
    let now = Instant::now();
    let mut adapter =
        ChatgptWireAdapter::new(GEN.to_owned(), EXT.to_owned()).expect("valid adapter");
    let first = adapter.written_start(now).expect("single bootstrap call");
    assert_eq!(frame(&first)["method"], "getInfo");
    let expired = adapter.expire(now + DEADLINE + Duration::from_millis(1));
    assert!(adapter.ended);
    assert!(!adapter.ready);
    assert_eq!(adapter.rpc.pending_len(), 0);
    assert!(expired
        .iter()
        .any(|action| matches!(action, ExtensionWireAction::TransportEnded { .. })));
    assert!(!expired
        .iter()
        .any(|action| matches!(action, ExtensionWireAction::ExtensionFrame { .. })));
    assert!(!expired.iter().any(|action| matches!(action, ExtensionWireAction::BrokerMessage(value) if value["kind"] == "hello")));
}

#[test]
fn capped_user_inventory_absence_is_unknown_but_present_raw_id_still_resolves() {
    for (count, raw_id, expected) in [
        (999, 1001, "tab_unavailable"),
        (1000, 1001, "inventory_truncated"),
        (1000, 1000, "present"),
    ] {
        let (mut adapter, _, now) = boot();
        let request = frame(
            &adapter
                .written_semantic(
                    semantic("1", "resolve", json!({"rawId":raw_id.to_string()})),
                    None,
                    now,
                )
                .expect("readonly raw ID inventory lookup"),
        );
        assert_eq!(request["method"], "getUserTabs");
        assert_eq!(request["params"], json!({}));
        let tabs: Vec<_> = (1..=count)
            .map(|id| json!({"id":id,"url":"https://fixture.invalid/"}))
            .collect();
        let output = response(&reply(&mut adapter, &request, json!(tabs), now));
        if expected == "present" {
            assert_eq!(output["result"]["tab"]["id"], raw_id);
        } else {
            assert_eq!(output["error"]["kind"], expected, "count={count}");
        }
        assert!(
            adapter.leases.is_empty(),
            "readonly lookup must not claim or attach before admission"
        );
        assert!(adapter.claims.is_empty());
    }
}

#[test]
fn managed_raw_id_resolves_through_the_exact_uncapped_owned_session_inventory() {
    let (mut adapter, context, now) = boot();
    let create = frame(
        &adapter
            .written_semantic(semantic("1", "createTab", json!({})), Some(&context), now)
            .expect("existing owned creation"),
    );
    reply(
        &mut adapter,
        &create,
        json!({"id":2001,"url":"about:blank"}),
        now,
    );
    let request = frame(
        &adapter
            .written_semantic(
                semantic("2", "resolve", json!({"rawId":"2001"})),
                Some(&context),
                now,
            )
            .expect("resolve existing owned logical lease"),
    );
    assert_eq!(request["method"], "getTabs");
    assert_eq!(request["params"]["session_id"], SID);
    assert_eq!(request["params"]["turn_id"], "turn1");
    let tabs: Vec<_> = (1..=2001)
        .map(|id| json!({"id":id,"url":"about:blank"}))
        .collect();
    let result = response(&reply(&mut adapter, &request, json!(tabs), now));
    assert_eq!(result["result"]["tab"]["id"], 2001);
    assert!(
        adapter.claims.is_empty(),
        "managed metadata lookup must not physically attach"
    );
    assert_eq!(adapter.leases.len(), 1);
}

#[test]
fn known_managed_id_without_its_trusted_context_does_not_borrow_session_authority() {
    let (mut adapter, context, now) = boot();
    let create = frame(
        &adapter
            .written_semantic(semantic("1", "createTab", json!({})), Some(&context), now)
            .expect("owned creation"),
    );
    reply(
        &mut adapter,
        &create,
        json!({"id":2001,"url":"about:blank"}),
        now,
    );
    let request = frame(
        &adapter
            .written_semantic(semantic("2", "resolve", json!({"rawId":"2001"})), None, now)
            .expect("context-free metadata remains global inventory"),
    );
    assert_eq!(request["method"], "getUserTabs");
    assert_eq!(request["params"], json!({}));
    assert_eq!(adapter.session_turns[SID].turn, "turn1");
}

#[test]
fn managed_inventory_native_rejection_does_not_fabricate_a_readonly_outcome() {
    let (mut adapter, context, now) = boot();
    let create = frame(
        &adapter
            .written_semantic(semantic("1", "createTab", json!({})), Some(&context), now)
            .expect("owned creation"),
    );
    reply(
        &mut adapter,
        &create,
        json!({"id":2001,"url":"about:blank"}),
        now,
    );
    let request = frame(
        &adapter
            .written_semantic(
                semantic("2", "resolve", json!({"rawId":"2001"})),
                Some(&context),
                now,
            )
            .expect("managed metadata request"),
    );
    assert_eq!(request["method"], "getTabs");
    let actions = adapter.written_extension(json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":1,"message":"extension failure after possible activation"}}), now).expect("matched extension rejection");
    assert_eq!(response(&actions)["error"]["kind"], "outcome_unknown");
    assert_eq!(
        response(&actions)["error"]["details"]["provenance"],
        "mixed_extension_or_chrome"
    );
    assert_eq!(
        adapter.session_turns[SID].phase,
        TurnPhase::ActivationUnknown
    );
}

fn child_attach(
    adapter: &mut ChatgptWireAdapter,
    context: &ExtensionWireContext,
    outer: &str,
    token: &str,
    now: Instant,
) -> Value {
    frame(&adapter.written_semantic(semantic(outer,"cdp",json!({"claim":token,"method":"Target.attachToTarget","params":{"targetId":"target-7","flatten":true}})), Some(context), now).expect("admitted child attach under exact root"))
}

fn child_event(adapter: &mut ChatgptWireAdapter, method: &str, params: Value, now: Instant) {
    adapter.written_extension(json!({"jsonrpc":"2.0","method":"onCDPEvent","params":{"source":{"tabId":7},"method":method,"params":params}}), now).expect("actual scoped CDP event");
}

fn child_input(
    adapter: &mut ChatgptWireAdapter,
    context: &ExtensionWireContext,
    outer: &str,
    token: &str,
    child: &str,
    now: Instant,
) -> Result<Vec<ExtensionWireAction>, ExtensionWireError> {
    adapter.written_semantic(semantic(outer,"cdp",json!({"claim":token,"sessionId":child,"method":"Input.insertText","params":{"text":"fixture-only"}})), Some(context), now)
}

#[test]
fn exact_attach_ack_grants_child_without_an_attached_event_and_never_before_ack() {
    let (mut adapter, context, now) = boot();
    let token = attached(&mut adapter, &context, "1", 7, now);
    let attach = child_attach(&mut adapter, &context, "2", &token, now);
    assert!(child_input(&mut adapter, &context, "3", &token, "ack-child", now).is_err());
    assert_eq!(
        adapter.rpc.pending_len(),
        1,
        "unobserved child must not dispatch input"
    );
    let ack = response(&reply(
        &mut adapter,
        &attach,
        json!({"sessionId":"ack-child"}),
        now,
    ));
    assert_eq!(ack["result"]["result"]["sessionId"], "ack-child");
    let input = frame(
        &child_input(&mut adapter, &context, "4", &token, "ack-child", now)
            .expect("matched actual ACK is a scoped child receipt"),
    );
    assert_eq!(input["params"]["target"]["tabId"], 7);
    assert_eq!(input["params"]["target"]["sessionId"], "ack-child");
}

#[test]
fn observed_child_detach_before_attach_ack_cannot_revive_child_authority() {
    let (mut adapter, context, now) = boot();
    let token = attached(&mut adapter, &context, "1", 7, now);
    let attach = child_attach(&mut adapter, &context, "2", &token, now);
    child_event(
        &mut adapter,
        "Target.attachedToTarget",
        json!({"sessionId":"child","targetInfo":{"targetId":"target-7"}}),
        now,
    );
    child_event(
        &mut adapter,
        "Target.detachedFromTarget",
        json!({"sessionId":"child"}),
        now,
    );
    let ack = response(&reply(
        &mut adapter,
        &attach,
        json!({"sessionId":"child"}),
        now,
    ));
    assert_eq!(ack["error"]["kind"], "outcome_unknown");
    assert!(child_input(&mut adapter, &context, "3", &token, "child", now).is_err());
    assert!(
        !adapter.children.contains_key(&(7, "child".to_owned())),
        "temporary revocation retires after all pending attach calls settle"
    );
}

#[test]
fn unknown_child_detach_before_ack_is_revocation_only_and_blocks_the_late_ack() {
    let (mut adapter, context, now) = boot();
    let token = attached(&mut adapter, &context, "1", 7, now);
    let attach = child_attach(&mut adapter, &context, "2", &token, now);
    child_event(
        &mut adapter,
        "Target.detachedFromTarget",
        json!({"sessionId":"unknown-until-ack"}),
        now,
    );
    assert!(child_input(
        &mut adapter,
        &context,
        "3",
        &token,
        "unknown-until-ack",
        now
    )
    .is_err());
    let ack = response(&reply(
        &mut adapter,
        &attach,
        json!({"sessionId":"unknown-until-ack"}),
        now,
    ));
    assert_eq!(ack["error"]["kind"], "outcome_unknown");
    assert!(child_input(
        &mut adapter,
        &context,
        "4",
        &token,
        "unknown-until-ack",
        now
    )
    .is_err());
}

#[test]
fn child_detach_ack_retires_exact_session_without_requiring_a_detach_event() {
    let (mut adapter, context, now) = boot();
    let token = attached(&mut adapter, &context, "1", 7, now);
    let attach = child_attach(&mut adapter, &context, "2", &token, now);
    reply(&mut adapter, &attach, json!({"sessionId":"child"}), now);
    let detach = frame(&adapter.written_semantic(semantic("3","cdp",json!({"claim":token,"method":"Target.detachFromTarget","params":{"sessionId":"child"}})),Some(&context),now).expect("exact known child detach"));
    reply(&mut adapter, &detach, json!({}), now);
    assert!(child_input(&mut adapter, &context, "4", &token, "child", now).is_err());
    assert!(!adapter.children.contains_key(&(7, "child".to_owned())));
}

#[test]
fn parallel_child_attaches_keep_independent_ack_and_revocation_receipts() {
    let (mut adapter, context, now) = boot();
    let token = attached(&mut adapter, &context, "1", 7, now);
    let first = child_attach(&mut adapter, &context, "2", &token, now);
    let second = child_attach(&mut adapter, &context, "3", &token, now);
    child_event(
        &mut adapter,
        "Target.detachedFromTarget",
        json!({"sessionId":"second"}),
        now,
    );
    reply(&mut adapter, &first, json!({"sessionId":"first"}), now);
    let result = response(&reply(
        &mut adapter,
        &second,
        json!({"sessionId":"second"}),
        now,
    ));
    assert_eq!(result["error"]["kind"], "outcome_unknown");
    assert!(child_input(&mut adapter, &context, "4", &token, "first", now).is_ok());
    assert!(child_input(&mut adapter, &context, "5", &token, "second", now).is_err());
    assert!(
        adapter
            .children
            .values()
            .all(|entry| entry.state == ChildState::Live),
        "no permanent detached-session registry"
    );
}

#[test]
fn parent_detach_before_nested_attach_ack_does_not_grant_an_orphan_session() {
    let (mut adapter, context, now) = boot();
    let token = attached(&mut adapter, &context, "1", 7, now);
    child_event(
        &mut adapter,
        "Target.attachedToTarget",
        json!({"sessionId":"parent","targetInfo":{"targetId":"parent-target"}}),
        now,
    );
    let attach = frame(&adapter.written_semantic(semantic("2","cdp",json!({"claim":token,"sessionId":"parent","method":"Target.attachToTarget","params":{"targetId":"target-7","flatten":true}})),Some(&context),now).expect("nested attach from an actual parent"));
    child_event(
        &mut adapter,
        "Target.detachedFromTarget",
        json!({"sessionId":"parent"}),
        now,
    );
    let result = response(&reply(
        &mut adapter,
        &attach,
        json!({"sessionId":"nested"}),
        now,
    ));
    assert_eq!(result["error"]["kind"], "outcome_unknown");
    assert!(child_input(&mut adapter, &context, "3", &token, "nested", now).is_err());
}

#[test]
fn old_root_attach_ack_cannot_grant_a_child_to_a_new_physical_claim_epoch() {
    let (mut adapter, context, now) = boot();
    let old = attached(&mut adapter, &context, "1", 7, now);
    let attach = child_attach(&mut adapter, &context, "2", &old, now);
    let detach = frame(
        &adapter
            .written_semantic(
                semantic("3", "detach", json!({"claim":old})),
                Some(&context),
                now,
            )
            .expect("old exact root detach"),
    );
    adapter
        .written_extension(json!({"jsonrpc":"2.0","id":detach["id"]}), now)
        .expect("actual old root detach ACK");
    let new = attached(&mut adapter, &context, "4", 7, now);
    let result = response(&reply(
        &mut adapter,
        &attach,
        json!({"sessionId":"old-child"}),
        now,
    ));
    assert_eq!(result["error"]["kind"], "outcome_unknown");
    assert_ne!(old, new);
    assert!(adapter.claims[&new].live);
    assert!(child_input(&mut adapter, &context, "5", &new, "old-child", now).is_err());
}

#[test]
fn parent_detach_does_not_erase_an_already_matched_child_cleanup_ack() {
    let (mut adapter, context, now) = boot();
    let token = attached(&mut adapter, &context, "1", 7, now);
    child_event(
        &mut adapter,
        "Target.attachedToTarget",
        json!({"sessionId":"parent","targetInfo":{"targetId":"parent-target"}}),
        now,
    );
    adapter.written_extension(json!({"jsonrpc":"2.0","method":"onCDPEvent","params":{"source":{"tabId":7,"sessionId":"parent"},"method":"Target.attachedToTarget","params":{"sessionId":"child","targetInfo":{"targetId":"child-target"}}}}),now).expect("actual nested child event");
    let detach = frame(&adapter.written_semantic(semantic("2","cdp",json!({"claim":token,"sessionId":"parent","method":"Target.detachFromTarget","params":{"sessionId":"child"}})),Some(&context),now).expect("authorized nested child cleanup"));
    child_event(
        &mut adapter,
        "Target.detachedFromTarget",
        json!({"sessionId":"parent"}),
        now,
    );
    let result = response(&reply(&mut adapter, &detach, json!({}), now));
    assert_eq!(
        result["result"]["result"],
        json!({}),
        "matched cleanup ACK grants no new child and must be preserved"
    );
    assert!(child_input(&mut adapter, &context, "3", &token, "child", now).is_err());
    assert!(adapter.children.is_empty());
}

#[test]
fn target_id_only_child_detach_ack_retires_known_session_without_a_detach_event() {
    let (mut adapter, context, now) = boot();
    let token = attached(&mut adapter, &context, "1", 7, now);
    let attach = child_attach(&mut adapter, &context, "2", &token, now);
    reply(&mut adapter, &attach, json!({"sessionId":"child"}), now);
    let detach = frame(&adapter.written_semantic(semantic("3","cdp",json!({"claim":token,"method":"Target.detachFromTarget","params":{"targetId":"target-7"}})),Some(&context),now).expect("source-supported target-only cleanup"));
    reply(&mut adapter, &detach, json!({}), now);
    assert!(child_input(&mut adapter, &context, "4", &token, "child", now).is_err());
}

#[test]
fn explicit_child_session_precedes_the_ignored_target_id_in_detach() {
    let (mut adapter, context, now) = boot();
    let token = attached(&mut adapter, &context, "1", 7, now);
    child_event(
        &mut adapter,
        "Target.attachedToTarget",
        json!({"sessionId":"first","targetInfo":{"targetId":"first-target"}}),
        now,
    );
    child_event(
        &mut adapter,
        "Target.attachedToTarget",
        json!({"sessionId":"second","targetInfo":{"targetId":"second-target"}}),
        now,
    );
    let detach = frame(&adapter.written_semantic(semantic("2","cdp",json!({"claim":token,"method":"Target.detachFromTarget","params":{"sessionId":"first","targetId":"ignored-foreign-target"}})),Some(&context),now).expect("Chromium ignores targetId when exact sessionId is supplied"));
    assert_eq!(
        detach["params"]["commandParams"]["targetId"],
        "ignored-foreign-target"
    );
    reply(&mut adapter, &detach, json!({}), now);
    assert!(child_input(&mut adapter, &context, "3", &token, "first", now).is_err());
    assert!(child_input(&mut adapter, &context, "4", &token, "second", now).is_ok());
}

#[test]
fn target_only_cleanup_ack_fences_an_earlier_pending_attach_without_inventing_its_sid() {
    let (mut adapter, context, now) = boot();
    let token = attached(&mut adapter, &context, "1", 7, now);
    let attach = child_attach(&mut adapter, &context, "2", &token, now);
    let detach = frame(&adapter.written_semantic(semantic("3","cdp",json!({"claim":token,"method":"Target.detachFromTarget","params":{"targetId":"target-7"}})),Some(&context),now).expect("exact owned target cleanup"));
    reply(&mut adapter, &detach, json!({}), now);
    let result = response(&reply(
        &mut adapter,
        &attach,
        json!({"sessionId":"late-child"}),
        now,
    ));
    assert_eq!(result["error"]["kind"], "outcome_unknown");
    assert!(child_input(&mut adapter, &context, "4", &token, "late-child", now).is_err());
    assert!(adapter.children.is_empty());
}

#[test]
fn attached_event_between_target_cleanup_admission_and_ack_never_leaves_live_authority() {
    let (mut adapter, context, now) = boot();
    let token = attached(&mut adapter, &context, "1", 7, now);
    let attach = child_attach(&mut adapter, &context, "2", &token, now);
    let detach=frame(&adapter.written_semantic(semantic("3","cdp",json!({"claim":token,"method":"Target.detachFromTarget","params":{"targetId":"target-7"}})),Some(&context),now).expect("owned target cleanup"));
    child_event(
        &mut adapter,
        "Target.attachedToTarget",
        json!({"sessionId":"racing-child","targetInfo":{"targetId":"target-7"}}),
        now,
    );
    assert!(child_input(&mut adapter, &context, "4", &token, "racing-child", now).is_err());
    reply(&mut adapter, &detach, json!({}), now);
    assert_eq!(
        response(&reply(
            &mut adapter,
            &attach,
            json!({"sessionId":"racing-child"}),
            now
        ))["error"]["kind"],
        "outcome_unknown"
    );
    assert!(child_input(&mut adapter, &context, "5", &token, "racing-child", now).is_err());
    assert!(adapter.children.is_empty());
}

#[test]
fn attached_event_after_target_cleanup_ack_cannot_revive_an_earlier_pending_attach() {
    let (mut adapter, context, now) = boot();
    let token = attached(&mut adapter, &context, "1", 7, now);
    let attach = child_attach(&mut adapter, &context, "2", &token, now);
    let detach=frame(&adapter.written_semantic(semantic("3","cdp",json!({"claim":token,"method":"Target.detachFromTarget","params":{"targetId":"target-7"}})),Some(&context),now).expect("owned target cleanup"));
    reply(&mut adapter, &detach, json!({}), now);
    child_event(
        &mut adapter,
        "Target.attachedToTarget",
        json!({"sessionId":"racing-child","targetInfo":{"targetId":"target-7"}}),
        now,
    );
    assert!(child_input(&mut adapter, &context, "4", &token, "racing-child", now).is_err());
    reply(
        &mut adapter,
        &attach,
        json!({"sessionId":"racing-child"}),
        now,
    );
    assert!(child_input(&mut adapter, &context, "5", &token, "racing-child", now).is_err());
    assert!(adapter.children.is_empty());
}

#[test]
fn a_later_explicit_child_attach_receipt_is_not_reassigned_to_earlier_cleanup() {
    let (mut adapter, context, now) = boot();
    let token = attached(&mut adapter, &context, "1", 7, now);
    let old = child_attach(&mut adapter, &context, "2", &token, now);
    let detach=frame(&adapter.written_semantic(semantic("3","cdp",json!({"claim":token,"method":"Target.detachFromTarget","params":{"targetId":"target-7"}})),Some(&context),now).expect("owned target cleanup"));
    let new = child_attach(&mut adapter, &context, "4", &token, now);
    reply(&mut adapter, &new, json!({"sessionId":"later-child"}), now);
    reply(&mut adapter, &detach, json!({}), now);
    assert!(child_input(&mut adapter, &context, "5", &token, "later-child", now).is_ok());
    reply(&mut adapter, &old, json!({"sessionId":"old-child"}), now);
    assert!(child_input(&mut adapter, &context, "6", &token, "old-child", now).is_err());
    assert!(adapter
        .children
        .get(&(7, "later-child".to_owned()))
        .is_some_and(|child| child.state == ChildState::Live));
}

#[test]
fn old_root_pending_target_cleanup_cannot_quarantine_a_new_claim_event() {
    let (mut adapter, context, now) = boot();
    let old = attached(&mut adapter, &context, "1", 7, now);
    let old_target_cleanup=frame(&adapter.written_semantic(semantic("2","cdp",json!({"claim":old,"method":"Target.detachFromTarget","params":{"targetId":"target-7"}})),Some(&context),now).expect("old scoped target cleanup"));
    let detach = frame(
        &adapter
            .written_semantic(
                semantic("3", "detach", json!({"claim":old})),
                Some(&context),
                now,
            )
            .expect("old root cleanup"),
    );
    adapter
        .written_extension(json!({"jsonrpc":"2.0","id":detach["id"]}), now)
        .expect("actual old root detach ACK");
    let new = attached(&mut adapter, &context, "4", 7, now);
    child_event(
        &mut adapter,
        "Target.attachedToTarget",
        json!({"sessionId":"new-child","targetInfo":{"targetId":"target-7"}}),
        now,
    );
    assert!(
        child_input(&mut adapter, &context, "5", &new, "new-child", now).is_ok(),
        "retired claim's pending lifecycle cannot restrict a new physical claim"
    );
    reply(&mut adapter, &old_target_cleanup, json!({}), now);
    assert!(adapter
        .children
        .get(&(7, "new-child".to_owned()))
        .is_some_and(|child| child.state == ChildState::Live));
}

#[test]
fn matched_native_error_is_transport_terminal_without_claiming_chrome_rejection() {
    let (mut adapter, context, now) = boot();
    let token = attached(&mut adapter, &context, "1", 7, now);
    let request = frame(
        &adapter
            .written_semantic(
                semantic(
                    "2",
                    "cdp",
                    json!({"claim":token,"method":"Page.enable","params":{}}),
                ),
                Some(&context),
                now,
            )
            .expect("actual extension CDP request"),
    );
    let actions=adapter.written_extension(json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":1,"message":"extension handler answered"}}),now).expect("matched actual extension error");
    let (message, terminal) = actions
        .iter()
        .find_map(|action| match action {
            ExtensionWireAction::MatchedBrokerMessage { message, terminal } => {
                Some((message, terminal))
            }
            _ => None,
        })
        .expect("typed answered-RPC metadata");
    assert_eq!(message["error"]["kind"], "outcome_unknown");
    assert_eq!(
        message["error"]["details"]["provenance"],
        "mixed_extension_or_chrome"
    );
    assert!(terminal.matches(GEN, "owner", "2", Some(&context)));
    let other =
        ExtensionWireContext::new(SID, "different-turn").expect("another immutable invocation");
    assert!(!terminal.matches(GEN, "owner", "2", Some(&other)));
    assert!(message.get("result").is_none());
}

#[test]
fn cancelled_positive_native_ack_keeps_terminal_metadata_and_unknown_attach_custody() {
    let (mut adapter, context, now) = boot();
    let attach = before_attach_ack(&mut adapter, &context, "1", 7, now);
    adapter.on_cancel("1");
    let actions = adapter
        .written_extension(json!({"jsonrpc":"2.0","id":attach["id"]}), now)
        .expect("actual id-only extension acknowledgement");
    let (message, terminal) = actions
        .iter()
        .find_map(|action| match action {
            ExtensionWireAction::MatchedBrokerMessage { message, terminal } => {
                Some((message, terminal))
            }
            _ => None,
        })
        .expect("matched ACK transport provenance survives cancellation");
    assert_eq!(message["error"]["kind"], "outcome_unknown");
    assert_eq!(message["error"]["details"]["custody"]["tabId"], 7);
    assert!(terminal.matches(GEN, "owner", "1", Some(&context)));
    assert!(!actions
        .iter()
        .any(|action| matches!(action, ExtensionWireAction::ExtensionFrame { .. })));
}

#[test]
fn timeout_eof_and_malformed_native_replies_cannot_mint_answered_rpc_metadata() {
    for cause in ["timeout", "eof", "malformed"] {
        let (mut adapter, context, now) = boot();
        let token = attached(&mut adapter, &context, "1", 7, now);
        let request = frame(
            &adapter
                .written_semantic(
                    semantic(
                        "2",
                        "cdp",
                        json!({"claim":token,"method":"Page.enable","params":{}}),
                    ),
                    Some(&context),
                    now,
                )
                .expect("extension command pending"),
        );
        let actions=match cause {
            "timeout"=>adapter.expire(now+DEADLINE+Duration::from_millis(1)),
            "eof"=>adapter.on_eof("fixture transport ended"),
            _=>adapter.written_extension(json!({"jsonrpc":"2.0","id":request["id"],"result":{"remoteAcknowledged":true},"error":{"code":1,"message":"conflicting response outcomes"}}),now).expect("malformed reply normalized as unknown"),
        };
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, ExtensionWireAction::MatchedBrokerMessage { .. })),
            "{cause} has no trustworthy matched handler reply"
        );
        assert_eq!(response(&actions)["error"]["kind"], "outcome_unknown");
    }
}

#[test]
fn out_of_order_native_replies_keep_their_exact_semantic_owner_and_context() {
    let (mut adapter, _, now) = boot();
    let first = frame(
        &adapter
            .written_semantic(semantic("1", "inventory", json!({})), None, now)
            .expect("first readonly request"),
    );
    let mut other = semantic("2", "inventory", json!({}));
    other["owner"] = json!("owner-b");
    let second = frame(
        &adapter
            .written_semantic(other, None, now)
            .expect("another exact authenticated owner"),
    );
    let actions = reply(&mut adapter, &second, json!([]), now);
    let terminal = actions
        .iter()
        .find_map(|action| match action {
            ExtensionWireAction::MatchedBrokerMessage { terminal, .. } => Some(terminal),
            _ => None,
        })
        .expect("matched second response");
    assert!(terminal.matches(GEN, "owner-b", "2", None));
    assert!(!terminal.matches(GEN, "owner", "1", None));
    assert!(!terminal.matches("foreign-generation", "owner-b", "2", None));
    assert_eq!(adapter.rpc.pending_len(), 1);
    let done = reply(&mut adapter, &first, json!([]), now);
    assert!(done.iter().any(|action|matches!(action,ExtensionWireAction::MatchedBrokerMessage{terminal,..} if terminal.matches(GEN,"owner","1",None))));
}

#[test]
fn earlier_native_phase_ack_cannot_tag_a_later_phase_timeout_as_answered() {
    let (mut adapter, context, now) = boot();
    let attach = before_attach_ack(&mut adapter, &context, "1", 7, now);
    let probe = frame(
        &adapter
            .written_extension(json!({"jsonrpc":"2.0","id":attach["id"]}), now)
            .expect("actual earlier attach ACK"),
    );
    assert_eq!(probe["params"]["method"], "Runtime.evaluate");
    let actions = adapter.expire(now + DEADLINE + Duration::from_millis(1));
    assert!(
        !actions
            .iter()
            .any(|action| matches!(action, ExtensionWireAction::MatchedBrokerMessage { .. })),
        "the unanswered current probe is independent of the earlier matched ACK"
    );
    let result = response(&actions);
    assert_eq!(result["error"]["kind"], "outcome_unknown");
    assert_eq!(
        result["error"]["details"]["custody"]["tabId"], 7,
        "prior actual attach custody must still survive"
    );
}

#[test]
fn session_only_resolve_uses_actual_uncapped_session_inventory_without_acquiring() {
    let (mut adapter, context, now) = boot();
    let request = frame(
        &adapter
            .written_semantic(
                semantic("1", "resolve", json!({"rawId":"2001","sessionOnly":true})),
                Some(&context),
                now,
            )
            .expect("captured session-only lookup"),
    );
    assert_eq!(request["method"], "getTabs");
    assert_eq!(request["params"]["session_id"], SID);
    assert_eq!(request["params"]["turn_id"], "turn1");
    assert!(request["params"].get("sessionOnly").is_none());
    let tabs: Vec<_> = (1..=2001)
        .map(|id| json!({"id":id,"url":"https://fixture.invalid/"}))
        .collect();
    let actions = reply(&mut adapter, &request, json!(tabs), now);
    let terminal = response(&actions);
    assert_eq!(terminal["result"]["tab"]["id"], 2001);
    assert_eq!(terminal["result"]["sessionOnly"], true);
    assert!(actions
        .iter()
        .any(|action| matches!(action, ExtensionWireAction::MatchedBrokerMessage { .. })));
    assert!(
        adapter.leases.is_empty(),
        "metadata cannot mint an acquisition row"
    );
    assert!(
        adapter.claims.is_empty(),
        "metadata cannot mint a physical claim"
    );
    assert!(adapter.creations.is_empty());
    assert_eq!(adapter.rpc.pending_len(), 0);
}

#[test]
fn session_only_resolve_rejects_missing_context_and_malformed_selector_without_dispatch() {
    let (mut adapter, context, now) = boot();
    assert!(matches!(
        adapter.written_semantic(
            semantic("1", "resolve", json!({"rawId":"2001","sessionOnly":true})),
            None,
            now
        ),
        Err(ExtensionWireError::LocalRefusal { code, .. }) if code == "wire_context_required"
    ));
    for invalid in [Value::Null, json!("true"), json!(1), json!({})] {
        assert!(matches!(
            adapter.written_semantic(
                semantic("2", "resolve", json!({"rawId":"2001","sessionOnly":invalid})),
                Some(&context),
                now
            ),
            Err(ExtensionWireError::LocalRefusal { code, .. }) if code == "invalid_request"
        ));
    }
    assert_eq!(adapter.rpc.pending_len(), 0);
    assert!(adapter.session_turns.is_empty());
    assert!(adapter.leases.is_empty());
}

#[test]
fn completed_usage_can_reactivate_the_same_host_turn_with_a_fresh_epoch() {
    let (mut adapter, context, now) = boot();
    let create = frame(
        &adapter
            .written_semantic(semantic("1", "createTab", json!({})), Some(&context), now)
            .expect("actual owned creation"),
    );
    reply(
        &mut adapter,
        &create,
        json!({"id":2001,"url":"about:blank"}),
        now,
    );
    let old_epoch = adapter.session_turns[SID].epoch;
    let finish = frame(
        &adapter
            .written_semantic(semantic("2", "finishTurn", json!({})), Some(&context), now)
            .expect("finish exact usage"),
    );
    adapter
        .written_extension(json!({"jsonrpc":"2.0","id":finish["id"]}), now)
        .expect("actual finish ACK");
    assert_eq!(adapter.session_turns[SID].phase, TurnPhase::Finished);
    assert!(adapter.leases.is_empty());
    let request = frame(
        &adapter
            .written_semantic(
                semantic("3", "resolve", json!({"rawId":"2001","sessionOnly":true})),
                Some(&context),
                now,
            )
            .expect("fresh usage can reactivate the same trusted Host turn"),
    );
    assert_eq!(request["method"], "getTabs");
    assert_eq!(request["params"]["turn_id"], "turn1");
    let output = response(&reply(&mut adapter, &request, json!([{"id":2001}]), now));
    assert_eq!(output["result"]["sessionOnly"], true);
    assert_ne!(adapter.session_turns[SID].epoch, old_epoch);
    assert_eq!(adapter.session_turns[SID].phase, TurnPhase::Active);
    assert!(
        adapter.leases.is_empty(),
        "metadata cannot restore acquisition authority"
    );
}

#[test]
fn session_only_resolve_never_reassigns_a_foreign_logical_lease() {
    for same_session in [false, true] {
        let (mut adapter, context, now) = boot();
        let create = frame(
            &adapter
                .written_semantic(semantic("1", "createTab", json!({})), Some(&context), now)
                .expect("actual original owner"),
        );
        reply(
            &mut adapter,
            &create,
            json!({"id":2001,"url":"about:blank"}),
            now,
        );
        let foreign = ExtensionWireContext::new("33333333-3333-4333-8333-333333333333", "turn1")
            .expect("another canonical session");
        let mut envelope = semantic("2", "resolve", json!({"rawId":"2001","sessionOnly":true}));
        if same_session {
            envelope["owner"] = json!("foreign-owner");
            assert!(
                matches!(adapter.written_semantic(envelope, Some(&context), now), Err(ExtensionWireError::LocalRefusal { code, .. }) if code == "session_has_foreign_custody")
            );
        } else {
            assert!(matches!(
                adapter.written_semantic(envelope, Some(&foreign), now),
                Err(ExtensionWireError::LocalRefusal { code, .. }) if code == "claim_unavailable"
            ));
        }
        assert_eq!(adapter.leases[&2001], ("owner".to_owned(), SID.to_owned()));
        assert_eq!(
            adapter.rpc.pending_len(),
            0,
            "no fallback query may be dispatched"
        );
    }
}

#[test]
fn managed_resolve_native_failure_and_finish_uncertainty_keep_session_unavailable() {
    for finishing in [false, true] {
        let (mut adapter, context, now) = boot();
        let pending = if finishing {
            let create = frame(
                &adapter
                    .written_semantic(semantic("1", "createTab", json!({})), Some(&context), now)
                    .expect("active turn"),
            );
            reply(
                &mut adapter,
                &create,
                json!({"id":2001,"url":"about:blank"}),
                now,
            );
            frame(
                &adapter
                    .written_semantic(semantic("2", "finishTurn", json!({})), Some(&context), now)
                    .expect("actual pending finish"),
            )
        } else {
            frame(
                &adapter
                    .written_semantic(
                        semantic("1", "resolve", json!({"rawId":"2001","sessionOnly":true})),
                        Some(&context),
                        now,
                    )
                    .expect("actual managed metadata invocation"),
            )
        };
        if finishing {
            assert!(
                matches!(adapter.written_semantic(semantic("3", "resolve", json!({"rawId":"2001","sessionOnly":true})), Some(&context), now), Err(ExtensionWireError::LocalRefusal { code, .. }) if code == "session_unavailable")
            );
        }
        let actions = adapter.written_extension(json!({"jsonrpc":"2.0","id":pending["id"],"error":{"code":1,"message":"extension failure after possible activation"}}), now).expect("matched extension terminal");
        assert_eq!(response(&actions)["error"]["kind"], "outcome_unknown");
        assert_eq!(
            response(&actions)["error"]["details"]["provenance"],
            "mixed_extension_or_chrome"
        );
        assert!(actions
            .iter()
            .any(|action| matches!(action, ExtensionWireAction::MatchedBrokerMessage { .. })));
        assert_eq!(
            adapter.session_turns[SID].phase,
            if finishing {
                TurnPhase::FinishUnknown
            } else {
                TurnPhase::ActivationUnknown
            }
        );
        assert!(
            matches!(adapter.written_semantic(semantic("4", "resolve", json!({"rawId":"2001","sessionOnly":true})), Some(&context), now), Err(ExtensionWireError::LocalRefusal { code, .. }) if code == "session_unavailable")
        );
        assert_eq!(adapter.rpc.pending_len(), 0);
    }
}

#[test]
fn old_managed_metadata_reply_cannot_confirm_a_new_turn_or_acquire_a_row() {
    let (mut adapter, context, now) = boot();
    let old = frame(
        &adapter
            .written_semantic(
                semantic("1", "resolve", json!({"rawId":"2001","sessionOnly":true})),
                Some(&context),
                now,
            )
            .expect("old session lookup"),
    );
    let next = ExtensionWireContext::new(SID, "turn2").expect("new trusted turn");
    let new = frame(
        &adapter
            .written_semantic(
                semantic("2", "resolve", json!({"rawId":"2001","sessionOnly":true})),
                Some(&next),
                now,
            )
            .expect("new lookup replaces turn admission"),
    );
    let old_terminal = response(&reply(&mut adapter, &old, json!([{"id":2001}]), now));
    assert_eq!(old_terminal["error"]["kind"], "outcome_unknown");
    assert!(old_terminal.get("result").is_none());
    assert_eq!(adapter.session_turns[SID].turn, "turn2");
    let new_terminal = response(&reply(&mut adapter, &new, json!([{"id":2001}]), now));
    assert_eq!(new_terminal["result"]["sessionOnly"], true);
    assert!(adapter.leases.is_empty());
    assert!(adapter.claims.is_empty());
    assert_eq!(adapter.rpc.pending_len(), 0);
}

#[test]
fn detached_managed_session_preparation_claims_directly_after_actual_session_metadata() {
    let (mut adapter, context, now) = boot();
    let token = attached(&mut adapter, &context, "1", 2001, now);
    let detach = frame(
        &adapter
            .written_semantic(
                semantic("2", "detach", json!({"claim":token})),
                Some(&context),
                now,
            )
            .expect("exact physical detach"),
    );
    adapter
        .written_extension(json!({"jsonrpc":"2.0","id":detach["id"]}), now)
        .expect("physical detach ACK");
    assert!(adapter.claims.is_empty());
    assert_eq!(adapter.leases[&2001], ("owner".to_owned(), SID.to_owned()));
    let metadata = frame(
        &adapter
            .written_semantic(
                semantic("3", "resolve", json!({"rawId":"2001","sessionOnly":true})),
                Some(&context),
                now,
            )
            .expect("managed metadata after detach"),
    );
    assert_eq!(metadata["method"], "getTabs");
    reply(
        &mut adapter,
        &metadata,
        json!([{"id":2001,"url":"https://fixture.invalid/"}]),
        now,
    );
    let claim = frame(
        &adapter
            .written_semantic(
                semantic(
                    "4",
                    "prepareUserTab",
                    json!({"tabId":2001,"sessionOnly":true}),
                ),
                Some(&context),
                now,
            )
            .expect("strict managed preparation"),
    );
    assert_eq!(claim["method"], "claimUserTab");
    assert_eq!(claim["params"]["tabId"], 2001);
    assert_eq!(claim["params"]["session_id"], SID);
    assert!(adapter.claims.is_empty());
    let terminal = response(&reply(
        &mut adapter,
        &claim,
        json!({"id":2001,"url":"about:blank"}),
        now,
    ));
    assert_eq!(terminal["result"]["tab"]["url"], "about:blank");
    assert_eq!(terminal["result"]["sessionOnly"], true);
    assert!(
        terminal["result"].get("normalized").is_none(),
        "no pre-claim URL observation can authorize a normalization assertion"
    );
    assert_eq!(adapter.leases.len(), 1);
    assert!(adapter.claims.is_empty());
}

#[test]
fn session_metadata_does_not_consume_the_existing_acquisition_budget() {
    let (mut adapter, context, now) = boot();
    for tab in 1..=MAX_CLAIMS as u64 {
        adapter
            .leases
            .insert(tab, ("owner".to_owned(), SID.to_owned()));
    }
    let request = frame(
        &adapter
            .written_semantic(
                semantic("1", "resolve", json!({"rawId":"2001","sessionOnly":true})),
                Some(&context),
                now,
            )
            .expect("metadata is not a new acquisition"),
    );
    assert_eq!(request["method"], "getTabs");
    let terminal = response(&reply(&mut adapter, &request, json!([{"id":2001}]), now));
    assert_eq!(terminal["result"]["sessionOnly"], true);
    assert_eq!(adapter.leases.len(), MAX_CLAIMS);
    assert!(!adapter.leases.contains_key(&2001));
    assert!(adapter.claims.is_empty());
}

#[test]
fn forced_session_preparation_uses_direct_native_claim_and_confirms_exact_purpose() {
    let (mut adapter, context, now) = boot();
    let claim = frame(
        &adapter
            .written_semantic(
                semantic(
                    "1",
                    "prepareUserTab",
                    json!({"tabId":2001,"sessionOnly":true}),
                ),
                Some(&context),
                now,
            )
            .expect("forced session preparation"),
    );
    assert_eq!(claim["method"], "claimUserTab");
    assert_eq!(claim["params"]["session_id"], SID);
    assert_eq!(claim["params"]["turn_id"], "turn1");
    assert_eq!(claim["params"]["tabId"], 2001);
    assert!(
        adapter.leases.is_empty(),
        "only the real extension claim ACK records a logical lease"
    );
    assert!(adapter.claims.is_empty());
    let terminal = response(&reply(
        &mut adapter,
        &claim,
        json!({"id":2001,"url":"https://fixture.invalid/"}),
        now,
    ));
    assert_eq!(terminal["result"]["sessionOnly"], true);
    assert!(terminal["result"].get("normalized").is_none());
    assert_eq!(adapter.leases[&2001], ("owner".to_owned(), SID.to_owned()));
    assert!(adapter.claims.is_empty());
    assert_eq!(adapter.rpc.pending_len(), 0);
}

#[test]
fn forced_session_preparation_requires_trusted_scope_and_can_start_a_fresh_usage() {
    let (mut adapter, context, now) = boot();
    assert!(
        matches!(adapter.written_semantic(semantic("1", "prepareUserTab", json!({"tabId":2001,"sessionOnly":true})), None, now), Err(ExtensionWireError::LocalRefusal { code, .. }) if code == "wire_context_required")
    );
    assert!(
        matches!(adapter.written_semantic(semantic("2", "prepareUserTab", json!({"tabId":2001,"sessionOnly":"true"})), Some(&context), now), Err(ExtensionWireError::LocalRefusal { code, .. }) if code == "invalid_request")
    );
    let create = frame(
        &adapter
            .written_semantic(semantic("3", "createTab", json!({})), Some(&context), now)
            .expect("actual active turn"),
    );
    reply(
        &mut adapter,
        &create,
        json!({"id":2001,"url":"about:blank"}),
        now,
    );
    let finish = frame(
        &adapter
            .written_semantic(semantic("4", "finishTurn", json!({})), Some(&context), now)
            .expect("finish trusted turn"),
    );
    adapter
        .written_extension(json!({"jsonrpc":"2.0","id":finish["id"]}), now)
        .expect("actual finish ACK");
    let claim = frame(
        &adapter
            .written_semantic(
                semantic(
                    "5",
                    "prepareUserTab",
                    json!({"tabId":2001,"sessionOnly":true}),
                ),
                Some(&context),
                now,
            )
            .expect("fresh trusted usage after an acknowledged finish"),
    );
    assert_eq!(claim["method"], "claimUserTab");
    assert_eq!(claim["params"]["turn_id"], "turn1");
    reply(
        &mut adapter,
        &claim,
        json!({"id":2001,"url":"about:blank"}),
        now,
    );
    assert_eq!(adapter.leases[&2001], ("owner".to_owned(), SID.to_owned()));
    assert!(adapter.claims.is_empty());
    assert_eq!(adapter.rpc.pending_len(), 0);
}

#[test]
fn strict_session_prepare_does_not_invent_filtered_inventory_or_normalization_preconditions() {
    for known_lease in [false, true] {
        let (mut adapter, context, now) = boot();
        if known_lease {
            let create = frame(
                &adapter
                    .written_semantic(semantic("1", "createTab", json!({})), Some(&context), now)
                    .expect("existing actual logical owner"),
            );
            reply(
                &mut adapter,
                &create,
                json!({"id":2001,"url":"about:blank"}),
                now,
            );
        }
        let actions = adapter
            .written_semantic(
                semantic(
                    "2",
                    "prepareUserTab",
                    json!({"tabId":2001,"sessionOnly":true}),
                ),
                Some(&context),
                now,
            )
            .expect("source-backed direct extension claim");
        let claim = frame(&actions);
        assert_eq!(
            claim["method"], "claimUserTab",
            "filtered GetTabs must not block extension known-newtab normalization"
        );
        assert_eq!(claim["params"]["tabId"], 2001);
        assert_eq!(adapter.leases.contains_key(&2001), known_lease);
        let output = reply(
            &mut adapter,
            &claim,
            json!({"id":2001,"url":"about:blank"}),
            now,
        );
        let terminal = response(&output);
        assert_eq!(terminal["result"]["sessionOnly"], true);
        assert_eq!(terminal["result"]["tab"]["url"], "about:blank");
        assert!(terminal["result"].get("normalized").is_none());
        assert!(!output
            .iter()
            .any(|action| matches!(action, ExtensionWireAction::ExtensionFrame { .. })));
        assert_eq!(adapter.session_turns[SID].phase, TurnPhase::Active);
        assert_eq!(adapter.leases[&2001], ("owner".to_owned(), SID.to_owned()));
        assert!(adapter.claims.is_empty());
    }
    let (mut adapter, context, now) = boot();
    let before = frame(
        &adapter
            .written_semantic(
                semantic("1", "prepareUserTab", json!({"tabId":7})),
                Some(&context),
                now,
            )
            .expect("ordinary user preparation keeps prior observation contract"),
    );
    assert_eq!(before["method"], "getUserTabs");
    let claim = frame(&reply(
        &mut adapter,
        &before,
        json!([{"id":7,"url":"chrome://newtab/"}]),
        now,
    ));
    assert_eq!(claim["method"], "claimUserTab");
    let terminal = response(&reply(
        &mut adapter,
        &claim,
        json!({"id":7,"url":"about:blank"}),
        now,
    ));
    assert_eq!(terminal["result"]["normalized"], true);
    assert!(terminal["result"].get("sessionOnly").is_none());
}

#[test]
fn session_preparation_native_error_or_cancel_never_replays_or_echoes_success() {
    for cancel in [false, true] {
        let (mut adapter, context, now) = boot();
        let claim = frame(
            &adapter
                .written_semantic(
                    semantic(
                        "1",
                        "prepareUserTab",
                        json!({"tabId":2001,"sessionOnly":true}),
                    ),
                    Some(&context),
                    now,
                )
                .expect("actual direct extension claim"),
        );
        assert_eq!(claim["method"], "claimUserTab");
        let actions = if cancel {
            adapter.on_cancel("1");
            reply(
                &mut adapter,
                &claim,
                json!({"id":2001,"url":"about:blank"}),
                now,
            )
        } else {
            adapter.written_extension(json!({"jsonrpc":"2.0","id":claim["id"],"error":{"code":1,"message":"ClaimUserTab failed after possible preparation"}}), now).expect("actual extension rejection")
        };
        assert_eq!(response(&actions)["error"]["kind"], "outcome_unknown");
        assert!(response(&actions).get("result").is_none());
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, ExtensionWireAction::ExtensionFrame { .. })),
            "uncertain or canceled claim cannot trigger a replay"
        );
        assert!(actions
            .iter()
            .any(|action| matches!(action, ExtensionWireAction::MatchedBrokerMessage { .. })));
        assert!(adapter.leases.is_empty());
        assert!(adapter.claims.is_empty());
        assert_eq!(adapter.rpc.pending_len(), 0);
        if cancel {
            let terminal = response(&actions);
            assert_eq!(
                terminal["error"]["details"]["acknowledgedResult"]["tab"]["id"],
                2001
            );
            assert_eq!(
                terminal["error"]["details"]["acknowledgedResult"]["sessionOnly"],
                true
            );
            assert!(terminal["error"]["details"]["acknowledgedResult"]
                .get("normalized")
                .is_none());
            assert_eq!(terminal["error"]["details"]["remoteMethod"], "claimUserTab");
        } else {
            assert_eq!(
                adapter.session_turns[SID].phase,
                TurnPhase::ActivationUnknown
            );
        }
    }
}

#[test]
fn visible_session_inventory_miss_does_not_delete_owned_logical_or_creation_rows() {
    let (mut adapter, context, now) = boot();
    let create = frame(
        &adapter
            .written_semantic(semantic("1", "createTab", json!({})), Some(&context), now)
            .expect("actual owned creation"),
    );
    let created = response(&reply(
        &mut adapter,
        &create,
        json!({"id":7,"url":"about:blank"}),
        now,
    ));
    let creation = created["result"]["creation"]
        .as_str()
        .expect("actual receipt")
        .to_owned();
    let lookup = frame(
        &adapter
            .written_semantic(
                semantic("2", "resolve", json!({"rawId":"7","sessionOnly":true})),
                Some(&context),
                now,
            )
            .expect("strict metadata observation"),
    );
    assert_eq!(lookup["method"], "getTabs");
    let terminal = response(&reply(&mut adapter, &lookup, json!([]), now));
    assert_eq!(terminal["error"]["kind"], "tab_unavailable");
    assert!(terminal["error"]["message"]
        .as_str()
        .expect("visible inventory diagnostic")
        .contains("visible tab inventory"));
    assert!(
        adapter.leases.contains_key(&7),
        "filtered metadata absence is not logical deletion"
    );
    assert!(adapter.creations.contains_key(&creation));
    assert_eq!(adapter.session_turns[SID].phase, TurnPhase::Active);
}

#[test]
fn late_session_preparation_ack_after_finish_retains_metadata_without_reactivating_or_granting() {
    let (mut adapter, context, now) = boot();
    let claim = frame(
        &adapter
            .written_semantic(
                semantic(
                    "1",
                    "prepareUserTab",
                    json!({"tabId":2001,"sessionOnly":true}),
                ),
                Some(&context),
                now,
            )
            .expect("actual strict preparation pending"),
    );
    let finish = frame(
        &adapter
            .written_semantic(semantic("2", "finishTurn", json!({})), Some(&context), now)
            .expect("finish admitted turn"),
    );
    adapter
        .written_extension(json!({"jsonrpc":"2.0","id":finish["id"]}), now)
        .expect("actual finish ACK");
    let next = ExtensionWireContext::new(SID, "turn2").expect("next trusted turn");
    let metadata = frame(
        &adapter
            .written_semantic(
                semantic("3", "resolve", json!({"rawId":"2001","sessionOnly":true})),
                Some(&next),
                now,
            )
            .expect("new managed metadata invocation"),
    );
    reply(&mut adapter, &metadata, json!([]), now);
    let actions = reply(
        &mut adapter,
        &claim,
        json!({"id":2001,"url":"about:blank"}),
        now,
    );
    let terminal = response(&actions);
    assert_eq!(terminal["error"]["kind"], "outcome_unknown");
    assert_eq!(
        terminal["error"]["details"]["acknowledgedResult"]["tab"]["id"],
        2001
    );
    assert_eq!(
        terminal["error"]["details"]["acknowledgedResult"]["sessionOnly"],
        true
    );
    assert!(terminal.get("result").is_none());
    assert!(!actions
        .iter()
        .any(|action| matches!(action, ExtensionWireAction::ExtensionFrame { .. })));
    assert!(adapter.leases.is_empty());
    assert!(adapter.claims.is_empty());
    assert_eq!(adapter.session_turns[SID].turn, "turn2");
    assert_eq!(adapter.session_turns[SID].phase, TurnPhase::Active);
}

#[test]
fn session_preparation_foreign_returned_id_never_becomes_ack_metadata_or_a_lease() {
    for cancel in [false, true] {
        let (mut adapter, context, now) = boot();
        let claim = frame(
            &adapter
                .written_semantic(
                    semantic(
                        "1",
                        "prepareUserTab",
                        json!({"tabId":2001,"sessionOnly":true}),
                    ),
                    Some(&context),
                    now,
                )
                .expect("actual strict claim pending"),
        );
        if cancel {
            adapter.on_cancel("1");
        }
        let output = reply(
            &mut adapter,
            &claim,
            json!({"id":2002,"url":"about:blank"}),
            now,
        );
        let terminal = response(&output);
        assert_eq!(terminal["error"]["kind"], "outcome_unknown");
        assert!(terminal["error"]["details"]
            .get("acknowledgedResult")
            .is_none());
        assert!(terminal.get("result").is_none());
        assert!(adapter.leases.is_empty());
        assert!(adapter.claims.is_empty());
        assert!(!output
            .iter()
            .any(|action| matches!(action, ExtensionWireAction::ExtensionFrame { .. })));
    }
}

#[test]
fn acknowledged_close_retires_exact_creation_and_lease_across_more_than_the_budget() {
    let (mut adapter, context, now) = boot();
    for index in 0..=MAX_CLAIMS {
        let tab = 1000 + index as u64;
        let create = frame(
            &adapter
                .written_semantic(
                    semantic(&(3 * index + 1).to_string(), "createTab", json!({})),
                    Some(&context),
                    now,
                )
                .expect("sequential actual create remains admitted"),
        );
        let created = response(&reply(
            &mut adapter,
            &create,
            json!({"id":tab,"url":"about:blank"}),
            now,
        ));
        let creation = created["result"]["creation"]
            .as_str()
            .expect("actual created receipt")
            .to_owned();
        let claim = attached(
            &mut adapter,
            &context,
            &(3 * index + 2).to_string(),
            tab,
            now,
        );
        let close = frame(
            &adapter
                .written_semantic(
                    semantic(
                        &(3 * index + 3).to_string(),
                        "closeTab",
                        json!({"claim":claim}),
                    ),
                    Some(&context),
                    now,
                )
                .expect("close exact created target"),
        );
        assert_eq!(close["params"]["method"], "Target.closeTarget");
        assert_eq!(
            close["params"]["commandParams"]["targetId"],
            format!("target-{tab}")
        );
        let closed = response(&reply(&mut adapter, &close, json!({"success":true}), now));
        assert_eq!(closed["result"]["proof"], "close_ack");
        assert!(!adapter.creations.contains_key(&creation));
        assert!(!adapter.leases.contains_key(&tab));
        assert!(adapter.claims.is_empty());
        assert!(
            adapter.creations.is_empty(),
            "known gone creations must not accumulate"
        );
        assert!(
            adapter.leases.is_empty(),
            "known gone logical rows must not accumulate"
        );
        assert_eq!(adapter.session_turns[SID].phase, TurnPhase::Active);
        assert_eq!(adapter.rpc.pending_len(), 0);
    }
}

#[test]
fn detach_ack_and_unproven_or_contradictory_close_results_retain_logical_custody() {
    for result in [
        json!({"success":false}),
        json!({"success":"true"}),
        json!({"success":true,"tabId":999}),
        json!({"success":true,"targetId":"foreign"}),
        json!({"success":true,"claim":"foreign"}),
    ] {
        let (mut adapter, context, now) = boot();
        let create = frame(
            &adapter
                .written_semantic(semantic("1", "createTab", json!({})), Some(&context), now)
                .expect("real creation"),
        );
        let created = response(&reply(
            &mut adapter,
            &create,
            json!({"id":7,"url":"about:blank"}),
            now,
        ));
        let creation = created["result"]["creation"]
            .as_str()
            .expect("actual creation receipt")
            .to_owned();
        let claim = attached(&mut adapter, &context, "2", 7, now);
        let close = frame(
            &adapter
                .written_semantic(
                    semantic("3", "closeTab", json!({"claim":claim})),
                    Some(&context),
                    now,
                )
                .expect("admitted exact close"),
        );
        let terminal = response(&reply(&mut adapter, &close, result, now));
        assert_eq!(terminal["error"]["kind"], "outcome_unknown");
        assert!(terminal.get("result").is_none());
        assert!(adapter.claims.contains_key(&claim));
        assert_eq!(adapter.leases[&7], ("owner".to_owned(), SID.to_owned()));
        assert!(adapter.creations.contains_key(&creation));
    }
    let (mut adapter, context, now) = boot();
    let create = frame(
        &adapter
            .written_semantic(semantic("1", "createTab", json!({})), Some(&context), now)
            .expect("real creation before detach"),
    );
    let created = response(&reply(
        &mut adapter,
        &create,
        json!({"id":7,"url":"about:blank"}),
        now,
    ));
    let creation = created["result"]["creation"]
        .as_str()
        .expect("actual creation receipt")
        .to_owned();
    let claim = attached(&mut adapter, &context, "2", 7, now);
    let detach = frame(
        &adapter
            .written_semantic(
                semantic("3", "detach", json!({"claim":claim})),
                Some(&context),
                now,
            )
            .expect("detach exact physical claim"),
    );
    let terminal = response(
        &adapter
            .written_extension(json!({"jsonrpc":"2.0","id":detach["id"]}), now)
            .expect("real detach ACK"),
    );
    assert_eq!(terminal["result"]["proof"], "detach_ack");
    assert!(adapter.claims.is_empty());
    assert_eq!(adapter.leases[&7], ("owner".to_owned(), SID.to_owned()));
    assert!(adapter.creations.contains_key(&creation));
}

#[test]
fn close_native_error_and_foreign_request_cannot_remove_owned_logical_records() {
    let (mut adapter, context, now) = boot();
    let create = frame(
        &adapter
            .written_semantic(semantic("1", "createTab", json!({})), Some(&context), now)
            .expect("actual owner creates"),
    );
    let created = response(&reply(
        &mut adapter,
        &create,
        json!({"id":7,"url":"about:blank"}),
        now,
    ));
    let creation = created["result"]["creation"]
        .as_str()
        .expect("actual creation receipt")
        .to_owned();
    let claim = attached(&mut adapter, &context, "2", 7, now);
    let mut foreign = semantic("3", "closeTab", json!({"claim":claim}));
    foreign["owner"] = json!("foreign-owner");
    assert!(
        matches!(adapter.written_semantic(foreign, Some(&context), now), Err(ExtensionWireError::LocalRefusal { code, .. }) if code == "claim_unavailable")
    );
    assert_eq!(adapter.rpc.pending_len(), 0);
    let close = frame(
        &adapter
            .written_semantic(
                semantic("4", "closeTab", json!({"claim":claim})),
                Some(&context),
                now,
            )
            .expect("exact owner close"),
    );
    let output = adapter.written_extension(json!({"jsonrpc":"2.0","id":close["id"],"error":{"code":1,"message":"close effect unknown"}}), now).expect("extension error correlated");
    assert_eq!(response(&output)["error"]["kind"], "outcome_unknown");
    assert!(adapter.claims.contains_key(&claim));
    assert!(adapter.creations.contains_key(&creation));
    assert!(adapter.leases.contains_key(&7));
    assert_eq!(
        adapter.session_turns[SID].phase,
        TurnPhase::ActivationUnknown
    );
}

#[test]
fn late_positive_close_keeps_outer_unknown_but_collects_exact_old_custody() {
    let (mut adapter, context, now) = boot();
    let create = frame(
        &adapter
            .written_semantic(semantic("1", "createTab", json!({})), Some(&context), now)
            .expect("real creation"),
    );
    let created = response(&reply(
        &mut adapter,
        &create,
        json!({"id":7,"url":"about:blank"}),
        now,
    ));
    let creation = created["result"]["creation"]
        .as_str()
        .expect("created receipt")
        .to_owned();
    let claim = attached(&mut adapter, &context, "2", 7, now);
    let close = frame(
        &adapter
            .written_semantic(
                semantic("3", "closeTab", json!({"claim":claim})),
                Some(&context),
                now,
            )
            .expect("exact close pending"),
    );
    adapter.on_cancel("3");
    let output = reply(&mut adapter, &close, json!({"success":true}), now);
    let terminal = response(&output);
    assert_eq!(terminal["error"]["kind"], "outcome_unknown");
    assert_eq!(
        terminal["error"]["details"]["acknowledgedResult"]["proof"],
        "close_ack"
    );
    assert!(terminal.get("result").is_none());
    assert!(!adapter.claims.contains_key(&claim));
    assert!(!adapter.creations.contains_key(&creation));
    assert!(!adapter.leases.contains_key(&7));
    assert!(output
        .iter()
        .any(|action| matches!(action, ExtensionWireAction::MatchedBrokerMessage { .. })));
}

#[test]
fn old_close_ack_cannot_collect_new_turn_reused_raw_tab_custody() {
    let (mut adapter, context, now) = boot();
    let create = frame(
        &adapter
            .written_semantic(semantic("1", "createTab", json!({})), Some(&context), now)
            .expect("old creation"),
    );
    let old_created = response(&reply(
        &mut adapter,
        &create,
        json!({"id":7,"url":"about:blank"}),
        now,
    ));
    let old_creation = old_created["result"]["creation"]
        .as_str()
        .expect("old creation receipt")
        .to_owned();
    let old_claim = attached(&mut adapter, &context, "2", 7, now);
    let close = frame(
        &adapter
            .written_semantic(
                semantic("3", "closeTab", json!({"claim":old_claim})),
                Some(&context),
                now,
            )
            .expect("old exact target close pending"),
    );
    let detach = frame(
        &adapter
            .written_semantic(
                semantic("4", "detach", json!({"claim":old_claim})),
                Some(&context),
                now,
            )
            .expect("physical detach while close pending"),
    );
    adapter
        .written_extension(json!({"jsonrpc":"2.0","id":detach["id"]}), now)
        .expect("detach ACK");
    let finish = frame(
        &adapter
            .written_semantic(semantic("5", "finishTurn", json!({})), Some(&context), now)
            .expect("old turn finish"),
    );
    adapter
        .written_extension(json!({"jsonrpc":"2.0","id":finish["id"]}), now)
        .expect("old turn finish ACK");
    let next = ExtensionWireContext::new(SID, "turn2").expect("new immutable turn");
    let create = frame(
        &adapter
            .written_semantic(semantic("6", "createTab", json!({})), Some(&next), now)
            .expect("actual new creation with reused raw ID"),
    );
    let new_created = response(&reply(
        &mut adapter,
        &create,
        json!({"id":7,"url":"about:blank"}),
        now,
    ));
    let new_creation = new_created["result"]["creation"]
        .as_str()
        .expect("new creation receipt")
        .to_owned();
    assert_ne!(old_creation, new_creation);
    let pre = frame(
        &adapter
            .written_semantic(
                semantic("7", "attach", json!({"tabId":7})),
                Some(&next),
                now,
            )
            .expect("new logical tab attaches"),
    );
    let attach = frame(&reply(
        &mut adapter,
        &pre,
        json!({"targetInfos":[{"tabId":7,"type":"page","targetId":"new-target-7","attached":false}]}),
        now,
    ));
    let probe = frame(
        &adapter
            .written_extension(json!({"jsonrpc":"2.0","id":attach["id"]}), now)
            .expect("new physical attach ACK"),
    );
    let targets = frame(&reply(
        &mut adapter,
        &probe,
        json!({"result":{"value":0}}),
        now,
    ));
    let new_claim = response(&reply(&mut adapter, &targets, json!({"targetInfos":[{"tabId":7,"type":"page","targetId":"new-target-7","attached":true}]}), now))["result"]["claim"].as_str().expect("new physical claim").to_owned();
    let late = response(&reply(&mut adapter, &close, json!({"success":true}), now));
    assert_eq!(late["error"]["kind"], "outcome_unknown");
    assert!(!adapter.creations.contains_key(&old_creation));
    assert!(adapter.creations.contains_key(&new_creation));
    assert_eq!(adapter.leases[&7], ("owner".to_owned(), SID.to_owned()));
    assert_eq!(adapter.current_claim[&7], new_claim);
    assert!(adapter.claims[&new_claim].live);
    assert_eq!(adapter.claims[&new_claim].target, "new-target-7");
    assert_eq!(adapter.session_turns[SID].turn, "turn2");
}

#[test]
fn old_generation_close_reply_does_not_enter_new_generation_custody() {
    let (mut old, context, now) = boot();
    let create = frame(
        &old.written_semantic(semantic("1", "createTab", json!({})), Some(&context), now)
            .expect("old creation"),
    );
    reply(&mut old, &create, json!({"id":7,"url":"about:blank"}), now);
    let old_claim = attached(&mut old, &context, "2", 7, now);
    let close = frame(
        &old.written_semantic(
            semantic("3", "closeTab", json!({"claim":old_claim})),
            Some(&context),
            now,
        )
        .expect("old close pending"),
    );
    let generation = "33333333-3333-4333-8333-333333333333";
    let mut new = ChatgptWireAdapter::new(generation.to_owned(), EXT.to_owned())
        .expect("new independent generation");
    let info = frame(&new.written_start(now).expect("new bootstrap"));
    new.written_extension(json!({"jsonrpc":"2.0","id":info["id"],"result":{"type":"extension","version":"observed","metadata":{"extensionId":EXT,"extensionInstanceId":"instance-new"}}}), now).expect("new actual identity ACK");
    let mut create = semantic("1", "createTab", json!({}));
    create["generation"] = json!(generation);
    let create = frame(
        &new.written_semantic(create, Some(&context), now)
            .expect("new real creation"),
    );
    let created = response(&reply(
        &mut new,
        &create,
        json!({"id":7,"url":"about:blank"}),
        now,
    ));
    let receipt = created["result"]["creation"]
        .as_str()
        .expect("new receipt")
        .to_owned();
    let ignored = new
        .written_extension(
            json!({"jsonrpc":"2.0","id":close["id"],"result":{"success":true}}),
            now,
        )
        .expect("foreign generation reply is ignored by actual matcher");
    assert!(ignored.is_empty());
    assert!(new.creations.contains_key(&receipt));
    assert_eq!(new.leases[&7], ("owner".to_owned(), SID.to_owned()));
    assert_eq!(new.creations[&receipt].endpoint.generation, generation);
    assert_eq!(new.rpc.pending_len(), 0);
}

fn committed_url_semantic(id: &str, raw_id: &str) -> Value {
    semantic(
        id,
        "resolve",
        json!({"rawId":raw_id,"sessionOnly":true,"committedUrlOnly":true}),
    )
}

#[test]
fn committed_session_url_uses_only_actual_owned_native_url_and_preserves_empty_strings() {
    for url in [
        "",
        "about:blank",
        "chrome://newtab/",
        "https://fixture.invalid/Case?A=%20#B",
        "file:///fixture/data",
    ] {
        let (mut adapter, context, now) = boot();
        let mut envelope = committed_url_semantic("1", "7.0");
        envelope["params"]["url"] = json!("https://caller.invalid/fake");
        envelope["params"]["pendingUrl"] = json!("https://caller.invalid/pending");
        let request = frame(
            &adapter
                .written_semantic(envelope, Some(&context), now)
                .expect("captured owned URL purpose"),
        );
        assert_eq!(request["method"], "getCommittedTabUrl");
        assert_eq!(
            request["params"],
            json!({"tabId":7,"session_id":SID,"turn_id":"turn1","session_context":"live"})
        );
        assert_eq!(
            Method::GetCommittedTabUrl.call_effect(),
            super::super::chatgpt_rpc_v2::CallEffect::MayMutate
        );
        let actions = reply(&mut adapter, &request, json!(url), now);
        let terminal = response(&actions);
        assert_eq!(
            terminal["result"],
            json!({"url":url,"sessionOnly":true,"committedUrlOnly":true})
        );
        assert!(terminal["result"].get("tab").is_none());
        assert!(terminal["result"].get("normalized").is_none());
        assert!(actions
            .iter()
            .any(|action| matches!(action, ExtensionWireAction::MatchedBrokerMessage { .. })));
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, ExtensionWireAction::ExtensionFrame { .. })),
            "no preparer, attach, global inventory or retry follows URL data"
        );
        assert!(adapter.leases.is_empty());
        assert!(adapter.claims.is_empty());
        assert!(adapter.creations.is_empty());
    }
}

#[test]
fn committed_url_selector_requires_strict_session_purpose_and_trusted_context_before_dispatch() {
    let (mut adapter, context, now) = boot();
    assert!(
        matches!(adapter.written_semantic(committed_url_semantic("1", "7"), None, now), Err(ExtensionWireError::LocalRefusal { code, .. }) if code == "wire_context_required")
    );
    for session in [None, Some(json!(false))] {
        let mut envelope = committed_url_semantic("2", "7");
        match session {
            Some(value) => envelope["params"]["sessionOnly"] = value,
            None => {
                envelope["params"]
                    .as_object_mut()
                    .expect("request fields")
                    .remove("sessionOnly");
            }
        }
        assert!(
            matches!(adapter.written_semantic(envelope, Some(&context), now), Err(ExtensionWireError::LocalRefusal { code, .. }) if code == "invalid_request")
        );
    }
    for value in [Value::Null, json!(1), json!("true"), json!({}), json!([])] {
        let mut envelope = committed_url_semantic("3", "7");
        envelope["params"]["committedUrlOnly"] = value;
        assert!(
            matches!(adapter.written_semantic(envelope, Some(&context), now), Err(ExtensionWireError::LocalRefusal { code, .. }) if code == "invalid_request")
        );
    }
    assert_eq!(adapter.rpc.pending_len(), 0);
    assert!(adapter.session_turns.is_empty());
    assert!(adapter.leases.is_empty());
}

#[test]
fn committed_url_false_keeps_both_existing_generic_and_strict_metadata_purposes() {
    for session_only in [false, true] {
        let (mut adapter, context, now) = boot();
        let request = frame(
            &adapter
                .written_semantic(
                    semantic(
                        "1",
                        "resolve",
                        json!({"rawId":"7","sessionOnly":session_only,"committedUrlOnly":false}),
                    ),
                    Some(&context),
                    now,
                )
                .expect("unchanged metadata purpose"),
        );
        assert_eq!(
            request["method"],
            if session_only {
                "getTabs"
            } else {
                "getUserTabs"
            }
        );
        let terminal = response(&reply(
            &mut adapter,
            &request,
            json!([{"id":7,"url":"https://fixture.invalid/"}]),
            now,
        ));
        assert_eq!(terminal["result"]["tab"]["id"], 7);
        assert!(terminal["result"].get("committedUrlOnly").is_none());
        assert!(terminal["result"].get("url").is_none());
    }
}

#[test]
fn committed_url_foreign_local_scope_is_refused_before_native_ownership_is_borrowed() {
    for same_session in [false, true] {
        let (mut adapter, context, now) = boot();
        let create = frame(
            &adapter
                .written_semantic(semantic("1", "createTab", json!({})), Some(&context), now)
                .expect("real owner creation"),
        );
        reply(
            &mut adapter,
            &create,
            json!({"id":7,"url":"about:blank"}),
            now,
        );
        let mut envelope = committed_url_semantic("2", "7");
        let foreign = ExtensionWireContext::new("33333333-3333-4333-8333-333333333333", "turn1")
            .expect("other canonical session");
        if same_session {
            envelope["owner"] = json!("foreign-owner");
            assert!(
                matches!(adapter.written_semantic(envelope,Some(&context),now),Err(ExtensionWireError::LocalRefusal{code,..}) if code=="session_has_foreign_custody")
            );
        } else {
            assert!(
                matches!(adapter.written_semantic(envelope,Some(&foreign),now),Err(ExtensionWireError::LocalRefusal{code,..}) if code=="claim_unavailable")
            );
        }
        assert_eq!(adapter.rpc.pending_len(), 0);
        assert_eq!(adapter.leases[&7], ("owner".to_owned(), SID.to_owned()));
    }
}

#[test]
fn committed_url_remote_or_malformed_reply_stays_unknown_with_activation_custody() {
    for invalid in [
        Value::Null,
        json!(7),
        json!(false),
        json!({"url":"https://fake.invalid/"}),
        json!(["https://fake.invalid/"]),
    ] {
        let (mut adapter, context, now) = boot();
        let request = frame(
            &adapter
                .written_semantic(committed_url_semantic("1", "7"), Some(&context), now)
                .expect("actual URL method"),
        );
        let actions = reply(&mut adapter, &request, invalid, now);
        let terminal = response(&actions);
        assert_eq!(terminal["error"]["kind"], "outcome_unknown");
        assert!(terminal.get("result").is_none());
        assert_eq!(
            adapter.session_turns[SID].phase,
            TurnPhase::ActivationUnknown
        );
        assert!(adapter.leases.is_empty());
        assert!(adapter.claims.is_empty());
        assert!(!actions
            .iter()
            .any(|action| matches!(action, ExtensionWireAction::ExtensionFrame { .. })));
        assert!(
            matches!(adapter.written_semantic(committed_url_semantic("2","7"),Some(&context),now),Err(ExtensionWireError::LocalRefusal{code,..}) if code=="session_unavailable")
        );
    }
    let (mut adapter, context, now) = boot();
    let request = frame(
        &adapter
            .written_semantic(committed_url_semantic("1", "7"), Some(&context), now)
            .expect("actual owned URL method"),
    );
    let actions=adapter.written_extension(json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":1,"message":"actual owned URL read refused"}}),now).expect("actual extension error");
    let terminal = response(&actions);
    assert_eq!(terminal["error"]["kind"], "outcome_unknown");
    assert_eq!(
        terminal["error"]["details"]["provenance"],
        "mixed_extension_or_chrome"
    );
    assert!(actions
        .iter()
        .any(|action| matches!(action, ExtensionWireAction::MatchedBrokerMessage { .. })));
    assert_eq!(
        adapter.session_turns[SID].phase,
        TurnPhase::ActivationUnknown
    );
}

#[test]
fn committed_url_missing_reply_finish_and_closed_scope_never_use_global_fallback() {
    for mode in [
        "missing-result",
        "timeout",
        "eof",
        "finished",
        "finishing",
        "finish-unknown",
        "closed",
    ] {
        let (mut adapter, context, now) = boot();
        if matches!(mode, "finished" | "finishing" | "finish-unknown" | "closed") {
            let create = frame(
                &adapter
                    .written_semantic(semantic("1", "createTab", json!({})), Some(&context), now)
                    .expect("real owner"),
            );
            reply(
                &mut adapter,
                &create,
                json!({"id":7,"url":"about:blank"}),
                now,
            );
        }
        if matches!(mode, "finished" | "finishing" | "finish-unknown") {
            let finish = frame(
                &adapter
                    .written_semantic(semantic("2", "finishTurn", json!({})), Some(&context), now)
                    .expect("actual finish transition"),
            );
            match mode {
                "finished" => {
                    adapter
                        .written_extension(json!({"jsonrpc":"2.0","id":finish["id"]}), now)
                        .expect("actual finish ACK");
                }
                "finish-unknown" => {
                    adapter.written_extension(json!({"jsonrpc":"2.0","id":finish["id"],"error":{"code":1,"message":"finish uncertain"}}),now).expect("actual finish error");
                }
                _ => {}
            }
            if mode != "finished" {
                assert!(
                    matches!(adapter.written_semantic(committed_url_semantic("3","7"),Some(&context),now),Err(ExtensionWireError::LocalRefusal{code,..}) if code=="session_unavailable")
                );
                continue;
            }
        }
        if mode == "closed" {
            let claim = attached(&mut adapter, &context, "2", 7, now);
            let close = frame(
                &adapter
                    .written_semantic(
                        semantic("3", "closeTab", json!({"claim":claim})),
                        Some(&context),
                        now,
                    )
                    .expect("known actual close"),
            );
            reply(&mut adapter, &close, json!({"success":true}), now);
            assert!(adapter.leases.is_empty());
        }
        let request = frame(
            &adapter
                .written_semantic(committed_url_semantic("4", "7"), Some(&context), now)
                .expect("strict request has no local/global bypass"),
        );
        assert_eq!(request["method"], "getCommittedTabUrl");
        let actions=match mode {
            "missing-result"=>adapter.written_extension(json!({"jsonrpc":"2.0","id":request["id"]}),now).expect("source nonvoid method cannot accept id-only ACK"),
            "timeout"=>adapter.expire(now+DEADLINE+Duration::from_millis(1)),
            "eof"=>adapter.on_eof("owned URL connection ended"),
            "finished" | "closed"=>adapter.written_extension(json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":1,"message":"Tab is not part of this browser session"}}),now).expect("extension actual owned check refuses closed row"),
            _=>unreachable!("each mode handled"),
        };
        assert_eq!(response(&actions)["error"]["kind"], "outcome_unknown");
        assert!(!actions
            .iter()
            .any(|action| matches!(action, ExtensionWireAction::ExtensionFrame { .. })));
        assert!(adapter.leases.is_empty());
        assert!(adapter.claims.is_empty());
    }
}

#[test]
fn canceled_old_committed_url_retains_actual_payload_in_its_original_unknown_scope() {
    let (mut adapter, context, now) = boot();
    let old = frame(
        &adapter
            .written_semantic(committed_url_semantic("1", "7"), Some(&context), now)
            .expect("old captured URL request"),
    );
    let next = ExtensionWireContext::new(SID, "turn2").expect("new trusted turn");
    let new = frame(
        &adapter
            .written_semantic(committed_url_semantic("2", "7"), Some(&next), now)
            .expect("new captured URL request"),
    );
    let actions = reply(
        &mut adapter,
        &old,
        json!("https://old.fixture.invalid/#committed"),
        now,
    );
    let old_terminal = response(&actions);
    assert_eq!(old_terminal["id"], "1");
    assert_eq!(old_terminal["error"]["kind"], "outcome_unknown");
    assert_eq!(
        old_terminal["error"]["details"]["acknowledgedResult"],
        json!({"url":"https://old.fixture.invalid/#committed","sessionOnly":true,"committedUrlOnly":true})
    );
    assert_eq!(
        old_terminal["error"]["details"]["remoteMethod"],
        "getCommittedTabUrl"
    );
    assert!(old_terminal.get("result").is_none());
    assert!(actions
        .iter()
        .any(|action| matches!(action, ExtensionWireAction::MatchedBrokerMessage { .. })));
    assert!(!actions
        .iter()
        .any(|action| matches!(action, ExtensionWireAction::ExtensionFrame { .. })));
    assert_eq!(adapter.session_turns[SID].turn, "turn2");
    let current = response(&reply(&mut adapter, &new, json!("chrome://newtab/"), now));
    assert_eq!(current["id"], "2");
    assert_eq!(current["result"]["url"], "chrome://newtab/");
    assert!(adapter.leases.is_empty());
    assert!(adapter.claims.is_empty());
}

#[test]
fn whole_session_inventory_calls_get_tabs_once_even_empty_without_acquiring_metadata() {
    for candidates in [json!([]), json!([2001, 51])] {
        let (mut adapter, context, now) = boot();
        let actions = adapter
            .written_semantic(
                semantic(
                    "1",
                    "inventory",
                    json!({"sessionOnly":true,"knownTabIds":candidates}),
                ),
                Some(&context),
                now,
            )
            .unwrap();
        assert_eq!(
            actions
                .iter()
                .filter(|a| matches!(a, ExtensionWireAction::ExtensionFrame { .. }))
                .count(),
            1
        );
        let request = frame(&actions);
        assert_eq!(request["method"], "getTabs");
        assert_eq!(request["params"]["session_id"], SID);
        assert_eq!(request["params"]["turn_id"], "turn1");
        assert!(request["params"].get("knownTabIds").is_none());
        assert_eq!(adapter.session_turns[SID].phase, TurnPhase::Active);
        let rows: Vec<_> = (1..=1002)
            .rev()
            .map(|id| json!({"id":id,"title":format!("actual-{id}")}))
            .collect();
        let done = reply(&mut adapter, &request, json!(rows), now);
        let result = response(&done);
        assert_eq!(result["result"]["sessionOnly"], true);
        assert_eq!(result["result"]["tabs"].as_array().unwrap().len(), 1002);
        assert_eq!(result["result"]["tabs"][0]["id"], 1002);
        assert!(
            !done
                .iter()
                .any(|a| matches!(a, ExtensionWireAction::ExtensionFrame { .. })),
            "no fallback or follow-up GetTabs"
        );
        assert!(
            adapter.leases.is_empty() && adapter.claims.is_empty() && adapter.creations.is_empty()
        );
    }
    let (mut adapter, context, now) = boot();
    let request = frame(
        &adapter
            .written_semantic(
                semantic(
                    "1",
                    "inventory",
                    json!({"sessionOnly":true,"knownTabIds":[]}),
                ),
                Some(&context),
                now,
            )
            .unwrap(),
    );
    assert_eq!(
        response(&reply(&mut adapter, &request, json!([]), now))["result"],
        json!({"tabs":[],"sessionOnly":true})
    );
    assert_eq!(adapter.session_turns[SID].phase, TurnPhase::Active);
}

#[test]
fn whole_session_inventory_refuses_invalid_candidates_before_native_and_keeps_activation_unknown() {
    let (mut adapter, context, now) = boot();
    for params in [
        json!({"sessionOnly":true}),
        json!({"sessionOnly":true,"knownTabIds":[0]}),
        json!({"sessionOnly":true,"knownTabIds":[2,2]}),
        json!({"sessionOnly":true,"knownTabIds":[9_007_199_254_740_992u64]}),
        json!({"sessionOnly":false,"knownTabIds":[]}),
        json!({"sessionOnly":null,"knownTabIds":[]}),
    ] {
        assert!(
            matches!(adapter.written_semantic(semantic("1","inventory",params),Some(&context),now),Err(ExtensionWireError::LocalRefusal{code,..}) if code=="invalid_request")
        );
        assert_eq!(adapter.rpc.pending_len(), 0);
    }
    assert!(
        matches!(adapter.written_semantic(semantic("1","inventory",json!({"sessionOnly":true,"knownTabIds":[]})),None,now),Err(ExtensionWireError::LocalRefusal{code,..}) if code=="wire_context_required")
    );
    let request = frame(
        &adapter
            .written_semantic(
                semantic(
                    "1",
                    "inventory",
                    json!({"sessionOnly":true,"knownTabIds":[]}),
                ),
                Some(&context),
                now,
            )
            .unwrap(),
    );
    let actions=adapter.written_extension(json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":1,"message":"activation is not known"}}),now).unwrap();
    assert_eq!(response(&actions)["error"]["kind"], "outcome_unknown");
    assert_eq!(
        adapter.session_turns[SID].phase,
        TurnPhase::ActivationUnknown
    );
    assert!(
        matches!(adapter.written_semantic(semantic("2","inventory",json!({"sessionOnly":true,"knownTabIds":[]})),Some(&context),now),Err(ExtensionWireError::LocalRefusal{code,..}) if code=="session_unavailable")
    );
}

#[test]
fn whole_session_inventory_late_reply_cannot_satisfy_replacement_turn() {
    let (mut adapter, context, now) = boot();
    let params = json!({"sessionOnly":true,"knownTabIds":[]});
    let old = frame(
        &adapter
            .written_semantic(
                semantic("1", "inventory", params.clone()),
                Some(&context),
                now,
            )
            .unwrap(),
    );
    let next = ExtensionWireContext::new(SID, "turn2").unwrap();
    let new = frame(
        &adapter
            .written_semantic(semantic("2", "inventory", params), Some(&next), now)
            .unwrap(),
    );
    assert_eq!(
        response(&reply(&mut adapter, &old, json!([]), now))["error"]["kind"],
        "outcome_unknown"
    );
    assert_eq!(adapter.session_turns[SID].turn, "turn2");
    assert_eq!(
        response(&reply(&mut adapter, &new, json!([]), now))["result"],
        json!({"tabs":[],"sessionOnly":true})
    );
    assert!(adapter.leases.is_empty() && adapter.claims.is_empty());
}

#[test]
fn whole_session_inventory_cancellation_preserves_late_native_reply_without_replay() {
    let (mut adapter, context, now) = boot();
    let request = frame(
        &adapter
            .written_semantic(
                semantic(
                    "1",
                    "inventory",
                    json!({"sessionOnly":true,"knownTabIds":[]}),
                ),
                Some(&context),
                now,
            )
            .unwrap(),
    );
    let _ = adapter.on_cancel("1");
    let actions = reply(&mut adapter, &request, json!([]), now);
    assert_eq!(response(&actions)["error"]["kind"], "outcome_unknown");
    assert!(!actions
        .iter()
        .any(|action| matches!(action, ExtensionWireAction::ExtensionFrame { .. })));
    assert_eq!(adapter.rpc.pending_len(), 0);
    assert!(adapter.leases.is_empty() && adapter.claims.is_empty());
}

#[test]
fn notification_keeps_actual_source_target_and_never_uses_payload_as_provenance() {
    let (mut adapter, context, now) = boot();
    let _token = attached(&mut adapter, &context, "1", 7, now);
    for target in [Some("actual-debuggee-target"), None] {
        let mut source = json!({"tabId":7});
        if let Some(target) = target {
            source["targetId"] = json!(target);
        }
        let actions = adapter
            .written_extension(
                json!({
                    "jsonrpc":"2.0","method":"onCDPEvent",
                    "params":{"source":source,"method":"Page.fileChooserOpened",
                        "params":{"backendNodeId":17,"targetId":"payload-target"}},
                }),
                now,
            )
            .unwrap();
        let event = actions
            .into_iter()
            .find_map(|action| match action {
                ExtensionWireAction::BrokerMessage(value) if value["kind"] == "event" => {
                    Some(value)
                }
                _ => None,
            })
            .expect("actual owned native notification");
        assert_eq!(event["sourceTargetId"].as_str(), target);
        assert!(event.get("sessionId").is_none());
        assert_eq!(event["params"]["targetId"], "payload-target");
    }
}

fn queued_phase(actions: &[ExtensionWireAction]) -> RequestId {
    actions
        .iter()
        .find_map(|action| match action {
            ExtensionWireAction::ExtensionFrame {
                phase: Some(phase), ..
            } => Some(phase.clone()),
            _ => None,
        })
        .expect("actual locally minted pending RPC phase")
}

#[test]
fn zero_frame_discard_preserves_the_old_turn_children_and_other_pending_rpc() {
    for finishing in [false, true] {
        let (mut adapter, context, now) = boot();
        let token = attached(&mut adapter, &context, "1", 7, now);
        let child = child_attach(&mut adapter, &context, "2", &token, now);
        reply(
            &mut adapter,
            &child,
            json!({"sessionId":"actual-child"}),
            now,
        );
        let epoch = adapter.session_turns[SID].epoch;
        let next = ExtensionWireContext::new(SID, "turn2").unwrap();
        let queued = ExtensionWireAdapter::on_semantic(
            &mut adapter,
            if finishing {
                semantic("3", "finishTurn", json!({}))
            } else {
                semantic(
                    "3",
                    "inventory",
                    json!({"sessionOnly":true,"knownTabIds":[]}),
                )
            },
            Some(if finishing { &context } else { &next }),
            now,
        )
        .unwrap();
        let phase = queued_phase(&queued);
        let sibling = ExtensionWireAdapter::on_semantic(
            &mut adapter,
            semantic("4", "inventory", json!({})),
            None,
            now,
        )
        .unwrap();
        let sibling_phase = queued_phase(&sibling);
        assert_eq!(adapter.session_turns[SID].epoch, epoch);
        assert_eq!(adapter.session_turns[SID].phase, TurnPhase::Active);
        assert_eq!(adapter.session_turns[SID].turn, context.host_turn_id());
        assert!(adapter.claims[&token].live);
        assert_eq!(adapter.claims[&token].turn, context.host_turn_id());
        assert_eq!(
            adapter.children[&(7, "actual-child".into())].state,
            ChildState::Live
        );
        let discarded = adapter.discard_unwritten(&phase).unwrap();
        assert!(
            matches!(&discarded[..], [ExtensionWireAction::SemanticFinished { semantic_id }] if semantic_id=="3")
        );
        assert!(!adapter.tasks.contains_key(&phase));
        assert!(adapter.rpc.pending_method(&phase).is_none());
        assert!(adapter.tasks.contains_key(&sibling_phase));
        assert_eq!(
            adapter.rpc.pending_method(&sibling_phase),
            Some(Method::GetUserTabs)
        );
        adapter.commit_write(&sibling_phase).unwrap();
        reply(&mut adapter, &frame(&sibling), json!([]), now);
        assert!(adapter
            .expire(now + DEADLINE + Duration::from_secs(1))
            .is_empty());
        assert!(adapter
            .on_extension(
                json!({"jsonrpc":"2.0","id":phase.as_str(),"result":null}),
                now
            )
            .unwrap()
            .is_empty());
        assert_eq!(adapter.session_turns[SID].epoch, epoch);
        assert_eq!(adapter.session_turns[SID].phase, TurnPhase::Active);
        assert!(adapter.claims[&token].live);
        assert_eq!(
            adapter.children[&(7, "actual-child".into())].state,
            ChildState::Live
        );
    }
}

#[test]
fn initial_attach_reservation_commits_only_at_the_same_actual_phase_start() {
    let (mut adapter, context, now) = boot();
    let queued = ExtensionWireAdapter::on_semantic(
        &mut adapter,
        semantic("1", "attach", json!({"tabId":8})),
        Some(&context),
        now,
    )
    .unwrap();
    let phase = queued_phase(&queued);
    assert!(!adapter.attaching.contains_key(&8));
    assert!(!adapter.session_turns.contains_key(SID));
    assert!(adapter
        .on_semantic(
            semantic("2", "attach", json!({"tabId":8})),
            Some(&context),
            now
        )
        .is_err());
    adapter.discard_unwritten(&phase).unwrap();
    assert!(adapter.tasks.is_empty());
    assert!(!adapter.attaching.contains_key(&8));
    let replacement = ExtensionWireAdapter::on_semantic(
        &mut adapter,
        semantic("3", "attach", json!({"tabId":8})),
        Some(&context),
        now,
    )
    .unwrap();
    let replacement_phase = queued_phase(&replacement);
    assert_ne!(phase, replacement_phase);
    adapter.commit_write(&replacement_phase).unwrap();
    assert_eq!(adapter.session_turns[SID].phase, TurnPhase::Active);
    assert_eq!(adapter.attaching[&8].turn, context.host_turn_id());
    assert!(adapter.discard_unwritten(&replacement_phase).is_err());
    assert!(adapter.tasks.contains_key(&replacement_phase));
    assert!(adapter.rpc.pending_method(&replacement_phase).is_some());
    assert!(adapter.commit_write(&replacement_phase).is_err());
}

#[test]
fn started_finish_cannot_be_refunded_and_expiry_remains_unknown() {
    let (mut adapter, context, now) = boot();
    let token = attached(&mut adapter, &context, "1", 7, now);
    let queued = ExtensionWireAdapter::on_semantic(
        &mut adapter,
        semantic("2", "finishTurn", json!({})),
        Some(&context),
        now,
    )
    .unwrap();
    let phase = queued_phase(&queued);
    assert_eq!(adapter.session_turns[SID].phase, TurnPhase::Active);
    adapter.commit_write(&phase).unwrap();
    assert_eq!(adapter.session_turns[SID].phase, TurnPhase::Finishing);
    assert!(!adapter.claims[&token].live);
    assert!(adapter.discard_unwritten(&phase).is_err());
    let expired = adapter.expire(now + DEADLINE + Duration::from_secs(1));
    assert_eq!(response(&expired)["error"]["kind"], "outcome_unknown");
    assert_eq!(adapter.session_turns[SID].phase, TurnPhase::FinishUnknown);
    assert!(adapter
        .on_semantic(semantic("3", "finishTurn", json!({})), Some(&context), now)
        .is_err());
}

#[test]
fn a_fenced_followup_keeps_the_earlier_actual_attach_ack_custody() {
    let (mut adapter, context, now) = boot();
    let attach = before_attach_ack(&mut adapter, &context, "1", 7, now);
    let next = ExtensionWireAdapter::on_extension(
        &mut adapter,
        json!({"jsonrpc":"2.0","id":attach["id"]}),
        now,
    )
    .unwrap();
    let phase = queued_phase(&next);
    assert_eq!(
        adapter.tasks[&phase].write_phase,
        WritePhase::AfterEarlierWrite
    );
    assert!(adapter.tasks[&phase].attach_acknowledged);
    assert!(adapter.discard_unwritten(&phase).is_err());
    assert!(adapter.tasks.contains_key(&phase));
    assert!(adapter.rpc.pending_method(&phase).is_some());
    adapter.on_cancel("1");
    let expired = adapter.expire(now + DEADLINE + Duration::from_secs(1));
    let value = response(&expired);
    assert_eq!(value["error"]["kind"], "outcome_unknown");
    let token = value["error"]["details"]["custody"]["claim"]
        .as_str()
        .unwrap();
    assert!(!adapter.claims[token].live);
    assert_eq!(
        adapter.claims[token].identity,
        AttachmentIdentity::ReconciliationRequired
    );
}

#[test]
fn cancelled_session_name_keeps_the_matched_positive_ack_without_replay() {
    let (mut adapter, context, now) = boot();
    let request = frame(
        &adapter
            .written_semantic(
                semantic("51", "nameSession", json!({"name":"actual title"})),
                Some(&context),
                now,
            )
            .expect("admitted session naming"),
    );
    assert_eq!(request["method"], "nameSession");
    assert_eq!(request["params"]["session_id"], SID);
    assert_eq!(request["params"]["turn_id"], "turn1");
    adapter.on_cancel("51");
    let actions = reply(&mut adapter, &request, Value::Null, now);
    let value = response(&actions);
    assert_eq!(value["error"]["kind"], "outcome_unknown");
    assert_eq!(
        value["error"]["details"]["acknowledgedResult"],
        json!({"renamed":true}),
        "matched native naming success must survive the cancellation fence"
    );
    assert!(
        !actions
            .iter()
            .any(|action| matches!(action, ExtensionWireAction::ExtensionFrame { .. })),
        "late naming acknowledgement must not replay a native operation"
    );
    assert_eq!(
        actions
            .iter()
            .filter(|action| matches!(action, ExtensionWireAction::SemanticFinished { .. }))
            .count(),
        1
    );
}

#[test]
fn framed_original_inventory_preserves_title_and_group_before_broker_value_ipc() {
    let (mut adapter, _, now) = boot();
    let request = frame(
        &adapter
            .written_semantic(semantic("1", "inventory", json!({})), None, now)
            .unwrap(),
    );
    let text = format!(
        r#"{{"jsonrpc":"2.0","id":{},"result":[{{"id":17,"title":"\ud800","tabGroup":"\udc00"}}]}}"#,
        serde_json::to_string(request["id"].as_str().unwrap()).unwrap()
    );
    let mut wire = (text.len() as u32).to_ne_bytes().to_vec();
    wire.extend_from_slice(text.as_bytes());
    let bytes = super::super::extension_framing::read_frame(
        &mut std::io::Cursor::new(wire),
        super::super::extension_framing::Direction::ChromeToHost,
    )
    .unwrap()
    .unwrap();
    assert!(serde_json::from_slice::<Value>(&bytes).is_err());
    let raw: Box<RawValue> = serde_json::from_slice(&bytes).unwrap();
    let actions = adapter.written_extension_json(&raw, now).unwrap();
    let terminal = response(&actions);
    assert_eq!(terminal["result"]["tabs"][0]["id"], 17);
    assert_eq!(terminal["result"]["tabs"][0]["titleJson"], r#""\ud800""#);
    assert_eq!(
        terminal["result"]["tabs"][0]["groupTitleJson"],
        r#""\udc00""#
    );
    let ipc = serde_json::to_vec(&terminal).unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&ipc).unwrap(), terminal);
    assert!(actions
        .iter()
        .any(|a| matches!(a, ExtensionWireAction::MatchedBrokerMessage { .. })));
}

#[test]
fn original_debugger_claim_and_attached_event_preserve_preexisting_lone_title() {
    let (mut adapter, context, now) = boot();
    let claim_request = frame(
        &adapter
            .written_semantic(
                semantic("1", "attach", json!({"tabId":7})),
                Some(&context),
                now,
            )
            .unwrap(),
    );
    assert_eq!(claim_request["method"], "claimUserTab");
    let raw_reply = |request: &Value, body: &str| -> Box<RawValue> {
        serde_json::from_str(&format!(
            r#"{{"jsonrpc":"2.0","id":{},"result":{body}}}"#,
            serde_json::to_string(request["id"].as_str().unwrap()).unwrap()
        ))
        .unwrap()
    };
    let targets = frame(
        &adapter
            .written_extension_json(
                &raw_reply(
                    &claim_request,
                    r#"{"id":7,"url":"about:blank","title":"\ud800"}"#,
                ),
                now,
            )
            .unwrap(),
    );
    assert_eq!(targets["params"]["method"], "Target.getTargets");
    let attach = frame(&adapter.written_extension_json(&raw_reply(&targets, r#"{"targetInfos":[{"tabId":7,"type":"page","targetId":"target-7","attached":false,"title":"\ud800"}]}"#), now).unwrap());
    assert_eq!(attach["method"], "attach");
    let probe = frame(
        &adapter
            .written_extension_json(&raw_reply(&attach, "null"), now)
            .unwrap(),
    );
    let targets = frame(
        &adapter
            .written_extension_json(&raw_reply(&probe, r#"{"result":{"value":0}}"#), now)
            .unwrap(),
    );
    let terminal = response(&adapter.written_extension_json(&raw_reply(&targets, r#"{"targetInfos":[{"tabId":7,"type":"page","targetId":"target-7","attached":true,"title":"\ud800"}]}"#), now).unwrap());
    let token = terminal["result"]["claim"].as_str().unwrap();
    assert!(adapter.claims[token].live);
    assert_eq!(adapter.claims[token].tab, 7);
    assert_eq!(adapter.claims[token].target, "target-7");
    let event: &RawValue = serde_json::from_str(r#"{"jsonrpc":"2.0","method":"onCDPEvent","params":{"source":{"tabId":7},"method":"Target.attachedToTarget","params":{"sessionId":"child-raw","targetInfo":{"targetId":"child-target","type":"iframe","title":"\udc00"}}}}"#).unwrap();
    let actions = adapter.written_extension_json(event, now).unwrap();
    assert_eq!(
        adapter.children[&(7, "child-raw".to_owned())].state,
        ChildState::Live
    );
    let forwarded = actions
        .iter()
        .find_map(|action| match action {
            ExtensionWireAction::BrokerMessage(value) if value["kind"] == "event" => Some(value),
            _ => None,
        })
        .unwrap();
    assert!(forwarded.get("params").is_none());
    assert_eq!(
        forwarded["paramsJson"],
        r#"{"sessionId":"child-raw","targetInfo":{"targetId":"child-target","type":"iframe","title":"\udc00"}}"#
    );
    assert_eq!(forwarded["claim"], token);
}

#[test]
fn early_notifications_replay_past_old_count_and_size_quotas_in_order() {
    for (count, padding) in [(1100, 8), (1, 1024 * 1024 + 1)] {
        let (mut adapter, context, now) = boot();
        let available = adapter.early_budget.available_bytes();
        let attach = before_attach_ack(&mut adapter, &context, "1", 7, now);
        for index in 0..count {
            let actions = adapter
                .written_extension(
                    json!({
                        "jsonrpc":"2.0", "method":"onCDPEvent",
                        "params":{"source":{"tabId":7}, "method":"Runtime.consoleAPICalled",
                            "params":{"index":index, "padding":"x".repeat(padding)}}
                    }),
                    now,
                )
                .expect("legitimate early notifications must not end the generation");
            assert!(actions.is_empty());
        }
        assert!(adapter.early_budget.available_bytes() < available);
        let probe = frame(
            &adapter
                .written_extension(json!({"jsonrpc":"2.0","id":attach["id"]}), now)
                .unwrap(),
        );
        let targets = frame(&reply(
            &mut adapter,
            &probe,
            json!({"result":{"value":0}}),
            now,
        ));
        let actions = reply(
            &mut adapter,
            &targets,
            json!({"targetInfos":[{"tabId":7,"type":"page","targetId":"target-7","attached":true}]}),
            now,
        );
        let token = response(&actions)["result"]["claim"]
            .as_str()
            .unwrap()
            .to_owned();
        let events: Vec<_> = actions
            .iter()
            .filter_map(|action| match action {
                ExtensionWireAction::BrokerMessage(value) if value["kind"] == "event" => {
                    Some(value)
                }
                _ => None,
            })
            .collect();
        assert_eq!(events.len(), count);
        for (index, event) in events.iter().enumerate() {
            assert_eq!(event["claim"], token);
            let params = event
                .get("paramsJson")
                .and_then(Value::as_str)
                .map(|raw| serde_json::from_str::<Value>(raw).unwrap())
                .unwrap_or_else(|| event["params"].clone());
            assert_eq!(params["index"], index);
            assert_eq!(params["padding"].as_str().unwrap().len(), padding);
        }
        assert_eq!(adapter.early_budget.available_bytes(), available);
    }
}
