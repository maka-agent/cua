// SPDX-License-Identifier: MIT

use super::*;

const SCOPE: &str = "11111111-1111-4111-8111-111111111111";
fn fixed_broker_ui() -> Value {
    json!({"operation":"control","cursor":{"id":"cursor","label":"Maka","color":"blue","enabled":true,"reducedMotion":false},"ownerEpoch":"1","point":null,"action":"idle"})
}
fn fixed_broker_fixture(profile: Option<&str>) -> (ExtensionHostBroker, ClientConnection) {
    let origin = ExtensionOrigin::from_id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    let (_, mut broker, _) = ExtensionHostBroker::channels(origin, LocalPrincipal::UnixUid(123));
    let mut capabilities = json!({"metadata":true,"sessionTabResolution":true});
    if let Some(profile) = profile {
        capabilities["sessionPreparation"] = json!(profile);
    }
    broker.extension(json!({"kind":"hello","protocol":1,"extensionId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","instanceId":"fixed-test","capabilities":capabilities}),&mut Vec::new()).unwrap();
    let client = broker
        .admit(CheckedLocalPeer::from_checked_principal(
            LocalPrincipal::UnixUid(123),
        ))
        .unwrap();
    (broker, client)
}
fn fixed_control(method: &str) -> Value {
    let mut request = json!({"method":method,"id":1,"tabId":11,"scopeId":SCOPE});
    if method == "prepareSessionTab" {
        request["policy"] = json!({"popupEnabled":false,"headerEnabled":false,"headers":[]});
        request["ui"] = fixed_broker_ui();
    }
    if method == "sessionUi" {
        request["ui"] = fixed_broker_ui();
    }
    request
}
#[test]
fn fixed_controls_are_closed_and_cleanup_alone_uses_reserved_admission() {
    for method in [
        "prepareSessionTab",
        "sessionUi",
        "clearSessionPreparation",
        "createSessionPopupTab",
    ] {
        let valid = fixed_control(method);
        let decoded: ControlRequest = serde_json::from_value(valid.clone()).unwrap();
        assert_eq!(decoded.is_cleanup(), method == "clearSessionPreparation");
        if decoded.is_cleanup() {
            assert!(decoded.bounded_cleanup());
        }
        for field in ["owner", "generation", "expression", "grant"] {
            let mut invalid = valid.clone();
            invalid[field] = json!("forged");
            assert!(
                serde_json::from_value::<ControlRequest>(invalid).is_err(),
                "extra field {field}"
            );
        }
    }
}
#[test]
fn fixed_controls_require_actual_profile_and_context_without_physical_claim_inference() {
    for method in [
        "prepareSessionTab",
        "sessionUi",
        "clearSessionPreparation",
        "createSessionPopupTab",
    ] {
        for profile in [
            None,
            Some("metadata_only"),
            Some("provider_session"),
            Some("explicit_fixed"),
        ] {
            for contextual in [false, true] {
                let (mut broker, mut client) = fixed_broker_fixture(profile);
                let wire = ExtensionWireContext::new("fixed-owner", "turn-A").unwrap();
                if contextual {
                    broker.input_context = Some(wire.clone());
                }
                let mut output = Vec::new();
                broker.control(
                    client.sender.lease.id,
                    serde_json::from_value(fixed_control(method)).unwrap(),
                    &mut output,
                );
                if contextual && profile == Some("explicit_fixed") {
                    assert_eq!(output.len(), 1);
                    let outbound = output.pop().unwrap();
                    assert_eq!(outbound.value["method"], method);
                    assert_eq!(outbound.value["params"]["scopeId"], SCOPE);
                    assert_eq!(outbound.wire_context, Some(wire));
                } else {
                    assert!(output.is_empty());
                    let event = client.events.try_recv().unwrap().into_parts().0;
                    let expected = if contextual {
                        "unsupported"
                    } else {
                        "context_required"
                    };
                    assert!(
                        matches!(event,ControlEvent::Reply{outcome:ControlOutcome::ConnectorRejected{kind,..},..} if kind==expected)
                    );
                }
                assert!(
                    broker.claims.is_empty(),
                    "logical preparation cannot acquire or register physical authority"
                );
            }
        }
    }
}
#[test]
fn fixed_control_invalid_scope_tab_or_ui_never_dispatches() {
    for (field, value) in [
        ("scopeId", json!("not-a-scope")),
        ("tabId", json!(0)),
        ("tabId", json!(9_007_199_254_740_992u64)),
        ("ui", json!({"operation":"evaluate"})),
    ] {
        let (mut broker, mut client) = fixed_broker_fixture(Some("explicit_fixed"));
        broker.input_context = Some(ExtensionWireContext::new("fixed-owner", "turn-A").unwrap());
        let mut request = fixed_control("prepareSessionTab");
        request[field] = value;
        match serde_json::from_value::<ControlRequest>(request) {
            Err(_) => {}
            Ok(request) => {
                let mut output = Vec::new();
                broker.control(client.sender.lease.id, request, &mut output);
                assert!(output.is_empty());
                assert!(
                    matches!(client.events.try_recv().unwrap().into_parts().0,ControlEvent::Reply{outcome:ControlOutcome::ConnectorRejected{kind,..},..} if kind=="invalid_request")
                );
            }
        }
        assert!(broker.pending.is_empty() && broker.claims.is_empty());
    }
}
#[test]
fn logical_events_use_existing_exact_owner_route_without_a_physical_claim() {
    let (mut broker, mut client) = fixed_broker_fixture(Some("explicit_fixed"));
    let mut sibling = broker
        .admit(CheckedLocalPeer::from_checked_principal(
            LocalPrincipal::UnixUid(123),
        ))
        .unwrap();
    let owner = broker.clients[&client.sender.lease.id].owner.clone();
    let wire = ExtensionWireContext::new("fixed-owner", "turn-A").unwrap();
    for cleanup in [false, true] {
        let mut event = json!({"kind":if cleanup {"session_preparation_cleanup"} else {"session_popup_requested"},"protocol":1,"generation":broker.generation,"owner":owner,"tabId":11,"scopeId":SCOPE,"wireContext":wire});
        if cleanup {
            event["cleanupConfirmed"] = json!(false);
        } else {
            event["url"] = json!("https://popup.fixture.invalid/");
            event["frameId"] = json!(3);
        }
        let mut output = Vec::new();
        broker.extension(event, &mut output).unwrap();
        assert!(output.is_empty());
        let observed = client.events.try_recv().unwrap().into_parts().0;
        match observed {
            ControlEvent::SessionPreparationCleanup {
                scope_id,
                tab_id,
                cleanup_confirmed,
                wire_context,
                ..
            } if cleanup => {
                assert_eq!(scope_id, SCOPE);
                assert_eq!(tab_id, 11);
                assert!(!cleanup_confirmed);
                assert_eq!(wire_context, wire);
            }
            ControlEvent::SessionPopupRequested {
                scope_id,
                tab_id,
                frame_id,
                wire_context,
                ..
            } if !cleanup => {
                assert_eq!(scope_id, SCOPE);
                assert_eq!(tab_id, 11);
                assert_eq!(frame_id, Some(3));
                assert_eq!(wire_context, wire);
            }
            other => panic!("logical observation became an unrelated physical event: {other:?}"),
        }
        assert!(sibling.events.try_recv().is_err());
        assert!(broker.claims.is_empty());
    }
}

#[test]
fn queued_fixed_cleanup_survives_its_fresh_turn_finish_while_business_work_is_fenced() {
    let (mut broker, mut client) = fixed_broker_fixture(Some("explicit_fixed"));
    let context = ExtensionWireContext::new("fixed-owner", "fresh-cleanup-turn").unwrap();
    broker.input_context = Some(context.clone());
    let mut queued = Vec::new();
    let mut business = fixed_control("sessionUi");
    business["ui"]["operation"] = json!("update");
    broker.control(
        client.sender.lease.id,
        serde_json::from_value(business).unwrap(),
        &mut queued,
    );
    let mut clear = fixed_control("clearSessionPreparation");
    clear["id"] = json!(2);
    broker.control(
        client.sender.lease.id,
        serde_json::from_value(clear).unwrap(),
        &mut queued,
    );
    assert_eq!(
        queued.len(),
        2,
        "both actual outbounds must precede turn finishing"
    );
    let cleanup = queued.pop().unwrap();
    let business = queued.pop().unwrap();
    let cleanup_id = cleanup.outer_id().unwrap();
    let business_id = business.outer_id().unwrap();
    let cleanup_guard = cleanup.dispatch_guard();
    let business_guard = business.dispatch_guard();
    assert!(cleanup_guard.is_live() && business_guard.is_live());
    assert!(
        broker.pending[&cleanup_id].scope_fence.is_none(),
        "only the exact fixed cleanup joins the existing cleanup scope exemption"
    );
    assert!(broker.pending[&business_id].scope_fence.is_some());
    assert_eq!(cleanup.wire_context(), Some(&context));
    assert!(
        cleanup.payload_for_transport()["params"]
            .get("claim")
            .is_none()
    );

    broker.control(
        client.sender.lease.id,
        ControlRequest::FinishTurn { id: 3, keep: None },
        &mut queued,
    );
    assert_eq!(
        queued.len(),
        1,
        "FinishTurn must not replay or replace either queued request"
    );
    assert_eq!(queued[0].payload_for_transport()["method"], "finishTurn");
    assert!(
        !business_guard.is_live(),
        "ended turn must fence queued ordinary UI work"
    );
    assert!(
        cleanup_guard.is_live(),
        "cleanup must settle after its own fresh turn ends"
    );

    let mut business_bytes = Vec::new();
    let business_report = business.write_to(&mut business_bytes).unwrap();
    assert_eq!(
        business_report,
        Some(WriteReport::Skipped { outer: business_id })
    );
    assert!(business_bytes.is_empty());
    let mut generated = Vec::new();
    broker.written(business_report.unwrap(), &mut generated);
    assert!(matches!(client.events.try_recv().unwrap().into_parts().0,
        ControlEvent::Reply { id: 1, outcome: ControlOutcome::ConnectorRejected { kind, message, .. } }
        if kind == "not_dispatched" && message == "extension command was fenced before any write"));

    let mut cleanup_bytes = Vec::new();
    let cleanup_report = cleanup.write_to(&mut cleanup_bytes).unwrap();
    assert_eq!(
        cleanup_report,
        Some(WriteReport::Written { outer: cleanup_id })
    );
    broker.written(cleanup_report.unwrap(), &mut generated);
    let mut reader = std::io::Cursor::new(cleanup_bytes);
    let body = extension_framing::read_frame(&mut reader, Direction::HostToChrome)
        .unwrap()
        .unwrap();
    let actual: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(actual["method"], "clearSessionPreparation");
    assert_eq!(actual["params"], json!({"tabId":11,"scopeId":SCOPE}));
    assert_eq!(
        actual["wireContext"],
        serde_json::to_value(&context).unwrap()
    );
    assert_eq!(
        extension_framing::read_frame(&mut reader, Direction::HostToChrome).unwrap(),
        None,
        "the original non-cloneable cleanup outbound writes exactly once"
    );
    assert!(
        generated.is_empty(),
        "no replay may be generated after either write outcome"
    );
    assert!(
        broker.claims.is_empty(),
        "logical cleanup cannot acquire physical custody"
    );
}
