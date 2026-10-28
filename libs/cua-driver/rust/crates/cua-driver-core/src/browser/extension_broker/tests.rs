use super::*;
use std::io::Cursor;

// Earlier keepers consume their original semantic events. Dedicated V6
// keepers assert the additive trusted metadata lane directly.
fn semantic_control(client: &mut ClientConnection) -> Queued<ControlEvent> {
    loop {
        let (event, charge) = client.events.try_recv().unwrap().into_parts();
        if !matches!(
            event,
            ControlEvent::CdpUnconfirmed { .. } | ControlEvent::CdpRouteClosed { .. }
        ) {
            return Queued::new(event, charge);
        }
    }
}

fn terminal_control(client: &mut ClientConnection) -> Queued<ControlEvent> {
    loop {
        let (event, charge) = client.events.try_recv().unwrap().into_parts();
        if !matches!(
            event,
            ControlEvent::CdpUnconfirmed { event: None, .. } | ControlEvent::CdpRouteClosed { .. }
        ) {
            return Queued::new(event, charge);
        }
    }
}

fn fixture() -> ExtensionHostBroker {
    fixture_with_output().0
}

fn fixture_with_output() -> (ExtensionHostBroker, mpsc::Receiver<ExtensionOutbound>) {
    let origin = ExtensionOrigin::from_id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    let (_, mut broker, output_receiver) =
        ExtensionHostBroker::channels(origin, LocalPrincipal::UnixUid(123));
    let mut output = Vec::new();
    broker.extension(json!({"kind":"hello","protocol":1,"extensionId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","instanceId":"actual-fixture-instance","capabilities":{"metadata":true,"rawTabCdp":true,"nativeWindowProof":false}}), &mut output).unwrap();
    let bound = write(output.pop().unwrap());
    assert_eq!(bound["kind"], "bound");
    (broker, output_receiver)
}

fn write(outbound: ExtensionOutbound) -> Value {
    let mut bytes = Vec::new();
    outbound.write_to(&mut bytes).unwrap();
    let mut reader = Cursor::new(bytes);
    let body = extension_framing::read_frame(&mut reader, Direction::HostToChrome)
        .unwrap()
        .unwrap();
    assert!(
        extension_framing::read_frame(&mut reader, Direction::HostToChrome)
            .unwrap()
            .is_none()
    );
    serde_json::from_slice(&body).unwrap()
}

fn admit(broker: &mut ExtensionHostBroker) -> ClientConnection {
    broker
        .admit(CheckedLocalPeer::from_checked_principal(
            LocalPrincipal::UnixUid(123),
        ))
        .unwrap()
}

fn request(
    broker: &mut ExtensionHostBroker,
    client: &ClientConnection,
    control: ControlRequest,
) -> Value {
    let mut output = Vec::new();
    broker.control(client.sender.lease.id, control, &mut output);
    assert_eq!(output.len(), 1, "control should dispatch exactly once");
    write(output.pop().unwrap())
}

fn reply(broker: &mut ExtensionHostBroker, command: &Value, result: Value) {
    let mut output = Vec::new();
    broker.extension(json!({"kind":"response","protocol":1,"generation":broker.generation,"id":command["id"],"result":result}), &mut output).unwrap();
    assert!(output.is_empty(), "a matched reply must not replay work");
}

fn attach(
    broker: &mut ExtensionHostBroker,
    client: &mut ClientConnection,
    id: u64,
    tab_id: u64,
    token: &str,
) -> CdpRoute {
    let command = request(broker, client, ControlRequest::Attach { id, tab_id });
    reply(
        broker,
        &command,
        json!({"claim":token,"tabId":tab_id,"targetId":format!("opaque-target-{tab_id}")}),
    );
    assert!(
        matches!(semantic_control(client).into_parts().0, ControlEvent::Reply { id: actual, outcome: ControlOutcome::Result(_) } if actual == id)
    );
    broker.bind_route(client.sender.lease.id, token).unwrap()
}

fn cdp(
    broker: &mut ExtensionHostBroker,
    client: &ClientConnection,
    route: &CdpRoute,
    id: u64,
) -> Value {
    let mut output = Vec::new();
    broker.cdp(
        client.sender.lease.id,
        route.sender.lease.id,
        json!({"id":id,"method":"Runtime.evaluate","params":{"expression":"1"}}),
        &mut output,
    );
    assert_eq!(output.len(), 1);
    write(output.pop().unwrap())
}

#[test]
fn peer_and_decoded_input_cannot_choose_a_foreign_owner() {
    let mut broker = fixture();
    assert!(matches!(
        broker.admit(CheckedLocalPeer::from_checked_principal(
            LocalPrincipal::UnixUid(456)
        )),
        Err(BrokerError::WrongPrincipal)
    ));
    assert!(serde_json::from_value::<ControlRequest>(
        json!({"method":"inventory","id":1,"owner":"forged"})
    )
    .is_err());
    let first = admit(&mut broker);
    let second = admit(&mut broker);
    let a = request(
        &mut broker,
        &first,
        ControlRequest::Inventory {
            id: 1,
            session_only: None,
            known_tab_ids: None,
        },
    );
    let b = request(
        &mut broker,
        &second,
        ControlRequest::Inventory {
            id: 1,
            session_only: None,
            known_tab_ids: None,
        },
    );
    assert_ne!(a["owner"], b["owner"]);
    assert_eq!(a["id"], "1");
    assert_eq!(b["id"], "2");
}

#[test]
fn out_of_order_control_results_keep_the_original_client_and_local_id() {
    let mut broker = fixture();
    let mut first = admit(&mut broker);
    let mut second = admit(&mut broker);
    let a = request(
        &mut broker,
        &first,
        ControlRequest::Inventory {
            id: 1,
            session_only: None,
            known_tab_ids: None,
        },
    );
    let b = request(
        &mut broker,
        &second,
        ControlRequest::Inventory {
            id: 1,
            session_only: None,
            known_tab_ids: None,
        },
    );
    reply(
        &mut broker,
        &b,
        json!({"tabs":[{"id":22,"lastAccessed":123.5}]}),
    );
    reply(&mut broker, &a, json!({"tabs":[{"id":11}]}));
    assert!(
        matches!(semantic_control(&mut first).into_parts().0, ControlEvent::Reply { id:1, outcome:ControlOutcome::Result(value) } if value["tabs"][0]["id"] == 11)
    );
    assert!(
        matches!(semantic_control(&mut second).into_parts().0, ControlEvent::Reply { id:1, outcome:ControlOutcome::Result(value) } if value["tabs"][0]["lastAccessed"] == 123.5)
    );
}

#[test]
fn same_owner_multiple_claims_can_reuse_inner_cdp_ids_without_collision() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let mut first = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let mut second = attach(&mut broker, &mut client, 2, 22, "claim-b");
    let a = cdp(&mut broker, &client, &first, 1);
    let b = cdp(&mut broker, &client, &second, 1);
    assert_eq!(
        a["owner"], b["owner"],
        "claims retain their logical transport owner"
    );
    assert_ne!(a["id"], b["id"]);
    assert_eq!(a["params"]["claim"], "claim-a");
    reply(&mut broker, &b, json!({"result":{"value":"second"}}));
    reply(&mut broker, &a, json!({"result":{"value":"first"}}));
    assert!(
        matches!(first.events.try_recv().unwrap().into_parts().0, BrokerCdpEvent::ChromeMessage(value) if value["id"] == 1 && value["result"]["value"] == "first")
    );
    assert!(
        matches!(second.events.try_recv().unwrap().into_parts().0, BrokerCdpEvent::ChromeMessage(value) if value["id"] == 1 && value["result"]["value"] == "second")
    );
}

#[test]
fn actual_chrome_rejection_and_connector_refusal_keep_distinct_provenance() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let mut route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let first = cdp(&mut broker, &client, &route, 1);
    let mut output = Vec::new();
    broker.extension(json!({"kind":"response","protocol":1,"generation":broker.generation,"id":first["id"],"error":{"kind":"chrome_rejected","message":"actual Chrome fixture rejection"}}), &mut output).unwrap();
    assert!(
        matches!(route.events.try_recv().unwrap().into_parts().0, BrokerCdpEvent::ChromeMessage(value) if value["error"]["message"] == "actual Chrome fixture rejection")
    );
    let second = cdp(&mut broker, &client, &route, 2);
    broker.extension(json!({"kind":"response","protocol":1,"generation":broker.generation,"id":second["id"],"error":{"kind":"unsupported","message":"Browser domain unavailable"}}), &mut output).unwrap();
    assert!(
        matches!(route.events.try_recv().unwrap().into_parts().0, BrokerCdpEvent::LocalRejected { id:2, code, .. } if code == "unsupported")
    );
    assert!(
        output.is_empty(),
        "neither rejection should replay or automatically attach"
    );
}

#[test]
fn closing_one_cdp_route_keeps_physical_custody_and_late_ack_without_touching_siblings() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let mut first = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let second = attach(&mut broker, &mut client, 2, 22, "claim-b");
    let written = cdp(&mut broker, &client, &first, 1);
    let mut output = Vec::new();
    broker.close_route(first.sender.lease.id, "fixture close", &mut output);
    assert!(matches!(
        terminal_control(&mut client).into_parts().0,
        ControlEvent::CdpUnconfirmed {
            id: 1,
            event: Some(BrokerCdpEvent::TransportFailure(_)),
            ..
        }
    ));
    assert!(
        first.events.try_recv().is_err(),
        "failure is delivered once in the atomic owner lane"
    );
    assert!(
        output.is_empty(),
        "reader cancellation is not detach authority"
    );
    assert!(client.sender.lease.alive.load(Ordering::SeqCst));
    assert!(broker.claims["claim-a"].alive.load(Ordering::SeqCst));
    reply(
        &mut broker,
        &written,
        json!({"result":{"acknowledged":"once"}}),
    );
    assert!(
        matches!(semantic_control(&mut client).into_parts().0, ControlEvent::OrphanCdpCompletion { route, claim, id:1, event:BrokerCdpEvent::ChromeMessage(value),.. } if route == first.sender.lease.id.0 && claim == "claim-a" && value["result"]["acknowledged"] == "once")
    );
    let b = cdp(&mut broker, &client, &second, 1);
    assert_eq!(b["params"]["claim"], "claim-b");
}

#[test]
fn queued_work_is_fenced_on_client_eof_and_close_owner_is_not_replayed() {
    let mut broker = fixture();
    let client = admit(&mut broker);
    let mut output = Vec::new();
    broker.control(
        client.sender.lease.id,
        ControlRequest::Inventory {
            id: 1,
            session_only: None,
            known_tab_ids: None,
        },
        &mut output,
    );
    let queued = output.pop().unwrap();
    broker.close_client(client.sender.lease.id, &mut output);
    let mut bytes = Vec::new();
    assert!(matches!(
        queued.write_to(&mut bytes).unwrap(),
        Some(WriteReport::Skipped { outer: 1 })
    ));
    assert!(bytes.is_empty());
    let close = write(output.pop().unwrap());
    assert_eq!(close["method"], "closeOwner");
    assert_eq!(close["id"], "2");
    broker.close_client(client.sender.lease.id, &mut output);
    assert!(output.is_empty(), "owner-close must be issued at most once");
}

#[test]
fn extension_eof_closes_all_routes_and_fences_previously_queued_frames() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let mut route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let mut output = Vec::new();
    broker.cdp(
        client.sender.lease.id,
        route.sender.lease.id,
        json!({"id":1,"method":"Input.insertText","params":{"text":"once"}}),
        &mut output,
    );
    broker.end_generation("fixture extension EOF");
    assert!(matches!(
        client.events.try_recv().unwrap().into_parts().0,
        ControlEvent::CdpUnconfirmed {
            id: 1,
            write_phase: ExtensionCdpWritePhase::Queued,
            event: None,
            ..
        }
    ));
    assert!(matches!(
        client.events.try_recv().unwrap().into_parts().0,
        ControlEvent::GenerationClosed { .. }
    ));
    assert!(
        route.events.try_recv().is_err(),
        "EOF cannot race phase metadata on the route lane"
    );
    let mut bytes = Vec::new();
    assert!(matches!(
        output.pop().unwrap().write_to(&mut bytes).unwrap(),
        Some(WriteReport::Skipped { .. })
    ));
    assert!(bytes.is_empty());
}

#[test]
fn event_before_reply_is_forwarded_in_order_and_late_duplicate_reply_has_no_effect() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let mut route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let command = cdp(&mut broker, &client, &route, 1);
    let mut output = Vec::new();
    broker.extension(json!({"kind":"event","protocol":1,"generation":broker.generation,"owner":command["owner"],"claim":"claim-a","method":"Runtime.consoleAPICalled","params":{"type":"log"}}), &mut output).unwrap();
    reply(&mut broker, &command, json!({"result":null}));
    assert!(
        matches!(route.events.try_recv().unwrap().into_parts().0, BrokerCdpEvent::ChromeMessage(value) if value["method"] == "Runtime.consoleAPICalled")
    );
    assert!(
        matches!(route.events.try_recv().unwrap().into_parts().0, BrokerCdpEvent::ChromeMessage(value) if value["id"] == 1 && value["result"].is_null())
    );
    reply(
        &mut broker,
        &command,
        json!({"result":{"unexpected":"duplicate"}}),
    );
    assert!(route.events.try_recv().is_err());
}

#[test]
fn early_revocation_never_publishes_a_live_claim_or_ends_unrelated_clients() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let other = admit(&mut broker);
    let command = request(
        &mut broker,
        &client,
        ControlRequest::Attach { id: 1, tab_id: 11 },
    );
    let mut output = Vec::new();
    broker.extension(json!({"kind":"revoked","protocol":1,"generation":broker.generation,"owner":command["owner"],"claim":"claim-a","reason":"canceled_by_user"}), &mut output).unwrap();
    reply(
        &mut broker,
        &command,
        json!({"claim":"claim-a","tabId":11,"targetId":"opaque-target-11"}),
    );
    assert!(matches!(
        semantic_control(&mut client).into_parts().0,
        ControlEvent::ClaimUnavailable { .. }
    ));
    assert!(matches!(
        semantic_control(&mut client).into_parts().0,
        ControlEvent::Reply {
            id: 1,
            outcome: ControlOutcome::Unknown { .. }
        }
    ));
    assert!(broker
        .bind_route(client.sender.lease.id, "claim-a")
        .is_err());
    assert!(!broker.stopped);
    let _ = request(
        &mut broker,
        &other,
        ControlRequest::Inventory {
            id: 1,
            session_only: None,
            known_tab_ids: None,
        },
    );
}

#[test]
fn global_pending_budget_does_not_consume_reserved_exact_claim_cleanup() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let mut route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    for id in 1..=64 {
        let _ = cdp(&mut broker, &client, &route, id);
    }
    let mut output = Vec::new();
    broker.cdp(
        client.sender.lease.id,
        route.sender.lease.id,
        json!({"id":65,"method":"Runtime.evaluate","params":{}}),
        &mut output,
    );
    assert!(output.is_empty());
    assert!(
        matches!(route.events.try_recv().unwrap().into_parts().0, BrokerCdpEvent::LocalRejected { id:65, code, .. } if code == "request_budget")
    );
    broker.control(
        client.sender.lease.id,
        ControlRequest::Detach {
            id: 2,
            claim: "claim-a".to_owned(),
        },
        &mut output,
    );
    assert_eq!(write(output.pop().unwrap())["method"], "detach");
}

#[test]
fn header_cleanup_receipt_is_not_a_cdp_event_or_physical_detach_ack() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let mut route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let owner = broker.clients[&client.sender.lease.id].owner.clone();
    let mut output = Vec::new();
    broker.extension(json!({"kind":"effects_cleanup","protocol":1,"generation":broker.generation,"owner":owner,"claim":"claim-a","effect":"scoped_headers","cleanupConfirmed":false,"error":"actual header cleanup fixture error"}), &mut output).unwrap();
    assert!(
        matches!(semantic_control(&mut client).into_parts().0, ControlEvent::EffectsCleanup { claim, effect, cleanup_confirmed:false, error:Some(error), wire_context:None } if claim == "claim-a" && effect == "scoped_headers" && error == "actual header cleanup fixture error")
    );
    assert!(
        route.events.try_recv().is_err(),
        "effect receipt cannot manufacture debugger detach or CDP output"
    );
    assert!(broker.claims["claim-a"].alive.load(Ordering::SeqCst));
    assert!(output.is_empty());
}

#[test]
fn structured_cleanup_diagnostics_preserve_native_cause_without_releasing_claim() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let mut route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let owner = broker.clients[&client.sender.lease.id].owner.clone();
    let mut output = Vec::new();
    let diagnostic = json!({"kind":"outcome_unknown","message":"scoped header update or cleanup was not acknowledged","details":{"pendingRemoval":true}});
    broker.extension(json!({"kind":"effects_cleanup","protocol":1,"generation":broker.generation,"owner":owner,"claim":"claim-a","effect":"scoped_headers","cleanupConfirmed":false,"error":diagnostic}), &mut output).unwrap();
    let ControlEvent::EffectsCleanup {
        claim,
        effect,
        cleanup_confirmed,
        error,
        wire_context: None,
    } = semantic_control(&mut client).into_parts().0
    else {
        panic!("structured cleanup diagnostic must remain an effect receipt");
    };
    assert_eq!(claim, "claim-a");
    assert_eq!(effect, "scoped_headers");
    assert!(!cleanup_confirmed);
    assert_eq!(
        serde_json::from_str::<Value>(error.as_deref().unwrap()).unwrap(),
        diagnostic
    );
    assert!(broker.claims["claim-a"].alive.load(Ordering::SeqCst));
    assert!(
        route.events.try_recv().is_err(),
        "cleanup diagnostic is not a detach or CDP acknowledgement"
    );
    assert!(
        output.is_empty(),
        "cleanup diagnostics must not replay or dispatch browser work"
    );

    for malformed in [
        json!({"kind":"outcome_unknown"}),
        json!({"message":"missing kind"}),
        json!({"kind":3,"message":"invalid kind"}),
        json!({"kind":"","message":"empty kind"}),
        json!(4),
    ] {
        let failure = broker.extension(json!({"kind":"effects_cleanup","protocol":1,"generation":broker.generation,"owner":owner,"claim":"claim-a","effect":"scoped_headers","cleanupConfirmed":false,"error":malformed}), &mut output);
        assert!(
            matches!(failure, Err(BrokerError::Protocol(message)) if message == "malformed connector error")
        );
        assert!(
            client.events.try_recv().is_err(),
            "malformed cleanup must not emit a fabricated receipt"
        );
        assert!(broker.claims["claim-a"].alive.load(Ordering::SeqCst));
        assert!(output.is_empty());
    }
}

#[test]
fn route_fence_between_fragments_emits_exact_cancel_and_never_the_last_part() {
    let generation = Arc::new(AtomicBool::new(true));
    let route = Arc::new(AtomicBool::new(true));
    let outbound = ExtensionOutbound {
        value: json!({"kind":"request","protocol":1,"generation":"g","owner":"owner-a","id":"1","method":"cdp","params":{"claim":"c","method":"Runtime.evaluate","params":{"expression":"x".repeat(2 * 1024 * 1024)}}}),
        generation: "g".to_owned(),
        owner: Some("owner-a".to_owned()),
        outer: Some(1),
        fences: vec![generation, route.clone()],
        dispatch: Arc::new(AtomicU8::new(QUEUED)),
        _charge: None,
        wire_context: None,
    };
    struct CancelAfterFrame {
        bytes: Vec<u8>,
        route: Arc<AtomicBool>,
        flushes: usize,
    }
    impl Write for CancelAfterFrame {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes += 1;
            if self.flushes == 1 {
                self.route.store(false, Ordering::SeqCst);
            }
            Ok(())
        }
    }
    let mut writer = CancelAfterFrame {
        bytes: Vec::new(),
        route,
        flushes: 0,
    };
    assert!(matches!(
        outbound.write_to(&mut writer).unwrap(),
        Some(WriteReport::Abandoned { outer: 1 })
    ));
    let mut reader = Cursor::new(writer.bytes);
    let first: Value = serde_json::from_slice(
        &extension_framing::read_frame(&mut reader, Direction::HostToChrome)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let cancel: Value = serde_json::from_slice(
        &extension_framing::read_frame(&mut reader, Direction::HostToChrome)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(first["kind"], "chunk");
    assert_eq!(first["part"], 0);
    assert_eq!(
        cancel,
        json!({"kind":"cancelChunk","protocol":1,"generation":"g","owner":"owner-a","logicalId":"1"})
    );
    assert!(
        extension_framing::read_frame(&mut reader, Direction::HostToChrome)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn async_actor_publishes_only_the_actual_successful_hello_identity() {
    let origin = ExtensionOrigin::from_id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    let (handle, broker, mut extension) =
        ExtensionHostBroker::channels(origin, LocalPrincipal::UnixUid(123));
    let task = tokio::spawn(broker.run());
    assert!(matches!(
        handle.identity().await,
        Err(BrokerError::NotReady)
    ));
    handle.extension_message(json!({"kind":"hello","protocol":1,"extensionId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","instanceId":"actual-instance","capabilities":{"metadata":true,"nativeWindowProof":false}})).await.unwrap();
    let bound = write(extension.recv().await.unwrap());
    let identity = handle.identity().await.unwrap();
    assert_eq!(identity.instance_id, "actual-instance");
    assert_eq!(identity.generation, bound["generation"]);
    assert_eq!(
        identity.capabilities,
        json!({"metadata":true,"nativeWindowProof":false})
    );
    handle.extension_eof("fixture EOF").await;
    task.await.unwrap();
}

#[test]
fn unknown_attach_positive_custody_is_cleanup_only_and_preserves_error_details() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let command = request(
        &mut broker,
        &client,
        ControlRequest::Attach { id: 1, tab_id: 11 },
    );
    let details = json!({"custody":{"claim":"claim-unknown","tabId":11,"targetId":"actual-target-11"},"cause":"actual post-attach observation failure"});
    let mut output = Vec::new();
    broker.extension(json!({"kind":"response","protocol":1,"generation":broker.generation,"id":command["id"],"error":{"kind":"outcome_unknown","message":"cleanup was not confirmed","details":details}}),&mut output).unwrap();
    assert!(
        matches!(semantic_control(&mut client).into_parts().0,ControlEvent::Reply{id:1,outcome:ControlOutcome::Unknown{details:Some(actual),..}} if actual==details)
    );
    assert!(broker.claims["claim-unknown"].cleanup_only);
    assert!(
        broker
            .bind_route(client.sender.lease.id, "claim-unknown")
            .is_err(),
        "positive ACK cleanup custody is not new input authority"
    );
    let detach = request(
        &mut broker,
        &client,
        ControlRequest::Detach {
            id: 2,
            claim: "claim-unknown".to_owned(),
        },
    );
    assert_eq!(detach["method"], "detach");
    assert_eq!(detach["params"]["claim"], "claim-unknown");
}

#[tokio::test]
async fn saturated_route_retains_ack_until_reader_capacity_returns() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let mut route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let mut output = Vec::new();
    for sequence in 0..EVENT_CAPACITY {
        broker.emit_cdp(
            route.sender.lease.id,
            BrokerCdpEvent::ChromeMessage(
                json!({"method":"Runtime.fixture","params":{"sequence":sequence}}),
            ),
            &mut output,
        );
    }
    let command = cdp(&mut broker, &client, &route, 1);
    reply(
        &mut broker,
        &command,
        json!({"result":{"ack":"exact Chrome reply"}}),
    );
    assert_eq!(
        broker.deliveries.len(),
        1,
        "full internal queue must retain matched ACK"
    );
    assert_eq!(
        broker.pending.len(),
        0,
        "the delivery owns the matched completion now"
    );
    assert!(
        matches!(route.events.recv().await.unwrap().into_parts().0,BrokerCdpEvent::ChromeMessage(value) if value["params"]["sequence"]==0)
    );
    broker.flush_deliveries();
    for _ in 1..EVENT_CAPACITY {
        let _ = route.events.recv().await.unwrap();
    }
    assert!(
        matches!(route.events.recv().await.unwrap().into_parts().0,BrokerCdpEvent::ChromeMessage(value) if value["id"]==1 && value["result"]["ack"]=="exact Chrome reply")
    );
    assert!(client.sender.lease.alive.load(Ordering::SeqCst));
    assert!(output.is_empty());
}

#[tokio::test]
async fn closed_cdp_consumer_moves_actual_ack_to_owner_custody_receipt() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let route_id = route.sender.lease.id;
    let command = cdp(&mut broker, &client, &route, 1);
    drop(route.events);
    reply(&mut broker, &command, json!({"result":{"actual":"ack"}}));
    broker.flush_deliveries();
    assert!(
        matches!(client.events.recv().await.unwrap().into_parts().0,ControlEvent::OrphanCdpCompletion{route,claim,id:1,event:BrokerCdpEvent::ChromeMessage(value),..} if route==route_id.0 && claim=="claim-a" && value["result"]["actual"]=="ack")
    );
    assert!(
        broker.claims["claim-a"].alive.load(Ordering::SeqCst),
        "reader loss is not physical detach authority"
    );
}

#[tokio::test]
async fn full_control_queue_backpressures_without_closing_owner_or_siblings() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let _route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let mut output = Vec::new();
    for id in 1..=EVENT_CAPACITY {
        broker.emit_control(
            client.sender.lease.id,
            ControlEvent::Reply {
                id: id as u64,
                outcome: ControlOutcome::Result(json!({"n":id})),
            },
            &mut output,
        );
    }
    broker.emit_control(
        client.sender.lease.id,
        ControlEvent::EffectsCleanup {
            claim: "claim-a".to_owned(),
            effect: "scoped_headers".to_owned(),
            cleanup_confirmed: false,
            error: Some("actual fixture cleanup error".to_owned()),
            wire_context: None,
        },
        &mut output,
    );
    assert_eq!(broker.deliveries.len(), 1);
    assert!(client.sender.lease.alive.load(Ordering::SeqCst));
    assert!(!broker.clients[&client.sender.lease.id].closing);
    assert!(
        output.is_empty(),
        "internal pressure cannot issue closeOwner"
    );
    let _ = client.events.recv().await.unwrap();
    broker.flush_deliveries();
    for _ in 1..EVENT_CAPACITY {
        let _ = client.events.recv().await.unwrap();
    }
    assert!(matches!(
        client.events.recv().await.unwrap().into_parts().0,
        ControlEvent::EffectsCleanup {
            cleanup_confirmed: false,
            ..
        }
    ));
    assert!(broker.claims["claim-a"].alive.load(Ordering::SeqCst));
}

#[test]
fn closed_control_receiver_retains_custody_without_fabricating_ipc_eof() {
    let mut broker = fixture();
    let client = admit(&mut broker);
    let client_id = client.sender.lease.id;
    drop(client.events);
    let mut output = Vec::new();
    broker.emit_control(
        client_id,
        ControlEvent::Reply {
            id: 1,
            outcome: ControlOutcome::Result(json!({"actual":"completion"})),
        },
        &mut output,
    );
    assert!(broker.clients[&client_id].delivery_blocked);
    assert_eq!(broker.clients[&client_id].undelivered.len(), 1);
    assert!(!broker.clients[&client_id].closing);
    assert!(client.sender.lease.alive.load(Ordering::SeqCst));
    assert!(output.is_empty());
}

#[tokio::test]
async fn immutable_wire_context_is_attached_per_request_and_serialized_at_own_envelope() {
    let origin = ExtensionOrigin::from_id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    let (handle, broker, mut extension) =
        ExtensionHostBroker::channels(origin, LocalPrincipal::UnixUid(123));
    let task = tokio::spawn(broker.run());
    handle.extension_message(json!({"kind":"hello","protocol":1,"extensionId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","instanceId":"actual-instance","capabilities":{"metadata":true}})).await.unwrap();
    let _ = write(extension.recv().await.unwrap());
    let client = handle
        .admit_peer(CheckedLocalPeer::from_checked_principal(
            LocalPrincipal::UnixUid(123),
        ))
        .await
        .unwrap();
    let first = ExtensionWireContext::new("actual-host-session", "trusted-turn-one").unwrap();
    let second = ExtensionWireContext::new("actual-host-session", "trusted-turn-two").unwrap();
    client
        .sender
        .control_with_context(
            ControlRequest::Inventory {
                id: 1,
                session_only: None,
                known_tab_ids: None,
            },
            Some(first.clone()),
        )
        .await
        .unwrap();
    client
        .sender
        .control_with_context(
            ControlRequest::Inventory {
                id: 2,
                session_only: None,
                known_tab_ids: None,
            },
            Some(second.clone()),
        )
        .await
        .unwrap();
    let first_out = extension.recv().await.unwrap();
    let second_out = extension.recv().await.unwrap();
    assert_eq!(first_out.wire_context(), Some(&first));
    assert_eq!(second_out.wire_context(), Some(&second));
    let first_frame = write(first_out);
    let second_frame = write(second_out);
    assert_eq!(first_frame["wireContext"], json!(first));
    assert_eq!(second_frame["wireContext"], json!(second));
    assert!(first_frame["params"].get("wireContext").is_none());
    assert!(second_frame["params"].get("wireContext").is_none());
    handle.extension_eof("fixture EOF").await;
    task.await.unwrap();
}

#[test]
fn orphan_cdp_ack_uses_originating_context_instead_of_arrival_context() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let original = ExtensionWireContext::new("actual-host-session", "old-trusted-turn").unwrap();
    broker.input_context = Some(original.clone());
    let command = cdp(&mut broker, &client, &route, 1);
    broker.input_context = None;
    let mut output = Vec::new();
    broker.close_route(
        route.sender.lease.id,
        "fixture reader cancellation",
        &mut output,
    );
    broker.input_context =
        Some(ExtensionWireContext::new("actual-host-session", "different-current-turn").unwrap());
    reply(&mut broker, &command, json!({"result":{"actual":"ack"}}));
    assert!(
        matches!(semantic_control(&mut client).into_parts().0,ControlEvent::OrphanCdpCompletion{wire_context:Some(context),..} if context==original)
    );
    assert!(
        output.is_empty(),
        "orphan receipt never becomes detach or another input"
    );
}

#[test]
fn download_metadata_has_no_inferred_owner_and_shares_one_immutable_payload() {
    let mut broker = fixture();
    let mut first = admit(&mut broker);
    let mut second = admit(&mut broker);
    let mut output = Vec::new();
    broker.extension(json!({"kind":"download_changed","protocol":1,"generation":broker.generation,"download":{"id":"0","filename":"","url":"https://fixture.invalid/actual-final","status":"started"}}),&mut output).unwrap();
    let a = semantic_control(&mut first).into_parts().0;
    let b = semantic_control(&mut second).into_parts().0;
    match (&a, &b) {
        (
            ControlEvent::DownloadChanged { download: a },
            ControlEvent::DownloadChanged { download: b },
        ) => {
            assert!(Arc::ptr_eq(&a.0, &b.0));
            assert_eq!(a.0.filename, "");
        }
        _ => panic!("actual download metadata did not reach both admitted views"),
    }
    let encoded = serde_json::to_value(a).unwrap();
    assert_eq!(encoded["kind"], "downloadChanged");
    assert!(encoded["data"].get("owner").is_none());
    assert!(encoded["data"].get("claim").is_none());
    assert!(
        broker.claims.is_empty(),
        "metadata must not create attachment or approval authority"
    );
    assert!(output.is_empty());
}

#[test]
fn session_header_controls_are_session_scoped_and_preserve_matched_facts() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let context = ExtensionWireContext::new("trusted-session", "trusted-turn").unwrap();
    broker.input_context = Some(context.clone());
    let set = request(
        &mut broker,
        &client,
        ControlRequest::SetSessionHeaders {
            id: 1,
            headers: vec![ScopedHeader {
                name: "X-Fixture".to_owned(),
                value: "actual-value".to_owned(),
            }],
        },
    );
    assert_eq!(set["method"], "setSessionHeaders");
    assert_eq!(
        set["params"],
        json!({"headers":[{"name":"X-Fixture","value":"actual-value"}]})
    );
    assert!(set["params"].get("claim").is_none());
    let proof = json!({
        "hostSessionId":"trusted-session", "hostTurnId":"trusted-turn",
        "generation":broker.generation, "owner":set["owner"],
        "stateConfirmed":true,"active":true,"cleanupConfirmed":false
    });
    reply(&mut broker, &set, proof.clone());
    match semantic_control(&mut client).into_parts().0 {
        ControlEvent::Reply {
            id: 1,
            outcome: ControlOutcome::Result(actual),
        } => assert_eq!(actual, proof),
        other => panic!("session header facts changed: {other:?}"),
    }
    let clear = request(
        &mut broker,
        &client,
        ControlRequest::ClearSessionHeaders { id: 2 },
    );
    assert_eq!(clear["method"], "clearSessionHeaders");
    assert_eq!(clear["params"], json!({}));
    assert_eq!(
        broker.pending[&clear["id"].as_str().unwrap().parse::<u64>().unwrap()].wire_context,
        Some(context)
    );
}

#[test]
fn cursor_control_cannot_use_foreign_cleanup_only_or_nonfinite_claim_requests() {
    let mut broker = fixture();
    let mut owner = admit(&mut broker);
    let mut other = admit(&mut broker);
    let route = attach(&mut broker, &mut owner, 1, 11, "claim-a");
    let cursor = |id, x| ControlRequest::MoveMouse {
        id,
        claim: "claim-a".to_owned(),
        x,
        y: 0.0,
        wait_for_arrival: Some(false),
    };
    let mut output = Vec::new();
    broker.control(other.sender.lease.id, cursor(1, 12.5), &mut output);
    assert!(output.is_empty());
    assert!(matches!(semantic_control(&mut other).into_parts().0,
        ControlEvent::Reply { outcome: ControlOutcome::NotDispatched { kind, .. }, .. } if kind == "claim_unavailable"));
    broker.control(owner.sender.lease.id, cursor(2, f64::NAN), &mut output);
    assert!(output.is_empty());
    assert!(matches!(semantic_control(&mut owner).into_parts().0,
        ControlEvent::Reply { outcome: ControlOutcome::NotDispatched { kind, .. }, .. } if kind == "invalid_request"));
    broker.claims.get_mut("claim-a").unwrap().cleanup_only = true;
    broker.control(owner.sender.lease.id, cursor(3, 12.5), &mut output);
    assert!(output.is_empty());
    assert!(matches!(semantic_control(&mut owner).into_parts().0,
        ControlEvent::Reply { outcome: ControlOutcome::NotDispatched { kind, .. }, .. } if kind == "claim_unavailable"));
    assert!(
        route.sender.lease.alive.load(Ordering::SeqCst),
        "local refusal does not retire an existing route"
    );
}

#[test]
fn cursor_control_uses_exact_optional_wire_field_and_ack_is_not_cleanup_proof() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let _route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let cursor = request(
        &mut broker,
        &client,
        ControlRequest::MoveMouse {
            id: 2,
            claim: "claim-a".to_owned(),
            x: -1.25,
            y: 0.0,
            wait_for_arrival: Some(false),
        },
    );
    assert_eq!(cursor["method"], "moveMouse");
    assert_eq!(
        cursor["params"],
        json!({"claim":"claim-a","x":-1.25,"y":0.0,"waitForArrival":false})
    );
    let ack = json!({"acknowledged":true});
    reply(&mut broker, &cursor, ack.clone());
    assert!(matches!(semantic_control(&mut client).into_parts().0,
        ControlEvent::Reply { id: 2, outcome: ControlOutcome::Result(actual) } if actual == ack));
    assert!(broker.claims["claim-a"].alive.load(Ordering::SeqCst));
    let encoded = serde_json::to_value(ControlRequest::MoveMouse {
        id: 3,
        claim: "claim-a".to_owned(),
        x: 1.0,
        y: 2.0,
        wait_for_arrival: None,
    })
    .unwrap();
    assert_eq!(encoded["method"], "moveMouse");
    assert!(encoded.get("waitForArrival").is_none());
    assert!(serde_json::from_value::<ControlRequest>(
        json!({"method":"setSessionHeaders","id":4,"headers":[],"owner":"forged"})
    )
    .is_err());
}

#[test]
fn adapter_guard_refuses_only_before_first_write_and_reports_semantic_write_once() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let mut output = Vec::new();
    broker.control(
        client.sender.lease.id,
        ControlRequest::Inventory {
            id: 1,
            session_only: None,
            known_tab_ids: None,
        },
        &mut output,
    );
    let first = output.pop().unwrap().into_adapter_request();
    let first_guard = first.guard.clone();
    assert_eq!(first.semantic_id.as_deref(), Some("1"));
    let report = first_guard
        .reject_before_write("fixture_refusal".to_owned(), "not sent".to_owned())
        .expect("the original guard rejected before any frame");
    assert!(matches!(
        report,
        WriteReport::LocalRejected { outer: 1, .. }
    ));
    broker.written(report, &mut output);
    assert!(matches!(semantic_control(&mut client).into_parts().0,
        ControlEvent::Reply { id: 1, outcome: ControlOutcome::NotDispatched { kind, message, details: None } }
            if kind == "fixture_refusal" && message == "not sent"));
    assert!(!broker.pending.contains_key(&1));
    assert!(!first_guard.start_write());
    assert!(!first_guard.was_started());
    assert!(first_guard
        .reject_before_write("repeat".to_owned(), "not sent".to_owned())
        .is_none());
    assert!(first_guard.written_report().is_none());

    broker.control(
        client.sender.lease.id,
        ControlRequest::Inventory {
            id: 2,
            session_only: None,
            known_tab_ids: None,
        },
        &mut output,
    );
    let second = output.pop().unwrap().into_adapter_request();
    let writer_guard = second.guard.clone();
    assert!(writer_guard.start_write());
    assert!(second
        .guard
        .reject_before_write(
            "false_refusal".to_owned(),
            "phase already started".to_owned()
        )
        .is_none());
    writer_guard.frame_written();
    assert!(matches!(
        writer_guard.written_report(),
        Some(WriteReport::Written { outer: 2 })
    ));
    assert!(
        second.guard.written_report().is_none(),
        "later extension phases do not create a second semantic dispatch ACK"
    );
    writer_guard
        .fences
        .last()
        .unwrap()
        .store(false, Ordering::SeqCst);
    assert!(
        !second.guard.start_write(),
        "followup extension phase keeps the exact original owner fence"
    );
    assert!(
        second.guard.was_started(),
        "canceled followup remains outcome unknown rather than predispatch refusal"
    );
    assert!(second
        .guard
        .reject_before_write("false_refusal".to_owned(), "phase already sent".to_owned())
        .is_none());
}

fn queued_control_with_context(
    broker: &mut ExtensionHostBroker,
    client: &ClientConnection,
    request: ControlRequest,
    context: Option<&ExtensionWireContext>,
) -> ExtensionAdapterRequest {
    broker.input_context = context.cloned();
    let mut output = Vec::new();
    broker.control(client.sender.lease.id, request, &mut output);
    broker.input_context = None;
    assert_eq!(output.len(), 1);
    output.pop().unwrap().into_adapter_request()
}

#[test]
fn turn_finish_fences_only_existing_same_client_session_turn_work_and_keeps_cleanup_live() {
    let mut broker = fixture();
    let first = admit(&mut broker);
    let second = admit(&mut broker);
    let scope = ExtensionWireContext::new("trusted-session", "trusted-turn").unwrap();
    let other_turn = ExtensionWireContext::new("trusted-session", "other-turn").unwrap();
    let other_session = ExtensionWireContext::new("other-session", "trusted-turn").unwrap();
    let same = queued_control_with_context(
        &mut broker,
        &first,
        ControlRequest::Inventory {
            id: 1,
            session_only: None,
            known_tab_ids: None,
        },
        Some(&scope),
    );
    let sibling_turn = queued_control_with_context(
        &mut broker,
        &first,
        ControlRequest::Inventory {
            id: 2,
            session_only: None,
            known_tab_ids: None,
        },
        Some(&other_turn),
    );
    let sibling_session = queued_control_with_context(
        &mut broker,
        &first,
        ControlRequest::Inventory {
            id: 3,
            session_only: None,
            known_tab_ids: None,
        },
        Some(&other_session),
    );
    let sibling_client = queued_control_with_context(
        &mut broker,
        &second,
        ControlRequest::Inventory {
            id: 1,
            session_only: None,
            known_tab_ids: None,
        },
        Some(&scope),
    );
    let no_context = queued_control_with_context(
        &mut broker,
        &first,
        ControlRequest::Inventory {
            id: 4,
            session_only: None,
            known_tab_ids: None,
        },
        None,
    );
    let cleanup = queued_control_with_context(
        &mut broker,
        &first,
        ControlRequest::StopCreatedTab {
            id: 5,
            creation: "fixture-opaque-creation".to_owned(),
            tab_id: None,
        },
        Some(&scope),
    );
    let finish = queued_control_with_context(
        &mut broker,
        &first,
        ControlRequest::FinishTurn { id: 6, keep: None },
        Some(&scope),
    );
    assert!(!same.guard.is_live());
    assert!(
        !same.guard.start_write(),
        "unsent old work cannot start a extension phase after Finish admission"
    );
    assert!(!same.guard.was_started());
    assert!(sibling_turn.guard.is_live());
    assert!(sibling_session.guard.is_live());
    assert!(sibling_client.guard.is_live());
    assert!(no_context.guard.is_live());
    assert!(cleanup.guard.is_live());
    assert!(
        finish.guard.is_live(),
        "Finish's own cleanup request bypasses its scope gate"
    );
    assert_eq!(
        broker.pending.len(),
        7,
        "execution fencing alone consumes no ACK/custody correlations"
    );
    assert!(first.sender.lease.alive.load(Ordering::SeqCst));
    assert!(second.sender.lease.alive.load(Ordering::SeqCst));
}

#[test]
fn scope_fenced_written_attach_retains_exact_late_cleanup_only_custody() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let scope = ExtensionWireContext::new("trusted-session", "trusted-turn").unwrap();
    let attach = queued_control_with_context(
        &mut broker,
        &client,
        ControlRequest::Attach { id: 1, tab_id: 11 },
        Some(&scope),
    );
    let command = attach.message.event().clone();
    assert!(attach.guard.start_write());
    attach.guard.frame_written();
    let finish = queued_control_with_context(
        &mut broker,
        &client,
        ControlRequest::FinishTurn { id: 2, keep: None },
        Some(&scope),
    );
    assert!(!attach.guard.is_live());
    assert!(attach.guard.was_started());
    assert!(attach
        .guard
        .reject_before_write("false_refusal".to_owned(), "already sent".to_owned())
        .is_none());
    assert!(finish.guard.is_live());
    assert_eq!(broker.pending.len(), 2);
    let mut output = Vec::new();
    broker.extension(json!({"kind":"response","protocol":1,"generation":broker.generation,"id":command["id"],
        "error":{"kind":"outcome_unknown","message":"follow-up phase fenced after actual attach ACK",
            "details":{"custody":{"claim":"late-custody","tabId":11,"targetId":"actual-target"}}}}), &mut output).unwrap();
    assert!(matches!(semantic_control(&mut client).into_parts().0,
        ControlEvent::Reply { id:1,outcome:ControlOutcome::Unknown { details:Some(details), .. }} if details["custody"]["claim"]=="late-custody"));
    assert!(broker.claims["late-custody"].cleanup_only);
    assert!(matches!(
        broker.bind_route(client.sender.lease.id, "late-custody"),
        Err(BrokerError::ClaimUnavailable)
    ));
    let detach = request(
        &mut broker,
        &client,
        ControlRequest::Detach {
            id: 3,
            claim: "late-custody".to_owned(),
        },
    );
    assert_eq!(detach["method"], "detach");
    assert_eq!(
        broker.pending.len(),
        2,
        "actual late custody replaces only its original attach correlation"
    );
}

fn fenced_snapshot(
    broker: &mut ExtensionHostBroker,
    client: &mut ClientConnection,
    id: u64,
    claim: &str,
) -> Value {
    let mut output = Vec::new();
    broker.control(
        client.sender.lease.id,
        ControlRequest::FenceCdp {
            id,
            claim: claim.to_owned(),
        },
        &mut output,
    );
    assert!(
        output.is_empty(),
        "a local fence must not dispatch a extension RPC"
    );
    match semantic_control(client).into_parts().0 {
        ControlEvent::Reply {
            id: actual,
            outcome: ControlOutcome::Result(snapshot),
        } if actual == id => snapshot,
        event => panic!("expected exact local fence reply {id}, got {event:?}"),
    }
}

fn expect_cdp_progress(client: &mut ClientConnection, claim: &str) {
    assert!(
        matches!(semantic_control(client).into_parts().0, ControlEvent::ClaimCdpProgress { claim: actual } if actual == claim)
    );
}

#[test]
fn exact_claim_fence_counts_queued_and_written_work_until_actual_terminal_receipts() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let first = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let second = attach(&mut broker, &mut client, 2, 22, "claim-b");
    let written = cdp(&mut broker, &client, &first, 1);
    let sibling = cdp(&mut broker, &client, &second, 1);
    let mut output = Vec::new();
    broker.cdp(
        client.sender.lease.id,
        first.sender.lease.id,
        json!({"id":2,"method":"Input.dispatchMouseEvent","params":{"type":"mousePressed"}}),
        &mut output,
    );
    let queued = output.pop().unwrap();
    let queued_outer = queued.outer.unwrap();
    let snapshot = fenced_snapshot(&mut broker, &mut client, 3, "claim-a");
    assert_eq!(snapshot["claim"], "claim-a");
    assert_eq!(snapshot["generation"], broker.generation);
    assert_eq!(snapshot["fenced"], true);
    assert_eq!(snapshot["pending"].as_array().unwrap().len(), 2);
    assert_eq!(snapshot["pending"][0]["id"], 1);
    assert_eq!(snapshot["pending"][1]["id"], 2);
    assert_eq!(snapshot["pending"][0]["route"], first.sender.lease.id.0);
    assert!(snapshot["pending"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["unknownReason"].is_null()));
    assert!(broker.owns_active_claim(client.sender.lease.id, "claim-b"));
    assert!(broker
        .pending
        .contains_key(&canonical_id(sibling["id"].as_str()).unwrap()));
    assert!(matches!(
        broker.bind_route(client.sender.lease.id, "claim-a"),
        Err(BrokerError::ClaimUnavailable)
    ));
    broker.cdp(
        client.sender.lease.id,
        first.sender.lease.id,
        json!({"id":3,"method":"Input.dispatchMouseEvent","params":{}}),
        &mut output,
    );
    assert!(
        output.is_empty(),
        "the exact claim is fenced before its snapshot can report empty"
    );
    assert_eq!(
        broker.pending[&queued_outer]
            .dispatch
            .load(Ordering::SeqCst),
        QUEUED
    );
    let mut bytes = Vec::new();
    let skipped = queued.write_to(&mut bytes).unwrap().unwrap();
    assert!(bytes.is_empty());
    assert!(matches!(skipped, WriteReport::Skipped { outer } if outer == queued_outer));
    broker.written(skipped, &mut output);
    assert!(
        matches!(semantic_control(&mut client).into_parts().0, ControlEvent::OrphanCdpCompletion { id:2,event:BrokerCdpEvent::LocalRejected { code, .. }, .. } if code == "not_dispatched")
    );
    expect_cdp_progress(&mut client, "claim-a");
    let waiting = fenced_snapshot(&mut broker, &mut client, 4, "claim-a");
    assert_eq!(waiting["pending"].as_array().unwrap().len(), 1);
    assert_eq!(waiting["pending"][0]["id"], 1);
    reply(&mut broker, &written, json!({"result":{"actual":"ack"}}));
    assert!(
        matches!(semantic_control(&mut client).into_parts().0, ControlEvent::OrphanCdpCompletion { id:1,event:BrokerCdpEvent::ChromeMessage(value), .. } if value["result"]["actual"] == "ack")
    );
    expect_cdp_progress(&mut client, "claim-a");
    let drained = fenced_snapshot(&mut broker, &mut client, 5, "claim-a");
    assert!(drained["pending"].as_array().unwrap().is_empty());
    assert!(
        broker
            .pending
            .contains_key(&canonical_id(sibling["id"].as_str()).unwrap()),
        "a sibling claim cannot enter or block this drain"
    );
    assert!(output.is_empty());
}

#[test]
fn adapted_unknown_cdp_cannot_be_cleared_by_adapted_duplicate_detach_or_eof() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let command = cdp(&mut broker, &client, &route, 1);
    fenced_snapshot(&mut broker, &mut client, 2, "claim-a");
    let mut output = Vec::new();
    broker.extension_with_provenance(json!({"kind":"response","protocol":1,"generation":broker.generation,"id":command["id"],"error":{"kind":"outcome_unknown","message":"fixture ACK unavailable","details":{"remoteAcknowledged":true}}}), ExtensionReplyProvenance::Adapted, &mut output).unwrap();
    assert!(matches!(
        semantic_control(&mut client).into_parts().0,
        ControlEvent::OrphanCdpCompletion {
            event: BrokerCdpEvent::TransportFailure(reason),
            ..
        } if reason == "extension claim request ended: outcome_unknown: fixture ACK unavailable"
    ));
    expect_cdp_progress(&mut client, "claim-a");
    let snapshot = fenced_snapshot(&mut broker, &mut client, 3, "claim-a");
    assert_eq!(snapshot["pending"].as_array().unwrap().len(), 1);
    assert_eq!(snapshot["pending"][0]["unknownReason"], UNKNOWN_CDP_REASON);
    broker.extension_with_provenance(json!({"kind":"response","protocol":1,"generation":broker.generation,"id":command["id"],"result":{"result":{"late":true}}}), ExtensionReplyProvenance::Adapted, &mut output).unwrap();
    assert!(
        client.events.try_recv().is_err(),
        "a duplicate/late normalized reply cannot settle unknown custody"
    );
    let detach = request(
        &mut broker,
        &client,
        ControlRequest::Detach {
            id: 4,
            claim: "claim-a".to_owned(),
        },
    );
    reply(
        &mut broker,
        &detach,
        json!({"detached":true,"proof":"detach_ack"}),
    );
    assert!(matches!(
        semantic_control(&mut client).into_parts().0,
        ControlEvent::Reply {
            id: 4,
            outcome: ControlOutcome::Result(_)
        }
    ));
    let still_unknown = fenced_snapshot(&mut broker, &mut client, 5, "claim-a");
    assert_eq!(
        still_unknown["pending"], snapshot["pending"],
        "physical detach is not a CDP terminal receipt"
    );
    broker.end_generation("fixture transport EOF");
    assert!(matches!(
        semantic_control(&mut client).into_parts().0,
        ControlEvent::GenerationClosed { .. }
    ));
    broker.control(
        client.sender.lease.id,
        ControlRequest::FenceCdp {
            id: 6,
            claim: "claim-a".to_owned(),
        },
        &mut output,
    );
    assert!(matches!(
        semantic_control(&mut client).into_parts().0,
        ControlEvent::Reply {
            id: 6,
            outcome: ControlOutcome::Unknown { .. }
        }
    ));
    assert!(
        output.is_empty(),
        "EOF cannot turn clearing the pending map into a drain proof"
    );
}

#[test]
fn an_already_started_write_cannot_become_known_unsent_from_a_skipped_report() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let mut output = Vec::new();
    broker.cdp(
        client.sender.lease.id,
        route.sender.lease.id,
        json!({"id":1,"method":"Input.insertText","params":{"text":"once"}}),
        &mut output,
    );
    let request = output.pop().unwrap().into_adapter_request();
    let outer = request
        .semantic_id
        .as_deref()
        .and_then(|id| canonical_id(Some(id)))
        .unwrap();
    assert!(request.guard.start_write());
    fenced_snapshot(&mut broker, &mut client, 2, "claim-a");
    broker.written(WriteReport::Skipped { outer }, &mut output);
    assert!(matches!(
        semantic_control(&mut client).into_parts().0,
        ControlEvent::OrphanCdpCompletion {
            event: BrokerCdpEvent::TransportFailure(_),
            ..
        }
    ));
    expect_cdp_progress(&mut client, "claim-a");
    let snapshot = fenced_snapshot(&mut broker, &mut client, 3, "claim-a");
    assert_eq!(snapshot["pending"].as_array().unwrap().len(), 1);
    assert!(snapshot["pending"][0]["unknownReason"].is_string());
    broker.written(WriteReport::Abandoned { outer }, &mut output);
    assert!(
        client.events.try_recv().is_err(),
        "repeated writer reports cannot invent another completion"
    );
    assert!(output.is_empty());
}

#[test]
fn a_foreign_claim_fence_is_unknown_and_leaves_the_other_owner_live() {
    let mut broker = fixture();
    let mut owner = admit(&mut broker);
    let mut peer = admit(&mut broker);
    let _route = attach(&mut broker, &mut owner, 1, 11, "claim-a");
    let mut output = Vec::new();
    broker.control(
        peer.sender.lease.id,
        ControlRequest::FenceCdp {
            id: 1,
            claim: "claim-a".to_owned(),
        },
        &mut output,
    );
    assert!(matches!(
        semantic_control(&mut peer).into_parts().0,
        ControlEvent::Reply {
            id: 1,
            outcome: ControlOutcome::Unknown { .. }
        }
    ));
    assert!(broker.owns_active_claim(owner.sender.lease.id, "claim-a"));
    assert!(output.is_empty());
}

#[test]
fn cdp_fence_keeps_exact_scoped_header_and_physical_cleanup_admissible() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let _route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let snapshot = fenced_snapshot(&mut broker, &mut client, 2, "claim-a");
    assert!(snapshot["pending"].as_array().unwrap().is_empty());
    assert!(matches!(
        broker.bind_route(client.sender.lease.id, "claim-a"),
        Err(BrokerError::ClaimUnavailable)
    ));
    let clear = request(
        &mut broker,
        &client,
        ControlRequest::ClearScopedHeaders {
            id: 3,
            claim: "claim-a".to_owned(),
        },
    );
    assert_eq!(clear["method"], "clearScopedHeaders");
    assert_eq!(clear["params"]["claim"], "claim-a");
    reply(
        &mut broker,
        &clear,
        json!({"cleanupConfirmed":true,"active":false,"stateConfirmed":true}),
    );
    assert!(matches!(
        semantic_control(&mut client).into_parts().0,
        ControlEvent::Reply {
            id: 3,
            outcome: ControlOutcome::Result(_)
        }
    ));
    let detach = request(
        &mut broker,
        &client,
        ControlRequest::Detach {
            id: 4,
            claim: "claim-a".to_owned(),
        },
    );
    assert_eq!(detach["method"], "detach");
    assert_eq!(detach["params"]["claim"], "claim-a");
}

#[test]
fn a_revoked_claim_keeps_pending_cdp_observable_without_readmitting_execution() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let command = cdp(&mut broker, &client, &route, 1);
    let owner = broker.clients[&client.sender.lease.id].owner.clone();
    let mut output = Vec::new();
    broker.extension(json!({"kind":"revoked","protocol":1,"generation":broker.generation,"owner":owner,"claim":"claim-a","reason":"actual debugger detach fixture"}), &mut output).unwrap();
    assert!(
        matches!(semantic_control(&mut client).into_parts().0, ControlEvent::ClaimUnavailable { claim, .. } if claim == "claim-a")
    );
    assert!(!broker.owns_active_claim(client.sender.lease.id, "claim-a"));
    assert!(matches!(
        broker.bind_route(client.sender.lease.id, "claim-a"),
        Err(BrokerError::ClaimUnavailable)
    ));
    let snapshot = fenced_snapshot(&mut broker, &mut client, 2, "claim-a");
    assert_eq!(snapshot["pending"].as_array().unwrap().len(), 1);
    reply(&mut broker, &command, json!({"result":{"terminal":true}}));
    assert!(matches!(
        semantic_control(&mut client).into_parts().0,
        ControlEvent::OrphanCdpCompletion {
            event: BrokerCdpEvent::ChromeMessage(_),
            ..
        }
    ));
    expect_cdp_progress(&mut client, "claim-a");
    let drained = fenced_snapshot(&mut broker, &mut client, 3, "claim-a");
    assert!(drained["pending"].as_array().unwrap().is_empty());
    assert!(matches!(
        broker.bind_route(client.sender.lease.id, "claim-a"),
        Err(BrokerError::ClaimUnavailable)
    ));
}

#[test]
fn a_variable_claim_snapshot_retains_its_own_queue_byte_charge() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    broker.input_context =
        Some(ExtensionWireContext::new("actual-session-fixture", "actual-turn-fixture").unwrap());
    let _command = cdp(&mut broker, &client, &route, 1);
    broker.input_context = None;
    let before = broker.budget.available_bytes();
    let mut output = Vec::new();
    broker.control(
        client.sender.lease.id,
        ControlRequest::FenceCdp {
            id: 2,
            claim: "claim-a".to_owned(),
        },
        &mut output,
    );
    let (event, charge) = semantic_control(&mut client).into_parts();
    let bytes = charge
        .as_ref()
        .expect("variable snapshots require an independent queue charge")
        .bytes();
    assert_eq!(bytes, serde_json::to_vec(&event).unwrap().len());
    assert_eq!(broker.budget.available_bytes(), before - bytes);
    let ControlEvent::Reply {
        outcome: ControlOutcome::Result(snapshot),
        ..
    } = &event
    else {
        panic!("expected charged snapshot result")
    };
    assert_eq!(
        snapshot["pending"][0]["wireContext"]["hostTurnId"],
        "actual-turn-fixture"
    );
    drop(event);
    assert_eq!(
        broker.budget.available_bytes(),
        before - bytes,
        "writer still owns the charge"
    );
    drop(charge);
    assert_eq!(broker.budget.available_bytes(), before);
    assert!(output.is_empty());
}

#[tokio::test]
async fn snapshot_and_unconfirmed_budget_exhaustion_close_only_own_peer_without_proof() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let other = admit(&mut broker);
    let route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let _command = cdp(&mut broker, &client, &route, 1);
    // Use the real shared budget; no smaller test-only production constructor.
    let large = "x".repeat(64 * 1024 * 1024 - 2);
    let first = broker.budget.charge(&large).await.unwrap();
    let second = broker.budget.charge(&large).await.unwrap();
    assert_eq!(broker.budget.available_bytes(), 0);
    let mut output = Vec::new();
    broker.control(
        client.sender.lease.id,
        ControlRequest::FenceCdp {
            id: 2,
            claim: "claim-a".to_owned(),
        },
        &mut output,
    );
    assert!(matches!(client.events.try_recv().unwrap().into_parts().0,
        ControlEvent::GenerationClosed { reason } if reason == "owner CDP delivery budget exhausted; invocation and effect settlement remain unknown"));
    assert!(
        matches!(semantic_control(&mut client).into_parts().0, ControlEvent::Reply { id:2,outcome:ControlOutcome::Unknown { reason, .. }} if reason == "claim CDP snapshot could not enter the bounded delivery queue")
    );
    assert!(!broker.clients[&client.sender.lease.id]
        .alive
        .load(Ordering::SeqCst));
    assert!(broker.clients[&other.sender.lease.id]
        .alive
        .load(Ordering::SeqCst));
    assert!(broker.claims["claim-a"].cdp_fenced);
    assert!(broker.pending.values().any(
        |pending| matches!(&pending.kind, PendingKind::Cdp { claim, .. } if claim == "claim-a")
    ));
    assert!(
        matches!(
            client
                .sender
                .control_with_context(
                    ControlRequest::Inventory {
                        id: 3,
                        session_only: None,
                        known_tab_ids: None
                    },
                    None
                )
                .await,
            Err(BrokerError::Closed)
        ),
        "closing the lease must stop new wire admission"
    );
    assert!(
        output.is_empty(),
        "resource failure cannot recursively invent a extension cleanup effect"
    );
    assert!(!broker
        .pending
        .values()
        .any(|pending| matches!(pending.kind, PendingKind::CloseOwner)));
    broker.end_generation("actual later extension EOF");
    assert!(broker.stopped);
    assert!(matches!(
        client.events.try_recv().unwrap().into_parts().0,
        ControlEvent::GenerationClosed { .. }
    ));
    assert!(
        client.events.try_recv().is_err(),
        "saturated EOF metadata must not recurse or emit an unbounded tail"
    );
    drop(first);
    drop(second);
}

#[test]
fn actual_native_reply_can_end_raw_wait_while_its_effect_remains_unknown() {
    use super::super::extension_wire::MatchedExtensionReply;

    for matched in [false, true] {
        let mut broker = fixture();
        let mut client = admit(&mut broker);
        let route = attach(&mut broker, &mut client, 1, 11, "claim-a");
        let context = ExtensionWireContext::new("actual-session", "actual-turn").unwrap();
        broker.input_context = Some(context.clone());
        let command = cdp(&mut broker, &client, &route, 1);
        broker.input_context = None;
        fenced_snapshot(&mut broker, &mut client, 2, "claim-a");
        let provenance = if matched {
            ExtensionReplyProvenance::Matched(MatchedExtensionReply::from_matched_rpc(
                broker.generation.clone(),
                broker.clients[&client.sender.lease.id].owner.clone(),
                command["id"].as_str().unwrap().to_owned(),
                Some(context),
            ))
        } else {
            ExtensionReplyProvenance::DirectExtension
        };
        let mut output = Vec::new();
        broker.extension_with_provenance(json!({"kind":"response","protocol":1,"generation":broker.generation,"id":command["id"],"error":{"kind":"outcome_unknown","message":"extension request answered after caller cancellation"}}), provenance, &mut output).unwrap();
        assert!(
            matches!(semantic_control(&mut client).into_parts().0, ControlEvent::OrphanCdpCompletion { event:BrokerCdpEvent::TransportFailure(reason), .. } if reason == "extension claim request ended: outcome_unknown: extension request answered after caller cancellation")
        );
        expect_cdp_progress(&mut client, "claim-a");
        let snapshot = fenced_snapshot(&mut broker, &mut client, 3, "claim-a");
        assert!(
            snapshot["pending"].as_array().unwrap().is_empty(),
            "an actual extension terminal reply ends the raw wait"
        );
        assert!(
            broker.claims["claim-a"].alive.load(Ordering::SeqCst),
            "raw request settlement is not physical debugger cleanup"
        );
        assert!(
            matches!(
                broker.bind_route(client.sender.lease.id, "claim-a"),
                Err(BrokerError::ClaimUnavailable)
            ),
            "settlement must not reopen execution"
        );
        assert!(output.is_empty());
    }
}

#[test]
fn typed_matched_reply_must_preserve_every_exact_pending_association() {
    use super::super::extension_wire::MatchedExtensionReply;

    for changed in ["generation", "owner", "outer", "context"] {
        let mut broker = fixture();
        let mut client = admit(&mut broker);
        let route = attach(&mut broker, &mut client, 1, 11, "claim-a");
        let context = ExtensionWireContext::new("actual-session", "actual-turn").unwrap();
        broker.input_context = Some(context.clone());
        let command = cdp(&mut broker, &client, &route, 1);
        broker.input_context = None;
        fenced_snapshot(&mut broker, &mut client, 2, "claim-a");
        let proof = MatchedExtensionReply::from_matched_rpc(
            if changed == "generation" {
                "foreign-generation".to_owned()
            } else {
                broker.generation.clone()
            },
            if changed == "owner" {
                "foreign-owner".to_owned()
            } else {
                broker.clients[&client.sender.lease.id].owner.clone()
            },
            if changed == "outer" {
                "999".to_owned()
            } else {
                command["id"].as_str().unwrap().to_owned()
            },
            Some(if changed == "context" {
                ExtensionWireContext::new("actual-session", "foreign-turn").unwrap()
            } else {
                context
            }),
        );
        let mut output = Vec::new();
        let error = broker.extension_with_provenance(json!({"kind":"response","protocol":1,"generation":broker.generation,"id":command["id"],"result":{"result":{"ack":true}}}), ExtensionReplyProvenance::Matched(proof), &mut output);
        assert!(
            matches!(error, Err(BrokerError::Protocol(message)) if message == "matched extension reply changed its pending association"),
            "changed {changed} cannot authenticate another request's terminal result"
        );
        assert!(broker
            .pending
            .contains_key(&canonical_id(command["id"].as_str()).unwrap()));
        assert!(client.events.try_recv().is_err());
        broker.end_generation("matched association protocol failure");
        assert!(matches!(
            semantic_control(&mut client).into_parts().0,
            ControlEvent::GenerationClosed { .. }
        ));
        broker.control(
            client.sender.lease.id,
            ControlRequest::FenceCdp {
                id: 3,
                claim: "claim-a".to_owned(),
            },
            &mut output,
        );
        assert!(matches!(
            semantic_control(&mut client).into_parts().0,
            ControlEvent::Reply {
                id: 3,
                outcome: ControlOutcome::Unknown { .. }
            }
        ));
        assert!(output.is_empty());
    }
}

#[test]
fn explicit_native_cleanup_preserves_exact_host_identity_without_execution_scope_fence() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let _route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let context = ExtensionWireContext::new(
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "captured-cleanup-turn",
    )
    .unwrap();
    for request in [
        ControlRequest::Detach {
            id: 2,
            claim: "claim-a".to_owned(),
        },
        ControlRequest::FinishTurn { id: 3, keep: None },
        ControlRequest::StopCreatedTab {
            id: 4,
            creation: "actual-created-receipt-fixture".to_owned(),
            tab_id: None,
        },
    ] {
        broker.input_context = Some(context.clone());
        let mut output = Vec::new();
        broker.control(client.sender.lease.id, request, &mut output);
        broker.input_context = None;
        assert_eq!(output.len(), 1);
        let outbound = output.pop().unwrap();
        let outer = outbound.outer.unwrap();
        assert!(
            broker.pending[&outer].scope_fence.is_none(),
            "cleanup cannot be fenced by its ended execution scope"
        );
        assert_eq!(broker.pending[&outer].wire_context.as_ref(), Some(&context));
        let adapter_request = outbound.into_adapter_request();
        assert_eq!(
            adapter_request.wire_context.as_ref(),
            Some(&context),
            "trusted identity is independent of execution fencing"
        );
        assert!(adapter_request.guard.is_live());
    }
}

fn retire_locally(
    broker: &mut ExtensionHostBroker,
    client: &mut ClientConnection,
    id: u64,
    claim: &str,
    cleanup_id: u64,
) -> ControlOutcome {
    let mut output = Vec::new();
    broker.control(
        client.sender.lease.id,
        ControlRequest::RetireClaim {
            id,
            claim: claim.to_owned(),
            cleanup_id,
        },
        &mut output,
    );
    assert!(
        output.is_empty(),
        "retirement cannot perform extension effects"
    );
    match semantic_control(client).into_parts().0 {
        ControlEvent::Reply {
            id: actual,
            outcome,
        } if actual == id => outcome,
        event => panic!("expected exact local retirement reply {id}, got {event:?}"),
    }
}

#[test]
fn more_than_sixty_four_turns_retire_only_after_exact_known_cleanup_and_drain() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    for turn in 0..80_u64 {
        let id = turn * 4 + 1;
        let token = format!("turn-claim-{turn}");
        let _route = attach(&mut broker, &mut client, id, turn + 1, &token);
        assert!(
            fenced_snapshot(&mut broker, &mut client, id + 1, &token)["pending"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let command = request(
            &mut broker,
            &client,
            ControlRequest::Detach {
                id: id + 2,
                claim: token.clone(),
            },
        );
        reply(
            &mut broker,
            &command,
            json!({"detached":true,"proof":"detach_ack"}),
        );
        assert!(matches!(semantic_control(&mut client).into_parts().0,
            ControlEvent::Reply { id: actual, outcome: ControlOutcome::Result(_) } if actual == id + 2));
        assert!(
            matches!(retire_locally(&mut broker, &mut client, id + 3, &token, id + 2),
            ControlOutcome::Result(result) if result == json!({"retired":true,"claim":token}))
        );
        assert!(
            broker.claims.is_empty(),
            "folded turn {turn} must release its claim bookkeeping"
        );
        assert!(broker.routes.is_empty());
        assert!(broker.pending.is_empty());
    }
}

#[test]
fn active_claims_and_routes_have_no_invented_lifetime_count_limit() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let mut routes = Vec::new();
    for id in 1..=300_u64 {
        routes.push(attach(
            &mut broker,
            &mut client,
            id,
            id,
            &format!("claim-{id}"),
        ));
    }
    assert_eq!(broker.claims.len(), 300);
    assert_eq!(broker.routes.len(), 300);
    assert!(
        broker.pending.is_empty(),
        "the finite concurrent-request budget remains independent"
    );
    assert!(routes
        .iter()
        .all(|route| route.sender.lease.alive.load(Ordering::SeqCst)));
}

#[test]
fn retirement_needs_same_owner_fence_exact_cleanup_id_and_known_raw_settlement() {
    let mut broker = fixture();
    let mut owner = admit(&mut broker);
    let mut other = admit(&mut broker);
    let route = attach(&mut broker, &mut owner, 1, 11, "claim-a");
    let command = cdp(&mut broker, &owner, &route, 1);
    let snapshot = fenced_snapshot(&mut broker, &mut owner, 2, "claim-a");
    assert_eq!(snapshot["pending"].as_array().unwrap().len(), 1);
    let detach = request(
        &mut broker,
        &owner,
        ControlRequest::Detach {
            id: 3,
            claim: "claim-a".to_owned(),
        },
    );
    reply(
        &mut broker,
        &detach,
        json!({"detached":true,"proof":"detach_ack"}),
    );
    assert!(matches!(
        semantic_control(&mut owner).into_parts().0,
        ControlEvent::Reply { id: 3, .. }
    ));
    assert!(
        matches!(
            retire_locally(&mut broker, &mut owner, 4, "claim-a", 3),
            ControlOutcome::Unknown { .. }
        ),
        "physical ACK cannot retire an unresolved CDP command"
    );
    reply(&mut broker, &command, json!({"result":{"finished":true}}));
    assert!(matches!(
        semantic_control(&mut owner).into_parts().0,
        ControlEvent::OrphanCdpCompletion { id: 1, .. }
    ));
    expect_cdp_progress(&mut owner, "claim-a");
    assert!(matches!(
        retire_locally(&mut broker, &mut other, 1, "claim-a", 3),
        ControlOutcome::Unknown { .. }
    ));
    assert!(matches!(
        retire_locally(&mut broker, &mut owner, 5, "claim-a", 999),
        ControlOutcome::Unknown { .. }
    ));
    assert!(broker.claims.contains_key("claim-a"));
    assert!(matches!(
        retire_locally(&mut broker, &mut owner, 6, "claim-a", 3),
        ControlOutcome::Result(_)
    ));
    assert!(!broker.claims.contains_key("claim-a"));
    assert!(
        matches!(
            retire_locally(&mut broker, &mut owner, 7, "claim-a", 3),
            ControlOutcome::Unknown { .. }
        ),
        "retirement never creates a reusable cleanup authority"
    );
}

#[test]
fn synthetic_unknown_and_unrecognized_cleanup_never_authorize_retirement() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let command = cdp(&mut broker, &client, &route, 1);
    fenced_snapshot(&mut broker, &mut client, 2, "claim-a");
    let mut output = Vec::new();
    broker.extension_with_provenance(json!({"kind":"response","protocol":1,"generation":broker.generation,"id":command["id"],"error":{"kind":"outcome_unknown","message":"no matched RPC ACK"}}), ExtensionReplyProvenance::Adapted, &mut output).unwrap();
    assert!(matches!(
        semantic_control(&mut client).into_parts().0,
        ControlEvent::OrphanCdpCompletion {
            event: BrokerCdpEvent::TransportFailure(_),
            ..
        }
    ));
    expect_cdp_progress(&mut client, "claim-a");
    let detach = request(
        &mut broker,
        &client,
        ControlRequest::Detach {
            id: 3,
            claim: "claim-a".to_owned(),
        },
    );
    reply(
        &mut broker,
        &detach,
        json!({"detached":true,"proof":"unrecognized"}),
    );
    assert!(matches!(
        semantic_control(&mut client).into_parts().0,
        ControlEvent::Reply { id: 3, .. }
    ));
    assert!(broker.claims["claim-a"].cleanup_id.is_none());
    assert!(matches!(
        retire_locally(&mut broker, &mut client, 4, "claim-a", 3),
        ControlOutcome::Unknown { .. }
    ));
    let detach = request(
        &mut broker,
        &client,
        ControlRequest::Detach {
            id: 5,
            claim: "claim-a".to_owned(),
        },
    );
    reply(
        &mut broker,
        &detach,
        json!({"detached":true,"proof":"detach_ack"}),
    );
    let _ = semantic_control(&mut client);
    assert!(matches!(
        retire_locally(&mut broker, &mut client, 6, "claim-a", 5),
        ControlOutcome::Unknown { .. }
    ));
    assert!(broker.claims.contains_key("claim-a"));
    assert!(broker.pending.values().any(|pending| matches!(
        pending.kind,
        PendingKind::Cdp {
            unknown: Some(_),
            ..
        }
    )));
}

#[test]
fn unconfirmed_reports_actual_dispatch_for_every_route_request_before_failure() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let mut route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let written = cdp(&mut broker, &client, &route, 1);
    let mut output = Vec::new();
    for id in [2, 3] {
        broker.cdp(
            client.sender.lease.id,
            route.sender.lease.id,
            json!({"id":id,"method":"Runtime.evaluate","params":{"expression":"1"}}),
            &mut output,
        );
    }
    let started = output.pop().unwrap();
    broker.pending[&started.outer.unwrap()]
        .dispatch
        .store(STARTED, Ordering::SeqCst);
    let queued = output.pop().unwrap();
    assert_eq!(
        broker.pending[&queued.outer.unwrap()]
            .dispatch
            .load(Ordering::SeqCst),
        QUEUED
    );
    broker.retire_route(route.sender.lease.id, "route canceled before outcomes");
    let mut phases = HashMap::new();
    for _ in 0..3 {
        match client.events.try_recv().unwrap().into_parts().0 {
            ControlEvent::CdpUnconfirmed {
                claim,
                route: actual,
                id,
                write_phase,
                reason,
                event,
                wire_context,
            } => {
                assert_eq!(claim, "claim-a");
                assert_eq!(actual, route.sender.lease.id.0);
                assert_eq!(reason, UNKNOWN_CDP_REASON);
                assert!(
                    matches!(event, Some(BrokerCdpEvent::TransportFailure(reason)) if reason == UNKNOWN_CDP_REASON)
                );
                assert!(wire_context.is_none());
                phases.insert(id, write_phase);
            }
            event => panic!("unconfirmed metadata must precede route failure: {event:?}"),
        }
    }
    assert_eq!(phases[&1], ExtensionCdpWritePhase::Written);
    assert_eq!(phases[&2], ExtensionCdpWritePhase::Queued);
    assert_eq!(phases[&3], ExtensionCdpWritePhase::Started);
    assert!(
        matches!(client.events.try_recv().unwrap().into_parts().0,
        ControlEvent::CdpRouteClosed { route:actual, claim, .. } if actual == route.sender.lease.id.0 && claim == "claim-a"),
        "route lifecycle marker must follow every exact per-ID fact"
    );
    assert!(
        route.events.try_recv().is_err(),
        "no separate failure can overtake another ID's atomic metadata"
    );
    assert_eq!(broker.pending.len(), 3);
    assert!(broker
        .pending
        .contains_key(&canonical_id(written["id"].as_str()).unwrap()));
}

#[test]
fn eof_reports_retired_route_requests_before_generation_closed() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let _command = cdp(&mut broker, &client, &route, 1);
    fenced_snapshot(&mut broker, &mut client, 2, "claim-a");
    broker.end_generation("extension port EOF without response");
    assert!(matches!(
        client.events.try_recv().unwrap().into_parts().0,
        ControlEvent::CdpUnconfirmed {
            id: 1,
            write_phase: ExtensionCdpWritePhase::Written,
            ..
        }
    ));
    assert!(matches!(
        client.events.try_recv().unwrap().into_parts().0,
        ControlEvent::GenerationClosed { .. }
    ));
}

#[test]
fn stop_created_local_identity_binds_cleanup_without_leaking_metadata_or_fabricating_result() {
    for known_tab in [None, Some(11)] {
        let mut broker = fixture();
        let mut client = admit(&mut broker);
        let _route = attach(&mut broker, &mut client, 1, 11, "claim-a");
        let _sibling = attach(&mut broker, &mut client, 2, 22, "claim-b");
        fenced_snapshot(&mut broker, &mut client, 3, "claim-a");
        let command = request(
            &mut broker,
            &client,
            ControlRequest::StopCreatedTab {
                id: 4,
                creation: "actual-issued-creation".to_owned(),
                tab_id: known_tab,
            },
        );
        assert_eq!(
            command["params"],
            json!({"creation":"actual-issued-creation"}),
            "local custody metadata is not a new extension RPC field"
        );
        reply(
            &mut broker,
            &command,
            json!({"closed":true,"proof":"close_ack"}),
        );
        assert!(
            matches!(semantic_control(&mut client).into_parts().0,
            ControlEvent::Reply { id:4, outcome:ControlOutcome::Result(result) } if result == json!({"closed":true,"proof":"close_ack"})),
            "actual extension result remains intact without fabricated tab identity"
        );
        assert_eq!(broker.claims["claim-a"].cleanup_id, known_tab.map(|_| 4));
        assert!(broker.claims["claim-b"].cleanup_id.is_none());
        assert!(broker.claims["claim-b"].alive.load(Ordering::SeqCst));
        let outcome = retire_locally(&mut broker, &mut client, 5, "claim-a", 4);
        assert_eq!(
            matches!(outcome, ControlOutcome::Result(_)),
            known_tab.is_some()
        );
    }
}

#[test]
fn late_actual_error_after_atomic_route_failure_preserves_new_cause_and_origin_context() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let mut route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let context = ExtensionWireContext::new("actual-old-session", "actual-old-turn").unwrap();
    broker.input_context = Some(context.clone());
    let command = cdp(&mut broker, &client, &route, 1);
    broker.input_context = None;
    broker.retire_route(route.sender.lease.id, "caller canceled before raw response");
    assert!(matches!(client.events.try_recv().unwrap().into_parts().0,
        ControlEvent::CdpUnconfirmed { id:1, event:Some(BrokerCdpEvent::TransportFailure(_)), wire_context:Some(actual), .. } if actual == context));
    assert!(matches!(client.events.try_recv().unwrap().into_parts().0,
        ControlEvent::CdpRouteClosed { route:actual, claim, .. } if actual == route.sender.lease.id.0 && claim == "claim-a"));
    assert!(
        broker.claims["claim-a"].alive.load(Ordering::SeqCst),
        "route marker is not physical cleanup"
    );
    assert!(route.events.try_recv().is_err());
    broker.input_context =
        Some(ExtensionWireContext::new("arrival-session", "arrival-turn").unwrap());
    let mut output = Vec::new();
    broker.extension(json!({"kind":"response","protocol":1,"generation":broker.generation,"id":command["id"],"error":{"kind":"outcome_unknown","message":"actual later extension error cause"}}), &mut output).unwrap();
    assert!(matches!(client.events.try_recv().unwrap().into_parts().0,
        ControlEvent::CdpUnconfirmed { id:1, event:None, wire_context:Some(actual), .. } if actual == context));
    assert!(matches!(client.events.try_recv().unwrap().into_parts().0,
        ControlEvent::OrphanCdpCompletion { id:1, event:BrokerCdpEvent::TransportFailure(reason), wire_context:Some(actual), .. }
        if reason == "extension claim request ended: outcome_unknown: actual later extension error cause" && actual == context));
    assert!(
        broker.pending.is_empty(),
        "actual direct extension response is raw terminal while effects stay unknown"
    );
    assert!(
        output.is_empty(),
        "late error cannot replay the original command"
    );
}

#[test]
fn unconfirmed_terminal_and_captured_context_own_an_independent_byte_charge() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let context =
        ExtensionWireContext::new("old-session", "old-turn-with-byte-accounting").unwrap();
    broker.input_context = Some(context.clone());
    let command = cdp(&mut broker, &client, &route, 1);
    broker.input_context = None;
    let before = broker.budget.available_bytes();
    let mut output = Vec::new();
    broker.extension(json!({"kind":"response","protocol":1,"generation":broker.generation,"id":command["id"],"error":{"kind":"outcome_unknown","message":"actual charged extension cause"}}), &mut output).unwrap();
    let (event, charge) = client.events.try_recv().unwrap().into_parts();
    let (route_event, route_charge) = client.events.try_recv().unwrap().into_parts();
    assert!(matches!(route_event, ControlEvent::CdpRouteClosed { .. }));
    assert_eq!(
        route_charge.as_ref().unwrap().bytes(),
        serde_json::to_vec(&route_event).unwrap().len()
    );
    drop(route_event);
    drop(route_charge);
    let bytes = charge
        .as_ref()
        .expect("each variable unconfirmed payload requires its own charge")
        .bytes();
    assert_eq!(bytes, serde_json::to_vec(&event).unwrap().len());
    assert_eq!(broker.budget.available_bytes(), before - bytes);
    assert!(
        matches!(&event, ControlEvent::CdpUnconfirmed { event:Some(BrokerCdpEvent::TransportFailure(reason)), wire_context:Some(actual), .. }
        if reason == "extension claim request ended: outcome_unknown: actual charged extension cause" && actual == &context)
    );
    drop(event);
    assert_eq!(
        broker.budget.available_bytes(),
        before - bytes,
        "socket writer still owns exact bytes"
    );
    drop(charge);
    assert_eq!(broker.budget.available_bytes(), before);
    assert!(output.is_empty());
}

#[tokio::test]
async fn admitted_cdp_input_racing_route_retirement_is_exactly_known_unsent() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let mut other = admit(&mut broker);
    let route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let sibling = attach(&mut broker, &mut other, 1, 22, "claim-b");
    let context = ExtensionWireContext::new("issued-session", "queued-old-turn").unwrap();
    route
        .sender
        .send_json_with_context(
            json!({"id":1,"method":"Input.insertText","params":{"text":"must not dispatch"}}),
            Some(context.clone()),
        )
        .await
        .unwrap();
    let input = broker
        .input
        .try_recv()
        .expect("actual RouteSender must have admitted one typed input");
    assert!(matches!(&input, Input::Cdp { claim, .. } if claim == "claim-a"));
    broker.retire_route(route.sender.lease.id, "route retired before actor dequeue");
    assert!(matches!(
        client.events.try_recv().unwrap().into_parts().0,
        ControlEvent::CdpRouteClosed { .. }
    ));
    broker.current_charge = input.charge();
    broker.input_context = input.wire_context();
    let mut output = Vec::new();
    match input {
        Input::Cdp {
            client,
            route,
            claim,
            message,
            ..
        } => {
            broker.cdp_input(client, route, &claim, message, &mut output);
        }
        _ => panic!("expected the actual captured CDP input"),
    }
    broker.current_charge = None;
    broker.input_context = None;
    assert!(matches!(client.events.try_recv().unwrap().into_parts().0,
        ControlEvent::CdpMessage { route:actual, claim,
            event:BrokerCdpEvent::LocalRejected { id:1,code,message }, wire_context:Some(actual_context) }
        if actual == route.sender.lease.id.0 && claim == "claim-a" && code == "not_dispatched" &&
            message == "CDP route ended before extension dispatch" && actual_context == context));
    assert!(broker.pending.is_empty());
    assert!(
        output.is_empty(),
        "the raced request must perform zero extension effects"
    );
    assert!(client.sender.lease.alive.load(Ordering::SeqCst));
    assert!(other.sender.lease.alive.load(Ordering::SeqCst));
    assert!(other.events.try_recv().is_err());
    let command = cdp(&mut broker, &other, &sibling, 1);
    assert_eq!(command["params"]["claim"], "claim-b");
}

#[test]
fn direct_own_reply_before_writer_flush_returns_proves_exact_frame_written() {
    struct ReplyDuringFlush<'a> {
        broker: &'a mut ExtensionHostBroker,
        bytes: Vec<u8>,
    }
    impl Write for ReplyDuringFlush<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            let body = extension_framing::read_frame(
                &mut Cursor::new(&self.bytes),
                Direction::HostToChrome,
            )
            .unwrap()
            .unwrap();
            let request: Value = serde_json::from_slice(&body).unwrap();
            let outer = canonical_id(request["id"].as_str()).unwrap();
            assert_eq!(
                self.broker.pending[&outer].dispatch.load(Ordering::SeqCst),
                STARTED,
                "the actual complete frame can be parsed before the writer resumes after flush"
            );
            let mut output = Vec::new();
            self.broker.extension(json!({"kind":"response","protocol":1,"generation":request["generation"],"id":request["id"],"error":{"kind":"outcome_unknown","message":"actual extension invocation answered during flush"}}), &mut output).unwrap();
            assert!(output.is_empty());
            Ok(())
        }
    }
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let mut output = Vec::new();
    broker.cdp(
        client.sender.lease.id,
        route.sender.lease.id,
        json!({"id":1,"method":"Runtime.evaluate","params":{"expression":"1"}}),
        &mut output,
    );
    let outbound = output.pop().unwrap();
    let outer = outbound.outer.unwrap();
    let report = outbound
        .write_to(&mut ReplyDuringFlush {
            broker: &mut broker,
            bytes: Vec::new(),
        })
        .unwrap();
    assert!(matches!(report, Some(WriteReport::Written { outer:actual, .. }) if actual == outer));
    assert!(
        matches!(client.events.try_recv().unwrap().into_parts().0,
        ControlEvent::CdpUnconfirmed { id:1, write_phase:ExtensionCdpWritePhase::Written,
            event:Some(BrokerCdpEvent::TransportFailure(reason)), .. }
        if reason == "extension claim request ended: outcome_unknown: actual extension invocation answered during flush"),
        "transport write proof never fabricates Chrome or effect success"
    );
    assert!(broker.pending.is_empty());
}

#[test]
fn adapted_or_original_semantic_matched_reply_never_promotes_started_to_written() {
    use super::super::extension_wire::MatchedExtensionReply;
    for adapted in [true, false] {
        let mut broker = fixture();
        let mut client = admit(&mut broker);
        let route = attach(&mut broker, &mut client, 1, 11, "claim-a");
        let mut output = Vec::new();
        broker.cdp(
            client.sender.lease.id,
            route.sender.lease.id,
            json!({"id":1,"method":"Runtime.evaluate","params":{"expression":"1"}}),
            &mut output,
        );
        let request = output.pop().unwrap().into_adapter_request();
        assert!(request.guard.start_write());
        let outer = request.semantic_id.as_ref().unwrap();
        let provenance = if adapted {
            ExtensionReplyProvenance::Adapted
        } else {
            ExtensionReplyProvenance::Matched(MatchedExtensionReply::from_matched_rpc(
                broker.generation.clone(),
                broker.clients[&client.sender.lease.id].owner.clone(),
                outer.clone(),
                None,
            ))
        };
        broker.extension_with_provenance(json!({"kind":"response","protocol":1,"generation":broker.generation,"id":outer,"error":{"kind":"outcome_unknown","message":"semantic activation or missing RPC response"}}), provenance, &mut output).unwrap();
        assert!(matches!(
            client.events.try_recv().unwrap().into_parts().0,
            ControlEvent::CdpUnconfirmed {
                write_phase: ExtensionCdpWritePhase::Started,
                ..
            }
        ));
        assert_eq!(
            broker.pending.is_empty(),
            !adapted,
            "matched extension termination and actual CDP full-frame write are distinct"
        );
    }
}

#[test]
fn invalid_direct_response_bindings_never_promote_dispatch() {
    for invalid in [
        "protocol",
        "generation",
        "unissued_id",
        "not_released",
        "invalid_outcome",
    ] {
        let mut broker = fixture();
        let mut client = admit(&mut broker);
        let route = attach(&mut broker, &mut client, 1, 11, "claim-a");
        let mut output = Vec::new();
        broker.cdp(
            client.sender.lease.id,
            route.sender.lease.id,
            json!({"id":1,"method":"Runtime.evaluate","params":{"expression":"1"}}),
            &mut output,
        );
        let request = output.pop().unwrap().into_adapter_request();
        let outer = request.semantic_id.as_ref().unwrap();
        let dispatch = broker.pending[&canonical_id(Some(outer)).unwrap()]
            .dispatch
            .clone();
        if invalid != "not_released" {
            assert!(request.guard.start_write());
        }
        let initial = dispatch.load(Ordering::SeqCst);
        let mut response = json!({"kind":"response","protocol":1,"generation":broker.generation,"id":outer,"error":{"kind":"outcome_unknown","message":"untrusted malformed response"}});
        match invalid {
            "protocol" => response["protocol"] = json!(2),
            "generation" => response["generation"] = json!("foreign-generation"),
            "unissued_id" => response["id"] = json!("999999"),
            "not_released" => {}
            "invalid_outcome" => response["result"] = json!({"result":{}}),
            _ => unreachable!(),
        }
        assert!(matches!(
            broker.extension(response, &mut output),
            Err(BrokerError::Protocol(_))
        ));
        assert_eq!(
            dispatch.load(Ordering::SeqCst),
            initial,
            "invalid {invalid} cannot prove write progress"
        );
        assert!(client.events.try_recv().is_err());
        assert!(output.is_empty());
    }
}

#[test]
fn late_cleanup_ack_in_unknown_result_retains_exact_purpose_bound_retirement_proof() {
    for detach in [true, false] {
        let mut broker = fixture();
        let mut client = admit(&mut broker);
        let _route = attach(&mut broker, &mut client, 1, 11, "claim-a");
        fenced_snapshot(&mut broker, &mut client, 2, "claim-a");
        let (request_value, physical_result) = if detach {
            (
                ControlRequest::Detach {
                    id: 3,
                    claim: "claim-a".to_owned(),
                },
                json!({"detached":true,"proof":"detach_ack"}),
            )
        } else {
            (
                ControlRequest::StopCreatedTab {
                    id: 3,
                    creation: "issued-creation".to_owned(),
                    tab_id: Some(11),
                },
                json!({"closed":true,"proof":"close_ack"}),
            )
        };
        let command = request(&mut broker, &client, request_value);
        let mut output = Vec::new();
        broker.extension(json!({"kind":"response","protocol":1,"generation":broker.generation,"id":command["id"],"error":{"kind":"outcome_unknown","message":"cleanup ACK arrived after caller cancellation","details":{"acknowledgedResult":physical_result}}}), &mut output).unwrap();
        assert!(
            matches!(
                semantic_control(&mut client).into_parts().0,
                ControlEvent::Reply {
                    id: 3,
                    outcome: ControlOutcome::Unknown { .. }
                }
            ),
            "overall cancellation/effect uncertainty remains visible"
        );
        assert_eq!(broker.claims["claim-a"].cleanup_id, Some(3));
        assert!(
            matches!(
                retire_locally(&mut broker, &mut client, 4, "claim-a", 3),
                ControlOutcome::Result(_)
            ),
            "an exact positive physical cleanup receipt survives its cancelled caller"
        );
        assert!(output.is_empty());
    }
}

#[test]
fn actual_late_own_reply_after_abandoned_write_settles_raw_wait_and_preserves_orphan() {
    for success in [true, false] {
        let mut broker = fixture();
        let mut client = admit(&mut broker);
        let route = attach(&mut broker, &mut client, 1, 11, "claim-a");
        let context = ExtensionWireContext::new("old-session", "abandoned-turn").unwrap();
        broker.input_context = Some(context.clone());
        let mut output = Vec::new();
        broker.cdp(
            client.sender.lease.id,
            route.sender.lease.id,
            json!({"id":1,"method":"Input.insertText","params":{"text":"only once"}}),
            &mut output,
        );
        broker.input_context = None;
        let request = output.pop().unwrap().into_adapter_request();
        assert!(request.guard.start_write());
        let outer = canonical_id(request.semantic_id.as_deref()).unwrap();
        broker.written(WriteReport::Abandoned { outer }, &mut output);
        assert!(matches!(
            client.events.try_recv().unwrap().into_parts().0,
            ControlEvent::CdpUnconfirmed {
                id: 1,
                write_phase: ExtensionCdpWritePhase::Started,
                event: Some(BrokerCdpEvent::TransportFailure(_)),
                ..
            }
        ));
        assert!(matches!(
            broker.pending[&outer].kind,
            PendingKind::Cdp {
                unknown: Some(_),
                ..
            }
        ));
        let mut wrong = json!({"kind":"response","protocol":1,"generation":"foreign-generation","id":outer.to_string(),"result":{"result":{"actual":true}}});
        assert!(matches!(
            broker.extension(wrong.clone(), &mut output),
            Err(BrokerError::Protocol(_))
        ));
        assert!(
            broker.pending.contains_key(&outer),
            "mismatched actual port reply cannot clear unknown custody"
        );
        wrong["generation"] = json!(broker.generation);
        if !success {
            wrong.as_object_mut().unwrap().remove("result");
            wrong["error"] =
                json!({"kind":"outcome_unknown","message":"actual late extension failure cause"});
        }
        broker.extension(wrong, &mut output).unwrap();
        if !success {
            assert!(matches!(client.events.try_recv().unwrap().into_parts().0,
                ControlEvent::CdpUnconfirmed { id:1, write_phase:ExtensionCdpWritePhase::Written,
                    event:None, wire_context:Some(actual), .. } if actual == context));
        }
        let event = client.events.try_recv().unwrap().into_parts().0;
        assert!(
            matches!(&event, ControlEvent::OrphanCdpCompletion { id:1, wire_context:Some(actual), .. } if actual == &context)
        );
        match event {
            ControlEvent::OrphanCdpCompletion {
                event: BrokerCdpEvent::ChromeMessage(value),
                ..
            } if success => assert_eq!(value["result"]["actual"], true),
            ControlEvent::OrphanCdpCompletion {
                event: BrokerCdpEvent::TransportFailure(reason),
                ..
            } if !success => assert_eq!(
                reason,
                "extension claim request ended: outcome_unknown: actual late extension failure cause"
            ),
            event => panic!("actual late receipt must retain its exact source outcome: {event:?}"),
        }
        assert!(
            broker.pending.is_empty(),
            "actual parsed Maka reply terminates raw extension invocation only"
        );
        assert!(
            output.is_empty(),
            "no replay or new extension cleanup may be created"
        );
    }
}

#[test]
fn ordered_route_open_early_events_replies_and_unknown_share_one_owner_fifo() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let command = request(
        &mut broker,
        &client,
        ControlRequest::Attach { id: 1, tab_id: 11 },
    );
    reply(
        &mut broker,
        &command,
        json!({"claim":"claim-a","tabId":11,"targetId":"opaque-target-11"}),
    );
    let _ = client.events.try_recv().unwrap();
    let owner = broker.clients[&client.sender.lease.id].owner.clone();
    let mut output = Vec::new();
    broker.extension(json!({"kind":"event","protocol":1,"generation":broker.generation,"owner":owner,"claim":"claim-a","method":"Runtime.consoleAPICalled","params":{"sequence":1}}), &mut output).unwrap();
    let mut route = broker
        .bind_route_with_delivery(
            client.sender.lease.id,
            "claim-a",
            RouteDelivery::Ordered { open_id: 9 },
        )
        .unwrap();
    let context = ExtensionWireContext::new("captured-session", "reply-origin-turn").unwrap();
    broker.input_context = Some(context.clone());
    let known = cdp(&mut broker, &client, &route, 1);
    broker.input_context = None;
    reply(&mut broker, &known, json!({"result":{"sequence":2}}));
    broker.extension(json!({"kind":"event","protocol":1,"generation":broker.generation,"owner":owner,"claim":"claim-a","method":"Debugger.paused","params":{"sequence":3}}), &mut output).unwrap();
    let failed = cdp(&mut broker, &client, &route, 2);
    broker.extension(json!({"kind":"response","protocol":1,"generation":broker.generation,"id":failed["id"],"error":{"kind":"outcome_unknown","message":"actual invocation unknown after earlier raw events"}}), &mut output).unwrap();
    assert!(matches!(client.events.try_recv().unwrap().into_parts().0,
        ControlEvent::CdpOpened { id:9, route:actual } if actual == route.sender.lease.id.0));
    assert!(matches!(client.events.try_recv().unwrap().into_parts().0,
        ControlEvent::CdpMessage { event:BrokerCdpEvent::ChromeMessage(value),wire_context:None,.. }
        if value["method"] == "Runtime.consoleAPICalled" && value["params"]["sequence"] == 1));
    assert!(matches!(client.events.try_recv().unwrap().into_parts().0,
        ControlEvent::CdpMessage { event:BrokerCdpEvent::ChromeMessage(value),wire_context:Some(actual),.. }
        if value["id"] == 1 && value["result"]["sequence"] == 2 && actual == context));
    assert!(matches!(client.events.try_recv().unwrap().into_parts().0,
        ControlEvent::CdpMessage { event:BrokerCdpEvent::ChromeMessage(value),wire_context:None,.. }
        if value["method"] == "Debugger.paused" && value["params"]["sequence"] == 3));
    assert!(matches!(
        client.events.try_recv().unwrap().into_parts().0,
        ControlEvent::CdpUnconfirmed {
            id: 2,
            event: Some(BrokerCdpEvent::TransportFailure(_)),
            ..
        }
    ));
    assert!(matches!(client.events.try_recv().unwrap().into_parts().0,
        ControlEvent::CdpRouteClosed { route:actual,claim,.. } if actual == route.sender.lease.id.0 && claim == "claim-a"));
    assert!(client.events.try_recv().is_err());
    assert!(
        route.events.try_recv().is_err(),
        "production output must not duplicate into a parallel raw lane"
    );
    assert!(output.is_empty());
}

#[test]
fn supplied_foreign_cleanup_identity_never_associates_a_local_retirement_receipt() {
    for nested_unknown in [true, false] {
        for operation in ["detach", "close", "stopCreated"] {
            for foreign_field in ["claim", "tabId"] {
                let mut broker = fixture();
                let mut client = admit(&mut broker);
                let _route = attach(&mut broker, &mut client, 1, 11, "claim-a");
                fenced_snapshot(&mut broker, &mut client, 2, "claim-a");
                let (request_value, mut physical) = match operation {
                    "detach" => (
                        ControlRequest::Detach {
                            id: 3,
                            claim: "claim-a".to_owned(),
                        },
                        json!({"detached":true,"proof":"detach_ack"}),
                    ),
                    "close" => (
                        ControlRequest::CloseTab {
                            id: 3,
                            claim: "claim-a".to_owned(),
                        },
                        json!({"closed":true,"proof":"close_ack"}),
                    ),
                    "stopCreated" => (
                        ControlRequest::StopCreatedTab {
                            id: 3,
                            creation: "issued-creation".to_owned(),
                            tab_id: Some(11),
                        },
                        json!({"closed":true,"proof":"close_ack"}),
                    ),
                    _ => unreachable!(),
                };
                physical[foreign_field] = if foreign_field == "claim" {
                    json!("foreign-claim")
                } else {
                    json!(22)
                };
                let command = request(&mut broker, &client, request_value);
                let mut response = json!({"kind":"response","protocol":1,"generation":broker.generation,"id":command["id"]});
                if nested_unknown {
                    response["error"] = json!({"kind":"outcome_unknown","message":"late mismatched cleanup identity","details":{"acknowledgedResult":physical}});
                } else {
                    response["result"] = physical;
                }
                let mut output = Vec::new();
                broker.extension(response, &mut output).unwrap();
                let _ = semantic_control(&mut client);
                assert!(
                    broker.claims["claim-a"].cleanup_id.is_none(),
                    "{operation} supplied foreign {foreign_field} cannot prove claim-a cleanup"
                );
                assert!(matches!(
                    retire_locally(&mut broker, &mut client, 4, "claim-a", 3),
                    ControlOutcome::Unknown { .. }
                ));
                assert!(broker.claims.contains_key("claim-a"));
                assert!(output.is_empty());
            }
        }
    }
}

#[tokio::test]
async fn stopped_broker_drains_prior_messages_all_phase_facts_then_eof_after_reader_progress() {
    let (mut broker, mut extension_output) = fixture_with_output();
    let mut client = admit(&mut broker);
    let command = request(
        &mut broker,
        &client,
        ControlRequest::Attach { id: 1, tab_id: 11 },
    );
    reply(
        &mut broker,
        &command,
        json!({"claim":"claim-a","tabId":11,"targetId":"opaque-target-11"}),
    );
    let _ = client.events.try_recv().unwrap();
    let route = broker
        .bind_route_with_delivery(
            client.sender.lease.id,
            "claim-a",
            RouteDelivery::Ordered { open_id: 2 },
        )
        .unwrap();
    let _ = client.events.try_recv().unwrap();
    let context = ExtensionWireContext::new("pending-session", "eof-old-turn").unwrap();
    broker.input_context = Some(context.clone());
    let _pending = cdp(&mut broker, &client, &route, 1);
    broker.input_context = None;
    let owner = broker.clients[&client.sender.lease.id].owner.clone();
    let mut output = Vec::new();
    for sequence in 0..EVENT_CAPACITY {
        broker.extension(json!({"kind":"event","protocol":1,"generation":broker.generation,"owner":owner,"claim":"claim-a","method":"Runtime.consoleAPICalled","params":{"sequence":sequence}}), &mut output).unwrap();
    }
    assert_eq!(
        client.events.len(),
        EVENT_CAPACITY,
        "the real owner channel must be full before EOF"
    );
    let handle = BrokerHandle {
        input: broker.input_sender.clone(),
        budget: broker.budget.clone(),
    };
    let task = tokio::spawn(broker.run());
    handle
        .extension_eof("actual extension EOF under output pressure")
        .await;
    assert!(
        matches!(handle.identity().await, Err(BrokerError::Closed)),
        "the actor must enter stopped drainage before the reader resumes"
    );
    assert!(
        matches!(
            extension_output.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ),
        "extension writer scope must close before waiting on the slow local owner"
    );
    for sequence in 0..EVENT_CAPACITY {
        let event = tokio::time::timeout(IPC_SHUTDOWN_DRAIN_TIMEOUT, client.events.recv())
            .await
            .unwrap()
            .unwrap()
            .into_parts()
            .0;
        assert!(
            matches!(event, ControlEvent::CdpMessage { event:BrokerCdpEvent::ChromeMessage(value), .. }
            if value["params"]["sequence"] == sequence),
            "earlier real CDP events cannot be dropped or overtaken"
        );
        handle.delivery_progress();
    }
    let phase = tokio::time::timeout(IPC_SHUTDOWN_DRAIN_TIMEOUT, client.events.recv())
        .await
        .unwrap()
        .unwrap()
        .into_parts()
        .0;
    assert!(
        matches!(phase, ControlEvent::CdpUnconfirmed { id:1,write_phase:ExtensionCdpWritePhase::Written,event:None,wire_context:Some(actual),.. } if actual == context)
    );
    handle.delivery_progress();
    let eof = tokio::time::timeout(IPC_SHUTDOWN_DRAIN_TIMEOUT, client.events.recv())
        .await
        .unwrap()
        .unwrap()
        .into_parts()
        .0;
    assert!(
        matches!(eof, ControlEvent::GenerationClosed { reason } if reason == "actual extension EOF under output pressure")
    );
    handle.delivery_progress();
    tokio::time::timeout(IPC_SHUTDOWN_DRAIN_TIMEOUT, task)
        .await
        .unwrap()
        .unwrap();
    assert!(client.events.try_recv().is_err());
    assert!(output.is_empty());
}

// Append inside extension_broker/tests.rs; reuses its actual broker/framing fixtures.
fn claim_preparation_control(method: &str, id: u64, claim: &str) -> ControlRequest {
    let mut value = json!({"method":method,"id":id,"claim":claim});
    if method == "prepareClaim" {
        value["document"] = json!({
            "frameId":"actual-frame-fixture",
            "loaderId":"actual-loader-fixture",
            "url":"https://prepared.example.test/document"
        });
        value["policy"] = json!({
            "popupEnabled":true,
            "headerEnabled":true,
            "headers":[{"name":"X-Preparation-Fixture","value":"one"}]
        });
    }
    serde_json::from_value(value).expect("typed preparation control fixture")
}

#[test]
fn preparation_and_popup_capture_existing_claim_context_before_ambient_turn_changes() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let _route = attach(&mut broker, &mut client, 1, 11, "preparation-claim");
    let original = ExtensionWireContext::new(
        "550e8400-e29b-41d4-a716-446655440000",
        "original-preparation-turn",
    )
    .unwrap();
    let newer =
        ExtensionWireContext::new("550e8400-e29b-41d4-a716-446655440000", "later-ambient-turn")
            .unwrap();
    let mut output = Vec::new();
    broker.input_context = Some(original.clone());
    broker.control(
        client.sender.lease.id,
        claim_preparation_control("prepareClaim", 2, "preparation-claim"),
        &mut output,
    );
    broker.control(
        client.sender.lease.id,
        claim_preparation_control("createPopupTab", 3, "preparation-claim"),
        &mut output,
    );
    broker.input_context = Some(newer);
    assert_eq!(output.len(), 2, "each admitted operation forwards once");
    for (outbound, method) in output.into_iter().zip(["prepareClaim", "createPopupTab"]) {
        let outer = outbound.outer.unwrap();
        assert_eq!(
            broker.pending[&outer].wire_context.as_ref(),
            Some(&original),
            "pending operation retains originating context before physical write"
        );
        assert_eq!(outbound.wire_context(), Some(&original));
        let command = write(outbound);
        assert_eq!(command["method"], method);
        assert_eq!(command["params"]["claim"], "preparation-claim");
        assert_eq!(command["wireContext"], json!(original));
        assert!(command["params"].get("wireContext").is_none());
        assert!(command["params"].get("hostSessionId").is_none());
        assert!(command["params"].get("hostTurnId").is_none());
        if method == "prepareClaim" {
            assert_eq!(
                command["params"]["document"]["frameId"],
                "actual-frame-fixture"
            );
            assert_eq!(
                command["params"]["document"]["loaderId"],
                "actual-loader-fixture"
            );
            assert_eq!(command["params"]["policy"]["headers"][0]["value"], "one");
        }
    }
    assert_eq!(
        broker.claims.len(),
        1,
        "forwarding does not mint another claim"
    );
    assert!(
        client.events.try_recv().is_err(),
        "queueing a popup request is not a physical creation acknowledgement"
    );
}

#[test]
fn preparation_and_popup_refuse_foreign_claims_and_missing_context_before_dispatch() {
    let mut broker = fixture();
    let mut owner = admit(&mut broker);
    let mut foreign = admit(&mut broker);
    let _route = attach(&mut broker, &mut owner, 1, 11, "preparation-claim");
    let captured = ExtensionWireContext::new(
        "550e8400-e29b-41d4-a716-446655440000",
        "trusted-preparation-turn",
    )
    .unwrap();
    for (client, context) in [(&mut owner, None), (&mut foreign, Some(captured))] {
        broker.input_context = context;
        for (id, method) in [(2, "prepareClaim"), (3, "createPopupTab")] {
            let mut output = Vec::new();
            broker.control(
                client.sender.lease.id,
                claim_preparation_control(method, id, "preparation-claim"),
                &mut output,
            );
            assert!(output.is_empty(), "{method} refusal must dispatch nothing");
            assert!(
                matches!(
                    semantic_control(client).into_parts().0,
                    ControlEvent::Reply {
                        id: actual,
                        outcome: ControlOutcome::NotDispatched { .. },
                    } if actual == id
                ),
                "refusal must settle only the exact local request"
            );
        }
    }
    assert_eq!(
        broker.claims["preparation-claim"].client,
        owner.sender.lease.id
    );
    assert!(broker.claims["preparation-claim"]
        .alive
        .load(Ordering::SeqCst));
    assert!(
        broker.pending.is_empty(),
        "refusals create no extension pending invocation"
    );
}

#[test]
fn maka_chunked_context_survives_reassembly_while_original_adapter_context_stays_sidechannel() {
    use base64::Engine;

    let mut broker = fixture();
    let client = admit(&mut broker);
    let original = ExtensionWireContext::new(
        "550e8400-e29b-41d4-a716-446655440000",
        "chunked-original-turn",
    )
    .unwrap();
    // A valid existing header-control shape exercises actual logical framing;
    // no new preparation document or policy limit is assumed by this fixture.
    let header_value = "value".repeat((NATIVE_HOST_FRAME_BYTES + CHUNK_BYTES) / 5 + 1);
    let mut output = Vec::new();
    broker.input_context = Some(original.clone());
    broker.control(
        client.sender.lease.id,
        ControlRequest::SetSessionHeaders {
            id: 1,
            headers: vec![ScopedHeader {
                name: "X-Preparation-Fixture".to_owned(),
                value: header_value.clone(),
            }],
        },
        &mut output,
    );
    let outbound = output.pop().expect("one admitted header-control frame");
    assert!(output.is_empty());
    let outer = outbound.outer.unwrap();
    let owner = outbound.owner.clone().unwrap();
    let generation = outbound.generation.clone();
    broker.input_context = Some(
        ExtensionWireContext::new("550e8400-e29b-41d4-a716-446655440000", "newer-turn").unwrap(),
    );
    let mut bytes = Vec::new();
    assert!(matches!(
        outbound.write_to(&mut bytes).unwrap(),
        Some(WriteReport::Written { outer: actual }) if actual == outer
    ));
    let mut reader = Cursor::new(bytes);
    let mut assembled = Vec::new();
    let mut part_count = 0usize;
    let mut expected_parts = None;
    let mut expected_bytes = None;
    while let Some(body) =
        extension_framing::read_frame(&mut reader, Direction::HostToChrome).unwrap()
    {
        let frame: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(frame["kind"], "chunk");
        assert_eq!(frame["generation"], generation);
        assert_eq!(frame["owner"], owner);
        assert_eq!(frame["logicalId"], outer.to_string());
        assert_eq!(frame["part"], part_count);
        assert!(
            frame.get("wireContext").is_none(),
            "context belongs to the assembled logical request, not a chunk grant"
        );
        let parts = usize::try_from(frame["parts"].as_u64().unwrap()).unwrap();
        let length = usize::try_from(frame["bytes"].as_u64().unwrap()).unwrap();
        if let Some(expected) = expected_parts {
            assert_eq!(parts, expected);
            assert_eq!(Some(length), expected_bytes);
        } else {
            expected_parts = Some(parts);
            expected_bytes = Some(length);
        }
        assembled.extend(
            base64::engine::general_purpose::STANDARD
                .decode(frame["data"].as_str().unwrap())
                .unwrap(),
        );
        part_count += 1;
    }
    assert!(
        part_count > 1,
        "fixture must cross an actual framing boundary"
    );
    assert_eq!(Some(part_count), expected_parts);
    assert_eq!(Some(assembled.len()), expected_bytes);
    let command: Value = serde_json::from_slice(&assembled).unwrap();
    assert_eq!(command["method"], "setSessionHeaders");
    assert_eq!(command["wireContext"], json!(original));
    assert!(command["params"].get("wireContext").is_none());
    assert_eq!(command["params"]["headers"][0]["value"], header_value);

    broker.input_context = Some(original.clone());
    broker.control(
        client.sender.lease.id,
        ControlRequest::Inventory {
            id: 2,
            session_only: None,
            known_tab_ids: None,
        },
        &mut output,
    );
    let adapter = output.pop().unwrap().into_adapter_request();
    assert_eq!(adapter.wire_context.as_ref(), Some(&original));
    assert!(
        adapter.message.event().get("wireContext").is_none(),
        "ChatGPT translator receives trusted context through the Rust sidechannel"
    );
    assert!(adapter.message.event()["params"]
        .get("wireContext")
        .is_none());
}

#[test]
fn popup_intent_metadata_preserves_exact_live_claim_and_actual_sender_without_host_cause() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let _route = attach(&mut broker, &mut client, 1, 11, "popup-source");
    let owner = broker.clients[&client.sender.lease.id].owner.clone();
    let captured = ExtensionWireContext::new("prepared-session", "old-prepared-turn").unwrap();
    broker.input_context =
        Some(ExtensionWireContext::new("another-session", "ambient-new-turn").unwrap());
    let mut output = Vec::new();
    broker.extension(json!({"kind":"popup_requested","protocol":1,"generation":broker.generation,"owner":owner,"claim":"popup-source","tabId":11,"wireContext":captured,"url":"https://popup.invalid/actual","frameId":0,"documentId":"actual-chrome-document","sourceUrl":"https://source.invalid/actual","hostOperation":{"operationId":"page-spoof"}}),&mut output).unwrap();
    let event = semantic_control(&mut client).into_parts().0;
    assert!(
        matches!(&event,ControlEvent::PopupRequested{claim,tab_id:11,wire_context,frame_id:Some(0),document_id:Some(document),source_url:Some(source),..} if claim=="popup-source"&&wire_context==&captured&&document=="actual-chrome-document"&&source=="https://source.invalid/actual")
    );
    let value = serde_json::to_value(event).unwrap();
    assert!(
        value["data"].get("hostOperation").is_none(),
        "page metadata never creates a causal Host operation"
    );
    assert!(
        output.is_empty(),
        "metadata neither creates/adopts/navigates nor grants a child"
    );
    assert_eq!(broker.claims.len(), 1);
}

#[test]
fn popup_metadata_refuses_missing_scope_wrong_tab_and_non_chrome_frame_identity() {
    for invalid in ["context", "tab", "frame"] {
        let mut broker = fixture();
        let mut client = admit(&mut broker);
        let _route = attach(&mut broker, &mut client, 1, 11, "popup-source");
        let owner = broker.clients[&client.sender.lease.id].owner.clone();
        let mut value = json!({"kind":"popup_requested","protocol":1,"generation":broker.generation,"owner":owner,"claim":"popup-source","tabId":11,"wireContext":{"hostSessionId":"actual-session","hostTurnId":"actual-turn"},"url":"https://popup.invalid/","frameId":0});
        match invalid {
            "context" => {
                value.as_object_mut().unwrap().remove("wireContext");
            }
            "tab" => value["tabId"] = json!(22),
            _ => value["frameId"] = json!("cdp-string-frame"),
        }
        let mut output = Vec::new();
        assert!(
            broker.extension(value, &mut output).is_err(),
            "invalid {invalid}"
        );
        assert!(client.events.try_recv().is_err());
        assert!(output.is_empty());
    }
    let mut broker = fixture();
    let mut first = admit(&mut broker);
    let mut other = admit(&mut broker);
    let _route = attach(&mut broker, &mut first, 1, 11, "popup-source");
    let other_owner = broker.clients[&other.sender.lease.id].owner.clone();
    let mut output = Vec::new();
    broker.extension(json!({"kind":"popup_requested","protocol":1,"generation":broker.generation,"owner":other_owner,"claim":"popup-source","tabId":11,"wireContext":{"hostSessionId":"other-session","hostTurnId":"other-turn"},"url":"https://popup.invalid/"}),&mut output).unwrap();
    assert!(first.events.try_recv().is_err() && other.events.try_recv().is_err());
    assert!(output.is_empty());
}

#[test]
fn fixed_cleanup_unknown_retains_only_actual_top_level_physical_proof() {
    for foreign in [false, true] {
        let mut broker = fixture();
        let mut client = admit(&mut broker);
        let _route = attach(&mut broker, &mut client, 1, 11, "cleanup-source");
        let detach = request(
            &mut broker,
            &client,
            ControlRequest::Detach {
                id: 2,
                claim: "cleanup-source".into(),
            },
        );
        let mut proof = json!({"detached":true,"proof":"detach_ack"});
        if foreign {
            proof["claim"] = json!("foreign");
        }
        let mut output = Vec::new();
        broker.extension(json!({"kind":"response","protocol":1,"generation":broker.generation,"id":detach["id"],"error":{"kind":"outcome_unknown","message":"actual fixed preparation cleanup remains unknown","details":{"physicalProof":proof}}}),&mut output).unwrap();
        assert!(matches!(
            semantic_control(&mut client).into_parts().0,
            ControlEvent::Reply {
                id: 2,
                outcome: ControlOutcome::Unknown { .. }
            }
        ));
        assert_eq!(
            broker.claims["cleanup-source"].cleanup_id.is_some(),
            !foreign
        );
        assert!(
            output.is_empty(),
            "known physical fact never becomes an all-effect ACK or replay"
        );
    }
}

#[test]
fn session_tab_control_selector_is_optional_but_strictly_boolean() {
    for method in ["resolve", "prepareUserTab"] {
        let mut fields = if method == "resolve" {
            json!({"method":method,"id":1,"rawId":"2001"})
        } else {
            json!({"method":method,"id":1,"tabId":2001})
        };
        assert!(serde_json::from_value::<ControlRequest>(fields.clone()).is_ok());
        for valid in [false, true] {
            fields["sessionOnly"] = json!(valid);
            assert!(serde_json::from_value::<ControlRequest>(fields.clone()).is_ok());
        }
        for invalid in [Value::Null, json!("true"), json!(1), json!({})] {
            fields["sessionOnly"] = invalid;
            assert!(serde_json::from_value::<ControlRequest>(fields.clone()).is_err());
        }
    }
}

#[test]
fn session_tab_control_requires_context_and_capability_and_forwards_exact_existing_method() {
    for method in ["resolve", "prepareUserTab"] {
        for supported in [false, true] {
            for contextual in [false, true] {
                let mut broker = fixture();
                let mut client = admit(&mut broker);
                broker.identity.as_mut().unwrap().capabilities["sessionTabResolution"] =
                    json!(supported);
                broker.identity.as_mut().unwrap().capabilities["sessionPreparation"] =
                    json!("provider_session");
                let wire = ExtensionWireContext::new("actual-host-session", "actual-turn").unwrap();
                if contextual {
                    broker.input_context = Some(wire.clone());
                }
                let fields = if method == "resolve" {
                    json!({"method":method,"id":1,"rawId":"2001","sessionOnly":true})
                } else {
                    json!({"method":method,"id":1,"tabId":2001,"sessionOnly":true})
                };
                let mut output = Vec::new();
                broker.control(
                    client.sender.lease.id,
                    serde_json::from_value(fields).unwrap(),
                    &mut output,
                );
                if contextual && supported {
                    assert_eq!(output.len(), 1);
                    let outbound = output.pop().unwrap();
                    assert_eq!(outbound.wire_context, Some(wire));
                    let sent = write(outbound);
                    assert_eq!(sent["method"], method);
                    assert_eq!(sent["params"]["sessionOnly"], true);
                    assert!(
                        broker.claims.is_empty(),
                        "selector does not acquire a physical claim"
                    );
                } else {
                    assert!(
                        output.is_empty(),
                        "unsupported or unscoped selectors never fall back to extension metadata"
                    );
                    let expected = if contextual {
                        "unsupported"
                    } else {
                        "context_required"
                    };
                    assert!(
                        matches!(semantic_control(&mut client).into_parts().0,ControlEvent::Reply{outcome:ControlOutcome::NotDispatched{kind,..},..} if kind==expected)
                    );
                    assert!(broker.pending.is_empty());
                    assert!(broker.claims.is_empty());
                }
            }
        }
    }
}

#[test]
fn committed_url_control_selector_requires_boolean_and_session_purpose() {
    for invalid in [Value::Null, json!("true"), json!(1), json!({})] {
        assert!(serde_json::from_value::<ControlRequest>(json!({"method":"resolve","id":1,"rawId":"2001","sessionOnly":true,"committedUrlOnly":invalid})).is_err());
    }
    for session in [false, true] {
        let mut broker = fixture();
        let mut client = admit(&mut broker);
        broker.input_context = Some(ExtensionWireContext::new("url-owner", "turn").unwrap());
        broker.identity.as_mut().unwrap().capabilities["sessionCommittedUrl"] = json!(true);
        let control=serde_json::from_value(json!({"method":"resolve","id":1,"rawId":"2001","sessionOnly":session,"committedUrlOnly":true})).unwrap();
        let mut output = Vec::new();
        broker.control(client.sender.lease.id, control, &mut output);
        if session {
            assert_eq!(output.len(), 1);
        } else {
            assert!(output.is_empty());
            assert!(
                matches!(semantic_control(&mut client).into_parts().0,ControlEvent::Reply{outcome:ControlOutcome::NotDispatched{kind,..},..} if kind=="invalid_request")
            );
        }
    }
}

#[test]
fn committed_url_control_checks_its_capability_and_context_before_same_resolve_dispatch() {
    for contextual in [false, true] {
        for supported in [false, true] {
            let mut broker = fixture();
            let mut client = admit(&mut broker);
            let wire = ExtensionWireContext::new("url-owner", "url-turn").unwrap();
            if contextual {
                broker.input_context = Some(wire.clone());
            }
            broker.identity.as_mut().unwrap().capabilities["sessionCommittedUrl"] =
                json!(supported);
            // URL-only support does not silently inherit or require the full-tab capability.
            broker.identity.as_mut().unwrap().capabilities["sessionTabResolution"] = json!(false);
            let control=serde_json::from_value(json!({"method":"resolve","id":1,"rawId":"2001","sessionOnly":true,"committedUrlOnly":true})).unwrap();
            let mut output = Vec::new();
            broker.control(client.sender.lease.id, control, &mut output);
            if contextual && supported {
                assert_eq!(output.len(), 1);
                let outbound = output.pop().unwrap();
                assert_eq!(outbound.wire_context, Some(wire));
                let sent = write(outbound);
                assert_eq!(sent["method"], "resolve");
                assert_eq!(
                    sent["params"],
                    json!({"rawId":"2001","sessionOnly":true,"committedUrlOnly":true})
                );
                assert!(broker.claims.is_empty());
            } else {
                assert!(output.is_empty());
                let expected = if contextual {
                    "unsupported"
                } else {
                    "context_required"
                };
                assert!(
                    matches!(semantic_control(&mut client).into_parts().0,ControlEvent::Reply{outcome:ControlOutcome::NotDispatched{kind,..},..} if kind==expected)
                );
                assert!(broker.pending.is_empty());
                assert!(broker.claims.is_empty());
            }
        }
    }
}

#[test]
fn whole_session_inventory_selector_reaches_existing_method_only_with_context_and_new_capability() {
    for contextual in [false, true] {
        for supported in [false, true] {
            let mut broker = fixture();
            let mut client = admit(&mut broker);
            broker.identity.as_mut().unwrap().capabilities["sessionTabInventory"] =
                json!(supported);
            let wire = ExtensionWireContext::new("actual-host-session", "actual-turn").unwrap();
            if contextual {
                broker.input_context = Some(wire.clone())
            };
            let request = serde_json::from_value(
                json!({"method":"inventory","id":1,"sessionOnly":true,"knownTabIds":[]}),
            )
            .unwrap();
            let mut output = Vec::new();
            broker.control(client.sender.lease.id, request, &mut output);
            if contextual && supported {
                assert_eq!(output.len(), 1);
                let outbound = output.pop().unwrap();
                assert_eq!(outbound.wire_context, Some(wire));
                let value = write(outbound);
                assert_eq!(value["method"], "inventory");
                assert_eq!(
                    value["params"],
                    json!({"sessionOnly":true,"knownTabIds":[]})
                );
            } else {
                assert!(output.is_empty());
                assert!(matches!(
                    semantic_control(&mut client).into_parts().0,
                    ControlEvent::Reply {
                        outcome: ControlOutcome::NotDispatched { .. },
                        ..
                    }
                ));
            }
            assert!(broker.claims.is_empty());
        }
    }
}

#[test]
fn whole_session_inventory_candidate_validation_is_not_a_global_inventory_fallback() {
    for fields in [
        json!({"method":"inventory","id":1,"sessionOnly":true}),
        json!({"method":"inventory","id":1,"knownTabIds":[]}),
        json!({"method":"inventory","id":1,"sessionOnly":true,"knownTabIds":[0]}),
        json!({"method":"inventory","id":1,"sessionOnly":true,"knownTabIds":[2,2]}),
    ] {
        let mut broker = fixture();
        let mut client = admit(&mut broker);
        broker.input_context =
            Some(ExtensionWireContext::new("actual-session", "actual-turn").unwrap());
        broker.identity.as_mut().unwrap().capabilities["sessionTabInventory"] = json!(true);
        let mut output = Vec::new();
        broker.control(
            client.sender.lease.id,
            serde_json::from_value(fields).unwrap(),
            &mut output,
        );
        assert!(output.is_empty());
        assert!(matches!(
            semantic_control(&mut client).into_parts().0,
            ControlEvent::Reply {
                outcome: ControlOutcome::NotDispatched { .. },
                ..
            }
        ));
    }
    for value in [Value::Null, json!("true"), json!(1)] {
        assert!(serde_json::from_value::<ControlRequest>(
            json!({"method":"inventory","id":1,"sessionOnly":value,"knownTabIds":[]})
        )
        .is_err());
    }
    assert!(serde_json::from_value::<ControlRequest>(
        json!({"method":"inventory","id":1,"sessionOnly":true,"knownTabIds":null})
    )
    .is_err());
}

fn physical_writer_value(value_len: usize) -> Value {
    json!({
        "kind":"request","protocol":1,"generation":"physical-writer-generation",
        "owner":"captured-writer-owner","id":"17","method":"cdp",
        "params":{
            "claim":"actual-claim","sessionId":"actual-child-session",
            "method":"Runtime.callFunctionOn",
            "params":{
                "objectId":"actual-remote-object","functionDeclaration":"function (value) { return value; }",
                "arguments":[{"value":"x".repeat(value_len)},{"unserializableValue":"NaN"},{"value":"你好🌍"}],
                "returnByValue":false,"awaitPromise":true
            }
        }
    })
}

fn physical_writer_context() -> ExtensionWireContext {
    ExtensionWireContext::new("captured-writer-session", "captured-original-turn").unwrap()
}

// Independent inert inputs exercise the shared writer. No outbound is cloned,
// reconstructed from adapter metadata, or reused after its consuming write.
fn physical_writer_outbound(value_len: usize) -> ExtensionOutbound {
    ExtensionOutbound {
        value: physical_writer_value(value_len),
        generation: "physical-writer-generation".to_owned(),
        owner: Some("captured-writer-owner".to_owned()),
        outer: Some(17),
        fences: vec![
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicBool::new(true)),
        ],
        dispatch: Arc::new(AtomicU8::new(QUEUED)),
        _charge: None,
        wire_context: Some(physical_writer_context()),
    }
}

fn physical_writer_frames(bytes: &[u8]) -> Vec<Value> {
    let mut reader = Cursor::new(bytes);
    let mut frames = Vec::new();
    while let Some(body) = extension_framing::read_frame(&mut reader, Direction::HostToChrome)
        .expect("the actual writer emitted complete extension frames")
    {
        frames.push(serde_json::from_slice(&body).unwrap());
    }
    frames
}

#[test]
fn direct_own_outbound_preserves_actual_bytes_reports_and_chunked_context() {
    use base64::Engine;

    for value_len in [64, NATIVE_HOST_FRAME_BYTES + CHUNK_BYTES] {
        let outbound = physical_writer_outbound(value_len);
        assert_eq!(outbound.outer_id(), Some(17));
        assert_eq!(outbound.wire_context(), Some(&physical_writer_context()));
        assert_eq!(
            outbound.payload_for_transport(),
            &physical_writer_value(value_len)
        );
        let dispatch = outbound.dispatch_guard();
        let mut bytes = Vec::new();
        let report = outbound.write_to(&mut bytes).unwrap();
        assert_eq!(report, Some(WriteReport::Written { outer: 17 }));
        assert_eq!(dispatch.dispatch.load(Ordering::SeqCst), WRITTEN);

        let frames = physical_writer_frames(&bytes);
        let logical = if value_len > NATIVE_HOST_FRAME_BYTES {
            assert!(frames.len() > 1, "the actual >1MiB request must be chunked");
            let mut assembled = Vec::new();
            let mut declared_bytes = None;
            for (part, frame) in frames.iter().enumerate() {
                assert_eq!(frame["kind"], "chunk");
                assert_eq!(frame["part"], part);
                assert_eq!(frame["parts"], frames.len());
                assert_eq!(frame["generation"], "physical-writer-generation");
                assert_eq!(frame["owner"], "captured-writer-owner");
                assert_eq!(frame["logicalId"], "17");
                assert!(frame.get("wireContext").is_none());
                let bytes = frame["bytes"].as_u64().unwrap();
                assert_eq!(*declared_bytes.get_or_insert(bytes), bytes);
                assembled.extend(
                    base64::engine::general_purpose::STANDARD
                        .decode(frame["data"].as_str().unwrap())
                        .unwrap(),
                );
            }
            assert_eq!(
                u64::try_from(assembled.len()).unwrap(),
                declared_bytes.unwrap()
            );
            serde_json::from_slice::<Value>(&assembled).unwrap()
        } else {
            assert_eq!(frames.len(), 1);
            frames.into_iter().next().unwrap()
        };
        let mut expected = physical_writer_value(value_len);
        expected["wireContext"] = serde_json::to_value(physical_writer_context()).unwrap();
        assert_eq!(
            logical, expected,
            "actual business and immutable context round-trip without an adapter rewrite"
        );
    }
}

#[test]
fn partial_native_prefix_or_body_failure_retains_started_unknown_eligible_dispatch() {
    struct FailAfterBytes {
        bytes: Vec<u8>,
        limit: usize,
        flushes: usize,
    }
    impl Write for FailAfterBytes {
        fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
            if self.bytes.len() == self.limit {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "actual partial extension-write fixture failure",
                ));
            }
            let accepted = input.len().min(self.limit - self.bytes.len());
            self.bytes.extend_from_slice(&input[..accepted]);
            Ok(accepted)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }
    for limit in [2, 4 + 11] {
        let outbound = physical_writer_outbound(64);
        let dispatch = outbound.dispatch_guard();
        let mut writer = FailAfterBytes {
            bytes: Vec::new(),
            limit,
            flushes: 0,
        };
        let result = outbound.write_to(&mut writer);
        assert!(
            matches!(result, Err(BrokerError::Frame(FrameError::Io(error)))
            if error.kind() == std::io::ErrorKind::BrokenPipe)
        );
        assert_eq!(writer.bytes.len(), limit);
        assert_eq!(writer.flushes, 0);
        assert_eq!(dispatch.dispatch.load(Ordering::SeqCst), STARTED);
        assert!(dispatch.was_started());
        assert!(dispatch.written_report().is_none());
        assert!(dispatch
            .reject_before_write(
                "do_not_replay".to_owned(),
                "a partial physical write cannot become a local skip".to_owned()
            )
            .is_none());
        assert_eq!(dispatch.dispatch.load(Ordering::SeqCst), STARTED);
    }
}

struct FenceAfterFirstPhysicalFlush {
    bytes: Vec<u8>,
    fence: Arc<AtomicBool>,
    flushes: usize,
}

impl Write for FenceAfterFirstPhysicalFlush {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.flushes += 1;
        if self.flushes == 1 {
            self.fence.store(false, Ordering::SeqCst);
        }
        Ok(())
    }
}

#[test]
fn physical_port_death_after_first_chunk_abandons_without_sending_cancel_chunk() {
    let outbound = physical_writer_outbound(NATIVE_HOST_FRAME_BYTES + CHUNK_BYTES);
    let dispatch = outbound.dispatch_guard();
    let port_live = outbound.fences[0].clone();
    let mut writer = FenceAfterFirstPhysicalFlush {
        bytes: Vec::new(),
        fence: port_live.clone(),
        flushes: 0,
    };
    assert_eq!(
        outbound.write_to(&mut writer).unwrap(),
        Some(WriteReport::Abandoned { outer: 17 })
    );
    assert_eq!(writer.flushes, 1);
    let frames = physical_writer_frames(&writer.bytes);
    assert_eq!(
        frames.len(),
        1,
        "dead-port retirement must not attempt a cancel write"
    );
    assert_eq!(frames[0]["kind"], "chunk");
    assert_eq!(frames[0]["part"], 0);
    assert!(frames[0]["parts"].as_u64().unwrap() > 1);
    assert_eq!(dispatch.dispatch.load(Ordering::SeqCst), STARTED);
    assert!(dispatch.written_report().is_none());
    assert!(!port_live.load(Ordering::SeqCst));
}

#[test]
fn physical_owner_revocation_while_port_is_live_preserves_exact_original_chunk_cancel() {
    let outbound = physical_writer_outbound(NATIVE_HOST_FRAME_BYTES + CHUNK_BYTES);
    let dispatch = outbound.dispatch_guard();
    let owner_live = outbound.fences[1].clone();
    let port_live = outbound.fences[0].clone();
    let mut writer = FenceAfterFirstPhysicalFlush {
        bytes: Vec::new(),
        fence: owner_live,
        flushes: 0,
    };
    assert_eq!(
        outbound.write_to(&mut writer).unwrap(),
        Some(WriteReport::Abandoned { outer: 17 })
    );
    assert_eq!(writer.flushes, 2);
    let frames = physical_writer_frames(&writer.bytes);
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0]["kind"], "chunk");
    assert_eq!(frames[0]["part"], 0);
    assert_eq!(
        frames[1],
        json!({"kind":"cancelChunk","protocol":1,"generation":"physical-writer-generation","owner":"captured-writer-owner","logicalId":"17"})
    );
    assert_eq!(dispatch.dispatch.load(Ordering::SeqCst), STARTED);
    assert!(dispatch.written_report().is_none());
    assert!(port_live.load(Ordering::SeqCst));
}

#[test]
fn native_error_named_not_dispatched_cannot_mint_a_rust_dispatch_proof() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let command = request(
        &mut broker,
        &client,
        ControlRequest::Inventory {
            id: 1,
            session_only: None,
            known_tab_ids: None,
        },
    );
    let mut output = Vec::new();
    broker
        .extension(
            json!({
                "kind":"response", "protocol":1, "generation":broker.generation,
                "id":command["id"], "error":{
                    "kind":"not_dispatched", "message":"not sent",
                    "details":{"provenance":"local_refusal","dispatch":"skipped"}
                }
            }),
            &mut output,
        )
        .unwrap();
    assert!(output.is_empty());
    assert!(matches!(semantic_control(&mut client).into_parts().0,
        ControlEvent::Reply { id: 1, outcome: ControlOutcome::ConnectorRejected { kind, message, details: Some(details) } }
            if kind == "not_dispatched" && message == "not sent"
                && details["provenance"] == "local_refusal"));
    assert!(broker.pending.is_empty());
}

#[test]
fn duplicate_control_id_cannot_prove_the_original_written_request_undispatched() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let original = request(
        &mut broker,
        &client,
        ControlRequest::Inventory {
            id: 1,
            session_only: None,
            known_tab_ids: None,
        },
    );
    let mut output = Vec::new();
    broker.control(
        client.sender.lease.id,
        ControlRequest::Inventory {
            id: 1,
            session_only: None,
            known_tab_ids: None,
        },
        &mut output,
    );
    assert!(output.is_empty());
    assert!(matches!(semantic_control(&mut client).into_parts().0,
        ControlEvent::Reply { id:1, outcome:ControlOutcome::ConnectorRejected {kind,..} }
            if kind == "duplicate_local_id"));
    assert_eq!(
        broker.pending.len(),
        1,
        "the original written request retains custody"
    );
    reply(&mut broker, &original, json!({"tabs":[]}));
    assert!(matches!(semantic_control(&mut client).into_parts().0,
        ControlEvent::Reply { id:1, outcome:ControlOutcome::Result(result) }
            if result["tabs"] == json!([])));
    assert!(broker.pending.is_empty());
}

#[test]
fn actual_event_source_target_is_forwarded_on_the_existing_claim_route() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let mut route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let command = cdp(&mut broker, &client, &route, 1);
    for target in [Some("actual-debuggee-target"), None] {
        let mut event = json!({"kind":"event","protocol":1,
            "generation":broker.generation,"owner":command["owner"],"claim":"claim-a",
            "method":"Page.fileChooserOpened","params":{"backendNodeId":17,"targetId":"payload-target"}});
        if let Some(target) = target {
            event["sourceTargetId"] = json!(target);
        }
        let mut output = Vec::new();
        broker.extension(event, &mut output).unwrap();
        assert!(output.is_empty());
        let BrokerCdpEvent::ChromeMessage(actual) = route.events.try_recv().unwrap().into_parts().0
        else {
            panic!("real source event must remain on the existing Chrome-message route");
        };
        assert_eq!(actual["sourceTargetId"].as_str(), target);
        assert!(actual.get("sessionId").is_none());
        assert_eq!(actual["params"]["targetId"], "payload-target");
    }
    reply(&mut broker, &command, json!({"result":null}));
}

#[test]
fn malformed_event_source_target_is_rejected_before_forwarding() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let mut route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let command = cdp(&mut broker, &client, &route, 1);
    let mut output = Vec::new();
    let result = broker.extension(
        json!({"kind":"event","protocol":1,
        "generation":broker.generation,"owner":command["owner"],"claim":"claim-a",
        "method":"Page.fileChooserOpened","sourceTargetId":17,"params":{"backendNodeId":17}}),
        &mut output,
    );
    assert!(
        matches!(result, Err(BrokerError::Protocol(message)) if message == "event source target is invalid")
    );
    assert!(output.is_empty());
    assert!(route.events.try_recv().is_err());
    reply(&mut broker, &command, json!({"result":null}));
}
