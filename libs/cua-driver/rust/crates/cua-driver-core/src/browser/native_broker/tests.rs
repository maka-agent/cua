use super::*;
use std::io::Cursor;

fn fixture() -> NativeHostBroker {
    let origin = ExtensionOrigin::from_id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    let (_, mut broker, _) = NativeHostBroker::channels(origin, LocalPrincipal::UnixUid(123));
    let mut output = Vec::new();
    broker.native(json!({"kind":"hello","protocol":1,"extensionId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","instanceId":"actual-fixture-instance","capabilities":{"metadata":true,"rawTabCdp":true,"nativeWindowProof":false}}), &mut output).unwrap();
    let bound = write(output.pop().unwrap());
    assert_eq!(bound["kind"], "bound");
    broker
}

fn write(outbound: NativeOutbound) -> Value {
    let mut bytes = Vec::new();
    outbound.write_to(&mut bytes).unwrap();
    let mut reader = Cursor::new(bytes);
    let body = native_framing::read_frame(&mut reader, Direction::HostToChrome)
        .unwrap()
        .unwrap();
    assert!(
        native_framing::read_frame(&mut reader, Direction::HostToChrome)
            .unwrap()
            .is_none()
    );
    serde_json::from_slice(&body).unwrap()
}

fn admit(broker: &mut NativeHostBroker) -> ClientConnection {
    broker
        .admit(CheckedLocalPeer::from_checked_principal(
            LocalPrincipal::UnixUid(123),
        ))
        .unwrap()
}

fn request(
    broker: &mut NativeHostBroker,
    client: &ClientConnection,
    control: ControlRequest,
) -> Value {
    let mut output = Vec::new();
    broker.control(client.sender.lease.id, control, &mut output);
    assert_eq!(output.len(), 1, "control should dispatch exactly once");
    write(output.pop().unwrap())
}

fn reply(broker: &mut NativeHostBroker, command: &Value, result: Value) {
    let mut output = Vec::new();
    broker.native(json!({"kind":"response","protocol":1,"generation":broker.generation,"id":command["id"],"result":result}), &mut output).unwrap();
    assert!(output.is_empty(), "a matched reply must not replay work");
}

fn attach(
    broker: &mut NativeHostBroker,
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
        matches!(client.events.try_recv().unwrap().into_parts().0, ControlEvent::Reply { id: actual, outcome: ControlOutcome::Result(_) } if actual == id)
    );
    broker.bind_route(client.sender.lease.id, token).unwrap()
}

fn cdp(
    broker: &mut NativeHostBroker,
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
    let a = request(&mut broker, &first, ControlRequest::Inventory { id: 1 });
    let b = request(&mut broker, &second, ControlRequest::Inventory { id: 1 });
    assert_ne!(a["owner"], b["owner"]);
    assert_eq!(a["id"], "1");
    assert_eq!(b["id"], "2");
}

#[test]
fn out_of_order_control_results_keep_the_original_client_and_local_id() {
    let mut broker = fixture();
    let mut first = admit(&mut broker);
    let mut second = admit(&mut broker);
    let a = request(&mut broker, &first, ControlRequest::Inventory { id: 1 });
    let b = request(&mut broker, &second, ControlRequest::Inventory { id: 1 });
    reply(
        &mut broker,
        &b,
        json!({"tabs":[{"id":22,"lastAccessed":123.5}]}),
    );
    reply(&mut broker, &a, json!({"tabs":[{"id":11}]}));
    assert!(
        matches!(first.events.try_recv().unwrap().into_parts().0, ControlEvent::Reply { id:1, outcome:ControlOutcome::Result(value) } if value["tabs"][0]["id"] == 11)
    );
    assert!(
        matches!(second.events.try_recv().unwrap().into_parts().0, ControlEvent::Reply { id:1, outcome:ControlOutcome::Result(value) } if value["tabs"][0]["lastAccessed"] == 123.5)
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
    broker.native(json!({"kind":"response","protocol":1,"generation":broker.generation,"id":first["id"],"error":{"kind":"chrome_rejected","message":"actual Chrome fixture rejection"}}), &mut output).unwrap();
    assert!(
        matches!(route.events.try_recv().unwrap().into_parts().0, BrokerCdpEvent::ChromeMessage(value) if value["error"]["message"] == "actual Chrome fixture rejection")
    );
    let second = cdp(&mut broker, &client, &route, 2);
    broker.native(json!({"kind":"response","protocol":1,"generation":broker.generation,"id":second["id"],"error":{"kind":"unsupported","message":"Browser domain unavailable"}}), &mut output).unwrap();
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
        first.events.try_recv().unwrap().into_parts().0,
        BrokerCdpEvent::TransportFailure(_)
    ));
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
        matches!(client.events.try_recv().unwrap().into_parts().0, ControlEvent::OrphanCdpCompletion { route, claim, id:1, event:BrokerCdpEvent::ChromeMessage(value),.. } if route == first.sender.lease.id.0 && claim == "claim-a" && value["result"]["acknowledged"] == "once")
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
        ControlRequest::Inventory { id: 1 },
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
fn native_eof_closes_all_routes_and_fences_previously_queued_frames() {
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
    broker.end_generation("fixture native EOF");
    assert!(
        matches!(route.events.try_recv().unwrap().into_parts().0, BrokerCdpEvent::TransportFailure(reason) if reason.contains("do not replay"))
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
    broker.native(json!({"kind":"event","protocol":1,"generation":broker.generation,"owner":command["owner"],"claim":"claim-a","method":"Runtime.consoleAPICalled","params":{"type":"log"}}), &mut output).unwrap();
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
    broker.native(json!({"kind":"revoked","protocol":1,"generation":broker.generation,"owner":command["owner"],"claim":"claim-a","reason":"canceled_by_user"}), &mut output).unwrap();
    reply(
        &mut broker,
        &command,
        json!({"claim":"claim-a","tabId":11,"targetId":"opaque-target-11"}),
    );
    assert!(matches!(
        client.events.try_recv().unwrap().into_parts().0,
        ControlEvent::ClaimUnavailable { .. }
    ));
    assert!(matches!(
        client.events.try_recv().unwrap().into_parts().0,
        ControlEvent::Reply {
            id: 1,
            outcome: ControlOutcome::Unknown { .. }
        }
    ));
    assert!(broker
        .bind_route(client.sender.lease.id, "claim-a")
        .is_err());
    assert!(!broker.stopped);
    let _ = request(&mut broker, &other, ControlRequest::Inventory { id: 1 });
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
    broker.native(json!({"kind":"effects_cleanup","protocol":1,"generation":broker.generation,"owner":owner,"claim":"claim-a","effect":"scoped_headers","cleanupConfirmed":false,"error":"actual header cleanup fixture error"}), &mut output).unwrap();
    assert!(
        matches!(client.events.try_recv().unwrap().into_parts().0, ControlEvent::EffectsCleanup { claim, effect, cleanup_confirmed:false, error:Some(error) } if claim == "claim-a" && effect == "scoped_headers" && error == "actual header cleanup fixture error")
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
    broker.native(json!({"kind":"effects_cleanup","protocol":1,"generation":broker.generation,"owner":owner,"claim":"claim-a","effect":"scoped_headers","cleanupConfirmed":false,"error":diagnostic}), &mut output).unwrap();
    let ControlEvent::EffectsCleanup {
        claim,
        effect,
        cleanup_confirmed,
        error,
    } = client.events.try_recv().unwrap().into_parts().0
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
        let failure = broker.native(json!({"kind":"effects_cleanup","protocol":1,"generation":broker.generation,"owner":owner,"claim":"claim-a","effect":"scoped_headers","cleanupConfirmed":false,"error":malformed}), &mut output);
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
    let outbound = NativeOutbound {
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
        &native_framing::read_frame(&mut reader, Direction::HostToChrome)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let cancel: Value = serde_json::from_slice(
        &native_framing::read_frame(&mut reader, Direction::HostToChrome)
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
        native_framing::read_frame(&mut reader, Direction::HostToChrome)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn async_actor_publishes_only_the_actual_successful_hello_identity() {
    let origin = ExtensionOrigin::from_id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    let (handle, broker, mut native) =
        NativeHostBroker::channels(origin, LocalPrincipal::UnixUid(123));
    let task = tokio::spawn(broker.run());
    assert!(matches!(
        handle.identity().await,
        Err(BrokerError::NotReady)
    ));
    handle.native_message(json!({"kind":"hello","protocol":1,"extensionId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","instanceId":"actual-instance","capabilities":{"metadata":true,"nativeWindowProof":false}})).await.unwrap();
    let bound = write(native.recv().await.unwrap());
    let identity = handle.identity().await.unwrap();
    assert_eq!(identity.instance_id, "actual-instance");
    assert_eq!(identity.generation, bound["generation"]);
    assert_eq!(
        identity.capabilities,
        json!({"metadata":true,"nativeWindowProof":false})
    );
    handle.native_eof("fixture EOF").await;
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
    broker.native(json!({"kind":"response","protocol":1,"generation":broker.generation,"id":command["id"],"error":{"kind":"outcome_unknown","message":"cleanup was not confirmed","details":details}}),&mut output).unwrap();
    assert!(
        matches!(client.events.try_recv().unwrap().into_parts().0,ControlEvent::Reply{id:1,outcome:ControlOutcome::Unknown{details:Some(actual),..}} if actual==details)
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
async fn immutable_wire_context_is_attached_per_request_and_absent_from_own_chrome_json() {
    let origin = ExtensionOrigin::from_id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    let (handle, broker, mut native) =
        NativeHostBroker::channels(origin, LocalPrincipal::UnixUid(123));
    let task = tokio::spawn(broker.run());
    handle.native_message(json!({"kind":"hello","protocol":1,"extensionId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","instanceId":"actual-instance","capabilities":{"metadata":true}})).await.unwrap();
    let _ = write(native.recv().await.unwrap());
    let client = handle
        .admit_peer(CheckedLocalPeer::from_checked_principal(
            LocalPrincipal::UnixUid(123),
        ))
        .await
        .unwrap();
    let first = NativeWireContext::new("actual-host-session", "trusted-turn-one").unwrap();
    let second = NativeWireContext::new("actual-host-session", "trusted-turn-two").unwrap();
    client
        .sender
        .control_with_context(ControlRequest::Inventory { id: 1 }, Some(first.clone()))
        .await
        .unwrap();
    client
        .sender
        .control_with_context(ControlRequest::Inventory { id: 2 }, Some(second.clone()))
        .await
        .unwrap();
    let first_out = native.recv().await.unwrap();
    let second_out = native.recv().await.unwrap();
    assert_eq!(first_out.wire_context(), Some(&first));
    assert_eq!(second_out.wire_context(), Some(&second));
    assert!(
        write(first_out).get("wireContext").is_none(),
        "own Chrome protocol is unchanged"
    );
    assert!(write(second_out).get("wireContext").is_none());
    handle.native_eof("fixture EOF").await;
    task.await.unwrap();
}

#[test]
fn orphan_cdp_ack_uses_originating_context_instead_of_arrival_context() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let original = NativeWireContext::new("actual-host-session", "old-trusted-turn").unwrap();
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
        Some(NativeWireContext::new("actual-host-session", "different-current-turn").unwrap());
    reply(&mut broker, &command, json!({"result":{"actual":"ack"}}));
    assert!(
        matches!(client.events.try_recv().unwrap().into_parts().0,ControlEvent::OrphanCdpCompletion{wire_context:Some(context),..} if context==original)
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
    broker.native(json!({"kind":"download_changed","protocol":1,"generation":broker.generation,"download":{"id":"0","filename":"","url":"https://fixture.invalid/actual-final","status":"started"}}),&mut output).unwrap();
    let a = first.events.try_recv().unwrap().into_parts().0;
    let b = second.events.try_recv().unwrap().into_parts().0;
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
    let context = NativeWireContext::new("trusted-session", "trusted-turn").unwrap();
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
    match client.events.try_recv().unwrap().into_parts().0 {
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
    assert!(matches!(other.events.try_recv().unwrap().into_parts().0,
        ControlEvent::Reply { outcome: ControlOutcome::ConnectorRejected { kind, .. }, .. } if kind == "claim_unavailable"));
    broker.control(owner.sender.lease.id, cursor(2, f64::NAN), &mut output);
    assert!(output.is_empty());
    assert!(matches!(owner.events.try_recv().unwrap().into_parts().0,
        ControlEvent::Reply { outcome: ControlOutcome::ConnectorRejected { kind, .. }, .. } if kind == "invalid_request"));
    broker.claims.get_mut("claim-a").unwrap().cleanup_only = true;
    broker.control(owner.sender.lease.id, cursor(3, 12.5), &mut output);
    assert!(output.is_empty());
    assert!(matches!(owner.events.try_recv().unwrap().into_parts().0,
        ControlEvent::Reply { outcome: ControlOutcome::ConnectorRejected { kind, .. }, .. } if kind == "claim_unavailable"));
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
    assert!(matches!(client.events.try_recv().unwrap().into_parts().0,
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
    let client = admit(&mut broker);
    let mut output = Vec::new();
    broker.control(
        client.sender.lease.id,
        ControlRequest::Inventory { id: 1 },
        &mut output,
    );
    let first = output.pop().unwrap().into_adapter_request();
    let first_guard = first.guard.clone();
    assert_eq!(first.semantic_id.as_deref(), Some("1"));
    assert!(matches!(
        first_guard.reject_before_write("fixture_refusal".to_owned(), "not sent".to_owned()),
        Some(WriteReport::LocalRejected { outer: 1, .. })
    ));
    assert!(!first_guard.start_write());
    assert!(!first_guard.was_started());
    assert!(first_guard
        .reject_before_write("repeat".to_owned(), "not sent".to_owned())
        .is_none());
    assert!(first_guard.written_report().is_none());

    broker.control(
        client.sender.lease.id,
        ControlRequest::Inventory { id: 2 },
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
        "later native phases do not create a second semantic dispatch ACK"
    );
    writer_guard
        .fences
        .last()
        .unwrap()
        .store(false, Ordering::SeqCst);
    assert!(
        !second.guard.start_write(),
        "followup native phase keeps the exact original owner fence"
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
    broker: &mut NativeHostBroker,
    client: &ClientConnection,
    request: ControlRequest,
    context: Option<&NativeWireContext>,
) -> NativeAdapterRequest {
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
    let scope = NativeWireContext::new("trusted-session", "trusted-turn").unwrap();
    let other_turn = NativeWireContext::new("trusted-session", "other-turn").unwrap();
    let other_session = NativeWireContext::new("other-session", "trusted-turn").unwrap();
    let same = queued_control_with_context(
        &mut broker,
        &first,
        ControlRequest::Inventory { id: 1 },
        Some(&scope),
    );
    let sibling_turn = queued_control_with_context(
        &mut broker,
        &first,
        ControlRequest::Inventory { id: 2 },
        Some(&other_turn),
    );
    let sibling_session = queued_control_with_context(
        &mut broker,
        &first,
        ControlRequest::Inventory { id: 3 },
        Some(&other_session),
    );
    let sibling_client = queued_control_with_context(
        &mut broker,
        &second,
        ControlRequest::Inventory { id: 1 },
        Some(&scope),
    );
    let no_context = queued_control_with_context(
        &mut broker,
        &first,
        ControlRequest::Inventory { id: 4 },
        None,
    );
    let cleanup = queued_control_with_context(
        &mut broker,
        &first,
        ControlRequest::StopCreatedTab {
            id: 5,
            creation: "fixture-opaque-creation".to_owned(),
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
        "unsent old work cannot start a native phase after Finish admission"
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
    let scope = NativeWireContext::new("trusted-session", "trusted-turn").unwrap();
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
    broker.native(json!({"kind":"response","protocol":1,"generation":broker.generation,"id":command["id"],
        "error":{"kind":"outcome_unknown","message":"follow-up phase fenced after actual attach ACK",
            "details":{"custody":{"claim":"late-custody","tabId":11,"targetId":"actual-target"}}}}), &mut output).unwrap();
    assert!(matches!(client.events.try_recv().unwrap().into_parts().0,
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
    broker: &mut NativeHostBroker,
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
        "a local fence must not dispatch a native RPC"
    );
    match client.events.try_recv().unwrap().into_parts().0 {
        ControlEvent::Reply {
            id: actual,
            outcome: ControlOutcome::Result(snapshot),
        } if actual == id => snapshot,
        event => panic!("expected exact local fence reply {id}, got {event:?}"),
    }
}

fn expect_cdp_progress(client: &mut ClientConnection, claim: &str) {
    assert!(
        matches!(client.events.try_recv().unwrap().into_parts().0, ControlEvent::ClaimCdpProgress { claim: actual } if actual == claim)
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
        matches!(client.events.try_recv().unwrap().into_parts().0, ControlEvent::OrphanCdpCompletion { id:2,event:BrokerCdpEvent::LocalRejected { code, .. }, .. } if code == "not_dispatched")
    );
    expect_cdp_progress(&mut client, "claim-a");
    let waiting = fenced_snapshot(&mut broker, &mut client, 4, "claim-a");
    assert_eq!(waiting["pending"].as_array().unwrap().len(), 1);
    assert_eq!(waiting["pending"][0]["id"], 1);
    reply(&mut broker, &written, json!({"result":{"actual":"ack"}}));
    assert!(
        matches!(client.events.try_recv().unwrap().into_parts().0, ControlEvent::OrphanCdpCompletion { id:1,event:BrokerCdpEvent::ChromeMessage(value), .. } if value["result"]["actual"] == "ack")
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
fn unknown_cdp_cannot_be_cleared_by_duplicate_reply_detach_ack_or_generation_eof() {
    let mut broker = fixture();
    let mut client = admit(&mut broker);
    let route = attach(&mut broker, &mut client, 1, 11, "claim-a");
    let command = cdp(&mut broker, &client, &route, 1);
    fenced_snapshot(&mut broker, &mut client, 2, "claim-a");
    let mut output = Vec::new();
    broker.native_with_provenance(json!({"kind":"response","protocol":1,"generation":broker.generation,"id":command["id"],"error":{"kind":"outcome_unknown","message":"fixture ACK unavailable","details":{"nativeAcknowledged":true}}}), NativeReplyProvenance::Adapted, &mut output).unwrap();
    assert!(matches!(
        client.events.try_recv().unwrap().into_parts().0,
        ControlEvent::OrphanCdpCompletion {
            event: BrokerCdpEvent::TransportFailure(reason),
            ..
        } if reason == "native claim request ended: outcome_unknown: fixture ACK unavailable"
    ));
    expect_cdp_progress(&mut client, "claim-a");
    let snapshot = fenced_snapshot(&mut broker, &mut client, 3, "claim-a");
    assert_eq!(snapshot["pending"].as_array().unwrap().len(), 1);
    assert_eq!(snapshot["pending"][0]["unknownReason"], UNKNOWN_CDP_REASON);
    reply(&mut broker, &command, json!({"result":{"late":true}}));
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
        client.events.try_recv().unwrap().into_parts().0,
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
        client.events.try_recv().unwrap().into_parts().0,
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
        client.events.try_recv().unwrap().into_parts().0,
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
        client.events.try_recv().unwrap().into_parts().0,
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
        peer.events.try_recv().unwrap().into_parts().0,
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
        client.events.try_recv().unwrap().into_parts().0,
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
    broker.native(json!({"kind":"revoked","protocol":1,"generation":broker.generation,"owner":owner,"claim":"claim-a","reason":"actual debugger detach fixture"}), &mut output).unwrap();
    assert!(
        matches!(client.events.try_recv().unwrap().into_parts().0, ControlEvent::ClaimUnavailable { claim, .. } if claim == "claim-a")
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
        client.events.try_recv().unwrap().into_parts().0,
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
        Some(NativeWireContext::new("actual-session-fixture", "actual-turn-fixture").unwrap());
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
    let (event, charge) = client.events.try_recv().unwrap().into_parts();
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
async fn snapshot_budget_exhaustion_is_unknown_and_closes_only_its_own_peer() {
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
    assert!(
        matches!(client.events.try_recv().unwrap().into_parts().0, ControlEvent::Reply { id:2,outcome:ControlOutcome::Unknown { reason, .. }} if reason == "claim CDP snapshot could not enter the bounded delivery queue")
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
                .control_with_context(ControlRequest::Inventory { id: 3 }, None)
                .await,
            Err(BrokerError::Closed)
        ),
        "closing the lease must stop new wire admission"
    );
    assert_eq!(output.len(), 1);
    assert_eq!(
        output[0].value["method"], "closeOwner",
        "owner transport cleanup is separate from a CDP drain proof"
    );
    drop(first);
    drop(second);
}

#[test]
fn actual_native_reply_can_end_raw_wait_while_its_effect_remains_unknown() {
    use super::super::native_wire::MatchedNativeReply;

    for matched in [false, true] {
        let mut broker = fixture();
        let mut client = admit(&mut broker);
        let route = attach(&mut broker, &mut client, 1, 11, "claim-a");
        let context = NativeWireContext::new("actual-session", "actual-turn").unwrap();
        broker.input_context = Some(context.clone());
        let command = cdp(&mut broker, &client, &route, 1);
        broker.input_context = None;
        fenced_snapshot(&mut broker, &mut client, 2, "claim-a");
        let provenance = if matched {
            NativeReplyProvenance::Matched(MatchedNativeReply::from_matched_rpc(
                broker.generation.clone(),
                broker.clients[&client.sender.lease.id].owner.clone(),
                command["id"].as_str().unwrap().to_owned(),
                Some(context),
            ))
        } else {
            NativeReplyProvenance::DirectNative
        };
        let mut output = Vec::new();
        broker.native_with_provenance(json!({"kind":"response","protocol":1,"generation":broker.generation,"id":command["id"],"error":{"kind":"outcome_unknown","message":"native request answered after caller cancellation"}}), provenance, &mut output).unwrap();
        assert!(
            matches!(client.events.try_recv().unwrap().into_parts().0, ControlEvent::OrphanCdpCompletion { event:BrokerCdpEvent::TransportFailure(reason), .. } if reason == "native claim request ended: outcome_unknown: native request answered after caller cancellation")
        );
        expect_cdp_progress(&mut client, "claim-a");
        let snapshot = fenced_snapshot(&mut broker, &mut client, 3, "claim-a");
        assert!(
            snapshot["pending"].as_array().unwrap().is_empty(),
            "an actual native terminal reply ends the raw wait"
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
    use super::super::native_wire::MatchedNativeReply;

    for changed in ["generation", "owner", "outer", "context"] {
        let mut broker = fixture();
        let mut client = admit(&mut broker);
        let route = attach(&mut broker, &mut client, 1, 11, "claim-a");
        let context = NativeWireContext::new("actual-session", "actual-turn").unwrap();
        broker.input_context = Some(context.clone());
        let command = cdp(&mut broker, &client, &route, 1);
        broker.input_context = None;
        fenced_snapshot(&mut broker, &mut client, 2, "claim-a");
        let proof = MatchedNativeReply::from_matched_rpc(
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
                NativeWireContext::new("actual-session", "foreign-turn").unwrap()
            } else {
                context
            }),
        );
        let mut output = Vec::new();
        let error = broker.native_with_provenance(json!({"kind":"response","protocol":1,"generation":broker.generation,"id":command["id"],"result":{"result":{"ack":true}}}), NativeReplyProvenance::Matched(proof), &mut output);
        assert!(
            matches!(error, Err(BrokerError::Protocol(message)) if message == "matched native reply changed its pending association"),
            "changed {changed} cannot authenticate another request's terminal result"
        );
        assert!(broker
            .pending
            .contains_key(&canonical_id(command["id"].as_str()).unwrap()));
        assert!(client.events.try_recv().is_err());
        broker.end_generation("matched association protocol failure");
        assert!(matches!(
            client.events.try_recv().unwrap().into_parts().0,
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
            client.events.try_recv().unwrap().into_parts().0,
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
    let context = NativeWireContext::new(
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
