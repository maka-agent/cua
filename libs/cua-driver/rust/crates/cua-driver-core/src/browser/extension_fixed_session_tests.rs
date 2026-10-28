// SPDX-License-Identifier: MIT

fn fixed_test_ui() -> ExtensionFixedUiRequest {
    ExtensionFixedUiRequest {
        operation: ExtensionFixedUiOperation::Control,
        cursor: ExtensionFixedUiCursor {
            id: "fixed-cursor".into(),
            label: "Maka 🧭".into(),
            color: ExtensionFixedUiColor::Mint,
            enabled: true,
            reduced_motion: false,
        },
        owner_epoch: "1".into(),
        point: None,
        action: ExtensionFixedUiAction::Idle,
    }
}
#[cfg(unix)]
fn fixed_test_view(provider: &ExtensionBrowserProvider, turn: &str) -> ExtensionBrowserProvider {
    provider
        .with_wire_context(ExtensionWireContext::new("fixed-owner", turn).unwrap())
        .with_host_operation(ExtensionHostOperation {
            operation_id: format!("actual-host-{turn}"),
            turn_id: turn.into(),
        })
}
#[cfg(unix)]
fn fixed_test_capabilities() -> Value {
    let mut capabilities = maka_capabilities();
    capabilities["sessionPreparation"] = json!("explicit_fixed");
    capabilities
}
#[cfg(unix)]
fn fixed_test_result(scope: &str, tab_id: u64) -> Value {
    json!({"tab":{"id":tab_id},"sessionOnly":true,"preparation":{
        "scopeId":scope,"foreignInstalled":false,"popupInstalled":false,
        "headers":{"stateConfirmed":true,"cleanupConfirmed":true,"active":false,"pendingRemoval":false},
        "ui":{"status":"attempted","acknowledged":false,"state":{"status":"ready","visible":false,"requestedPosition":null}}
    }})
}

#[test]
fn fixed_session_wire_is_finite_and_does_not_accept_executable_ui_or_malformed_epoch() {
    let valid = serde_json::to_value(fixed_test_ui()).unwrap();
    for (field, value) in [
        ("svg", json!("<svg/>")),
        ("expression", json!("arbitrary()")),
        ("nativeControl", json!({"sessionId":"forged"})),
        ("operation", json!("evaluate")),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = value;
        assert!(
            serde_json::from_value::<ExtensionFixedUiRequest>(invalid).is_err(),
            "invalid field {field}"
        );
    }
    for epoch in ["0", "01", "+1", "18446744073709551616"] {
        let mut ui = fixed_test_ui();
        ui.owner_epoch = epoch.into();
        assert!(ui.validate().is_err());
    }
    let mut ui = fixed_test_ui();
    ui.point = Some([f64::NAN, 0.0]);
    assert!(ui.validate().is_err());
    let mut ui = fixed_test_ui();
    ui.operation = ExtensionFixedUiOperation::Update;
    assert!(ui.validate_preparation().is_err());
    assert!(serde_json::from_value::<ExtensionFixedUiAck>(json!({"status":"attempted","acknowledged":true,"state":{"status":"ready","visible":false}})).is_err(), "actual renderer state requires its nullable point");
}

#[cfg(unix)]
#[tokio::test]
async fn fixed_session_service_and_actual_host_context_are_required_before_dispatch() {
    for profile in [
        None,
        Some("unknown"),
        Some("metadata_only"),
        Some("provider_session"),
    ] {
        let mut capabilities = maka_capabilities();
        capabilities["sessionTabResolution"] = json!(true);
        if let Some(profile) = profile {
            capabilities["sessionPreparation"] = json!(profile);
        }
        let (provider, mut server) = fixture_with_capabilities(capabilities);
        let view = fixed_test_view(&provider, "turn-A");
        assert!(
            matches!(view.prepare_fixed_session_tab(11,&ExtensionPreparationPolicy::default(),&fixed_test_ui()).await,Err(ExtensionProviderError::Refused{kind,..}) if kind=="unsupported")
        );
        if profile != Some("provider_session") {
            assert!(
                matches!(view.prepare_session_tab(11).await,Err(ExtensionProviderError::Refused{kind,..}) if kind=="unsupported")
            );
        }
        assert!(provider.pending_completions().await.unwrap().is_empty());
        let mut bytes = [0u8; 1];
        assert_eq!(
            server.try_read(&mut bytes).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        provider.close().await;
    }
    let (provider, mut server) = fixture_with_capabilities(fixed_test_capabilities());
    let wire_only =
        provider.with_wire_context(ExtensionWireContext::new("fixed-owner", "turn-A").unwrap());
    assert!(
        matches!(wire_only.prepare_fixed_session_tab(11,&ExtensionPreparationPolicy::default(),&fixed_test_ui()).await,Err(ExtensionProviderError::Refused{kind,..}) if kind=="context_required")
    );
    let mut bytes = [0u8; 1];
    assert_eq!(
        server.try_read(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    provider.close().await;
}

#[cfg(unix)]
#[tokio::test]
async fn fixed_session_preparation_keeps_actual_false_outcomes_and_issued_logical_receipt() {
    let (provider, mut server) = fixture_with_capabilities(fixed_test_capabilities());
    let view = fixed_test_view(&provider, "turn-A");
    let pending = view.clone();
    let call = tokio::spawn(async move {
        pending
            .prepare_fixed_session_tab(11, &ExtensionPreparationPolicy::default(), &fixed_test_ui())
            .await
    });
    let sent = request(&mut server).await;
    let id = sent["request"]["id"].as_u64().unwrap();
    let scope = sent["request"]["scopeId"].as_str().unwrap().to_owned();
    assert_eq!(sent["request"]["method"], "prepareSessionTab");
    assert_eq!(sent["request"]["tabId"], 11);
    assert_eq!(uuid::Uuid::parse_str(&scope).unwrap().to_string(), scope);
    assert!(sent["request"].get("claim").is_none());
    assert!(sent["request"]["ui"].get("svg").is_none());
    assert_eq!(
        sent["wireContext"],
        json!({"hostSessionId":"fixed-owner","hostTurnId":"turn-A"})
    );
    control_result(&mut server, id, fixed_test_result(&scope, 11)).await;
    let prepared = bounded(call).await.unwrap().unwrap();
    assert!(!prepared.foreign_installed && !prepared.popup_installed);
    assert!(matches!(
        prepared.ui,
        ExtensionFixedUiAck::Attempted {
            acknowledged: false,
            ..
        }
    ));
    assert_eq!(prepared.receipt.scope_id(), scope);
    assert_eq!(prepared.receipt.tab_id(), 11);
    assert!(!prepared.receipt.is_cleanup_only());
    assert_eq!(prepared.receipt.completion_id(), id);
    assert!(
        matches!(provider.recover_completion(id).await.unwrap(),ExtensionRecoveredOperation::FixedSessionPrepared(value) if value.receipt.scope_id()==scope)
    );
    assert!(matches!(
        provider.pending_completions().await.unwrap()[0].operation,
        ExtensionOperation::PrepareFixedSessionTab { tab_id: 11, .. }
    ));
    provider.close().await;
}

#[cfg(unix)]
#[tokio::test]
async fn fixed_preparation_wrong_tab_or_scope_never_mints_a_usable_receipt() {
    for wrong_tab in [false, true] {
        let (provider, mut server) = fixture_with_capabilities(fixed_test_capabilities());
        let pending = fixed_test_view(&provider, "turn-A");
        let call = tokio::spawn(async move {
            pending
                .prepare_fixed_session_tab(
                    11,
                    &ExtensionPreparationPolicy::default(),
                    &fixed_test_ui(),
                )
                .await
        });
        let sent = request(&mut server).await;
        let id = sent["request"]["id"].as_u64().unwrap();
        let scope = sent["request"]["scopeId"].as_str().unwrap();
        let result = if wrong_tab {
            fixed_test_result(scope, 12)
        } else {
            fixed_test_result("foreign-scope", 11)
        };
        control_result(&mut server, id, result).await;
        assert!(matches!(
            bounded(call).await.unwrap(),
            Err(ExtensionProviderError::Protocol(_))
        ));
        assert!(matches!(
            provider.recover_completion(id).await,
            Err(ExtensionProviderError::Protocol(_))
        ));
        assert_eq!(
            provider.pending_completions().await.unwrap().len(),
            1,
            "Host must retain the contradictory actual result"
        );
        let cleanup = provider.recover_fixed_session_cleanup(id).await.unwrap();
        assert!(cleanup.is_cleanup_only());
        assert_eq!(cleanup.scope_id(), scope);
        assert!(
            matches!(fixed_test_view(&provider,"turn-A").session_ui(&cleanup,&fixed_test_ui()).await,Err(ExtensionProviderError::Refused{kind,..}) if kind=="preparation_unavailable")
        );

        provider.close().await;
    }
}

#[cfg(unix)]
#[tokio::test]
async fn fixed_unknown_retains_only_exact_logical_cleanup_and_uses_current_cleanup_context() {
    let (provider, mut server) = fixture_with_capabilities(fixed_test_capabilities());
    let view = fixed_test_view(&provider, "turn-A");
    let pending = view.clone();
    let call = tokio::spawn(async move {
        pending
            .prepare_fixed_session_tab(11, &ExtensionPreparationPolicy::default(), &fixed_test_ui())
            .await
    });
    let sent = request(&mut server).await;
    let id = sent["request"]["id"].as_u64().unwrap();
    let scope = sent["request"]["scopeId"].as_str().unwrap().to_owned();
    local_ipc::write_json(&mut server,&json!({"kind":"controlEvent","event":{"kind":"reply","data":{"id":id,"outcome":{"kind":"unknown","data":{"reason":"actual pending install","details":null}}}}})).await.unwrap();
    assert!(matches!(
        bounded(call).await.unwrap(),
        Err(ExtensionProviderError::OutcomeUnknown { .. })
    ));
    let ExtensionRecoveredOperation::Unknown { custody, .. } =
        provider.recover_completion(id).await.unwrap()
    else {
        panic!("unknown must remain unknown")
    };
    assert!(custody.claim.is_none() && custody.preparation.is_none());
    let receipt = custody.fixed_session.unwrap();
    assert!(receipt.is_cleanup_only());
    assert_eq!(receipt.scope_id(), scope);
    assert!(
        matches!(view.session_ui(&receipt,&fixed_test_ui()).await,Err(ExtensionProviderError::Refused{kind,..}) if kind=="preparation_unavailable")
    );
    let cleaning = fixed_test_view(&provider, "turn-B");
    let cleanup_receipt = receipt.clone();
    let clear =
        tokio::spawn(async move { cleaning.clear_session_preparation(&cleanup_receipt).await });
    let sent = request(&mut server).await;
    let cleanup_id = sent["request"]["id"].as_u64().unwrap();
    assert_eq!(
        sent["request"],
        json!({"method":"clearSessionPreparation","id":cleanup_id,"tabId":11,"scopeId":scope})
    );
    assert_eq!(
        sent["wireContext"],
        json!({"hostSessionId":"fixed-owner","hostTurnId":"turn-B"})
    );
    assert_eq!(receipt.wire_context().host_turn_id(), "turn-A");
    control_result(
        &mut server,
        cleanup_id,
        json!({"tabId":11,"scopeId":scope,"cleanupConfirmed":true}),
    )
    .await;
    let proof = bounded(clear).await.unwrap().unwrap();
    assert_eq!(proof.scope_id(), scope);
    assert_eq!(proof.tab_id(), 11);
    provider.close().await;
}

#[cfg(unix)]
#[tokio::test]
async fn fixed_ui_requires_exact_scope_turn_except_new_epoch_configuration() {
    let (provider, mut server) = fixture_with_capabilities(fixed_test_capabilities());
    let view = fixed_test_view(&provider, "turn-A");
    let pending = view.clone();
    let call = tokio::spawn(async move {
        pending
            .prepare_fixed_session_tab(11, &ExtensionPreparationPolicy::default(), &fixed_test_ui())
            .await
    });
    let sent = request(&mut server).await;
    let id = sent["request"]["id"].as_u64().unwrap();
    let scope = sent["request"]["scopeId"].as_str().unwrap().to_owned();
    control_result(&mut server, id, fixed_test_result(&scope, 11)).await;
    let receipt = bounded(call).await.unwrap().unwrap().receipt;
    let newer = fixed_test_view(&provider, "turn-B");
    let mut ui = fixed_test_ui();
    ui.operation = ExtensionFixedUiOperation::Update;
    ui.owner_epoch = "2".into();
    assert!(
        matches!(newer.session_ui(&receipt,&ui).await,Err(ExtensionProviderError::Refused{kind,..}) if kind=="context_mismatch")
    );
    ui.operation = ExtensionFixedUiOperation::Configure;
    ui.owner_epoch = "1".into();
    assert!(
        matches!(newer.session_ui(&receipt,&ui).await,Err(ExtensionProviderError::Refused{kind,..}) if kind=="context_mismatch")
    );
    ui.owner_epoch = "2".into();
    let next = ui.clone();
    let retained = receipt.clone();
    let configure = tokio::spawn(async move { newer.session_ui(&retained, &next).await });
    let sent = request(&mut server).await;
    let update_id = sent["request"]["id"].as_u64().unwrap();
    assert_eq!(sent["request"]["method"], "sessionUi");
    assert_eq!(sent["request"]["scopeId"], scope);
    assert_eq!(sent["wireContext"]["hostTurnId"], "turn-B");
    control_result(&mut server,update_id,json!({"tabId":11,"scopeId":scope,"ui":{"status":"attempted","acknowledged":true,"state":{"status":"ready","visible":false,"requestedPosition":null}}})).await;
    assert!(matches!(
        bounded(configure).await.unwrap().unwrap().ui,
        ExtensionFixedUiAck::Attempted {
            acknowledged: true,
            ..
        }
    ));
    ui.operation = ExtensionFixedUiOperation::Update;
    assert!(
        matches!(fixed_test_view(&provider,"turn-B").session_ui(&receipt,&ui).await,
        Err(ExtensionProviderError::Refused{kind,..}) if kind=="context_mismatch"),
        "acknowledged cross-turn Configure must not rebind ordinary UI authority"
    );
    assert_eq!(receipt.wire_context().host_turn_id(), "turn-A");
    assert_eq!(receipt.ui_identity().owner_epoch(), "1");
    let mut bytes = [0u8; 1];
    assert_eq!(
        server.try_read(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "post-Configure wrong-turn Update must perform no extension dispatch"
    );
    let (foreign, _other) = fixture_with_capabilities(fixed_test_capabilities());
    assert!(
        matches!(fixed_test_view(&foreign,"turn-A").session_ui(&receipt,&fixed_test_ui()).await,Err(ExtensionProviderError::Refused{kind,..}) if kind=="preparation_unavailable")
    );
    foreign.close().await;
    provider.close().await;
}

#[cfg(unix)]
#[tokio::test]
async fn fixed_ui_minimal_retained_identity_uses_existing_budget_before_wire_dispatch() {
    let (provider, mut server) = fixture_with_capabilities_and_budget(
        fixed_test_capabilities(),
        ByteBudget::test_with_capacity(1),
    );
    let view = fixed_test_view(&provider, "turn-A");
    assert!(
        matches!(view.prepare_fixed_session_tab(11,&ExtensionPreparationPolicy::default(),&fixed_test_ui()).await,Err(ExtensionProviderError::Refused{kind,..}) if kind=="preparation_budget")
    );
    let mut bytes = [0u8; 1];
    assert_eq!(
        server.try_read(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(provider.pending_completions().await.unwrap().is_empty());
    provider.close().await;
}

#[cfg(unix)]
#[tokio::test]
async fn logical_session_events_are_charged_retained_observations_not_physical_custody() {
    let (provider, mut server) = fixture_with_capabilities(fixed_test_capabilities());
    let mut events = provider.subscribe_events();
    let scope = "11111111-1111-4111-8111-111111111111";
    for cleanup in [false, true] {
        let mut fields = json!({"generation":provider.identity().generation,"owner":"actual-native-owner","tabId":11,"scopeId":scope,"wireContext":{"hostSessionId":"fixed-owner","hostTurnId":"observed-turn"}});
        if cleanup {
            fields["cleanupConfirmed"] = json!(false);
        } else {
            fields["url"] = json!("https://popup.fixture.invalid/雪");
            fields["frameId"] = json!(4);
        }
        let kind = if cleanup {
            "sessionPreparationCleanup"
        } else {
            "sessionPopupRequested"
        };
        local_ipc::write_json(
            &mut server,
            &json!({"kind":"controlEvent","event":{"kind":kind,"data":fields}}),
        )
        .await
        .unwrap();
        loop {
            match bounded(events.recv()).await.unwrap() {
                ExtensionProviderEvent::SessionPopupRequested { request } if !cleanup => {
                    assert_eq!(request.scope_id(), scope);
                    assert_eq!(request.frame_id(), Some(4));
                    assert_eq!(request.wire_context().host_turn_id(), "observed-turn");
                    break;
                }
                ExtensionProviderEvent::SessionPreparationCleanup { observation } if cleanup => {
                    assert_eq!(observation.scope_id(), scope);
                    assert!(!observation.cleanup_confirmed());
                    break;
                }
                _ => {}
            }
        }
    }
    let ready = provider.pending_completions().await.unwrap();
    assert_eq!(ready.len(), 2);
    for receipt in ready {
        assert!(
            receipt.host_operation.is_none(),
            "an event must not invent an Agent Host operation"
        );
        assert_eq!(
            receipt.wire_context.as_ref().unwrap().host_turn_id(),
            "observed-turn"
        );
        match provider.recover_completion(receipt.id).await.unwrap() {
            ExtensionRecoveredOperation::SessionPopupRequested(request) => {
                assert_eq!(request.scope_id(), scope)
            }
            ExtensionRecoveredOperation::SessionPreparationCleanup(observation) => {
                assert_eq!(observation.scope_id(), scope)
            }
            other => panic!("logical event became a sealed claim or cleanup proof: {other:?}"),
        }
    }
    provider.close().await;
}

#[cfg(unix)]
#[tokio::test]
async fn logical_popup_creation_uses_issued_session_receipt_and_existing_created_custody() {
    let (provider, mut server) = fixture_with_capabilities(fixed_test_capabilities());
    let view = fixed_test_view(&provider, "turn-A");
    let preparing = view.clone();
    let prepare = tokio::spawn(async move {
        preparing
            .prepare_fixed_session_tab(11, &ExtensionPreparationPolicy::default(), &fixed_test_ui())
            .await
    });
    let sent = request(&mut server).await;
    let id = sent["request"]["id"].as_u64().unwrap();
    let scope = sent["request"]["scopeId"].as_str().unwrap().to_owned();
    control_result(&mut server, id, fixed_test_result(&scope, 11)).await;
    let receipt = bounded(prepare).await.unwrap().unwrap().receipt;
    let creating = view.clone();
    let opener = receipt.clone();
    let create = tokio::spawn(async move { creating.create_session_popup_tab(&opener).await });
    let sent = request(&mut server).await;
    let create_id = sent["request"]["id"].as_u64().unwrap();
    assert_eq!(
        sent["request"],
        json!({"method":"createSessionPopupTab","id":create_id,"tabId":11,"scopeId":scope})
    );
    assert!(sent["request"].get("claim").is_none());
    control_result(
        &mut server,
        create_id,
        json!({"creation":"actual-blank-child","tab":{"id":12,"url":"about:blank"}}),
    )
    .await;
    let created = bounded(create).await.unwrap().unwrap();
    assert_eq!(
        created.creation_receipt().creation_id(),
        "actual-blank-child"
    );
    assert_eq!(created.tab.id, 12);
    assert!(matches!(
        provider.recover_completion(create_id).await.unwrap(),
        ExtensionRecoveredOperation::Created(_)
    ));
    assert!(
        matches!(fixed_test_view(&provider,"turn-B").create_session_popup_tab(&receipt).await,Err(ExtensionProviderError::Refused{kind,..}) if kind=="context_mismatch")
    );
    provider.close().await;
}

#[cfg(unix)]
#[tokio::test]
async fn canceled_fixed_preparation_keeps_the_original_issued_receipt_without_replay() {
    let (provider, mut server) = fixture_with_capabilities(fixed_test_capabilities());
    let preparing = fixed_test_view(&provider, "old-turn");
    let mut events = provider.subscribe_events();
    let call = tokio::spawn(async move {
        preparing
            .prepare_fixed_session_tab(11, &ExtensionPreparationPolicy::default(), &fixed_test_ui())
            .await
    });
    let sent = request(&mut server).await;
    let id = sent["request"]["id"].as_u64().unwrap();
    let scope = sent["request"]["scopeId"].as_str().unwrap().to_owned();
    call.abort();
    let _ = call.await;
    let _newer = fixed_test_view(&provider, "new-turn");
    let pending = provider.pending_operations().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(
        pending[0].wire_context.as_ref().unwrap().host_turn_id(),
        "old-turn"
    );
    assert!(
        matches!(&pending[0].operation,ExtensionOperation::PrepareFixedSessionTab{scope_id,..} if scope_id==&scope)
    );
    control_result(&mut server, id, fixed_test_result(&scope, 11)).await;
    loop {
        if matches!(bounded(events.recv()).await.unwrap(),ExtensionProviderEvent::CompletionReady{id:actual} if actual==id)
        {
            break;
        }
    }
    let ExtensionRecoveredOperation::FixedSessionPrepared(prepared) =
        provider.recover_completion(id).await.unwrap()
    else {
        panic!("late actual response must remain an issued fixed preparation")
    };
    assert_eq!(prepared.receipt.scope_id(), scope);
    assert_eq!(prepared.receipt.wire_context().host_turn_id(), "old-turn");
    let mut bytes = [0u8; 1];
    assert_eq!(
        server.try_read(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "late recovery must not replay the mutation"
    );
    provider.acknowledge_completion(id).await.unwrap();
    assert!(provider.pending_completions().await.unwrap().is_empty());
    provider.close().await;
}
