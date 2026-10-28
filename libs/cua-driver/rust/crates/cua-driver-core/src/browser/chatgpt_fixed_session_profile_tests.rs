// SPDX-License-Identifier: MIT

use super::*;

#[test]
fn actual_original_hello_reports_provider_session_without_claiming_the_fixed_service() {
    let generation = "11111111-1111-4111-8111-111111111111";
    let extension = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let now = Instant::now();
    let mut adapter = ChatgptWireAdapter::new(generation.into(), extension.into()).unwrap();
    let startup = adapter.start(now).unwrap();
    let request = startup
        .iter()
        .find_map(|action| match action {
            ExtensionWireAction::ExtensionFrame { message, .. } => Some(message),
            _ => None,
        })
        .unwrap();
    assert_eq!(request["method"], "getInfo");
    let actual=adapter.on_extension(json!({"jsonrpc":"2.0","id":request["id"],"result":{"type":"extension","version":"observed","metadata":{"extensionId":extension,"extensionInstanceId":"actual-instance"}}}),now).unwrap();
    let hello = actual
        .iter()
        .find_map(|action| match action {
            ExtensionWireAction::BrokerMessage(value) if value["kind"] == "hello" => Some(value),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        hello["capabilities"]["sessionPreparation"],
        "provider_session"
    );
    let context =
        ExtensionWireContext::new("22222222-2222-4222-8222-222222222222", "actual-turn").unwrap();
    let unsupported=adapter.on_semantic(json!({"kind":"request","protocol":1,"generation":generation,"id":"1","owner":"actual-owner","method":"prepareSessionTab","params":{"tabId":11,"scopeId":"33333333-3333-4333-8333-333333333333","policy":{"popupEnabled":false,"headerEnabled":false,"headers":[]},"ui":{}}}),Some(&context),now);
    match unsupported {
        Err(ExtensionWireError::LocalRefusal { code, .. }) => assert_eq!(code, "unsupported"),
        Ok(actions) => {
            assert!(
                actions.iter().any(|action| matches!(action,
                ExtensionWireAction::BrokerMessage(value)
                    if value["kind"] == "response" && value["id"] == "1"
                    && value["error"]["kind"] == "unsupported")),
                "fixed service must return its exact unsupported refusal"
            );
            assert!(
                !actions
                    .iter()
                    .any(|action| matches!(action, ExtensionWireAction::ExtensionFrame { .. })),
                "unsupported Maka fixed service must not become another ChatGPT RPC or exec fallback"
            );
        }
        other => panic!("fixed service must be an explicit unsupported operation: {other:?}"),
    }
}
