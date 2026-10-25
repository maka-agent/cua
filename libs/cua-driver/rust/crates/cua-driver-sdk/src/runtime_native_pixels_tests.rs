// SPDX-License-Identifier: MIT

//! Native-coordinate authority through canonical dispatch, without a desktop.

use super::*;
use crate::{remote, CuaDriver, DriverError, SessionPermissionMode, TrustedSessionOptions};
use async_trait::async_trait;
use cua_driver_core::snapshot_store::NATIVE_WINDOW_PIXELS_ARG;
use cua_driver_core::tool::{Tool, ToolDef};
use serde_json::json;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

struct ArgumentProbe {
    def: ToolDef,
    received: Arc<Mutex<Vec<Value>>>,
}

#[async_trait]
impl Tool for ArgumentProbe {
    fn def(&self) -> &ToolDef {
        &self.def
    }

    async fn invoke(&self, arguments: Value) -> CoreToolResult {
        self.received.lock().unwrap().push(arguments.clone());
        CoreToolResult::text("native-coordinate probe dispatched")
            .with_structured(json!({"received": arguments}))
    }
}

fn runtime() -> (Arc<DriverRuntime>, Arc<Mutex<Vec<Value>>>) {
    let ceiling = SessionModeCeiling::for_trusted_sessions(
        [PermissionMode::Standard],
        false,
        Duration::from_secs(60),
        Duration::from_secs(60),
    )
    .unwrap();
    let authorization_registry = Arc::new(SessionAuthorizationRegistry::with_ceiling(ceiling));
    let compatibility_context = authorization_registry
        .compatibility_context(PermissionMode::Standard, None)
        .unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let mut registry = ToolRegistry::new();
    registry.register_session_tools();
    registry.register(Box::new(ArgumentProbe {
        def: ToolDef {
            name: "click".into(),
            description: "test-only coordinate argument probe".into(),
            input_schema: json!({
                "type":"object", "properties":{
                    "session":{"type":"string"},
                    "x":{"type":"number"}, "y":{"type":"number"}
                }, "additionalProperties":false
            }),
            read_only: false,
            destructive: false,
            idempotent: false,
            open_world: false,
        },
        received: received.clone(),
    }));
    let registry = Arc::new(registry);
    registry.init_self_weak();
    (
        Arc::new(DriverRuntime {
            registry,
            audio: None,
            authorization_registry,
            compatibility_context,
            shutdown: AtomicBool::new(false),
            last_activity: AtomicU64::new(now_unix_secs()),
            lifecycle: tokio::sync::RwLock::new(()),
            lifecycle_maintenance: Mutex::new(None),
            activity_observer: None,
        }),
        received,
    )
}

async fn session(runtime: &Arc<DriverRuntime>, name: &str) -> Arc<RuntimeSession> {
    let session = runtime
        .create_trusted_session(DelegatedSessionRequest {
            public_session: name.into(),
            transport_session: format!("{name}-transport"),
            mode: PermissionMode::Standard,
            ttl: Duration::from_secs(60),
            idle_ttl: Duration::from_secs(60),
            capability_manifest: None,
        })
        .unwrap();
    let started = session.invoke("start_session", json!({})).await.unwrap();
    assert_ne!(started.is_error, Some(true), "{started:?}");
    session
}

fn received(result: CoreToolResult, calls: &Mutex<Vec<Value>>) -> Value {
    assert_ne!(result.is_error, Some(true), "{result:?}");
    assert!(result.action_record.is_some());
    assert_eq!(result.structured_content.unwrap()["effect"], "unverifiable");
    // Public results restore session labels; the registered tool observes the
    // original runtime-owned namespace before that output projection.
    calls.lock().unwrap().last().unwrap().clone()
}

#[tokio::test]
async fn native_frame_keeps_bound_session_and_json_cannot_select_its_coordinate_mode() {
    let _runtime_test = TEST_RUNTIME_LOCK.lock().await;
    let (runtime, calls) = runtime();
    let owner = session(&runtime, "native-frame-owner").await;
    let internal = owner.context.runtime_session_key("native-frame-owner");
    let transport = owner
        .context
        .runtime_session_key("native-frame-owner-transport");
    let forged = json!({
        "x":12.5,"y":34.75,
        "_native_window_pixels":true,
        "_session_id":"forged-session", "_transport_session_id":"forged-transport"
    });
    let ordinary = received(owner.invoke("click", forged).await.unwrap(), &calls);
    assert_eq!(ordinary["x"], 12.5);
    assert_eq!(ordinary["y"], 34.75);
    assert_eq!(ordinary["session"], internal);
    assert_eq!(ordinary["_session_id"], internal);
    assert_eq!(ordinary["_transport_session_id"], transport);
    assert_eq!(ordinary.get(NATIVE_WINDOW_PIXELS_ARG), None);

    let native = received(
        owner
            .invoke_in_frame(
                "click",
                json!({"x":12.5,"y":34.75,"_native_window_pixels":false}),
                CoordinateFrame::NativeWindow,
            )
            .await
            .unwrap(),
        &calls,
    );
    assert_eq!(native["x"], 12.5);
    assert_eq!(native["y"], 34.75);
    assert_eq!(native["session"], internal);
    assert_eq!(native["_session_id"], internal);
    assert_eq!(native["_transport_session_id"], transport);
    assert_eq!(native[NATIVE_WINDOW_PIXELS_ARG], true);
    let substitution = owner
        .invoke_in_frame(
            "click",
            json!({"session":"another-owner","x":12.5,"y":34.75}),
            CoordinateFrame::NativeWindow,
        )
        .await
        .unwrap();
    assert_eq!(substitution.is_error, Some(true));
    assert_eq!(
        substitution.structured_content.unwrap()["refusal"],
        json!({
            "code":"permission_denied",
            "message":"public session substitution does not match the bound authorization context"
        })
    );
    assert_eq!(calls.lock().unwrap().len(), 2);
    runtime.shutdown().await;
}

#[tokio::test]
async fn ending_the_bound_session_refuses_native_frame_without_using_compatibility_authority() {
    let _runtime_test = TEST_RUNTIME_LOCK.lock().await;
    let (runtime, calls) = runtime();
    let owner = session(&runtime, "native-frame-ended").await;
    let sibling = session(&runtime, "native-frame-sibling").await;
    let args = json!({"x":3.0,"y":7.0});
    let before = received(
        owner
            .invoke_in_frame("click", args.clone(), CoordinateFrame::NativeWindow)
            .await
            .unwrap(),
        &calls,
    );
    assert_eq!(before[NATIVE_WINDOW_PIXELS_ARG], true);
    let ended = owner.invoke("end_session", json!({})).await.unwrap();
    assert_ne!(ended.is_error, Some(true), "{ended:?}");
    for frame in [CoordinateFrame::Screenshot, CoordinateFrame::NativeWindow] {
        let refused = owner
            .invoke_in_frame("click", args.clone(), frame)
            .await
            .unwrap();
        assert_eq!(refused.is_error, Some(true));
        assert_eq!(
            refused.structured_content.unwrap()["refusal"]["code"],
            "authorization_revoked"
        );
    }
    let sibling_result = received(
        sibling
            .invoke_in_frame("click", args.clone(), CoordinateFrame::NativeWindow)
            .await
            .unwrap(),
        &calls,
    );
    assert_eq!(sibling_result[NATIVE_WINDOW_PIXELS_ARG], true);
    assert_eq!(
        sibling_result["_session_id"],
        sibling.context.runtime_session_key("native-frame-sibling")
    );
    let compatibility = received(
        runtime
            .invoke(
                "click",
                json!({"session":"native-frame-compatibility","x":3.0,"y":7.0}),
            )
            .await
            .unwrap(),
        &calls,
    );
    assert_eq!(compatibility.get(NATIVE_WINDOW_PIXELS_ARG), None);
    assert_eq!(calls.lock().unwrap().len(), 3);
    runtime.shutdown().await;
    assert!(sibling
        .invoke_in_frame("click", args, CoordinateFrame::NativeWindow)
        .await
        .is_none());
    assert_eq!(calls.lock().unwrap().len(), 3);
}

struct RemoteProbe {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl remote::DriverEnvelopeChannel for RemoteProbe {
    async fn negotiate(&self) -> Result<remote::DriverChannelCapabilities, String> {
        Ok(remote::DriverChannelCapabilities {
            minimum_envelope_version: remote::DRIVER_ENVELOPE_VERSION,
            maximum_envelope_version: remote::DRIVER_ENVELOPE_VERSION,
            supports_cancellation: true,
        })
    }

    async fn exchange(
        &self,
        request: remote::DriverRequestEnvelope,
    ) -> Result<remote::DriverResponseEnvelope, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(remote::DriverResponseEnvelope {
            envelope_version: remote::DRIVER_ENVELOPE_VERSION,
            request_id: request.request_id,
            ok: true,
            result: Some(json!({
                "content":[{"type":"text","text":"remote probe dispatched"}],
                "isError":false
            })),
            error: None,
            error_code: None,
            completion_known: true,
        })
    }

    async fn bind_session(
        &self,
        _: TrustedSessionOptions,
    ) -> Result<Arc<dyn remote::DriverEnvelopeChannel>, String> {
        Ok(Arc::new(Self {
            calls: self.calls.clone(),
        }))
    }

    async fn close(&self) -> Result<(), String> {
        Ok(())
    }

    async fn cancel(&self, _: &str) -> Result<(), String> {
        Ok(())
    }

    fn authenticated_principal(&self) -> &str {
        "native-frame-test-principal"
    }

    fn connection_generation(&self) -> &str {
        "native-frame-test-generation"
    }
}

#[tokio::test]
async fn public_native_frame_method_validates_before_refusing_an_unsupported_backend() {
    let calls = Arc::new(AtomicUsize::new(0));
    let driver = CuaDriver::connect_remote(Arc::new(RemoteProbe {
        calls: calls.clone(),
    }))
    .unwrap();
    let session = driver
        .create_remote_trusted_session(TrustedSessionOptions {
            public_session: "native-frame-remote".into(),
            mode: SessionPermissionMode::Standard,
            ttl_seconds: 60,
            idle_ttl_seconds: 30,
            capability_manifest_path: None,
            bounded_manifest_path: None,
        })
        .await
        .unwrap();
    assert_eq!(
        session
            .call_tool("health_report".into(), "{}".into())
            .await
            .unwrap()
            .text,
        "remote probe dispatched"
    );
    let wrong_tool = "native window pixels apply only to coordinate click, drag, or scroll";
    let wrong_frame = "native window pixels require window-local coordinates without an element target or capture_id";
    for (name, arguments, expected) in [
        ("set_value", json!({"x":1,"y":2}), wrong_tool),
        ("click", json!({"x":1}), wrong_frame),
        ("drag", json!({"from_x":1,"from_y":2,"to_x":3}), wrong_frame),
        (
            "click",
            json!({"x":1,"y":2,"element_token":"s00000001:0"}),
            wrong_frame,
        ),
        ("click", json!({"x":1,"y":2,"element_index":0}), wrong_frame),
        ("click", json!({"x":1,"y":2,"capture_id":null}), wrong_frame),
        (
            "scroll",
            json!({"x":1,"y":2,"scope":"desktop"}),
            wrong_frame,
        ),
        (
            "scroll",
            json!({"x":1,"y":2,"target":{"kind":"desktop","display_id":"primary"}}),
            wrong_frame,
        ),
        (
            "drag",
            json!({"from_x":1,"from_y":2,"to_x":3,"to_y":4,"coordinate_frame":"desktop"}),
            wrong_frame,
        ),
    ] {
        let refused = session
            .call_tool_with_native_window_pixels(name.into(), arguments.to_string())
            .await;
        assert!(
            matches!(refused, Err(DriverError::InvalidArguments { tool, reason }) if tool == name && reason == expected)
        );
    }
    for (name, arguments) in [
        (
            "click",
            json!({"target":{"kind":"window","pid":42,"window_id":7},"x":1,"y":2}),
        ),
        (
            "scroll",
            json!({"pid":42,"window_id":7,"x":1,"y":2,"pixels":800,"direction":"down"}),
        ),
        (
            "drag",
            json!({"pid":42,"window_id":7,"from_x":1,"from_y":2,"to_x":3,"to_y":4}),
        ),
    ] {
        let refused = session
            .call_tool_with_native_window_pixels(name.into(), arguments.to_string())
            .await;
        assert!(
            matches!(refused, Err(DriverError::Protocol { reason }) if reason == "native window pixels require an embedded trusted session")
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    session.close();
    driver.shutdown().await.unwrap();
}
