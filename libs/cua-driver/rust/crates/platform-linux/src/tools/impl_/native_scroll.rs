// SPDX-License-Identifier: MIT

use cua_driver_core::action_record::{
    ActionEffect, ActionExecutionRecord, ActionTransport, ActualDelivery, RequestedDelivery,
};
use cua_driver_core::protocol::ToolResult;
use serde_json::{json, Value};

use crate::input::native_element::NativeElementScrollRequest;
use crate::input::native_window::{
    NativeWindowOutcome, NativeWindowPhase, NativeWindowSetupFailure,
};

pub(super) async fn invoke(args: Value, request: NativeElementScrollRequest) -> ToolResult {
    invoke_on_route(args, request, crate::wayland::is_wayland()).await
}

async fn invoke_on_route(
    args: Value,
    request: NativeElementScrollRequest,
    selected_wayland: bool,
) -> ToolResult {
    if selected_wayland {
        let code = crate::atspi::native_observation::X11_ROUTE_REQUIRED;
        return refusal(code, code);
    }
    if !request.matches_arguments(&args) {
        return refusal(
            "native_element_request_mismatch",
            "native element scroll data does not match the authorized arguments",
        );
    }
    let Some(session) = args.get("_session_id").and_then(Value::as_str) else {
        return refusal(
            "native_element_lifecycle_required",
            "native element scroll requires an admitted lifecycle",
        );
    };
    if cua_driver_core::session::is_session_ending(session) {
        return refusal(
            "action_cancelled",
            "native element scroll invocation was cancelled",
        );
    }
    let observation = match crate::atspi::native_observation::for_window(
        request.pid,
        u64::from(request.window_id),
    ) {
        Ok(Some(observation)) => observation,
        Ok(None) => {
            return refusal(
                "native_element_context_required",
                "native element scroll requires its scoped lookup context",
            );
        }
        Err(error) => {
            return refusal("native_element_context_mismatch", &error.to_string());
        }
    };
    if let Some(reason) = observation.stop_reason() {
        return refusal("action_cancelled", reason);
    }
    let Some(lease) = cua_driver_core::tool::current_native_input_worker_lease() else {
        return refusal(
            "native_element_admission_required",
            "native element scroll requires the original admitted input operation",
        );
    };
    let session_id = session.to_owned();
    let outcome = tokio::task::spawn_blocking(move || {
        // The original input/cursor/session admission covers fresh lookup,
        // position, the entire wheel train, and final focus cleanup.
        let _lease = lease;
        crate::atspi::native::scroll_native_element(&request, observation, &session_id)
    })
    .await;
    match outcome {
        Ok(outcome) => native_result(outcome),
        Err(error) => ToolResult::error(format!(
            "native element scroll worker did not complete normally: {error}"
        ))
        .with_structured(
            json!({"code":"input_outcome_unknown","effect":"unverifiable","verified":false}),
        )
        .with_action_record(delivery_record(
            ActionEffect::Unverifiable,
            ActualDelivery::Unknown,
            None,
        )),
    }
}

fn refusal(code: &str, reason: &str) -> ToolResult {
    ToolResult::error(reason)
        .with_structured(json!({"code":code,"effect":"refused"}))
        .with_action_record(
            ActionExecutionRecord::builder(
                ActionEffect::Refused,
                ActionTransport::LinuxXSendEvent,
                RequestedDelivery::Background,
            )
            .refusal(code, None)
            .build()
            .expect("a refused native element scroll has no delivery"),
        )
}

fn delivery_record(
    effect: ActionEffect,
    delivery: ActualDelivery,
    completed: Option<u32>,
) -> ActionExecutionRecord {
    let mut record = ActionExecutionRecord::builder(
        effect,
        ActionTransport::LinuxXSendEvent,
        RequestedDelivery::Background,
    )
    .actual_delivery(delivery);
    if let Some(completed) = completed {
        record = record.delivered_count(completed);
    }
    record
        .build()
        .expect("native element wheel records preserve known completed pair counts")
}

fn native_result(
    outcome: Result<NativeWindowOutcome<(), anyhow::Error>, NativeWindowSetupFailure>,
) -> ToolResult {
    match outcome {
        Ok(NativeWindowOutcome {
            result: Ok(()),
            phase,
        }) => ToolResult::text(
            "Native element wheel train posted; application effect remains unverified.",
        )
        .with_structured(json!({
            "effect":"unverifiable","verified":false,
            "completed_button_pairs":phase.completed_button_pairs,
        }))
        .with_action_record(delivery_record(
            ActionEffect::Unverifiable,
            ActualDelivery::Background,
            Some(phase.completed_button_pairs),
        )),
        Ok(NativeWindowOutcome {
            result: Err(error),
            phase,
        })
        | Err(NativeWindowSetupFailure { error, phase }) => failed(error, phase),
    }
}

fn failed(error: anyhow::Error, phase: NativeWindowPhase) -> ToolResult {
    if !phase.input_attempted {
        // Keep the original native text through Main's existing element
        // boundary; refusal proves no focus/motion/wheel input was attempted.
        return refusal("input_preparation_failed", &error.to_string());
    }
    let effect = if phase.completed_button_pairs > 0 {
        ActionEffect::Partial
    } else {
        ActionEffect::Unverifiable
    };
    ToolResult::error(error.to_string())
        .with_structured(json!({
            "code":"input_outcome_unknown",
            "effect":if effect == ActionEffect::Partial { "partial" } else { "unverifiable" },
            "verified":false,"completed_button_pairs":phase.completed_button_pairs,
        }))
        .with_action_record(delivery_record(
            effect,
            ActualDelivery::Background,
            Some(phase.completed_button_pairs),
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::native_window::NativeScrollDirection;

    fn request() -> NativeElementScrollRequest {
        NativeElementScrollRequest {
            pid: 123,
            window_id: 456,
            element_id: ":1.0:/org/a11y/atspi/accessible/5".into(),
            direction: NativeScrollDirection::Down,
            pixels: 100,
            deadline: None,
        }
    }

    #[tokio::test]
    async fn native_scroll_sidecar_reaches_actual_tool_before_generic_zero_pixel_parse() {
        use cua_driver_core::tool::Tool;

        // Construct only in-memory state. No user configuration or desktop
        // service is consulted before the typed lifecycle guard.
        let state = std::sync::Arc::new(super::super::ToolState {
            snapshots: std::sync::Arc::new(crate::atspi::Snapshots::new()),
            cursor_registry: std::sync::Arc::new(cursor_overlay::CursorRegistry::new()),
            capture_service: std::sync::Arc::new(
                cua_driver_core::capture_runtime::CaptureService::default(),
            ),
            mouse_hold: std::sync::Mutex::new(Default::default()),
            config: std::sync::Arc::new(std::sync::RwLock::new(Default::default())),
        });
        let tool = super::super::ScrollTool { state };
        let mut request = request();
        request.pixels = 0;
        let args = request.arguments();
        let result =
            crate::input::native_element::with_native_element_scroll(request, tool.invoke(args))
                .await;
        assert_eq!(
            result.structured_content.unwrap()["code"],
            if crate::wayland::is_wayland() {
                crate::atspi::native_observation::X11_ROUTE_REQUIRED
            } else {
                "native_element_lifecycle_required"
            }
        );
        let record = result.action_record.unwrap();
        assert_eq!(record.effect, ActionEffect::Refused);
        assert_eq!(record.actual_delivery, None);
    }

    #[tokio::test]
    async fn native_scroll_guards_refuse_before_lookup_or_input() {
        let request = request();
        let result = invoke_on_route(request.arguments(), request.clone(), true).await;
        assert_eq!(
            result.structured_content.unwrap()["code"],
            crate::atspi::native_observation::X11_ROUTE_REQUIRED
        );
        let mut substituted = request.arguments();
        substituted["element_token"] = "forged".into();
        let result = invoke_on_route(substituted, request.clone(), false).await;
        assert_eq!(
            result.structured_content.unwrap()["code"],
            "native_element_request_mismatch"
        );
        let result = invoke_on_route(request.arguments(), request, false).await;
        assert_eq!(
            result.structured_content.unwrap()["code"],
            "native_element_lifecycle_required"
        );
    }

    #[test]
    fn native_scroll_errors_keep_text_and_distinguish_no_input_focus_and_partial_wheel() {
        for (phase, effect, actual, count, code) in [
            (
                NativeWindowPhase::default(),
                ActionEffect::Refused,
                None,
                None,
                "input_preparation_failed",
            ),
            (
                NativeWindowPhase {
                    input_attempted: true,
                    completed_button_pairs: 0,
                },
                ActionEffect::Unverifiable,
                Some(ActualDelivery::Background),
                Some(0),
                "input_outcome_unknown",
            ),
            (
                NativeWindowPhase {
                    input_attempted: true,
                    completed_button_pairs: 2,
                },
                ActionEffect::Partial,
                Some(ActualDelivery::Background),
                Some(2),
                "input_outcome_unknown",
            ),
        ] {
            let result = native_result(Ok(NativeWindowOutcome {
                result: Err(anyhow::anyhow!("original native error")),
                phase,
            }));
            assert_eq!(
                serde_json::to_value(&result.content).unwrap()[0]["text"],
                "original native error"
            );
            assert_eq!(result.structured_content.as_ref().unwrap()["code"], code);
            let record = result.action_record.unwrap();
            assert_eq!(record.effect, effect);
            assert_eq!(record.transport, ActionTransport::LinuxXSendEvent);
            assert_eq!(record.actual_delivery, actual);
            assert_eq!(record.delivered_count, count);
            assert!(record.public_result().is_ok());
        }
    }

    #[test]
    fn native_scroll_setup_error_retains_focus_phase_and_success_retains_actual_pairs() {
        let phase = NativeWindowPhase {
            input_attempted: true,
            completed_button_pairs: 0,
        };
        let result = native_result(Err(NativeWindowSetupFailure {
            error: anyhow::anyhow!("focus setup failed"),
            phase,
        }));
        assert_eq!(
            result.structured_content.unwrap()["code"],
            "input_outcome_unknown"
        );
        assert_eq!(
            result.action_record.unwrap().effect,
            ActionEffect::Unverifiable
        );
        let result = native_result(Ok(NativeWindowOutcome {
            result: Ok(()),
            phase: NativeWindowPhase {
                input_attempted: true,
                completed_button_pairs: 4,
            },
        }));
        let record = result.action_record.unwrap();
        assert_eq!(record.effect, ActionEffect::Unverifiable);
        assert_eq!(record.actual_delivery, Some(ActualDelivery::Background));
        assert_eq!(record.delivered_count, Some(4));
        assert!(record.public_result().is_ok());
    }
}
