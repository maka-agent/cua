// SPDX-License-Identifier: MIT

use cua_driver_core::action_record::{
    ActionEffect, ActionExecutionRecord, ActionTransport, ActualDelivery, RequestedDelivery,
};
use cua_driver_core::protocol::ToolResult;
use serde_json::{json, Value};

use crate::input::native_element::{
    NativeElementClickFailure, NativeElementClickRequest, NativeElementDelivery,
    NativeElementTransport,
};
use crate::input::native_window::NativeClickButton;

pub(super) async fn invoke(args: Value, request: NativeElementClickRequest) -> ToolResult {
    invoke_on_route(args, request, crate::wayland::is_wayland()).await
}

async fn invoke_on_route(
    args: Value,
    request: NativeElementClickRequest,
    selected_wayland: bool,
) -> ToolResult {
    if selected_wayland {
        let code = crate::atspi::native_observation::X11_ROUTE_REQUIRED;
        return refusal(&request, initial_transport(&request), code, code);
    }
    if !request.matches_arguments(&args) {
        return refusal(
            &request,
            initial_transport(&request),
            "native_element_request_mismatch",
            "native element click data does not match the authorized arguments",
        );
    }
    if let Err(error) = request.validate_options() {
        return refusal(
            &request,
            initial_transport(&request),
            "invalid_arguments",
            &error.to_string(),
        );
    }
    let Some(session) = args.get("_session_id").and_then(Value::as_str) else {
        return refusal(
            &request,
            initial_transport(&request),
            "native_element_lifecycle_required",
            "native element click requires an admitted lifecycle",
        );
    };
    if cua_driver_core::session::is_session_ending(session) {
        return refusal(
            &request,
            initial_transport(&request),
            "action_cancelled",
            "native element click invocation was cancelled",
        );
    }
    let observation = match crate::atspi::native_observation::for_window(
        request.pid,
        u64::from(request.window_id),
    ) {
        Ok(Some(observation)) => observation,
        Ok(None) => {
            return refusal(
                &request,
                initial_transport(&request),
                "native_element_context_required",
                "native element click requires its scoped lookup context",
            );
        }
        Err(error) => {
            return refusal(
                &request,
                initial_transport(&request),
                "native_element_context_mismatch",
                &error.to_string(),
            );
        }
    };
    if let Some(reason) = observation.stop_reason() {
        return refusal(
            &request,
            initial_transport(&request),
            "action_cancelled",
            reason,
        );
    }
    let Some(lease) = cua_driver_core::tool::current_native_input_worker_lease() else {
        return refusal(
            &request,
            initial_transport(&request),
            "native_element_admission_required",
            "native element click requires the original admitted input operation",
        );
    };
    let worker_request = request.clone();
    let session_id = session.to_owned();
    let outcome = tokio::task::spawn_blocking(move || {
        // Keep the original input/cursor/session admissions through final
        // actuator completion, even if the async observer is dropped.
        let _lease = lease;
        crate::atspi::native::click_native_element(&worker_request, observation, &session_id)
    })
    .await;
    match outcome {
        Ok(Ok(delivery)) => delivered(&request, delivery),
        Ok(Err(failure)) => failed(&request, failure),
        Err(error) => ToolResult::error(format!(
            "native element click worker did not complete normally: {error}"
        ))
        .with_structured(
            json!({"code":"input_outcome_unknown","effect":"unverifiable","verified":false}),
        )
        .with_action_record(record(
            &request,
            initial_transport(&request),
            ActionEffect::Unverifiable,
            Some(ActualDelivery::Unknown),
            None,
        )),
    }
}

fn initial_transport(request: &NativeElementClickRequest) -> NativeElementTransport {
    if request.button == NativeClickButton::Right {
        NativeElementTransport::WindowSendEvent
    } else {
        NativeElementTransport::Accessibility
    }
}

fn transport_details(transport: NativeElementTransport) -> (ActionTransport, ActualDelivery) {
    match transport {
        NativeElementTransport::Accessibility => (
            ActionTransport::LinuxAtSpiAction,
            ActualDelivery::Background,
        ),
        NativeElementTransport::WindowSendEvent => {
            (ActionTransport::LinuxXSendEvent, ActualDelivery::Background)
        }
    }
}

fn record(
    _request: &NativeElementClickRequest,
    transport: NativeElementTransport,
    effect: ActionEffect,
    actual: Option<ActualDelivery>,
    refusal_code: Option<&str>,
) -> ActionExecutionRecord {
    let mut record = ActionExecutionRecord::builder(
        effect,
        transport_details(transport).0,
        RequestedDelivery::Background,
    );
    if let Some(actual) = actual {
        record = record.actual_delivery(actual);
    }
    if let Some(code) = refusal_code {
        record = record.refusal(code, None);
    }
    record
        .build()
        .expect("native element click records distinguish preparation from attempted delivery")
}

fn refusal(
    request: &NativeElementClickRequest,
    transport: NativeElementTransport,
    code: &str,
    reason: &str,
) -> ToolResult {
    ToolResult::error(reason)
        .with_structured(json!({"code":code,"effect":"refused"}))
        .with_action_record(record(
            request,
            transport,
            ActionEffect::Refused,
            None,
            Some(code),
        ))
}

fn delivered(request: &NativeElementClickRequest, delivery: NativeElementDelivery) -> ToolResult {
    let (transport, unacknowledged) = match delivery {
        NativeElementDelivery::Accessibility { unacknowledged } => {
            (NativeElementTransport::Accessibility, unacknowledged)
        }
        NativeElementDelivery::WindowSendEvent => (NativeElementTransport::WindowSendEvent, false),
    };
    ToolResult::text("Native element click dispatched; application effect remains unverified.")
        .with_structured(
            json!({"effect":"unverifiable","verified":false,"unacknowledged":unacknowledged}),
        )
        .with_action_record(record(
            request,
            transport,
            ActionEffect::Unverifiable,
            Some(transport_details(transport).1),
            None,
        ))
}

fn failed(request: &NativeElementClickRequest, failure: NativeElementClickFailure) -> ToolResult {
    if !failure.dispatched {
        return refusal(
            request,
            failure.transport,
            "input_preparation_failed",
            &failure.error.to_string(),
        );
    }
    ToolResult::error(failure.error.to_string())
        .with_structured(
            json!({"code":"input_outcome_unknown","effect":"unverifiable","verified":false}),
        )
        .with_action_record(record(
            request,
            failure.transport,
            ActionEffect::Unverifiable,
            Some(transport_details(failure.transport).1),
            None,
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(button: NativeClickButton) -> NativeElementClickRequest {
        NativeElementClickRequest {
            pid: 123,
            window_id: 456,
            element_id: None,
            button,
            count: 1,
            deadline: None,
        }
    }

    #[tokio::test]
    async fn typed_click_guards_refuse_before_any_native_lookup() {
        let request = request(NativeClickButton::Left);
        let result = invoke_on_route(request.arguments(), request.clone(), true).await;
        assert_eq!(
            result.structured_content.unwrap()["code"],
            crate::atspi::native_observation::X11_ROUTE_REQUIRED
        );
        let mut arguments = request.arguments();
        arguments["element_token"] = "forged".into();
        let result = invoke_on_route(arguments, request.clone(), false).await;
        assert_eq!(
            result.structured_content.unwrap()["code"],
            "native_element_request_mismatch"
        );
        let mut invalid = request.clone();
        invalid.count = 0;
        let result = invoke_on_route(invalid.arguments(), invalid, false).await;
        assert_eq!(
            result.structured_content.unwrap()["code"],
            "invalid_arguments"
        );
        let result = invoke_on_route(request.arguments(), request, false).await;
        assert_eq!(
            result.structured_content.unwrap()["code"],
            "native_element_lifecycle_required"
        );
    }

    #[test]
    fn delivery_records_never_promote_rpc_acknowledgement_to_verified_effect() {
        for (button, delivery, transport, actual) in [
            (
                NativeClickButton::Left,
                NativeElementDelivery::Accessibility {
                    unacknowledged: false,
                },
                ActionTransport::LinuxAtSpiAction,
                ActualDelivery::Background,
            ),
            (
                NativeClickButton::Right,
                NativeElementDelivery::Accessibility {
                    unacknowledged: true,
                },
                ActionTransport::LinuxAtSpiAction,
                ActualDelivery::Background,
            ),
            (
                NativeClickButton::Right,
                NativeElementDelivery::WindowSendEvent,
                ActionTransport::LinuxXSendEvent,
                ActualDelivery::Background,
            ),
        ] {
            let result = delivered(&request(button), delivery);
            assert_eq!(result.structured_content.unwrap()["verified"], false);
            let record = result.action_record.unwrap();
            assert_eq!(record.effect, ActionEffect::Unverifiable);
            assert_eq!(record.transport, transport);
            assert_eq!(record.actual_delivery, Some(actual));
            assert!(record.public_result().is_ok());
        }
    }

    #[test]
    fn focus_input_before_primary_failure_is_recorded_as_background_uncertainty() {
        let result = failed(
            &request(NativeClickButton::Right),
            NativeElementClickFailure {
                error: anyhow::anyhow!("position was unavailable"),
                dispatched: true,
                transport: NativeElementTransport::WindowSendEvent,
            },
        );
        assert_eq!(
            serde_json::to_value(&result.content).unwrap()[0]["text"],
            "position was unavailable"
        );
        assert_eq!(
            result.structured_content.as_ref().unwrap()["verified"],
            false
        );
        let record = result.action_record.unwrap();
        assert_eq!(record.effect, ActionEffect::Unverifiable);
        assert_eq!(record.transport, ActionTransport::LinuxXSendEvent);
        assert_eq!(record.requested_delivery, RequestedDelivery::Background);
        assert_eq!(record.actual_delivery, Some(ActualDelivery::Background));
        assert!(record.public_result().is_ok());
    }

    #[test]
    fn preparation_refusal_has_no_delivery_and_dispatch_failure_stays_unknown() {
        for dispatched in [false, true] {
            let result = failed(
                &request(NativeClickButton::Right),
                NativeElementClickFailure {
                    error: anyhow::anyhow!("native failure"),
                    dispatched,
                    transport: NativeElementTransport::WindowSendEvent,
                },
            );
            let record = result.action_record.unwrap();
            assert_eq!(
                record.effect,
                if dispatched {
                    ActionEffect::Unverifiable
                } else {
                    ActionEffect::Refused
                }
            );
            assert_eq!(
                record.actual_delivery,
                dispatched.then_some(ActualDelivery::Background)
            );
            assert!(record.public_result().is_ok());
        }
    }
}
