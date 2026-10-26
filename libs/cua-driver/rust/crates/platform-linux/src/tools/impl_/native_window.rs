// SPDX-License-Identifier: MIT

use cua_driver_core::action_record::{
    ActionEffect, ActionExecutionRecord, ActionTransport, ActualDelivery, RequestedDelivery,
};
use cua_driver_core::protocol::ToolResult;
use serde_json::{json, Value};

use crate::input::native_window::{
    NativeWindowCancellation, NativeWindowError, NativeWindowInputRequest,
};

pub(super) async fn invoke(
    tool: &str,
    args: Value,
    request: NativeWindowInputRequest,
) -> ToolResult {
    invoke_on_route(tool, args, request, crate::wayland::is_wayland()).await
}

async fn invoke_on_route(
    tool: &str,
    args: Value,
    request: NativeWindowInputRequest,
    selected_wayland: bool,
) -> ToolResult {
    if selected_wayland {
        let code = crate::atspi::native_observation::X11_ROUTE_REQUIRED;
        return refusal(code, code);
    }
    if !request.matches_arguments(tool, &args) {
        return refusal(
            "native_window_request_mismatch",
            "native window input data does not match the authorized arguments",
        );
    }
    let Some(session) = args.get("_session_id").and_then(Value::as_str) else {
        return refusal(
            "native_window_lifecycle_required",
            "native window input requires an admitted lifecycle",
        );
    };
    let Some(lease) = cua_driver_core::tool::current_native_input_worker_lease() else {
        return refusal(
            "native_window_admission_required",
            "native window input requires the original admitted input operation",
        );
    };
    let (_cancellation_guard, cancellation) =
        NativeWindowCancellation::invocation(session.to_owned());
    let outcome = tokio::task::spawn_blocking(move || {
        // This is the original cursor/input/session admission, retained
        // through the final release, 100 ms settle, and X11 roundtrip even
        // when the async observer is aborted.
        let _lease = lease;
        crate::input::native_window::execute(request, cancellation)
    })
    .await;
    match outcome {
        Ok(Ok(())) => posted_result(request),
        Ok(Err(error)) => input_error(error),
        Err(error) => ToolResult::error(format!(
            "native window input worker did not complete normally: {error}"
        ))
        .with_structured(json!({"code":"input_outcome_unknown","effect":"unverifiable"}))
        .with_action_record(delivery_record(
            ActionEffect::Unverifiable,
            ActualDelivery::Unknown,
            0,
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
            .expect("a refused native window input has no delivery"),
        )
}

fn delivery_record(
    effect: ActionEffect,
    delivery: ActualDelivery,
    completed: u32,
) -> ActionExecutionRecord {
    ActionExecutionRecord::builder(
        effect,
        ActionTransport::LinuxXSendEvent,
        RequestedDelivery::Background,
    )
    .actual_delivery(delivery)
    .delivered_count(completed)
    .build()
    .expect("native window input delivery records carry their completed pair count")
}

fn posted_result(request: NativeWindowInputRequest) -> ToolResult {
    let pairs = request.pairs();
    ToolResult::text("Native window pointer train posted.")
        .with_structured(json!({
            "path":"x11_xsendevent", "native_profile":"native_window_input",
            "effect":"unverifiable", "verified":false,
            "input":request.arguments(),"button_pairs":pairs,
        }))
        .with_action_record(delivery_record(
            ActionEffect::Unverifiable,
            ActualDelivery::Background,
            pairs,
        ))
}

fn error_code(error: &anyhow::Error) -> &'static str {
    match error.downcast_ref::<NativeWindowError>() {
        Some(NativeWindowError::TargetUnavailable) => "window_not_found",
        Some(NativeWindowError::PointOutsideWindow) => "point_outside_window",
        Some(NativeWindowError::IncompletePoint) => "incomplete_point",
        Some(NativeWindowError::InvalidPixels) => "invalid_arguments",
        Some(NativeWindowError::Cancelled) => "action_cancelled",
        Some(NativeWindowError::Dispatch { cause, .. }) => match error_code(cause) {
            "input_preparation_failed" => "input_outcome_unknown",
            code => code,
        },
        None => "input_preparation_failed",
    }
}

fn input_error(error: anyhow::Error) -> ToolResult {
    let (effect, completed) = match error.downcast_ref::<NativeWindowError>() {
        Some(NativeWindowError::Dispatch { completed, .. }) => (
            if *completed > 0 {
                "partial"
            } else {
                "unverifiable"
            },
            *completed,
        ),
        _ => ("refused", 0),
    };
    let code = error_code(&error);
    let record = match effect {
        "partial" => delivery_record(ActionEffect::Partial, ActualDelivery::Background, completed),
        "unverifiable" => delivery_record(
            ActionEffect::Unverifiable,
            ActualDelivery::Background,
            completed,
        ),
        _ => return refusal(code, &error.to_string()),
    };
    ToolResult::error(error.to_string())
        .with_structured(json!({
            "code":code,"effect":effect,"completed_button_pairs":completed,
            "native_profile":"native_window_input",
        }))
        .with_action_record(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::native_window::{
        NativeClickButton, NativeScrollDirection, NativeWindowInput,
    };

    #[tokio::test]
    async fn selected_wayland_refuses_typed_input_before_lifecycle_or_worker_admission() {
        let request = NativeWindowInputRequest {
            pid: 123,
            window_id: 456,
            input: NativeWindowInput::Click {
                point: [37, 41],
                button: NativeClickButton::Left,
                count: 1,
            },
        };
        let result = invoke_on_route("click", request.arguments(), request, true).await;
        assert_eq!(result.is_error, Some(true));
        let details = result
            .structured_content
            .expect("typed refusal carries its code");
        assert_eq!(
            details["code"],
            crate::atspi::native_observation::X11_ROUTE_REQUIRED
        );
        assert_eq!(details["effect"], "refused");
        let record = result
            .action_record
            .expect("typed refusal records no delivery");
        assert_eq!(record.effect, ActionEffect::Refused);
        assert_eq!(record.actual_delivery, None);
        assert_eq!(record.delivered_count, None);
        assert!(record.public_result().is_ok());

        let x11_result = invoke_on_route("click", request.arguments(), request, false).await;
        let details = x11_result
            .structured_content
            .expect("X11 retains its existing lifecycle refusal before any worker");
        assert_eq!(details["code"], "native_window_lifecycle_required");
    }

    #[test]
    fn native_result_records_keep_actual_click_and_wheel_pair_counts() {
        let mut requests = [0, 4, u32::MAX]
            .map(|count| NativeWindowInputRequest {
                pid: 123,
                window_id: 456,
                input: NativeWindowInput::Click {
                    point: [37, 41],
                    button: NativeClickButton::Left,
                    count,
                },
            })
            .to_vec();
        requests.push(NativeWindowInputRequest {
            pid: 123,
            window_id: 456,
            input: NativeWindowInput::Scroll {
                x: Some(37),
                y: Some(41),
                direction: NativeScrollDirection::Down,
                pixels: 150,
            },
        });
        for request in requests {
            let result = posted_result(request);
            let record = result.action_record.unwrap();
            assert_eq!(record.effect, ActionEffect::Unverifiable);
            assert_eq!(record.transport, ActionTransport::LinuxXSendEvent);
            assert_eq!(record.actual_delivery, Some(ActualDelivery::Background));
            assert_eq!(record.delivered_count, Some(request.pairs()));
            assert!(record.public_result().is_ok());
            let details = result.structured_content.unwrap();
            assert_eq!(details["input"], request.arguments());
            assert_eq!(details["button_pairs"], request.pairs());
        }
    }

    #[test]
    fn errors_after_virtual_focus_keep_the_native_code_and_unknown_effect() {
        for (cause, code) in [
            (
                NativeWindowError::PointOutsideWindow,
                "point_outside_window",
            ),
            (NativeWindowError::IncompletePoint, "incomplete_point"),
        ] {
            let result = input_error(
                NativeWindowError::Dispatch {
                    completed: 0,
                    cause: cause.into(),
                }
                .into(),
            );
            let record = result.action_record.unwrap();
            assert_eq!(record.transport, ActionTransport::LinuxXSendEvent);
            assert_eq!(record.effect, ActionEffect::Unverifiable);
            assert!(record.public_result().is_ok());
            let details = result.structured_content.unwrap();
            assert_eq!(details["code"], code);
            assert_eq!(details["effect"], "unverifiable");
            assert_eq!(details["completed_button_pairs"], 0);
        }
    }

    #[test]
    fn cancellation_after_completed_pairs_keeps_partial_delivery() {
        let result = input_error(
            NativeWindowError::Dispatch {
                completed: 4,
                cause: NativeWindowError::Cancelled.into(),
            }
            .into(),
        );
        let record = result.action_record.unwrap();
        assert_eq!(record.effect, ActionEffect::Partial);
        assert_eq!(record.delivered_count, Some(4));
        assert!(record.public_result().is_ok());
        let details = result.structured_content.unwrap();
        assert_eq!(details["code"], "action_cancelled");
        assert_eq!(details["effect"], "partial");
        assert_eq!(details["completed_button_pairs"], 4);
    }
}
