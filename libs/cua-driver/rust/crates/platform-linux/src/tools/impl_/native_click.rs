// SPDX-License-Identifier: MIT

use cua_driver_core::action_record::{
    ActionEffect, ActionExecutionRecord, ActionTransport, ActualDelivery, RequestedDelivery,
};
use cua_driver_core::protocol::ToolResult;
use serde_json::{json, Value};

use crate::input::native_click::{NativeClickCancellation, NativeClickError, NativeClickRequest};

impl super::ClickTool {
    pub(super) async fn invoke_native_click(
        &self,
        args: Value,
        request: NativeClickRequest,
    ) -> ToolResult {
        if !request.matches_arguments(&args) {
            return refusal(
                "native_click_request_mismatch",
                "native click data does not match the authorized arguments",
            );
        }
        let Some(session) = args.get("_session_id").and_then(Value::as_str) else {
            return refusal(
                "native_click_lifecycle_required",
                "native click requires an admitted lifecycle",
            );
        };
        let Some(lease) = cua_driver_core::tool::current_native_input_worker_lease() else {
            return refusal(
                "native_click_admission_required",
                "native click requires the original admitted input operation",
            );
        };
        let (_cancellation_guard, cancellation) =
            NativeClickCancellation::invocation(session.to_owned());
        let outcome = tokio::task::spawn_blocking(move || {
            // This is the original cursor/input/session admission, retained
            // through the final release, 100 ms settle, and X11 roundtrip even
            // when the async observer is aborted.
            let _lease = lease;
            crate::input::native_click::execute(request, cancellation)
        })
        .await;
        match outcome {
            Ok(Ok(())) => posted_result(request),
            Ok(Err(error)) => input_error(error),
            Err(error) => ToolResult::error(format!(
                "native click worker did not complete normally: {error}"
            ))
            .with_structured(json!({"code":"input_outcome_unknown","effect":"unverifiable"}))
            .with_action_record(delivery_record(
                ActionEffect::Unverifiable,
                ActualDelivery::Unknown,
                0,
            )),
        }
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
            .expect("a refused native click has no delivery"),
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
    .expect("native click delivery records carry their completed pair count")
}

fn posted_result(request: NativeClickRequest) -> ToolResult {
    ToolResult::text("Native window click train posted.")
        .with_structured(json!({
            "path":"x11_xsendevent", "native_profile":"native_click",
            "effect":"unverifiable", "verified":false,
            "pid":request.pid,"window_id":request.window_id,
            "window_point":request.point,"button":request.button.as_str(),"count":request.count,
            "button_pairs":request.count,
        }))
        .with_action_record(delivery_record(
            ActionEffect::Unverifiable,
            ActualDelivery::Background,
            request.count,
        ))
}

fn error_code(error: &anyhow::Error) -> &'static str {
    match error.downcast_ref::<NativeClickError>() {
        Some(NativeClickError::TargetUnavailable) => "window_not_found",
        Some(NativeClickError::PointOutsideWindow) => "point_outside_window",
        Some(NativeClickError::Cancelled) => "action_cancelled",
        Some(NativeClickError::Dispatch { cause, .. }) => match error_code(cause) {
            "input_preparation_failed" => "input_outcome_unknown",
            code => code,
        },
        None => "input_preparation_failed",
    }
}

fn input_error(error: anyhow::Error) -> ToolResult {
    let (effect, completed) = match error.downcast_ref::<NativeClickError>() {
        Some(NativeClickError::Dispatch { completed, .. }) => (
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
            "native_profile":"native_click",
        }))
        .with_action_record(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_result_records_keep_the_actual_u32_count_including_zero() {
        for count in [0, 4, u32::MAX] {
            let result = posted_result(NativeClickRequest {
                pid: 123,
                window_id: 456,
                point: [37, 41],
                button: crate::input::native_click::NativeClickButton::Left,
                count,
            });
            let record = result.action_record.unwrap();
            assert_eq!(record.effect, ActionEffect::Unverifiable);
            assert_eq!(record.transport, ActionTransport::LinuxXSendEvent);
            assert_eq!(record.actual_delivery, Some(ActualDelivery::Background));
            assert_eq!(record.delivered_count, Some(count));
            assert!(record.public_result().is_ok());
        }
    }

    #[test]
    fn an_error_after_virtual_move_keeps_its_refusal_code_and_unknown_effect() {
        let result = input_error(
            NativeClickError::Dispatch {
                completed: 0,
                cause: NativeClickError::PointOutsideWindow.into(),
            }
            .into(),
        );
        let record = result.action_record.unwrap();
        assert_eq!(record.transport, ActionTransport::LinuxXSendEvent);
        assert_eq!(record.effect, ActionEffect::Unverifiable);
        assert!(record.public_result().is_ok());
        let details = result.structured_content.unwrap();
        assert_eq!(details["code"], "point_outside_window");
        assert_eq!(details["effect"], "unverifiable");
        assert_eq!(details["completed_button_pairs"], 0);
    }

    #[test]
    fn cancellation_after_completed_pairs_never_reports_a_refused_no_effect_action() {
        let result = input_error(
            NativeClickError::Dispatch {
                completed: 4,
                cause: NativeClickError::Cancelled.into(),
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
