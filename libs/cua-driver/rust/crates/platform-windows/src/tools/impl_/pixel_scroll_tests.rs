use super::*;

fn tool() -> ScrollTool {
    ScrollTool {
        state: Arc::new(ToolState {
            snapshots: Arc::new(Snapshots::new()),
            cursor_registry: Arc::new(CursorRegistry::new()),
            config: Arc::new(RwLock::new(DriverConfig::default())),
            capture_bridge: None,
            raw_window_capture: std::sync::Mutex::new(None),
        }),
    }
}

#[tokio::test]
async fn pixel_scroll_refuses_invalid_or_indexed_requests_before_native_effects() {
    let tool = tool();
    let base = json!({
        "direction":"down", "pixels":800,
        "x":10, "y":20, "scope":"desktop", "delivery_mode":"foreground"
    });
    for change in [
        json!({"amount":1}),
        json!({"by":"page"}),
        json!({"element_token":"s0000002a:11"}),
        json!({"delivery_mode":"background"}),
        json!({"pixels":"800"}),
        json!({"pixels":2147483648.0}),
        json!({"direction":"diagonal"}),
        json!({"x":"10"}),
        json!({"y":null}),
        json!({"scope":"window"}),
    ] {
        let mut args = base.clone();
        args.as_object_mut()
            .unwrap()
            .extend(change.as_object().unwrap().clone());
        let result = tool.invoke(args.clone()).await;
        assert_eq!(result.is_error, Some(true), "{args}");
        let details = result.structured_content.unwrap();
        assert_eq!(details["effect"], "refused", "{args}");
        assert_eq!(details["code"], "invalid_arguments", "{args}");
    }
}

#[tokio::test]
async fn pixel_scroll_needs_owned_screenshot_context_before_window_geometry() {
    let result = tool()
        .invoke(json!({
            "direction":"down", "pixels":800, "x":10, "y":20,
            "pid":123, "window_id":456, "delivery_mode":"foreground"
        }))
        .await;
    assert_eq!(result.is_error, Some(true));
    assert_eq!(
        result.structured_content.unwrap()["code"],
        "screenshot_context_missing"
    );
}

#[test]
fn incomplete_wheel_batch_reports_actual_counts_and_never_a_refusal() {
    for inserted in [0, 1] {
        let result = pixel_wheel_dispatch_result(
            crate::input::mouse::PixelWheelDispatch {
                requested: 2,
                inserted,
            },
            800,
            -40000,
        );
        assert_eq!(result.is_error, Some(true));
        let record = result.action_record.as_ref().unwrap();
        assert_eq!(record.delivered_count, Some(inserted));
        assert_eq!(
            record.effect,
            cua_driver_core::action_record::ActionEffect::Partial
        );
        let details = result.structured_content.unwrap();
        assert_eq!(details["effect"], "partial");
        assert_eq!(details["code"], "input_outcome_unknown");
        assert_eq!(details["wheel_events_requested"], 2);
        assert_eq!(details["wheel_events_inserted"], inserted);
        assert_eq!(details["wheel_delta_x"], 800);
        assert_eq!(details["wheel_delta_y"], -32768);
        assert!(details.get("refusal").is_none());
    }
    let result = pixel_wheel_dispatch_result(
        crate::input::mouse::PixelWheelDispatch {
            requested: 1,
            inserted: 1,
        },
        800,
        0,
    );
    assert_ne!(result.is_error, Some(true));
    assert_eq!(result.structured_content.unwrap()["effect"], "unverifiable");
}
