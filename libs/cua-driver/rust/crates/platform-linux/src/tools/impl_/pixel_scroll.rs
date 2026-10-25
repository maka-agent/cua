// SPDX-License-Identifier: MIT

use cua_driver_core::protocol::ToolResult;
use serde_json::{json, Value};

#[derive(Clone, Copy, Debug)]
pub(super) struct PixelScroll {
    pub detents: usize,
}

impl PixelScroll {
    pub(super) fn from_arguments(args: &Value) -> Result<Option<Self>, ToolResult> {
        let Some(value) = args.get("pixels") else {
            return Ok(None);
        };
        if args.get("by").is_some() || args.get("amount").is_some() {
            return Err(invalid("pixels cannot be combined with by or amount"));
        }
        let pixels: u16 = serde_json::from_value(value.clone())
            .map_err(|error| invalid(&format!("invalid pixels: {error}")))?;
        if pixels == 0 {
            return Err(invalid("pixels must be non-zero"));
        }
        // Original Linux native service: u16 -> f32, divss 100, roundf, max 1.
        let detents = (f32::from(pixels) / 100.0).round().max(1.0) as usize;
        Ok(Some(Self { detents }))
    }
}

fn invalid(detail: &str) -> ToolResult {
    ToolResult::error(detail).with_structured(json!({
        "code": "invalid_arguments", "tool": "scroll", "detail": detail
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_pixel_boundaries_preserve_rounding_and_requests_above_fifty_detents() {
        for (pixels, detents) in [
            (1, 1),
            (49, 1),
            (50, 1),
            (99, 1),
            (100, 1),
            (149, 1),
            (150, 2),
            (250, 3),
            (800, 8),
            (5001, 50),
            (5100, 51),
            (65535, 655),
        ] {
            let request = PixelScroll::from_arguments(&json!({ "pixels": pixels }))
                .unwrap()
                .unwrap();
            assert_eq!(request.detents, detents, "{pixels} pixels");
        }
        assert!(PixelScroll::from_arguments(&json!({"amount":3}))
            .unwrap()
            .is_none());
    }

    #[test]
    fn invalid_native_pixel_inputs_refuse_before_any_input_dispatch() {
        for value in [
            json!(0),
            json!(-1),
            json!(0.1),
            json!(49.5),
            json!(149.5),
            json!(150.1),
            json!(65536),
            json!("800"),
            Value::Null,
        ] {
            let error = PixelScroll::from_arguments(&json!({"pixels":value})).unwrap_err();
            assert_eq!(
                error.structured_content.unwrap()["code"],
                "invalid_arguments"
            );
        }
        for extra in [
            json!({"pixels":800,"amount":3}),
            json!({"pixels":800,"by":"line"}),
        ] {
            let error = PixelScroll::from_arguments(&extra).unwrap_err();
            assert_eq!(
                error.structured_content.unwrap()["detail"],
                "pixels cannot be combined with by or amount"
            );
        }
    }
}
