//! Current screen geometry of an exact, retained accessibility element.

use cua_driver_contract::ElementFrame;

fn screen_frame(left: i32, top: i32, right: i32, bottom: i32) -> Option<ElementFrame> {
    (right > left && bottom > top).then(|| ElementFrame {
        x: f64::from(left),
        y: f64::from(top),
        w: f64::from(right) - f64::from(left),
        h: f64::from(bottom) - f64::from(top),
    })
}

#[cfg(target_os = "windows")]
pub(crate) use native::ElementBoundsTool;

#[cfg(target_os = "windows")]
mod native {
    use std::sync::{Arc, OnceLock};

    use async_trait::async_trait;
    use cua_driver_core::{
        element_token::ResolvedElement,
        protocol::ToolResult,
        tool::{Tool, ToolDef},
        tool_args::ArgsExt,
    };
    use serde_json::{json, Value};
    use windows::{
        core::Interface,
        Win32::{
            Foundation::HWND,
            System::Com::{
                CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
            },
            UI::Accessibility::{CUIAutomation, IUIAutomation, IUIAutomationElement},
        },
    };

    use crate::uia::snapshot::{RetainedElement, Snapshots};

    pub(crate) struct ElementBoundsTool {
        pub snapshots: Arc<Snapshots>,
    }

    #[async_trait]
    impl Tool for ElementBoundsTool {
        fn def(&self) -> &ToolDef {
            static DEF: OnceLock<ToolDef> = OnceLock::new();
            DEF.get_or_init(|| ToolDef {
                name: "element_bounds".into(),
                description: "Read the current screen-physical-pixel bounds of a retained UIA element without focusing or scrolling it. Requires the exact window and an element_token from get_window_state. MSAA-only elements are unsupported.".into(),
                input_schema: json!({
                    "type":"object",
                    "required":["pid","window_id","element_token"],
                    "properties":{
                        "pid":{"type":"integer","minimum":1},
                        "window_id":{"type":"integer","minimum":1},
                        "element_token":cua_driver_core::tool_schema::element_token_schema(),
                        "session":cua_driver_core::tool_schema::session_schema()
                    },
                    "additionalProperties":false
                }),
                read_only: true,
                destructive: false,
                idempotent: true,
                open_world: false,
            })
        }

        async fn invoke(&self, args: Value) -> ToolResult {
            let pid = match args.require_u32("pid") {
                Ok(pid) => pid,
                Err(error) => return error,
            };
            let window_id = match args.require_u64("window_id") {
                Ok(window_id) => window_id,
                Err(error) => return error,
            };
            let retained = match self.snapshots.resolve(pid as i32, &args) {
                Ok(ResolvedElement::Element { element, .. }) => element,
                Ok(ResolvedElement::None) => {
                    return refused(
                        "invalid_element_token",
                        "element_bounds requires an element_token",
                    )
                }
                Err(error) => return error,
            };
            if !retained.is_uia() {
                return refused(
                    "unsupported",
                    "current element bounds are unavailable for MSAA-only elements",
                );
            }
            match tokio::task::spawn_blocking(move || current_frame(retained, pid, window_id)).await
            {
                Ok(Ok(frame)) => ToolResult::text("Read current accessibility element bounds.")
                    .with_structured(json!({
                        "pid":pid,
                        "window_id":window_id,
                        "frame":frame,
                        "coordinate_space":"screen_physical_pixels"
                    })),
                Ok(Err(error)) => refused("element_bounds_unavailable", error.to_string()),
                Err(error) => refused(
                    "element_bounds_unavailable",
                    format!("UIA bounds task failed: {error}"),
                ),
            }
        }
    }

    fn refused(code: &str, message: impl Into<String>) -> ToolResult {
        ToolResult::error(message).with_structured(json!({"code":code,"effect":"refused"}))
    }

    struct ComApartment;

    impl Drop for ComApartment {
        fn drop(&mut self) {
            // SAFETY: constructed only after successful CoInitializeEx on this thread.
            unsafe { windows::Win32::System::Com::CoUninitialize() };
        }
    }

    fn current_frame(
        retained: RetainedElement,
        pid: u32,
        window_id: u64,
    ) -> anyhow::Result<cua_driver_contract::ElementFrame> {
        // SAFETY: COM is initialized on this blocking thread. The retained
        // snapshot owns the element reference until every native read finishes.
        unsafe {
            CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;
            let _com = ComApartment;
            let retained = retained;
            anyhow::ensure!(
                crate::win32::window_owner_pid(window_id) == Some(pid),
                "the window no longer belongs to the target process"
            );
            let automation: IUIAutomation =
                CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER)?;
            let element = std::mem::ManuallyDrop::new(IUIAutomationElement::from_raw(
                retained.as_ptr() as *mut _,
            ));
            let root = automation.ElementFromHandle(HWND(window_id as *mut _))?;
            let walker = automation.RawViewWalker()?;
            let mut ancestor = (*element).clone();
            while !automation.CompareElements(&ancestor, &root)?.as_bool() {
                ancestor = walker.GetParentElement(&ancestor).map_err(|error| {
                    anyhow::anyhow!("element no longer belongs to the observed window: {error}")
                })?;
            }
            let rect = element.CurrentBoundingRectangle()?;
            anyhow::ensure!(
                crate::win32::window_owner_pid(window_id) == Some(pid),
                "the window changed while reading element bounds"
            );
            super::screen_frame(rect.left, rect.top, rect.right, rect.bottom)
                .ok_or_else(|| anyhow::anyhow!("the element has no usable current bounds"))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test]
        async fn unknown_snapshot_is_refused_before_native_lookup() {
            let tool = ElementBoundsTool {
                snapshots: Arc::new(Snapshots::new()),
            };
            let result = tool
                .invoke(json!({
                    "pid":123,
                    "window_id":456,
                    "element_token":cua_driver_core::element_token::token_for(0xdeadbeef,0)
                }))
                .await;
            assert_eq!(
                result.structured_content.unwrap()["refusal"]["code"],
                "stale_element_token"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_physical_coordinates_on_monitors_left_and_above_primary() {
        assert_eq!(
            screen_frame(-1920, -1080, -1820, -1030),
            Some(ElementFrame {
                x: -1920.0,
                y: -1080.0,
                w: 100.0,
                h: 50.0
            })
        );
        assert_eq!(
            screen_frame(i32::MIN, 0, i32::MAX, 20).unwrap().w,
            4294967295.0
        );
    }

    #[test]
    fn missing_or_inverted_geometry_has_no_point_to_indicate() {
        assert!(screen_frame(10, 10, 10, 20).is_none());
        assert!(screen_frame(10, 20, 20, 10).is_none());
    }
}
