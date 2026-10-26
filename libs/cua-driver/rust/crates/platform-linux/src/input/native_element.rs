// SPDX-License-Identifier: MIT

//! Bound native selectors carried outside ordinary click arguments.

use std::{cell::RefCell, future::Future, time::Instant};

use serde_json::{json, Value};

use super::native_window::NativeClickButton;
use crate::atspi::native_observation::{with_native_observation, NativeObservationRequest};

/// A native selector for one selected process and X11 client window.
///
/// The string identifies data to look up afresh; it grants no action authority.
#[derive(Clone, Debug)]
pub struct NativeElementClickRequest {
    /// Expected process owning the selected window.
    pub pid: u32,
    /// Exact X11 client window selected by the caller.
    pub window_id: u32,
    /// Opaque native selector, including the original absent-selector case.
    pub element_id: Option<String>,
    /// Original native mouse option; element clicks support left and right.
    pub button: NativeClickButton,
    /// Original native click count; an element click requires one.
    pub count: u32,
    /// Caller deadline, retained in memory rather than JSON arguments.
    pub deadline: Option<Instant>,
}

impl NativeElementClickRequest {
    /// Ordinary click arguments used by the existing authorization path.
    #[doc(hidden)]
    pub fn arguments(&self) -> Value {
        json!({
            "pid":self.pid,"window_id":self.window_id,"scope":"window",
            "button":self.button.as_str(),"count":self.count,
            "delivery_mode":if self.button == NativeClickButton::Right { "foreground" } else { "background" },
        })
    }

    pub(crate) fn matches_arguments(&self, args: &Value) -> bool {
        let expected = self.arguments();
        expected.as_object().is_some_and(|fields| {
            fields
                .iter()
                .all(|(name, value)| args.get(name) == Some(value))
                && args.as_object().is_some_and(|actual| {
                    actual.keys().all(|name| {
                        name.starts_with('_')
                            || fields.contains_key(name)
                            || (name == "session" && actual[name].is_string())
                    })
                })
        })
    }

    pub(crate) fn validate_options(&self) -> anyhow::Result<()> {
        if self.count != 1 || self.button == NativeClickButton::Middle {
            anyhow::bail!(
                "element click supports one left or right click without key or duration; use coordinates for other mouse options"
            );
        }
        Ok(())
    }
}

tokio::task_local! {
    static NATIVE_ELEMENT_CLICK: RefCell<Option<NativeElementClickRequest>>;
}

/// Scope selector data and the existing native cancellation context together.
#[doc(hidden)]
pub async fn with_native_element_click<F: Future>(
    request: NativeElementClickRequest,
    operation: F,
) -> F::Output {
    let observation = NativeObservationRequest {
        pid: request.pid,
        window_id: u64::from(request.window_id),
        deadline: request.deadline,
    };
    with_native_observation(
        observation,
        NATIVE_ELEMENT_CLICK.scope(RefCell::new(Some(request)), operation),
    )
    .await
}

pub(crate) fn take_native_element_click() -> Option<NativeElementClickRequest> {
    NATIVE_ELEMENT_CLICK
        .try_with(|request| request.borrow_mut().take())
        .ok()
        .flatten()
}

/// The actuator selected after fresh native lookup and preparation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeElementTransport {
    Accessibility,
    PhysicalPointer,
}

/// Delivery is distinct from independently observed application effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeElementDelivery {
    Accessibility { unacknowledged: bool },
    PhysicalPointer,
}

/// Preserve whether an error happened before or after an actuator was tried.
#[derive(Debug)]
pub(crate) struct NativeElementClickFailure {
    pub(crate) error: anyhow::Error,
    pub(crate) dispatched: bool,
    pub(crate) transport: NativeElementTransport,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> NativeElementClickRequest {
        NativeElementClickRequest {
            pid: 123,
            window_id: 456,
            element_id: Some(":1.0:/org/a11y/atspi/accessible/5".into()),
            button: NativeClickButton::Left,
            count: 1,
            deadline: None,
        }
    }

    #[test]
    fn canonical_click_arguments_keep_native_selectors_out_of_json() {
        let mut request = request();
        for (button, delivery) in [
            (NativeClickButton::Left, "background"),
            (NativeClickButton::Right, "foreground"),
        ] {
            request.button = button;
            assert_eq!(
                request.arguments(),
                json!({
                    "pid":123,"window_id":456,"scope":"window","button":button.as_str(),
                    "count":1,"delivery_mode":delivery,
                })
            );
            let mut authorized = request.arguments();
            authorized["_session_id"] = "private-runtime-session".into();
            assert!(request.matches_arguments(&authorized));
            for (field, value) in [
                ("window_id", json!(789)),
                ("x", json!(0)),
                ("element_token", json!("forged")),
                ("element_id", json!("native")),
            ] {
                let mut changed = authorized.clone();
                changed[field] = value;
                assert!(!request.matches_arguments(&changed), "{field}");
            }
        }
    }

    #[test]
    fn native_element_mouse_options_refuse_before_lookup() {
        let mut request = request();
        for count in [0, 2, u32::MAX] {
            request.count = count;
            assert_eq!(
                request.validate_options().unwrap_err().to_string(),
                "element click supports one left or right click without key or duration; use coordinates for other mouse options"
            );
        }
        request.count = 1;
        request.button = NativeClickButton::Middle;
        assert!(request.validate_options().is_err());
    }

    #[tokio::test]
    async fn selector_scope_is_one_shot_and_cancels_retained_lookup_when_dropped() {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let mut invocation = Box::pin(with_native_element_click(request(), async move {
            let selected = take_native_element_click().expect("typed request is scoped");
            assert_eq!(
                selected.element_id.as_deref(),
                Some(":1.0:/org/a11y/atspi/accessible/5")
            );
            assert!(take_native_element_click().is_none());
            let observation = crate::atspi::native_observation::current()
                .expect("same native cancellation context is scoped");
            ready_tx
                .send(observation)
                .expect("test retains native lookup context");
            std::future::pending::<()>().await;
        }));
        let observation = tokio::select! {
            _ = invocation.as_mut() => panic!("invocation stays pending"),
            observation = ready_rx => observation.expect("lookup context is ready"),
        };
        assert_eq!(observation.stop_reason(), None);
        drop(invocation);
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(5), observation.stopped())
                .await
                .expect("dropping the invocation wakes its native lookup"),
            "cancelled"
        );
        assert!(take_native_element_click().is_none());
        assert!(crate::atspi::native_observation::current().is_none());
    }
}
