// SPDX-License-Identifier: MIT
//! Original native editable typing over the existing AT-SPI and input owners.

use anyhow::{Result, anyhow, bail};
use atspi::proxy::{component::ComponentProxy, text::TextProxy};
use atspi::zbus::{fdo::PropertiesProxy, message::Message, proxy::CacheProperties};
use atspi_connection::AccessibilityConnection;
use x11rb::rust_connection::RustConnection;

use super::{RawObjectRef, element};
use crate::input::native_window::{NativeWindowContext, NativeWindowTarget};

const TEXT_INTERFACE: &str = "org.a11y.atspi.Text";
const NOT_EDITABLE: &str =
    "element is not editable; refresh get_window_state() and choose an editable element";
const CARET_MISSING: &str = "editable element did not return a caret offset";
const CARET_INVALID: &str = "editable element did not return a valid caret offset";
const SELECTION_INVALID: &str = "editable element did not return valid selection offsets";
const BOUNDS_EMPTY: &str = "editable element has no visible bounds";
const RESTORE_REFUSED: &str = "editable element refused to restore its text selection";

/// A fresh member of the admitted window's tree, pinned to its unique bus owner.
/// This identity is not an authority token and opens no input lifetime.
pub(crate) struct PreparedNativeTyping {
    conn: &'static AccessibilityConnection,
    object: RawObjectRef,
}

pub(crate) fn prepare_native_typing(
    target: NativeWindowTarget,
    selector: &str,
    session_id: &str,
    check: &dyn Fn() -> Result<()>,
) -> Result<PreparedNativeTyping> {
    super::runtime().block_on(async {
        check()?;
        let conn = super::shared_connection().await?;
        check()?;
        let window = element::selected_window(conn, target, session_id).await?;
        check()?;
        let located = element::locate(conn, &window.root, Some(selector), session_id).await?;
        check()?;
        let located = element::pin(conn, located, session_id).await?;
        check()?;
        let accessible =
            element::checked(session_id, super::accessible_via_bus(conn, &located.object)).await?;
        let states = element::checked(session_id, accessible.get_state()).await?;
        check()?;
        if !states.contains(atspi::State::Editable) {
            bail!(NOT_EDITABLE);
        }
        Ok(PreparedNativeTyping {
            conn,
            object: located.object,
        })
    })
}

fn caret(reply: &Message) -> Result<i32> {
    let signature = super::reply::signature(reply)?;
    if signature.is_empty() {
        bail!(CARET_MISSING);
    }
    if !signature.starts_with('v') {
        bail!(CARET_INVALID);
    }
    super::reply::variant_i32(reply)?.ok_or_else(|| anyhow!(CARET_INVALID))
}

fn selection_count(reply: &Message) -> Result<i32> {
    let signature = super::reply::signature(reply)?;
    // The complete successful body was parsed by the same library. Only its
    // first top-level value selects this branch; later values are ignored.
    if !signature.starts_with('i') {
        return Ok(0);
    }
    Ok(reply.body().deserialize_unchecked::<i32>()?.max(0))
}

fn selection(reply: &Message) -> Result<(i32, i32)> {
    if super::reply::signature(reply)? != "ii" {
        bail!(SELECTION_INVALID);
    }
    Ok(reply.body().deserialize_unchecked()?)
}

fn screen_center(reply: &Message) -> Result<[i16; 2]> {
    let (x, y, width, height) = super::reply::rectangle(reply)?;
    if width <= 0 || height <= 0 {
        bail!(BOUNDS_EMPTY);
    }
    Ok([
        i16::try_from(i64::from(x) + i64::from(width) / 2)?,
        i16::try_from(i64::from(y) + i64::from(height) / 2)?,
    ])
}

fn restore_acknowledged(reply: &Message) -> Result<()> {
    if super::reply::boolean(reply)? == Some(true) {
        return Ok(());
    }
    bail!(RESTORE_REFUSED)
}

impl PreparedNativeTyping {
    /// Preserve the original caret/first selection across its background focus
    /// click, then let the caller enter the existing clipboard transaction.
    pub(crate) fn focus_before_paste(
        self,
        x11: &RustConnection,
        context: &NativeWindowContext,
    ) -> Result<()> {
        super::runtime().block_on(async {
            context.check()?;
            let properties = PropertiesProxy::builder(self.conn.connection())
                .cache_properties(CacheProperties::No)
                .destination(self.object.name.clone())?
                .path(self.object.path.clone())?
                .build()
                .await?;
            let text = TextProxy::builder(self.conn.connection())
                .cache_properties(CacheProperties::No)
                .destination(self.object.name.clone())?
                .path(self.object.path.clone())?
                .build()
                .await?;
            let component = ComponentProxy::builder(self.conn.connection())
                .cache_properties(CacheProperties::No)
                .destination(self.object.name.clone())?
                .path(self.object.path)?
                .build()
                .await?;
            let session = context.session_id();
            context.check()?;
            let reply = element::checked(
                session,
                super::reply::call_method(
                    properties.inner(),
                    "Get",
                    &(TEXT_INTERFACE, "CaretOffset"),
                ),
            )
            .await?;
            context.check()?;
            let caret_offset = caret(&reply)?;
            let reply = element::checked(
                session,
                super::reply::call_method(text.inner(), "GetNSelections", &()),
            )
            .await?;
            context.check()?;
            let selected = if selection_count(&reply)? > 0 {
                let reply = element::checked(
                    session,
                    super::reply::call_method(text.inner(), "GetSelection", &(0_i32,)),
                )
                .await?;
                context.check()?;
                Some(selection(&reply)?)
            } else {
                None
            };
            let reply = element::checked(
                session,
                super::reply::call_method(
                    component.inner(),
                    "GetExtents",
                    &(atspi::CoordType::Screen,),
                ),
            )
            .await?;
            context.check()?;
            let point = screen_center(&reply)?;
            context.owned_move_to_root(x11, point, false)?;
            let pressed = context.button_edge_owned(x11, 1, true);
            let down_ack = pressed.is_ok();
            let action = pressed.and_then(|()| context.pause(std::time::Duration::from_millis(12)));
            // The exact retained pair is released even if Stop woke the hold.
            let released = context.button_edge_owned(x11, 1, false);
            if down_ack && released.is_ok() {
                context.mark_completed();
            }
            action.and(released)?;
            context.pause(std::time::Duration::from_millis(30))?;
            context.check()?;
            context.mark_attempted();
            // Retain and await this same accepted mutation. No caller-cancel
            // select, detached timeout, retry or generic GrabFocus fallback.
            let reply = match selected {
                Some((start, end)) => {
                    super::reply::call_method(text.inner(), "AddSelection", &(start, end)).await?
                }
                None => {
                    super::reply::call_method(text.inner(), "SetCaretOffset", &(caret_offset,))
                        .await?
                }
            };
            restore_acknowledged(&reply)?;
            context.check()?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::reply::{BOUNDS_INVALID, BOUNDS_MISSING};
    use super::*;
    use atspi::zbus::zvariant::{DynamicType, Value};

    fn reply<T: serde::Serialize + DynamicType>(body: &T) -> Message {
        Message::method_call("/org/cua/Fixture", "Reply")
            .unwrap()
            .build(body)
            .unwrap()
    }

    #[test]
    fn editable_typing_decodes_original_caret_selection_and_screen_bounds() {
        assert_eq!(caret(&reply(&Value::from(-7_i32))).unwrap(), -7);
        assert_eq!(caret(&reply(&())).unwrap_err().to_string(), CARET_MISSING);
        assert_eq!(
            caret(&reply(&Value::from(7_u32))).unwrap_err().to_string(),
            CARET_INVALID
        );
        assert_eq!(
            caret(&reply(&7_i32)).unwrap_err().to_string(),
            CARET_INVALID
        );
        for body in [reply(&()), reply(&7_u32), reply(&"not an i32")] {
            assert_eq!(selection_count(&body).unwrap(), 0);
        }
        assert_eq!(selection_count(&reply(&-4_i32)).unwrap(), 0);
        assert_eq!(selection_count(&reply(&3_i32)).unwrap(), 3);
        assert_eq!(selection(&reply(&(-7_i32, 3_i32))).unwrap(), (-7, 3));
        assert_eq!(
            selection(&reply(&(7_i32, 3_u32))).unwrap_err().to_string(),
            SELECTION_INVALID
        );
        assert_eq!(
            screen_center(&reply(&((-5_i32, -3_i32, 3_i32, 5_i32),))).unwrap(),
            [-4, -1]
        );
        assert_eq!(
            screen_center(&reply(&())).unwrap_err().to_string(),
            BOUNDS_MISSING
        );
        assert_eq!(
            screen_center(&reply(&((0_i32, 0_i32, 0_i32, 1_i32),)))
                .unwrap_err()
                .to_string(),
            BOUNDS_EMPTY
        );
        assert_eq!(
            screen_center(&reply(&((0_i32, 0_i32, 1_u32, 1_i32),)))
                .unwrap_err()
                .to_string(),
            BOUNDS_INVALID
        );
        assert!(screen_center(&reply(&((i32::MAX, 0_i32, i32::MAX, 1_i32),))).is_err());
    }

    #[test]
    fn editable_typing_keeps_first_values_and_exact_selection_structure() {
        assert_eq!(
            caret(&reply(&(Value::from(-7_i32), "ignored"))).unwrap(),
            -7
        );
        assert_eq!(selection_count(&reply(&(3_i32, 9_u32))).unwrap(), 3);
        assert_eq!(selection_count(&reply(&((3_i32, 9_i32),))).unwrap(), 0);
        assert_eq!(selection_count(&reply(&(3_u32, 9_i32))).unwrap(), 0);
        for message in [reply(&((3_i32, 9_i32),)), reply(&(3_i32, 9_i32, 11_i32))] {
            assert_eq!(
                selection(&message).unwrap_err().to_string(),
                SELECTION_INVALID
            );
        }
        assert_eq!(
            screen_center(&reply(&((1_i32, 2_i32, 3_i32, 4_i32), "ignored"))).unwrap(),
            [2, 4]
        );
        for message in [
            reply(&(1_i32, 2_i32, 3_i32, 4_i32)),
            reply(&true),
            reply(&Value::from((1_i32, 2_i32, 3_i32, 4_i32))),
        ] {
            assert_eq!(
                screen_center(&message).unwrap_err().to_string(),
                BOUNDS_MISSING
            );
        }
        for message in [
            reply(&(((1_i32, 2_i32, 3_i32, 4_i32),),)),
            reply(&((1_i32, 2_i32, 3_i32, 4_i32, 5_i32),)),
        ] {
            assert_eq!(
                screen_center(&message).unwrap_err().to_string(),
                BOUNDS_INVALID
            );
        }
    }

    #[test]
    fn noncanonical_boolean_variant_keeps_the_native_caret_type_error() {
        let word = super::super::reply::BooleanWord(2);
        let message = reply(&atspi::zbus::zvariant::SerializeValue(&word));
        assert_eq!(caret(&message).unwrap_err().to_string(), CARET_INVALID);
    }

    #[test]
    fn editable_restore_checks_first_boolean_ack_without_losing_extra_values() {
        for word in [1, 2, u32::MAX] {
            restore_acknowledged(&reply(&super::super::reply::BooleanWord(word))).unwrap();
        }
        restore_acknowledged(&reply(&true)).unwrap();
        restore_acknowledged(&reply(&(true, 7_u32))).unwrap();
        for message in [
            reply(&(false, true)),
            reply(&((true,),)),
            reply(&Value::from(true)),
            reply(&()),
            reply(&(7_i32, true)),
        ] {
            assert_eq!(
                restore_acknowledged(&message).unwrap_err().to_string(),
                RESTORE_REFUSED
            );
        }
    }
}
