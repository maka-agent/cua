// SPDX-License-Identifier: MIT
//! Original named AT-SPI action over the existing native window lifetime.

use anyhow::{Result, anyhow, bail};
use atspi::proxy::action::ActionProxy;
use atspi::zbus::{message::Message, proxy::CacheProperties};

use super::element;
use crate::input::native_window::{NativeWindowContext, NativeWindowTarget};

pub(crate) struct PreparedNativeSecondary {
    proxy: ActionProxy<'static>,
    index: usize,
}

fn selected_index(names: &[String], action: &str) -> Result<usize> {
    // Trimming validates blankness only. Lookup preserves the supplied name.
    if action.trim().is_empty() {
        bail!("action name must not be empty");
    }
    let mut matches = names
        .iter()
        .enumerate()
        .filter_map(|(index, name)| name.eq_ignore_ascii_case(action).then_some(index));
    let index = matches.next().ok_or_else(|| {
        anyhow!("AT-SPI action {action:?} is unavailable; available actions: {names:?}")
    })?;
    if matches.next().is_some() {
        bail!("AT-SPI action {action:?} is ambiguous");
    }
    Ok(index)
}

pub(crate) fn prepare_native_secondary(
    target: NativeWindowTarget,
    selector: &str,
    action: &str,
    session_id: &str,
    check: &dyn Fn() -> Result<()>,
) -> Result<PreparedNativeSecondary> {
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
        // The shared reader performs GetInterfaces before NActions/GetName,
        // just like the original, and preserves its distinct reply failures.
        let read = async {
            let proxy = ActionProxy::builder(conn.connection())
                .cache_properties(CacheProperties::No)
                .destination(located.object.name)?
                .path(located.object.path)?
                .build()
                .await?;
            let names = super::native_action_names(&proxy, Some(session_id)).await?;
            Ok::<_, anyhow::Error>((proxy, names))
        }
        .await;
        check()?;
        let (proxy, names) = read.map_err(element::ActionReadError)?;
        // Membership and the entire source action reader precede even the
        // blank-action error. Only a unique ASCII-insensitive match dispatches.
        let index = selected_index(&names, action)?;
        Ok(PreparedNativeSecondary { proxy, index })
    })
}

fn acknowledged(reply: &Message, index: usize) -> Result<()> {
    if super::reply::boolean(reply)? == Some(true) {
        return Ok(());
    }
    bail!("AT-SPI element refused action {index}; refresh get_window_state() to check its state")
}

impl PreparedNativeSecondary {
    pub(crate) fn dispatch(
        self,
        context: &NativeWindowContext,
        attempted: &mut bool,
    ) -> Result<()> {
        super::runtime().block_on(async {
            context.check()?;
            // Source checks i32 conversion after InputTarget.new as well.
            let index = i32::try_from(self.index)?;
            context.check()?;
            context.mark_attempted();
            *attempted = true;
            // Keep the same accepted mutation until its real reply. Stop may
            // seal later producers, not drop/replay this method call.
            let reply =
                super::reply::call_method(self.proxy.inner(), "DoAction", &(index,)).await?;
            acknowledged(&reply, self.index)?;
            context.check()?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atspi::zbus::zvariant::DynamicType;

    fn reply<T: serde::Serialize + DynamicType>(body: &T) -> Message {
        Message::method_call("/org/cua/Fixture", "Reply")
            .unwrap()
            .build(body)
            .unwrap()
    }

    #[test]
    fn named_action_selects_one_ascii_match_without_trimming_or_default_click() {
        let names = ["press".into(), "Expand".into(), "Äction".into()];
        assert_eq!(selected_index(&names, "eXpAnD").unwrap(), 1);
        assert_eq!(selected_index(&names, "Äction").unwrap(), 2);
        assert!(
            selected_index(&names, "äction").is_err(),
            "non-ASCII letters are not folded"
        );
        assert_eq!(
            selected_index(&names, "\u{0085} \t")
                .unwrap_err()
                .to_string(),
            "action name must not be empty"
        );
        assert_eq!(
            selected_index(&names, " Expand ").unwrap_err().to_string(),
            "AT-SPI action \" Expand \" is unavailable; available actions: [\"press\", \"Expand\", \"Äction\"]"
        );
        assert_eq!(
            selected_index(&["Expand".into(), "EXPAND".into()], "expand")
                .unwrap_err()
                .to_string(),
            "AT-SPI action \"expand\" is ambiguous"
        );
        assert_eq!(
            selected_index(&[], "press").unwrap_err().to_string(),
            "AT-SPI action \"press\" is unavailable; available actions: []"
        );
    }

    #[test]
    fn named_action_requires_real_boolean_true_reply() {
        for word in [1, 2, u32::MAX] {
            acknowledged(&reply(&super::super::reply::BooleanWord(word)), 3).unwrap();
        }
        acknowledged(&reply(&true), 3).unwrap();
        acknowledged(&reply(&(true, 7_u32)), 3).unwrap();
        for message in [
            reply(&false),
            reply(&()),
            reply(&1_i32),
            reply(&"true"),
            reply(&((true,),)),
            reply(&(1_i32, true)),
            reply(&(false, true)),
        ] {
            assert_eq!(
                acknowledged(&message, 3).unwrap_err().to_string(),
                "AT-SPI element refused action 3; refresh get_window_state() to check its state"
            );
        }
    }
}
