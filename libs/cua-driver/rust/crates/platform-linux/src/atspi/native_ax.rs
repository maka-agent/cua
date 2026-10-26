// SPDX-License-Identifier: MIT

//! Native accessibility metadata from one observation, without action authority.

use atspi::State;
use serde::{Deserialize, Serialize};

/// The metadata source used by a native accessibility observation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NativeAxSource {
    /// Rows reported by the selected window's AT-SPI tree.
    #[serde(rename = "at_spi")]
    AtSpi,
    /// Window metadata recovered from X11 without AT-SPI element authority.
    #[serde(rename = "x11")]
    X11,
}

/// Native rows in observed preorder, without granting action authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAxSnapshot {
    /// The source of the observed rows.
    pub source: NativeAxSource,
    /// Rows in the order produced by the observation's existing traversal.
    pub rows: Vec<NativeAxRow>,
}

/// One observed native node; its address is metadata, not an action token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAxRow {
    /// Native address reported by the source, without independent authority.
    pub native_id: String,
    /// Parent row's position in this snapshot, when a parent was observed.
    pub parent: Option<usize>,
    /// Depth in the selected window's observed tree.
    pub depth: usize,
    /// Role reported by the source.
    pub role: String,
    /// Reported name, or `None` when it is unknown.
    pub name: Option<String>,
    /// Reported description, or `None` when it is unknown.
    pub description: Option<String>,
    /// Reported value, or `None` when it is unknown.
    pub value: Option<String>,
    /// Known state names; `None` preserves an unavailable state query.
    pub states: Option<Vec<String>>,
    /// Reported action names; `None` preserves an unavailable action query.
    pub actions: Option<Vec<String>>,
    /// Existing actionable index, if the observation assigned one.
    pub element_index: Option<usize>,
}

/// Project known states in the native observation's specified order.
/// Callers retain an unknown state query as `None` rather than an empty set.
pub(crate) fn state_names(states: atspi::StateSet) -> Vec<String> {
    [
        (State::Checked, "checked"),
        (State::Defunct, "defunct"),
        (State::Editable, "editable"),
        (State::Enabled, "enabled"),
        (State::Expanded, "expanded"),
        (State::Focusable, "focusable"),
        (State::Focused, "focused"),
        (State::Selected, "selected"),
        (State::Sensitive, "sensitive"),
        (State::Showing, "showing"),
        (State::Visible, "visible"),
        (State::Indeterminate, "indeterminate"),
        (State::Checkable, "checkable"),
    ]
    .into_iter()
    .filter(|(state, _)| states.contains(*state))
    .map(|(_, name)| name.to_owned())
    .collect()
}

/// Format a reported AT-SPI address without resolving its bus owner.
pub(crate) fn native_id(bus_name: &str, path: &str) -> String {
    format!("{bus_name}:{path}")
}

/// Format an X11 metadata address without granting action authority.
pub(crate) fn x11_native_id(xid: u32) -> String {
    format!("x11:{xid:#x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use atspi::StateSet;
    use serde_json::json;

    #[test]
    fn native_state_projection_orders_only_the_thirteen_supported_states() {
        let all_states: StateSet = [
            State::Invalid,
            State::Active,
            State::Armed,
            State::Busy,
            State::Checked,
            State::Collapsed,
            State::Defunct,
            State::Editable,
            State::Enabled,
            State::Expandable,
            State::Expanded,
            State::Focusable,
            State::Focused,
            State::HasTooltip,
            State::Horizontal,
            State::Iconified,
            State::Modal,
            State::MultiLine,
            State::Multiselectable,
            State::Opaque,
            State::Pressed,
            State::Resizable,
            State::Selectable,
            State::Selected,
            State::Sensitive,
            State::Showing,
            State::SingleLine,
            State::Stale,
            State::Transient,
            State::Vertical,
            State::Visible,
            State::ManagesDescendants,
            State::Indeterminate,
            State::Required,
            State::Truncated,
            State::Animated,
            State::InvalidEntry,
            State::SupportsAutocompletion,
            State::SelectableText,
            State::IsDefault,
            State::Visited,
            State::Checkable,
            State::HasPopup,
            State::ReadOnly,
        ]
        .into_iter()
        .collect();
        assert_eq!(
            state_names(all_states),
            [
                "checked",
                "defunct",
                "editable",
                "enabled",
                "expanded",
                "focusable",
                "focused",
                "selected",
                "sensitive",
                "showing",
                "visible",
                "indeterminate",
                "checkable",
            ],
            "other AT-SPI states must not broaden the native state payload"
        );
        assert_eq!(
            state_names(StateSet::new(State::ReadOnly | State::Focused)),
            ["focused"],
            "projection preserves presence and excludes unsupported states"
        );
    }

    #[test]
    fn flat_snapshot_roundtrip_preserves_unknown_and_known_empty_fields() {
        let unknown_states: Option<StateSet> = None;
        let snapshot = NativeAxSnapshot {
            source: NativeAxSource::AtSpi,
            rows: vec![
                NativeAxRow {
                    native_id: ":1.42:/org/a11y/atspi/accessible/1".to_owned(),
                    parent: None,
                    depth: 0,
                    role: "frame".to_owned(),
                    name: Some("Example".to_owned()),
                    description: None,
                    value: None,
                    states: Some(state_names(StateSet::empty())),
                    actions: Some(Vec::new()),
                    element_index: None,
                },
                NativeAxRow {
                    native_id: ":1.42:/org/a11y/atspi/accessible/2".to_owned(),
                    parent: Some(0),
                    depth: 1,
                    role: "label".to_owned(),
                    name: None,
                    description: Some("Description".to_owned()),
                    value: Some(String::new()),
                    states: unknown_states.map(state_names),
                    actions: None,
                    element_index: Some(7),
                },
            ],
        };
        let encoded = serde_json::to_value(&snapshot).expect("snapshot serializes");
        assert_eq!(
            encoded,
            json!({
                "source": "at_spi",
                "rows": [
                    {
                        "native_id": ":1.42:/org/a11y/atspi/accessible/1",
                        "parent": null,
                        "depth": 0,
                        "role": "frame",
                        "name": "Example",
                        "description": null,
                        "value": null,
                        "states": [],
                        "actions": [],
                        "element_index": null
                    },
                    {
                        "native_id": ":1.42:/org/a11y/atspi/accessible/2",
                        "parent": 0,
                        "depth": 1,
                        "role": "label",
                        "name": null,
                        "description": "Description",
                        "value": "",
                        "states": null,
                        "actions": null,
                        "element_index": 7
                    }
                ]
            }),
            "flat metadata keeps unknown fields distinct from known empty fields"
        );
        assert_eq!(
            serde_json::from_value::<NativeAxSnapshot>(encoded).expect("snapshot deserializes"),
            snapshot
        );
        assert_eq!(
            serde_json::to_value(NativeAxSource::X11).expect("X11 source serializes"),
            json!("x11")
        );
    }

    #[test]
    fn x11_metadata_addresses_use_lowercase_hex() {
        assert_eq!(
            native_id(":1.0", "/org/a11y/atspi/accessible/1"),
            ":1.0:/org/a11y/atspi/accessible/1",
            "native metadata preserves unique bus addresses exactly"
        );
        assert_eq!(
            native_id("org.example.Accessible", "/org/a11y/atspi/accessible/1"),
            "org.example.Accessible:/org/a11y/atspi/accessible/1",
            "formatting preserves a well-known bus name without resolving it"
        );
        for (xid, expected) in [
            (0, "x11:0x0"),
            (0x12ab, "x11:0x12ab"),
            (u32::MAX, "x11:0xffffffff"),
        ] {
            assert_eq!(x11_native_id(xid), expected, "X11 id {xid}");
        }
    }
}
