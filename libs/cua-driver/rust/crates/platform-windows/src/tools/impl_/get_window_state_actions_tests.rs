use super::*;
use crate::uia::UiaNode;

fn node(actions: Vec<String>) -> UiaNode {
    UiaNode {
        element_index: Some(1),
        control_type: "Button".to_owned(),
        name: Some("OK".to_owned()),
        value: None,
        automation_id: None,
        help_text: None,
        actions,
        enabled: Some(true),
        focused: None,
        selected: None,
        element_ptr: 0,
        center_x: 0,
        center_y: 0,
        rect: None,
        msaa_role: None,
        depth: 0,
        parent_element_index: None,
        in_web_content: false,
    }
}

#[test]
fn element_entry_includes_actions_when_present() {
    let n = node(vec!["invoke".to_owned(), "toggle".to_owned()]);
    let entry = build_element_entry(&n, None).unwrap();
    assert_eq!(entry["actions"], json!(["invoke", "toggle"]));
}

#[test]
fn element_entry_omits_actions_when_empty() {
    let n = node(Vec::new());
    let entry = build_element_entry(&n, None).unwrap();
    assert!(entry.get("actions").is_none());
}

#[test]
fn observation_preserves_decision_state_and_observed_empty_values() {
    let mut n = node(vec!["set_value".to_owned()]);
    n.focused = Some(true);
    n.value = Some(String::new());
    let entry = build_element_entry(&n, None).unwrap();
    assert_eq!(entry["focused"], true);
    assert_eq!(entry["value"], "");
    assert!(crate::uia::format_node_line(&n).contains("[focused]"));
    n.enabled = Some(false);
    n.element_index = None;
    n.actions.clear();
    assert!(crate::uia::format_node_line(&n).contains("[disabled]"));
    assert!(build_element_entry(&n, None).is_none());
}
