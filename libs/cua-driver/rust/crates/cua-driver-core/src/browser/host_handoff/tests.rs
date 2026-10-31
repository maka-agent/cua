// SPDX-License-Identifier: MIT

use super::*;

#[test]
fn restart_restores_original_bytes_and_absent_override() {
    let root = tempfile::tempdir().unwrap();
    let existing = root.path().join("existing.json");
    let absent = root.path().join("absent.json");
    std::fs::write(&existing, b"original").unwrap();
    let directory = std::fs::canonicalize(root.path())
        .unwrap()
        .join("transaction");
    let slots = [
        RegistrationSlot::Manifest(existing.clone()),
        RegistrationSlot::Manifest(absent.clone()),
    ];
    let original = storage::read(&slots[0]).unwrap();
    let mut transaction = RegistrationTransaction::open(&directory).unwrap();
    transaction
        .replace(
            slots
                .iter()
                .cloned()
                .map(|slot| (slot, b"maka".to_vec()))
                .collect(),
        )
        .unwrap();
    assert_eq!(std::fs::read(&existing).unwrap(), b"maka");
    assert_eq!(std::fs::read(&absent).unwrap(), b"maka");
    assert!(
        matches!(RegistrationTransaction::open(&directory), Err(HandoffError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock)
    );
    drop(transaction);
    let mut successor = RegistrationTransaction::open(&directory).unwrap();
    successor.restore().unwrap();
    assert_eq!(storage::read(&slots[0]).unwrap(), original);
    assert!(!absent.exists());
    assert!(!directory.join("registration.json").exists());
}

#[test]
fn external_update_survives_while_other_slots_are_restored() {
    let root = tempfile::tempdir().unwrap();
    let first = root.path().join("first.json");
    let second = root.path().join("second.json");
    std::fs::write(&first, b"first original").unwrap();
    std::fs::write(&second, b"second original").unwrap();
    let directory = std::fs::canonicalize(root.path())
        .unwrap()
        .join("transaction");
    let first_slot = RegistrationSlot::Manifest(first.clone());
    let mut transaction = RegistrationTransaction::open(&directory).unwrap();
    transaction
        .replace(vec![
            (first_slot.clone(), b"maka".to_vec()),
            (RegistrationSlot::Manifest(second.clone()), b"maka".to_vec()),
        ])
        .unwrap();
    std::fs::write(&first, b"updated by original installer").unwrap();
    assert!(
        matches!(transaction.restore(), Err(HandoffError::Conflict(slots)) if slots == vec![first_slot])
    );
    assert_eq!(
        std::fs::read(&first).unwrap(),
        b"updated by original installer"
    );
    assert_eq!(std::fs::read(&second).unwrap(), b"second original");
    assert!(!directory.join("registration.json").exists());
}

#[test]
fn failed_publication_restores_already_changed_slots() {
    let root = tempfile::tempdir().unwrap();
    let first = root.path().join("first.json");
    std::fs::write(&first, b"original").unwrap();
    let directory = std::fs::canonicalize(root.path())
        .unwrap()
        .join("transaction");
    let mut transaction = RegistrationTransaction::open(&directory).unwrap();
    let result = transaction.replace(vec![
        (RegistrationSlot::Manifest(first.clone()), b"maka".to_vec()),
        (
            RegistrationSlot::Manifest(root.path().join("nonexistent-parent/manifest.json")),
            b"maka".to_vec(),
        ),
    ]);
    assert!(
        matches!(result, Err(HandoffError::Io(error)) if error.kind() == io::ErrorKind::NotFound)
    );
    assert_eq!(std::fs::read(&first).unwrap(), b"original");
    assert!(!directory.join("registration.json").exists());
}
