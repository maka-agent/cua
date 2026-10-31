// SPDX-License-Identifier: MIT

//! Recoverable changes to the current user's native messaging registration.
//!
//! The handoff supervisor owns this synchronous transaction. Callers must keep
//! blocking registration and durability work off the async executor.

use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io,
    path::{Path, PathBuf},
};

mod browser_family;
pub use browser_family::BrowserFamily;
mod configuration;
mod plan;
pub mod transport;
pub use plan::{OriginalHost, PreparedHandoff};
mod storage;
pub use configuration::{
    ConfiguredHandoff, NativeHostReceipt, recorded_native_hosts, restore_current,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistrationSlot {
    Manifest(PathBuf),
    #[cfg(windows)]
    Registry {
        subkey: String,
        view: RegistryView,
    },
}

impl RegistrationSlot {
    fn same_slot(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Manifest(left), Self::Manifest(right)) => left == right,
            #[cfg(windows)]
            (Self::Registry { subkey: left, .. }, Self::Registry { subkey: right, .. }) => {
                left.eq_ignore_ascii_case(right)
            }
            #[cfg(windows)]
            _ => false,
        }
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryView {
    Bits32,
    Bits64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Value {
    bytes: Vec<u8>,
    #[cfg(unix)]
    mode: u32,
    #[cfg(windows)]
    registry_type: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Change {
    slot: RegistrationSlot,
    before: Option<Value>,
    after: Value,
}

#[derive(Debug, thiserror::Error)]
pub enum HandoffError {
    #[error("native host handoff IPC: {0}")]
    Ipc(#[from] crate::browser::local_ipc::IpcError),
    #[error("native host handoff configuration: {0}")]
    Configuration(String),
    #[error("native host registration I/O: {0}")]
    Io(#[from] io::Error),
    #[error("native host handoff journal: {0}")]
    Journal(#[from] serde_json::Error),
    #[error("registration changed outside this handoff: {0:?}")]
    Conflict(Vec<RegistrationSlot>),
    #[error("browser host recovery failed: {0:?}")]
    ScopeRestore(Vec<(BrowserFamily, String)>),
    #[error("a previous handoff must be restored before another can begin")]
    PendingRecovery,
    #[error("registration slot appears more than once in one handoff")]
    DuplicateSlot,
    #[error("registration recovery failed: {0:?}")]
    Restore(Vec<(RegistrationSlot, String)>),
    #[error("registration change failed: {operation}; recovery also failed: {recovery}")]
    Recovery {
        operation: Box<HandoffError>,
        recovery: Box<HandoffError>,
    },
}

/// Holds the cooperating cross-process lock until registration restoration ends.
/// Dropping it leaves the journal intact for a successor after supervisor death.
pub struct RegistrationTransaction {
    directory: PathBuf,
    _lock: File,
    changes: Vec<Change>,
}

impl RegistrationTransaction {
    pub fn open(directory: &Path) -> Result<Self, HandoffError> {
        super::local_ipc::ensure_private_state_directory(directory)
            .map_err(|error| io::Error::other(error.to_string()))?;
        if let Some(parent) = directory.parent() {
            storage::sync_directory(parent)?;
        }
        let lock = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join("registration.lock"))?;
        fs2::FileExt::try_lock_exclusive(&lock)?;
        let changes = match std::fs::read(directory.join("registration.json")) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            directory: directory.to_owned(),
            _lock: lock,
            changes,
        })
    }

    /// Capture every original before changing any slot. Registry replacement
    /// bytes are the exact UTF-16 REG_SZ data, including its terminating zero.
    pub fn replace(
        &mut self,
        replacements: Vec<(RegistrationSlot, Vec<u8>)>,
    ) -> Result<(), HandoffError> {
        let mut changes: Vec<Change> = Vec::new();
        for (slot, bytes) in replacements {
            let before = storage::read(&slot)?;
            let after = storage::replacement(&slot, bytes);
            changes.push(Change {
                slot,
                before,
                after,
            });
        }
        self.publish_changes(changes)
    }

    fn publish_changes(&mut self, changes: Vec<Change>) -> Result<(), HandoffError> {
        if !self.changes.is_empty() {
            return Err(HandoffError::PendingRecovery);
        }
        for (index, change) in changes.iter().enumerate() {
            if changes[..index]
                .iter()
                .any(|earlier| earlier.slot.same_slot(&change.slot))
            {
                return Err(HandoffError::DuplicateSlot);
            }
        }
        // Journal publication precedes the first externally visible mutation.
        storage::atomic_file(
            &self.directory.join("registration.json"),
            &serde_json::to_vec(&changes)?,
            None,
        )?;
        self.changes = changes;
        let result = self.apply();
        if let Err(operation) = result {
            return match self.restore() {
                Ok(()) => Err(operation),
                Err(recovery) => Err(HandoffError::Recovery {
                    operation: Box::new(operation),
                    recovery: Box::new(recovery),
                }),
            };
        }
        Ok(())
    }

    fn apply(&self) -> Result<(), HandoffError> {
        for change in &self.changes {
            if storage::read(&change.slot)? != change.before {
                return Err(HandoffError::Conflict(vec![change.slot.clone()]));
            }
            storage::write(&change.slot, Some(&change.after))?;
        }
        Ok(())
    }

    /// Restore owned values, preserving external updates and reporting them as
    /// conflicts. Only failed restoration retains an active recovery journal.
    pub fn restore(&mut self) -> Result<(), HandoffError> {
        let mut conflicts = Vec::new();
        let mut errors = Vec::new();
        for change in self.changes.iter().rev() {
            let restored: io::Result<()> = (|| {
                let current = storage::read(&change.slot)?;
                if current != change.before {
                    if current.as_ref() != Some(&change.after) {
                        conflicts.push(change.slot.clone());
                        return Ok(());
                    }
                    storage::write(&change.slot, change.before.as_ref())?;
                }
                storage::barrier(&change.slot)?;
                Ok(())
            })();
            if let Err(error) = restored {
                errors.push((change.slot.clone(), error.to_string()));
            }
        }
        if !errors.is_empty() {
            if !conflicts.is_empty() {
                self.changes
                    .retain(|change| !conflicts.contains(&change.slot));
                storage::atomic_file(
                    &self.directory.join("registration.json"),
                    &serde_json::to_vec(&self.changes)?,
                    None,
                )?;
            }
            return Err(HandoffError::Restore(errors));
        }
        match std::fs::remove_file(self.directory.join("registration.json")) {
            Ok(()) => storage::sync_directory(&self.directory)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        self.changes.clear();
        if conflicts.is_empty() {
            Ok(())
        } else {
            Err(HandoffError::Conflict(conflicts))
        }
    }
}

#[cfg(test)]
mod tests;
