// SPDX-License-Identifier: MIT

use super::{HandoffError, RegistrationTransaction};
use crate::browser::{
    extension_catalog, extension_host::InstalledHostConfig, extension_process::CHATGPT_HOST_NAME,
};
use std::path::{Path, PathBuf};

/// The embedding host supplies its kernel process-start identity. Keeping the
/// receipt before admission lets a successor retire the exact previous host.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct NativeHostReceipt {
    pub pid: u32,
    pub identity: String,
    pub executable: PathBuf,
}

/// An opt-in selected by connector setup, read without changing the browser.
#[derive(Debug, Clone)]
pub struct ConfiguredHandoff {
    pub(super) config: InstalledHostConfig,
    browser: super::BrowserFamily,
}

impl ConfiguredHandoff {
    pub fn remember_native_hosts(&self, hosts: &[NativeHostReceipt]) -> Result<(), HandoffError> {
        super::storage::atomic_file(
            &self.recovery_directory().join("native-hosts.json"),
            &serde_json::to_vec(hosts)?,
            None,
        )?;
        Ok(())
    }

    pub fn native_hosts(&self) -> Result<Vec<NativeHostReceipt>, HandoffError> {
        match crate::browser::local_ipc::load_private_state(
            &self.recovery_directory().join("native-hosts.json"),
        ) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(crate::browser::local_ipc::IpcError::MissingInstallationFile) => Ok(Vec::new()),
            Err(error) => Err(error.into()),
        }
    }
    pub fn remember_original(&self, original: &super::OriginalHost) -> Result<(), HandoffError> {
        super::storage::atomic_file(
            &self.recovery_directory().join("original.json"),
            &serde_json::to_vec(original)?,
            None,
        )?;
        Ok(())
    }

    pub fn original(&self) -> Result<super::OriginalHost, HandoffError> {
        let bytes = crate::browser::local_ipc::load_private_state(
            &self.recovery_directory().join("original.json"),
        )?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn has_pending_registration(&self) -> Result<bool, HandoffError> {
        match std::fs::metadata(self.recovery_directory().join("registration.json")) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
    pub fn load() -> Result<Option<Self>, HandoffError> {
        Self::for_executable(&std::env::current_exe()?)
    }

    pub(crate) fn for_executable(executable: &Path) -> Result<Option<Self>, HandoffError> {
        let catalog = extension_catalog::load(executable)
            .map_err(|error| HandoffError::Configuration(error.to_string()))?;
        if let Some(rejected) = catalog
            .rejected
            .iter()
            .find(|entry| entry.adapter == CHATGPT_HOST_NAME)
        {
            return Err(HandoffError::Configuration(rejected.reason.clone()));
        }
        Ok(catalog.entries.into_iter().find_map(|entry| {
            if entry.config.adapter != CHATGPT_HOST_NAME {
                return None;
            }
            let browser = entry.config.handoff?;
            Some(Self {
                config: entry.config,
                browser,
            })
        }))
    }

    pub fn browser(&self) -> super::BrowserFamily {
        self.browser
    }

    pub fn extension_id(&self) -> &str {
        &self.config.expected_extension_id
    }

    pub fn executable(&self) -> &Path {
        &self.config.executable
    }

    // All installed Maka executables cooperate on this user/browser/host scope.
    pub fn recovery_directory(&self) -> PathBuf {
        self.config
            .private_state_directory
            .join(self.browser.recovery_name())
    }

    pub fn restore(&self) -> Result<(), HandoffError> {
        RegistrationTransaction::open(&self.recovery_directory())?.restore()
    }
}

/// Recover the common browser-host scope even if installation metadata was lost.
pub fn restore_current() -> Result<(), HandoffError> {
    let directory = crate::browser::local_ipc::current_user_runtime_directory()
        .map_err(|error| HandoffError::Configuration(error.to_string()))?;
    restore_directory(&directory)
}

fn restore_directory(directory: &Path) -> Result<(), HandoffError> {
    let mut errors = Vec::new();
    for browser in [super::BrowserFamily::Chrome, super::BrowserFamily::Chromium] {
        let path = directory.join(browser.recovery_name());
        let result = match std::fs::symlink_metadata(&path) {
            Ok(_) => RegistrationTransaction::open(&path)
                .and_then(|mut transaction| transaction.restore()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => Err(error.into()),
        };
        if let Err(error) = result {
            errors.push((browser, error.to_string()));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(HandoffError::ScopeRestore(errors))
    }
}

/// Exact native admission receipts from the supported registration namespaces.
/// Callers must compare each receipt's process-start identity with the live PID.
pub fn recorded_native_hosts()
-> Result<Vec<(super::BrowserFamily, NativeHostReceipt)>, HandoffError> {
    let directory = crate::browser::local_ipc::current_user_runtime_directory()
        .map_err(|error| HandoffError::Configuration(error.to_string()))?;
    let mut hosts = Vec::new();
    for browser in [super::BrowserFamily::Chrome, super::BrowserFamily::Chromium] {
        let scope = directory.join(browser.recovery_name());
        match std::fs::symlink_metadata(&scope) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        }
        let path = scope.join("native-hosts.json");
        match crate::browser::local_ipc::load_private_state(&path) {
            Ok(bytes) => {
                let receipts: Vec<NativeHostReceipt> = serde_json::from_slice(&bytes)?;
                hosts.extend(receipts.into_iter().map(|host| (browser, host)));
            }
            Err(crate::browser::local_ipc::IpcError::MissingInstallationFile) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(hosts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser::host_handoff::{BrowserFamily, RegistrationSlot};

    #[test]
    fn an_active_browser_scope_does_not_prevent_recovering_an_abandoned_other_scope() {
        let root = tempfile::tempdir().unwrap();
        let directory = std::fs::canonicalize(root.path()).unwrap();
        let chrome_manifest = directory.join("chrome.json");
        let chromium_manifest = directory.join("chromium.json");
        std::fs::write(&chrome_manifest, b"original Chrome").unwrap();
        std::fs::write(&chromium_manifest, b"original Chromium").unwrap();
        let mut chrome =
            RegistrationTransaction::open(&directory.join(BrowserFamily::Chrome.recovery_name()))
                .unwrap();
        chrome
            .replace(vec![(
                RegistrationSlot::Manifest(chrome_manifest.clone()),
                b"Maka Chrome".to_vec(),
            )])
            .unwrap();
        let mut chromium =
            RegistrationTransaction::open(&directory.join(BrowserFamily::Chromium.recovery_name()))
                .unwrap();
        chromium
            .replace(vec![(
                RegistrationSlot::Manifest(chromium_manifest.clone()),
                b"Maka Chromium".to_vec(),
            )])
            .unwrap();
        drop(chromium);
        let error = restore_directory(&directory).unwrap_err();
        assert!(
            matches!(error, HandoffError::ScopeRestore(ref scopes) if scopes.len() == 1 && scopes[0].0 == BrowserFamily::Chrome)
        );
        assert_eq!(std::fs::read(&chrome_manifest).unwrap(), b"Maka Chrome");
        assert_eq!(
            std::fs::read(&chromium_manifest).unwrap(),
            b"original Chromium"
        );
        chrome.restore().unwrap();
        assert_eq!(std::fs::read(&chrome_manifest).unwrap(), b"original Chrome");
    }
}
