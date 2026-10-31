// SPDX-License-Identifier: MIT

use super::{
    Change, ConfiguredHandoff, HandoffError, RegistrationSlot, RegistrationTransaction, storage,
};
#[cfg(unix)]
use crate::browser::extension_host::RegistrationPlan;
use crate::browser::{
    extension_host::{AdapterRegistration, ExtensionOrigin},
    extension_install,
    extension_process::CHATGPT_HOST_NAME,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OriginalHost {
    pub executable: PathBuf,
    pub allowed_origins: Vec<String>,
}

/// Read-only plan. The supervisor applies it only after recovering the previous
/// transaction and taking the shared registration lock.
pub struct PreparedHandoff {
    pub original: OriginalHost,
    replacements: Vec<Change>,
}

impl PreparedHandoff {
    pub fn publish(
        self,
        transaction: &mut RegistrationTransaction,
    ) -> Result<OriginalHost, HandoffError> {
        for change in &self.replacements {
            match &change.slot {
                RegistrationSlot::Manifest(path) => {
                    crate::browser::local_ipc::ensure_installation_directory(
                        path.parent()
                            .ok_or_else(|| configuration("manifest lacks parent"))?,
                    )
                    .map_err(configuration)?;
                }
                #[cfg(windows)]
                RegistrationSlot::Registry { .. } => {}
            }
        }
        transaction.publish_changes(self.replacements)?;
        Ok(self.original)
    }
}

impl ConfiguredHandoff {
    #[cfg(unix)]
    pub(crate) fn prepare_files(
        &self,
        plan: RegistrationPlan,
        system: &Path,
    ) -> Result<PreparedHandoff, HandoffError> {
        prepare_files(self, plan, system)
    }
    pub fn prepare(&self) -> Result<PreparedHandoff, HandoffError> {
        let adapter = AdapterRegistration::selected_adapter(
            CHATGPT_HOST_NAME,
            ExtensionOrigin::from_id(self.extension_id()).map_err(configuration)?,
        )
        .map_err(configuration)?;
        let mut plan = extension_install::current_plan_for(adapter).map_err(configuration)?;
        #[cfg(unix)]
        {
            let home = extension_install::current_home().map_err(configuration)?;
            let xdg = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
            plan.manifest_path = self.browser().user_manifest(&home, xdg.as_deref())?;
            let system = self.browser().system_manifest();
            self.prepare_files(plan, &system)
        }
        #[cfg(windows)]
        {
            let subkey = self.browser().registry_subkey();
            if self.browser() == super::BrowserFamily::Chromium {
                plan.manifest_path = self
                    .config
                    .private_state_directory
                    .join("chromium")
                    .join(format!("{CHATGPT_HOST_NAME}.json"));
            }
            let slot = RegistrationSlot::Registry {
                subkey: subkey.clone(),
                view: super::RegistryView::Bits32,
            };
            let before = storage::read(&slot)?;
            let original_path = super::storage::registered_manifest(&subkey)?.ok_or_else(|| {
                HandoffError::Configuration(
                    "original ChatGPT browser host is not registered".into(),
                )
            })?;
            let original_bytes = std::fs::read(&original_path)?;
            let (original, replacement) = rewrite(self, &original_path, &original_bytes)?;
            // Windows registration points to our private manifest; the original
            // installer's manifest file is never overwritten.
            let pointer: Vec<u8> = plan
                .manifest_path
                .as_os_str()
                .to_str()
                .ok_or_else(|| HandoffError::Configuration("manifest path is not Unicode".into()))?
                .encode_utf16()
                .chain(Some(0))
                .flat_map(u16::to_le_bytes)
                .collect();
            Ok(PreparedHandoff {
                original,
                replacements: vec![
                    planned_file(plan.manifest_path, replacement)?,
                    Change {
                        after: storage::replacement(&slot, pointer),
                        slot,
                        before,
                    },
                ],
            })
        }
    }
}

fn configuration(error: impl std::fmt::Display) -> HandoffError {
    HandoffError::Configuration(error.to_string())
}

#[cfg(unix)]
pub(super) fn prepare_files(
    config: &ConfiguredHandoff,
    plan: RegistrationPlan,
    system: &Path,
) -> Result<PreparedHandoff, HandoffError> {
    let slot = RegistrationSlot::Manifest(plan.manifest_path.clone());
    let before = storage::read(&slot)?;
    let (original_path, original_bytes) = match &before {
        Some(value) => (plan.manifest_path.clone(), value.bytes.clone()),
        None => (system.to_owned(), std::fs::read(system)?),
    };
    let (original, replacement) = rewrite(config, &original_path, &original_bytes)?;
    Ok(PreparedHandoff {
        original,
        replacements: vec![Change {
            after: storage::replacement(&slot, replacement),
            slot,
            before,
        }],
    })
}

fn rewrite(
    config: &ConfiguredHandoff,
    manifest_path: &Path,
    bytes: &[u8],
) -> Result<(OriginalHost, Vec<u8>), HandoffError> {
    let original = super::discovery::parse_host(manifest_path, bytes)?;
    if original.executable == config.executable() {
        return Err(configuration(
            "registration already points to Maka; restore the previous handoff first",
        ));
    }
    if !original
        .allowed_origins
        .contains(&format!("chrome-extension://{}/", config.extension_id()))
    {
        return Err(configuration(
            "original host registration does not allow the selected extension",
        ));
    }
    let mut manifest: serde_json::Value = serde_json::from_slice(bytes)?;
    manifest["path"] = serde_json::to_value(config.executable())?;
    Ok((original, serde_json::to_vec_pretty(&manifest)?))
}

#[cfg(windows)]
fn planned_file(path: PathBuf, bytes: Vec<u8>) -> Result<Change, HandoffError> {
    let slot = RegistrationSlot::Manifest(path);
    Ok(Change {
        before: storage::read(&slot)?,
        after: storage::replacement(&slot, bytes),
        slot,
    })
}
