// SPDX-License-Identifier: MIT

//! Explicit current-user registration; Maka is the default selection.
//!
//! This does not install an extension, change browser policies or approve sites.
//! An actual installed extension ID is a required setup parameter. Chatgpt
//! compatibility requires the explicit adapter option and actual extension ID.
//! Existing changed registrations refuse; only exactly matched maka entries remove.

use super::{
    extension_catalog,
    extension_host::{
        self, AdapterRegistration, ExistingRegistration, ExtensionOrigin, HostError,
        InstalledHostConfig, MAKA_HOST_NAME, Platform, RegistrationPlan,
    },
    local_ipc::{self, CreatedInstallationFile, IpcError},
};
use serde_json::Value;
use std::{
    ffi::OsString,
    io,
    path::{Path, PathBuf},
    process::ExitCode,
};

#[path = "extension_assets.rs"]
mod assets;

#[derive(Debug, thiserror::Error)]
pub(crate) enum InstallError {
    #[error(transparent)]
    Ipc(#[from] IpcError),
    #[error(transparent)]
    Host(#[from] HostError),
    #[error(transparent)]
    Catalog(#[from] extension_catalog::CatalogError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("connector setup refused: {0}")]
    Refused(String),
}

#[derive(Debug)]
pub(crate) struct InstallReport {
    pub(crate) created_entries: usize,
    pub(crate) unchanged_entries: usize,
}

fn current_plan(extension_id: &str) -> Result<RegistrationPlan, InstallError> {
    current_plan_for(AdapterRegistration::maka(ExtensionOrigin::from_id(
        extension_id,
    )?))
}

fn current_plan_for(adapter: AdapterRegistration) -> Result<RegistrationPlan, InstallError> {
    let executable = std::fs::canonicalize(std::env::current_exe()?)?;
    #[cfg(unix)]
    let home = std::env::var_os("HOME");
    #[cfg(windows)]
    let home = std::env::var_os("USERPROFILE");
    let home =
        std::fs::canonicalize(PathBuf::from(home.ok_or_else(|| {
            InstallError::Refused("user home is unavailable".to_owned())
        })?))?;
    let state = local_ipc::current_user_runtime_directory()?;
    #[cfg(target_os = "linux")]
    let platform = Platform::Linux;
    #[cfg(target_os = "macos")]
    let platform = Platform::Macos;
    #[cfg(target_os = "windows")]
    let platform = Platform::Windows;
    Ok(extension_host::registration_plan(
        &adapter,
        platform,
        &home,
        &executable,
        Some(&state),
    )?)
}

fn existing(path: &Path) -> Result<Option<Vec<u8>>, InstallError> {
    match local_ipc::load_private_installation_config(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(IpcError::MissingInstallationFile) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Perform only a setup action selected explicitly by the caller.
pub(crate) fn install_current_user(extension_id: &str) -> Result<InstallReport, InstallError> {
    install_plan(current_plan(extension_id)?)
}

fn chatgpt_registration(extension_id: &str) -> Result<AdapterRegistration, InstallError> {
    Ok(AdapterRegistration::selected_adapter(
        super::extension_process::CHATGPT_HOST_NAME,
        ExtensionOrigin::from_id(extension_id)?,
    )?)
}

fn install_chatgpt(extension_id: &str) -> Result<InstallReport, InstallError> {
    install_plan(current_plan_for(chatgpt_registration(extension_id)?)?)
}

fn install_plan(plan: RegistrationPlan) -> Result<InstallReport, InstallError> {
    ensure_no_alternate_registration(&plan)?;
    install_entries(plan)
}

fn install_entries(plan: RegistrationPlan) -> Result<InstallReport, InstallError> {
    let sidecar: InstalledHostConfig = serde_json::from_str(&plan.sidecar_json)?;
    let mutation = extension_catalog::Mutation::open(&sidecar.executable)?;
    local_ipc::ensure_private_state_directory(&sidecar.private_state_directory)?;
    mutation.load()?.validate_new_entry(&sidecar)?;
    local_ipc::ensure_installation_directory(
        plan.sidecar_path
            .parent()
            .ok_or_else(|| InstallError::Refused("installation entry lacks parent".to_owned()))?,
    )?;
    local_ipc::ensure_installation_directory(
        plan.manifest_path
            .parent()
            .ok_or_else(|| InstallError::Refused("manifest lacks parent".to_owned()))?,
    )?;
    let manifest = existing(&plan.manifest_path)?;
    let sidecar_existing = existing(&plan.sidecar_path)?;
    let manifest_action = plan.inspect_existing_manifest(manifest.as_deref())?;
    plan.inspect_existing_sidecar(sidecar_existing.as_deref())?;
    #[cfg(windows)]
    let registry_existing = registry::read(
        plan.registry
            .as_ref()
            .ok_or_else(|| InstallError::Refused("Windows registry plan is absent".to_owned()))?,
    )?;
    #[cfg(windows)]
    let registry_action = plan.inspect_existing_registry_value(registry_existing.as_deref())?;
    // Selected legacy migration commits independently. If a later write fails,
    // roll back only this transaction's new files, preserving the migrated registration.
    let migrated = mutation.migrate_legacy_for(&sidecar.adapter)?;
    let sidecar_existing = existing(&plan.sidecar_path)?;
    let sidecar_action = plan.inspect_existing_sidecar(sidecar_existing.as_deref())?;
    let mut created: Vec<CreatedInstallationFile> = Vec::new();
    let mut unchanged = 0;
    let writes = (|| {
        for (action, path, bytes) in [
            (
                sidecar_action,
                &plan.sidecar_path,
                plan.sidecar_json.as_bytes(),
            ),
            (
                manifest_action,
                &plan.manifest_path,
                plan.manifest_json.as_bytes(),
            ),
        ] {
            match action {
                ExistingRegistration::Create => {
                    created.push(local_ipc::create_installation_file(path, bytes)?)
                }
                ExistingRegistration::Unchanged => {
                    if !migrated || path != &plan.sidecar_path {
                        unchanged += 1;
                    }
                }
            }
        }
        #[cfg(windows)]
        match registry_action {
            ExistingRegistration::Create => {
                registry::create_exact(plan.registry.as_ref().expect("Windows plan checked above"))?
            }
            ExistingRegistration::Unchanged => unchanged += 1,
        }
        Ok::<(), InstallError>(())
    })();
    if let Err(error) = writes {
        let mut cleanup = Vec::new();
        for file in created.into_iter().rev() {
            if let Err(error) = file.rollback() {
                cleanup.push(error.to_string());
            }
        }
        return if cleanup.is_empty() {
            Err(error)
        } else {
            Err(InstallError::Refused(format!(
                "{error}; own-entry rollback unconfirmed: {}",
                cleanup.join("; ")
            )))
        };
    }
    let count = created.len() + usize::from(migrated);
    #[cfg(windows)]
    let count = count + usize::from(registry_action == ExistingRegistration::Create);
    Ok(InstallReport {
        created_entries: count,
        unchanged_entries: unchanged,
    })
}

#[derive(Debug)]
struct AlternateRegistration {
    location: String,
    present: bool,
}

fn refuse_alternate_presence(slots: &[AlternateRegistration]) -> Result<(), InstallError> {
    if let Some(slot) = slots.iter().find(|slot| slot.present) {
        return Err(InstallError::Refused(format!(
            "existing alternate extension-host registration at {}; refusing to shadow or bypass it",
            slot.location
        )));
    }
    Ok(())
}

#[cfg(any(unix, test))]
fn system_manifest(platform: Platform, namespace: &str) -> Option<PathBuf> {
    match platform {
        Platform::Linux => Some(
            PathBuf::from("/etc/opt/chrome/native-messaging-hosts")
                .join(format!("{namespace}.json")),
        ),
        Platform::Macos => Some(
            PathBuf::from("/Library/Google/Chrome/NativeMessagingHosts")
                .join(format!("{namespace}.json")),
        ),
        Platform::Windows => None,
    }
}

/// Google Chrome's exact selected namespace only; no profile or extension scan.
/// Alternate slots are presence-only refusals, including unreadable/reparse
/// entries. Setup never parses a root-owned system manifest as a private file.
fn ensure_no_alternate_registration(plan: &RegistrationPlan) -> Result<(), InstallError> {
    #[cfg(unix)]
    {
        let manifest: Value = serde_json::from_str(&plan.manifest_json)?;
        let namespace = manifest["name"]
            .as_str()
            .ok_or_else(|| InstallError::Refused("planned manifest lacks namespace".to_owned()))?;
        #[cfg(target_os = "linux")]
        let platform = Platform::Linux;
        #[cfg(target_os = "macos")]
        let platform = Platform::Macos;
        let path =
            system_manifest(platform, namespace).expect("supported POSIX Chrome has a system slot");
        let present = match std::fs::symlink_metadata(&path) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        refuse_alternate_presence(&[AlternateRegistration {
            location: path.display().to_string(),
            present,
        }])?;
    }
    #[cfg(windows)]
    registry::refuse_alternate_slots(
        plan.registry
            .as_ref()
            .ok_or_else(|| InstallError::Refused("Windows registry plan is absent".to_owned()))?,
    )?;
    Ok(())
}

pub(crate) fn uninstall_current_user() -> Result<(), InstallError> {
    uninstall_selected_current_user(MAKA_HOST_NAME)
}

fn uninstall_selected_current_user(expected_adapter: &str) -> Result<(), InstallError> {
    let executable = std::fs::canonicalize(std::env::current_exe()?)?;
    let mutation = extension_catalog::Mutation::open(&executable)?;
    let catalog = mutation.load()?;
    let entry = catalog.entry(expected_adapter)?;
    let installed = &entry.config;
    let bytes = local_ipc::load_private_installation_config(&entry.path)?;
    let plan = if expected_adapter == MAKA_HOST_NAME {
        current_plan(&installed.expected_extension_id)?
    } else if expected_adapter == super::extension_process::CHATGPT_HOST_NAME {
        current_plan_for(chatgpt_registration(&installed.expected_extension_id)?)?
    } else {
        return Err(InstallError::Refused(
            "unsupported selected adapter".to_owned(),
        ));
    };
    uninstall_entries(&mutation, &plan, installed, &bytes)
}

fn selected_installation(
    executable: &Path,
    expected_adapter: &str,
) -> Result<(InstalledHostConfig, Vec<u8>), InstallError> {
    let sidecar_path = extension_host::installed_adapter_path(executable, expected_adapter)?;
    let bytes = local_ipc::load_private_installation_config(&sidecar_path)?;
    let installed: InstalledHostConfig = serde_json::from_slice(&bytes)?;
    if installed.protocol != 1
        || installed.adapter != expected_adapter
        || std::fs::canonicalize(&installed.executable)? != executable
    {
        return Err(InstallError::Refused(
            "sidecar is not the exact explicitly selected executable registration".to_owned(),
        ));
    }
    Ok((installed, bytes))
}

fn uninstall_entries(
    mutation: &extension_catalog::Mutation,
    plan: &RegistrationPlan,
    installed: &InstalledHostConfig,
    bytes: &[u8],
) -> Result<(), InstallError> {
    plan.inspect_existing_sidecar(Some(bytes))?;
    let manifest = existing(&plan.manifest_path)?;
    plan.inspect_existing_manifest(manifest.as_deref())?;
    #[cfg(windows)]
    let registry_present = {
        let entry = plan
            .registry
            .as_ref()
            .ok_or_else(|| InstallError::Refused("Windows registry plan is absent".to_owned()))?;
        let value = registry::read(entry)?;
        plan.inspect_existing_registry_value(value.as_deref())?;
        value.is_some()
    };
    // Refuse changed browser registrations before selected legacy migration
    // removes its source. The guard also spans the resulting exact-slot removal.
    mutation.migrate_legacy_for(&installed.adapter)?;
    let (_, selected_bytes) = selected_installation(&installed.executable, &installed.adapter)?;
    plan.inspect_existing_sidecar(Some(&selected_bytes))?;
    #[cfg(windows)]
    if registry_present {
        registry::remove_exact(plan.registry.as_ref().expect("Windows plan checked above"))?;
    }
    if manifest.is_some() {
        local_ipc::remove_exact_installation_file(
            &plan.manifest_path,
            &serde_json::from_str::<Value>(&plan.manifest_json)?,
        )?;
    }
    local_ipc::remove_exact_installation_file(
        &plan.sidecar_path,
        &serde_json::from_str::<Value>(&plan.sidecar_json)?,
    )?;
    Ok(())
}

fn export_extension(destination: &Path) -> Result<InstallReport, InstallError> {
    if !destination.is_absolute() {
        return Err(InstallError::Refused(
            "extension export directory must be absolute".to_owned(),
        ));
    }
    local_ipc::ensure_installation_directory(destination)?;
    for entry in std::fs::read_dir(destination)? {
        let name = entry?.file_name();
        if !assets::EXTENSION_ASSETS
            .iter()
            .any(|(expected, _)| Some(*expected) == name.to_str())
        {
            return Err(InstallError::Refused(
                "extension export directory contains an unrelated entry".to_owned(),
            ));
        }
    }
    let mut missing = Vec::new();
    let mut unchanged = 0;
    for (name, body) in assets::EXTENSION_ASSETS {
        let path = destination.join(name);
        match existing(&path)? {
            None => missing.push((path, body.as_bytes())),
            Some(bytes) if bytes == body.as_bytes() => unchanged += 1,
            Some(_) => {
                return Err(InstallError::Refused(
                    "refusing to overwrite changed extension source".to_owned(),
                ));
            }
        }
    }
    let mut created = Vec::new();
    for (path, body) in missing {
        match local_ipc::create_installation_file(&path, body) {
            Ok(file) => created.push(file),
            Err(error) => {
                let mut cleanup = Vec::new();
                for file in created.into_iter().rev() {
                    if let Err(error) = file.rollback() {
                        cleanup.push(error.to_string());
                    }
                }
                return if cleanup.is_empty() {
                    Err(error.into())
                } else {
                    Err(InstallError::Refused(format!(
                        "{error}; own export rollback unconfirmed: {}",
                        cleanup.join("; ")
                    )))
                };
            }
        }
    }
    Ok(InstallReport {
        created_entries: created.len(),
        unchanged_entries: unchanged,
    })
}

enum SetupCommand {
    Install(String),
    InstallChatgpt { extension_id: String },
    Uninstall,
    UninstallChatgpt,
    Export(PathBuf),
}
fn setup_command(arguments: &[OsString]) -> Option<Result<SetupCommand, InstallError>> {
    if arguments.first().and_then(|arg| arg.to_str()) != Some("browser") {
        return None;
    }
    match arguments.get(1).and_then(|arg| arg.to_str()) {
        Some("install") => Some(match arguments {
            [_, _, flag, id] if flag == "--extension-id" => id
                .to_str()
                .ok_or_else(|| InstallError::Refused("extension ID is not Unicode".to_owned()))
                .and_then(|id| {
                    ExtensionOrigin::from_id(id)?;
                    Ok(SetupCommand::Install(id.to_owned()))
                }),
            [_, _, provider_flag, provider, id_flag, id]
                if provider_flag == "--provider" && id_flag == "--extension-id" =>
            {
                id.to_str()
                    .ok_or_else(|| InstallError::Refused("extension ID is not Unicode".to_owned()))
                    .and_then(|id| {
                        if provider == "maka" {
                            ExtensionOrigin::from_id(id)?;
                            Ok(SetupCommand::Install(id.to_owned()))
                        } else if provider == "chatgpt" {
                            chatgpt_registration(id)?;
                            Ok(SetupCommand::InstallChatgpt { extension_id: id.to_owned() })
                        } else {
                            Err(InstallError::Refused("browser provider must be maka or chatgpt".to_owned()))
                        }
                    })
            }
            _ => Err(InstallError::Refused(
                "use browser install [--provider maka|chatgpt] --extension-id <actual-extension-id>".to_owned(),
            )),
        }),
        Some("uninstall") => Some(match arguments {
            [_, _] => Ok(SetupCommand::Uninstall),
            [_, _, provider_flag, provider] if provider_flag == "--provider" => {
                if provider == "maka" {
                    Ok(SetupCommand::Uninstall)
                } else if provider == "chatgpt" {
                    Ok(SetupCommand::UninstallChatgpt)
                } else {
                    Err(InstallError::Refused("browser provider must be maka or chatgpt".to_owned()))
                }
            }
            _ => Err(InstallError::Refused(
                "use browser uninstall [--provider maka|chatgpt]".to_owned(),
            )),
        }),
        Some("extension") => Some(match arguments {
            [_, _, flag, path] if flag == "--output" => {
                Ok(SetupCommand::Export(PathBuf::from(path)))
            }
            _ => Err(InstallError::Refused(
                "use browser extension --output <absolute-empty-directory>".to_owned(),
            )),
        }),
        _ => None,
    }
}

pub(crate) fn bootstrap_setup(arguments: &[OsString]) -> Option<ExitCode> {
    let command = setup_command(arguments)?;
    let outcome = match command {
        Ok(SetupCommand::Install(id)) => install_current_user(&id).map(|report| {
            format!(
                "Registered own browser connector: {} created, {} unchanged; install or enable the matching own extension in Chrome.",
                report.created_entries, report.unchanged_entries,
            )
        }),
        Ok(SetupCommand::InstallChatgpt { extension_id }) => {
            install_chatgpt(&extension_id).map(|report| {
                format!(
                    "Registered explicitly selected ChatGPT provider: {} created, {} unchanged.",
                    report.created_entries, report.unchanged_entries,
                )
            })
        }
        Ok(SetupCommand::Uninstall) => uninstall_current_user()
            .map(|()| "Removed exact own browser connector registration.".to_owned()),
        Ok(SetupCommand::UninstallChatgpt) => {
            uninstall_selected_current_user(super::extension_process::CHATGPT_HOST_NAME)
                .map(|()| "Removed exact selected ChatGPT provider registration.".to_owned())
        }
        Ok(SetupCommand::Export(path)) => export_extension(&path).map(|report| {
            format!(
                "Exported own extension source: {} created, {} unchanged. Install it with Chrome's extension UI, then register its actual ID with browser install --extension-id.",
                report.created_entries, report.unchanged_entries,
            )
        }),
        Err(error) => Err(error),
    };
    Some(match outcome {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Maka browser setup failed: {error}");
            ExitCode::FAILURE
        }
    })
}

#[cfg(windows)]
mod registry {
    use super::*;
    use crate::browser::extension_host::RegistryEntry;
    use std::ffi::c_void;
    type Key = *mut c_void;
    const CURRENT_USER: Key = (0x8000_0001_u32 as i32 as isize) as Key;
    const LOCAL_MACHINE: Key = (0x8000_0002_u32 as i32 as isize) as Key;
    const VIEW_32: u32 = 0x0200;
    const VIEW_64: u32 = 0x0100;
    // Pin both install and removal to the same view across process architecture.
    const SELECTED_VIEW: u32 = VIEW_64;
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn RegOpenKeyExW(
            key: Key,
            name: *const u16,
            options: u32,
            access: u32,
            result: *mut Key,
        ) -> i32;
        fn RegCreateKeyExW(
            key: Key,
            name: *const u16,
            reserved: u32,
            class: *mut u16,
            options: u32,
            access: u32,
            security: *const c_void,
            result: *mut Key,
            disposition: *mut u32,
        ) -> i32;
        fn RegQueryValueExW(
            key: Key,
            name: *const u16,
            reserved: *mut u32,
            kind: *mut u32,
            data: *mut u8,
            bytes: *mut u32,
        ) -> i32;
        fn RegSetValueExW(
            key: Key,
            name: *const u16,
            reserved: u32,
            kind: u32,
            data: *const u8,
            bytes: u32,
        ) -> i32;
        fn RegDeleteValueW(key: Key, name: *const u16) -> i32;
        fn RegCloseKey(key: Key) -> i32;
    }
    struct OwnedKey(Key);
    impl Drop for OwnedKey {
        fn drop(&mut self) {
            // SAFETY: this guard uniquely owns a successful registry open/create.
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }
    fn subkey(entry: &RegistryEntry) -> Result<Vec<u16>, InstallError> {
        let text = entry.key.strip_prefix("HKCU\\").ok_or_else(|| {
            InstallError::Refused("registry plan is not current-user scoped".to_owned())
        })?;
        Ok(text.encode_utf16().chain(Some(0)).collect())
    }
    fn status(error: i32) -> Result<(), InstallError> {
        if error == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(error).into())
        }
    }
    fn value(key: Key) -> Result<Option<String>, InstallError> {
        let mut kind = 0;
        let mut bytes = 0;
        // SAFETY: querying an unnamed value size writes only these outputs.
        let error = unsafe {
            RegQueryValueExW(
                key,
                std::ptr::null(),
                std::ptr::null_mut(),
                &mut kind,
                std::ptr::null_mut(),
                &mut bytes,
            )
        };
        if error == 2 {
            return Ok(None);
        }
        status(error)?;
        if kind != 1 || !(2..=65536).contains(&bytes) || bytes % 2 != 0 {
            return Err(InstallError::Refused(
                "extension host registry value is not bounded REG_SZ".to_owned(),
            ));
        }
        let mut data = vec![0_u16; (bytes / 2) as usize];
        // SAFETY: the allocated UTF-16 buffer fits the probed byte count.
        status(unsafe {
            RegQueryValueExW(
                key,
                std::ptr::null(),
                std::ptr::null_mut(),
                &mut kind,
                data.as_mut_ptr().cast(),
                &mut bytes,
            )
        })?;
        if kind != 1 || bytes < 2 || bytes % 2 != 0 || bytes as usize > data.len() * 2 {
            return Err(InstallError::Refused(
                "extension host registry value changed during read".to_owned(),
            ));
        }
        data.truncate((bytes / 2) as usize);
        if data.last() != Some(&0) {
            return Err(InstallError::Refused(
                "extension host registry value lacks terminator".to_owned(),
            ));
        }
        data.pop();
        if data.contains(&0) {
            return Err(InstallError::Refused(
                "extension host registry value contains NUL".to_owned(),
            ));
        }
        Ok(Some(String::from_utf16(&data).map_err(|_| {
            InstallError::Refused("extension host registry value is not UTF-16".to_owned())
        })?))
    }
    pub(super) fn read(entry: &RegistryEntry) -> Result<Option<String>, InstallError> {
        let name = subkey(entry)?;
        let mut key = std::ptr::null_mut();
        // SAFETY: the fixed current-user key and terminated subkey are valid.
        let error =
            unsafe { RegOpenKeyExW(CURRENT_USER, name.as_ptr(), 0, 1 | SELECTED_VIEW, &mut key) };
        if error == 2 {
            return Ok(None);
        }
        status(error)?;
        let key = OwnedKey(key);
        value(key.0)
    }
    pub(super) fn create_exact(entry: &RegistryEntry) -> Result<(), InstallError> {
        let name = subkey(entry)?;
        let mut key = std::ptr::null_mut();
        // SAFETY: only the explicit maka current-user registration is selected.
        status(unsafe {
            RegCreateKeyExW(
                CURRENT_USER,
                name.as_ptr(),
                0,
                std::ptr::null_mut(),
                0,
                1 | 2 | SELECTED_VIEW,
                std::ptr::null(),
                &mut key,
                std::ptr::null_mut(),
            )
        })?;
        let key = OwnedKey(key);
        if let Some(actual) = value(key.0)? {
            return if actual == entry.value {
                Ok(())
            } else {
                Err(InstallError::Refused(
                    "refusing to overwrite a changed extension-host registry value".to_owned(),
                ))
            };
        }
        let data = entry
            .value
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let bytes = u32::try_from(data.len() * 2)
            .map_err(|_| InstallError::Refused("registry path exceeds byte range".to_owned()))?;
        // SAFETY: data remains allocated for its complete UTF-16 byte count.
        status(unsafe {
            RegSetValueExW(key.0, std::ptr::null(), 0, 1, data.as_ptr().cast(), bytes)
        })
    }
    pub(super) fn remove_exact(entry: &RegistryEntry) -> Result<(), InstallError> {
        let name = subkey(entry)?;
        let mut key = std::ptr::null_mut();
        // SAFETY: open only the current-user registration value for this plan.
        status(unsafe {
            RegOpenKeyExW(
                CURRENT_USER,
                name.as_ptr(),
                0,
                1 | 2 | SELECTED_VIEW,
                &mut key,
            )
        })?;
        let key = OwnedKey(key);
        if value(key.0)?.as_deref() != Some(entry.value.as_str()) {
            return Err(InstallError::Refused(
                "refusing to remove a changed registry registration".to_owned(),
            ));
        }
        // SAFETY: delete only this exact unnamed value. Other named values and
        // subkeys are deliberately retained; no whole-key deletion occurs.
        status(unsafe { RegDeleteValueW(key.0, std::ptr::null()) })
    }

    pub(super) fn refuse_alternate_slots(entry: &RegistryEntry) -> Result<(), InstallError> {
        let name = subkey(entry)?;
        let mut slots = Vec::new();
        for (root, view, label) in [
            (CURRENT_USER, VIEW_32, "HKCU32"),
            (LOCAL_MACHINE, VIEW_32, "HKLM32"),
            (LOCAL_MACHINE, VIEW_64, "HKLM64"),
        ] {
            let mut raw = std::ptr::null_mut();
            // SAFETY: fixed Chrome namespace, explicit hive/view and terminated
            // subkey only. This never writes or reads arbitrary named values.
            let result = unsafe { RegOpenKeyExW(root, name.as_ptr(), 0, 1 | view, &mut raw) };
            let present = if result == 2 {
                false
            } else {
                status(result)?;
                let _key = OwnedKey(raw);
                true
            };
            slots.push(AlternateRegistration {
                location: format!("{label} {}", entry.key.trim_start_matches("HKCU\\")),
                present,
            });
        }
        refuse_alternate_presence(&slots)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    struct InstallationFixture {
        _root: tempfile::TempDir,
        home: PathBuf,
        executable: PathBuf,
    }

    #[cfg(unix)]
    impl InstallationFixture {
        fn new() -> Self {
            use std::os::unix::fs::PermissionsExt;

            let root = tempfile::tempdir().unwrap();
            let root_path = std::fs::canonicalize(root.path()).unwrap();
            let home = root_path.join("home");
            local_ipc::ensure_installation_directory(&home).unwrap();
            let bin = home.join("bin");
            local_ipc::ensure_installation_directory(&bin).unwrap();
            let executable = bin.join("fixture-host");
            std::fs::write(&executable, b"installation fixture only").unwrap();
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
            local_ipc::ensure_private_state_directory(&home.join(".maka-browser")).unwrap();
            let mut directory = home.clone();
            for component in [".config", "google-chrome", "NativeMessagingHosts"] {
                directory.push(component);
                local_ipc::ensure_installation_directory(&directory).unwrap();
            }
            Self {
                _root: root,
                home,
                executable,
            }
        }

        fn plan(&self, adapter: &str, extension_id: &str) -> RegistrationPlan {
            let registration = AdapterRegistration::selected_adapter(
                adapter,
                ExtensionOrigin::from_id(extension_id).unwrap(),
            )
            .unwrap();
            extension_host::registration_plan(
                &registration,
                Platform::Linux,
                &self.home,
                &self.executable,
                None,
            )
            .unwrap()
        }

        fn legacy(&self, plan: &RegistrationPlan) -> Vec<u8> {
            let bytes = format!("{}\n", plan.sidecar_json).into_bytes();
            let path = extension_host::installed_sidecar_path(&self.executable).unwrap();
            local_ipc::create_installation_file(&path, &bytes).unwrap();
            bytes
        }

        fn uninstall(&self, plan: &RegistrationPlan) -> Result<(), InstallError> {
            let expected: InstalledHostConfig = serde_json::from_str(&plan.sidecar_json)?;
            let mutation = extension_catalog::Mutation::open(&self.executable)?;
            let catalog = mutation.load()?;
            let entry = catalog.entry(&expected.adapter)?;
            let bytes = local_ipc::load_private_installation_config(&entry.path)?;
            uninstall_entries(&mutation, plan, &entry.config, &bytes)
        }
    }

    #[cfg(unix)]
    #[test]
    fn adapter_installations_coexist_and_uninstall_removes_only_the_selected_slot() {
        let fixture = InstallationFixture::new();
        let maka = fixture.plan(MAKA_HOST_NAME, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let original = fixture.plan(
            super::super::extension_process::CHATGPT_HOST_NAME,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        for plan in [&maka, &original] {
            let report = install_entries(plan.clone()).unwrap();
            assert_eq!((report.created_entries, report.unchanged_entries), (2, 0));
        }
        let other_slot =
            local_ipc::load_private_installation_config(&original.sidecar_path).unwrap();
        let other_manifest =
            local_ipc::load_private_installation_config(&original.manifest_path).unwrap();
        let report = install_entries(maka.clone()).unwrap();
        assert_eq!((report.created_entries, report.unchanged_entries), (0, 2));

        fixture.uninstall(&maka).unwrap();
        assert!(!maka.sidecar_path.exists());
        assert!(!maka.manifest_path.exists());
        assert_eq!(
            local_ipc::load_private_installation_config(&original.sidecar_path).unwrap(),
            other_slot
        );
        assert_eq!(
            local_ipc::load_private_installation_config(&original.manifest_path).unwrap(),
            other_manifest
        );
        assert!(
            extension_host::installed_catalog_directory(&fixture.executable)
                .unwrap()
                .is_dir()
        );
    }

    #[cfg(unix)]
    #[test]
    fn selected_installation_never_defaults_to_another_installed_adapter() {
        let fixture = InstallationFixture::new();
        let original = fixture.plan(
            super::super::extension_process::CHATGPT_HOST_NAME,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        install_entries(original.clone()).unwrap();
        let other_bytes =
            local_ipc::load_private_installation_config(&original.sidecar_path).unwrap();
        let maka = fixture.plan(MAKA_HOST_NAME, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(matches!(
            fixture.uninstall(&maka),
            Err(InstallError::Catalog(extension_catalog::CatalogError::Refused(message)))
                if message == format!("selected adapter {MAKA_HOST_NAME} is not installed")
        ));
        assert_eq!(
            local_ipc::load_private_installation_config(&original.sidecar_path).unwrap(),
            other_bytes
        );
    }

    #[cfg(unix)]
    #[test]
    fn another_adapters_legacy_bytes_are_untouched_by_install_and_uninstall() {
        let fixture = InstallationFixture::new();
        let maka = fixture.plan(MAKA_HOST_NAME, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let original = fixture.plan(
            super::super::extension_process::CHATGPT_HOST_NAME,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        let legacy_bytes = fixture.legacy(&maka);
        let legacy_path = extension_host::installed_sidecar_path(&fixture.executable).unwrap();
        install_entries(original.clone()).unwrap();
        assert_eq!(
            local_ipc::load_private_installation_config(&legacy_path).unwrap(),
            legacy_bytes
        );
        assert!(!maka.sidecar_path.exists());
        fixture.uninstall(&original).unwrap();
        assert_eq!(
            local_ipc::load_private_installation_config(&legacy_path).unwrap(),
            legacy_bytes
        );
        assert!(!maka.sidecar_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn selected_legacy_migration_is_counted_once_and_is_idempotent() {
        let fixture = InstallationFixture::new();
        let maka = fixture.plan(MAKA_HOST_NAME, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let legacy_bytes = fixture.legacy(&maka);
        local_ipc::create_installation_file(&maka.manifest_path, maka.manifest_json.as_bytes())
            .unwrap();
        let report = install_entries(maka.clone()).unwrap();
        assert_eq!((report.created_entries, report.unchanged_entries), (1, 1));
        assert_eq!(
            local_ipc::load_private_installation_config(&maka.sidecar_path).unwrap(),
            legacy_bytes
        );
        assert!(
            !extension_host::installed_sidecar_path(&fixture.executable)
                .unwrap()
                .exists()
        );
        let report = install_entries(maka.clone()).unwrap();
        assert_eq!((report.created_entries, report.unchanged_entries), (0, 2));
        fixture.uninstall(&maka).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn selected_uninstall_migrates_legacy_before_removing_only_that_registration() {
        let fixture = InstallationFixture::new();
        let maka = fixture.plan(MAKA_HOST_NAME, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        fixture.legacy(&maka);
        local_ipc::create_installation_file(&maka.manifest_path, maka.manifest_json.as_bytes())
            .unwrap();
        fixture.uninstall(&maka).unwrap();
        assert!(!maka.sidecar_path.exists());
        assert!(!maka.manifest_path.exists());
        assert!(
            !extension_host::installed_sidecar_path(&fixture.executable)
                .unwrap()
                .exists()
        );
        assert!(
            extension_host::installed_catalog_directory(&fixture.executable)
                .unwrap()
                .is_dir()
        );
    }

    #[cfg(unix)]
    #[test]
    fn changed_manifest_refuses_before_committing_selected_migration() {
        let fixture = InstallationFixture::new();
        let maka = fixture.plan(MAKA_HOST_NAME, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let legacy_bytes = fixture.legacy(&maka);
        let mut changed: Value = serde_json::from_str(&maka.manifest_json).unwrap();
        changed["path"] = Value::String("/unrelated-host".to_owned());
        let changed_bytes = serde_json::to_vec(&changed).unwrap();
        local_ipc::create_installation_file(&maka.manifest_path, &changed_bytes).unwrap();
        assert!(matches!(
            install_entries(maka.clone()),
            Err(InstallError::Host(HostError::RegistrationConflict))
        ));
        assert_eq!(
            local_ipc::load_private_installation_config(
                &extension_host::installed_sidecar_path(&fixture.executable).unwrap()
            )
            .unwrap(),
            legacy_bytes
        );
        assert!(!maka.sidecar_path.exists());
        assert_eq!(
            local_ipc::load_private_installation_config(&maka.manifest_path).unwrap(),
            changed_bytes
        );
    }

    #[cfg(unix)]
    #[test]
    fn legacy_uninstall_refuses_changed_manifest_without_migrating_or_touching_other_entries() {
        let fixture = InstallationFixture::new();
        let maka = fixture.plan(MAKA_HOST_NAME, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let original = fixture.plan(
            super::super::extension_process::CHATGPT_HOST_NAME,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        let legacy_bytes = fixture.legacy(&maka);
        install_entries(original.clone()).unwrap();
        let other_slot =
            local_ipc::load_private_installation_config(&original.sidecar_path).unwrap();
        let other_manifest =
            local_ipc::load_private_installation_config(&original.manifest_path).unwrap();
        let mut changed: Value = serde_json::from_str(&maka.manifest_json).unwrap();
        changed["path"] = Value::String("/unrelated-host".to_owned());
        let changed_bytes = serde_json::to_vec(&changed).unwrap();
        local_ipc::create_installation_file(&maka.manifest_path, &changed_bytes).unwrap();

        assert!(matches!(
            fixture.uninstall(&maka),
            Err(InstallError::Host(HostError::RegistrationConflict))
        ));
        assert_eq!(
            local_ipc::load_private_installation_config(
                &extension_host::installed_sidecar_path(&fixture.executable).unwrap()
            )
            .unwrap(),
            legacy_bytes
        );
        assert!(!maka.sidecar_path.exists());
        for (path, expected) in [
            (&maka.manifest_path, changed_bytes),
            (&original.sidecar_path, other_slot),
            (&original.manifest_path, other_manifest),
        ] {
            assert_eq!(
                local_ipc::load_private_installation_config(path).unwrap(),
                expected,
                "uninstall refusal must preserve {}",
                path.display()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn write_failure_rolls_back_new_slot_but_preserves_committed_migration() {
        for migrate in [false, true] {
            let fixture = InstallationFixture::new();
            let mut maka = fixture.plan(MAKA_HOST_NAME, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            let legacy_bytes = migrate.then(|| fixture.legacy(&maka));
            // The second publication collides with the first selected-slot
            // publication, exercising the same post-write rollback as a race.
            maka.manifest_path = maka.sidecar_path.clone();
            assert!(matches!(
                install_entries(maka.clone()),
                Err(InstallError::Ipc(IpcError::Io(error)))
                    if error.kind() == io::ErrorKind::AlreadyExists
            ));
            if let Some(expected) = legacy_bytes {
                assert_eq!(
                    local_ipc::load_private_installation_config(&maka.sidecar_path).unwrap(),
                    expected,
                    "independently committed migration must survive later failure"
                );
                assert!(
                    !extension_host::installed_sidecar_path(&fixture.executable)
                        .unwrap()
                        .exists()
                );
            } else {
                assert!(
                    !maka.sidecar_path.exists(),
                    "new transaction slot must roll back"
                );
            }
        }
    }

    #[test]
    fn removed_custom_adapter_setup_commands_are_refused() {
        for arguments in [
            vec![
                "browser",
                "install",
                "--provider",
                "opencli",
                "--extension-id",
                "cccccccccccccccccccccccccccccccc",
            ],
            vec![
                "browser",
                "install",
                "--provider",
                "opencli-exec",
                "--extension-id",
                "cccccccccccccccccccccccccccccccc",
            ],
        ] {
            assert!(matches!(
                setup_command(&arguments.into_iter().map(OsString::from).collect::<Vec<_>>()),
                Some(Err(InstallError::Refused(message)))
                    if message == "browser provider must be maka or chatgpt"
            ));
        }
        assert!(matches!(
            setup_command(&["browser".into(), "uninstall".into(), "--provider".into(), "opencli".into()]),
            Some(Err(InstallError::Refused(message)))
                if message == "browser provider must be maka or chatgpt"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn removed_custom_registration_cannot_change_existing_adapters() {
        let fixture = InstallationFixture::new();
        let maka = fixture.plan(MAKA_HOST_NAME, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let original = fixture.plan(
            super::super::extension_process::CHATGPT_HOST_NAME,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        for plan in [&maka, &original] {
            install_entries(plan.clone()).unwrap();
        }
        let retained = [
            &maka.sidecar_path,
            &maka.manifest_path,
            &original.sidecar_path,
            &original.manifest_path,
        ]
        .map(|path| (path.clone(), std::fs::read(path).unwrap()));
        let removed = fixture.plan(
            "org.apache.maka.opencli_connector",
            "cccccccccccccccccccccccccccccccc",
        );
        assert!(matches!(
            install_entries(removed.clone()),
            Err(InstallError::Catalog(extension_catalog::CatalogError::Refused(message)))
                if message == "unsupported installation protocol or adapter"
        ));
        assert!(!removed.sidecar_path.exists());
        assert!(!removed.manifest_path.exists());
        for (path, bytes) in retained {
            assert_eq!(std::fs::read(path).unwrap(), bytes);
        }
    }

    #[test]
    fn explicit_install_requires_actual_extension_id_and_no_extra_authority() {
        assert!(
            setup_command(&["browser".into(), "install".into()])
                .unwrap()
                .is_err()
        );
        assert!(
            setup_command(&[
                "browser".into(),
                "install".into(),
                "--extension-id".into(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()
            ])
            .unwrap()
            .is_ok()
        );
        assert!(
            setup_command(&[
                "browser".into(),
                "install".into(),
                "--extension-id".into(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                "--host".into(),
                "foreign.host".into()
            ])
            .unwrap()
            .is_err()
        );
    }
    #[test]
    fn other_cli_commands_never_enter_setup() {
        assert!(setup_command(&["--help".into()]).is_none());
        assert!(setup_command(&["browser".into(), "list".into()]).is_none());
        assert!(
            setup_command(&["chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/".into()])
                .is_none()
        );
    }

    #[test]
    fn fixed_ui_assets_export_and_reimport_flat_without_replacing_changed_bytes() {
        let root = tempfile::tempdir().unwrap();
        let destination = std::fs::canonicalize(root.path())
            .unwrap()
            .join("extension");
        let first = export_extension(&destination).unwrap();
        assert_eq!(first.created_entries, assets::EXTENSION_ASSETS.len());
        assert_eq!(first.unchanged_entries, 0);
        let expected = [
            (
                "maka-ui-cursor.js",
                include_str!("extension_assets/maka-ui/cursor.js"),
            ),
            (
                "maka-ui-LICENSE",
                include_str!("extension_assets/maka-ui/LICENSE"),
            ),
            (
                "maka-ui-NOTICE",
                include_str!("extension_assets/maka-ui/NOTICE"),
            ),
            (
                "maka-ui-UPSTREAM.json",
                include_str!("extension_assets/maka-ui/UPSTREAM.json"),
            ),
        ];
        for (name, source) in expected {
            assert_eq!(
                std::fs::read(destination.join(name)).unwrap(),
                source.as_bytes()
            );
        }
        assert_eq!(
            std::fs::read(destination.join("maka-ui-cursor.js")).unwrap(),
            super::super::FIXED_BROWSER_UI_SCRIPT.as_bytes(),
        );
        assert!(
            std::fs::read_dir(&destination)
                .unwrap()
                .all(|entry| { entry.unwrap().file_type().unwrap().is_file() })
        );
        let second = export_extension(&destination).unwrap();
        assert_eq!(second.created_entries, 0);
        assert_eq!(second.unchanged_entries, assets::EXTENSION_ASSETS.len());

        let cursor = destination.join("maka-ui-cursor.js");
        std::fs::write(&cursor, b"changed by the installed source owner").unwrap();
        let before: Vec<_> = assets::EXTENSION_ASSETS
            .iter()
            .map(|(name, _)| {
                (
                    (*name).to_owned(),
                    std::fs::read(destination.join(name)).unwrap(),
                )
            })
            .collect();
        let error = export_extension(&destination).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("refusing to overwrite changed extension source")
        );
        for (name, bytes) in before {
            assert_eq!(std::fs::read(destination.join(name)).unwrap(), bytes);
        }
    }

    #[test]
    fn exported_package_contains_manifest_worker_and_static_module_imports() {
        let find = |name: &str| {
            assets::EXTENSION_ASSETS
                .iter()
                .find_map(|(path, body)| (*path == name).then_some(*body))
        };
        let manifest: Value = serde_json::from_str(find("manifest.json").unwrap()).unwrap();
        let worker = manifest["background"]["service_worker"].as_str().unwrap();
        assert!(find(worker).is_some(), "manifest worker must be exported");
        for (name, source) in assets::EXTENSION_ASSETS {
            if !name.ends_with(".mjs") {
                continue;
            }
            for line in source.lines() {
                for quote in ["'", "\""] {
                    let marker = format!("from {quote}./");
                    if let Some((_, rest)) = line.split_once(&marker) {
                        let dependency = rest.split(quote).next().unwrap();
                        assert!(
                            find(dependency).is_some(),
                            "missing exported module {dependency} imported by {name}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn explicit_export_has_no_registration_authority() {
        assert!(matches!(
            setup_command(&[
                "browser".into(),
                "extension".into(),
                "--output".into(),
                "/private-fixture".into()
            ])
            .unwrap()
            .unwrap(),
            SetupCommand::Export(_)
        ));
        assert!(
            setup_command(&[
                "browser".into(),
                "extension".into(),
                "--output".into(),
                "/private-fixture".into(),
                "--extension-id".into(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()
            ])
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn provider_setup_defaults_to_maka_and_refuses_legacy_aliases() {
        let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
        let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        for values in [
            vec!["browser", "install", "--extension-id", id],
            vec![
                "browser",
                "install",
                "--provider",
                "maka",
                "--extension-id",
                id,
            ],
        ] {
            assert!(
                matches!(setup_command(&args(&values)).unwrap().unwrap(), SetupCommand::Install(actual) if actual == id)
            );
        }
        assert!(matches!(
            setup_command(&args(&["browser", "uninstall", "--provider", "maka"]))
                .unwrap()
                .unwrap(),
            SetupCommand::Uninstall
        ));
        for values in [
            vec![
                "browser",
                "install",
                "--adapter",
                "original",
                "--extension-id",
                id,
            ],
            vec![
                "browser",
                "install",
                "--provider",
                "original",
                "--extension-id",
                id,
            ],
        ] {
            assert!(setup_command(&args(&values)).unwrap().is_err());
        }
    }

    #[test]
    fn original_setup_uses_explicit_adapter_and_actual_extension_id() {
        let valid = [
            "browser",
            "install",
            "--provider",
            "chatgpt",
            "--extension-id",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ];
        let parsed = setup_command(&valid.map(OsString::from)).unwrap().unwrap();
        assert!(
            matches!(parsed, SetupCommand::InstallChatgpt { extension_id }
            if extension_id == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        for invalid in [
            "",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
        ] {
            let mut arguments = valid.map(OsString::from);
            arguments[5] = invalid.into();
            assert!(
                setup_command(&arguments).unwrap().is_err(),
                "invalid ID {invalid:?}"
            );
        }
        assert!(
            setup_command(&[
                "browser".into(),
                "install".into(),
                "--provider".into(),
                "chatgpt".into(),
            ])
            .unwrap()
            .is_err()
        );
        assert!(matches!(
            setup_command(&[
                "browser".into(),
                "uninstall".into(),
                "--provider".into(),
                "chatgpt".into(),
            ])
            .unwrap()
            .unwrap(),
            SetupCommand::UninstallChatgpt
        ));
        assert!(matches!(
            setup_command(&[
                "browser".into(),
                "install".into(),
                "--extension-id".into(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()
            ])
            .unwrap()
            .unwrap(),
            SetupCommand::Install(_)
        ));
    }

    #[test]
    fn selected_original_plan_refuses_foreign_host_and_changed_selection_identity() {
        let plan = extension_host::registration_plan(
            &chatgpt_registration("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            Platform::Linux,
            Path::new("/fixture-user"),
            Path::new("/fixture-user/bin/maka"),
            None,
        )
        .unwrap();
        let mut manifest: Value = serde_json::from_str(&plan.manifest_json).unwrap();
        manifest["path"] = Value::String("/fixture-official-app/native-host".to_owned());
        assert!(matches!(
            plan.inspect_existing_manifest(Some(&serde_json::to_vec(&manifest).unwrap())),
            Err(HostError::RegistrationConflict)
        ));
        assert_eq!(
            plan.inspect_existing_sidecar(Some(plan.sidecar_json.as_bytes()))
                .unwrap(),
            ExistingRegistration::Unchanged
        );
        for (field, value) in [
            ("adapter", MAKA_HOST_NAME),
            ("expectedExtensionId", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            ("executable", "/fixture-other/bin/maka"),
            ("privateStateDirectory", "/fixture-other/state"),
        ] {
            let mut sidecar: Value = serde_json::from_str(&plan.sidecar_json).unwrap();
            sidecar[field] = Value::String(value.to_owned());
            assert!(
                matches!(
                    plan.inspect_existing_sidecar(Some(&serde_json::to_vec(&sidecar).unwrap())),
                    Err(HostError::RegistrationConflict)
                ),
                "changed {field} must not match the installed selection"
            );
        }
    }

    #[test]
    fn alternate_windows_view_or_system_manifest_prevents_shadow_install() {
        assert!(
            matches!(refuse_alternate_presence(&[AlternateRegistration{location:"HKCU32 selected namespace".to_owned(),present:true}]),Err(InstallError::Refused(message)) if message.contains("refusing to shadow or bypass"))
        );
        for platform in [Platform::Linux, Platform::Macos] {
            let path =
                system_manifest(platform, super::super::extension_process::CHATGPT_HOST_NAME)
                    .unwrap();
            assert!(matches!(
                refuse_alternate_presence(&[AlternateRegistration {
                    location: path.display().to_string(),
                    present: true
                }]),
                Err(InstallError::Refused(_))
            ));
        }
        assert!(
            refuse_alternate_presence(&[AlternateRegistration {
                location: "absent alternate slot".to_owned(),
                present: false
            }])
            .is_ok()
        );
    }
}
