// SPDX-License-Identifier: MIT

//! Explicit current-user registration; Own is the default selection.
//!
//! This does not install an extension, change browser policies or approve sites.
//! An actual installed extension ID is a required setup parameter. Original
//! compatibility requires the explicit adapter option and actual extension ID.
//! Existing changed registrations refuse; only exactly matched own entries remove.

use super::{
    local_ipc::{self, CreatedInstallationFile, IpcError},
    native_host::{
        self, AdapterRegistration, ExistingRegistration, ExtensionOrigin, HostError,
        InstalledHostConfig, Platform, RegistrationPlan, OWN_HOST_NAME,
    },
};
use serde_json::Value;
use std::{
    ffi::OsString,
    io,
    path::{Path, PathBuf},
    process::ExitCode,
};

#[path = "native_assets.rs"]
mod assets;

#[derive(Debug, thiserror::Error)]
pub(crate) enum InstallError {
    #[error(transparent)]
    Ipc(#[from] IpcError),
    #[error(transparent)]
    Host(#[from] HostError),
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
    current_plan_for(AdapterRegistration::own(ExtensionOrigin::from_id(
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
    Ok(native_host::registration_plan(
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

fn original_registration(extension_id: &str) -> Result<AdapterRegistration, InstallError> {
    Ok(AdapterRegistration::selected_adapter(
        super::native_process::ORIGINAL_HOST_NAME,
        ExtensionOrigin::from_id(extension_id)?,
    )?)
}

fn install_original(extension_id: &str) -> Result<InstallReport, InstallError> {
    install_plan(current_plan_for(original_registration(extension_id)?)?)
}

fn install_plan(plan: RegistrationPlan) -> Result<InstallReport, InstallError> {
    ensure_no_alternate_registration(&plan)?;
    let sidecar: InstalledHostConfig = serde_json::from_str(&plan.sidecar_json)?;
    local_ipc::ensure_private_state_directory(&sidecar.private_state_directory)?;
    local_ipc::ensure_installation_directory(
        plan.manifest_path
            .parent()
            .ok_or_else(|| InstallError::Refused("manifest lacks parent".to_owned()))?,
    )?;
    let manifest = existing(&plan.manifest_path)?;
    let sidecar_existing = existing(&plan.sidecar_path)?;
    let manifest_action = plan.inspect_existing_manifest(manifest.as_deref())?;
    let sidecar_action = plan.inspect_existing_sidecar(sidecar_existing.as_deref())?;
    #[cfg(windows)]
    let registry_existing = registry::read(
        plan.registry
            .as_ref()
            .ok_or_else(|| InstallError::Refused("Windows registry plan is absent".to_owned()))?,
    )?;
    #[cfg(windows)]
    let registry_action = plan.inspect_existing_registry_value(registry_existing.as_deref())?;
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
                ExistingRegistration::Unchanged => unchanged += 1,
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
    let count = created.len();
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
            "existing alternate native-host registration at {}; refusing to shadow or bypass it",
            slot.location
        )));
    }
    Ok(())
}

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
    uninstall_selected_current_user(OWN_HOST_NAME)
}

fn uninstall_selected_current_user(expected_adapter: &str) -> Result<(), InstallError> {
    let executable = std::fs::canonicalize(std::env::current_exe()?)?;
    let sidecar_path = native_host::installed_sidecar_path(&executable)?;
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
    let plan = if expected_adapter == OWN_HOST_NAME {
        current_plan(&installed.expected_extension_id)?
    } else if expected_adapter == super::native_process::ORIGINAL_HOST_NAME {
        current_plan_for(original_registration(&installed.expected_extension_id)?)?
    } else {
        return Err(InstallError::Refused(
            "unsupported selected adapter".to_owned(),
        ));
    };
    plan.inspect_existing_sidecar(Some(&bytes))?;
    let manifest = existing(&plan.manifest_path)?;
    plan.inspect_existing_manifest(manifest.as_deref())?;
    #[cfg(windows)]
    {
        let entry = plan
            .registry
            .as_ref()
            .ok_or_else(|| InstallError::Refused("Windows registry plan is absent".to_owned()))?;
        let value = registry::read(entry)?;
        plan.inspect_existing_registry_value(value.as_deref())?;
        if value.is_some() {
            registry::remove_exact(entry)?;
        }
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
                ))
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
    InstallOriginal { extension_id: String },
    Uninstall,
    UninstallOriginal,
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
            [_, _, adapter_flag, adapter, id_flag, id]
                if adapter_flag == "--adapter"
                    && adapter == "original"
                    && id_flag == "--extension-id" =>
            {
                id.to_str()
                    .ok_or_else(|| InstallError::Refused("extension ID is not Unicode".to_owned()))
                    .and_then(|id| {
                        original_registration(id)?;
                        Ok(SetupCommand::InstallOriginal {
                            extension_id: id.to_owned(),
                        })
                    })
            }
            _ => Err(InstallError::Refused(
                "use browser install --extension-id <actual-own-extension-id>, or browser install --adapter original --extension-id <actual-original-extension-id>".to_owned(),
            )),
        }),
        Some("uninstall") => Some(match arguments {
            [_, _] => Ok(SetupCommand::Uninstall),
            [_, _, adapter_flag, adapter] if adapter_flag == "--adapter" && adapter == "original" => {
                Ok(SetupCommand::UninstallOriginal)
            }
            _ => Err(InstallError::Refused(
                "use browser uninstall, or browser uninstall --adapter original".to_owned(),
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
        Ok(SetupCommand::InstallOriginal { extension_id }) => {
            install_original(&extension_id).map(|report| {
                format!(
                    "Registered explicitly selected Original adapter: {} created, {} unchanged.",
                    report.created_entries, report.unchanged_entries,
                )
            })
        }
        Ok(SetupCommand::Uninstall) => uninstall_current_user()
            .map(|()| "Removed exact own browser connector registration.".to_owned()),
        Ok(SetupCommand::UninstallOriginal) => {
            uninstall_selected_current_user(super::native_process::ORIGINAL_HOST_NAME)
                .map(|()| "Removed exact selected Original adapter registration.".to_owned())
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
    use crate::browser::native_host::RegistryEntry;
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
        if kind != 1 || bytes < 2 || bytes > 65536 || bytes % 2 != 0 {
            return Err(InstallError::Refused(
                "native host registry value is not bounded REG_SZ".to_owned(),
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
                "native host registry value changed during read".to_owned(),
            ));
        }
        data.truncate((bytes / 2) as usize);
        if data.last() != Some(&0) {
            return Err(InstallError::Refused(
                "native host registry value lacks terminator".to_owned(),
            ));
        }
        data.pop();
        if data.contains(&0) {
            return Err(InstallError::Refused(
                "native host registry value contains NUL".to_owned(),
            ));
        }
        Ok(Some(String::from_utf16(&data).map_err(|_| {
            InstallError::Refused("native host registry value is not UTF-16".to_owned())
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
        // SAFETY: only the explicit own current-user registration is selected.
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
                    "refusing to overwrite a changed native-host registry value".to_owned(),
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
    #[test]
    fn explicit_install_requires_actual_extension_id_and_no_extra_authority() {
        assert!(setup_command(&["browser".into(), "install".into()])
            .unwrap()
            .is_err());
        assert!(setup_command(&[
            "browser".into(),
            "install".into(),
            "--extension-id".into(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()
        ])
        .unwrap()
        .is_ok());
        assert!(setup_command(&[
            "browser".into(),
            "install".into(),
            "--extension-id".into(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            "--host".into(),
            "foreign.host".into()
        ])
        .unwrap()
        .is_err());
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
        assert!(setup_command(&[
            "browser".into(),
            "extension".into(),
            "--output".into(),
            "/private-fixture".into(),
            "--extension-id".into(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()
        ])
        .unwrap()
        .is_err());
    }

    #[test]
    fn original_setup_uses_explicit_adapter_and_actual_extension_id() {
        let valid = [
            "browser",
            "install",
            "--adapter",
            "original",
            "--extension-id",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ];
        let parsed = setup_command(&valid.map(OsString::from)).unwrap().unwrap();
        assert!(
            matches!(parsed, SetupCommand::InstallOriginal { extension_id }
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
        assert!(setup_command(&[
            "browser".into(),
            "install".into(),
            "--adapter".into(),
            "original".into(),
        ])
        .unwrap()
        .is_err());
        assert!(matches!(
            setup_command(&[
                "browser".into(),
                "uninstall".into(),
                "--adapter".into(),
                "original".into(),
            ])
            .unwrap()
            .unwrap(),
            SetupCommand::UninstallOriginal
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
        let plan = native_host::registration_plan(
            &original_registration("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
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
            ("adapter", OWN_HOST_NAME),
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
            let path = system_manifest(platform, super::super::native_process::ORIGINAL_HOST_NAME)
                .unwrap();
            assert!(matches!(
                refuse_alternate_presence(&[AlternateRegistration {
                    location: path.display().to_string(),
                    present: true
                }]),
                Err(InstallError::Refused(_))
            ));
        }
        assert!(refuse_alternate_presence(&[AlternateRegistration {
            location: "absent alternate slot".to_owned(),
            present: false
        }])
        .is_ok());
    }
}
