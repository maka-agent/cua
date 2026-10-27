// SPDX-License-Identifier: MIT

//! Pure native-host entry discrimination and registration planning.
//!
//! An origin argument selects an explicitly configured adapter. It does not
//! authenticate Chrome or attest an extension signature. Sibling `native_process`
//! owns the finite Chrome process and retains current-user IPC and claim boundaries.

use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

pub(crate) const OWN_HOST_NAME: &str = "org.apache.maka.browser_connector";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExtensionOrigin {
    id: String,
    origin: String,
}

impl ExtensionOrigin {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }
    pub(crate) fn from_id(id: &str) -> Result<Self, HostError> {
        if id.len() != 32 || !id.bytes().all(|byte| (b'a'..=b'p').contains(&byte)) {
            return Err(HostError::InvalidExtensionId);
        }
        Ok(Self {
            id: id.to_owned(),
            origin: format!("chrome-extension://{id}/"),
        })
    }

    pub(crate) fn validate_hello_id(&self, actual: &str) -> Result<(), HostError> {
        if actual != self.id {
            return Err(HostError::HelloIdentityMismatch);
        }
        Ok(())
    }
}

/// Values come from trusted installation configuration, never a page or tool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AdapterRegistration {
    host_name: String,
    extension: ExtensionOrigin,
}

impl AdapterRegistration {
    pub(crate) fn host_name(&self) -> &str {
        &self.host_name
    }

    pub(crate) fn own(extension: ExtensionOrigin) -> Self {
        Self {
            host_name: OWN_HOST_NAME.to_owned(),
            extension,
        }
    }

    /// Construct an explicitly selected compatibility registration plan.
    ///
    /// This selects an exact host namespace and extension origin; it does not
    /// implement a foreign protocol or overwrite an existing registration.
    pub(crate) fn selected_adapter(
        host_name: &str,
        extension: ExtensionOrigin,
    ) -> Result<Self, HostError> {
        if !valid_host_name(host_name) {
            return Err(HostError::InvalidHostName);
        }
        Ok(Self {
            host_name: host_name.to_owned(),
            extension,
        })
    }

    /// Recognize only this adapter's exact registered origin argument.
    ///
    /// `arguments` excludes argv[0]. Call before application logging or CLI
    /// setup. `None` means the normal application path; no side effects occur.
    pub(crate) fn invocation(
        &self,
        arguments: &[OsString],
        platform: Platform,
    ) -> Result<Option<NativeInvocation>, HostError> {
        if arguments.first().and_then(|arg| arg.to_str()) != Some(self.extension.origin.as_str()) {
            return Ok(None);
        }
        let parent_window = match arguments {
            [_] => None,
            [_, extra] if platform == Platform::Windows => {
                let number = extra
                    .to_str()
                    .and_then(|text| text.strip_prefix("--parent-window="))
                    .filter(|number| {
                        !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
                    })
                    .ok_or(HostError::InvalidInvocation)?;
                Some(number.parse().map_err(|_| HostError::InvalidInvocation)?)
            }
            _ => return Err(HostError::InvalidInvocation),
        };
        Ok(Some(NativeInvocation {
            host_name: self.host_name.clone(),
            declared_origin: self.extension.origin.clone(),
            parent_window,
        }))
    }
}

fn valid_host_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && !name.ends_with('.')
        && !name.contains("..")
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.')
        })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Platform {
    Linux,
    Macos,
    Windows,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NativeInvocation {
    pub(crate) host_name: String,
    pub(crate) declared_origin: String,
    /// Chrome's optional Windows parent-window value is metadata, not authority.
    pub(crate) parent_window: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum HostError {
    #[error("extension id must contain exactly 32 lowercase characters a through p")]
    InvalidExtensionId,
    #[error("native-host name is invalid")]
    InvalidHostName,
    #[error("native-host invocation has unexpected arguments")]
    InvalidInvocation,
    #[error("extension hello id differs from the selected registered-origin claim")]
    HelloIdentityMismatch,
    #[error("registration path must be an absolute Unicode path")]
    InvalidPath,
    #[error("Windows requires an explicitly selected own manifest directory")]
    MissingWindowsManifestDirectory,
    #[error("existing registration differs; refusing to overwrite it")]
    RegistrationConflict,
    #[error("registration JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct NativeManifest {
    name: String,
    description: String,
    path: String,
    #[serde(rename = "type")]
    kind: &'static str,
    allowed_origins: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RegistryEntry {
    pub(crate) key: String,
    pub(crate) value: String,
}

/// An inert plan: no directory, manifest, registry or profile is modified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RegistrationPlan {
    pub(crate) manifest_path: PathBuf,
    pub(crate) manifest_json: String,
    pub(crate) registry: Option<RegistryEntry>,
    pub(crate) sidecar_path: PathBuf,
    pub(crate) sidecar_json: String,
}

/// Own installation data, written only by explicit connector setup.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct InstalledHostConfig {
    pub(crate) protocol: u32,
    pub(crate) adapter: String,
    pub(crate) expected_extension_id: String,
    pub(crate) executable: PathBuf,
    pub(crate) private_state_directory: PathBuf,
}

pub(crate) fn installed_sidecar_path(executable: &Path) -> Result<PathBuf, HostError> {
    absolute_unicode(executable)?;
    if executable.file_name().is_none() {
        return Err(HostError::InvalidPath);
    }
    Ok(executable.with_extension("browser-connector.json"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExistingRegistration {
    Create,
    Unchanged,
}

impl RegistrationPlan {
    pub(crate) fn inspect_existing_sidecar(
        &self,
        existing: Option<&[u8]>,
    ) -> Result<ExistingRegistration, HostError> {
        let Some(bytes) = existing else {
            return Ok(ExistingRegistration::Create);
        };
        let expected: serde_json::Value = serde_json::from_str(&self.sidecar_json)?;
        let current: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| HostError::RegistrationConflict)?;
        if current != expected {
            return Err(HostError::RegistrationConflict);
        }
        Ok(ExistingRegistration::Unchanged)
    }
    /// A future installer must check before writing; changed entries refuse.
    pub(crate) fn inspect_existing_manifest(
        &self,
        existing: Option<&[u8]>,
    ) -> Result<ExistingRegistration, HostError> {
        let Some(bytes) = existing else {
            return Ok(ExistingRegistration::Create);
        };
        let expected: serde_json::Value = serde_json::from_str(&self.manifest_json)?;
        let current: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| HostError::RegistrationConflict)?;
        if current != expected {
            return Err(HostError::RegistrationConflict);
        }
        Ok(ExistingRegistration::Unchanged)
    }

    #[cfg(any(windows, test))]
    pub(crate) fn inspect_existing_registry_value(
        &self,
        existing: Option<&str>,
    ) -> Result<ExistingRegistration, HostError> {
        match (&self.registry, existing) {
            (Some(entry), Some(value)) if entry.value == value => {
                Ok(ExistingRegistration::Unchanged)
            }
            (_, None) => Ok(ExistingRegistration::Create),
            _ => Err(HostError::RegistrationConflict),
        }
    }
}

fn absolute_unicode(path: &Path) -> Result<&str, HostError> {
    if !path.is_absolute() {
        return Err(HostError::InvalidPath);
    }
    path.to_str().ok_or(HostError::InvalidPath)
}

/// Generate a current-user Google Chrome registration plan for native paths.
///
/// Call with the actual installation platform and its native absolute paths.
/// Other Chromium-family browsers need independently reviewed registration
/// adapters. This function neither verifies executables nor installs anything.
pub(crate) fn registration_plan(
    adapter: &AdapterRegistration,
    platform: Platform,
    home: &Path,
    executable: &Path,
    windows_manifest_directory: Option<&Path>,
) -> Result<RegistrationPlan, HostError> {
    absolute_unicode(home)?;
    let executable_path = executable;
    let executable = absolute_unicode(executable)?;
    let directory = match platform {
        Platform::Linux => home.join(".config/google-chrome/NativeMessagingHosts"),
        Platform::Macos => {
            home.join("Library/Application Support/Google/Chrome/NativeMessagingHosts")
        }
        Platform::Windows => {
            let directory =
                windows_manifest_directory.ok_or(HostError::MissingWindowsManifestDirectory)?;
            absolute_unicode(directory)?;
            directory.to_path_buf()
        }
    };
    let manifest_path = directory.join(format!("{}.json", adapter.host_name));
    let manifest = NativeManifest {
        name: adapter.host_name.clone(),
        description: "Maka browser connector".to_owned(),
        path: executable.to_owned(),
        kind: "stdio",
        allowed_origins: vec![adapter.extension.origin.clone()],
    };
    let registry = if platform == Platform::Windows {
        Some(RegistryEntry {
            key: format!(
                "HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\{}",
                adapter.host_name
            ),
            value: absolute_unicode(&manifest_path)?.to_owned(),
        })
    } else {
        None
    };
    let private_state_directory = if platform == Platform::Windows {
        directory
    } else {
        home.join(".maka-browser")
    };
    let sidecar = InstalledHostConfig {
        protocol: 1,
        adapter: adapter.host_name.clone(),
        expected_extension_id: adapter.extension.id.clone(),
        executable: executable_path.to_owned(),
        private_state_directory,
    };
    Ok(RegistrationPlan {
        manifest_path,
        manifest_json: serde_json::to_string_pretty(&manifest)? + "\n",
        registry,
        sidecar_path: installed_sidecar_path(executable_path)?,
        sidecar_json: serde_json::to_string_pretty(&sidecar)? + "\n",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn own() -> AdapterRegistration {
        AdapterRegistration::own(
            ExtensionOrigin::from_id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
        )
    }

    #[test]
    fn only_the_selected_exact_origin_dispatches_native_mode() {
        let adapter = own();
        for argument in [
            "--help",
            "chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/",
            "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "https://example.test/",
        ] {
            assert!(
                adapter
                    .invocation(&[argument.into()], Platform::Linux)
                    .unwrap()
                    .is_none(),
                "unexpected native dispatch for {argument}"
            );
        }
        let invocation = adapter
            .invocation(
                &["chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/".into()],
                Platform::Linux,
            )
            .unwrap()
            .unwrap();
        assert_eq!(invocation.host_name, OWN_HOST_NAME);
        assert!(invocation.parent_window.is_none());
        assert!(adapter
            .extension
            .validate_hello_id("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .is_err());
    }

    #[test]
    fn windows_parent_window_is_optional_decimal_metadata_only() {
        let origin: OsString = "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/".into();
        assert_eq!(
            own()
                .invocation(
                    &[origin.clone(), "--parent-window=0".into()],
                    Platform::Windows
                )
                .unwrap()
                .unwrap()
                .parent_window,
            Some(0)
        );
        for extra in [
            "--parent-window=+1",
            "--parent-window=-1",
            "--parent-window=",
            "--parent-window=18446744073709551616",
            "--silent-debugger-extension-api",
        ] {
            assert!(
                own()
                    .invocation(&[origin.clone(), extra.into()], Platform::Windows)
                    .is_err(),
                "unexpected invocation {extra}"
            );
        }
        assert!(own()
            .invocation(&[origin, "--parent-window=0".into()], Platform::Linux)
            .is_err());
    }

    #[test]
    fn own_manifest_is_exact_and_changed_existing_registration_refuses() {
        let home = std::env::temp_dir().join("maka-source-only-home");
        let executable = home.join("bin/maka");
        let plan = registration_plan(&own(), Platform::Linux, &home, &executable, None).unwrap();
        let json: serde_json::Value = serde_json::from_str(&plan.manifest_json).unwrap();
        assert_eq!(json["name"], OWN_HOST_NAME);
        assert_eq!(json["type"], "stdio");
        assert_eq!(
            json["allowed_origins"],
            serde_json::json!(["chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"])
        );
        assert_eq!(json["path"], executable.to_str().unwrap());
        assert!(
            json.get("args").is_none(),
            "Chrome manifest has no executable argument field"
        );
        assert_eq!(
            plan.inspect_existing_manifest(Some(plan.manifest_json.as_bytes()))
                .unwrap(),
            ExistingRegistration::Unchanged
        );
        assert!(matches!(
            plan.inspect_existing_manifest(Some(b"{\"name\":\"other.host\"}")),
            Err(HostError::RegistrationConflict)
        ));
        assert!(matches!(
            plan.inspect_existing_manifest(Some(b"malformed")),
            Err(HostError::RegistrationConflict)
        ));
    }

    #[test]
    fn compatibility_requires_explicit_identity_and_preserves_foreign_entries() {
        let extension = ExtensionOrigin::from_id("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        for name in [
            "",
            ".invalid",
            "invalid.",
            "invalid..host",
            "Invalid.host",
            "invalid/host",
        ] {
            assert!(
                AdapterRegistration::selected_adapter(name, extension.clone()).is_err(),
                "invalid host {name}"
            );
        }
        let adapter = AdapterRegistration::selected_adapter("example.compat", extension).unwrap();
        let home = std::env::temp_dir().join("maka-source-only-home");
        let plan = registration_plan(
            &adapter,
            Platform::Windows,
            &home,
            &home.join("maka.exe"),
            Some(&home.join("own-manifest")),
        )
        .unwrap();
        let registry = plan.registry.as_ref().unwrap();
        assert_eq!(
            registry.key,
            "HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\example.compat"
        );
        let sidecar: InstalledHostConfig = serde_json::from_str(&plan.sidecar_json).unwrap();
        assert_eq!(sidecar.adapter, "example.compat");
        assert_eq!(
            sidecar.expected_extension_id,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(sidecar.executable, home.join("maka.exe"));
        assert!(matches!(
            plan.inspect_existing_registry_value(Some("other-installed-host.json")),
            Err(HostError::RegistrationConflict)
        ));
        assert_eq!(
            plan.inspect_existing_registry_value(Some(&registry.value))
                .unwrap(),
            ExistingRegistration::Unchanged
        );
    }

    #[test]
    fn relative_paths_never_produce_an_install_plan() {
        assert!(matches!(
            registration_plan(
                &own(),
                Platform::Linux,
                Path::new("relative"),
                Path::new("maka"),
                None
            ),
            Err(HostError::InvalidPath)
        ));
        let home = std::env::temp_dir();
        assert!(matches!(
            registration_plan(
                &own(),
                Platform::Windows,
                &home,
                &home.join("maka.exe"),
                None
            ),
            Err(HostError::MissingWindowsManifestDirectory)
        ));
    }
}
