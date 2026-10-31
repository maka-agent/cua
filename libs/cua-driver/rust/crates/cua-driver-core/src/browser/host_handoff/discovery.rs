// SPDX-License-Identifier: MIT

use super::{BrowserFamily, ConfiguredHandoff, HandoffError, OriginalHost};
use crate::browser::{
    extension_host::{ExtensionOrigin, InstalledHostConfig},
    extension_process::CHATGPT_HOST_NAME,
    local_ipc,
};
#[cfg(unix)]
use crate::browser::extension_install;
use std::path::{Path, PathBuf};

fn configuration(error: impl std::fmt::Display) -> HandoffError {
    HandoffError::Configuration(error.to_string())
}

fn registration(browser: BrowserFamily) -> Result<Option<PathBuf>, HandoffError> {
    #[cfg(unix)]
    {
        let home = extension_install::current_home().map_err(configuration)?;
        let xdg = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
        let path = browser.user_manifest(&home, xdg.as_deref())?;
        match std::fs::metadata(&path) {
            Ok(_) => return Ok(Some(path)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let path = browser.system_manifest();
        match std::fs::metadata(&path) {
            Ok(_) => Ok(Some(path)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
    #[cfg(windows)]
    {
        super::storage::registered_manifest(&browser.registry_subkey()).map_err(Into::into)
    }
}

fn profile_root(browser: BrowserFamily) -> Result<PathBuf, HandoffError> {
    #[cfg(unix)]
    {
        let home = extension_install::current_home().map_err(configuration)?;
        let xdg = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
        Ok(browser
            .user_manifest(&home, xdg.as_deref())?
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| configuration("browser profile path lacks parent"))?
            .to_owned())
    }
    #[cfg(windows)]
    {
        let local = std::env::var_os("LOCALAPPDATA")
            .ok_or_else(|| configuration("LOCALAPPDATA is unavailable"))?;
        Ok(PathBuf::from(local).join(match browser {
            BrowserFamily::Chrome => "Google/Chrome/User Data",
            BrowserFamily::Chromium => "Chromium/User Data",
        }))
    }
}

fn read_host(path: &Path) -> Result<OriginalHost, HandoffError> {
    parse_host(path, &std::fs::read(path)?)
}

pub(super) fn parse_host(path: &Path, bytes: &[u8]) -> Result<OriginalHost, HandoffError> {
    let manifest: serde_json::Value = serde_json::from_slice(bytes)?;
    if manifest["name"] != CHATGPT_HOST_NAME || manifest["type"] != "stdio" {
        return Err(configuration(
            "original registration is not a ChatGPT stdio host",
        ));
    }
    let executable = Path::new(
        manifest["path"]
            .as_str()
            .ok_or_else(|| configuration("original host path is missing"))?,
    );
    #[cfg(unix)]
    if !executable.is_absolute() {
        return Err(configuration("original host path must be absolute"));
    }
    let executable = if executable.is_absolute() {
        executable.to_owned()
    } else {
        path.parent()
            .ok_or_else(|| configuration("manifest lacks parent"))?
            .join(executable)
    };
    let allowed_origins: Vec<String> = serde_json::from_value(manifest["allowed_origins"].clone())?;
    Ok(OriginalHost {
        executable: std::fs::canonicalize(executable)?,
        allowed_origins,
    })
}

pub(super) fn discover(
    executable: &Path,
    browser: BrowserFamily,
) -> Result<Option<ConfiguredHandoff>, HandoffError> {
    let Some(path) = registration(browser)? else {
        return Ok(None);
    };
    let original = read_host(&path)?;
    let root = profile_root(browser)?;
    let profiles = match std::fs::read_dir(&root) {
        Ok(profiles) => profiles.collect::<Result<Vec<_>, _>>()?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    selected(
        executable,
        browser,
        &original,
        &profiles
            .iter()
            .map(|profile| profile.path())
            .collect::<Vec<_>>(),
        local_ipc::current_user_runtime_directory().map_err(configuration)?,
    )
}

fn selected(
    executable: &Path,
    browser: BrowserFamily,
    original: &OriginalHost,
    profiles: &[PathBuf],
    runtime: PathBuf,
) -> Result<Option<ConfiguredHandoff>, HandoffError> {
    let executable = std::fs::canonicalize(executable)?;
    if original.executable == executable {
        return Err(configuration(
            "registration points to Maka without an active handoff; restore it first",
        ));
    }
    for origin in &original.allowed_origins {
        let Some(id) = origin
            .strip_prefix("chrome-extension://")
            .and_then(|origin| origin.strip_suffix('/'))
        else {
            continue;
        };
        ExtensionOrigin::from_id(id).map_err(configuration)?;
        if profiles
            .iter()
            .any(|profile| profile.join("Extensions").join(id).is_dir())
        {
            return Ok(Some(ConfiguredHandoff {
                browser,
                config: InstalledHostConfig {
                    protocol: 1,
                    adapter: CHATGPT_HOST_NAME.into(),
                    expected_extension_id: id.into(),
                    executable,
                    private_state_directory: runtime,
                    handoff: Some(browser),
                },
            }));
        }
    }
    Ok(None)
}

pub(super) fn registered_host(config: &ConfiguredHandoff) -> Result<OriginalHost, HandoffError> {
    let path = registration(config.browser())?
        .ok_or_else(|| configuration("original ChatGPT browser host is not registered"))?;
    let original = read_host(&path)?;
    if original.executable == std::fs::canonicalize(std::env::current_exe()?)? {
        return Err(configuration(
            "registration still points to Maka without an active handoff",
        ));
    }
    Ok(original)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_selects_an_installed_allowed_extension_without_writing_registration() {
        let temp = tempfile::tempdir().unwrap();
        let profile = temp.path().join("Default");
        let id = "hehggadaopoacecdllhhajmbjkdcmajg";
        std::fs::create_dir_all(profile.join("Extensions").join(id)).unwrap();
        let original = OriginalHost {
            executable: temp.path().join("vendor-host"),
            allowed_origins: vec![
                "chrome-extension://odlomjlbamekndcpllcnffbgeohgkmjh/".into(),
                format!("chrome-extension://{id}/"),
            ],
        };
        let runtime = temp.path().join("runtime");
        let config = selected(
            &std::env::current_exe().unwrap(),
            BrowserFamily::Chrome,
            &original,
            &[profile],
            runtime.clone(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(config.extension_id(), id);
        assert_eq!(config.browser(), BrowserFamily::Chrome);
        assert!(!runtime.exists(), "passive discovery must not create state");
        assert!(selected(
            &std::env::current_exe().unwrap(),
            BrowserFamily::Chrome,
            &original,
            &[],
            runtime
        )
        .unwrap()
        .is_none());
    }
}
