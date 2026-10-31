// SPDX-License-Identifier: MIT

#[cfg(unix)]
use super::HandoffError;
use crate::browser::extension_process::CHATGPT_HOST_NAME;
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::path::{Path, PathBuf};

/// The native-messaging registration namespace selected during connector setup.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BrowserFamily {
    Chrome,
    Chromium,
}

impl BrowserFamily {
    pub(super) fn recovery_name(self) -> &'static str {
        match self {
            Self::Chrome => "chatgpt-handoff",
            Self::Chromium => "chatgpt-handoff-chromium",
        }
    }

    #[cfg(unix)]
    pub(crate) fn user_manifest(
        self,
        home: &Path,
        xdg_config_home: Option<&Path>,
    ) -> Result<PathBuf, HandoffError> {
        #[cfg(target_os = "macos")]
        let _ = xdg_config_home;
        #[cfg(target_os = "macos")]
        let directory = home.join(match self {
            Self::Chrome => "Library/Application Support/Google/Chrome",
            Self::Chromium => "Library/Application Support/Chromium",
        });
        #[cfg(target_os = "linux")]
        let directory = {
            let base = xdg_config_home
                .map(Path::to_owned)
                .unwrap_or_else(|| home.join(".config"));
            if !base.is_absolute() {
                return Err(HandoffError::Configuration(
                    "XDG_CONFIG_HOME must be absolute".into(),
                ));
            }
            base.join(match self {
                Self::Chrome => "google-chrome",
                Self::Chromium => "chromium",
            })
        };
        Ok(directory
            .join("NativeMessagingHosts")
            .join(format!("{CHATGPT_HOST_NAME}.json")))
    }

    #[cfg(unix)]
    pub(super) fn system_manifest(self) -> PathBuf {
        #[cfg(target_os = "macos")]
        let directory = match self {
            Self::Chrome => "/Library/Google/Chrome/NativeMessagingHosts",
            Self::Chromium => "/Library/Application Support/Chromium/NativeMessagingHosts",
        };
        #[cfg(target_os = "linux")]
        let directory = match self {
            Self::Chrome => "/etc/opt/chrome/native-messaging-hosts",
            Self::Chromium => "/etc/chromium/native-messaging-hosts",
        };
        Path::new(directory).join(format!("{CHATGPT_HOST_NAME}.json"))
    }

    #[cfg(windows)]
    pub(super) fn registry_subkey(self) -> String {
        let browser = match self {
            Self::Chrome => "Google\\Chrome",
            Self::Chromium => "Chromium",
        };
        format!("Software\\{browser}\\NativeMessagingHosts\\{CHATGPT_HOST_NAME}")
    }
}
