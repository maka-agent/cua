// SPDX-License-Identifier: MIT

//! Installation configuration only; entries never grant browser authority.

use super::{
    extension_host::{self, ExtensionOrigin, HostError, InstalledHostConfig, MAKA_HOST_NAME},
    extension_process::CHATGPT_HOST_NAME,
    local_ipc::{self, InstallationMutationLock, IpcError},
};
use std::{
    collections::HashSet,
    io,
    path::{Path, PathBuf},
};

const ADAPTERS: [&str; 2] = [MAKA_HOST_NAME, CHATGPT_HOST_NAME];

#[derive(Debug, thiserror::Error)]
pub(crate) enum CatalogError {
    #[error(transparent)]
    Ipc(#[from] IpcError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Host(#[from] HostError),
    #[error("installed extension catalog refused: {0}")]
    Refused(String),
}

#[derive(Clone, Debug)]
pub(crate) struct Entry {
    pub(crate) config: InstalledHostConfig,
    pub(crate) path: PathBuf,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct Rejection {
    pub(crate) adapter: String,
    pub(crate) path: PathBuf,
    pub(crate) reason: String,
    claimed_extension: Option<String>,
}

#[derive(Debug)]
pub(crate) struct InstalledCatalog {
    executable: PathBuf,
    pub(crate) entries: Vec<Entry>,
    pub(crate) rejected: Vec<Rejection>,
    legacy: Option<Entry>,
}

fn validate_config(config: &InstalledHostConfig, executable: &Path) -> Result<(), CatalogError> {
    if config.protocol != 1 || !ADAPTERS.contains(&config.adapter.as_str()) {
        return Err(CatalogError::Refused(
            "unsupported installation protocol or adapter".into(),
        ));
    }
    ExtensionOrigin::from_id(&config.expected_extension_id)?;
    if !config.executable.is_absolute()
        || std::fs::canonicalize(&config.executable)? != executable
        || !config.private_state_directory.is_absolute()
    {
        return Err(CatalogError::Refused(
            "entry disagrees with executable or private state path".into(),
        ));
    }
    match std::fs::symlink_metadata(&config.private_state_directory) {
        Ok(_) => local_ipc::validate_runtime_directory(&config.private_state_directory)?,
        // Existing startup may recreate a removed private runtime directory;
        // discovery returns no endpoints until its exact directory is present.
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn read_entry(
    path: PathBuf,
    slot: Option<&str>,
    executable: &Path,
) -> Result<Option<Entry>, Rejection> {
    let mut rejection = Rejection {
        adapter: slot.unwrap_or("legacy").to_owned(),
        path: path.clone(),
        reason: String::new(),
        claimed_extension: None,
    };
    let bytes = match local_ipc::load_private_installation_config(&path) {
        Ok(bytes) => bytes,
        Err(IpcError::MissingInstallationFile) => return Ok(None),
        Err(error) => {
            rejection.reason = error.to_string();
            return Err(rejection);
        }
    };
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(error) => {
            rejection.reason = error.to_string();
            return Err(rejection);
        }
    };
    // A valid ID in a rejected object can only deny an ambiguous route. It
    // never becomes an accepted configuration, owner, path or grant.
    rejection.claimed_extension = value
        .get("expectedExtensionId")
        .and_then(|id| id.as_str())
        .filter(|id| ExtensionOrigin::from_id(id).is_ok())
        .map(str::to_owned);
    let config: InstalledHostConfig = match serde_json::from_slice(&bytes) {
        Ok(config) => config,
        Err(error) => {
            rejection.reason = error.to_string();
            return Err(rejection);
        }
    };
    if slot.is_none() {
        rejection.adapter = config.adapter.clone();
    }
    if slot.is_some_and(|slot| slot != config.adapter) {
        rejection.reason = "entry adapter disagrees with its exact catalog slot".into();
        return Err(rejection);
    }
    if let Err(error) = validate_config(&config, executable) {
        rejection.reason = error.to_string();
        return Err(rejection);
    }
    Ok(Some(Entry {
        config,
        path,
        bytes,
    }))
}

/// Read only exact known installation slots; no profile or endpoint fallback.
pub(crate) fn load(executable: &Path) -> Result<InstalledCatalog, CatalogError> {
    let executable = std::fs::canonicalize(executable)?;
    let mut entries = Vec::new();
    let mut rejected = Vec::new();
    let legacy = match read_entry(
        extension_host::installed_sidecar_path(&executable)?,
        None,
        &executable,
    ) {
        Ok(entry) => entry,
        Err(error) => {
            rejected.push(error);
            None
        }
    };
    if let Some(entry) = &legacy {
        entries.push(entry.clone());
    }
    let directory = extension_host::installed_catalog_directory(&executable)?;
    match std::fs::symlink_metadata(&directory) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
        Ok(_) => {
            local_ipc::validate_runtime_directory(&directory)?;
            for adapter in ADAPTERS {
                match read_entry(
                    extension_host::installed_adapter_path(&executable, adapter)?,
                    Some(adapter),
                    &executable,
                ) {
                    Ok(Some(entry)) => {
                        if let Some(previous) = entries
                            .iter_mut()
                            .find(|previous| previous.config == entry.config)
                        {
                            // A copied legacy entry during selected migration is
                            // one logical configuration, not another authority.
                            *previous = entry;
                        } else {
                            entries.push(entry);
                        }
                    }
                    Ok(None) => {}
                    Err(error) => rejected.push(error),
                }
            }
        }
    }
    let rejected_origins: HashSet<_> = rejected
        .iter()
        .filter_map(|entry| entry.claimed_extension.clone())
        .collect();
    let mut conflicts = vec![None; entries.len()];
    for (index, entry) in entries.iter().enumerate() {
        if rejected_origins.contains(&entry.config.expected_extension_id) {
            conflicts[index] = Some("origin is also claimed by a rejected installation entry");
        }
        for (other, candidate) in entries.iter().enumerate().skip(index + 1) {
            let reason = if entry.config.adapter == candidate.config.adapter {
                Some("adapter has divergent legacy and catalog entries")
            } else if entry.config.expected_extension_id == candidate.config.expected_extension_id {
                Some("origin is assigned to multiple adapters")
            } else {
                None
            };
            if let Some(reason) = reason {
                conflicts[index] = Some(reason);
                conflicts[other] = Some(reason);
            }
        }
    }
    let entries = entries
        .into_iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            if let Some(reason) = conflicts[index] {
                rejected.push(Rejection {
                    adapter: entry.config.adapter.clone(),
                    path: entry.path,
                    reason: reason.to_owned(),
                    claimed_extension: Some(entry.config.expected_extension_id),
                });
                None
            } else {
                Some(entry)
            }
        })
        .collect();
    Ok(InstalledCatalog {
        executable,
        entries,
        rejected,
        legacy,
    })
}

impl InstalledCatalog {
    pub(crate) fn entry(&self, adapter: &str) -> Result<&Entry, CatalogError> {
        if let Some(rejected) = self.rejected.iter().find(|entry| entry.adapter == adapter) {
            return Err(CatalogError::Refused(format!(
                "selected adapter {adapter} is rejected: {}",
                rejected.reason
            )));
        }
        self.entries
            .iter()
            .find(|entry| entry.config.adapter == adapter)
            .ok_or_else(|| {
                CatalogError::Refused(format!("selected adapter {adapter} is not installed"))
            })
    }

    /// Route the literal extension origin; the registration parser still validates
    /// platform arguments. This neither authenticates Chrome nor approves input.
    pub(crate) fn origin(&self, origin: &str) -> Result<&Entry, CatalogError> {
        let matches = self
            .entries
            .iter()
            .filter(|entry| {
                origin == format!("chrome-extension://{}/", entry.config.expected_extension_id)
            })
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [entry] => Ok(*entry),
            [] => Err(CatalogError::Refused(
                "invocation origin has no unique valid installed entry".into(),
            )),
            _ => Err(CatalogError::Refused(
                "invocation origin is ambiguous".into(),
            )),
        }
    }

    pub(crate) fn validate_new_entry(
        &self,
        config: &InstalledHostConfig,
    ) -> Result<(), CatalogError> {
        validate_config(config, &self.executable)?;
        let legacy_path = extension_host::installed_sidecar_path(&self.executable)?;
        if self.rejected.iter().any(|entry| {
            entry.adapter == config.adapter
                || entry.path == legacy_path
                || entry.claimed_extension.as_deref() == Some(config.expected_extension_id.as_str())
        }) {
            return Err(CatalogError::Refused(
                "selected adapter or origin has rejected installation state".into(),
            ));
        }
        for entry in &self.entries {
            if entry.config.adapter == config.adapter && entry.config != *config {
                return Err(CatalogError::Refused(
                    "selected adapter installation differs".into(),
                ));
            }
            if entry.config.adapter != config.adapter
                && entry.config.expected_extension_id == config.expected_extension_id
            {
                return Err(CatalogError::Refused(
                    "origin is already assigned to another adapter".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Holds the existing private-file lock across a complete cooperating mutation.
pub(crate) struct Mutation {
    executable: PathBuf,
    _lock: InstallationMutationLock,
}

impl Mutation {
    pub(crate) fn open(executable: &Path) -> Result<Self, CatalogError> {
        let executable = std::fs::canonicalize(executable)?;
        let directory = extension_host::installed_catalog_directory(&executable)?;
        local_ipc::ensure_private_state_directory(&directory)?;
        let lock = local_ipc::lock_installation_directory(&directory)?;
        Ok(Self {
            executable,
            _lock: lock,
        })
    }

    pub(crate) fn load(&self) -> Result<InstalledCatalog, CatalogError> {
        load(&self.executable)
    }

    /// Selected format migration commits independently. Later setup failure
    /// does not remove a successfully migrated existing registration.
    pub(crate) fn migrate_legacy_for(&self, adapter: &str) -> Result<bool, CatalogError> {
        let catalog = self.load()?;
        let Some(legacy) = &catalog.legacy else {
            return Ok(false);
        };
        if legacy.config.adapter != adapter {
            return Ok(false);
        }
        catalog.validate_new_entry(&legacy.config)?;
        Ok(local_ipc::migrate_exact_installation_file(
            &legacy.path,
            &extension_host::installed_adapter_path(&self.executable, adapter)?,
            &legacy.bytes,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _directory: tempfile::TempDir,
        executable: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let parent = std::fs::canonicalize(std::env::temp_dir()).unwrap();
            let directory = tempfile::tempdir_in(parent).unwrap();
            let executable = directory.path().join("fixture-connector");
            std::fs::write(&executable, b"inert fixture, never executed").unwrap();
            Self {
                _directory: directory,
                executable,
            }
        }
        fn config(&self, adapter: &str, id: char) -> InstalledHostConfig {
            let state = self._directory.path().join(format!("state-{id}"));
            local_ipc::ensure_private_state_directory(&state).unwrap();
            InstalledHostConfig {
                protocol: 1,
                adapter: adapter.into(),
                expected_extension_id: id.to_string().repeat(32),
                executable: self.executable.clone(),
                private_state_directory: state,
            }
        }
        fn legacy(&self, config: &InstalledHostConfig) -> Vec<u8> {
            let bytes =
                format!("{}\n\n", serde_json::to_string_pretty(config).unwrap()).into_bytes();
            local_ipc::create_installation_file(
                &extension_host::installed_sidecar_path(&self.executable).unwrap(),
                &bytes,
            )
            .unwrap();
            bytes
        }
        fn slot(&self, slot: &str, config: &InstalledHostConfig) {
            let directory = extension_host::installed_catalog_directory(&self.executable).unwrap();
            local_ipc::ensure_private_state_directory(&directory).unwrap();
            local_ipc::create_installation_file(
                &extension_host::installed_adapter_path(&self.executable, slot).unwrap(),
                &serde_json::to_vec(config).unwrap(),
            )
            .unwrap();
        }
    }

    #[test]
    fn legacy_single_load_is_readonly_and_origin_is_not_a_default() {
        let fixture = Fixture::new();
        let maka = fixture.config(MAKA_HOST_NAME, 'a');
        let bytes = fixture.legacy(&maka);
        let catalog = load(&fixture.executable).unwrap();
        assert_eq!(catalog.entries.len(), 1);
        assert_eq!(
            catalog
                .origin(&format!(
                    "chrome-extension://{}/",
                    maka.expected_extension_id
                ))
                .unwrap()
                .config,
            maka
        );
        assert!(
            matches!(catalog.origin("chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/"), Err(CatalogError::Refused(message)) if message == "invocation origin has no unique valid installed entry")
        );
        assert_eq!(
            std::fs::read(extension_host::installed_sidecar_path(&fixture.executable).unwrap())
                .unwrap(),
            bytes
        );
        assert!(
            !extension_host::installed_catalog_directory(&fixture.executable)
                .unwrap()
                .exists()
        );
    }

    #[test]
    fn selected_migration_preserves_bytes_and_other_adapter_is_untouched() {
        let fixture = Fixture::new();
        let original = fixture.config(CHATGPT_HOST_NAME, 'b');
        let bytes = fixture.legacy(&original);
        let mutation = Mutation::open(&fixture.executable).unwrap();
        assert!(!mutation.migrate_legacy_for(MAKA_HOST_NAME).unwrap());
        assert_eq!(
            std::fs::read(extension_host::installed_sidecar_path(&fixture.executable).unwrap())
                .unwrap(),
            bytes
        );
        assert!(mutation.migrate_legacy_for(CHATGPT_HOST_NAME).unwrap());
        assert!(!mutation.migrate_legacy_for(CHATGPT_HOST_NAME).unwrap());
        assert!(!extension_host::installed_sidecar_path(&fixture.executable)
            .unwrap()
            .exists());
        assert_eq!(
            std::fs::read(
                extension_host::installed_adapter_path(&fixture.executable, CHATGPT_HOST_NAME)
                    .unwrap()
            )
            .unwrap(),
            bytes
        );
    }

    #[test]
    fn identical_legacy_copy_deduplicates_but_divergent_entry_cannot_route() {
        let fixture = Fixture::new();
        let maka = fixture.config(MAKA_HOST_NAME, 'a');
        fixture.legacy(&maka);
        fixture.slot(MAKA_HOST_NAME, &maka);
        assert_eq!(load(&fixture.executable).unwrap().entries.len(), 1);
        let path =
            extension_host::installed_adapter_path(&fixture.executable, MAKA_HOST_NAME).unwrap();
        local_ipc::remove_exact_installation_file(&path, &serde_json::to_value(&maka).unwrap())
            .unwrap();
        let changed = fixture.config(MAKA_HOST_NAME, 'b');
        fixture.slot(MAKA_HOST_NAME, &changed);
        let catalog = load(&fixture.executable).unwrap();
        assert!(catalog.entries.is_empty());
        assert_eq!(catalog.rejected.len(), 2);
        assert!(
            matches!(catalog.entry(MAKA_HOST_NAME), Err(CatalogError::Refused(message)) if message.starts_with("selected adapter org.apache.maka.browser_connector is rejected:"))
        );
    }

    #[test]
    fn malformed_sibling_is_reported_without_borrowing_its_owner_or_directory() {
        let fixture = Fixture::new();
        let maka = fixture.config(MAKA_HOST_NAME, 'a');
        fixture.slot(MAKA_HOST_NAME, &maka);
        let mut original = fixture.config(CHATGPT_HOST_NAME, 'b');
        original.protocol = 2;
        fixture.slot(CHATGPT_HOST_NAME, &original);
        let catalog = load(&fixture.executable).unwrap();
        assert_eq!(catalog.entries.len(), 1);
        assert_eq!(
            catalog
                .entry(MAKA_HOST_NAME)
                .unwrap()
                .config
                .private_state_directory,
            maka.private_state_directory
        );
        assert!(catalog
            .rejected
            .iter()
            .any(|entry| entry.adapter == CHATGPT_HOST_NAME));
        assert!(
            matches!(catalog.origin(&format!("chrome-extension://{}/", original.expected_extension_id)), Err(CatalogError::Refused(message)) if message == "invocation origin has no unique valid installed entry")
        );
    }

    #[test]
    fn duplicate_origins_and_rejected_claims_never_choose_a_healthy_default() {
        let fixture = Fixture::new();
        let maka = fixture.config(MAKA_HOST_NAME, 'a');
        let original = fixture.config(CHATGPT_HOST_NAME, 'a');
        fixture.slot(MAKA_HOST_NAME, &maka);
        fixture.slot(CHATGPT_HOST_NAME, &original);
        let catalog = load(&fixture.executable).unwrap();
        assert!(catalog.entries.is_empty());
        assert_eq!(catalog.rejected.len(), 2);
        assert!(
            matches!(catalog.origin(&format!("chrome-extension://{}/", maka.expected_extension_id)), Err(CatalogError::Refused(message)) if message == "invocation origin has no unique valid installed entry")
        );
    }

    #[test]
    fn rejected_schema_origin_hint_only_denies_a_sibling_route() {
        for missing_protocol in [true, false] {
            let fixture = Fixture::new();
            let maka = fixture.config(MAKA_HOST_NAME, 'a');
            fixture.slot(MAKA_HOST_NAME, &maka);
            let mut malformed =
                serde_json::to_value(fixture.config(CHATGPT_HOST_NAME, 'a')).unwrap();
            if missing_protocol {
                malformed.as_object_mut().unwrap().remove("protocol");
            } else {
                malformed["unexpected"] = serde_json::json!(true);
            }
            local_ipc::create_installation_file(
                &extension_host::installed_adapter_path(&fixture.executable, CHATGPT_HOST_NAME)
                    .unwrap(),
                &serde_json::to_vec(&malformed).unwrap(),
            )
            .unwrap();
            let catalog = load(&fixture.executable).unwrap();
            assert!(
                catalog.entries.is_empty(),
                "a rejected schema must never redirect this origin to Maka"
            );
            assert_eq!(catalog.rejected.len(), 2);
            assert!(
                matches!(catalog.origin(&format!("chrome-extension://{}/", maka.expected_extension_id)), Err(CatalogError::Refused(message)) if message == "invocation origin has no unique valid installed entry")
            );
        }
    }

    #[test]
    fn removed_custom_adapter_sidecar_is_not_a_supported_catalog_entry() {
        let fixture = Fixture::new();
        let removed = fixture.config("org.apache.maka.opencli_connector", 'c');
        let bytes = fixture.legacy(&removed);
        let catalog = load(&fixture.executable).unwrap();
        assert!(catalog.entries.is_empty());
        assert_eq!(catalog.rejected.len(), 1);
        assert_eq!(
            catalog.rejected[0].reason,
            "installed extension catalog refused: unsupported installation protocol or adapter"
        );
        assert_eq!(
            std::fs::read(extension_host::installed_sidecar_path(&fixture.executable).unwrap())
                .unwrap(),
            bytes,
            "discovery never rewrites an unsupported former registration"
        );
    }

    #[test]
    fn duplicate_fields_are_rejected_from_original_bytes() {
        for field in ["adapter", "expectedExtensionId", "protocol"] {
            let fixture = Fixture::new();
            let config = fixture.config(MAKA_HOST_NAME, 'a');
            let value = serde_json::to_value(&config).unwrap();
            let serialized = serde_json::to_string(&config).unwrap();
            let duplicate = format!(
                "{{\"{field}\":{},{}",
                serde_json::to_string(&value[field]).unwrap(),
                &serialized[1..]
            );
            let directory =
                extension_host::installed_catalog_directory(&fixture.executable).unwrap();
            local_ipc::ensure_private_state_directory(&directory).unwrap();
            local_ipc::create_installation_file(
                &extension_host::installed_adapter_path(&fixture.executable, MAKA_HOST_NAME)
                    .unwrap(),
                duplicate.as_bytes(),
            )
            .unwrap();
            let catalog = load(&fixture.executable).unwrap();
            assert!(catalog.entries.is_empty());
            assert_eq!(catalog.rejected.len(), 1);
            assert!(catalog.rejected[0]
                .reason
                .starts_with(&format!("duplicate field `{field}`")));
        }
    }

    #[test]
    fn selected_slot_cannot_change_adapter_or_executable() {
        let fixture = Fixture::new();
        let original = fixture.config(CHATGPT_HOST_NAME, 'b');
        fixture.slot(MAKA_HOST_NAME, &original);
        let mut changed = fixture.config(CHATGPT_HOST_NAME, 'c');
        changed.executable = fixture._directory.path().join("different-executable");
        std::fs::write(&changed.executable, b"different inert fixture").unwrap();
        fixture.slot(CHATGPT_HOST_NAME, &changed);
        let catalog = load(&fixture.executable).unwrap();
        assert!(catalog.entries.is_empty());
        assert!(catalog
            .rejected
            .iter()
            .any(|entry| entry.reason == "entry adapter disagrees with its exact catalog slot"));
        assert!(catalog
            .rejected
            .iter()
            .any(|entry| entry.reason.contains("entry disagrees with executable")));
    }

    #[test]
    fn cooperating_mutation_lock_is_retained_and_uniqueness_is_rechecked() {
        let fixture = Fixture::new();
        let maka = fixture.config(MAKA_HOST_NAME, 'a');
        let original = fixture.config(CHATGPT_HOST_NAME, 'a');
        let mutation = Mutation::open(&fixture.executable).unwrap();
        let path = extension_host::installed_catalog_directory(&fixture.executable)
            .unwrap()
            .join(".mutation.lock");
        let probe = std::fs::File::open(&path).unwrap();
        let error = fs2::FileExt::try_lock_exclusive(&probe).unwrap_err();
        assert_eq!(
            error.raw_os_error(),
            fs2::lock_contended_error().raw_os_error()
        );
        mutation.load().unwrap().validate_new_entry(&maka).unwrap();
        fixture.slot(MAKA_HOST_NAME, &maka);
        drop(mutation);
        fs2::FileExt::try_lock_exclusive(&probe).unwrap();
        fs2::FileExt::unlock(&probe).unwrap();
        assert!(
            path.exists(),
            "unlock must not split waiting writers onto another inode"
        );
        let mutation = Mutation::open(&fixture.executable).unwrap();
        assert!(
            matches!(mutation.load().unwrap().validate_new_entry(&original), Err(CatalogError::Refused(message)) if message == "origin is already assigned to another adapter")
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_catalog_or_world_readable_selected_entry_is_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let fixture = Fixture::new();
        let maka = fixture.config(MAKA_HOST_NAME, 'a');
        fixture.slot(MAKA_HOST_NAME, &maka);
        let path =
            extension_host::installed_adapter_path(&fixture.executable, MAKA_HOST_NAME).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let catalog = load(&fixture.executable).unwrap();
        assert!(catalog.entries.is_empty());
        assert_eq!(catalog.rejected.len(), 1);
        let directory = extension_host::installed_catalog_directory(&fixture.executable).unwrap();
        let moved = directory.with_extension("moved");
        std::fs::rename(&directory, &moved).unwrap();
        symlink(&moved, &directory).unwrap();
        assert!(
            matches!(load(&fixture.executable), Err(CatalogError::Ipc(IpcError::Rejected(message))) if message == "private IPC path traverses a symlink")
        );
    }
}
