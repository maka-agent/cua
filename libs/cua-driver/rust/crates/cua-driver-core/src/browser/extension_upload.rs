// SPDX-License-Identifier: MIT

//! Bounded byte transport and native-host backing for already authorized uploads.
//!
//! This module never opens a caller-supplied source path. The Host authorizes and
//! freezes source bytes before transfer. Actual browser placement is a separate
//! prerequisite; neither a stage ID nor captured context grants filesystem access.

use super::extension_wire::ExtensionWireContext;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::PathBuf,
};
use uuid::Uuid;

/// One existing IPC frame carries at most this many decoded upload bytes.
pub const EXTENSION_UPLOAD_CHUNK_BYTES: usize = 64 * 1024;

/// Actual source modification time, encoded as Unix floor seconds and a
/// nonnegative fractional nanosecond. This is metadata, never source-path access.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "ModifiedTimeFields")]
pub struct ExtensionUploadModifiedTime {
    seconds: i64,
    nanos: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModifiedTimeFields {
    seconds: i64,
    nanos: u32,
}
impl TryFrom<ModifiedTimeFields> for ExtensionUploadModifiedTime {
    type Error = ExtensionUploadDescriptorError;
    fn try_from(value: ModifiedTimeFields) -> Result<Self, Self::Error> {
        Self::new(value.seconds, value.nanos)
    }
}
impl ExtensionUploadModifiedTime {
    pub fn new(seconds: i64, nanos: u32) -> Result<Self, ExtensionUploadDescriptorError> {
        if nanos >= 1_000_000_000 {
            return Err(ExtensionUploadDescriptorError);
        }
        Ok(Self { seconds, nanos })
    }
    pub fn seconds(&self) -> i64 {
        self.seconds
    }
    pub fn nanos(&self) -> u32 {
        self.nanos
    }
    fn system_time(self) -> Result<std::time::SystemTime, UploadError> {
        use std::time::{Duration, UNIX_EPOCH};
        let whole = if self.seconds >= 0 {
            UNIX_EPOCH.checked_add(Duration::from_secs(self.seconds as u64))
        } else {
            UNIX_EPOCH.checked_sub(Duration::from_secs(self.seconds.unsigned_abs()))
        };
        whole
            .and_then(|time| time.checked_add(Duration::from_nanos(u64::from(self.nanos))))
            .ok_or(UploadError::Refused(
                "source modification time cannot be represented on this native host",
            ))
    }
}

/// Metadata of the immutable source bytes already approved by the Host.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionUploadFile {
    name: String,
    bytes: u64,
    sha256: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    modified_time: Option<ExtensionUploadModifiedTime>,
}
impl ExtensionUploadFile {
    pub fn new(
        name: String,
        bytes: u64,
        sha256: [u8; 32],
    ) -> Result<Self, ExtensionUploadDescriptorError> {
        validate_name(&name)?;
        Ok(Self {
            name,
            bytes,
            sha256,
            modified_time: None,
        })
    }
    pub fn with_modified(mut self, modified: ExtensionUploadModifiedTime) -> Self {
        self.modified_time = Some(modified);
        self
    }
    pub fn modified_time(&self) -> Option<ExtensionUploadModifiedTime> {
        self.modified_time
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("upload name is not an exact file basename on the native host")]
pub struct ExtensionUploadDescriptorError;
fn validate_name(name: &str) -> Result<(), ExtensionUploadDescriptorError> {
    use std::path::{Component, Path};
    let mut components = Path::new(name).components();
    if name.is_empty()
        || name.contains('\0')
        || !matches!(
            (components.next(), components.next()),
            (Some(Component::Normal(part)), None) if part == std::ffi::OsStr::new(name)
        )
    {
        return Err(ExtensionUploadDescriptorError);
    }
    #[cfg(windows)]
    {
        // Win32 aliases/streams must not silently change the authorized basename.
        // Microsoft naming-a-file: reserved characters/devices and trailing dots/spaces.
        if name.ends_with(['.', ' '])
            || name
                .chars()
                .any(|ch| ch < ' ' || matches!(ch, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
        {
            return Err(ExtensionUploadDescriptorError);
        }
        let stem = name
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || ["COM", "LPT"].iter().any(|prefix| {
                stem.strip_prefix(prefix).is_some_and(|suffix| {
                    matches!(
                        suffix,
                        "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                    )
                })
            });
        if reserved {
            return Err(ExtensionUploadDescriptorError);
        }
    }
    Ok(())
}

/// Opaque resource address issued by this exact provider connection.
/// It conveys no page, site, filesystem, or DOM authorization.
#[derive(Clone, Debug)]
pub struct ExtensionUploadStage {
    pub(super) binding: Uuid,
    pub(super) context: ExtensionWireContext,
    pub(super) id: Uuid,
    pub(super) tab_id: u64,
    pub(super) target_id: String,
    pub(super) claim: String,
    pub(super) files: Vec<ExtensionUploadFile>,
    pub(super) completion_id: u64,
    pub(super) cleanup_only: bool,
}
impl ExtensionUploadStage {
    pub fn stage_id(&self) -> Uuid {
        self.id
    }
    pub fn claim_id(&self) -> &str {
        &self.claim
    }
    pub fn target_id(&self) -> &str {
        &self.target_id
    }
    pub fn wire_context(&self) -> &ExtensionWireContext {
        &self.context
    }
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
    pub fn tab_id(&self) -> u64 {
        self.tab_id
    }
}

#[derive(Clone, Debug)]
pub struct ExtensionUploadChunkAck {
    pub(super) stage_id: Uuid,
    pub(super) completion_id: u64,
}
impl ExtensionUploadChunkAck {
    pub fn stage_id(&self) -> Uuid {
        self.stage_id
    }
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
}

/// Only an actual retain acknowledgement exposes browser-local paths.
/// Its backing survives turn completion, debugger detach and client disconnect.
/// It is released only by known matching tab retirement. Host shutdown without
/// that proof leaves the backing and reports unconfirmed cleanup.
#[derive(Clone, Debug)]
pub struct ExtensionRetainedUpload {
    pub(super) stage: ExtensionUploadStage,
    pub(super) paths: Vec<PathBuf>,
    pub(super) completion_id: u64,
}
impl ExtensionRetainedUpload {
    pub fn stage_id(&self) -> Uuid {
        self.stage.id
    }
    pub fn claim_id(&self) -> &str {
        &self.stage.claim
    }
    pub fn target_id(&self) -> &str {
        &self.stage.target_id
    }
    pub fn wire_context(&self) -> &ExtensionWireContext {
        &self.stage.context
    }
    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
    pub fn tab_id(&self) -> u64 {
        self.stage.tab_id
    }
}

#[derive(Clone, Debug)]
pub struct ExtensionUploadAbandonAck {
    pub(super) stage_id: Uuid,
    pub(super) completion_id: u64,
}
impl ExtensionUploadAbandonAck {
    pub fn stage_id(&self) -> Uuid {
        self.stage_id
    }
    pub fn completion_id(&self) -> u64 {
        self.completion_id
    }
}

/// Actual native-host resource binding, copied from existing claim/context state.
/// There is no constructor from page data and no independent ownership registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct UploadOwner {
    pub(super) session_id: String,
    pub(super) tab_id: u64,
    pub(super) target_id: String,
}
#[derive(Debug, thiserror::Error)]
pub(super) enum UploadError {
    #[error("upload staging refused: {0}")]
    Refused(&'static str),
    #[error("upload staging I/O is unconfirmed: {0}")]
    Io(#[from] io::Error),
    #[error("upload stage {stage} materialization is unconfirmed: {error}")]
    BeginIo { stage: Uuid, error: io::Error },
}
struct UploadFile {
    descriptor: ExtensionUploadFile,
    path: PathBuf,
    output: File,
    identity: super::local_ipc::UploadFileIdentity,
    written: u64,
    hash: Sha256,
    poisoned: bool,
}
struct Stage {
    owner: UploadOwner,
    directory: PathBuf,
    directory_proof: Option<super::local_ipc::UploadDirectoryIdentity>,
    index_directories: Vec<(PathBuf, super::local_ipc::UploadDirectoryIdentity)>,
    files: Vec<UploadFile>,
    retained: bool,
    materialized: bool,
    cleanup_started: bool,
}

/// File-resource custody for one actual native-host lifetime. No Drop hook on
/// client/provider/claim owns this store. Placement validation wraps these methods
/// in the broker; tests of this backend alone make no placement claims.
#[derive(Default)]
pub(super) struct UploadResources {
    stages: HashMap<Uuid, Stage>,
}
impl UploadResources {
    pub(super) fn begin(
        &mut self,
        owner: UploadOwner,
        descriptors: &[ExtensionUploadFile],
    ) -> Result<Uuid, UploadError> {
        if descriptors.is_empty() {
            return Err(UploadError::Refused("upload has no files"));
        }
        for descriptor in descriptors {
            validate_name(&descriptor.name)
                .map_err(|_| UploadError::Refused("invalid upload filename"))?;
        }
        let temporary = std::env::temp_dir();
        if !temporary.is_absolute() {
            return Err(UploadError::Refused(
                "native host temporary directory is not absolute",
            ));
        }
        let temporary = std::fs::canonicalize(temporary)?;
        let id = Uuid::new_v4();
        let directory = temporary.join(format!("maka-browser-upload-{id}"));
        self.stages.insert(
            id,
            Stage {
                owner,
                directory,
                directory_proof: None,
                index_directories: Vec::new(),
                files: Vec::new(),
                retained: false,
                materialized: false,
                cleanup_started: false,
            },
        );
        let stage = self.stages.get_mut(&id).expect("inserted resource exists");
        let materialized = (|| -> io::Result<()> {
            let proof = super::local_ipc::create_upload_directory(&stage.directory)
                .map_err(io::Error::other)?;
            stage.directory_proof = Some(proof);
            let native_path = stage
                .directory_proof
                .as_ref()
                .expect("created directory proof")
                .native_path(&stage.directory)
                .map_err(io::Error::other)?;
            stage.directory = native_path;
            for (index, descriptor) in descriptors.iter().enumerate() {
                let subdirectory = stage.directory.join(index.to_string());
                let index_proof = super::local_ipc::create_upload_directory(&subdirectory)
                    .map_err(io::Error::other)?;
                stage
                    .index_directories
                    .push((subdirectory.clone(), index_proof));
                let path = subdirectory.join(&descriptor.name);
                let mut options = OpenOptions::new();
                options.write(true).read(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let output = options.open(&path)?;
                let identity =
                    super::local_ipc::upload_file_identity(&output).map_err(io::Error::other)?;
                stage.files.push(UploadFile {
                    descriptor: descriptor.clone(),
                    path,
                    output,
                    identity,
                    written: 0,
                    hash: Sha256::new(),
                    poisoned: false,
                });
            }
            Ok(())
        })();
        materialized.map_err(|error| UploadError::BeginIo { stage: id, error })?;
        stage.materialized = true;
        Ok(id)
    }
    /// Resolve only this resource's existing owner, for the broker to compare
    /// against its current real claim. This creates no new owner or claim state.
    pub(super) fn owner_for_session(
        &self,
        id: Uuid,
        session_id: &str,
    ) -> Result<UploadOwner, UploadError> {
        self.stages
            .get(&id)
            .filter(|stage| stage.owner.session_id == session_id)
            .map(|stage| stage.owner.clone())
            .ok_or(UploadError::Refused(
                "upload stage is unavailable for this session",
            ))
    }
    fn owned_mut(&mut self, id: Uuid, owner: &UploadOwner) -> Result<&mut Stage, UploadError> {
        self.stages
            .get_mut(&id)
            .filter(|stage| &stage.owner == owner)
            .ok_or(UploadError::Refused(
                "upload stage is unavailable for this owner and tab",
            ))
    }
    pub(super) fn write_chunk(
        &mut self,
        id: Uuid,
        owner: &UploadOwner,
        file_index: u32,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), UploadError> {
        if bytes.is_empty() || bytes.len() > EXTENSION_UPLOAD_CHUNK_BYTES {
            return Err(UploadError::Refused(
                "upload chunk is empty or exceeds 64 KiB",
            ));
        }
        let stage = self.owned_mut(id, owner)?;
        if !stage.materialized || stage.retained || stage.cleanup_started {
            return Err(UploadError::Refused(
                "retained or retiring upload bytes cannot be changed",
            ));
        }
        validate_stage_directory(stage)?;
        let file = stage
            .files
            .get_mut(file_index as usize)
            .ok_or(UploadError::Refused("upload file index is unavailable"))?;
        if file.poisoned
            || file.written != offset
            || (bytes.len() as u64) > file.descriptor.bytes.saturating_sub(file.written)
        {
            return Err(UploadError::Refused(
                "upload chunk does not match the exact next offset or declared size",
            ));
        }
        // An error may leave a prefix on disk. Never treat it as an empty write
        // or allow sealing to reinterpret that prefix as the expected bytes.
        file.poisoned = true;
        file.output.write_all(bytes)?;
        file.hash.update(bytes);
        file.written += bytes.len() as u64;
        file.poisoned = false;
        Ok(())
    }
    pub(super) fn retain(
        &mut self,
        id: Uuid,
        owner: &UploadOwner,
    ) -> Result<Vec<PathBuf>, UploadError> {
        let stage = self.owned_mut(id, owner)?;
        if !stage.materialized || stage.retained || stage.cleanup_started {
            return Err(UploadError::Refused(
                "retained or retiring upload cannot be replayed",
            ));
        }
        validate_stage_directory(stage)?;
        for file in &stage.files {
            let actual: [u8; 32] = file.hash.clone().finalize().into();
            if file.poisoned
                || file.written != file.descriptor.bytes
                || actual != file.descriptor.sha256
            {
                return Err(UploadError::Refused(
                    "upload bytes are incomplete or have a different digest",
                ));
            }
        }
        for file in &mut stage.files {
            file.output.seek(SeekFrom::Start(0))?;
            let mut actual = Sha256::new();
            let mut count = 0u64;
            let mut buffer = [0u8; EXTENSION_UPLOAD_CHUNK_BYTES];
            loop {
                // Read only the approved remaining extent plus one sentinel
                // byte, so append/corruption cannot create unbounded verification.
                let remaining = file.descriptor.bytes.saturating_sub(count);
                let limit = if remaining >= buffer.len() as u64 {
                    buffer.len()
                } else {
                    remaining as usize + 1
                };
                let read = file.output.read(&mut buffer[..limit])?;
                if read == 0 {
                    break;
                }
                count = count
                    .checked_add(read as u64)
                    .ok_or(UploadError::Refused("upload file length overflow"))?;
                if count > file.descriptor.bytes {
                    return Err(UploadError::Refused(
                        "native backing exceeds the approved byte extent",
                    ));
                }
                actual.update(&buffer[..read]);
            }
            let actual: [u8; 32] = actual.finalize().into();
            if count != file.descriptor.bytes || actual != file.descriptor.sha256 {
                return Err(UploadError::Refused(
                    "native backing bytes changed before selection",
                ));
            }
        }
        // Validate all timestamps before changing any file metadata. Native OS
        // precision quantization is allowed; no ns-equality refusal is invented.
        let modified = stage
            .files
            .iter()
            .map(|file| {
                file.descriptor
                    .modified_time
                    .map(ExtensionUploadModifiedTime::system_time)
                    .transpose()
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (file, modified) in stage.files.iter_mut().zip(modified) {
            file.output.flush()?;
            if let Some(modified) = modified {
                file.output
                    .set_times(std::fs::FileTimes::new().set_modified(modified))?;
            }
            file.output.sync_data()?;
        }
        // Mark before exposing any path. Cancellation after this point must not
        // remove bytes which a following DOM request may already be selecting.
        stage.retained = true;
        Ok(stage.files.iter().map(|file| file.path.clone()).collect())
    }
    pub(super) fn abandon(&mut self, id: Uuid, owner: &UploadOwner) -> Result<(), UploadError> {
        let stage = self.owned_mut(id, owner)?;
        if stage.retained {
            return Err(UploadError::Refused(
                "selected backing has no confirmed File lifetime end",
            ));
        }
        self.remove(id)
    }
    /// An exact tab-close acknowledgement ends this tab's unselected stages.
    /// It cannot prove that another browser consumer no longer holds a File.
    pub(super) fn retire_tab(&mut self, owner: &UploadOwner) -> Result<(), UploadError> {
        let ids: Vec<_> = self
            .stages
            .iter()
            .filter_map(|(id, stage)| (&stage.owner == owner).then_some(*id))
            .collect();
        let mut first_error = None;
        for id in ids {
            if self.stages[&id].retained {
                if first_error.is_none() {
                    first_error = Some(UploadError::Refused(
                        "retained upload backing has no confirmed File lifetime end",
                    ));
                }
                continue;
            }
            if let Err(error) = self.remove(id) {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    /// The worker calls this only after actual placement revalidation at final
    /// native-host shutdown. Ending a host or tab cannot prove that every
    /// browser consumer finished reading selected backing.
    /// An unvalidated namespace change leaves cleanup unconfirmed as well.
    pub(super) fn cleanup_all(&mut self) -> Result<(), UploadError> {
        let ids: Vec<_> = self.stages.keys().copied().collect();
        let mut first_error = None;
        for id in ids {
            if self.stages[&id].retained {
                if first_error.is_none() {
                    first_error = Some(UploadError::Refused(
                        "retained upload backing has no confirmed File lifetime end",
                    ));
                }
                continue;
            }
            if let Err(error) = self.remove(id) {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    fn remove(&mut self, id: Uuid) -> Result<(), UploadError> {
        let stage = self
            .stages
            .get_mut(&id)
            .ok_or(UploadError::Refused("upload stage is unavailable"))?;
        // Closing files first permits removal on Windows. Retain path custody if
        // directory removal fails; the caller receives Unknown, never success.
        validate_stage_directory(stage)?;
        stage.cleanup_started = true;
        stage.files.clear();
        // Record each completed owned-subdirectory deletion immediately. A later
        // failure can retry without treating a missing path as deletion proof.
        // Still-live renamed/replaced objects always fail the identity check.
        while let Some((path, proof)) = stage.index_directories.last() {
            proof
                .validate_path(path)
                .map_err(|error| UploadError::Io(io::Error::other(error)))?;
            std::fs::remove_dir_all(path)?;
            stage.index_directories.pop();
        }
        // Do not recursively consume unexpected new entries in the top level.
        std::fs::remove_dir(&stage.directory)?;
        self.stages.remove(&id);
        Ok(())
    }
}

fn validate_stage_directory(stage: &Stage) -> Result<(), UploadError> {
    let proof = stage.directory_proof.as_ref().ok_or(UploadError::Refused(
        "upload directory creation has no verified owned object",
    ))?;
    proof
        .validate_path(&stage.directory)
        .map_err(|error| UploadError::Io(io::Error::other(error)))?;
    for (path, proof) in &stage.index_directories {
        proof
            .validate_path(path)
            .map_err(|error| UploadError::Io(io::Error::other(error)))?;
    }
    for file in &stage.files {
        file.identity
            .validate_path(&file.output, &file.path)
            .map_err(|error| UploadError::Io(io::Error::other(error)))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn owner() -> UploadOwner {
        UploadOwner {
            session_id: "test-owner".into(),
            tab_id: 7,
            target_id: "actual-target".into(),
        }
    }
    fn file(name: &str, bytes: &[u8]) -> ExtensionUploadFile {
        ExtensionUploadFile::new(
            name.into(),
            bytes.len() as u64,
            Sha256::digest(bytes).into(),
        )
        .unwrap()
    }
    #[test]
    fn exact_chunks_hash_and_retain_preserve_name_bytes_and_lifetime() {
        let bytes = vec![42; EXTENSION_UPLOAD_CHUNK_BYTES + 19];
        let mut resources = UploadResources::default();
        let binding = owner();
        let id = resources
            .begin(binding.clone(), &[file("Café 日本語 🐧.txt", &bytes)])
            .unwrap();
        assert!(resources.retain(id, &binding).is_err());
        assert!(resources
            .write_chunk(id, &binding, 0, 1, &bytes[..1])
            .is_err());
        for (index, chunk) in bytes.chunks(EXTENSION_UPLOAD_CHUNK_BYTES).enumerate() {
            resources
                .write_chunk(
                    id,
                    &binding,
                    0,
                    (index * EXTENSION_UPLOAD_CHUNK_BYTES) as u64,
                    chunk,
                )
                .unwrap();
        }
        let paths = resources.retain(id, &binding).unwrap();
        assert_eq!(paths[0].file_name().unwrap(), "Café 日本語 🐧.txt");
        assert_eq!(std::fs::read(&paths[0]).unwrap(), bytes);
        assert!(resources.abandon(id, &binding).is_err());
        assert!(resources
            .write_chunk(id, &binding, 0, bytes.len() as u64, b"x")
            .is_err());
        let foreign = UploadOwner {
            session_id: "other".into(),
            ..binding.clone()
        };
        assert!(resources.retire_tab(&foreign).is_ok());
        assert!(paths[0].exists());
        assert!(matches!(
            resources.retire_tab(&binding),
            Err(UploadError::Refused(
                "retained upload backing has no confirmed File lifetime end"
            ))
        ));
        assert_eq!(std::fs::read(&paths[0]).unwrap(), bytes);
        // No browser received this test-owned fixture. Its local owner can
        // remove it explicitly without inventing a production File-death proof.
        resources.remove(id).unwrap();
        assert!(!paths[0].exists());
    }
}
