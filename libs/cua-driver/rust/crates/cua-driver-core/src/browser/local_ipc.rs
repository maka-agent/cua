// SPDX-License-Identifier: MIT

//! Private current-user IPC for the Chrome-owned extension-host process.
//!
//! Endpoint records are routing capabilities for this user account. They do not
//! attest Chrome signatures or exclude arbitrary software running as that user.
//! The runtime connects outward; this module does not start another daemon.

use super::extension_broker::{CheckedLocalPeer, LocalPrincipal};
use super::extension_framing::{self, Direction};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[cfg(unix)]
#[path = "local_ipc/unix.rs"]
mod platform;
#[cfg(windows)]
#[path = "local_ipc/windows.rs"]
mod platform;

pub(crate) use platform::LocalListener;
pub use platform::LocalStream;

/// Actual object identity of a newly created, private native-host upload directory.
/// A resource address never substitutes for this kept descriptor and identity.
pub(super) struct UploadDirectoryIdentity {
    file: std::fs::File,
    identity: platform::FileIdentity,
}
impl UploadDirectoryIdentity {
    /// The native object path, with a global volume-GUID prefix on Windows.
    /// This changes only the private staging prefix, never an approved basename.
    pub(super) fn native_path(&self, current: &Path) -> Result<PathBuf, IpcError> {
        self.validate_path(current)?;
        platform::upload_directory_native_path(&self.file, current)
    }
    pub(super) fn validate_path(&self, path: &Path) -> Result<(), IpcError> {
        if platform::file_identity(&self.file)? != self.identity {
            return Err(rejected(
                "owned upload directory descriptor changed identity",
            ));
        }
        let current = platform::open_private_upload_directory(path)?;
        if platform::file_identity(&current)? != self.identity {
            return Err(rejected("owned upload directory path was replaced"));
        }
        Ok(())
    }
}
pub(super) struct UploadFileIdentity(platform::FileIdentity);
pub(super) fn upload_file_identity(file: &std::fs::File) -> Result<UploadFileIdentity, IpcError> {
    if !file.metadata()?.is_file() {
        return Err(rejected("upload backing is not a regular file"));
    }
    Ok(UploadFileIdentity(platform::file_identity(file)?))
}
impl UploadFileIdentity {
    pub(super) fn validate_path(&self, file: &std::fs::File, path: &Path) -> Result<(), IpcError> {
        if platform::file_identity(file)? != self.0 {
            return Err(rejected("upload backing descriptor changed identity"));
        }
        let actual = platform::open_upload_file_for_identity(path)?;
        if platform::file_identity(&actual)? != self.0 {
            return Err(rejected("upload backing path was replaced"));
        }
        Ok(())
    }
}

/// Only the upload worker supplies this internally minted absolute path. Creation
/// is exclusive, and applies existing current-user directory security primitives.
pub(super) fn create_upload_directory(path: &Path) -> Result<UploadDirectoryIdentity, IpcError> {
    platform::create_private_upload_directory(path)?;
    let file = platform::open_private_upload_directory(path)?;
    let identity = platform::file_identity(&file)?;
    Ok(UploadDirectoryIdentity { file, identity })
}

const MAX_LOCAL_FRAME: usize = 64 * 1024 * 1024;
const MAX_DESCRIPTOR: u64 = 64 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Metadata supplied by the actual extension hello, plus the extension host PID.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionEndpointIdentity {
    pub adapter: String,
    pub extension_id: String,
    pub instance_id: String,
    pub generation: String,
    pub capabilities: Value,
    pub host_pid: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "address", rename_all = "camelCase")]
pub(crate) enum EndpointAddress {
    Unix(PathBuf),
    Windows(String),
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Descriptor {
    protocol: u32,
    identity: ExtensionEndpointIdentity,
    endpoint: EndpointAddress,
    capability: String,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IpcError {
    #[error("private installation entry is absent after its parent was validated")]
    MissingInstallationFile,
    #[error("private extension IPC I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("private extension IPC JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("private extension IPC frame failed: {0}")]
    Frame(String),
    #[error("private extension IPC rejected: {0}")]
    Rejected(String),
    #[error("private extension IPC handshake timed out")]
    Timeout,
}

impl From<extension_framing::FrameError> for IpcError {
    fn from(error: extension_framing::FrameError) -> Self {
        Self::Frame(error.to_string())
    }
}

fn rejected(message: &str) -> IpcError {
    IpcError::Rejected(message.to_owned())
}

/// A descriptor loaded from a private directory and bound to its file identity.
#[derive(Clone)]
pub struct ValidatedExtensionEndpoint {
    descriptor: Descriptor,
    descriptor_path: PathBuf,
    file_identity: platform::FileIdentity,
}

impl std::fmt::Debug for ValidatedExtensionEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedExtensionEndpoint")
            .field("identity", &self.descriptor.identity)
            .field("descriptor_path", &self.descriptor_path)
            .finish_non_exhaustive()
    }
}

impl ValidatedExtensionEndpoint {
    /// Read only a current-user private, non-reparse descriptor for this adapter.
    ///
    /// # Errors
    /// Refuses changed ownership/permissions, symlinks, malformed identity, an
    /// unexpected adapter, a public endpoint, or a descriptor larger than 64 KiB.
    pub fn load(path: &Path, expected_adapter: &str) -> Result<Self, IpcError> {
        let parent = path
            .parent()
            .ok_or_else(|| rejected("descriptor has no private parent"))?;
        platform::validate_directory(parent)?;
        let mut file = platform::open_private_file(path)?;
        let file_identity = platform::file_identity(&file)?;
        if file.metadata()?.len() > MAX_DESCRIPTOR {
            return Err(rejected("descriptor exceeds its byte budget"));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_DESCRIPTOR + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_DESCRIPTOR {
            return Err(rejected("descriptor grew beyond its byte budget"));
        }
        let descriptor: Descriptor = serde_json::from_slice(&bytes)?;
        validate_descriptor(path, expected_adapter, &descriptor)?;
        if platform::path_identity(path)? != file_identity {
            return Err(rejected("descriptor changed while loading"));
        }
        platform::validate_address(
            parent,
            &descriptor.identity.generation,
            &descriptor.endpoint,
        )?;
        Ok(Self {
            descriptor,
            descriptor_path: path.to_owned(),
            file_identity,
        })
    }

    pub fn identity(&self) -> &ExtensionEndpointIdentity {
        &self.descriptor.identity
    }

    /// Remove this captured generation after its exact native-host process has
    /// been confirmed exited by the handoff supervisor. Never call on a live host.
    pub fn cleanup_after_host_exit(&self) -> Result<(), IpcError> {
        platform::remove_owned_file(&self.descriptor_path, &self.file_identity)?;
        #[cfg(unix)]
        {
            let EndpointAddress::Unix(path) = &self.descriptor.endpoint else {
                return Err(rejected("retired endpoint is not a Unix socket"));
            };
            let parent = self
                .descriptor_path
                .parent()
                .ok_or_else(|| rejected("descriptor lacks parent"))?;
            match platform::validate_address(
                parent,
                &self.descriptor.identity.generation,
                &self.descriptor.endpoint,
            ) {
                Ok(()) => std::fs::remove_file(path)?,
                Err(IpcError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Compare physical endpoint identity without exposing its routing capability.
    pub fn same_endpoint(&self, other: &Self) -> bool {
        self.descriptor_path == other.descriptor_path
            && self.file_identity == other.file_identity
            && self.descriptor.endpoint == other.descriptor.endpoint
            && self.descriptor.identity == other.descriptor.identity
            && capability_matches(&self.descriptor.capability, &other.descriptor.capability)
    }

    /// Connect once, verify the actual host peer, then complete the IPC handshake.
    ///
    /// # Errors
    /// Any path/peer/identity change or lost handshake refuses the connection.
    /// The returned stream is never automatically reconnected or replayed.
    pub async fn connect(&self) -> Result<LocalStream, IpcError> {
        let path = self.descriptor_path.clone();
        let adapter = self.descriptor.identity.adapter.clone();
        let current = tokio::task::spawn_blocking(move || Self::load(&path, &adapter))
            .await
            .map_err(|error| rejected(&format!("endpoint revalidation task ended: {error}")))??;
        if current.file_identity != self.file_identity
            || current.descriptor.identity != self.descriptor.identity
            || !capability_matches(&current.descriptor.capability, &self.descriptor.capability)
        {
            return Err(rejected("selected endpoint generation changed"));
        }
        let mut stream =
            platform::connect(&self.descriptor.endpoint, self.descriptor.identity.host_pid).await?;
        let handshake = async {
            write_json(&mut stream, &json!({"kind":"hello","protocol":1,"generation":self.descriptor.identity.generation,"capability":self.descriptor.capability})).await?;
            let response = read_json_limited(&mut stream, MAX_DESCRIPTOR as usize)
                .await?
                .ok_or_else(|| rejected("host closed during handshake"))?;
            let welcome: Welcome = serde_json::from_value(response)?;
            if welcome.kind != "welcome"
                || welcome.protocol != 1
                || welcome.generation != self.descriptor.identity.generation
                || welcome.identity != self.descriptor.identity
            {
                return Err(rejected(
                    "welcome identity disagrees with selected descriptor",
                ));
            }
            Ok(())
        };
        tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
            .await
            .map_err(|_| IpcError::Timeout)??;
        Ok(stream)
    }
}

fn validate_descriptor(
    path: &Path,
    expected_adapter: &str,
    descriptor: &Descriptor,
) -> Result<(), IpcError> {
    let identity = &descriptor.identity;
    if descriptor.protocol != 1
        || identity.adapter != expected_adapter
        || !valid_namespace(&identity.adapter)
    {
        return Err(rejected("unexpected descriptor protocol or adapter"));
    }
    if identity.extension_id.len() != 32
        || !identity
            .extension_id
            .bytes()
            .all(|byte| (b'a'..=b'p').contains(&byte))
    {
        return Err(rejected("descriptor extension ID is invalid"));
    }
    let generation = uuid::Uuid::parse_str(&identity.generation)
        .map_err(|_| rejected("descriptor generation is invalid"))?;
    if generation.to_string() != identity.generation
        || identity.instance_id.is_empty()
        || identity.instance_id.len() > 128
        || !identity.capabilities.is_object()
        || identity.host_pid == 0
    {
        return Err(rejected("descriptor identity is invalid"));
    }
    if descriptor.capability.len() != 64
        || !descriptor
            .capability
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(rejected("descriptor capability is invalid"));
    }
    if path.file_name().and_then(|name| name.to_str())
        != Some(format!("{}.json", identity.generation).as_str())
    {
        return Err(rejected("descriptor filename disagrees with generation"));
    }
    Ok(())
}

fn validate_identity(identity: &ExtensionEndpointIdentity) -> Result<(), IpcError> {
    if !valid_namespace(&identity.adapter)
        || identity.extension_id.len() != 32
        || !identity
            .extension_id
            .bytes()
            .all(|byte| (b'a'..=b'p').contains(&byte))
    {
        return Err(rejected(
            "extension endpoint adapter or extension ID is invalid",
        ));
    }
    let generation = uuid::Uuid::parse_str(&identity.generation)
        .map_err(|_| rejected("extension endpoint generation is invalid"))?;
    if generation.to_string() != identity.generation
        || identity.instance_id.is_empty()
        || identity.instance_id.len() > 128
        || !identity.capabilities.is_object()
        || identity.host_pid == 0
    {
        return Err(rejected("extension endpoint identity is invalid"));
    }
    Ok(())
}

fn valid_namespace(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('.')
        && !value.ends_with('.')
        && !value.contains("..")
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.')
        })
}

fn capability_matches(expected: &str, received: &str) -> bool {
    if expected.len() != 64 || received.len() != 64 {
        return false;
    }
    expected
        .bytes()
        .zip(received.bytes())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    kind: String,
    protocol: u32,
    generation: String,
    capability: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Welcome {
    kind: String,
    protocol: u32,
    generation: String,
    identity: ExtensionEndpointIdentity,
}

/// Existing installation-selected private runtime directory, never public /tmp.
pub(crate) fn current_user_runtime_directory() -> Result<PathBuf, IpcError> {
    platform::runtime_directory()
}

pub(crate) fn validate_runtime_directory(path: &Path) -> Result<(), IpcError> {
    platform::validate_directory(path)
}

struct LoadedInstallationFile {
    path: PathBuf,
    bytes: Vec<u8>,
    identity: platform::FileIdentity,
}

impl LoadedInstallationFile {
    fn remove_exact(self, expected: &Value) -> Result<(), IpcError> {
        let current: Value = serde_json::from_slice(&self.bytes)?;
        if &current != expected {
            return Err(rejected("refusing to remove a changed installation entry"));
        }
        platform::remove_owned_file(&self.path, &self.identity)
    }
}

fn load_installation_file(path: &Path) -> Result<LoadedInstallationFile, IpcError> {
    platform::validate_installation_parent(
        path.parent()
            .ok_or_else(|| rejected("installation sidecar lacks parent"))?,
    )?;
    let mut file = match platform::open_private_file(path) {
        Err(IpcError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            return Err(IpcError::MissingInstallationFile);
        }
        result => result?,
    };
    if file.metadata()?.len() > MAX_DESCRIPTOR {
        return Err(rejected("installation sidecar exceeds byte budget"));
    }
    let identity = platform::file_identity(&file)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_DESCRIPTOR + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_DESCRIPTOR || platform::path_identity(path)? != identity {
        return Err(rejected("installation sidecar changed while loading"));
    }
    Ok(LoadedInstallationFile {
        path: path.to_owned(),
        bytes,
        identity,
    })
}

/// Private state grows with actual live owners rather than a descriptor budget.
pub(crate) fn load_private_state(path: &Path) -> Result<Vec<u8>, IpcError> {
    platform::validate_directory(
        path.parent()
            .ok_or_else(|| rejected("state lacks parent"))?,
    )?;
    let mut file = match platform::open_private_file(path) {
        Err(IpcError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            return Err(IpcError::MissingInstallationFile);
        }
        result => result?,
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

pub(crate) fn load_private_installation_config(path: &Path) -> Result<Vec<u8>, IpcError> {
    Ok(load_installation_file(path)?.bytes)
}

pub(crate) fn ensure_private_state_directory(path: &Path) -> Result<(), IpcError> {
    platform::ensure_directory(path)
}
pub(crate) fn ensure_installation_directory(path: &Path) -> Result<(), IpcError> {
    platform::ensure_installation_directory(path)
}

/// Serializes cooperating installer mutations, without attesting a caller.
/// The pathname remains after unlock so waiting writers use the same inode.
#[derive(Debug)]
pub(crate) struct InstallationMutationLock {
    _file: std::fs::File,
}

pub(crate) fn lock_installation_directory(
    directory: &Path,
) -> Result<InstallationMutationLock, IpcError> {
    platform::validate_directory(directory)?;
    let path = directory.join(".mutation.lock");
    match create_installation_file(&path, b"") {
        Ok(_) => {}
        Err(IpcError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let file = platform::open_private_file(&path)?;
    let identity = platform::file_identity(&file)?;
    if file.metadata()?.len() != 0 {
        return Err(rejected(
            "installation mutation lock is not an empty owned file",
        ));
    }
    fs2::FileExt::lock_exclusive(&file)?;
    platform::validate_directory(directory)?;
    if platform::path_identity(&path)? != identity {
        return Err(rejected("installation mutation lock changed while waiting"));
    }
    Ok(InstallationMutationLock { _file: file })
}

pub(crate) struct CreatedInstallationFile {
    path: PathBuf,
    identity: platform::FileIdentity,
}
impl CreatedInstallationFile {
    pub(crate) fn rollback(self) -> Result<(), IpcError> {
        platform::remove_owned_file(&self.path, &self.identity)
    }
}

/// Publish a new owned installation file; an existing path is never replaced.
pub(crate) fn create_installation_file(
    path: &Path,
    bytes: &[u8],
) -> Result<CreatedInstallationFile, IpcError> {
    let parent = path
        .parent()
        .ok_or_else(|| rejected("installation file lacks parent"))?;
    platform::validate_installation_parent(parent)?;
    let temporary = parent.join(format!(".maka-install-{}.pending", uuid::Uuid::new_v4()));
    let mut file = platform::create_installation_file(&temporary)?;
    let identity = platform::file_identity(&file)?;
    let write = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok::<(), IpcError>(())
    })();
    drop(file);
    let publication = write.and_then(|()| std::fs::hard_link(&temporary, path).map_err(Into::into));
    let cleanup = platform::remove_owned_file(&temporary, &identity);
    publication?;
    if let Err(error) = cleanup {
        let _ = platform::remove_owned_file(path, &identity);
        return Err(error);
    }
    Ok(CreatedInstallationFile {
        path: path.to_owned(),
        identity,
    })
}

pub(crate) fn remove_exact_installation_file(
    path: &Path,
    expected: &Value,
) -> Result<(), IpcError> {
    load_installation_file(path)?.remove_exact(expected)
}

/// Copy a selected legacy entry, then remove that same loaded file identity.
/// Caller holds the catalog mutation lock. This is not a filesystem CAS against
/// a noncooperating same-user pathname replacer.
pub(crate) fn migrate_exact_installation_file(
    source: &Path,
    destination: &Path,
    expected_bytes: &[u8],
) -> Result<bool, IpcError> {
    let loaded = load_installation_file(source)?;
    if loaded.bytes.as_slice() != expected_bytes {
        return Err(rejected(
            "legacy installation entry changed before migration",
        ));
    }
    let expected: Value = serde_json::from_slice(expected_bytes)?;
    let created = match create_installation_file(destination, expected_bytes) {
        Ok(file) => Some(file),
        Err(IpcError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
            let current = load_installation_file(destination)?;
            if serde_json::from_slice::<Value>(&current.bytes)? != expected {
                return Err(rejected("legacy migration destination differs"));
            }
            None
        }
        Err(error) => return Err(error),
    };
    let changed = created.is_some();
    if let Err(error) = loaded.remove_exact(&expected) {
        if let Some(created) = created {
            if let Err(rollback) = created.rollback() {
                return Err(rejected(&format!(
                    "legacy migration failed: {error}; own-copy rollback unconfirmed: {rollback}"
                )));
            }
        }
        return Err(error);
    }
    Ok(changed)
}

pub(crate) fn current_user_principal() -> Result<LocalPrincipal, IpcError> {
    platform::current_principal()
}

/// Listener and descriptor belong to one Chrome extension-port generation.
pub(crate) struct PublishedEndpoint {
    pub(crate) identity: ExtensionEndpointIdentity,
    descriptor: Descriptor,
    descriptor_path: PathBuf,
    descriptor_identity: platform::FileIdentity,
    listener: platform::LocalListener,
}

impl PublishedEndpoint {
    pub(crate) async fn publish(
        directory: &Path,
        identity: ExtensionEndpointIdentity,
    ) -> Result<Self, IpcError> {
        validate_identity(&identity)?;
        platform::ensure_directory(directory)?;
        let (listener, endpoint) =
            platform::LocalListener::bind(directory, &identity.generation).await?;
        let publication = (|| {
            let mut random = [0_u8; 32];
            getrandom::fill(&mut random).map_err(|error| {
                rejected(&format!("could not allocate endpoint capability: {error}"))
            })?;
            let capability = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let descriptor = Descriptor {
                protocol: 1,
                identity: identity.clone(),
                endpoint,
                capability,
            };
            let descriptor_path = directory.join(format!("{}.json", identity.generation));
            validate_descriptor(&descriptor_path, &identity.adapter, &descriptor)?;
            let bytes = serde_json::to_vec(&descriptor)?;
            if bytes.len() as u64 > MAX_DESCRIPTOR {
                return Err(rejected("actual hello metadata exceeds descriptor budget"));
            }
            let temporary = directory.join(format!(".{}.pending", identity.generation));
            let mut file = platform::create_private_file(&temporary)?;
            let temporary_identity = platform::file_identity(&file)?;
            let write_result = (|| {
                file.write_all(&bytes)?;
                file.sync_all()?;
                Ok::<(), IpcError>(())
            })();
            drop(file);
            let publish_result = write_result.and_then(|()| {
                std::fs::hard_link(&temporary, &descriptor_path).map_err(Into::into)
            });
            let temporary_cleanup = platform::remove_owned_file(&temporary, &temporary_identity);
            publish_result?;
            if let Err(error) = temporary_cleanup {
                let _ = platform::remove_owned_file(&descriptor_path, &temporary_identity);
                return Err(error);
            }
            // Linking completed bytes atomically refuses an existing generation.
            if platform::path_identity(&descriptor_path)? != temporary_identity {
                return Err(rejected(
                    "published descriptor changed before ownership capture",
                ));
            }
            let descriptor_identity = temporary_identity;
            Ok((descriptor, descriptor_path, descriptor_identity))
        })();
        match publication {
            Ok((descriptor, descriptor_path, descriptor_identity)) => Ok(Self {
                identity,
                descriptor,
                descriptor_path,
                descriptor_identity,
                listener,
            }),
            Err(error) => {
                let _ = listener.cleanup();
                Err(error)
            }
        }
    }

    pub(crate) async fn accept(&mut self) -> Result<(LocalStream, CheckedLocalPeer), IpcError> {
        self.listener.accept().await
    }

    /// Called after actual OS peer validation and before creating a broker owner.
    pub(crate) async fn handshake(&self, stream: &mut LocalStream) -> Result<(), IpcError> {
        let admission = async {
            let value = read_json_limited(stream, MAX_DESCRIPTOR as usize)
                .await?
                .ok_or_else(|| rejected("client closed before hello"))?;
            let hello: Hello = serde_json::from_value(value)?;
            if hello.kind != "hello"
                || hello.protocol != 1
                || hello.generation != self.identity.generation
                || !capability_matches(&self.descriptor.capability, &hello.capability)
            {
                return Err(rejected("local client capability or generation mismatch"));
            }
            write_json(stream, &json!({"kind":"welcome","protocol":1,"generation":self.identity.generation,"identity":self.identity})).await
        };
        tokio::time::timeout(HANDSHAKE_TIMEOUT, admission)
            .await
            .map_err(|_| IpcError::Timeout)?
    }

    /// Remove only files/socket still bearing this process's captured identity.
    pub(crate) fn cleanup(self) -> Result<(), IpcError> {
        let descriptor =
            platform::remove_owned_file(&self.descriptor_path, &self.descriptor_identity);
        let listener = self.listener.cleanup();
        descriptor?;
        listener
    }
}

pub(crate) async fn read_json(
    reader: &mut (impl AsyncRead + Unpin),
) -> Result<Option<Value>, IpcError> {
    read_json_limited(reader, MAX_LOCAL_FRAME).await
}

async fn read_json_limited(
    reader: &mut (impl AsyncRead + Unpin),
    limit: usize,
) -> Result<Option<Value>, IpcError> {
    let mut header = [0_u8; 4];
    let mut received = 0;
    while received < header.len() {
        let read = reader.read(&mut header[received..]).await?;
        if read == 0 {
            return if received == 0 {
                Ok(None)
            } else {
                Err(rejected("truncated IPC header"))
            };
        }
        received += read;
    }
    let length = u32::from_ne_bytes(header) as usize;
    if length == 0 || length > limit {
        return Err(rejected("IPC frame exceeds its byte budget"));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|error| rejected(&format!("IPC allocation failed: {error}")))?;
    bytes.resize(length, 0);
    reader.read_exact(&mut bytes).await?;
    std::str::from_utf8(&bytes).map_err(|_| rejected("IPC payload is not UTF-8"))?;
    Ok(Some(serde_json::from_slice(&bytes)?))
}

pub(crate) async fn write_json(
    writer: &mut (impl AsyncWrite + Unpin),
    value: &Value,
) -> Result<(), IpcError> {
    let bytes = extension_framing::encode_json(value, Direction::ChromeToHost)?;
    let length =
        u32::try_from(bytes.len()).map_err(|_| rejected("IPC payload cannot fit its header"))?;
    writer.write_all(&length.to_ne_bytes()).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> Descriptor {
        Descriptor {
            protocol: 1,
            identity: ExtensionEndpointIdentity {
                adapter: "org.apache.maka.browser_connector".into(),
                extension_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                instance_id: "actual-hello-fixture".into(),
                generation: "c539a521-554a-4b0d-bc72-eb47702c97cd".into(),
                capabilities: json!({"rawTabCdp":true}),
                host_pid: 1234,
            },
            endpoint: EndpointAddress::Unix(PathBuf::from("/private/fixture.sock")),
            capability: "a".repeat(64),
        }
    }

    #[test]
    fn descriptor_identity_is_exact_and_has_no_fake_metadata() {
        let descriptor = descriptor();
        let path = PathBuf::from("/private/c539a521-554a-4b0d-bc72-eb47702c97cd.json");
        assert!(
            validate_descriptor(&path, "org.apache.maka.browser_connector", &descriptor).is_ok()
        );
        assert!(validate_descriptor(&path, "other.adapter", &descriptor).is_err());
        assert!(validate_descriptor(
            Path::new("/private/different.json"),
            "org.apache.maka.browser_connector",
            &descriptor
        )
        .is_err());
        let mut changed = descriptor;
        changed.identity.generation = changed.identity.generation.to_uppercase();
        assert!(validate_descriptor(&path, "org.apache.maka.browser_connector", &changed).is_err());
    }

    #[test]
    fn capability_has_exact_length_and_content() {
        assert!(capability_matches(&"a".repeat(64), &"a".repeat(64)));
        assert!(!capability_matches(&"a".repeat(64), &"b".repeat(64)));
        assert!(!capability_matches(&"a".repeat(64), &"a".repeat(63)));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn selected_installation_file_does_not_adopt_replacement_identity() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("owned");
        platform::ensure_directory(&directory).unwrap();
        let path = directory.join("registration.json");
        let _created = create_installation_file(&path, br#"{"owned":true}"#).unwrap();
        let selected = load_installation_file(&path).unwrap();
        std::fs::rename(&path, directory.join("original.json")).unwrap();
        let _replacement = create_installation_file(&path, br#"{"owned":false}"#).unwrap();
        assert!(selected.remove_exact(&json!({"owned":true})).is_err());
        assert_eq!(
            serde_json::from_slice::<Value>(&load_private_installation_config(&path).unwrap())
                .unwrap(),
            json!({"owned":false})
        );
    }

    #[tokio::test]
    async fn ipc_codec_preserves_unicode_and_frame_boundaries() {
        let (mut writer, mut reader) = tokio::io::duplex(128);
        let task = tokio::spawn(async move {
            write_json(&mut writer, &json!({"text":"你好"}))
                .await
                .unwrap();
            write_json(&mut writer, &json!([2])).await.unwrap();
        });
        assert_eq!(
            read_json(&mut reader).await.unwrap(),
            Some(json!({"text":"你好"}))
        );
        assert_eq!(read_json(&mut reader).await.unwrap(), Some(json!([2])));
        task.await.unwrap();
        assert!(read_json(&mut reader).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn oversized_and_partial_ipc_headers_refuse_without_body() {
        let mut oversized = std::io::Cursor::new((MAX_LOCAL_FRAME as u32 + 1).to_ne_bytes());
        assert!(read_json(&mut oversized).await.is_err());
        let mut partial = std::io::Cursor::new([1_u8, 2]);
        assert!(read_json(&mut partial).await.is_err());
    }
}

pub(crate) async fn connect_service(
    directory: &Path,
    generation: &str,
    address: &EndpointAddress,
    pid: u32,
) -> Result<LocalStream, IpcError> {
    platform::validate_address(directory, generation, address)?;
    platform::connect(address, pid).await
}
