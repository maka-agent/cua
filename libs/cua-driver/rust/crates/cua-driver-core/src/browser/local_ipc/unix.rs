// SPDX-License-Identifier: MIT

//! Unix policy adapted from Cua serve.rs socket ownership and peer checks.

use super::*;
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
};
use tokio::net::{UnixListener, UnixStream};

pub type LocalStream = UnixStream;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FileIdentity {
    device: u64,
    inode: u64,
}

pub(super) fn current_principal() -> Result<LocalPrincipal, IpcError> {
    // SAFETY: geteuid has no preconditions and does not modify process state.
    Ok(LocalPrincipal::UnixUid(unsafe { libc::geteuid() }))
}

fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and does not modify process state.
    unsafe { libc::geteuid() }
}

fn no_symlink_components(path: &Path) -> Result<(), IpcError> {
    if !path.is_absolute() {
        return Err(rejected("private IPC path is not absolute"));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        if matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        ) {
            return Err(rejected("private IPC path is not normalized"));
        }
        current.push(component.as_os_str());
        if fs::symlink_metadata(&current)?.file_type().is_symlink() {
            return Err(rejected("private IPC path traverses a symlink"));
        }
    }
    Ok(())
}

pub(super) fn validate_directory(path: &Path) -> Result<(), IpcError> {
    no_symlink_components(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != current_uid()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(rejected(
            "extension IPC directory is not current-user private 0700",
        ));
    }
    validate_acl(&file)?;
    Ok(())
}

pub(super) fn create_private_upload_directory(path: &Path) -> Result<(), IpcError> {
    if !path.is_absolute() {
        return Err(rejected("upload directory is not absolute"));
    }
    fs::DirBuilder::new().mode(0o700).create(path)?;
    secure_new_directory(path)?;
    validate_directory(path)
}
pub(super) fn open_private_upload_directory(path: &Path) -> Result<File, IpcError> {
    validate_directory(path)?;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(Into::into)
}

pub(super) fn open_upload_file_for_identity(path: &Path) -> Result<File, IpcError> {
    no_symlink_components(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(rejected("upload backing path is not a regular file"));
    }
    Ok(file)
}

pub(super) fn upload_directory_native_path(file: &File, path: &Path) -> Result<PathBuf, IpcError> {
    file_identity(file)?;
    Ok(path.to_owned())
}

pub(super) fn ensure_directory(path: &Path) -> Result<(), IpcError> {
    let parent = path
        .parent()
        .ok_or_else(|| rejected("extension IPC directory has no parent"))?;
    validate_installation_parent(parent)?;
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => secure_new_directory(path)?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    validate_directory(path)
}

pub(super) fn runtime_directory() -> Result<PathBuf, IpcError> {
    let base = std::env::var_os("HOME")
        .ok_or_else(|| rejected("HOME is required for private browser IPC"))?;
    let base = fs::canonicalize(PathBuf::from(base))?;
    validate_installation_parent(&base)?;
    Ok(base.join(".maka-browser"))
}

pub(super) fn validate_installation_parent(path: &Path) -> Result<(), IpcError> {
    no_symlink_components(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir()
        || (metadata.uid() != 0 && metadata.uid() != current_uid())
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(rejected("installation parent is writable by another user"));
    }
    validate_acl(&file)?;
    Ok(())
}

pub(super) fn ensure_installation_directory(path: &Path) -> Result<(), IpcError> {
    match fs::symlink_metadata(path) {
        Ok(_) => return validate_installation_parent(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    validate_installation_parent(
        path.parent()
            .ok_or_else(|| rejected("installation directory lacks parent"))?,
    )?;
    fs::DirBuilder::new().mode(0o700).create(path)?;
    secure_new_directory(path)?;
    validate_installation_parent(path)
}

pub(super) fn create_installation_file(path: &Path) -> Result<File, IpcError> {
    validate_installation_parent(
        path.parent()
            .ok_or_else(|| rejected("installation file lacks parent"))?,
    )?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    clear_new_acl(&file)?;
    Ok(file)
}

pub(super) fn open_private_file(path: &Path) -> Result<File, IpcError> {
    no_symlink_components(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != current_uid()
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(rejected(
            "extension endpoint descriptor is not a current-user 0600 regular file",
        ));
    }
    validate_acl(&file)?;
    Ok(file)
}

pub(super) fn create_private_file(path: &Path) -> Result<File, IpcError> {
    validate_directory(
        path.parent()
            .ok_or_else(|| rejected("descriptor lacks parent"))?,
    )?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    clear_new_acl(&file)?;
    Ok(file)
}

fn secure_new_directory(path: &Path) -> Result<(), IpcError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    clear_new_acl(&file)?;
    file.set_permissions(fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_acl(_file: &File) -> Result<(), IpcError> {
    // Linux POSIX ACL named-user/group grants are constrained by the mask
    // represented in group mode bits; the checks above require that mask zero
    // on private objects and disallow write bits on installation parents.
    Ok(())
}
#[cfg(target_os = "linux")]
fn clear_new_acl(_file: &File) -> Result<(), IpcError> {
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn validate_acl(_file: &File) -> Result<(), IpcError> {
    Err(rejected("this Unix ACL boundary is not implemented"))
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn clear_new_acl(_file: &File) -> Result<(), IpcError> {
    Err(rejected("this Unix ACL boundary is not implemented"))
}

#[cfg(target_os = "macos")]
fn validate_acl(file: &File) -> Result<(), IpcError> {
    mac_acl::validate(file)
}
#[cfg(target_os = "macos")]
fn clear_new_acl(file: &File) -> Result<(), IpcError> {
    mac_acl::secure_new(file)
}

#[cfg(target_os = "macos")]
mod mac_acl {
    use super::*;
    use std::{ffi::c_void, os::fd::AsRawFd};
    const ACL_TYPE_EXTENDED: i32 = 0x100;
    const ACL_FIRST_ENTRY: i32 = 0;
    const ACL_NEXT_ENTRY: i32 = -1;
    const ACL_EXTENDED_ALLOW: i32 = 1;
    const ACL_EXTENDED_DENY: i32 = 2;
    unsafe extern "C" {
        fn acl_get_fd_np(fd: i32, kind: i32) -> *mut c_void;
        fn acl_set_fd_np(fd: i32, acl: *mut c_void, kind: i32) -> i32;
        fn acl_init(count: i32) -> *mut c_void;
        fn acl_valid(acl: *mut c_void) -> i32;
        fn acl_get_entry(acl: *mut c_void, selector: i32, entry: *mut *mut c_void) -> i32;
        fn acl_get_tag_type(entry: *mut c_void, tag: *mut i32) -> i32;
        fn acl_free(object: *mut c_void) -> i32;
    }
    struct Acl(*mut c_void);
    impl Drop for Acl {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: this guard owns one ACL working allocation.
                unsafe {
                    acl_free(self.0);
                }
            }
        }
    }

    pub(super) fn validate(file: &File) -> Result<(), IpcError> {
        // SAFETY: the opened regular-file/directory handle remains alive.
        let pointer = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
        if pointer.is_null() {
            let error = io::Error::last_os_error();
            // Apple Libc acl_get_fd_np uses FILESEC_ACL; absent property is
            // ENOENT. The handle itself was already opened and fstat-validated.
            return if error.raw_os_error() == Some(libc::ENOENT) {
                Ok(())
            } else {
                Err(error.into())
            };
        }
        let acl = Acl(pointer);
        // SAFETY: acl_get_fd_np returned one allocated working ACL.
        if unsafe { acl_valid(acl.0) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        for index in 0..=128 {
            let mut entry = std::ptr::null_mut();
            // SAFETY: the iterator and output refer to the retained extension ACL.
            let result = unsafe {
                acl_get_entry(
                    acl.0,
                    if index == 0 {
                        ACL_FIRST_ENTRY
                    } else {
                        ACL_NEXT_ENTRY
                    },
                    &mut entry,
                )
            };
            if result != 0 {
                let error = io::Error::last_os_error();
                return if result == -1 && error.raw_os_error() == Some(libc::EINVAL) {
                    Ok(())
                } else {
                    Err(error.into())
                };
            }
            if index == 128 || entry.is_null() {
                return Err(rejected(
                    "macOS extended ACL exceeds its proven entry bound",
                ));
            }
            let mut tag = 0;
            // SAFETY: entry is a descriptor within this retained working ACL.
            if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
            match tag {
                ACL_EXTENDED_DENY => {}
                ACL_EXTENDED_ALLOW => {
                    return Err(rejected(
                        "macOS private IPC requires no extended-ACL allow entries on existing directories/files",
                    ));
                }
                _ => {
                    return Err(rejected(
                        "macOS extended ACL has an unrecognized entry type",
                    ));
                }
            }
        }
        Err(rejected("macOS extended ACL iteration did not settle"))
    }

    pub(super) fn secure_new(file: &File) -> Result<(), IpcError> {
        // Called only for an object just created by this helper. Never clear
        // ACLs on HOME, a pre-existing directory, profile or application file.
        // SAFETY: acl_init(0) allocates a valid empty working ACL.
        let pointer = unsafe { acl_init(0) };
        if pointer.is_null() {
            return Err(io::Error::last_os_error().into());
        }
        let acl = Acl(pointer);
        // SAFETY: the helper owns this new object and the ACL stays allocated.
        if unsafe { acl_set_fd_np(file.as_raw_fd(), acl.0, ACL_TYPE_EXTENDED) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        validate(file)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    #[test]
    fn fifo_at_descriptor_path_refuses_without_waiting_for_a_writer() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("registration.json");
        let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: this is a unique task-owned fixture pathname with no NUL.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(open_private_file(&path).is_err());
    }
}

pub(super) fn file_identity(file: &File) -> Result<FileIdentity, IpcError> {
    let metadata = file.metadata()?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}
pub(super) fn path_identity(path: &Path) -> Result<FileIdentity, IpcError> {
    file_identity(&open_private_file(path)?)
}

pub(super) fn remove_owned_file(path: &Path, expected: &FileIdentity) -> Result<(), IpcError> {
    match path_identity(path) {
        Ok(actual) if &actual == expected => fs::remove_file(path).map_err(Into::into),
        Ok(_) => Err(rejected("refusing to remove a replaced descriptor")),
        Err(IpcError::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(super) fn validate_address(
    parent: &Path,
    generation: &str,
    address: &EndpointAddress,
) -> Result<(), IpcError> {
    let EndpointAddress::Unix(path) = address else {
        return Err(rejected("descriptor transport differs from this Unix host"));
    };
    if path != &parent.join(format!("{generation}.sock"))
        || path.as_os_str().as_encoded_bytes().len() >= 104
    {
        return Err(rejected(
            "Unix browser endpoint is outside its exact private generation path",
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != current_uid()
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(rejected(
            "Unix browser endpoint is not a current-user 0600 socket",
        ));
    }
    Ok(())
}

pub(super) async fn connect(
    address: &EndpointAddress,
    host_pid: u32,
) -> Result<LocalStream, IpcError> {
    let EndpointAddress::Unix(path) = address else {
        return Err(rejected("endpoint is not a Unix socket"));
    };
    let stream = UnixStream::connect(path).await?;
    let credentials = stream.peer_cred()?;
    if credentials.uid() != current_uid()
        || credentials.pid().and_then(|pid| u32::try_from(pid).ok()) != Some(host_pid)
    {
        return Err(rejected(
            "Unix extension host peer uid/pid disagrees with descriptor",
        ));
    }
    Ok(stream)
}

pub(crate) struct LocalListener {
    listener: UnixListener,
    path: PathBuf,
    identity: FileIdentity,
}

impl LocalListener {
    pub(crate) async fn bind(
        directory: &Path,
        generation: &str,
    ) -> Result<(Self, EndpointAddress), IpcError> {
        validate_directory(directory)?;
        let path = directory.join(format!("{generation}.sock"));
        if path.as_os_str().as_encoded_bytes().len() >= 104 {
            return Err(rejected("private Unix socket path exceeds portable length"));
        }
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(rejected("extension generation socket already exists")),
        }
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let metadata = fs::symlink_metadata(&path)?;
        let identity = FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        Ok((
            Self {
                listener,
                path: path.clone(),
                identity,
            },
            EndpointAddress::Unix(path),
        ))
    }

    pub(crate) async fn accept(&mut self) -> Result<(LocalStream, CheckedLocalPeer), IpcError> {
        loop {
            let (stream, _) = self.listener.accept().await?;
            let credentials = match stream.peer_cred() {
                Ok(credentials) => credentials,
                Err(_) => {
                    drop(stream);
                    continue;
                }
            };
            if credentials.uid() != current_uid() {
                drop(stream);
                continue;
            }
            return Ok((
                stream,
                CheckedLocalPeer::from_checked_principal(LocalPrincipal::UnixUid(
                    credentials.uid(),
                )),
            ));
        }
    }

    pub(crate) fn cleanup(self) -> Result<(), IpcError> {
        drop(self.listener);
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.identity.device
            && metadata.ino() == self.identity.inode
            && metadata.uid() == current_uid()
        {
            fs::remove_file(self.path)?;
            Ok(())
        } else {
            Err(rejected("refusing to remove a replaced extension socket"))
        }
    }
}
