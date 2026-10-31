// SPDX-License-Identifier: MIT

use super::{RegistrationSlot, Value};
use std::{
    fs,
    io::{self, Write},
    path::Path,
};

#[cfg(windows)]
mod registry;

#[cfg(windows)]
pub(super) fn registered_manifest(subkey: &str) -> io::Result<Option<std::path::PathBuf>> {
    registry::registered_manifest(subkey)
}

pub(super) fn barrier(slot: &RegistrationSlot) -> io::Result<()> {
    match slot {
        RegistrationSlot::Manifest(path) => {
            match fs::File::options()
                .read(true)
                .write(cfg!(windows))
                .open(path)
            {
                Ok(file) => file.sync_all()?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            let mut ancestor = path.parent();
            while let Some(parent) = ancestor {
                match sync_directory(parent) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        ancestor = parent.parent()
                    }
                    result => return result,
                }
            }
            Err(io::Error::other("registration has no existing parent"))
        }
        #[cfg(windows)]
        RegistrationSlot::Registry { .. } => registry::flush(),
    }
}

pub(super) fn read(slot: &RegistrationSlot) -> io::Result<Option<Value>> {
    match slot {
        RegistrationSlot::Manifest(path) => {
            let mut file = match fs::File::open(path) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error),
            };
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                file.metadata()?.permissions().mode()
            };
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut file, &mut bytes)?;
            Ok(Some(Value {
                bytes,
                #[cfg(unix)]
                mode,
                #[cfg(windows)]
                registry_type: None,
            }))
        }
        #[cfg(windows)]
        RegistrationSlot::Registry { subkey, view } => registry::read(subkey, *view),
    }
}

pub(super) fn replacement(slot: &RegistrationSlot, bytes: Vec<u8>) -> Value {
    let _ = slot;
    Value {
        bytes,
        #[cfg(unix)]
        mode: 0o100600,
        #[cfg(windows)]
        registry_type: match slot {
            RegistrationSlot::Manifest(_) => None,
            RegistrationSlot::Registry { .. } => Some(1),
        },
    }
}

pub(super) fn write(slot: &RegistrationSlot, value: Option<&Value>) -> io::Result<()> {
    match slot {
        RegistrationSlot::Manifest(path) => match value {
            Some(value) => atomic_file(path, &value.bytes, Some(value)),
            None => {
                fs::remove_file(path)?;
                sync_directory(
                    path.parent()
                        .ok_or_else(|| io::Error::other("manifest lacks parent"))?,
                )
            }
        },
        #[cfg(windows)]
        RegistrationSlot::Registry { subkey, view } => registry::write(subkey, *view, value),
    }
}

pub(super) fn atomic_file(path: &Path, bytes: &[u8], original: Option<&Value>) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("registration lacks parent"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(
                original.map_or(0o600, |value| value.mode),
            ))?;
    }
    #[cfg(not(unix))]
    let _ = original;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    #[cfg(not(windows))]
    temporary.persist(path).map_err(|error| error.error)?;
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn MoveFileExW(existing: *const u16, replacement: *const u16, flags: u32) -> i32;
        }
        let source: Vec<u16> = temporary
            .path()
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let target: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: both paths are terminated and remain alive; replace-existing
        // plus write-through makes publication precede durable registry writes.
        if unsafe { MoveFileExW(source.as_ptr(), target.as_ptr(), 1 | 8) } == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    sync_directory(parent)
}

pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}
