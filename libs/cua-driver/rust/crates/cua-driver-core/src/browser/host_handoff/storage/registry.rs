// SPDX-License-Identifier: MIT

use super::super::{RegistryView, Value};
use std::{ffi::c_void, io, ptr};

type Key = *mut c_void;
const CURRENT_USER: Key = (0x8000_0001_u32 as i32 as isize) as Key;
const MISSING: i32 = 2;

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
    fn RegFlushKey(key: Key) -> i32;
    fn RegCloseKey(key: Key) -> i32;
}

struct OwnedKey(Key);
impl Drop for OwnedKey {
    fn drop(&mut self) {
        // SAFETY: this uniquely owned handle came from a successful registry open.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

fn status(code: i32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code))
    }
}

pub(super) fn flush() -> io::Result<()> {
    // SAFETY: the predefined current-user hive is valid and is not closed here.
    status(unsafe { RegFlushKey(CURRENT_USER) })
}

fn open(
    root: Key,
    subkey: &str,
    view: RegistryView,
    write: bool,
    create: bool,
) -> io::Result<Option<OwnedKey>> {
    if subkey.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "registry key contains NUL",
        ));
    }
    let name: Vec<u16> = subkey.encode_utf16().chain(Some(0)).collect();
    let access = 1
        | if write { 2 } else { 0 }
        | match view {
            RegistryView::Bits32 => 0x0200,
            RegistryView::Bits64 => 0x0100,
        };
    let mut key = ptr::null_mut();
    // SAFETY: the name is terminated UTF-16; the output handle is initialized.
    let code = unsafe {
        if create {
            RegCreateKeyExW(
                root,
                name.as_ptr(),
                0,
                ptr::null_mut(),
                0,
                access,
                ptr::null(),
                &mut key,
                ptr::null_mut(),
            )
        } else {
            RegOpenKeyExW(root, name.as_ptr(), 0, access, &mut key)
        }
    };
    if code == MISSING {
        return Ok(None);
    }
    status(code)?;
    Ok(Some(OwnedKey(key)))
}

pub(super) fn read(subkey: &str, view: RegistryView) -> io::Result<Option<Value>> {
    read_from(CURRENT_USER, subkey, view)
}

fn read_from(root: Key, subkey: &str, view: RegistryView) -> io::Result<Option<Value>> {
    let Some(key) = open(root, subkey, view, false, false)? else {
        return Ok(None);
    };
    let mut kind = 0;
    let mut size = 0;
    // SAFETY: size probing writes only the initialized scalar outputs.
    let code = unsafe {
        RegQueryValueExW(
            key.0,
            ptr::null(),
            ptr::null_mut(),
            &mut kind,
            ptr::null_mut(),
            &mut size,
        )
    };
    if code == MISSING {
        return Ok(None);
    }
    status(code)?;
    let mut bytes = vec![0; size as usize];
    // SAFETY: bytes has exactly the probed capacity; Win32 rejects larger data.
    status(unsafe {
        RegQueryValueExW(
            key.0,
            ptr::null(),
            ptr::null_mut(),
            &mut kind,
            bytes.as_mut_ptr(),
            &mut size,
        )
    })?;
    bytes.truncate(size as usize);
    Ok(Some(Value {
        bytes,
        registry_type: Some(kind),
    }))
}

pub(super) fn write(subkey: &str, view: RegistryView, value: Option<&Value>) -> io::Result<()> {
    let Some(key) = open(CURRENT_USER, subkey, view, true, value.is_some())? else {
        return Ok(());
    };
    let code = match value {
        Some(value) => {
            let kind = value.registry_type.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "registry value lacks type")
            })?;
            let length = u32::try_from(value.bytes.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "registry value exceeds Win32 byte range",
                )
            })?;
            // SAFETY: bytes remains live for its full length; only the default value is changed.
            unsafe { RegSetValueExW(key.0, ptr::null(), 0, kind, value.bytes.as_ptr(), length) }
        }
        None => {
            // SAFETY: key is open for writes; a null name selects the default value.
            unsafe { RegDeleteValueW(key.0, ptr::null()) }
        }
    };
    if code != MISSING {
        status(code)?;
    }
    // SAFETY: this valid handle remains owned until the durability call returns.
    status(unsafe { RegFlushKey(key.0) })
}

pub(super) fn registered_manifest(subkey: &str) -> io::Result<Option<std::path::PathBuf>> {
    const MACHINE: Key = (0x8000_0002_u32 as i32 as isize) as Key;
    for root in [CURRENT_USER, MACHINE] {
        for view in [RegistryView::Bits32, RegistryView::Bits64] {
            if let Some(value) = read_from(root, subkey, view)? {
                if value.registry_type != Some(1) || value.bytes.len() % 2 != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "native host manifest registry value is not REG_SZ",
                    ));
                }
                let mut text: Vec<u16> = value
                    .bytes
                    .chunks_exact(2)
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .collect();
                if text.pop() != Some(0) || text.contains(&0) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "native host manifest registry path is not terminated UTF-16",
                    ));
                }
                let text = String::from_utf16(&text)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                return Ok(Some(text.into()));
            }
        }
    }
    Ok(None)
}
