// SPDX-License-Identifier: MIT

//! Windows policy adapted from Cua serve.rs current-user pipe checks.
//! Every first instance reserves its random name; remote pipe clients refuse.

use super::*;
use std::{
    ffi::c_void,
    fs::{self, File},
    os::windows::{
        ffi::OsStrExt,
        fs::MetadataExt,
        io::{AsRawHandle, FromRawHandle},
    },
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::ReadBuf,
    net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions},
};

type Handle = *mut c_void;
const INVALID_HANDLE: Handle = -1_isize as Handle;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_ALL_ACCESS: u32 = 0x001f_01ff;

#[repr(C)]
struct SecurityAttributes {
    length: u32,
    descriptor: *mut c_void,
    inherit: i32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct SidAndAttributes {
    sid: *mut c_void,
    attributes: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct TokenUser {
    user: SidAndAttributes,
}
#[repr(C)]
struct AclSizeInformation {
    count: u32,
    used: u32,
    free: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct AceHeader {
    kind: u8,
    flags: u8,
    size: u16,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FileTime {
    low: u32,
    high: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FileInformation {
    attributes: u32,
    creation: FileTime,
    access: FileTime,
    write: FileTime,
    volume: u32,
    size_high: u32,
    size_low: u32,
    links: u32,
    index_high: u32,
    index_low: u32,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
    fn LocalFree(memory: Handle) -> Handle;
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
    fn GetNamedPipeClientProcessId(pipe: Handle, pid: *mut u32) -> i32;
    fn GetNamedPipeServerProcessId(pipe: Handle, pid: *mut u32) -> i32;
    fn CreateDirectoryW(path: *const u16, security: *const SecurityAttributes) -> i32;
    fn CreateFileW(
        path: *const u16,
        access: u32,
        share: u32,
        security: *const SecurityAttributes,
        creation: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    fn GetFileInformationByHandle(file: Handle, information: *mut FileInformation) -> i32;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    fn GetTokenInformation(
        token: Handle,
        class: u32,
        information: Handle,
        length: u32,
        required: *mut u32,
    ) -> i32;
    fn ConvertSidToStringSidW(sid: Handle, text: *mut *mut u16) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16,
        revision: u32,
        descriptor: *mut Handle,
        length: *mut u32,
    ) -> i32;
    fn GetNamedSecurityInfoW(
        path: *const u16,
        kind: u32,
        information: u32,
        owner: *mut Handle,
        group: *mut Handle,
        dacl: *mut Handle,
        sacl: *mut Handle,
        descriptor: *mut Handle,
    ) -> u32;
    fn GetSecurityDescriptorControl(
        descriptor: Handle,
        control: *mut u16,
        revision: *mut u32,
    ) -> i32;
    fn GetAclInformation(acl: Handle, information: Handle, length: u32, class: u32) -> i32;
    fn GetAce(acl: *const c_void, index: u32, ace: *mut Handle) -> i32;
}

struct OwnedHandle(Handle);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE {
            // SAFETY: this guard owns one non-pseudo process/token handle.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}
struct OwnedLocal(Handle);
impl Drop for OwnedLocal {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this guard owns memory allocated by a LocalAlloc API.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

fn wide(path: &Path) -> Result<Vec<u16>, IpcError> {
    let mut text = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if text.contains(&0) {
        return Err(rejected("Windows path contains NUL"));
    }
    text.push(0);
    Ok(text)
}

fn sid_text(sid: Handle) -> Result<String, IpcError> {
    let mut text = std::ptr::null_mut();
    // SAFETY: input SID comes from Windows-owned token/security-descriptor data.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 || text.is_null() {
        return Err(io::Error::last_os_error().into());
    }
    let owned = OwnedLocal(text.cast());
    // SAFETY: Windows returned a terminated SID string. The bounded scan avoids
    // an unbounded walk if an unexpected extension result violates that contract.
    let length = (0..256)
        .find(|index| unsafe { *text.add(*index) == 0 })
        .ok_or_else(|| rejected("Windows SID string exceeds bound"))?;
    // SAFETY: the terminated Windows allocation contains these scanned units.
    let result = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
        .map_err(|_| rejected("Windows SID string is not UTF-16"))?;
    drop(owned);
    Ok(result)
}

fn process_sid(process: Handle) -> Result<String, IpcError> {
    let mut token = std::ptr::null_mut();
    // SAFETY: process is a live Windows process handle and output is writable.
    if unsafe { OpenProcessToken(process, 0x0008, &mut token) } == 0 || token.is_null() {
        return Err(io::Error::last_os_error().into());
    }
    let token = OwnedHandle(token);
    let mut required = 0;
    // SAFETY: zero-size probing is the documented GetTokenInformation pattern.
    unsafe {
        GetTokenInformation(token.0, 1, std::ptr::null_mut(), 0, &mut required);
    }
    if required == 0 || required > 65536 {
        return Err(rejected("Windows token SID size is invalid"));
    }
    let mut bytes = vec![0_u8; required as usize];
    // SAFETY: buffer is allocated for exactly the probed byte count.
    if unsafe {
        GetTokenInformation(
            token.0,
            1,
            bytes.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    if bytes.len() < std::mem::size_of::<TokenUser>() {
        return Err(rejected("Windows TOKEN_USER header is truncated"));
    }
    // SAFETY: extension API filled this byte buffer; copying unaligned avoids a
    // reference with an alignment stronger than Vec<u8> guarantees.
    let user = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<TokenUser>()) };
    sid_text(user.user.sid)
}

fn current_sid() -> Result<String, IpcError> {
    // SAFETY: GetCurrentProcess returns a valid pseudo handle, not owned here.
    process_sid(unsafe { GetCurrentProcess() })
}

fn sid_for_pid(pid: u32) -> Result<String, IpcError> {
    // SAFETY: this only opens a query handle for the OS-reported pipe peer PID.
    let process = unsafe { OpenProcess(0x1000, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error().into());
    }
    let process = OwnedHandle(process);
    process_sid(process.0)
}

pub(super) fn current_principal() -> Result<LocalPrincipal, IpcError> {
    Ok(LocalPrincipal::WindowsSid(current_sid()?))
}

fn user_security(sid: &str) -> Result<OwnedLocal, IpcError> {
    let sddl = format!("O:{sid}D:P(A;;GA;;;{sid})\0")
        .encode_utf16()
        .collect::<Vec<_>>();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: SDDL is terminated and output pointer is valid for this call.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
        || descriptor.is_null()
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(OwnedLocal(descriptor))
}

fn attributes(descriptor: &OwnedLocal) -> SecurityAttributes {
    SecurityAttributes {
        length: std::mem::size_of::<SecurityAttributes>() as u32,
        descriptor: descriptor.0,
        inherit: 0,
    }
}

enum DirectoryPolicy {
    CurrentUserOnly,
    UserProfileParent,
}

fn validate_acl(path: &Path, policy: DirectoryPolicy) -> Result<(), IpcError> {
    let expected = current_sid()?;
    let name = wide(path)?;
    let mut owner = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: output pointers are writable and Windows allocates descriptor.
    let error = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            1,
            0x0001 | 0x0004,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error as i32).into());
    }
    let descriptor = OwnedLocal(descriptor);
    if owner.is_null() || dacl.is_null() || !sid_text(owner)?.eq_ignore_ascii_case(&expected) {
        return Err(rejected(
            "Windows private IPC object owner or DACL is invalid",
        ));
    }
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: descriptor remains allocated by OwnedLocal throughout inspection.
    if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    if matches!(policy, DirectoryPolicy::CurrentUserOnly) && control & 0x1000 == 0 {
        return Err(rejected("Windows private IPC DACL is not protected"));
    }
    let mut information = AclSizeInformation {
        count: 0,
        used: 0,
        free: 0,
    };
    // SAFETY: dacl is Windows-validated security descriptor data; output fits.
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut information as *mut AclSizeInformation).cast(),
            std::mem::size_of::<AclSizeInformation>() as u32,
            2,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    if information.count == 0 || information.count > 32 {
        return Err(rejected(
            "Windows private IPC ACL has unexpected cardinality",
        ));
    }
    let mut user_full = false;
    for index in 0..information.count {
        let mut ace = std::ptr::null_mut();
        // SAFETY: index is bounded by the ACL information returned by Windows.
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: GetAce returned a live ACE within the retained extension ACL.
        let header = unsafe { std::ptr::read_unaligned(ace.cast::<AceHeader>()) };
        if header.kind != 0 || header.size < 16 {
            return Err(rejected(
                "Windows private IPC ACL contains an unexpected ACE",
            ));
        }
        // SAFETY: the checked allowed-ACE layout includes mask and SID offsets.
        let mask = unsafe { std::ptr::read_unaligned(ace.cast::<u8>().add(4).cast::<u32>()) };
        // SAFETY: allowed ACEs place their validated SID after header and mask.
        let sid = sid_text(unsafe { ace.cast::<u8>().add(8).cast() })?;
        if sid.eq_ignore_ascii_case(&expected) {
            user_full |= mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS || mask & 0x1000_0000 != 0;
        } else if matches!(policy, DirectoryPolicy::UserProfileParent)
            && matches!(sid.as_str(), "S-1-5-18" | "S-1-5-32-544")
        {
        } else {
            return Err(rejected("Windows private IPC ACL grants another principal"));
        }
        if matches!(policy, DirectoryPolicy::CurrentUserOnly) && header.flags & 0x10 != 0 {
            return Err(rejected("Windows private IPC ACL inherited an ACE"));
        }
    }
    if !user_full {
        return Err(rejected(
            "Windows private IPC ACL lacks current-user full control",
        ));
    }
    Ok(())
}

fn no_reparse_components(path: &Path) -> Result<(), IpcError> {
    if !path.is_absolute() {
        return Err(rejected("Windows private IPC path is not absolute"));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        if matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        ) {
            return Err(rejected("Windows private IPC path is not normalized"));
        }
        current.push(component.as_os_str());
        if current.as_os_str().is_empty() || matches!(component, std::path::Component::Prefix(_)) {
            continue;
        }
        if fs::symlink_metadata(&current)?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(rejected(
                "Windows private IPC path traverses a reparse point",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_directory(path: &Path) -> Result<(), IpcError> {
    no_reparse_components(path)?;
    if !fs::symlink_metadata(path)?.is_dir() {
        return Err(rejected("Windows private IPC directory is not a directory"));
    }
    validate_acl(path, DirectoryPolicy::CurrentUserOnly)
}

pub(super) fn ensure_directory(path: &Path) -> Result<(), IpcError> {
    let parent = path
        .parent()
        .ok_or_else(|| rejected("Windows private IPC directory has no parent"))?;
    no_reparse_components(parent)?;
    validate_acl(parent, DirectoryPolicy::UserProfileParent)?;
    let security = user_security(&current_sid()?)?;
    let attributes = attributes(&security);
    let name = wide(path)?;
    // SAFETY: path and security attributes stay alive through this synchronous call.
    if unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(183) {
            return Err(error.into());
        }
    }
    validate_directory(path)
}

pub(super) fn validate_installation_parent(path: &Path) -> Result<(), IpcError> {
    no_reparse_components(path)?;
    if !fs::symlink_metadata(path)?.is_dir() {
        return Err(rejected("Windows installation parent is not a directory"));
    }
    validate_acl(path, DirectoryPolicy::UserProfileParent)
}

pub(super) fn ensure_installation_directory(path: &Path) -> Result<(), IpcError> {
    ensure_directory(path)
}

pub(super) fn create_installation_file(path: &Path) -> Result<File, IpcError> {
    validate_installation_parent(
        path.parent()
            .ok_or_else(|| rejected("Windows installation file lacks parent"))?,
    )?;
    let security = user_security(&current_sid()?)?;
    let attributes = attributes(&security);
    let name = wide(path)?;
    // SAFETY: CREATE_NEW refuses replacement and security remains allocated.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            0x4000_0000,
            0,
            &attributes,
            1,
            0x80 | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: successful CREATE_NEW transfers one owned file handle here.
    Ok(unsafe { File::from_raw_handle(handle.cast()) })
}

pub(super) fn runtime_directory() -> Result<PathBuf, IpcError> {
    let base = std::env::var_os("LOCALAPPDATA")
        .ok_or_else(|| rejected("LOCALAPPDATA is required for private browser IPC"))?;
    let base = fs::canonicalize(PathBuf::from(base))?;
    no_reparse_components(&base)?;
    validate_acl(&base, DirectoryPolicy::UserProfileParent)?;
    Ok(base.join("MakaBrowserConnectors"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FileIdentity {
    volume: u32,
    index: u64,
}

pub(super) fn file_identity(file: &File) -> Result<FileIdentity, IpcError> {
    let mut information = FileInformation::default();
    // SAFETY: File owns a live handle and information is a writable extension struct.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut information) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    if information.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(rejected("Windows IPC descriptor handle is a reparse point"));
    }
    Ok(FileIdentity {
        volume: information.volume,
        index: ((information.index_high as u64) << 32) | information.index_low as u64,
    })
}

pub(super) fn open_private_file(path: &Path) -> Result<File, IpcError> {
    no_reparse_components(path)?;
    validate_acl(path, DirectoryPolicy::CurrentUserOnly)?;
    let name = wide(path)?;
    // SAFETY: path is terminated. No inheritable handles or write/delete sharing.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            0x8000_0000,
            1,
            std::ptr::null(),
            3,
            FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: successful CreateFileW transfers one owned file handle here.
    let file = unsafe { File::from_raw_handle(handle.cast()) };
    if !file.metadata()?.is_file() {
        return Err(rejected("Windows IPC descriptor is not a regular file"));
    }
    file_identity(&file)?;
    Ok(file)
}

pub(super) fn create_private_file(path: &Path) -> Result<File, IpcError> {
    validate_directory(
        path.parent()
            .ok_or_else(|| rejected("Windows descriptor lacks parent"))?,
    )?;
    let security = user_security(&current_sid()?)?;
    let attributes = attributes(&security);
    let name = wide(path)?;
    // SAFETY: CREATE_NEW refuses replacement, attributes remain valid for call.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            0x4000_0000,
            0,
            &attributes,
            1,
            0x80 | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: successful CREATE_NEW transfers one owned file handle here.
    Ok(unsafe { File::from_raw_handle(handle.cast()) })
}

pub(super) fn path_identity(path: &Path) -> Result<FileIdentity, IpcError> {
    file_identity(&open_private_file(path)?)
}
pub(super) fn remove_owned_file(path: &Path, expected: &FileIdentity) -> Result<(), IpcError> {
    match path_identity(path) {
        Ok(actual) if &actual == expected => fs::remove_file(path).map_err(Into::into),
        Ok(_) => Err(rejected("refusing to remove replaced Windows descriptor")),
        Err(IpcError::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn pipe_name(generation: &str) -> String {
    format!(r"\\.\pipe\org.apache.maka.browser_connector.{generation}")
}
pub(super) fn validate_address(
    _parent: &Path,
    generation: &str,
    address: &EndpointAddress,
) -> Result<(), IpcError> {
    match address {
        EndpointAddress::Windows(name) if name == &pipe_name(generation) => Ok(()),
        _ => Err(rejected(
            "Windows browser pipe differs from exact private generation name",
        )),
    }
}

pub enum LocalStream {
    Client(NamedPipeClient),
    Server(NamedPipeServer),
}
impl AsyncRead for LocalStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Client(pipe) => Pin::new(pipe).poll_read(context, buffer),
            Self::Server(pipe) => Pin::new(pipe).poll_read(context, buffer),
        }
    }
}
impl AsyncWrite for LocalStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Client(pipe) => Pin::new(pipe).poll_write(context, bytes),
            Self::Server(pipe) => Pin::new(pipe).poll_write(context, bytes),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Client(pipe) => Pin::new(pipe).poll_flush(context),
            Self::Server(pipe) => Pin::new(pipe).poll_flush(context),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Client(pipe) => Pin::new(pipe).poll_shutdown(context),
            Self::Server(pipe) => Pin::new(pipe).poll_shutdown(context),
        }
    }
}

pub(super) async fn connect(
    address: &EndpointAddress,
    expected_pid: u32,
) -> Result<LocalStream, IpcError> {
    let EndpointAddress::Windows(name) = address else {
        return Err(rejected("endpoint is not a Windows named pipe"));
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let pipe = loop {
        match ClientOptions::new()
            .security_qos_flags(0x0001_0000)
            .open(name)
        {
            Ok(pipe) => break pipe,
            Err(error)
                if error.raw_os_error() == Some(231) && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(25)).await
            }
            Err(error) => return Err(error.into()),
        }
    };
    let mut pid = 0;
    // SAFETY: pipe owns a live connected client handle; PID output is writable.
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle().cast(), &mut pid) } == 0
        || pid != expected_pid
        || !sid_for_pid(pid)?.eq_ignore_ascii_case(&current_sid()?)
    {
        return Err(rejected(
            "Windows extension host pipe peer differs from descriptor",
        ));
    }
    Ok(LocalStream::Client(pipe))
}

fn create_pipe(name: &str, first: bool) -> Result<NamedPipeServer, IpcError> {
    let security = user_security(&current_sid()?)?;
    let mut attributes = attributes(&security);
    // SAFETY: descriptor remains allocated throughout synchronous pipe creation;
    // pipe bytes are local-only and its DACL names only the current user.
    Ok(unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                name,
                (&mut attributes as *mut SecurityAttributes).cast(),
            )
    }?)
}

pub(super) struct LocalListener {
    name: String,
    pending: Option<NamedPipeServer>,
    sid: String,
}
impl LocalListener {
    pub(super) async fn bind(
        directory: &Path,
        generation: &str,
    ) -> Result<(Self, EndpointAddress), IpcError> {
        validate_directory(directory)?;
        let name = pipe_name(generation);
        let pending = create_pipe(&name, true)?;
        let sid = current_sid()?;
        Ok((
            Self {
                name: name.clone(),
                pending: Some(pending),
                sid,
            },
            EndpointAddress::Windows(name),
        ))
    }

    pub(super) async fn accept(&mut self) -> Result<(LocalStream, CheckedLocalPeer), IpcError> {
        loop {
            // Retain the reserved handle while awaiting: the outer loop can
            // cancel accept to service a completed client or shutdown signal.
            self.pending
                .as_ref()
                .ok_or_else(|| rejected("Windows listener lost its reserved instance"))?
                .connect()
                .await?;
            let server = self
                .pending
                .take()
                .ok_or_else(|| rejected("Windows listener lost its connected instance"))?;
            // Keep a reserved instance open before exposing this connected pipe.
            self.pending = Some(create_pipe(&self.name, false)?);
            let mut pid = 0;
            // SAFETY: server is connected and its handle remains live.
            if unsafe { GetNamedPipeClientProcessId(server.as_raw_handle().cast(), &mut pid) } == 0
                || pid == 0
            {
                drop(server);
                continue;
            }
            let actual = match sid_for_pid(pid) {
                Ok(actual) => actual,
                Err(_) => {
                    drop(server);
                    continue;
                }
            };
            if !actual.eq_ignore_ascii_case(&self.sid) {
                drop(server);
                continue;
            }
            return Ok((
                LocalStream::Server(server),
                CheckedLocalPeer::from_checked_principal(LocalPrincipal::WindowsSid(actual)),
            ));
        }
    }

    pub(super) fn cleanup(self) -> Result<(), IpcError> {
        drop(self);
        Ok(())
    }
}
