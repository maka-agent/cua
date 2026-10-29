// SPDX-License-Identifier: MIT

//! Windows native-port placement observations, never browser identity or a grant.
//!
//! The positive path is limited to observed ordinary, unpackaged processes with
//! no job membership, one DOS-device namespace/session and no AppContainer,
//! token filesystem virtualization or WOW64 view. The staging paths must come
//! from the retained native directory's actual volume-GUID path.
//!
//! QueryInformationJobObject(NULL) queries the immediate job, but its process
//! list also includes child jobs. Membership in that list cannot establish
//! equal innermost jobs/silos. Such job-contained placement remains OPEN rather
//! than being accepted from a shared list or parent PID.
//! Sources: Microsoft QueryInformationJobObject, JOBOBJECT_BASIC_PROCESS_ID_LIST,
//! IsProcessInJob, Nested Jobs, and WDK PsGetJobSilo/PsGetJobServerSilo.
//! The latter defines a silo as a job in the job hierarchy; absence of any job
//! therefore excludes process-level silos. This is a user-mode native-launch
//! inference, not attestation against kernel filesystem filters or silo DDI.
//!
//! This leaf borrows standard handles. It never duplicates, closes or reads a
//! pipe endpoint, and cannot change native-messaging EOF. The containing native
//! owner must bind the opaque value to its existing endpoint/generation.

use std::{
    collections::{HashMap, HashSet},
    ffi::{c_void, CStr, OsString},
    fs::{self, File, OpenOptions},
    io, mem,
    os::windows::{
        ffi::OsStringExt,
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Component, Path, PathBuf},
};

type Handle = *mut c_void;
const INVALID_HANDLE: Handle = -1_isize as Handle;
const QUERY_PROCESS: u32 = 0x1000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const TOKEN_QUERY: u32 = 0x0008;
const STD_INPUT_HANDLE: u32 = (-10_i32) as u32;
const STD_OUTPUT_HANDLE: u32 = (-11_i32) as u32;
const FILE_TYPE_PIPE: u32 = 3;
const PIPE_SERVER_END: u32 = 1;
const PROCESS_SNAPSHOT: u32 = 2;
const WAIT_TIMEOUT: u32 = 258;
const ERROR_NO_MORE_FILES: i32 = 18;
const ERROR_NO_TOKEN: i32 = 1008;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const SHARE_READ_WRITE: u32 = 3;
const VOLUME_NAME_GUID: u32 = 1;
const ERROR_INSUFFICIENT_BUFFER: i32 = 122;
const APPMODEL_ERROR_NO_PACKAGE: i32 = 15700;

#[derive(Debug, thiserror::Error)]
pub(super) enum PlacementError {
    #[error("Windows upload placement cannot observe {operation}: {source}")]
    Unobservable {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("Windows native messaging stdio does not expose the required pipe peers")]
    InvalidStdio,
    #[error("Windows native messaging stdio placement changed")]
    StdioChanged,
    #[error("Windows upload process identity or native-launch ancestry changed")]
    ProcessChanged,
    #[error("Windows native pipe peer is not an observed live launch ancestor")]
    LaunchPeerUnavailable,
    #[error("Windows native host's own filesystem namespace or staging root changed")]
    OwnRootChanged,
    #[error("Windows staging path is not an absolute descendant of the observed volume-GUID temporary root")]
    InvalidStagingPath,
    #[error("Windows upload placement cannot establish equal filesystem views for job-contained processes")]
    JobFilesystemViewUnobservable,
    #[error("Windows native host, worker and pipe peer do not share the observed DOS-device namespace/session")]
    DifferentDosNamespace,
    #[error("Windows native-launch filesystem placement does not support an observed AppContainer or virtualized token view")]
    VirtualizedFilesystemView,
    #[error("Windows native-launch filesystem placement does not establish an observed packaged process view")]
    PackagedFilesystemView,
    #[error("Windows native-launch filesystem placement does not establish an observed WOW64 filesystem view")]
    Wow64FilesystemViewUnobservable,
}

fn observe(operation: &'static str) -> PlacementError {
    PlacementError::Unobservable {
        operation,
        source: io::Error::last_os_error(),
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct FileTime {
    low: u32,
    high: u32,
}
impl FileTime {
    fn ticks(self) -> u64 {
        u64::from(self.low) | (u64::from(self.high) << 32)
    }
}

#[repr(C)]
struct ProcessEntry {
    size: u32,
    usage: u32,
    pid: u32,
    default_heap: usize,
    module: u32,
    threads: u32,
    parent: u32,
    priority: i32,
    flags: u32,
    executable: [u16; 260],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Luid {
    low: u32,
    high: i32,
}

#[repr(C)]
#[derive(Default)]
struct TokenStatistics {
    token: Luid,
    authentication: Luid,
    expires: i64,
    token_type: u32,
    impersonation: u32,
    charged: u32,
    available: u32,
    groups: u32,
    privileges: u32,
    modified: Luid,
}

#[repr(C)]
#[derive(Default)]
struct FileInformation {
    attributes: u32,
    created: FileTime,
    accessed: FileTime,
    written: FileTime,
    volume: u32,
    size_high: u32,
    size_low: u32,
    links: u32,
    index_high: u32,
    index_low: u32,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcessId() -> u32;
    fn GetCurrentThread() -> Handle;
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
    fn GetProcessId(process: Handle) -> u32;
    fn IsProcessInJob(process: Handle, job: Handle, result: *mut i32) -> i32;
    fn GetModuleHandleW(name: *const u16) -> Handle;
    fn GetProcAddress(
        module: Handle,
        name: *const u8,
    ) -> Option<unsafe extern "system" fn() -> isize>;
    fn GetProcessTimes(
        process: Handle,
        created: *mut FileTime,
        exited: *mut FileTime,
        kernel: *mut FileTime,
        user: *mut FileTime,
    ) -> i32;
    fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> Handle;
    fn Process32FirstW(snapshot: Handle, entry: *mut ProcessEntry) -> i32;
    fn Process32NextW(snapshot: Handle, entry: *mut ProcessEntry) -> i32;
    fn GetStdHandle(which: u32) -> Handle;
    fn GetFileType(file: Handle) -> u32;
    fn GetNamedPipeInfo(
        pipe: Handle,
        flags: *mut u32,
        output: *mut u32,
        input: *mut u32,
        maximum_instances: *mut u32,
    ) -> i32;
    fn GetNamedPipeClientProcessId(pipe: Handle, pid: *mut u32) -> i32;
    fn GetNamedPipeServerProcessId(pipe: Handle, pid: *mut u32) -> i32;
    fn GetFileInformationByHandle(file: Handle, information: *mut FileInformation) -> i32;
    fn GetFinalPathNameByHandleW(file: Handle, path: *mut u16, length: u32, flags: u32) -> u32;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    fn OpenThreadToken(thread: Handle, access: u32, open_as_self: i32, token: *mut Handle) -> i32;
    fn GetTokenInformation(
        token: Handle,
        class: u32,
        output: *mut c_void,
        length: u32,
        required: *mut u32,
    ) -> i32;
}

fn owned(handle: Handle, operation: &'static str) -> Result<OwnedHandle, PlacementError> {
    if handle.is_null() || handle == INVALID_HANDLE {
        return Err(observe(operation));
    }
    // SAFETY: each caller transfers one successful newly opened process,
    // snapshot or token handle. Standard/pseudo handles never use this guard.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn parent_snapshot() -> Result<HashMap<u32, u32>, PlacementError> {
    // SAFETY: this read-only snapshot neither opens nor operates any process.
    let snapshot = owned(
        unsafe { CreateToolhelp32Snapshot(PROCESS_SNAPSHOT, 0) },
        "native launch process snapshot",
    )?;
    // SAFETY: PROCESSENTRY32W is a C record of integer/array fields; zero is
    // valid for every field, and dwSize is set before calling the Windows API.
    let mut entry: ProcessEntry = unsafe { mem::zeroed() };
    entry.size = mem::size_of::<ProcessEntry>() as u32;
    let mut parents = HashMap::new();
    // SAFETY: snapshot remains live; entry has the documented size/layout.
    let mut found = unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) };
    loop {
        if found == 0 {
            if io::Error::last_os_error().raw_os_error() == Some(ERROR_NO_MORE_FILES) {
                return Ok(parents);
            }
            return Err(observe("native launch process snapshot entry"));
        }
        parents.insert(entry.pid, entry.parent);
        // SAFETY: same retained snapshot and initialized writable record.
        found = unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) };
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Namespace {
    authentication: Luid,
    session: u32,
    app_container: u32,
    virtualized: u32,
}

fn token_dword(token: &OwnedHandle, class: u32) -> Result<u32, PlacementError> {
    let mut value = 0_u32;
    let mut required = 0;
    // SAFETY: callers select only DWORD token classes. The supplied byte count
    // is exactly the initialized output's size; larger classes fail the API.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            (&mut value as *mut u32).cast(),
            mem::size_of::<u32>() as u32,
            &mut required,
        )
    } == 0
    {
        return Err(observe("process filesystem namespace token"));
    }
    if required as usize != mem::size_of::<u32>() {
        return Err(PlacementError::OwnRootChanged);
    }
    Ok(value)
}
fn token_namespace(token: &OwnedHandle) -> Result<Namespace, PlacementError> {
    let mut statistics = TokenStatistics::default();
    let mut required = 0;
    // SAFETY: TokenStatistics (class 10) has the fixed SDK repr(C) layout above.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            10,
            (&mut statistics as *mut TokenStatistics).cast(),
            mem::size_of::<TokenStatistics>() as u32,
            &mut required,
        )
    } == 0
    {
        return Err(observe("process filesystem namespace statistics"));
    }
    if required as usize != mem::size_of::<TokenStatistics>() {
        return Err(PlacementError::OwnRootChanged);
    }
    Ok(Namespace {
        authentication: statistics.authentication,
        session: token_dword(token, 12)?,
        virtualized: token_dword(token, 24)?,
        app_container: token_dword(token, 29)?,
    })
}
fn namespace(process: &OwnedHandle) -> Result<Namespace, PlacementError> {
    let mut token = std::ptr::null_mut();
    // SAFETY: process is a retained query handle and token output is writable.
    if unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(observe("process filesystem namespace token"));
    }
    token_namespace(&owned(token, "process filesystem namespace token")?)
}
fn worker_namespace(process: &OwnedHandle) -> Result<Namespace, PlacementError> {
    let mut token = std::ptr::null_mut();
    // SAFETY: the current-thread pseudo handle is borrowed; query access only.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } != 0 {
        return token_namespace(&owned(token, "worker effective filesystem token")?);
    }
    if io::Error::last_os_error().raw_os_error() != Some(ERROR_NO_TOKEN) {
        return Err(observe("worker effective filesystem token"));
    }
    namespace(process)
}

struct Process {
    handle: OwnedHandle,
    pid: u32,
    started: FileTime,
    namespace: Namespace,
}
impl Process {
    fn open(pid: u32) -> Result<Self, PlacementError> {
        // SAFETY: query/synchronize access only, no inheritance or process control.
        let handle = owned(
            unsafe { OpenProcess(QUERY_PROCESS | SYNCHRONIZE, 0, pid) },
            "native launch process",
        )?;
        let (actual, started) = Self::identity(&handle)?;
        if actual != pid {
            return Err(PlacementError::ProcessChanged);
        }
        let namespace = namespace(&handle)?;
        Ok(Self {
            handle,
            pid,
            started,
            namespace,
        })
    }
    fn identity(handle: &OwnedHandle) -> Result<(u32, FileTime), PlacementError> {
        // SAFETY: zero timeout is a non-mutating liveness query on this process.
        if unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) } != WAIT_TIMEOUT {
            return Err(PlacementError::ProcessChanged);
        }
        let (mut created, mut exited, mut kernel, mut user) = (
            FileTime::default(),
            FileTime::default(),
            FileTime::default(),
            FileTime::default(),
        );
        // SAFETY: process and all four fixed-size outputs remain valid.
        if unsafe {
            GetProcessTimes(
                handle.as_raw_handle(),
                &mut created,
                &mut exited,
                &mut kernel,
                &mut user,
            )
        } == 0
        {
            return Err(observe("process start identity"));
        }
        // SAFETY: query on the same retained live process object.
        let pid = unsafe { GetProcessId(handle.as_raw_handle()) };
        if pid == 0 {
            return Err(observe("process identifier"));
        }
        Ok((pid, created))
    }
    fn revalidate(&self) -> Result<(), PlacementError> {
        if Self::identity(&self.handle)? != (self.pid, self.started)
            || namespace(&self.handle)? != self.namespace
        {
            return Err(PlacementError::ProcessChanged);
        }
        Ok(())
    }
}

type KernelFunction = unsafe extern "system" fn() -> isize;
fn kernel_api(name: &CStr, operation: &'static str) -> Result<KernelFunction, PlacementError> {
    let kernel32 = "kernel32.dll\0".encode_utf16().collect::<Vec<_>>();
    // SAFETY: kernel32 is already loaded. This returns a borrowed module handle.
    let module = unsafe { GetModuleHandleW(kernel32.as_ptr()) };
    if module.is_null() {
        return Err(observe(operation));
    }
    // SAFETY: both callers supply a documented constant, terminated export name.
    unsafe { GetProcAddress(module, name.as_ptr().cast()) }.ok_or_else(|| observe(operation))
}

fn require_ordinary_process(process: &Process) -> Result<(), PlacementError> {
    let mut in_job = 0;
    // SAFETY: a retained live process query handle; NULL explicitly queries
    // membership under ANY job, including a nested job hierarchy.
    if unsafe {
        IsProcessInJob(
            process.handle.as_raw_handle(),
            std::ptr::null_mut(),
            &mut in_job,
        )
    } == 0
    {
        return Err(observe("native launch job membership"));
    }
    if in_job != 0 {
        return Err(PlacementError::JobFilesystemViewUnobservable);
    }

    // The older IsWow64Process is ambiguous on ARM64. Resolve its documented
    // replacement dynamically so absence refuses this feature, not host load.
    type Wow64Query = unsafe extern "system" fn(Handle, *mut u16, *mut u16) -> i32;
    // SAFETY: this constant OS export has exactly the documented Wow64Query ABI.
    let wow64: Wow64Query = unsafe {
        mem::transmute(kernel_api(
            c"IsWow64Process2",
            "native launch WOW64 observation API",
        )?)
    };
    let (mut process_machine, mut native_machine) = (0_u16, 0_u16);
    // SAFETY: metadata query on that same retained process and writable outputs.
    if unsafe {
        wow64(
            process.handle.as_raw_handle(),
            &mut process_machine,
            &mut native_machine,
        )
    } == 0
    {
        return Err(observe("native launch WOW64 filesystem view"));
    }
    if process_machine != 0 || native_machine == 0 {
        return Err(PlacementError::Wow64FilesystemViewUnobservable);
    }

    type PackageQuery = unsafe extern "system" fn(Handle, *mut u32, *mut u16) -> i32;
    // SAFETY: this constant OS export has exactly the documented PackageQuery ABI.
    let package: PackageQuery = unsafe {
        mem::transmute(kernel_api(
            c"GetPackageFullName",
            "native launch package observation API",
        )?)
    };
    let mut length = 0;
    // SAFETY: size query only; Windows returns its status directly, not via
    // GetLastError. No package name or executable name is used as authority.
    let status = unsafe {
        package(
            process.handle.as_raw_handle(),
            &mut length,
            std::ptr::null_mut(),
        )
    };
    match status {
        APPMODEL_ERROR_NO_PACKAGE => Ok(()),
        0 | ERROR_INSUFFICIENT_BUFFER => Err(PlacementError::PackagedFilesystemView),
        code => Err(PlacementError::Unobservable {
            operation: "native launch package view",
            source: io::Error::from_raw_os_error(code),
        }),
    }
}

fn require_shared_namespace(
    host: Namespace,
    worker: Namespace,
    peer: Namespace,
) -> Result<(), PlacementError> {
    if host != worker || host.authentication != peer.authentication || host.session != peer.session
    {
        return Err(PlacementError::DifferentDosNamespace);
    }
    if host.app_container != 0
        || peer.app_container != 0
        || host.virtualized != 0
        || peer.virtualized != 0
    {
        return Err(PlacementError::VirtualizedFilesystemView);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Pipe {
    // Borrowed metadata only. Do not duplicate/close these standard handles:
    // keeping another endpoint reference would alter native-port EOF.
    raw: usize,
    server_end: bool,
    peer: u32,
}
impl Pipe {
    fn capture(which: u32) -> Result<Self, PlacementError> {
        // SAFETY: GetStdHandle returns a borrowed process standard handle.
        let pipe = unsafe { GetStdHandle(which) };
        if pipe.is_null()
            || pipe == INVALID_HANDLE
            || unsafe { GetFileType(pipe) } != FILE_TYPE_PIPE
        {
            return Err(PlacementError::InvalidStdio);
        }
        let mut flags = 0;
        // SAFETY: metadata query only. GetNamedPipeInfo explicitly documents
        // anonymous CreatePipe handles; access failure refuses placement.
        if unsafe {
            GetNamedPipeInfo(
                pipe,
                &mut flags,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(observe("native stdio pipe endpoint"));
        }
        let server_end = flags & PIPE_SERVER_END != 0;
        let mut peer = 0;
        // SAFETY: query the opposite endpoint's OS PID, never a caller field.
        // Unlike GetNamedPipeInfo, peer-PID APIs do not promise every anonymous
        // pipe case. A failed query is a concrete pre-admission refusal.
        let observed = unsafe {
            if server_end {
                GetNamedPipeClientProcessId(pipe, &mut peer)
            } else {
                GetNamedPipeServerProcessId(pipe, &mut peer)
            }
        };
        if observed == 0 {
            return Err(observe("native stdio pipe peer"));
        }
        if peer == 0 {
            return Err(PlacementError::InvalidStdio);
        }
        Ok(Self {
            raw: pipe as usize,
            server_end,
            peer,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RootIdentity {
    volume: u32,
    index: u64,
}
fn directory_identity(file: &File) -> Result<RootIdentity, PlacementError> {
    let mut information = FileInformation::default();
    // SAFETY: this is a real directory handle, never a pipe. Windows explicitly
    // excludes pipe handles from GetFileInformationByHandle's file-ID contract.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(observe("native temporary root object"));
    }
    if information.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || information.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(PlacementError::OwnRootChanged);
    }
    Ok(RootIdentity {
        volume: information.volume,
        index: u64::from(information.index_low) | (u64::from(information.index_high) << 32),
    })
}
fn open_directory(path: &Path) -> Result<File, PlacementError> {
    OpenOptions::new()
        .read(true)
        .share_mode(SHARE_READ_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|source| PlacementError::Unobservable {
            operation: "native temporary root",
            source,
        })
}
fn volume_path(file: &File) -> Result<PathBuf, PlacementError> {
    // SAFETY: real retained directory handle, zero-size documented probe.
    let required = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            VOLUME_NAME_GUID,
        )
    };
    if required == 0 {
        return Err(observe("native temporary volume-GUID path"));
    }
    let mut path = vec![0_u16; required as usize];
    // SAFETY: buffer is allocated for the exact API-probed size.
    let written = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            path.as_mut_ptr(),
            required,
            VOLUME_NAME_GUID,
        )
    };
    if written == 0 {
        return Err(observe("native temporary volume-GUID path"));
    }
    if written >= required {
        return Err(PlacementError::OwnRootChanged);
    }
    path.truncate(written as usize);
    let path = PathBuf::from(OsString::from_wide(&path));
    if !path.is_absolute() {
        return Err(PlacementError::OwnRootChanged);
    }
    Ok(path)
}
struct Root {
    directory: File,
    path: PathBuf,
    identity: RootIdentity,
}
impl Root {
    fn capture() -> Result<Self, PlacementError> {
        let temporary = std::env::temp_dir();
        if !temporary.is_absolute() {
            return Err(PlacementError::InvalidStagingPath);
        }
        let canonical =
            fs::canonicalize(temporary).map_err(|source| PlacementError::Unobservable {
                operation: "native temporary root",
                source,
            })?;
        let directory = open_directory(&canonical)?;
        let identity = directory_identity(&directory)?;
        let path = volume_path(&directory)?;
        let value = Self {
            directory,
            path,
            identity,
        };
        value.revalidate()?;
        Ok(value)
    }
    fn revalidate(&self) -> Result<(), PlacementError> {
        if directory_identity(&self.directory)? != self.identity
            || volume_path(&self.directory)? != self.path
            || directory_identity(&open_directory(&self.path)?)? != self.identity
        {
            return Err(PlacementError::OwnRootChanged);
        }
        Ok(())
    }
}

/// Owned only by the already selected native-host endpoint/generation.
/// This captures OS placement facts; it is not a Chrome/extension signature.
pub(super) struct Placement {
    host: Process,
    ancestry: Vec<Process>,
    stdin: Pipe,
    stdout: Pipe,
    root: Root,
    worker_namespace: Namespace,
}
impl Placement {
    pub(super) fn capture_native_launch() -> Result<Self, PlacementError> {
        // SAFETY: this process's OS PID is not a model/IPC/argv value.
        let pid = unsafe { GetCurrentProcessId() };
        let host = Process::open(pid)?;
        let worker_namespace = worker_namespace(&host.handle)?;
        let stdin = Pipe::capture(STD_INPUT_HANDLE)?;
        let stdout = Pipe::capture(STD_OUTPUT_HANDLE)?;
        if stdin.peer != stdout.peer || stdin.peer == pid || stdin.raw == stdout.raw {
            return Err(PlacementError::InvalidStdio);
        }
        let parents = parent_snapshot()?;
        let mut ancestry = Vec::new();
        let mut seen = HashSet::from([pid]);
        let mut current = pid;
        let mut child_started = host.started;
        loop {
            current = *parents
                .get(&current)
                .ok_or(PlacementError::LaunchPeerUnavailable)?;
            if current == 0 || !seen.insert(current) {
                return Err(PlacementError::LaunchPeerUnavailable);
            }
            let parent = Process::open(current)?;
            if parent.started.ticks() > child_started.ticks() {
                return Err(PlacementError::LaunchPeerUnavailable);
            }
            child_started = parent.started;
            ancestry.push(parent);
            if current == stdin.peer {
                break;
            }
        }
        let root = Root::capture()?;
        let placement = Self {
            host,
            ancestry,
            stdin,
            stdout,
            root,
            worker_namespace,
        };
        placement.revalidate()?;
        Ok(placement)
    }

    pub(super) fn revalidate(&self) -> Result<(), PlacementError> {
        self.revalidate_owned_cleanup()?;
        if Pipe::capture(STD_INPUT_HANDLE)? != self.stdin
            || Pipe::capture(STD_OUTPUT_HANDLE)? != self.stdout
        {
            return Err(PlacementError::StdioChanged);
        }
        let parents = parent_snapshot()?;
        let mut child = self.host.pid;
        for ancestor in &self.ancestry {
            ancestor.revalidate()?;
            if parents.get(&child) != Some(&ancestor.pid) {
                return Err(PlacementError::ProcessChanged);
            }
            child = ancestor.pid;
        }
        if child != self.stdin.peer {
            return Err(PlacementError::LaunchPeerUnavailable);
        }
        let peer = self
            .ancestry
            .last()
            .ok_or(PlacementError::LaunchPeerUnavailable)?;
        require_shared_namespace(self.host.namespace, self.worker_namespace, peer.namespace)?;
        require_ordinary_process(&self.host)?;
        require_ordinary_process(peer)?;
        // The kept actual temp directory and GUID path were revalidated above.
        // The stager must derive every exposed file path from its corresponding
        // actual kept directory's GUID path; drive-canonical paths do not pass
        // revalidate_staging_path and cannot be presented as this positive path.
        Ok(())
    }

    pub(super) fn revalidate_staging_path(&self, path: &Path) -> Result<(), PlacementError> {
        if !path.is_absolute() {
            return Err(PlacementError::InvalidStagingPath);
        }
        let relative = path
            .strip_prefix(&self.root.path)
            .map_err(|_| PlacementError::InvalidStagingPath)?;
        if relative.as_os_str().is_empty()
            || !relative
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
        {
            return Err(PlacementError::InvalidStagingPath);
        }
        self.revalidate()
    }

    /// This is only a namespace prerequisite for unlinking a stage already
    /// owned by this host. The stager must separately match its kept directory
    /// identity and the exact owned children before deleting anything.
    pub(super) fn revalidate_owned_cleanup(&self) -> Result<(), PlacementError> {
        // Browser/ancestor process and native pipes may already be dead. Cleanup
        // observes only this original host and the retained original root.
        if unsafe { GetCurrentProcessId() } != self.host.pid {
            return Err(PlacementError::OwnRootChanged);
        }
        self.host.revalidate()?;
        if worker_namespace(&self.host.handle)? != self.worker_namespace {
            return Err(PlacementError::OwnRootChanged);
        }
        self.root.revalidate()
    }
}
