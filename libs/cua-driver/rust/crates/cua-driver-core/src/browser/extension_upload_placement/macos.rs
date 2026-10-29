// SPDX-License-Identifier: MIT

//! Native-port placement observations from Darwin libproc, not browser identity.

use std::{
    ffi::OsString,
    fs::File,
    io,
    mem::{self, MaybeUninit},
    os::{fd::AsRawFd, unix::ffi::OsStringExt},
    path::{Path, PathBuf},
};

const BSD_WITH_UNIQUE: i32 = 18;
const PIPE_INFO: i32 = 6;
const FREAD: u32 = 1;
const FWRITE: u32 = 2;
const VDIR: i32 = 2;

#[derive(Debug, thiserror::Error)]
pub(super) enum PlacementError {
    #[error("cannot observe macOS native placement {operation}: {source}")]
    Observation {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("macOS native placement {operation} returned {actual} bytes, expected {expected}")]
    Incomplete {
        operation: &'static str,
        actual: i32,
        expected: usize,
    },
    #[error("macOS native placement returned invalid process data")]
    InvalidProcess,
    #[error("macOS native placement process exited or changed")]
    ProcessChanged,
    #[error("macOS native placement ancestry changed")]
    AncestryChanged,
    #[error("macOS native port standard descriptors are not the required pipe ends")]
    InvalidStdio,
    #[error("macOS native port pipe endpoints changed")]
    StdioChanged,
    #[error("no observed ancestor owns the opposite macOS native pipe endpoints")]
    LaunchPeerUnavailable,
    #[error("macOS process descriptor list is invalid or exceeds its API size")]
    InvalidDescriptorList,
    #[error("macOS native placement root vnode observation is invalid")]
    InvalidRoot,
    #[error("the macOS system-root vnode cannot be materialized in this chroot view")]
    SystemRootUnobservable,
    #[error("macOS native placement filesystem root changed or differs")]
    DifferentRoot,
    #[error("upload staging path must be absolute")]
    RelativeStagingPath,
}

// Source-backed C ABI extensions not yet bound by this workspace's libc.
// These are data declarations only; no Apple implementation is copied.
#[repr(C)]
struct UniqueInfo {
    executable_uuid: [u8; 16],
    unique: u64,
    _parent_unique: u64,
    version: i32,
    _original_parent_version: i32,
    _reserved: [u64; 2],
}

#[repr(C)]
struct BsdWithUnique {
    bsd: libc::proc_bsdinfo,
    unique: UniqueInfo,
}

#[repr(C)]
struct ProcFileInfo {
    open_flags: u32,
    _status: u32,
    _offset: libc::off_t,
    kind: i32,
    _guard_flags: u32,
}

#[repr(C)]
struct PipeInfo {
    stat: libc::vinfo_stat,
    handle: u64,
    peer: u64,
    _status: i32,
    _reserved: i32,
}

#[repr(C)]
struct PipeFdInfo {
    file: ProcFileInfo,
    pipe: PipeInfo,
}

fn completed(operation: &'static str, actual: i32, expected: usize) -> Result<(), PlacementError> {
    if actual >= 0 && actual as usize == expected {
        return Ok(());
    }
    let source = io::Error::last_os_error();
    if actual <= 0 && source.raw_os_error().is_some_and(|code| code != 0) {
        return Err(PlacementError::Observation { operation, source });
    }
    Err(PlacementError::Incomplete {
        operation,
        actual,
        expected,
    })
}

fn observation(operation: &'static str) -> impl FnOnce(io::Error) -> PlacementError {
    move |source| PlacementError::Observation { operation, source }
}

fn process_info(pid: i32) -> Result<BsdWithUnique, PlacementError> {
    let mut info = MaybeUninit::<BsdWithUnique>::zeroed();
    let size = mem::size_of::<BsdWithUnique>();
    // SAFETY: the source-backed plain C structure matches flavor 18; the full
    // buffer is initialized, remains writable, and its exact filled size is checked.
    let written = unsafe {
        *libc::__error() = 0;
        libc::proc_pidinfo(
            pid,
            BSD_WITH_UNIQUE,
            0,
            info.as_mut_ptr().cast(),
            size as i32,
        )
    };
    completed("process identity ABI", written, size)?;
    // SAFETY: the entire C data object was filled and has no Rust-invalid fields.
    let info = unsafe { info.assume_init() };
    if pid <= 0 || info.bsd.pbi_pid != pid as u32 || info.unique.unique == 0 {
        return Err(PlacementError::InvalidProcess);
    }
    Ok(info)
}

fn root_view(pid: i32) -> Result<RootView, PlacementError> {
    let mut info = MaybeUninit::<libc::proc_vnodepathinfo>::zeroed();
    let size = mem::size_of::<libc::proc_vnodepathinfo>();
    // SAFETY: libc declares the exact plain C result for this flavor.
    let written = unsafe {
        *libc::__error() = 0;
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            info.as_mut_ptr().cast(),
            size as i32,
        )
    };
    completed("process root vnode", written, size)?;
    // SAFETY: exact successful output initialized every field of this C structure.
    let info = unsafe { info.assume_init() };
    let root = &info.pvi_rdir.vip_vi;
    let id = root_from_vnode(root);
    if root.vi_type == 0 && root.vi_stat.vst_mode == 0 && id == RootIdentity::ZERO {
        // XNU leaves rdir zero when fd_rdir is NULL; lookup then uses rootvnode.
        return Ok(RootView::System);
    }
    if root.vi_type != VDIR
        || root.vi_stat.vst_mode as u32 & libc::S_IFMT as u32 != libc::S_IFDIR as u32
    {
        return Err(PlacementError::InvalidRoot);
    }
    Ok(RootView::Explicit(id))
}

fn executable_path(pid: i32) -> Result<PathBuf, PlacementError> {
    let mut bytes = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: this is the OS-published maximum buffer and remains live/writable.
    let written = unsafe {
        *libc::__error() = 0;
        libc::proc_pidpath(pid, bytes.as_mut_ptr().cast(), bytes.len() as u32)
    };
    if written <= 0 {
        completed("executable path", written, 1)?;
    }
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(PlacementError::InvalidProcess)?;
    bytes.truncate(end);
    let path = PathBuf::from(OsString::from_vec(bytes));
    if !path.is_absolute() {
        return Err(PlacementError::InvalidProcess);
    }
    Ok(path)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProcessKey {
    pid: i32,
    unique: u64,
    started_seconds: u64,
    started_microseconds: u64,
}

fn process_key(info: &BsdWithUnique) -> ProcessKey {
    ProcessKey {
        pid: info.bsd.pbi_pid as i32,
        unique: info.unique.unique,
        started_seconds: info.bsd.pbi_start_tvsec,
        started_microseconds: info.bsd.pbi_start_tvusec,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RootIdentity {
    device: u32,
    inode: u64,
    generation: u32,
    filesystem: [u8; 8],
}

impl RootIdentity {
    const ZERO: Self = Self {
        device: 0,
        inode: 0,
        generation: 0,
        filesystem: [0; 8],
    };
}

fn filesystem_id(value: &libc::fsid_t) -> [u8; 8] {
    const _: [(); 8] = [(); mem::size_of::<libc::fsid_t>()];
    let mut result = [0u8; 8];
    // SAFETY: fsid_t is the SDK's initialized two-integer C identifier; copy its
    // bytes rather than relying on libc's private field names.
    unsafe {
        std::ptr::copy_nonoverlapping(
            (value as *const libc::fsid_t).cast(),
            result.as_mut_ptr(),
            result.len(),
        );
    }
    result
}

fn root_from_vnode(info: &libc::vnode_info) -> RootIdentity {
    RootIdentity {
        device: info.vi_stat.vst_dev,
        inode: info.vi_stat.vst_ino,
        generation: info.vi_stat.vst_gen,
        filesystem: filesystem_id(&info.vi_fsid),
    }
}

fn root_from_file(file: &File) -> Result<RootIdentity, PlacementError> {
    // SAFETY: both C buffers are plain output; the owned directory stays open.
    let mut stat: libc::stat = unsafe { mem::zeroed() };
    let mut filesystem: libc::statfs = unsafe { mem::zeroed() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut stat) } != 0 {
        return Err(observation("own root object")(io::Error::last_os_error()));
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(PlacementError::InvalidRoot);
    }
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut filesystem) } != 0 {
        return Err(observation("own root filesystem")(
            io::Error::last_os_error(),
        ));
    }
    Ok(RootIdentity {
        device: stat.st_dev as u32,
        inode: stat.st_ino,
        generation: stat.st_gen,
        filesystem: filesystem_id(&filesystem.f_fsid),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RootView {
    System,
    Explicit(RootIdentity),
}

fn resolve_root(
    view: RootView,
    system: Option<RootIdentity>,
) -> Result<RootIdentity, PlacementError> {
    match view {
        RootView::System => system.ok_or(PlacementError::SystemRootUnobservable),
        RootView::Explicit(root) => Ok(root),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PipeEnd {
    handle: u64,
    peer: u64,
    access: u32,
}

fn pipe_end(pid: i32, fd: i32) -> Result<PipeEnd, PlacementError> {
    let mut info = MaybeUninit::<PipeFdInfo>::zeroed();
    let size = mem::size_of::<PipeFdInfo>();
    // SAFETY: pipe_fdinfo ABI and flavor come from Apple's proc_info.h; the
    // query does not open/duplicate the endpoint or consume any native bytes.
    let written = unsafe {
        *libc::__error() = 0;
        libc::proc_pidfdinfo(pid, fd, PIPE_INFO, info.as_mut_ptr().cast(), size as i32)
    };
    completed("pipe endpoint ABI", written, size)?;
    // SAFETY: exact successful output filled the plain C object.
    let info = unsafe { info.assume_init() };
    if info.file.kind != libc::PROX_FDTYPE_PIPE
        || info.pipe.stat.vst_mode as u32 & libc::S_IFMT as u32 != libc::S_IFIFO as u32
    {
        return Err(PlacementError::InvalidStdio);
    }
    Ok(PipeEnd {
        handle: info.pipe.handle,
        peer: info.pipe.peer,
        access: info.file.open_flags & (FREAD | FWRITE),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stdio {
    input: PipeEnd,
    output: PipeEnd,
}

impl Stdio {
    fn capture(pid: i32) -> Result<Self, PlacementError> {
        let result = Self {
            input: pipe_end(pid, libc::STDIN_FILENO)?,
            output: pipe_end(pid, libc::STDOUT_FILENO)?,
        };
        if result.input.access != FREAD || result.output.access != FWRITE {
            return Err(PlacementError::InvalidStdio);
        }
        Ok(result)
    }
}

fn reciprocal(left: PipeEnd, right: PipeEnd, access: u32) -> bool {
    left.handle == right.peer && left.peer == right.handle && right.access == access
}

fn descriptor_list(pid: i32) -> Result<Vec<libc::proc_fdinfo>, PlacementError> {
    // SAFETY: null buffer asks this documented variable-length API for its size.
    let required = unsafe {
        *libc::__error() = 0;
        libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0)
    };
    if required < 0
        || required == 0
            && io::Error::last_os_error()
                .raw_os_error()
                .is_some_and(|code| code != 0)
    {
        return Err(observation("descriptor list size")(
            io::Error::last_os_error(),
        ));
    }
    let entry = mem::size_of::<libc::proc_fdinfo>();
    let mut count = (required as usize).div_ceil(entry).max(1);
    loop {
        let size = count
            .checked_mul(entry)
            .and_then(|size| i32::try_from(size).ok())
            .ok_or(PlacementError::InvalidDescriptorList)?;
        let mut descriptors = Vec::<libc::proc_fdinfo>::with_capacity(count);
        // SAFETY: capacity covers size bytes; length remains zero until every
        // returned complete C element is initialized and bounds-checked.
        let written = unsafe {
            *libc::__error() = 0;
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                descriptors.as_mut_ptr().cast(),
                size,
            )
        };
        if written < 0
            || written == 0
                && io::Error::last_os_error()
                    .raw_os_error()
                    .is_some_and(|code| code != 0)
        {
            return Err(observation("descriptor list")(io::Error::last_os_error()));
        }
        if written as usize > size as usize || written as usize % entry != 0 {
            return Err(PlacementError::InvalidDescriptorList);
        }
        if written == size {
            count = count
                .checked_mul(2)
                .ok_or(PlacementError::InvalidDescriptorList)?;
            continue;
        }
        // SAFETY: the exact returned prefix consists of initialized proc_fdinfo.
        unsafe {
            descriptors.set_len(written as usize / entry);
        }
        return Ok(descriptors);
    }
}

fn holds_opposite(pid: i32, stdio: Stdio) -> Result<bool, PlacementError> {
    let mut input = false;
    let mut output = false;
    for descriptor in descriptor_list(pid)? {
        if descriptor.proc_fdtype != libc::PROX_FDTYPE_PIPE as u32 {
            continue;
        }
        let end = match pipe_end(pid, descriptor.proc_fd) {
            Ok(end) => end,
            Err(PlacementError::Observation { source, .. })
                if matches!(
                    source.raw_os_error(),
                    Some(libc::EBADF) | Some(libc::ENOENT)
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        input |= reciprocal(stdio.input, end, FWRITE);
        output |= reciprocal(stdio.output, end, FREAD);
        if input && output {
            return Ok(true);
        }
    }
    Ok(false)
}

struct Snapshot {
    key: ProcessKey,
    parent: i32,
    executable_version: i32,
    executable_uuid: [u8; 16],
    executable_path: PathBuf,
    root: RootIdentity,
}

impl Snapshot {
    fn capture(pid: i32, system_root: Option<RootIdentity>) -> Result<Self, PlacementError> {
        let before = process_info(pid)?;
        if before.bsd.pbi_status == libc::SZOMB {
            return Err(PlacementError::ProcessChanged);
        }
        let path = executable_path(pid)?;
        let root = resolve_root(root_view(pid)?, system_root)?;
        let after = process_info(pid)?;
        if process_key(&before) != process_key(&after)
            || before.bsd.pbi_ppid != after.bsd.pbi_ppid
            || before.unique.version != after.unique.version
            || before.unique.executable_uuid != after.unique.executable_uuid
            || after.bsd.pbi_status == libc::SZOMB
        {
            return Err(PlacementError::ProcessChanged);
        }
        Ok(Self {
            key: process_key(&after),
            parent: after.bsd.pbi_ppid as i32,
            executable_version: after.unique.version,
            executable_uuid: after.unique.executable_uuid,
            executable_path: path,
            root,
        })
    }

    fn revalidate(
        &self,
        system: Option<RootIdentity>,
        bound_parent: bool,
    ) -> Result<(), PlacementError> {
        let current = Self::capture(self.key.pid, system)?;
        if bound_parent && self.parent != current.parent {
            return Err(PlacementError::AncestryChanged);
        }
        if self.key != current.key
            || self.executable_version != current.executable_version
            || self.executable_uuid != current.executable_uuid
            || self.executable_path != current.executable_path
        {
            return Err(PlacementError::ProcessChanged);
        }
        if self.root != current.root {
            return Err(PlacementError::DifferentRoot);
        }
        Ok(())
    }
}

/// The parent wrapper binds this only to its real registered native endpoint.
pub(super) struct Placement {
    processes: Vec<Snapshot>,
    stdio: Stdio,
    own_root: RootIdentity,
    system_root: Option<RootIdentity>,
    root_handle: File,
}

impl Placement {
    pub(super) fn capture_native_launch() -> Result<Self, PlacementError> {
        // SAFETY: getpid has no pointer arguments or side effects.
        let pid = unsafe { libc::getpid() };
        let before = process_info(pid)?;
        let view = root_view(pid)?;
        let root_handle = File::open("/").map_err(observation("pin own root"))?;
        let own_root = root_from_file(&root_handle)?;
        let system_root = matches!(view, RootView::System).then_some(own_root);
        if resolve_root(view, system_root)? != own_root {
            return Err(PlacementError::DifferentRoot);
        }
        let own = Snapshot::capture(pid, system_root)?;
        if own.key != process_key(&before) || own.root != own_root || root_view(pid)? != view {
            return Err(PlacementError::ProcessChanged);
        }
        let stdio = Stdio::capture(pid)?;
        let mut processes = vec![own];
        loop {
            let parent = processes.last().expect("captured own host").parent;
            if parent <= 0 {
                return Err(PlacementError::LaunchPeerUnavailable);
            }
            if processes.iter().any(|process| process.key.pid == parent) {
                return Err(PlacementError::AncestryChanged);
            }
            let process = Snapshot::capture(parent, system_root)?;
            let linked = holds_opposite(parent, stdio)?;
            process.revalidate(system_root, !linked)?;
            processes.push(process);
            if linked {
                break;
            }
        }
        let result = Self {
            processes,
            stdio,
            own_root,
            system_root,
            root_handle,
        };
        result.revalidate()?;
        Ok(result)
    }

    fn check_current_own_root(&self) -> Result<(), PlacementError> {
        let current_root = File::open("/").map_err(observation("current worker root"))?;
        if root_from_file(&self.root_handle)? != self.own_root
            || root_from_file(&current_root)? != self.own_root
        {
            return Err(PlacementError::DifferentRoot);
        }
        Ok(())
    }

    pub(super) fn revalidate(&self) -> Result<(), PlacementError> {
        let own = &self.processes[0];
        // SAFETY: getpid only reports the actual current process.
        if own.key.pid != unsafe { libc::getpid() } {
            return Err(PlacementError::ProcessChanged);
        }
        for (index, process) in self.processes.iter().enumerate() {
            process.revalidate(self.system_root, index + 1 < self.processes.len())?;
        }
        if Stdio::capture(own.key.pid)? != self.stdio
            || !holds_opposite(
                self.processes.last().expect("bound launch peer").key.pid,
                self.stdio,
            )?
        {
            return Err(PlacementError::StdioChanged);
        }
        self.processes
            .last()
            .expect("bound launch peer")
            .revalidate(self.system_root, false)?;
        if self.processes.last().expect("bound launch peer").root != self.own_root {
            return Err(PlacementError::DifferentRoot);
        }
        self.check_current_own_root()
    }

    pub(super) fn revalidate_staging_path(&self, path: &Path) -> Result<(), PlacementError> {
        if !path.is_absolute() {
            return Err(PlacementError::RelativeStagingPath);
        }
        self.revalidate()
    }

    pub(super) fn revalidate_owned_cleanup(&self) -> Result<(), PlacementError> {
        let captured = self.processes[0].key;
        // SAFETY: getpid reports this worker's actual process, not a wire value.
        if captured.pid != unsafe { libc::getpid() } {
            return Err(PlacementError::ProcessChanged);
        }
        let before = process_info(captured.pid)?;
        let root = resolve_root(root_view(captured.pid)?, self.system_root)?;
        let after = process_info(captured.pid)?;
        check_owned_cleanup(
            captured,
            process_key(&before),
            process_key(&after),
            self.own_root,
            root,
        )?;
        self.check_current_own_root()
    }
}

fn check_owned_cleanup(
    captured: ProcessKey,
    before: ProcessKey,
    after: ProcessKey,
    own_root: RootIdentity,
    current_root: RootIdentity,
) -> Result<(), PlacementError> {
    if captured != before || captured != after {
        return Err(PlacementError::ProcessChanged);
    }
    if own_root != current_root {
        return Err(PlacementError::DifferentRoot);
    }
    Ok(())
}
