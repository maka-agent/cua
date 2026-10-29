// SPDX-License-Identifier: MIT

//! Native-launch transport ancestry and filesystem placement, never a grant.
//!
//! Capture is restricted to the validated registered native-port entry. The
//! opaque witness is bound to that host's selected endpoint and generation by
//! the host-owned worker. It proves only observed launch topology and filesystem
//! placement, never browser product identity, file authority or page consumption.

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use std::io;
use std::path::Path;

#[cfg(target_os = "macos")]
#[path = "extension_upload_placement/macos.rs"]
mod macos;
#[cfg(windows)]
#[path = "extension_upload_placement/windows.rs"]
mod windows;

#[derive(Debug, thiserror::Error)]
pub(super) enum UploadPlacementError {
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    #[error("upload placement observation is not implemented on this platform")]
    UnsupportedPlatform,
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[error("upload placement cannot observe {operation}: {source}")]
    Unobservable {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[cfg(target_os = "linux")]
    #[error("upload placement requires real procfs")]
    NotProcfs,
    #[cfg(target_os = "linux")]
    #[error("upload process record is malformed")]
    InvalidProcessStat,
    #[cfg(target_os = "linux")]
    #[error("upload process has exited")]
    ProcessExited,
    #[cfg(target_os = "linux")]
    #[error("upload process identity changed")]
    ProcessChanged,
    #[cfg(target_os = "linux")]
    #[error("upload process ancestry changed")]
    ParentChainChanged,
    #[cfg(target_os = "linux")]
    #[error("native messaging standard input/output are not observable pipe endpoints")]
    InvalidStdio,
    #[cfg(target_os = "linux")]
    #[error("native messaging pipe topology changed")]
    NativePipeChanged,
    #[cfg(target_os = "linux")]
    #[error("no observed ancestor holds the opposite native pipe endpoints")]
    NativeLaunchPeerUnavailable,
    #[cfg(target_os = "linux")]
    #[error("process descriptor metadata is malformed")]
    InvalidFdInfo,
    #[cfg(target_os = "linux")]
    #[error("native launch peer and host have different mount namespaces")]
    DifferentMountNamespace,
    #[cfg(target_os = "linux")]
    #[error("native launch peer and host have different filesystem roots")]
    DifferentRoot,
    #[cfg(target_os = "linux")]
    #[error("filesystem root mount identity is unavailable")]
    RootMountIdentityUnavailable,
    #[error("upload staging path must be absolute")]
    RelativeStagingPath,
}

/// Construct only inside the already validated registered native-port entry.
/// This does not authenticate a browser product or confer file access.
pub(super) struct UploadPlacement {
    #[cfg(target_os = "linux")]
    inner: linux::Placement,
    #[cfg(target_os = "macos")]
    inner: macos::Placement,
    #[cfg(windows)]
    inner: windows::Placement,
}

#[cfg(any(target_os = "macos", windows))]
fn platform_error(source: impl std::error::Error + Send + Sync + 'static) -> UploadPlacementError {
    UploadPlacementError::Unobservable {
        operation: "native-launch platform placement",
        source: io::Error::other(source),
    }
}

impl UploadPlacement {
    pub(super) fn capture_native_launch() -> Result<Self, UploadPlacementError> {
        #[cfg(target_os = "linux")]
        {
            linux::Placement::capture_native_launch().map(|inner| Self { inner })
        }
        #[cfg(target_os = "macos")]
        {
            macos::Placement::capture_native_launch()
                .map(|inner| Self { inner })
                .map_err(platform_error)
        }
        #[cfg(windows)]
        {
            windows::Placement::capture_native_launch()
                .map(|inner| Self { inner })
                .map_err(platform_error)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            Err(UploadPlacementError::UnsupportedPlatform)
        }
    }

    pub(super) fn revalidate(&self) -> Result<(), UploadPlacementError> {
        #[cfg(target_os = "linux")]
        {
            self.inner.revalidate()
        }
        #[cfg(any(target_os = "macos", windows))]
        {
            self.inner.revalidate().map_err(platform_error)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            Err(UploadPlacementError::UnsupportedPlatform)
        }
    }

    /// Only for removing stages already owned by this native-host instance.
    /// The stager separately validates its retained directory identity. This
    /// weaker proof must never authorize begin, write or retain operations.
    pub(super) fn revalidate_owned_cleanup(&self) -> Result<(), UploadPlacementError> {
        #[cfg(target_os = "linux")]
        {
            self.inner.revalidate_owned_cleanup()
        }
        #[cfg(any(target_os = "macos", windows))]
        {
            self.inner
                .revalidate_owned_cleanup()
                .map_err(platform_error)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            Err(UploadPlacementError::UnsupportedPlatform)
        }
    }

    pub(super) fn revalidate_staging_path(&self, path: &Path) -> Result<(), UploadPlacementError> {
        if !path.is_absolute() {
            return Err(UploadPlacementError::RelativeStagingPath);
        }
        #[cfg(any(target_os = "macos", windows))]
        {
            self.inner
                .revalidate_staging_path(path)
                .map_err(platform_error)
        }
        #[cfg(not(any(target_os = "macos", windows)))]
        {
            self.revalidate()
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        ffi::{CStr, CString, OsString},
        fs::File,
        io::Read,
        os::{
            fd::{AsRawFd, FromRawFd, IntoRawFd},
            unix::{ffi::OsStringExt, fs::MetadataExt},
        },
        path::PathBuf,
    };

    use super::UploadPlacementError as Error;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct ProcessStat {
        pid: u32,
        parent: u32,
        started: u64,
    }

    fn parse_stat(bytes: &[u8]) -> Result<ProcessStat, Error> {
        let (process, state) = parse_stat_record(bytes)?;
        if matches!(state, b'Z' | b'X' | b'x') {
            return Err(Error::ProcessExited);
        }
        Ok(process)
    }

    fn parse_stat_record(bytes: &[u8]) -> Result<(ProcessStat, u8), Error> {
        let open = bytes
            .iter()
            .position(|byte| *byte == b'(')
            .ok_or(Error::InvalidProcessStat)?;
        let close = bytes
            .iter()
            .rposition(|byte| *byte == b')')
            .ok_or(Error::InvalidProcessStat)?;
        if close <= open {
            return Err(Error::InvalidProcessStat);
        }
        let number = |field: &[u8]| -> Result<u64, Error> {
            std::str::from_utf8(field)
                .ok()
                .and_then(|text| text.parse().ok())
                .ok_or(Error::InvalidProcessStat)
        };
        let pid = number(bytes[..open].trim_ascii())?;
        let fields: Vec<_> = bytes[close + 1..]
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty())
            .collect();
        if fields.len() < 20 || fields[0].len() != 1 {
            return Err(Error::InvalidProcessStat);
        }
        let pid = u32::try_from(pid)
            .ok()
            .filter(|pid| *pid != 0)
            .ok_or(Error::InvalidProcessStat)?;
        let parent = u32::try_from(number(fields[1])?).map_err(|_| Error::InvalidProcessStat)?;
        Ok((
            ProcessStat {
                pid,
                parent,
                started: number(fields[19])?,
            },
            fields[0][0],
        ))
    }

    fn observe_error(operation: &'static str) -> impl FnOnce(std::io::Error) -> Error {
        move |source| Error::Unobservable { operation, source }
    }

    fn open_at(directory: &File, name: &CStr, flags: i32) -> Result<File, Error> {
        // SAFETY: the directory is a retained, validated procfs directory. Magic
        // exe/root/ns links are intentionally followed to their kernel objects.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(observe_error("process object")(
                std::io::Error::last_os_error(),
            ));
        }
        // SAFETY: successful openat returned one newly owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn read_stat(directory: &File) -> Result<ProcessStat, Error> {
        parse_stat(&read_stat_bytes(directory)?)
    }

    fn read_stat_bytes(directory: &File) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new();
        open_at(directory, c"stat", libc::O_RDONLY)?
            .read_to_end(&mut bytes)
            .map_err(observe_error("process stat"))?;
        Ok(bytes)
    }

    fn executable_path(directory: &File) -> Result<PathBuf, Error> {
        let mut bytes = vec![0; 256];
        loop {
            // SAFETY: both pointers are valid for the syscall; readlinkat writes
            // at most bytes.len() bytes and does not add a terminator.
            let count = unsafe {
                libc::readlinkat(
                    directory.as_raw_fd(),
                    c"exe".as_ptr(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                )
            };
            if count < 0 {
                return Err(observe_error("process executable")(
                    std::io::Error::last_os_error(),
                ));
            }
            let count = count as usize;
            if count < bytes.len() {
                bytes.truncate(count);
                return Ok(PathBuf::from(OsString::from_vec(bytes)));
            }
            bytes.resize(bytes.len().checked_mul(2).ok_or(Error::ProcessChanged)?, 0);
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct ObjectIdentity {
        device: u64,
        inode: u64,
    }

    fn object_identity(file: &File) -> Result<ObjectIdentity, Error> {
        let metadata = file.metadata().map_err(observe_error("object identity"))?;
        Ok(ObjectIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct StdioIdentity {
        input: ObjectIdentity,
        output: ObjectIdentity,
    }

    fn host_pipe(fd: i32, access: i32) -> Result<ObjectIdentity, Error> {
        // SAFETY: F_GETFL only observes the existing standard descriptor.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(observe_error("standard pipe flags")(
                std::io::Error::last_os_error(),
            ));
        }
        if flags & libc::O_PATH != 0 || flags & libc::O_ACCMODE != access {
            return Err(Error::InvalidStdio);
        }
        // SAFETY: stat is plain C output and fstat only observes fd.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stat) } != 0 {
            return Err(observe_error("standard pipe identity")(
                std::io::Error::last_os_error(),
            ));
        }
        if stat.st_mode & libc::S_IFMT != libc::S_IFIFO {
            return Err(Error::InvalidStdio);
        }
        Ok(ObjectIdentity {
            device: stat.st_dev,
            inode: stat.st_ino,
        })
    }

    impl StdioIdentity {
        fn capture() -> Result<Self, Error> {
            Ok(Self {
                input: host_pipe(libc::STDIN_FILENO, libc::O_RDONLY)?,
                output: host_pipe(libc::STDOUT_FILENO, libc::O_WRONLY)?,
            })
        }
    }

    fn parse_fd_flags(bytes: &[u8]) -> Result<u64, Error> {
        let mut flags = None;
        for line in bytes.split(|byte| *byte == b'\n') {
            if let Some(value) = line.strip_prefix(b"flags:") {
                if flags.is_some() {
                    return Err(Error::InvalidFdInfo);
                }
                flags = std::str::from_utf8(value.trim_ascii())
                    .ok()
                    .and_then(|value| u64::from_str_radix(value, 8).ok());
                if flags.is_none() {
                    return Err(Error::InvalidFdInfo);
                }
            }
        }
        flags.ok_or(Error::InvalidFdInfo)
    }

    fn descriptor_flags(process: &File, name: &CStr) -> Result<Option<u64>, Error> {
        let mut path = b"fdinfo/".to_vec();
        path.extend_from_slice(name.to_bytes());
        let path = CString::new(path).expect("numeric proc descriptor has no NUL");
        let mut file = match open_at(process, &path, libc::O_RDONLY) {
            Ok(file) => file,
            Err(Error::Unobservable { source, .. })
                if source.raw_os_error() == Some(libc::ENOENT) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(observe_error("ancestor descriptor flags"))?;
        parse_fd_flags(&bytes).map(Some)
    }

    struct DirectoryStream(*mut libc::DIR);
    impl Drop for DirectoryStream {
        fn drop(&mut self) {
            // SAFETY: fdopendir transferred one descriptor to this owned stream.
            unsafe {
                libc::closedir(self.0);
            }
        }
    }

    fn opposite_access(flags: u64, access: i32) -> bool {
        flags & libc::O_PATH as u64 == 0 && flags & libc::O_ACCMODE as u64 == access as u64
    }

    fn holds_opposite_pipes(process: &File, stdio: StdioIdentity) -> Result<bool, Error> {
        let descriptors = open_at(process, c"fd", libc::O_RDONLY | libc::O_DIRECTORY)?;
        let fd = descriptors.into_raw_fd();
        // SAFETY: fdopendir takes ownership only on success. This is a directory
        // descriptor, never a duplicated native pipe endpoint.
        let pointer = unsafe { libc::fdopendir(fd) };
        if pointer.is_null() {
            let error = std::io::Error::last_os_error();
            // SAFETY: fdopendir failed, so fd is still owned here.
            drop(unsafe { File::from_raw_fd(fd) });
            return Err(observe_error("ancestor descriptor directory")(error));
        }
        let stream = DirectoryStream(pointer);
        // SAFETY: stream is live; the returned descriptor is borrowed only for
        // offset-independent fstatat observations while DIR keeps ownership.
        let directory = unsafe { libc::dirfd(stream.0) };
        if directory < 0 {
            return Err(observe_error("ancestor descriptor directory")(
                std::io::Error::last_os_error(),
            ));
        }
        let mut input = false;
        let mut output = false;
        loop {
            // SAFETY: errno is thread-local and stream is uniquely owned here.
            unsafe {
                *libc::__errno_location() = 0;
            }
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(0) {
                    return Err(observe_error("ancestor descriptor enumeration")(error));
                }
                return Ok(false);
            }
            // SAFETY: readdir returned a live entry with a NUL-terminated name;
            // copy it before another readdir can overwrite the entry.
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
                continue;
            }
            let name = CString::new(bytes).expect("numeric proc descriptor has no NUL");
            let Some(pipe) = pipe_at(directory, &name)? else {
                continue;
            };
            if pipe != stdio.input && pipe != stdio.output {
                continue;
            }
            let Some(flags) = descriptor_flags(process, &name)? else {
                continue;
            };
            if pipe_at(directory, &name)? != Some(pipe) {
                continue;
            }
            input |= pipe == stdio.input && opposite_access(flags, libc::O_WRONLY);
            output |= pipe == stdio.output && opposite_access(flags, libc::O_RDONLY);
            if input && output {
                return Ok(true);
            }
        }
    }

    fn pipe_at(directory: i32, name: &CStr) -> Result<Option<ObjectIdentity>, Error> {
        // SAFETY: descriptor remains held by DirectoryStream; this only stats
        // the kernel procfd link and cannot retain a native pipe endpoint.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatat(directory, name.as_ptr(), &mut stat, 0) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err(observe_error("ancestor pipe identity")(error));
        }
        Ok(
            (stat.st_mode & libc::S_IFMT == libc::S_IFIFO).then_some(ObjectIdentity {
                device: stat.st_dev,
                inode: stat.st_ino,
            }),
        )
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct RootIdentity {
        object: ObjectIdentity,
        mount: u64,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct FilesystemScope {
        namespace: ObjectIdentity,
        root: RootIdentity,
    }

    fn root_identity(file: &File) -> Result<RootIdentity, Error> {
        // SAFETY: statx is a plain C output structure; the initialized buffer and
        // empty pathname remain valid throughout this descriptor-only query.
        let mut stat: libc::statx = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::statx(
                file.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH,
                libc::STATX_INO | libc::STATX_MNT_ID,
                &mut stat,
            )
        };
        if result != 0 {
            return Err(observe_error("root mount identity")(
                std::io::Error::last_os_error(),
            ));
        }
        if stat.stx_mask & libc::STATX_MNT_ID == 0 {
            return Err(Error::RootMountIdentityUnavailable);
        }
        Ok(RootIdentity {
            object: object_identity(file)?,
            mount: stat.stx_mnt_id,
        })
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Identity {
        process: ProcessStat,
        executable: ObjectIdentity,
        executable_path: PathBuf,
        namespace: ObjectIdentity,
        root: RootIdentity,
    }

    struct Snapshot {
        identity: Identity,
        _executable: File,
        _namespace: File,
        _root: File,
    }

    impl Snapshot {
        fn read(directory: &File, pid: u32) -> Result<Self, Error> {
            let before = read_stat(directory)?;
            if before.pid != pid {
                return Err(Error::ProcessChanged);
            }
            let executable = open_at(directory, c"exe", libc::O_PATH)?;
            let namespace = open_at(directory, c"ns/mnt", libc::O_RDONLY)?;
            let root = open_at(directory, c"root", libc::O_PATH | libc::O_DIRECTORY)?;
            let identity = Identity {
                process: before,
                executable: object_identity(&executable)?,
                executable_path: executable_path(directory)?,
                namespace: object_identity(&namespace)?,
                root: root_identity(&root)?,
            };
            if read_stat(directory)? != before {
                return Err(Error::ProcessChanged);
            }
            Ok(Self {
                identity,
                _executable: executable,
                _namespace: namespace,
                _root: root,
            })
        }
    }

    struct Process {
        directory: File,
        snapshot: Snapshot,
    }

    fn validate_procfs(directory: &File) -> Result<(), Error> {
        // SAFETY: statfs is plain C output and directory remains open.
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(directory.as_raw_fd(), &mut filesystem) } != 0 {
            return Err(observe_error("procfs identity")(
                std::io::Error::last_os_error(),
            ));
        }
        if filesystem.f_type != libc::PROC_SUPER_MAGIC {
            return Err(Error::NotProcfs);
        }
        Ok(())
    }

    fn cleanup_thread_scope() -> Result<FilesystemScope, Error> {
        let directory =
            File::open("/proc/thread-self").map_err(observe_error("current cleanup thread"))?;
        validate_procfs(&directory)?;
        let before = read_stat(&directory)?;
        let namespace = open_at(&directory, c"ns/mnt", libc::O_RDONLY)?;
        let root = open_at(&directory, c"root", libc::O_PATH | libc::O_DIRECTORY)?;
        let scope = FilesystemScope {
            namespace: object_identity(&namespace)?,
            root: root_identity(&root)?,
        };
        let after = read_stat(&directory)?;
        if (before.pid, before.started) != (after.pid, after.started) {
            return Err(Error::ProcessChanged);
        }
        Ok(scope)
    }

    impl Process {
        fn capture(pid: u32) -> Result<Self, Error> {
            let directory =
                File::open(format!("/proc/{pid}")).map_err(observe_error("process directory"))?;
            Self::from_directory(directory, Some(pid))
        }

        fn current_host() -> Result<Self, Error> {
            let directory = File::open("/proc/self").map_err(observe_error("current host"))?;
            Self::from_directory(directory, Some(std::process::id()))
        }

        fn current_thread() -> Result<Self, Error> {
            let directory = File::open("/proc/thread-self")
                .map_err(observe_error("current execution thread"))?;
            Self::from_directory(directory, None)
        }

        fn from_directory(directory: File, expected_pid: Option<u32>) -> Result<Self, Error> {
            validate_procfs(&directory)?;
            let pid =
                expected_pid.map_or_else(|| read_stat(&directory).map(|stat| stat.pid), Ok)?;
            let snapshot = Snapshot::read(&directory, pid)?;
            Ok(Self {
                directory,
                snapshot,
            })
        }

        fn revalidate(&self, has_bound_parent: bool) -> Result<(), Error> {
            let current = Snapshot::read(&self.directory, self.snapshot.identity.process.pid)?;
            check_same_process(&self.snapshot.identity, &current.identity, has_bound_parent)
        }
    }

    fn check_same_process(
        expected: &Identity,
        current: &Identity,
        has_bound_parent: bool,
    ) -> Result<(), Error> {
        if has_bound_parent && expected.process.parent != current.process.parent {
            return Err(Error::ParentChainChanged);
        }
        if expected.process.pid != current.process.pid
            || expected.process.started != current.process.started
            || expected.executable != current.executable
            || expected.executable_path != current.executable_path
            || expected.namespace != current.namespace
            || expected.root != current.root
        {
            return Err(Error::ProcessChanged);
        }
        Ok(())
    }

    fn check_shared_root(host: &Identity, browser: &Identity) -> Result<(), Error> {
        if host.namespace != browser.namespace {
            return Err(Error::DifferentMountNamespace);
        }
        if host.root != browser.root {
            return Err(Error::DifferentRoot);
        }
        Ok(())
    }

    fn check_owned_cleanup(
        captured_host: &Identity,
        current_host: ProcessStat,
        current_scope: FilesystemScope,
    ) -> Result<(), Error> {
        if (captured_host.process.pid, captured_host.process.started)
            != (current_host.pid, current_host.started)
        {
            return Err(Error::ProcessChanged);
        }
        if captured_host.namespace != current_scope.namespace {
            return Err(Error::DifferentMountNamespace);
        }
        if captured_host.root != current_scope.root {
            return Err(Error::DifferentRoot);
        }
        Ok(())
    }

    pub(super) struct Placement {
        processes: Vec<Process>,
        stdio: StdioIdentity,
    }

    impl Placement {
        pub(super) fn capture_native_launch() -> Result<Self, Error> {
            let stdio = StdioIdentity::capture()?;
            let mut processes = vec![Process::current_host()?];
            loop {
                let parent = processes
                    .last()
                    .expect("captured host")
                    .snapshot
                    .identity
                    .process
                    .parent;
                if parent == 0 {
                    return Err(Error::NativeLaunchPeerUnavailable);
                }
                if processes
                    .iter()
                    .any(|process| process.snapshot.identity.process.pid == parent)
                {
                    return Err(Error::ParentChainChanged);
                }
                let process = Process::capture(parent)?;
                let linked = holds_opposite_pipes(&process.directory, stdio)?;
                processes.push(process);
                if linked {
                    break;
                }
            }
            let placement = Self { processes, stdio };
            placement.revalidate()?;
            Ok(placement)
        }

        pub(super) fn revalidate(&self) -> Result<(), Error> {
            if self.processes[0].snapshot.identity.process.pid != std::process::id() {
                return Err(Error::ProcessChanged);
            }
            for (index, process) in self.processes.iter().enumerate() {
                process.revalidate(index + 1 < self.processes.len())?;
            }
            if StdioIdentity::capture()? != self.stdio
                || !holds_opposite_pipes(
                    &self
                        .processes
                        .last()
                        .expect("bound launch ancestor")
                        .directory,
                    self.stdio,
                )?
            {
                return Err(Error::NativePipeChanged);
            }
            let browser = &self
                .processes
                .last()
                .expect("bound browser ancestor")
                .snapshot
                .identity;
            check_shared_root(&self.processes[0].snapshot.identity, browser)?;
            check_shared_root(&Process::current_thread()?.snapshot.identity, browser)
        }

        pub(super) fn revalidate_owned_cleanup(&self) -> Result<(), Error> {
            let host = &self.processes[0];
            let captured = &host.snapshot.identity;
            if captured.process.pid != std::process::id() {
                return Err(Error::ProcessChanged);
            }
            let current_host =
                File::open("/proc/self").map_err(observe_error("current cleanup host"))?;
            validate_procfs(&current_host)?;
            if object_identity(&current_host)? != object_identity(&host.directory)? {
                return Err(Error::ProcessChanged);
            }
            // A running worker can outlive its thread-group leader. This reads
            // only the original host identity, not live-peer/PPid/pipe/exe state.
            let (before, _) = parse_stat_record(&read_stat_bytes(&current_host)?)?;
            let scope = cleanup_thread_scope()?;
            let (after, _) = parse_stat_record(&read_stat_bytes(&current_host)?)?;
            if (before.pid, before.started) != (after.pid, after.started) {
                return Err(Error::ProcessChanged);
            }
            check_owned_cleanup(captured, after, scope)
        }
    }
}
