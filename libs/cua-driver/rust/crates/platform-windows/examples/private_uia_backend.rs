//! Opt-in, exact-HWND verification of the existing native UIA backend only.
//!
//! Launch only through the reviewed private_uia_fixture controller. This is
//! not the SDK runtime or a desktop/input/capture test. No automatic runner
//! selects this example. See private_uia_fixture/README.md before building it.

#[cfg(not(windows))]
fn main() {
    eprintln!("private_uia_backend requires a task-owned Windows fixture");
    std::process::exit(2);
}

#[cfg(windows)]
fn main() {
    if let Err(error) = native::run() {
        eprintln!("private UIA backend refused: {error:#}");
        std::process::exit(2);
    }
}

#[cfg(windows)]
mod native {
    use std::ffi::c_void;
    use std::io::{BufRead, Read, Write};
    use std::mem::{size_of, ManuallyDrop};

    use anyhow::{bail, ensure, Context, Result};
    use cua_driver_core::snapshot_store::SnapshotPayload;
    use platform_windows::uia::snapshot::{SnapshotKind, UiaSnapshot};
    use platform_windows::uia::{patterns, walk_native_tree_checked, UiaNode};
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use windows::core::{w, Interface, BSTR};
    use windows::Win32::Foundation::{CloseHandle, BOOL, HANDLE, HWND, LPARAM, WAIT_TIMEOUT};
    use windows::Win32::Security::{
        EqualSid, GetAce, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
        GetTokenInformation, GetUserObjectSecurity, IsWellKnownSid, TokenLogonSid,
        WinLocalSystemSid, ACCESS_ALLOWED_ACE, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        PSID, SE_DACL_PROTECTED, TOKEN_GROUPS, TOKEN_QUERY,
    };
    use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED};
    use windows::Win32::System::StationsAndDesktops::{
        EnumDesktopWindows, GetProcessWindowStation, GetThreadDesktop, GetUserObjectInformationW,
        HDESK, UOI_FLAGS, UOI_IO, UOI_NAME, USEROBJECTFLAGS,
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, OpenProcess, OpenProcessToken,
        WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    };
    use windows::Win32::UI::Accessibility::{
        IUIAutomationElement, IUIAutomationInvokePattern, IUIAutomationValuePattern,
        UIA_InvokePatternId, UIA_ValuePatternId,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        GetPropW, GetWindowThreadProcessId, IsChild, IsWindow,
    };

    const WSF_VISIBLE: u32 = 1;
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const MAX_COMMAND_BYTES: usize = 4096;

    struct OwnedHandle(HANDLE);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    struct Apartment;
    impl Apartment {
        fn new() -> Result<Self> {
            unsafe {
                CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;
            }
            Ok(Self)
        }
    }
    impl Drop for Apartment {
        fn drop(&mut self) {
            unsafe {
                CoUninitialize();
            }
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Command {
        op: String,
        #[serde(default)]
        pid: u32,
        #[serde(default)]
        hwnd: u64,
        #[serde(default)]
        generation: u64,
        #[serde(default)]
        edit_hwnd: u64,
        #[serde(default)]
        button_hwnd: u64,
        value: Option<String>,
    }

    // Field order is part of this tiny controller protocol, not a driver API.
    #[derive(Serialize)]
    struct Reply {
        ok: bool,
        result: Option<Value>,
        error: Option<String>,
    }

    /// The existing snapshot owns indexed references. The native walker also
    /// AddRefs nonindexed text nodes, which the fixture releases separately.
    struct Tree {
        snapshot: UiaSnapshot,
        nodes: Vec<UiaNode>,
    }
    impl Tree {
        fn new(nodes: Vec<UiaNode>) -> Self {
            let snapshot = UiaSnapshot::from_nodes(&nodes, SnapshotKind::Uia);
            Self { snapshot, nodes }
        }

        fn element(
            &self,
            hwnd: u64,
            pid: u32,
        ) -> Result<platform_windows::uia::snapshot::RetainedElement> {
            for (ordinal, node) in self
                .nodes
                .iter()
                .filter(|node| node.element_index.is_some())
                .enumerate()
            {
                ensure!(
                    node.element_ptr != 0,
                    "indexed native UIA reference is null"
                );
                let element = ManuallyDrop::new(unsafe {
                    IUIAutomationElement::from_raw(node.element_ptr as *mut _)
                });
                let native = unsafe { element.CurrentNativeWindowHandle()? };
                if native.0 as usize as u64 == hwnd {
                    ensure!(
                        unsafe { element.CurrentProcessId()? } as u32 == pid,
                        "child UIA PID mismatch"
                    );
                    return self
                        .snapshot
                        .retain(ordinal)
                        .context("native snapshot did not retain the element");
                }
            }
            bail!("exact fixture control has no indexed native UIA element")
        }
    }
    impl Drop for Tree {
        fn drop(&mut self) {
            for node in &self.nodes {
                if node.element_index.is_none() && node.element_ptr != 0 {
                    unsafe {
                        drop(IUIAutomationElement::from_raw(node.element_ptr as *mut _));
                    }
                }
            }
            // snapshot drops indexed references after this method returns.
        }
    }

    unsafe fn object_name(handle: HANDLE) -> Result<String> {
        let mut data = [0u16; 512];
        GetUserObjectInformationW(
            handle,
            UOI_NAME,
            Some(data.as_mut_ptr().cast()),
            size_of::<[u16; 512]>() as u32,
            None,
        )?;
        let end = data
            .iter()
            .position(|c| *c == 0)
            .context("unterminated USER object name")?;
        Ok(String::from_utf16(&data[..end])?)
    }

    unsafe fn check_acl(handle: HANDLE, protected: bool) -> Result<()> {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
        let token = OwnedHandle(token);
        let mut needed = 0;
        let _ = GetTokenInformation(token.0, TokenLogonSid, None, 0, &mut needed);
        ensure!(
            needed > 0 && needed <= 65536,
            "invalid logon SID buffer size"
        );
        ensure!(
            needed as usize >= size_of::<TOKEN_GROUPS>(),
            "short logon SID buffer"
        );
        let mut groups_storage = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
        GetTokenInformation(
            token.0,
            TokenLogonSid,
            Some(groups_storage.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )?;
        let groups = &*(groups_storage.as_ptr().cast::<TOKEN_GROUPS>());
        ensure!(groups.GroupCount == 1, "expected one logon SID");
        let own_sid = groups.Groups[0].Sid;

        let info = DACL_SECURITY_INFORMATION.0;
        let mut needed = 0;
        let _ = GetUserObjectSecurity(
            handle,
            &info,
            PSECURITY_DESCRIPTOR::default(),
            0,
            &mut needed,
        );
        ensure!(
            needed > 0 && needed <= 65536,
            "invalid USER security descriptor size"
        );
        let mut descriptor_storage = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
        let descriptor = PSECURITY_DESCRIPTOR(descriptor_storage.as_mut_ptr().cast());
        GetUserObjectSecurity(handle, &info, descriptor, needed, &mut needed)?;
        let mut control = 0;
        let mut revision = 0;
        GetSecurityDescriptorControl(descriptor, &mut control, &mut revision)?;
        ensure!(
            !protected || control & SE_DACL_PROTECTED.0 != 0,
            "private station DACL is not protected"
        );
        let mut present = BOOL(0);
        let mut defaulted = BOOL(0);
        let mut dacl = std::ptr::null_mut();
        GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)?;
        ensure!(
            present.as_bool() && !dacl.is_null() && !defaulted.as_bool(),
            "private object requires an explicit non-null DACL"
        );
        ensure!(
            (*dacl).AceCount > 0 && (*dacl).AceCount <= 2,
            "unexpected private object ACL entries"
        );
        let mut own = false;
        for i in 0..(*dacl).AceCount {
            let mut ace: *mut c_void = std::ptr::null_mut();
            GetAce(dacl, u32::from(i), &mut ace)?;
            let ace = &*(ace.cast::<ACCESS_ALLOWED_ACE>());
            ensure!(
                ace.Header.AceType == ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceFlags == 0,
                "unexpected private object ACE"
            );
            let sid = PSID((&ace.SidStart as *const u32).cast_mut().cast());
            let is_own = EqualSid(sid, own_sid).is_ok();
            ensure!(
                is_own || IsWellKnownSid(sid, WinLocalSystemSid).as_bool(),
                "private object grants another principal"
            );
            own |= is_own;
        }
        ensure!(own, "private object does not grant the own logon SID");
        Ok(())
    }

    fn private_context(station: &str, desktop: &str) -> Result<HDESK> {
        ensure!(size_of::<usize>() == 8, "fixture requires a 64-bit build");
        ensure!(
            !station.eq_ignore_ascii_case("WinSta0") && !station.is_empty(),
            "interactive station is forbidden"
        );
        unsafe {
            let own_station = GetProcessWindowStation()?;
            ensure!(
                object_name(HANDLE(own_station.0))? == station,
                "private station name mismatch"
            );
            let mut flags = USEROBJECTFLAGS::default();
            GetUserObjectInformationW(
                HANDLE(own_station.0),
                UOI_FLAGS,
                Some((&mut flags as *mut USEROBJECTFLAGS).cast()),
                size_of::<USEROBJECTFLAGS>() as u32,
                None,
            )?;
            ensure!(
                flags.dwFlags & WSF_VISIBLE == 0,
                "visible window station is forbidden"
            );
            check_acl(HANDLE(own_station.0), true)?;
            let own_desktop = GetThreadDesktop(GetCurrentThreadId())?;
            ensure!(
                object_name(HANDLE(own_desktop.0))? == desktop,
                "private desktop name mismatch"
            );
            let mut input = BOOL(1);
            GetUserObjectInformationW(
                HANDLE(own_desktop.0),
                UOI_IO,
                Some((&mut input as *mut BOOL).cast()),
                size_of::<BOOL>() as u32,
                None,
            )?;
            ensure!(!input.as_bool(), "input desktop is forbidden");
            check_acl(HANDLE(own_desktop.0), false)?;
            Ok(own_desktop)
        }
    }

    struct Membership {
        wanted: HWND,
        found: bool,
    }
    unsafe extern "system" fn member(hwnd: HWND, data: LPARAM) -> BOOL {
        let scan = &mut *(data.0 as *mut Membership);
        if hwnd == scan.wanted {
            scan.found = true;
            BOOL(0)
        } else {
            BOOL(1)
        }
    }

    fn identity(command: &Command, desktop: HDESK) -> Result<OwnedHandle> {
        ensure!(
            command.pid != 0 && command.pid != unsafe { GetCurrentProcessId() },
            "fixture must be a separate known process"
        );
        ensure!(
            command.hwnd != 0
                && command.generation != 0
                && command.edit_hwnd != 0
                && command.button_hwnd != 0,
            "fixture identity fields must be nonzero"
        );
        ensure!(
            command.hwnd != command.edit_hwnd
                && command.hwnd != command.button_hwnd
                && command.edit_hwnd != command.button_hwnd,
            "fixture HWNDs must be distinct"
        );
        let root = HWND(command.hwnd as *mut _);
        unsafe {
            let process = OwnedHandle(OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                false,
                command.pid,
            )?);
            ensure!(
                WaitForSingleObject(process.0, 0) == WAIT_TIMEOUT,
                "fixture process has exited"
            );
            let mut scan = Membership {
                wanted: root,
                found: false,
            };
            let _ = EnumDesktopWindows(
                desktop,
                Some(member),
                LPARAM((&mut scan as *mut Membership) as isize),
            );
            ensure!(
                scan.found,
                "fixture HWND is absent from the verified private desktop"
            );
            for window in [command.hwnd, command.edit_hwnd, command.button_hwnd] {
                let handle = HWND(window as *mut _);
                let mut owner = 0;
                ensure!(
                    IsWindow(handle).as_bool()
                        && GetWindowThreadProcessId(handle, Some(&mut owner)) != 0
                        && owner == command.pid,
                    "fixture HWND/PID mismatch"
                );
                ensure!(
                    window == command.hwnd || IsChild(root, handle).as_bool(),
                    "fixture control is outside the admitted root"
                );
            }
            ensure!(
                GetPropW(root, w!("MakaCuaFixtureGeneration")).0 as usize as u64
                    == command.generation,
                "fixture generation mismatch"
            );
            Ok(process)
        }
    }

    fn execute(command: &Command, station: &str, desktop_name: &str) -> Result<Value> {
        ensure!(
            matches!(command.op.as_str(), "observe" | "set_value" | "invoke"),
            "unsupported private fixture operation"
        );
        if command.op == "set_value" {
            let value = command
                .value
                .as_deref()
                .context("set_value requires value")?;
            ensure!(
                value.len() <= 128 && value.is_ascii(),
                "fixture value must be bounded ASCII"
            );
        } else {
            ensure!(command.value.is_none(), "value is only valid for set_value");
        }
        let desktop = private_context(station, desktop_name)?;
        let process = identity(command, desktop)?;
        // Prove private object membership before even initializing COM. All
        // returned/retained references drop before this command's MTA guard.
        let _apartment = Apartment::new()?;
        let tree = Tree::new(
            walk_native_tree_checked(command.hwnd, command.pid).map_err(anyhow::Error::msg)?,
        );
        let _rechecked = identity(command, desktop)?;
        ensure!(
            unsafe { WaitForSingleObject(process.0, 0) } == WAIT_TIMEOUT,
            "admitted fixture process exited"
        );
        match command.op.as_str() {
            "observe" => {
                let _edit = tree.element(command.edit_hwnd, command.pid)?;
                let _button = tree.element(command.button_hwnd, command.pid)?;
                Ok(
                    json!({"backend":"checked_native_uia", "nodes":tree.nodes.iter().map(|node| json!({
                "index":node.element_index,"control_type":node.control_type,"name":node.name,
                "value":node.value,"actions":node.actions
                })).collect::<Vec<_>>(), "generation":command.generation}),
                )
            }
            "set_value" => {
                let value = command
                    .value
                    .as_deref()
                    .context("set_value requires value")?;
                ensure!(
                    value.len() <= 128 && value.is_ascii(),
                    "fixture value must be bounded ASCII"
                );
                let retained = tree.element(command.edit_hwnd, command.pid)?;
                let element = ManuallyDrop::new(unsafe {
                    IUIAutomationElement::from_raw(retained.as_ptr() as *mut _)
                });
                let pattern: IUIAutomationValuePattern =
                    unsafe { element.GetCurrentPattern(UIA_ValuePatternId)? }.cast()?;
                let _last_check = identity(command, desktop)?;
                patterns::set_value(&pattern, &BSTR::from(value))
                    .context("ValuePattern dispatch returned failure; its effect is unknown")?;
                let _after = identity(command, desktop).context(
                    "fixture identity changed after ValuePattern dispatch; effect is unknown",
                )?;
                Ok(
                    json!({"path":"shared_value_pattern_leaf","hresult_success":true,"effect":"requires_fixture_oracle"}),
                )
            }
            "invoke" => {
                let retained = tree.element(command.button_hwnd, command.pid)?;
                let element = ManuallyDrop::new(unsafe {
                    IUIAutomationElement::from_raw(retained.as_ptr() as *mut _)
                });
                let pattern: IUIAutomationInvokePattern =
                    unsafe { element.GetCurrentPattern(UIA_InvokePatternId)? }.cast()?;
                let _last_check = identity(command, desktop)?;
                patterns::invoke(&pattern)
                    .context("InvokePattern dispatch returned failure; its effect is unknown")?;
                let _after = identity(command, desktop).context(
                    "fixture identity changed after InvokePattern dispatch; effect is unknown",
                )?;
                Ok(
                    json!({"path":"shared_invoke_pattern_leaf","hresult_success":true,"effect":"requires_fixture_oracle"}),
                )
            }
            _ => bail!("unsupported private fixture operation"),
        }
    }

    pub fn run() -> Result<()> {
        let args: Vec<String> = std::env::args().skip(1).collect();
        ensure!(
            args.len() == 5
                && args[0] == "--private-fixture"
                && args[1] == "--station"
                && args[3] == "--desktop",
            "launch only through the reviewed private fixture controller"
        );
        let (station, desktop) = (&args[2], &args[4]);
        // This must succeed before COM or any UIA operation is initialized.
        private_context(station, desktop)?;
        let mut output = std::io::stdout().lock();
        let input = std::io::stdin();
        let mut input = input.lock();
        loop {
            let mut line = Vec::new();
            if (&mut input)
                .take(MAX_COMMAND_BYTES as u64 + 1)
                .read_until(b'\n', &mut line)?
                == 0
            {
                break;
            }
            ensure!(
                line.len() <= MAX_COMMAND_BYTES && line.last() == Some(&b'\n'),
                "private command is too large or incomplete"
            );
            let command: Command = serde_json::from_slice(&line)?;
            let response = if command.op == "quit" {
                Reply {
                    ok: true,
                    result: Some(json!({"closed":true})),
                    error: None,
                }
            } else {
                match execute(&command, station, desktop) {
                    Ok(result) => Reply {
                        ok: true,
                        result: Some(result),
                        error: None,
                    },
                    Err(error) => Reply {
                        ok: false,
                        result: None,
                        error: Some(format!("{error:#}")),
                    },
                }
            };
            serde_json::to_writer(&mut output, &response)?;
            writeln!(output)?;
            output.flush()?;
            if !response.ok {
                bail!("private fixture operation failed; no retry or fallback");
            }
            if command.op == "quit" {
                break;
            }
        }
        Ok(())
    }
}
