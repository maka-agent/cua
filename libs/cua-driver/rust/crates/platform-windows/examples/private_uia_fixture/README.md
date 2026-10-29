# Private Windows UIA fixture

This opt-in example checks the existing native UIA walker and ValuePattern leaf
against its own standard Win32 controls. It is outside ordinary `cargo test` and
does not initialize the SDK.

## Build and run explicitly

Use a task-owned Windows validation environment with an existing native x64 MSVC
compiler, Windows SDK and the repository's static-CRT/Spectre library setup. No
compiler, application or dependency is installed by this fixture. From
`libs/cua-driver/rust`, a native x64 Developer Command Prompt can build the current
workspace and C controller into a task directory:

```bat
set "CUA_UIA_OUT=C:\task\private-uia"
mkdir "%CUA_UIA_OUT%"
set "CARGO_TARGET_DIR=%CUA_UIA_OUT%\target"
cargo build --locked --target x86_64-pc-windows-msvc -p platform-windows --example private_uia_backend
set "LIB=%VCToolsInstallDir%lib\spectre\x64;%LIB%"
cl /nologo /TC /std:c17 /W4 /MT /Zi /Od /Qspectre /Fo"%CUA_UIA_OUT%\fixture.obj" /Fd"%CUA_UIA_OUT%\fixture-compile.pdb" /Fe"%CUA_UIA_OUT%\fixture.exe" crates\platform-windows\examples\private_uia_fixture\fixture.c /link /INCREMENTAL:NO /SUBSYSTEM:CONSOLE /PDB:"%CUA_UIA_OUT%\fixture.pdb" user32.lib advapi32.lib kernel32.lib bcrypt.lib
"%CUA_UIA_OUT%\fixture.exe" --current-station-private-desktop --backend "%CUA_UIA_OUT%\target\x86_64-pc-windows-msvc\debug\examples\private_uia_backend.exe"
```

Build both subjects from the same checkout using the x64 toolchain. The fixture
refuses an unavailable context or pattern and does not retry a write or select
another input transport.

## Desktop isolation and identity

The controller uses its caller's already selected window station and creates a
new `MakaCuaPrivate-<PID>-<128-bit nonce>` desktop there. It checks absence of that
exact generated name, then checks the returned name, protected own-logon-SID
DACL and non-input state. The desktop mask is exactly `READ_CONTROL |
DESKTOP_CREATEWINDOW | DESKTOP_CREATEMENU | DESKTOP_READOBJECTS |
DESKTOP_WRITEOBJECTS` (`0x20087`), excluding `DESKTOP_SWITCHDESKTOP`. It does not
modify the station ACL. Public `CreateDesktopW` can reopen an existing name;
nonce plus absence preflight is not an atomic guarantee against a same-user race.
[CreateDesktopW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-createdesktopw),
[desktop rights](https://learn.microsoft.com/en-us/windows/win32/winstation/desktop-security-and-access-rights).

Each child receives the exact station/desktop in `STARTUPINFOEXW.lpDesktop`, only
its three standard handles, and a fixed system/task-temporary environment. The
controller creates children suspended, assigns its unnamed kill-on-close job,
then resumes them. No station/desktop handles are inherited. The fixture verifies
its own exact station, desktop, DACL and `UOI_IO == false` before creating windows
and again before readiness. The controller/backend retain their own private
context checks. Same-user file, registry and profile permissions remain available;
this is desktop-object isolation rather than a process/filesystem sandbox.

Readiness contains seven `uint64_t` fields in native Windows byte order: `magic`,
`pid`, `tid`, root `hwnd`, `edit_hwnd`, `button_hwnd`, and `generation`. The controller
matches PID and primary TID against its actual `PROCESS_INFORMATION`. All three
known HWNDs must keep that exact PID/TID, their child relationships and generation.
The trusted fixture creates all controls on that primary thread; Windows prohibits
changing a thread's desktop while it owns windows. This provenance proof applies
only to this controlled fixture, never arbitrary applications.
[CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw),
[SetThreadDesktop](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setthreaddesktop).

## Operations and independent oracles

The controller starts [the Rust worker](../private_uia_backend.rs) with the same
`--current-station-private-desktop` opt-in and explicit station/desktop names.
Its private JSON requests carry `op`, `pid`, mandatory typed `expected_tid`, the
three HWNDs, generation and the fixed expected value. No target discovery occurs.
The worker checks identity before COM, runs the existing
[`walk_native_tree_checked`](../../src/uia/mod.rs) in a windowless MTA, retains real
snapshot references, and uses the shared
[`patterns::set_value`](../../src/uia/patterns.rs) leaf. The returned references
are released before the apartment ends.

The sequence checks:

1. Baseline native UIA tree and literal ValuePattern readback.
2. ASCII write, independent `WM_GETTEXT`/counter readback, then fresh UIA readback.
3. Unicode `Café 日本語 🐧` write with the same two independent readbacks.
4. Separate workers with an incorrect expected TID and incorrect generation,
   exact refusals, exit code 2, and unchanged fixture values/counter. Neither
   refusing worker receives a subsequent command.
5. Normal fixture exit and owned-child cleanup.

The exact negative errors are `fixture HWND/TID mismatch` and
`fixture generation mismatch`; unrelated errors cannot pass those assertions.
`WM_APP + 1` reads the button counter and `WM_APP + 2` reads the in-process
generation. The counter remains zero throughout: Invoke is not executed.
Identity is checked before/after oracle groups, and every message shares its
30-second operation deadline. The private command/reply transport limits apply
only to this fixed fixture; oversized or truncated data never passes.

The final success line is:

```json
{"private_fixture":"current_station_private_desktop_passed","uia_value_readback":true,"ascii_value_oracle":true,"unicode_value_oracle":true,"counter_unchanged_oracle":true,"generation_oracle":true}
```

## Scope and limitations

This fixture exercises native subtree observation and ValuePattern behavior.
It does not exercise physical typing, Invoke effects, global input, foreground
activation, screenshots, cursor rendering, mixed DPI, SDK/browser integration,
current whole-workspace native behavior or parity with the original runtime.
There is no desktop switch, personal-window enumeration, capture or clipboard
operation in this path. OS-owned provider helpers outside the owned jobs are
outside its scope. Generation is a fixture lifetime cookie, not an atomic HWND-generation
API; an HRESULT after a write can leave its effect unknown.
