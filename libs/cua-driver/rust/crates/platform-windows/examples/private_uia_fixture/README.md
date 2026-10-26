# Private Windows UIA source fixture

This is an opt-in narrow Windows experiment, outside ordinary `cargo test`.
The initial controller and Rust backend were compiled with MSVC for x64. Its
first reviewed launch refused at `CreateWindowStationW(NULL, CWF_CREATE_ONLY)`
with `ERROR_ALREADY_EXISTS` (183), before creating a desktop, fixture window,
backend process or UIA operation. The fresh named-station controller was then
compiled and reviewed separately. Its one ordinary-token launch refused with
`ERROR_ACCESS_DENIED` (5) at the same station-creation call, also before creating
a desktop, fixture window or backend process. Private UIA live verification
is blocked by the current token's station-creation permission. No elevation,
existing-station fallback or further live attempt was made.

The controller and its fixture child share `fixture.c`. The controller accepts
only this explicit invocation shape:

```text
fixture.exe --private-fixture --backend C:\absolute\private_uia_backend.exe
```

That specifies the invocation shape; the observed refusals are described above.
No tool, compiler, executable or dependency is acquired by this source. The C
source uses Win32 `User32`, `Advapi32` and `Kernel32` APIs and requires a 64-bit
build.

## Isolation and lifetime

The controller requests a new window station named
`MakaCuaPrivate-<controller PID>-<lifetime generation>` using
`CreateWindowStationW(name, CWF_CREATE_ONLY, ...)`. It checks the returned
object's actual name against that exact request before selecting the station;
a collision fails without another attempt. It does not request administrator
privileges or open an existing station. Microsoft's contract restricts
explicit station names to members of Administrators. If the current token
cannot create one, the fixture refuses without elevation or a fallback.
An explicit protected
DACL grants access only to the calling token's logon SID. The same descriptor
is supplied for the new `Default` desktop and private working directory.
See Microsoft's [CreateWindowStation documentation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-createwindowstationw).

Before creating any fixture window, both controller and fixture child verify
the exact station name, reject `WinSta0`, require `WSF_VISIBLE` to be clear,
require desktop name `Default`, and require `UOI_IO` to report false.
[`GetUserObjectInformationW`](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getuserobjectinformationw)
documents the station flags, names and input-desktop query.

The controller selects only the newly created private station and desktop.
It never reconnects to the interactive station. Children receive the explicit
`<actual station name>\Default` startup desktop and an explicit inherited
handle list containing only their own standard input/output/error pipes (the
fixture child's unused input is `NUL`). No window-station or desktop handle
is inheritable. This avoids inherited desktop selection overriding the
declared startup desktop, as described in Microsoft's
[thread-to-desktop connection rules](https://learn.microsoft.com/en-us/windows/win32/winstation/thread-connection-to-a-desktop).

Children are created suspended, assigned to one new unnamed kill-on-close
job, and then resumed. The job contains only those created child processes.
Cleanup terminates remaining children, waits on their exact process handles,
closes their pipes, closes the job, and removes the empty working directory.
An unexpected nonempty directory is reported and retained; there is no
recursive deletion. The controller keeps its assigned station/desktop alive
until process exit, which releases the final USER-object references; closing
an assigned desktop or reconnecting to `WinSta0` is not part of cleanup.

The child environment is built from `SystemRoot`, `WINDIR`, a system-directory
`PATH`, and task-owned `TEMP`/`TMP`. It passes no agent environment or credential
variables and uses its own working directory. The children retain the same user
token and its file, registry and profile permissions; this is not process or
filesystem isolation. Windows APIs may still read profile settings.
There is no input-desktop opening, desktop switch, global window enumeration,
foreground activation, synthetic input, screenshot, clipboard access, new
account, elevation or host setting change in this controller.

## Fixture and backend protocol

The native fixture consists of a standard Win32 `EDIT`, `BUTTON`, and `STATIC`
inside its own root window. `WS_VISIBLE` applies only within the private
noninput station. The button's `BN_CLICKED` handler increments a counter.
The root carries a positive 64-bit `MakaCuaFixtureGeneration` property.

The fixture child writes one fixed-width readiness record to its dedicated
stdout pipe. All six fields are `uint64_t`, in native Windows byte order:

| Field | Meaning |
| --- | --- |
| `magic` | `0x4d414b4143554131` |
| `pid` | Fixture child's actual process ID |
| `hwnd` | Exact root HWND |
| `edit_hwnd` | Exact child EDIT HWND |
| `button_hwnd` | Exact child BUTTON HWND |
| `generation` | The root's positive lifetime generation |

The controller starts the separately reviewed Rust backend as:

```text
private_uia_backend.exe --private-fixture --station <actual station name> --desktop Default
```

Its stdin/stdout protocol is one JSON object per line. Each request contains
`op`, `pid`, `hwnd`, `generation`, `edit_hwnd`, and `button_hwnd`. Supported
operations are `observe`, `set_value`, `invoke`, and `quit`; only `set_value`
also contains `value`. The controller supplies numeric HWND values and fixed
fixture text, never arbitrary desktop targets.

Each reply must be serialized with fields in order `ok`, `result`, `error`.
The C controller checks the literal success prefix `{"ok":true,` and records
the complete line. The incorrect-generation case requires this exact reply:

```json
{"ok":false,"result":null,"error":"fixture generation mismatch"}
```

An unrelated failure cannot satisfy that negative assertion. This fixed envelope avoids a second JSON
implementation in this small controller. It is not an API outside this
source fixture.

Replies have a 1 MiB fixture-only transport limit before buffer growth. The
fixed three-control fixture produces much smaller observations. Exceeding
the limit ends the case with a refusal; truncated output is never accepted
as a successful reply. This limit does not change product response semantics.

The backend must revalidate its private context and the fixture's exact
HWND/PID/property generation before each operation and before reading any
UIA names or descendants. It must reuse the production checked HWND-root
walker and strict leaf functions accepting typed ValuePattern/InvokePattern
interfaces, also called by production handlers.
It must not enter the SDK, registry, desktop-root fallback, capture, generic
click, focus or coordinate-input paths. UIA references stay inside one MTA
lifetime, with every emitted reference released, including nonindexed nodes.

## Independent effect checks

The controller checks application state through its source fixture's own
messages, independently of UIA or the backend response:

- `WM_GETTEXT` sent only to the known owned EDIT reads the literal text.
- `WM_APP + 1` sent only to the known root reads its button counter.
- `WM_APP + 2` reads the fixture's in-process generation.

Before and after each oracle group, it checks the root and both child HWNDs'
owning PID, exact child relationship, and generation property. The baseline
uses one read. After ValuePattern and InvokePattern calls, it condition-polls
the expected text and counter, repeating the complete identity checks each
time. It fails immediately if identity is lost or the counter exceeds the
expected value, and records the actual observed text/counter on completion.
There is no actuator retry. Requests use `SendMessageTimeoutW`, passing the
remaining portion of one 30-second test deadline to each message. The backend
pipe reader uses the same operation deadline and drains its dedicated stderr pipe.
These deadlines stop the experiment if its own children stop responding;
they do not limit any product accessibility API.

The planned sequence is:

1. Observe the private fixture and verify unchanged baseline text/counter.
2. Set the EDIT value through the strict production UIA leaf; independently
   read the exact new text and unchanged counter.
3. Invoke the exact button through the strict production UIA leaf;
   independently read the counter increment and unchanged text.
4. Quit the normal-case backend and require successful exit.
5. Start a separate refusal-case backend, submit an incorrect generation,
   and require the exact `fixture generation mismatch` reply above, exit
   code 2, and unchanged fixture oracles. The
   refusing backend receives no subsequent request.
6. Quit the fixture, wait for its exit, then clean up.

Even a future successful run would prove only this exact private HWND native
UIA path and these source oracles. It would not establish Maka SDK behavior,
input injection, screenshots, cursor rendering, browser behavior, interactive
desktop behavior, or complete Windows parity with the reference runtime.

## Shared backend path and review gates

The Rust worker is [private_uia_backend.rs](../private_uia_backend.rs). Its
call path for each non-quit command is:

```text
own station/desktop names, nonvisible/noninput flags, actual own-logon-SID ACL
  -> EnumDesktopWindows(verified private HDESK): numeric HWND membership only
  -> own fixture PID, child relationships, lifetime-generation property
  -> initialize this command's windowless COM MTA
  -> walk_native_tree_checked(exact HWND, expected PID)
       -> native HWND owner check
       -> ElementFromHandle (one root resolution)
       -> CurrentNativeWindowHandle + CurrentProcessId; refuse mismatch
       -> existing node_cache_request + walk_native_level + emit_cached_node
  -> existing UiaSnapshot / SnapshotPayload retention of real indexed nodes
  -> discover exact ValuePattern or InvokePattern through official COM APIs
  -> shared patterns::set_value / patterns::invoke (one direct leaf call)
  -> recheck fixture identity; release every reference before CoUninitialize
  -> controller checks independent fixture messages
```

The checked entry in [uia/mod.rs](../../src/uia/mod.rs) shares the same native
walker as the existing `walk_native_tree` entry. The latter keeps its existing
default behavior. The checked entry does not call `walk_tree`, desktop-root
discovery, MSAA, SDK initialization or another actuator. It resolves the root
once, checks its intrinsic identity, then caches and walks that same root.

The two [pattern functions](../../src/uia/patterns.rs) accept already resolved
typed patterns. The production Invoke branch of `ClickTool` and ValuePattern
branch of `SetValueTool` in [impl_.rs](../../src/tools/impl_.rs) call these same
leaves. Their production discovery count, foreground guards, result
classification and outer fallback routing stay in place. The fixture does
not enter those broader tool paths. A failed HRESULT after entering a leaf
can have an unknown effect; `ok:false` does not imply no write occurred.

The generation is the source fixture's lifetime cookie, not an atomic Windows
HWND-generation API. Identity is checked before and after the operation, but
the test cannot establish atomicity against every provider mutation. The
specified-window contract of
[ElementFromHandle](https://learn.microsoft.com/en-us/windows/win32/api/uiautomationclient/nf-uiautomationclient-iuiautomation-elementfromhandle)
is the basis for this experiment; undocumented UIAutomationCore/provider
internal routing remains unverified. A run must fail and stop when the private
context or a required pattern is unavailable, without moving to an input
desktop or selecting a different transport.

Before any native run, review all six source files together: this document,
the C controller, Rust worker, checked walker, shared pattern functions and
their two production call-site substitutions. A later native runner should:

1. Recheck physical C: free space and keep all build output on the task-owned
   C: target. Retain the 27 GiB reserve and record compiler/dependency inputs.
2. Compile the example from the exact reviewed Cua revision with the normal
   Windows MSVC profile and repository CRT settings. Compile `fixture.c` as a
   64-bit console program with the existing Windows SDK, linking `User32`,
   `Advapi32` and `Kernel32`. No installation or dependency acquisition is
   specified by this fixture.
3. Record both source and executable SHA-256 values, inspect the resulting
   source call graph again, and review the exact explicit invocation above.
   A successful build is not permission to start it on another desktop.
4. Only after the private-launch review, run that explicit invocation with
   bounded stdout/stderr logs. Record refusal as refusal; never relax an ACL,
   use an existing station, retry an actuator, or change host settings to make
   the fixture pass.

The unchanged Rust backend and both controller revisions have native MSVC
build evidence. The two launches established only station-creation refusals;
neither reached COM/UIA or an actuator. The final status update changes only
this document, so it requires no artifact rebuild. Private UIA provider
support and the independent effect oracles remain unverified.
