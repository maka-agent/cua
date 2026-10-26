/* Source-only private-station fixture. Build and launch require separate review. */
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <aclapi.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#if UINTPTR_MAX != UINT64_MAX
#error This fixture requires a 64-bit Windows build.
#endif

#define COUNT_OF(a) (sizeof(a) / sizeof((a)[0]))
#define OPERATION_TIMEOUT_MS 30000
#define MAX_REPLY_BYTES (1024 * 1024)
#define GENERATION_PROPERTY L"MakaCuaFixtureGeneration"
#define FIXTURE_CLASS L"MakaCuaPrivateFixture"
#define ORACLE_COUNTER (WM_APP + 1)
#define ORACLE_GENERATION (WM_APP + 2)
#define FIXTURE_QUIT (WM_APP + 3)
#define READY_MAGIC UINT64_C(0x4d414b4143554131)

static const wchar_t initial_text[] = L"Maka private fixture baseline";
static const wchar_t final_text[] = L"Maka private UIA verified";

typedef struct {
    uint64_t magic, pid, hwnd, edit_hwnd, button_hwnd, generation;
} Ready;

typedef struct {
    PROCESS_INFORMATION process;
    HANDLE input, output, error;
} Child;

typedef struct {
    PTOKEN_GROUPS groups;
    PACL acl;
    SECURITY_DESCRIPTOR descriptor;
    SECURITY_ATTRIBUTES attributes;
} Security;

typedef struct {
    HWND edit, button, counter_label;
    uint64_t generation, counter;
} Fixture;

static BOOL api_error(const char *operation) {
    fprintf(stderr, "%s failed (Win32 error %lu)\n", operation, GetLastError());
    return FALSE;
}

static void close_handle(HANDLE *handle) {
    if (*handle && *handle != INVALID_HANDLE_VALUE) CloseHandle(*handle);
    *handle = NULL;
}

static wchar_t *object_name(HANDLE object) {
    DWORD bytes = 0;
    GetUserObjectInformationW(object, UOI_NAME, NULL, 0, &bytes);
    if (bytes < sizeof(wchar_t)) return NULL;
    wchar_t *name = calloc(1, (size_t)bytes + sizeof(wchar_t));
    if (!name) return NULL;
    if (!GetUserObjectInformationW(object, UOI_NAME, name, bytes, &bytes)) {
        free(name);
        return NULL;
    }
    return name;
}

static BOOL verify_private_context(const wchar_t *expected_station) {
    HWINSTA station = GetProcessWindowStation();
    HDESK desktop = GetThreadDesktop(GetCurrentThreadId());
    USEROBJECTFLAGS flags = {0};
    BOOL receives_input = TRUE;
    DWORD bytes = 0;
    wchar_t *station_name = object_name(station);
    wchar_t *desktop_name = object_name(desktop);
    BOOL valid = station_name && desktop_name &&
        _wcsicmp(station_name, L"WinSta0") != 0 &&
        wcscmp(station_name, expected_station) == 0 &&
        wcscmp(desktop_name, L"Default") == 0 &&
        GetUserObjectInformationW(station, UOI_FLAGS, &flags, sizeof(flags), &bytes) &&
        !(flags.dwFlags & WSF_VISIBLE) &&
        GetUserObjectInformationW(desktop, UOI_IO, &receives_input,
                                  sizeof(receives_input), &bytes) &&
        !receives_input;
    free(station_name);
    free(desktop_name);
    if (!valid) fprintf(stderr, "Refused: the current station/desktop is not the exact private noninput context.\n");
    return valid;
}

static BOOL logon_security(Security *security) {
    HANDLE token = NULL;
    DWORD bytes = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return api_error("OpenProcessToken");
    GetTokenInformation(token, TokenGroups, NULL, 0, &bytes);
    security->groups = malloc(bytes);
    if (!security->groups || !GetTokenInformation(token, TokenGroups,
            security->groups, bytes, &bytes)) {
        close_handle(&token);
        return api_error("GetTokenInformation(TokenGroups)");
    }
    close_handle(&token);
    PSID logon_sid = NULL;
    for (DWORD i = 0; i < security->groups->GroupCount; ++i) {
        if ((security->groups->Groups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID) {
            if (logon_sid) {
                fprintf(stderr, "Refused: more than one logon SID.\n");
                return FALSE;
            }
            logon_sid = security->groups->Groups[i].Sid;
        }
    }
    if (!logon_sid) {
        fprintf(stderr, "Refused: this token has no logon SID.\n");
        return FALSE;
    }
    EXPLICIT_ACCESSW access = {0};
    access.grfAccessPermissions = GENERIC_ALL;
    access.grfAccessMode = SET_ACCESS;
    access.grfInheritance = NO_INHERITANCE;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    access.Trustee.ptstrName = (LPWSTR)logon_sid;
    DWORD error = SetEntriesInAclW(1, &access, NULL, &security->acl);
    if (error != ERROR_SUCCESS) {
        SetLastError(error);
        return api_error("SetEntriesInAclW");
    }
    if (!InitializeSecurityDescriptor(&security->descriptor, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorDacl(&security->descriptor, TRUE, security->acl, FALSE) ||
        !SetSecurityDescriptorControl(&security->descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED))
        return api_error("private security descriptor");
    security->attributes.nLength = sizeof(security->attributes);
    security->attributes.lpSecurityDescriptor = &security->descriptor;
    security->attributes.bInheritHandle = FALSE;
    return TRUE;
}

static LRESULT CALLBACK fixture_window(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
    Fixture *fixture = (Fixture *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    if (message == WM_NCCREATE) {
        fixture = ((CREATESTRUCTW *)lparam)->lpCreateParams;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)fixture);
    }
    if (fixture) {
        if (message == WM_COMMAND && (HWND)lparam == fixture->button &&
            LOWORD(wparam) == 102 && HIWORD(wparam) == BN_CLICKED) {
            wchar_t text[64];
            ++fixture->counter;
            swprintf(text, COUNT_OF(text), L"Counter: %llu", (unsigned long long)fixture->counter);
            SetWindowTextW(fixture->counter_label, text);
            return 0;
        }
        if (message == ORACLE_COUNTER) return (LRESULT)fixture->counter;
        if (message == ORACLE_GENERATION) return (LRESULT)fixture->generation;
        if (message == FIXTURE_QUIT && (uint64_t)wparam == fixture->generation) {
            DestroyWindow(hwnd);
            return 0;
        }
        if (message == WM_DESTROY) {
            RemovePropW(hwnd, GENERATION_PROPERTY);
            PostQuitMessage(0);
            return 0;
        }
    }
    return DefWindowProcW(hwnd, message, wparam, lparam);
}

static int fixture_child(const wchar_t *station, uint64_t generation) {
    if (!generation || !verify_private_context(station)) return 2;
    Fixture fixture = {0};
    fixture.generation = generation;
    WNDCLASSEXW klass = {0};
    klass.cbSize = sizeof(klass);
    klass.lpfnWndProc = fixture_window;
    klass.hInstance = GetModuleHandleW(NULL);
    klass.lpszClassName = FIXTURE_CLASS;
    if (!RegisterClassExW(&klass)) return 2;
    HWND root = CreateWindowExW(0, FIXTURE_CLASS, L"Maka private UIA fixture",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE, 20, 20, 520, 220,
        NULL, NULL, klass.hInstance, &fixture);
    if (!root) return 2;
    fixture.edit = CreateWindowExW(0, L"EDIT", initial_text,
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        20, 20, 440, 28, root, (HMENU)(UINT_PTR)101, klass.hInstance, NULL);
    fixture.button = CreateWindowExW(0, L"BUTTON", L"Increment counter",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        20, 64, 180, 32, root, (HMENU)(UINT_PTR)102, klass.hInstance, NULL);
    fixture.counter_label = CreateWindowExW(0, L"STATIC", L"Counter: 0",
        WS_CHILD | WS_VISIBLE, 220, 70, 200, 28,
        root, (HMENU)(UINT_PTR)103, klass.hInstance, NULL);
    if (!fixture.edit || !fixture.button || !fixture.counter_label ||
        !SetPropW(root, GENERATION_PROPERTY, (HANDLE)(UINT_PTR)generation)) {
        DestroyWindow(root);
        return 2;
    }
    Ready ready = {READY_MAGIC, GetCurrentProcessId(), (uint64_t)(UINT_PTR)root,
        (uint64_t)(UINT_PTR)fixture.edit, (uint64_t)(UINT_PTR)fixture.button, generation};
    DWORD written = 0;
    if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), &ready, sizeof(ready), &written, NULL) ||
        written != sizeof(ready)) {
        DestroyWindow(root);
        return 2;
    }
    MSG message;
    BOOL status;
    while ((status = GetMessageW(&message, NULL, 0, 0)) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return status < 0 ? 2 : (int)message.wParam;
}

static BOOL make_pipe(HANDLE *reader, HANDLE *writer, Security *security) {
    SECURITY_ATTRIBUTES attributes = security->attributes;
    attributes.bInheritHandle = TRUE;
    return CreatePipe(reader, writer, &attributes, 0) || api_error("CreatePipe");
}

static BOOL spawn_child(Child *child, const wchar_t *application, wchar_t *command,
        wchar_t *desktop_path, wchar_t *environment, const wchar_t *working_directory,
        HANDLE job, HANDLE input, HANDLE output, HANDLE error) {
    STARTUPINFOEXW startup = {0};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.lpDesktop = desktop_path;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = input;
    startup.StartupInfo.hStdOutput = output;
    startup.StartupInfo.hStdError = error;
    HANDLE inherited[3] = {input, output, error};
    SIZE_T count = output == error ? 2 : 3;
    SIZE_T bytes = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &bytes);
    startup.lpAttributeList = malloc(bytes);
    if (!startup.lpAttributeList) return FALSE;
    BOOL initialized = InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &bytes);
    BOOL created = initialized && UpdateProcThreadAttribute(startup.lpAttributeList, 0,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, count * sizeof(HANDLE), NULL, NULL) &&
        CreateProcessW(application, command, NULL, NULL, TRUE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            environment, working_directory, &startup.StartupInfo, &child->process);
    DWORD create_error = GetLastError();
    if (initialized) DeleteProcThreadAttributeList(startup.lpAttributeList);
    free(startup.lpAttributeList);
    if (!created) {
        SetLastError(create_error);
        return api_error("CreateProcessW with explicit stdio handle list");
    }
    if (!AssignProcessToJobObject(job, child->process.hProcess)) {
        api_error("AssignProcessToJobObject");
        TerminateProcess(child->process.hProcess, 2);
        return FALSE;
    }
    if (ResumeThread(child->process.hThread) == (DWORD)-1) return api_error("ResumeThread");
    close_handle(&child->process.hThread);
    return TRUE;
}

static BOOL launch_fixture(Child *child, const wchar_t *self, const wchar_t *station,
        wchar_t *desktop, wchar_t *environment, const wchar_t *directory,
        HANDLE job, Security *security, uint64_t generation) {
    HANDLE writer = NULL, null_input = NULL;
    BOOL result = FALSE;
    wchar_t command[32768];
    if (swprintf(command, COUNT_OF(command), L"\"%ls\" --fixture-child --station \"%ls\" --generation %llu",
            self, station, (unsigned long long)generation) < 0) return FALSE;
    if (!make_pipe(&child->output, &writer, security) ||
        !SetHandleInformation(child->output, HANDLE_FLAG_INHERIT, 0)) goto done;
    SECURITY_ATTRIBUTES attributes = security->attributes;
    attributes.bInheritHandle = TRUE;
    null_input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        &attributes, OPEN_EXISTING, 0, NULL);
    if (null_input == INVALID_HANDLE_VALUE) {
        api_error("CreateFileW(NUL)");
        goto done;
    }
    result = spawn_child(child, self, command, desktop, environment, directory,
        job, null_input, writer, writer);
done:
    close_handle(&writer);
    close_handle(&null_input);
    return result;
}

static BOOL launch_backend(Child *child, const wchar_t *backend, const wchar_t *station,
        wchar_t *desktop, wchar_t *environment, const wchar_t *directory,
        HANDLE job, Security *security) {
    HANDLE input_reader = NULL, output_writer = NULL, error_writer = NULL;
    BOOL result = FALSE;
    wchar_t command[32768];
    if (swprintf(command, COUNT_OF(command), L"\"%ls\" --private-fixture --station \"%ls\" --desktop Default",
            backend, station) < 0) return FALSE;
    if (!make_pipe(&input_reader, &child->input, security) ||
        !make_pipe(&child->output, &output_writer, security) ||
        !make_pipe(&child->error, &error_writer, security) ||
        !SetHandleInformation(child->input, HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(child->output, HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(child->error, HANDLE_FLAG_INHERIT, 0)) goto done;
    result = spawn_child(child, backend, command, desktop, environment, directory,
        job, input_reader, output_writer, error_writer);
done:
    close_handle(&input_reader);
    close_handle(&output_writer);
    close_handle(&error_writer);
    return result;
}

static BOOL read_ready(Child *child, Ready *ready) {
    DWORD consumed = 0;
    ULONGLONG deadline = GetTickCount64() + OPERATION_TIMEOUT_MS;
    while (consumed < sizeof(*ready)) {
        DWORD available = 0, read = 0;
        if (!PeekNamedPipe(child->output, NULL, 0, NULL, &available, NULL)) return api_error("fixture readiness pipe");
        if (available) {
            DWORD requested = (DWORD)sizeof(*ready) - consumed;
            if (requested > available) requested = available;
            if (!ReadFile(child->output, (char *)ready + consumed, requested, &read, NULL) || !read)
                return api_error("ReadFile(fixture readiness)");
            consumed += read;
        } else if (GetTickCount64() >= deadline ||
                   WaitForSingleObject(child->process.hProcess, 0) != WAIT_TIMEOUT) {
            fprintf(stderr, "Fixture exited or timed out before readiness.\n");
            return FALSE;
        } else Sleep(10);
    }
    if (ready->magic != READY_MAGIC || ready->pid != child->process.dwProcessId ||
        !ready->hwnd || !ready->edit_hwnd || !ready->button_hwnd || !ready->generation) {
        fprintf(stderr, "Invalid fixture readiness identity.\n");
        return FALSE;
    }
    return TRUE;
}

static BOOL drain_error(Child *child) {
    DWORD available = 0, read = 0;
    char chunk[4096];
    if (!PeekNamedPipe(child->error, NULL, 0, NULL, &available, NULL))
        return GetLastError() == ERROR_BROKEN_PIPE || api_error("backend stderr pipe");
    if (!available) return TRUE;
    if (available > sizeof(chunk)) available = sizeof(chunk);
    if (!ReadFile(child->error, chunk, available, &read, NULL)) return api_error("ReadFile(backend stderr)");
    return fwrite(chunk, 1, read, stderr) == read;
}

static char *read_reply(Child *child) {
    size_t used = 0, capacity = 256;
    char *line = malloc(capacity);
    ULONGLONG deadline = GetTickCount64() + OPERATION_TIMEOUT_MS;
    if (!line) return NULL;
    for (;;) {
        DWORD available = 0, read = 0;
        char byte;
        if (GetTickCount64() >= deadline) break;
        if (!drain_error(child) || !PeekNamedPipe(child->output, NULL, 0, NULL, &available, NULL)) break;
        if (!available) {
            if (GetTickCount64() >= deadline ||
                WaitForSingleObject(child->process.hProcess, 0) != WAIT_TIMEOUT) break;
            Sleep(10);
            continue;
        }
        if (!ReadFile(child->output, &byte, 1, &read, NULL) || read != 1 || !byte) break;
        if (byte == '\n') {
            if (used && line[used - 1] == '\r') --used;
            line[used] = '\0';
            return line;
        }
        if (used == MAX_REPLY_BYTES) {
            fprintf(stderr, "Backend reply exceeds the fixture's 1 MiB transport limit.\n");
            break;
        }
        if (used + 1 == capacity) {
            size_t next_capacity = capacity * 2;
            if (next_capacity > MAX_REPLY_BYTES + 1) next_capacity = MAX_REPLY_BYTES + 1;
            char *larger = realloc(line, next_capacity);
            if (!larger) break;
            line = larger;
            capacity = next_capacity;
        }
        line[used++] = byte;
    }
    free(line);
    fprintf(stderr, "Backend reply missing, malformed, or timed out.\n");
    return NULL;
}

static BOOL request(Child *backend, const Ready *ready, const char *operation, BOOL succeeds) {
    char command[1024];
    int length = snprintf(command, sizeof(command),
        "{\"op\":\"%s\",\"pid\":%" PRIu64 ",\"hwnd\":%" PRIu64
        ",\"generation\":%" PRIu64 ",\"edit_hwnd\":%" PRIu64 ",\"button_hwnd\":%" PRIu64 "%s}\n",
        operation, ready->pid, ready->hwnd, ready->generation, ready->edit_hwnd,
        ready->button_hwnd, strcmp(operation, "set_value") == 0 ?
        ",\"value\":\"Maka private UIA verified\"" : "");
    DWORD written = 0;
    if (length < 0 || (size_t)length >= sizeof(command) ||
        !WriteFile(backend->input, command, (DWORD)length, &written, NULL) || written != (DWORD)length)
        return api_error("WriteFile(backend command)");
    char *reply = read_reply(backend);
    if (!reply) return FALSE;
    const char *success_prefix = "{\"ok\":true,";
    const char *generation_refusal =
        "{\"ok\":false,\"result\":null,\"error\":\"fixture generation mismatch\"}";
    BOOL accepted = succeeds ? strncmp(reply, success_prefix, strlen(success_prefix)) == 0 :
        strcmp(reply, generation_refusal) == 0;
    puts(reply);
    free(reply);
    if (!accepted) fprintf(stderr, "Unexpected backend status for %s.\n", operation);
    return accepted;
}

static BOOL owns_window(HWND hwnd, DWORD pid) {
    DWORD owner = 0;
    return GetWindowThreadProcessId(hwnd, &owner) != 0 && owner == pid;
}

static BOOL send_oracle(HWND window, UINT message, WPARAM wparam, LPARAM lparam,
        ULONGLONG deadline, DWORD_PTR *result) {
    ULONGLONG now = GetTickCount64();
    if (now >= deadline) return FALSE;
    return SendMessageTimeoutW(window, message, wparam, lparam,
        SMTO_ABORTIFHUNG | SMTO_BLOCK | SMTO_ERRORONEXIT, (DWORD)(deadline - now), result) != 0;
}

static BOOL fixture_identity_until(const Ready *ready, ULONGLONG deadline) {
    HWND root = (HWND)(UINT_PTR)ready->hwnd;
    HWND edit = (HWND)(UINT_PTR)ready->edit_hwnd;
    HWND button = (HWND)(UINT_PTR)ready->button_hwnd;
    DWORD pid = (DWORD)ready->pid;
    DWORD_PTR generation = 0;
    return ready->pid == pid && owns_window(root, pid) && owns_window(edit, pid) &&
        owns_window(button, pid) && IsChild(root, edit) && IsChild(root, button) &&
        (uint64_t)(UINT_PTR)GetPropW(root, GENERATION_PROPERTY) == ready->generation &&
        send_oracle(root, ORACLE_GENERATION, 0, 0, deadline, &generation) &&
        (uint64_t)generation == ready->generation;
}

static BOOL fixture_identity(const Ready *ready) {
    return fixture_identity_until(ready, GetTickCount64() + OPERATION_TIMEOUT_MS);
}

static BOOL read_oracles(const Ready *ready, wchar_t actual[256], uint64_t *counter,
        ULONGLONG deadline) {
    DWORD_PTR length = 0, count = 0;
    actual[0] = L'\0';
    if (!fixture_identity_until(ready, deadline) ||
        !send_oracle((HWND)(UINT_PTR)ready->edit_hwnd, WM_GETTEXT,
            256, (LPARAM)actual, deadline, &length) ||
        !send_oracle((HWND)(UINT_PTR)ready->hwnd, ORACLE_COUNTER, 0, 0, deadline, &count) ||
        length >= 256 || !fixture_identity_until(ready, deadline)) {
        fprintf(stderr, "Independent source fixture identity/message oracle failed.\n");
        return FALSE;
    }
    *counter = (uint64_t)count;
    return TRUE;
}

static void record_oracles(const wchar_t *text, uint64_t counter, uint64_t expected, BOOL passed) {
    fprintf(stderr, "Fixture oracle observed text=\"%ls\" counter=%llu expected_counter=%llu status=%s\n",
        text, (unsigned long long)counter, (unsigned long long)expected,
        passed ? "passed" : "failed");
}

static BOOL oracles(const Ready *ready, const wchar_t *text, uint64_t counter) {
    wchar_t actual[256] = {0};
    uint64_t count = 0;
    if (!read_oracles(ready, actual, &count, GetTickCount64() + OPERATION_TIMEOUT_MS)) return FALSE;
    BOOL passed = wcscmp(actual, text) == 0 && count == counter;
    record_oracles(actual, count, counter, passed);
    return passed;
}

static BOOL await_oracles(const Ready *ready, const wchar_t *text, uint64_t counter) {
    ULONGLONG deadline = GetTickCount64() + OPERATION_TIMEOUT_MS;
    wchar_t actual[256] = {0};
    uint64_t count = 0;
    for (;;) {
        if (!read_oracles(ready, actual, &count, deadline)) return FALSE;
        BOOL passed = wcscmp(actual, text) == 0 && count == counter;
        if (passed || count > counter || GetTickCount64() >= deadline) {
            record_oracles(actual, count, counter, passed);
            return passed;
        }
        Sleep(10);
    }
}

static BOOL wait_child(Child *child, DWORD expected_exit) {
    DWORD code = 0;
    return WaitForSingleObject(child->process.hProcess, OPERATION_TIMEOUT_MS) == WAIT_OBJECT_0 &&
        GetExitCodeProcess(child->process.hProcess, &code) && code == expected_exit;
}

static void close_child(Child *child) {
    close_handle(&child->input);
    close_handle(&child->output);
    close_handle(&child->error);
    close_handle(&child->process.hThread);
    close_handle(&child->process.hProcess);
}

static wchar_t *child_environment(const wchar_t *directory) {
    wchar_t windows[32768];
    UINT count = GetWindowsDirectoryW(windows, COUNT_OF(windows));
    if (!count || count >= COUNT_OF(windows)) return NULL;
    size_t capacity = 3 * wcslen(windows) + 2 * wcslen(directory) + 128;
    wchar_t *environment = calloc(capacity, sizeof(wchar_t));
    if (!environment) return NULL;
    wchar_t *cursor = environment;
    int length = swprintf(cursor, capacity, L"PATH=%ls\\System32", windows);
    if (length < 0) { free(environment); return NULL; }
    cursor += length + 1;
    const wchar_t *names[] = {L"SystemRoot", L"TEMP", L"TMP", L"WINDIR"};
    const wchar_t *values[] = {windows, directory, directory, windows};
    for (size_t i = 0; i < COUNT_OF(names); ++i) {
        length = swprintf(cursor, capacity - (size_t)(cursor - environment),
            L"%ls=%ls", names[i], values[i]);
        if (length < 0) { free(environment); return NULL; }
        cursor += length + 1;
    }
    *cursor = L'\0';
    return environment;
}

static int controller(const wchar_t *backend_argument) {
    Security security = {0};
    Child fixture = {0}, backend = {0};
    HWINSTA station = NULL;
    HDESK desktop = NULL;
    HANDLE job = NULL;
    wchar_t *station_name = NULL, *desktop_path = NULL, *environment = NULL;
    wchar_t self[32768], backend_path[32768], temporary[32768], directory[32768] = {0};
    wchar_t requested_station[128];
    BOOL directory_created = FALSE, success = FALSE;
    LARGE_INTEGER tick;
    if (!QueryPerformanceCounter(&tick)) return 2;
    uint64_t generation = ((uint64_t)tick.QuadPart ^ ((uint64_t)GetCurrentProcessId() << 32)) & INT64_MAX;
    if (!generation) generation = 1;
    BOOL absolute = (backend_argument[0] && backend_argument[1] == L':' &&
        (backend_argument[2] == L'\\' || backend_argument[2] == L'/')) ||
        (backend_argument[0] == L'\\' && backend_argument[1] == L'\\');
    if (!absolute || wcschr(backend_argument, L'"')) {
        fprintf(stderr, "An explicit absolute backend executable path is required.\n");
        goto done;
    }
    DWORD length = GetFullPathNameW(backend_argument, COUNT_OF(backend_path), backend_path, NULL);
    if (!length || length >= COUNT_OF(backend_path)) goto done;
    DWORD attributes = GetFileAttributesW(backend_path);
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY)) goto done;
    length = GetModuleFileNameW(NULL, self, COUNT_OF(self));
    if (!length || length >= COUNT_OF(self) || !logon_security(&security)) goto done;
    length = GetTempPathW(COUNT_OF(temporary), temporary);
    if (!length || length >= COUNT_OF(temporary) ||
        swprintf(directory, COUNT_OF(directory), L"%lsmaka-cua-private-%lu-%llu",
            temporary, GetCurrentProcessId(), (unsigned long long)generation) < 0 ||
        !CreateDirectoryW(directory, &security.attributes)) {
        api_error("CreateDirectoryW(private working directory)");
        goto done;
    }
    directory_created = TRUE;
    environment = child_environment(directory);
    if (!environment) goto done;
    if (swprintf(requested_station, COUNT_OF(requested_station), L"MakaCuaPrivate-%lu-%llu",
            GetCurrentProcessId(), (unsigned long long)generation) < 0) goto done;
    // A fresh task name avoids reopening the existing logon-session station.
    station = CreateWindowStationW(requested_station, CWF_CREATE_ONLY,
        WINSTA_ALL_ACCESS, &security.attributes);
    if (!station) { api_error("CreateWindowStationW(CWF_CREATE_ONLY)"); goto done; }
    station_name = object_name(station);
    USEROBJECTFLAGS flags = {0};
    DWORD bytes = 0;
    if (!station_name || wcscmp(station_name, requested_station) != 0 ||
        !*station_name || wcschr(station_name, L'"') ||
        _wcsicmp(station_name, L"WinSta0") == 0 ||
        !GetUserObjectInformationW(station, UOI_FLAGS, &flags, sizeof(flags), &bytes) ||
        (flags.dwFlags & WSF_VISIBLE) || !SetProcessWindowStation(station)) {
        fprintf(stderr, "Refused: the fresh station is not private or could not be selected.\n");
        goto done;
    }
    desktop = CreateDesktopW(L"Default", NULL, NULL, 0,
        DESKTOP_CREATEWINDOW | DESKTOP_CREATEMENU | DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS,
        &security.attributes);
    if (!desktop || !SetThreadDesktop(desktop) || !verify_private_context(station_name)) goto done;
    size_t desktop_chars = wcslen(station_name) + wcslen(L"\\Default") + 1;
    desktop_path = calloc(desktop_chars, sizeof(wchar_t));
    if (!desktop_path || swprintf(desktop_path, desktop_chars, L"%ls\\Default", station_name) < 0) goto done;
    job = CreateJobObjectW(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!job || !SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) goto done;
    if (!launch_fixture(&fixture, self, station_name, desktop_path, environment, directory,
            job, &security, generation)) goto done;
    Ready ready = {0};
    if (!read_ready(&fixture, &ready) || ready.generation != generation ||
        !oracles(&ready, initial_text, 0) ||
        !launch_backend(&backend, backend_path, station_name, desktop_path, environment,
            directory, job, &security)) goto done;
    if (!request(&backend, &ready, "observe", TRUE) || !oracles(&ready, initial_text, 0) ||
        !request(&backend, &ready, "set_value", TRUE) || !await_oracles(&ready, final_text, 0) ||
        !request(&backend, &ready, "invoke", TRUE) || !await_oracles(&ready, final_text, 1) ||
        !request(&backend, &ready, "quit", TRUE) || !wait_child(&backend, 0)) goto done;
    close_child(&backend);
    memset(&backend, 0, sizeof(backend));
    // A separate refusal case: no command follows a refused operation.
    if (!launch_backend(&backend, backend_path, station_name, desktop_path, environment,
            directory, job, &security)) goto done;
    Ready stale = ready;
    ++stale.generation;
    if (!request(&backend, &stale, "observe", FALSE) || !wait_child(&backend, 2) ||
        !oracles(&ready, final_text, 1) ||
        !fixture_identity(&ready)) goto done;
    if (!PostMessageW((HWND)(UINT_PTR)ready.hwnd, FIXTURE_QUIT, (WPARAM)generation, 0) ||
        !wait_child(&fixture, 0)) goto done;
    success = TRUE;
done:
    // The job contains only the children created suspended above.
    if (job && !TerminateJobObject(job, 2)) success = FALSE;
    Child *children[] = {&backend, &fixture};
    for (size_t i = 0; i < COUNT_OF(children); ++i) {
        if (children[i]->process.hProcess &&
            WaitForSingleObject(children[i]->process.hProcess, 0) == WAIT_TIMEOUT &&
            !TerminateProcess(children[i]->process.hProcess, 2)) success = FALSE;
        if (children[i]->process.hProcess &&
            WaitForSingleObject(children[i]->process.hProcess, OPERATION_TIMEOUT_MS) != WAIT_OBJECT_0)
            success = FALSE;
        close_child(children[i]);
    }
    close_handle(&job);
    if (directory_created && !RemoveDirectoryW(directory)) {
        fwprintf(stderr, L"Private working directory retained: %ls\n", directory);
        success = FALSE;
    }
    free(environment);
    free(desktop_path);
    free(station_name);
    if (security.acl) LocalFree(security.acl);
    free(security.groups);
    // Never reconnect to an interactive station to close assigned USER handles.
    // Windows releases this process's station/desktop references on process exit.
    if (success) puts("{\"private_fixture\":\"passed\",\"value_oracle\":true,\"counter_oracle\":true,\"generation_oracle\":true}");
    return success ? 0 : 2;
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 6 && wcscmp(argv[1], L"--fixture-child") == 0 &&
        wcscmp(argv[2], L"--station") == 0 && wcscmp(argv[4], L"--generation") == 0) {
        wchar_t *end = NULL;
        uint64_t generation = wcstoull(argv[5], &end, 10);
        return !end || *end || !generation ? 2 : fixture_child(argv[3], generation);
    }
    if (argc != 4 || wcscmp(argv[1], L"--private-fixture") != 0 ||
        wcscmp(argv[2], L"--backend") != 0) {
        fputs("Source fixture opt-in: fixture.exe --private-fixture --backend C:\\absolute\\private_uia_backend.exe\n", stderr);
        return 2;
    }
    return controller(argv[3]);
}
