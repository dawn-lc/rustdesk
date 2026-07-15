// SOS 便携服务使用的 Windows C++ 辅助函数
// 精简自 src/platform/windows.cc

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <tlhelp32.h>

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")

extern "C" {

// ── 桌面切换 ──
// selectInputDesktop 和 inputDesktopSelected 由上游 rustdesk 库提供

// ── 进程管理 ──

/// 获取登录会话中 explorer.exe 的 PID
DWORD GetLogonPid() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    DWORD pid = 0;

    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
                DWORD sessionId = 0;
                if (ProcessIdToSessionId(pe.th32ProcessID, &sessionId)) {
                    if (sessionId != 0) {
                        pid = pe.th32ProcessID;
                        break;
                    }
                }
            }
        } while (Process32NextW(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return pid;
}

/// 回退方案：获取 sihost.exe 的 PID
DWORD GetFallbackUserPid() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    DWORD pid = 0;

    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"sihost.exe") == 0) {
                DWORD sessionId = 0;
                if (ProcessIdToSessionId(pe.th32ProcessID, &sessionId)) {
                    if (sessionId != 0) {
                        pid = pe.th32ProcessID;
                        break;
                    }
                }
            }
        } while (Process32NextW(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return pid;
}

/// 获取会话用户令牌（通过用户进程的句柄获取令牌）
/// 此方法不需要 SYSTEM 权限，适合管理员进程使用。
HANDLE SosGetSessionUserTokenWin(DWORD dwSessionId) {
    HANDLE hToken = NULL;
    // 先尝试通过 explorer.exe 获取令牌
    DWORD Id = GetLogonPid();
    if (Id == 0) {
        Id = GetFallbackUserPid();
    }
    if (Id == 0) {
        return NULL;
    }
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, Id);
    if (!hProcess) {
        return NULL;
    }
    OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken);
    CloseHandle(hProcess);
    return hToken;
}

/// 在指定会话中以指定用户令牌启动进程
/// 返回进程句柄（失败返回 NULL(0)），调用方负责 CloseHandle
HANDLE SosLaunchProcessWin(LPCWSTR cmd, DWORD sessionId, HANDLE hToken) {
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi = { 0 };

    si.lpDesktop = (LPWSTR)L"winsta0\\default";
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;

    BOOL result = CreateProcessAsUserW(
        hToken,
        NULL,
        (LPWSTR)cmd,
        NULL,
        NULL,
        FALSE,
        NORMAL_PRIORITY_CLASS,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (result) {
        CloseHandle(pi.hThread);
        return pi.hProcess; // 返回进程句柄，调用方负责关闭
    }
    return NULL;
}

/// 终止进程并关闭句柄
BOOL TerminateProcessWin(HANDLE hProcess) {
    BOOL result = FALSE;
    if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
        result = TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
    }
    return result;
}


// ── 父子进程 IPC：持久命名管道 ──
//
// 子进程 (SYSTEM) 创建管道服务端，主进程作为客户端连接。
// 连接建立后子进程阻塞在 ReadFile 上——当主进程退出（正常或崩溃）时
// 管道自动断裂，ReadFile 返回 FALSE，子进程立即感知并自行退出。
// 无需轮询、无需 Mutex、无需 PID 传递。

/// 创建命名管道服务端（子进程/SYSTEM 端调用）
///
/// 安全模型：
/// - 管道创建于 SYSTEM 进程，默认 DACL 仅允许 SYSTEM + Administrators 访问
/// - 主进程以管理员身份运行，可通过 `ConnectIpcPipe` 正常连接
/// - 使用 `SECURITY_IDENTIFICATION` 客户端效验级别，防止客户端假冒服务器
/// - 连接后服务端可额外调用 `ImpersonateNamedPipeClient` 验证客户端身份
///
/// pipe_name e.g. L"\\\\.\\pipe\\RustDeskSOS"
/// 返回管道句柄，失败返回 INVALID_HANDLE_VALUE
HANDLE CreateIpcPipe(LPCWSTR pipe_name) {
    // 不设自定义 DACL — 使用 SYSTEM 进程的默认权限
    // 默认 DACL 仅允许 SYSTEM 和 Administrators，拒绝普通用户
    return CreateNamedPipeW(
        pipe_name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,              // 单实例
        4096, 4096,     // 缓冲区大小
        NMPWAIT_USE_DEFAULT_WAIT,
        NULL            // 使用默认安全属性
    );
}

/// 等待客户端连接（子进程/SYSTEM 端调用，阻塞直到连接建立）
/// 返回 TRUE=连接成功，FALSE=失败
BOOL AcceptIpcConnection(HANDLE hPipe) {
    return ConnectNamedPipe(hPipe, NULL) ? TRUE :
        (GetLastError() == ERROR_PIPE_CONNECTED ? TRUE : FALSE);
}

/// 阻塞等待管道断裂或收到关闭信号（子进程/SYSTEM 端调用）
/// ReadFile 阻塞读取 1 字节。
/// 返回 1=收到关闭信号（主进程正常退出），0=管道断裂（主进程崩溃）
/// 永远不会自行返回——要么收到数据（shutdown），要么管道断裂。
int WaitIpcSignal(HANDLE hPipe) {
    BYTE buf[1] = {0};
    DWORD read = 0;
    if (ReadFile(hPipe, buf, 1, &read, NULL)) {
        // 读到了数据 → 主进程发来了关闭信号
        return 1;
    } else {
        // 管道断裂 → 主进程已退出（正常或崩溃）
        return 0;
    }
}

/// 发送关闭信号并关闭管道（主进程调用）
void SignalAndCloseIpc(HANDLE hPipe) {
    if (hPipe && hPipe != INVALID_HANDLE_VALUE) {
        BYTE sig[1] = { 0x01 };
        DWORD written = 0;
        WriteFile(hPipe, sig, 1, &written, NULL);
        FlushFileBuffers(hPipe);
        CloseHandle(hPipe);
    }
}

/// 关闭 IPC 管道而不发送信号（主进程崩溃时由 OS 自动关闭）
void CloseIpcPipe(HANDLE hPipe) {
    if (hPipe && hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe);
    }
}

/// 客户端连接管道（主进程调用，失败时需重试）
/// pipe_name e.g. L"\\\\.\\pipe\\RustDeskSOS"
/// 返回管道句柄，失败返回 INVALID_HANDLE_VALUE
HANDLE ConnectIpcPipe(LPCWSTR pipe_name) {
    return CreateFileW(
        pipe_name,
        GENERIC_READ | GENERIC_WRITE,
        0,              // 独占
        NULL,
        OPEN_EXISTING,
        SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
        NULL
    );
}

// ── UAC 检测 ──

/// 检测 consent.exe（UAC 弹窗进程）是否正在运行
BOOL is_process_consent_running() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    BOOL found = FALSE;

    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"consent.exe") == 0) {
                found = TRUE;
                break;
            }
        } while (Process32NextW(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return found;
}

/// 获取交互会话中 winlogon.exe 的 SYSTEM 令牌
/// 返回主令牌句柄，失败返回 NULL。调用方负责 CloseHandle。
/// 包含 ImpersonateLoggedOnUser 步骤（与上游 StealToken 一致）。
HANDLE SosGetSystemTokenWin() {
    // 启用 SeDebugPrivilege（管理员进程默认持有此权限但被禁用）
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &tp.Privileges[0].Luid);
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        CloseHandle(hToken);
    }

    // 找交互 session（sessionId != 0）的 winlogon.exe
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return NULL;
    DWORD winlogonPid = 0;
    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0) {
                DWORD sessionId = 0;
                if (ProcessIdToSessionId(pe.th32ProcessID, &sessionId) && sessionId != 0) {
                    winlogonPid = pe.th32ProcessID;
                    break;
                }
            }
        } while (Process32NextW(snapshot, &pe));
    }
    CloseHandle(snapshot);
    if (winlogonPid == 0) return NULL;

    // 打开 winlogon 进程
    HANDLE hProcess = NULL;
    DWORD accessMasks[] = {
        PROCESS_ALL_ACCESS,
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        PROCESS_QUERY_INFORMATION
    };
    for (int i = 0; i < 3; i++) {
        hProcess = OpenProcess(accessMasks[i], FALSE, winlogonPid);
        if (hProcess) break;
    }
    if (!hProcess) return NULL;

    // 打开令牌
    hToken = NULL;
    DWORD tokenAccessMasks[] = {
        TOKEN_ALL_ACCESS,
        TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
        TOKEN_QUERY | TOKEN_DUPLICATE,
        TOKEN_QUERY
    };
    for (int i = 0; i < 4; i++) {
        if (OpenProcessToken(hProcess, tokenAccessMasks[i], &hToken)) {
            break;
        }
    }
    if (!hToken) {
        CloseHandle(hProcess);
        return NULL;
    }
    CloseHandle(hProcess);

    // ImpersonateLoggedOnUser — 与上游 StealToken 一致
    ImpersonateLoggedOnUser(hToken);

    // 复制令牌为主令牌
    HANDLE hDupToken = NULL;
    DWORD dupAccessMasks[] = {
        MAXIMUM_ALLOWED,
        TOKEN_ALL_ACCESS,
        TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY
    };
    for (int i = 0; i < 3; i++) {
        if (DuplicateTokenEx(hToken, dupAccessMasks[i], NULL, SecurityImpersonation,
                              TokenPrimary, &hDupToken)) {
            break;
        }
    }
    CloseHandle(hToken);
    return hDupToken;
}

/// 以 SYSTEM 身份在交互 session（session 1）中启动进程
/// 等效于上游的 impersonate_system::run_as_system，但按 sessionId 过滤 winlogon。
/// cmd: 完整的命令行（含 exe 路径和参数）
/// 返回进程句柄（调用者负责 CloseHandle），失败返回 0（NULL）。
intptr_t SosRunAsSystemInSession1(LPCWSTR cmd) {
    // 启用 SeDebugPrivilege
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &tp.Privileges[0].Luid);
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        CloseHandle(hToken);
    }

    // 找交互 session 的 winlogon
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    DWORD winlogonPid = 0;
    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0) {
                DWORD sessionId = 0;
                if (ProcessIdToSessionId(pe.th32ProcessID, &sessionId) && sessionId != 0) {
                    winlogonPid = pe.th32ProcessID;
                    break;
                }
            }
        } while (Process32NextW(snapshot, &pe));
    }
    CloseHandle(snapshot);
    if (winlogonPid == 0) return 0;

    // 打开 winlogon 进程
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, winlogonPid);
    if (!hProcess) return 0;

    // 打开其令牌
    HANDLE TokenHandle = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &TokenHandle)) {
        CloseHandle(hProcess);
        return 0;
    }
    CloseHandle(hProcess);

    // ImpersonateLoggedOnUser（与上游 StealToken 一致）
    ImpersonateLoggedOnUser(TokenHandle);

    // 复制令牌为主令牌
    HANDLE NewToken = NULL;
    if (!DuplicateTokenEx(TokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation,
                          TokenPrimary, &NewToken)) {
        CloseHandle(TokenHandle);
        return 0;
    }
    CloseHandle(TokenHandle);

    // 用该令牌创建进程
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.lpDesktop = (LPWSTR)L"winsta0\\default";

    // 获取当前目录作为进程工作目录
    wchar_t NPath[MAX_PATH];
    if (GetCurrentDirectory(MAX_PATH, NPath) == 0) {
        wcscpy_s(NPath, MAX_PATH, L"C:\\");
    }

    // 复制 cmd（CreateProcessWithTokenW 需要可写缓冲区）
    wchar_t cmdBuf[32768];
    wcscpy_s(cmdBuf, cmd);

    BOOL result = CreateProcessWithTokenW(
        NewToken,
        LOGON_WITH_PROFILE,
        NULL,           // 使用命令行中的 exe
        cmdBuf,
        0,              // 无特殊创建标志
        NULL,
        NPath,
        &si,
        &pi
    );

    CloseHandle(NewToken);

    if (!result) {
        return 0;
    }

    // 关闭线程句柄，保留进程句柄返回给调用者用于 WaitForSingleObject 监控
    CloseHandle(pi.hThread);
    return (intptr_t)pi.hProcess;
}

/// 启用 SeDebugPrivilege（返回 0=成功，-1=失败）
int SosEnableDebugPrivilege() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return -1;
    }
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return -1;
    }
    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hToken);
    if (!ok || err == ERROR_NOT_ALL_ASSIGNED) {
        return -1;
    }
    return 0;
}

/// 获取 winlogon.exe 的 SYSTEM 令牌（返回句柄，失败返回 NULL）
/// 与 SasGetSystemTokenWin 类似但使用更低权限的访问掩码
HANDLE SosImpersonateSystemToken() {
    // 启用 SeDebugPrivilege
    if (SosEnableDebugPrivilege() != 0) return NULL;

    // 查找 winlogon.exe
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return NULL;
    DWORD winlogonPid = 0;
    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0) {
                DWORD sessionId = 0;
                if (ProcessIdToSessionId(pe.th32ProcessID, &sessionId) && sessionId != 0) {
                    winlogonPid = pe.th32ProcessID;
                    break;
                }
            }
        } while (Process32NextW(snapshot, &pe));
    }
    CloseHandle(snapshot);
    if (winlogonPid == 0) return NULL;

    // 打开 winlogon 进程
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, winlogonPid);
    if (!hProcess) return NULL;

    // 打开其令牌
    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess,
            TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
            &hToken)) {
        CloseHandle(hProcess);
        return NULL;
    }
    CloseHandle(hProcess);

    // 模拟登录用户（使此线程以 SYSTEM 身份运行）
    if (!ImpersonateLoggedOnUser(hToken)) {
        CloseHandle(hToken);
        return NULL;
    }

    // 复制令牌为主令牌
    HANDLE hDupToken = NULL;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation,
                          TokenPrimary, &hDupToken)) {
        CloseHandle(hToken);
        return NULL;
    }
    CloseHandle(hToken);
    return hDupToken;
}

/// 恢复当前线程到原始安全上下文
void SosRevertToSelf() {
    RevertToSelf();
}

/// 以最低权限切换线程到输入桌面（安全桌面）
/// 使用 DESKTOP_READOBJECTS | DESKTOP_SWITCHDESKTOP 而不是 GENERIC_WRITE
/// 调用前需确保线程已 impersonate SYSTEM 或有足够权限
/// 返回 1=成功，0=失败
int SosSwitchToInputDesktop() {
    HDESK desktop = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS | DESKTOP_SWITCHDESKTOP);
    if (!desktop) {
        return 0;
    }
    if (!SetThreadDesktop(desktop)) {
        CloseDesktop(desktop);
        return 0;
    }
    CloseDesktop(desktop);
    return 1;
}

/// 返回 GetLastError 值（用于诊断）
DWORD SosGetLastError() {
    return GetLastError();
}

// ── 桌面切换事件监控 ──

static HANDLE s_hDesktopSwitchEvent = NULL;
static HWINEVENTHOOK s_hDesktopSwitchHook = NULL;

static VOID CALLBACK DesktopSwitchWinEventProc(
    HWINEVENTHOOK, DWORD, HWND, LONG, LONG, DWORD, DWORD)
{
    if (s_hDesktopSwitchEvent) {
        SetEvent(s_hDesktopSwitchEvent);
    }
}

static void EnsureDesktopSwitchHook()
{
    if (s_hDesktopSwitchHook) return;

    s_hDesktopSwitchEvent = CreateEventW(NULL, FALSE, FALSE, NULL); // auto-reset
    if (!s_hDesktopSwitchEvent) return;

    s_hDesktopSwitchHook = SetWinEventHook(
        EVENT_SYSTEM_DESKTOPSWITCH,
        EVENT_SYSTEM_DESKTOPSWITCH,
        NULL,
        DesktopSwitchWinEventProc,
        0, 0,
        WINEVENT_INCONTEXT       // 回调在消息泵线程内执行，可靠
    );
    if (!s_hDesktopSwitchHook) {
        CloseHandle(s_hDesktopSwitchEvent);
        s_hDesktopSwitchEvent = NULL;
    }
}

/// 阻塞等待下一次桌面切换，或 dwTimeout 毫秒超时。
/// 首次调用时注册 SetWinEventHook(WINEVENT_INCONTEXT) 并启动消息泵。
/// 返回 1=桌面已切换，0=超时，-1=错误/WM_QUIT。
int SosWaitForDesktopSwitch(DWORD dwTimeout)
{
    EnsureDesktopSwitchHook();
    if (!s_hDesktopSwitchHook || !s_hDesktopSwitchEvent) return -1;

    DWORD start = GetTickCount();
    for (;;) {
        DWORD elapsed = GetTickCount() - start;
        if (elapsed >= dwTimeout && dwTimeout != INFINITE) return 0;

        DWORD remaining = (dwTimeout == INFINITE) ? INFINITE : (dwTimeout - elapsed);

        // MsgWaitForMultipleObjects: 同时等事件 + 窗口消息
        DWORD ret = MsgWaitForMultipleObjects(
            1, &s_hDesktopSwitchEvent, FALSE, remaining, QS_ALLINPUT);

        if (ret == WAIT_OBJECT_0) {
            // 桌面切换事件已触发
            return 1;
        } else if (ret == WAIT_OBJECT_0 + 1) {
            // 有窗口消息 → 泵送（hook 回调在此触发）
            MSG msg;
            while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
                if (msg.message == WM_QUIT) return -1;
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            // 泵送完继续循环，检查事件是否被回调置位
        } else {
            return -1;
        }
    }
}

} // extern "C"

