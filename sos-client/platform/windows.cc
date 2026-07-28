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

// ── SYSTEM 令牌 ──

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
    if (!DuplicateTokenEx(TokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &NewToken)) {
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

// ── 输入桌面切换 ──

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

