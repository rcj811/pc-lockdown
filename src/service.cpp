#include <windows.h>
#include <shlobj.h>
#include <stdio.h>
#include "service.h"
#include "items.h"
#include "sys.h"
#include "reg.h"
#include "tray.h"

static SERVICE_STATUS_HANDLE gStatusHandle;
static SERVICE_STATUS gStatus;
static HANDLE gStopEvent;
static volatile LONG gResumed = 0;

static void ReportStatus(DWORD state) {
    gStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    gStatus.dwCurrentState = state;
    gStatus.dwControlsAccepted = (state == SERVICE_RUNNING) ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_POWEREVENT : 0;
    gStatus.dwWin32ExitCode = NO_ERROR;
    gStatus.dwWaitHint = 10000;
    SetServiceStatus(gStatusHandle, &gStatus);
}

static DWORD WINAPI CtrlHandler(DWORD ctrl, DWORD evt, LPVOID, LPVOID) {
    // 從睡眠／休眠醒來：通知時間看守以目前時間重新計算
    if (ctrl == SERVICE_CONTROL_POWEREVENT && (evt == 0x7 /*PBT_APMRESUMESUSPEND*/ || evt == 0x12 /*PBT_APMRESUMEAUTOMATIC*/))
        InterlockedExchange(&gResumed, 1);
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        ReportStatus(SERVICE_STOP_PENDING);
        SetEvent(gStopEvent);
    }
    return NO_ERROR;
}

static DWORD WINAPI TimeGuardThread(LPVOID) {
    TimeGuardLoop(gStopEvent, &gResumed);
    return 0;
}

static void WINAPI ServiceMain(DWORD, LPWSTR*) {
    gStatusHandle = RegisterServiceCtrlHandlerExW(SERVICE_NAME, CtrlHandler, NULL);
    if (!gStatusHandle) return;
    gStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    ReportStatus(SERVICE_RUNNING);
    HANDLE timeThread = CreateThread(NULL, 0, TimeGuardThread, NULL, 0, NULL);
    // 每 5 秒檢查一次：設定為「關」的項目被改掉就改回來
    do {
        ItemEnforceAll();
    } while (WaitForSingleObject(gStopEvent, 5000) == WAIT_TIMEOUT);
    if (timeThread) { WaitForSingleObject(timeThread, 5000); CloseHandle(timeThread); }
    ReportStatus(SERVICE_STOPPED);
}

int RunAsService() {
    SERVICE_TABLE_ENTRYW table[] = { { (LPWSTR)SERVICE_NAME, ServiceMain }, { NULL, NULL } };
    return StartServiceCtrlDispatcherW(table) ? 0 : 1;
}

// ───────── 安裝 / 移除 ─────────

static void InstallDir(wchar_t* out, int cch) {
    ExpandEnvironmentStringsW(L"%ProgramFiles%\\PcLockdown", out, cch);
}

static void InstalledExe(wchar_t* out, int cch) {
    wchar_t dir[MAX_PATH];
    InstallDir(dir, MAX_PATH);
    _snwprintf(out, cch - 1, L"%ls\\PcLockdown.exe", dir); out[cch - 1] = 0;
}

static bool SameFile(const wchar_t* a, const wchar_t* b) {
    HANDLE fa = CreateFileW(a, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE fb = CreateFileW(b, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    bool same = false;
    if (fa != INVALID_HANDLE_VALUE && fb != INVALID_HANDLE_VALUE &&
        GetFileSize(fa, NULL) == GetFileSize(fb, NULL)) {
        same = true;
        static BYTE ba[8192], bb[8192];
        DWORD ra, rb;
        while (same && ReadFile(fa, ba, sizeof(ba), &ra, NULL) && ReadFile(fb, bb, sizeof(bb), &rb, NULL) && ra) {
            if (ra != rb || memcmp(ba, bb, ra) != 0) same = false;
        }
    }
    if (fa != INVALID_HANDLE_VALUE) CloseHandle(fa);
    if (fb != INVALID_HANDLE_VALUE) CloseHandle(fb);
    return same;
}

static void StopService(SC_HANDLE svc) {
    SERVICE_STATUS st;
    if (!QueryServiceStatus(svc, &st) || st.dwCurrentState == SERVICE_STOPPED) return;
    ControlService(svc, SERVICE_CONTROL_STOP, &st);
    for (int i = 0; i < 50; i++) {
        Sleep(200);
        if (QueryServiceStatus(svc, &st) && st.dwCurrentState == SERVICE_STOPPED) break;
    }
}

static void ShortcutPath(wchar_t* out, int cch) {
    wchar_t dir[MAX_PATH] = {0};
    SHGetFolderPathW(NULL, CSIDL_COMMON_PROGRAMS, NULL, 0, dir);
    // 舊版（v1.0~v1.2）建立的捷徑名稱，只用來刪除
    _snwprintf(out, cch - 1, L"%ls\\PC Lockdown 電腦權限管理.lnk", dir); out[cch - 1] = 0;
}

// 開機自動載入右下角圖示（HKLM\\...\\Run，所有使用者登入時都會啟動）
static const wchar_t* kRunKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

static void RegisterAutoStart(const wchar_t* target) {
    wchar_t cmd[MAX_PATH + 32];
    _snwprintf(cmd, MAX_PATH + 31, L"\"%ls\" /tray", target); cmd[MAX_PATH + 31] = 0;
    RegWriteString(HKEY_LOCAL_MACHINE, kRunKey, L"PcLockdown", cmd);
}

void GetInstalledExe(wchar_t* out, int cch) { InstalledExe(out, cch); }

bool InstallService(wchar_t* err, int cch) {
    wchar_t self[MAX_PATH], dir[MAX_PATH], target[MAX_PATH], bin[MAX_PATH + 32];
    GetModuleFileNameW(NULL, self, MAX_PATH);
    InstallDir(dir, MAX_PATH);
    InstalledExe(target, MAX_PATH);
    _snwprintf(bin, MAX_PATH + 31, L"\"%ls\" /service", target); bin[MAX_PATH + 31] = 0;

    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) { _snwprintf(err, cch - 1, L"無法開啟服務管理員（錯誤 %lu）", GetLastError()); return false; }
    SC_HANDLE svc = OpenServiceW(scm, SERVICE_NAME, SERVICE_ALL_ACCESS);

    // 需要更新程式檔案時，先停止服務
    bool needCopy = lstrcmpiW(self, target) != 0 && !SameFile(self, target);
    if (needCopy) {
        if (svc) StopService(svc);
        CreateDirectoryW(dir, NULL);
        bool copied = false;
        for (int i = 0; i < 10 && !copied; i++) {
            copied = CopyFileW(self, target, FALSE) != 0;
            if (!copied) Sleep(300);
        }
        if (!copied) {
            _snwprintf(err, cch - 1, L"無法複製程式到 %ls（錯誤 %lu）", target, GetLastError());
            if (svc) CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return false;
        }
    }

    // 移除「從網際網路下載」標記（Zone.Identifier），否則 XP 每次啟動都跳「安全性警告」
    wchar_t ads[MAX_PATH + 32];
    _snwprintf(ads, MAX_PATH + 31, L"%ls:Zone.Identifier", target); ads[MAX_PATH + 31] = 0;
    DeleteFileW(ads);
    _snwprintf(ads, MAX_PATH + 31, L"%ls:Zone.Identifier", self); ads[MAX_PATH + 31] = 0;
    DeleteFileW(ads);

    if (!svc) {
        svc = CreateServiceW(scm, SERVICE_NAME, L"Lockdown 防護服務", SERVICE_ALL_ACCESS,
                             SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                             bin, NULL, NULL, NULL, NULL, NULL);
        if (!svc) {
            _snwprintf(err, cch - 1, L"無法建立背景服務（錯誤 %lu）", GetLastError());
            CloseServiceHandle(scm);
            return false;
        }
    } else {
        ChangeServiceConfigW(svc, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                             bin, NULL, NULL, NULL, NULL, NULL, L"Lockdown 防護服務");
    }
    SERVICE_DESCRIPTIONW desc = { (LPWSTR)L"維持 Lockdown 的權限設定，被修改時自動恢復。" };
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &desc);
    // 服務意外結束時自動重新啟動
    SC_ACTION acts[3] = { { SC_ACTION_RESTART, 5000 }, { SC_ACTION_RESTART, 5000 }, { SC_ACTION_RESTART, 5000 } };
    SERVICE_FAILURE_ACTIONSW fa; ZeroMemory(&fa, sizeof(fa));
    fa.dwResetPeriod = 86400; fa.cActions = 3; fa.lpsaActions = acts;
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);

    SERVICE_STATUS st;
    if (QueryServiceStatus(svc, &st) && st.dwCurrentState == SERVICE_STOPPED)
        StartServiceW(svc, 0, NULL);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    // 舊版建立的開始功能表捷徑：刪掉
    wchar_t lnk[MAX_PATH];
    ShortcutPath(lnk, MAX_PATH);
    DeleteFileW(lnk);
    RegisterAutoStart(target);
    return true;
}

void UninstallService() {
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm) {
        SC_HANDLE svc = OpenServiceW(scm, SERVICE_NAME, SERVICE_ALL_ACCESS);
        if (svc) {
            StopService(svc);
            DeleteService(svc);
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }
    wchar_t self[MAX_PATH], target[MAX_PATH], dir[MAX_PATH], lnk[MAX_PATH];
    GetModuleFileNameW(NULL, self, MAX_PATH);
    InstalledExe(target, MAX_PATH);
    InstallDir(dir, MAX_PATH);
    ShortcutPath(lnk, MAX_PATH);
    DeleteFileW(lnk);
    RegDeleteValueAt(HKEY_LOCAL_MACHINE, kRunKey, L"PcLockdown");
    CloseTrayIcons();
    if (lstrcmpiW(self, target) == 0) {
        // 正在執行的就是安裝的那份：重新開機後刪除
        MoveFileExW(target, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
        MoveFileExW(dir, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
    } else {
        DeleteFileW(target);
        RemoveDirectoryW(dir);
    }
}

void StopProtection() {
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm) {
        SC_HANDLE svc = OpenServiceW(scm, SERVICE_NAME, SERVICE_ALL_ACCESS);
        if (svc) {
            StopService(svc);
            // 改成手動啟動：重新開機也不會自動執行，直到再次執行本程式
            ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_NO_CHANGE,
                                 NULL, NULL, NULL, NULL, NULL, NULL, NULL);
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }
    RegDeleteValueAt(HKEY_LOCAL_MACHINE, kRunKey, L"PcLockdown");
}
