#include "sys.h"
#include "reg.h"
#include <stdio.h>

#ifndef KEY_WOW64_64KEY
#define KEY_WOW64_64KEY 0x0100
#endif

typedef LONG (WINAPI *RtlGetVersionFn)(OSVERSIONINFOEXW*);
typedef BOOL (WINAPI *IsWow64ProcessFn)(HANDLE, PBOOL);

static OSVERSIONINFOEXW GetVer() {
    static OSVERSIONINFOEXW v;
    static bool done = false;
    if (!done) {
        ZeroMemory(&v, sizeof(v)); v.dwOSVersionInfoSize = sizeof(v);
        RtlGetVersionFn rgv = (RtlGetVersionFn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
        if (!rgv || rgv(&v) != 0) GetVersionExW((OSVERSIONINFOW*)&v);
        done = true;
    }
    return v;
}

bool IsWindowsXP() { return GetVer().dwMajorVersion == 5; }

bool IsWow64() {
    BOOL wow = FALSE;
    IsWow64ProcessFn iw = (IsWow64ProcessFn)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process");
    if (iw) iw(GetCurrentProcess(), &wow);
    return wow != FALSE;
}

void GetOsText(wchar_t* out, int cch) {
    OSVERSIONINFOEXW v = GetVer();
    const wchar_t* name = L"Windows";
    DWORD M = v.dwMajorVersion, m = v.dwMinorVersion;
    if (M == 5 && m == 1) name = L"Windows XP";
    else if (M == 5 && m == 2) name = L"Windows XP x64 / Server 2003";
    else if (M == 6 && m == 0) name = L"Windows Vista";
    else if (M == 6 && m == 1) name = L"Windows 7";
    else if (M == 6 && m == 2) name = L"Windows 8";
    else if (M == 6 && m == 3) name = L"Windows 8.1";
    else if (M == 10) name = v.dwBuildNumber >= 22000 ? L"Windows 11" : L"Windows 10";
    _snwprintf(out, cch - 1, L"%ls %ls（%lu.%lu.%lu，%ls）", name, v.szCSDVersion,
               M, m, v.dwBuildNumber, IsWow64() ? L"64 位元" : L"32 位元");
    out[cch - 1] = 0;
}

bool IsAdmin() {
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID admins = NULL;
    BOOL member = FALSE;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                 0, 0, 0, 0, 0, 0, &admins)) {
        if (!CheckTokenMembership(NULL, admins, &member)) member = FALSE;
        FreeSid(admins);
    }
    return member != FALSE;
}

bool EnablePrivilege(const wchar_t* name) {
    HANDLE tok;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return false;
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool ok = LookupPrivilegeValueW(NULL, name, &tp.Privileges[0].Luid) &&
              AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL) &&
              GetLastError() == ERROR_SUCCESS;
    CloseHandle(tok);
    return ok;
}

void SystemExePath(const wchar_t* exe, wchar_t* out, int cch) {
    wchar_t dir[MAX_PATH];
    GetSystemDirectoryW(dir, MAX_PATH);
    _snwprintf(out, cch - 1, L"%ls\\%ls", dir, exe);
    out[cch - 1] = 0;
}

DWORD RunHidden(const wchar_t* cmdline, DWORD timeoutMs) {
    wchar_t buf[2048];
    lstrcpynW(buf, cmdline, 2048);
    STARTUPINFOW si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(NULL, buf, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return (DWORD)-1;
    DWORD code = (DWORD)-1;
    if (WaitForSingleObject(pi.hProcess, timeoutMs) == WAIT_OBJECT_0)
        GetExitCodeProcess(pi.hProcess, &code);
    else
        TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return code;
}

static bool IsUserSid(const wchar_t* s) {
    // 只處理一般使用者帳號 S-1-5-21-...（排除 _Classes）
    if (wcsncmp(s, L"S-1-5-21-", 9) != 0) return false;
    return wcsstr(s, L"_Classes") == NULL;
}

void ForEachUserHive(bool loadUnloaded, UserHiveFn fn, void* ctx) {
    fn(HKEY_LOCAL_MACHINE, ctx);

    // 1) 已載入（已登入）的使用者
    wchar_t name[256];
    for (DWORD i = 0;; i++) {
        DWORD cch = 256;
        if (RegEnumKeyExW(HKEY_USERS, i, name, &cch, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        if (!IsUserSid(name)) continue;
        HKEY k;
        if (RegOpenKeyExW(HKEY_USERS, name, 0, KEY_READ | KEY_WRITE, &k) == ERROR_SUCCESS) {
            fn(k, ctx);
            RegCloseKey(k);
        }
    }
    if (!loadUnloaded) return;

    // 2) 沒登入的使用者：暫時載入 NTUSER.DAT
    EnablePrivilege(L"SeBackupPrivilege");
    EnablePrivilege(L"SeRestorePrivilege");
    const wchar_t* plist = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
    HKEY pl;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, plist, 0, KEY_READ | KEY_WOW64_64KEY, &pl) != ERROR_SUCCESS) return;
    for (DWORD i = 0;; i++) {
        DWORD cch = 256;
        if (RegEnumKeyExW(pl, i, name, &cch, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        if (!IsUserSid(name)) continue;
        HKEY loaded;
        if (RegOpenKeyExW(HKEY_USERS, name, 0, KEY_READ, &loaded) == ERROR_SUCCESS) {  // 已處理過
            RegCloseKey(loaded);
            continue;
        }
        wchar_t sub[512], raw[MAX_PATH], path[MAX_PATH];
        _snwprintf(sub, 511, L"%ls\\%ls", plist, name); sub[511] = 0;
        if (!RegReadString(HKEY_LOCAL_MACHINE, sub, L"ProfileImagePath", raw, MAX_PATH)) continue;
        if (!ExpandEnvironmentStringsW(raw, path, MAX_PATH - 16)) continue;
        lstrcatW(path, L"\\NTUSER.DAT");
        if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) continue;
        const wchar_t* tmp = L"PcLockdown_Tmp";
        if (RegLoadKeyW(HKEY_USERS, tmp, path) != ERROR_SUCCESS) continue;
        HKEY k;
        if (RegOpenKeyExW(HKEY_USERS, tmp, 0, KEY_READ | KEY_WRITE, &k) == ERROR_SUCCESS) {
            fn(k, ctx);
            RegCloseKey(k);
        }
        RegUnLoadKeyW(HKEY_USERS, tmp);
    }
    RegCloseKey(pl);
}
