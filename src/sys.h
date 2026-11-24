#pragma once
#include <windows.h>

// 系統工具函式
bool IsWindowsXP();             // XP / Server 2003（5.x）
bool IsWow64();                 // 32 位元程式跑在 64 位元 Windows
void GetOsText(wchar_t* out, int cch);
bool IsAdmin();
bool EnablePrivilege(const wchar_t* name);
// 隱藏視窗執行指令，回傳結束代碼（失敗回傳 -1）
DWORD RunHidden(const wchar_t* cmdline, DWORD timeoutMs = 30000);
// 取得 System32 下的程式完整路徑
void SystemExePath(const wchar_t* exe, wchar_t* out, int cch);

// 對 HKLM 與所有使用者的 HKCU 套用同一個動作
// loadUnloaded = true 時，也會載入目前沒有登入的使用者設定檔
typedef void (*UserHiveFn)(HKEY root, void* ctx);
void ForEachUserHive(bool loadUnloaded, UserHiveFn fn, void* ctx);
