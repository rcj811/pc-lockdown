#include <windows.h>
#include <shellapi.h>
#include "tray.h"
#include "sys.h"
#include "service.h"
#include "app.h"

#define WM_TRAYICON (WM_APP + 1)
#define ID_OPEN 100

static NOTIFYICONDATAW gNid;
static UINT gTaskbarCreated;

static void AddIcon(HWND wnd) {
    ZeroMemory(&gNid, sizeof(gNid));
#ifdef NOTIFYICONDATAW_V2_SIZE
    gNid.cbSize = NOTIFYICONDATAW_V2_SIZE;  // XP 相容的結構大小
#else
    gNid.cbSize = sizeof(gNid);
#endif
    gNid.hWnd = wnd;
    gNid.uID = 1;
    gNid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    gNid.uCallbackMessage = WM_TRAYICON;
    gNid.hIcon = (HICON)LoadImageW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(1), IMAGE_ICON,
                                   GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0);
    lstrcpynW(gNid.szTip, L"Lockdown", 64);
    Shell_NotifyIconW(NIM_ADD, &gNid);
}

bool LaunchGui() {
    // 管理畫面已經開著：拉到最前面就好，不要再開一個
    HWND w = FindWindowW(NULL, APP_TITLE);
    if (w) {
        ShowWindow(w, SW_RESTORE);
        SetForegroundWindow(w);
        return true;
    }
    // 3 秒內重複點擊（正在等 UAC 或密碼視窗）不重複開啟
    static DWORD last = 0;
    DWORD now = GetTickCount();
    if (last && now - last < 3000) return true;
    last = now;

    wchar_t self[MAX_PATH];
    GetModuleFileNameW(NULL, self, MAX_PATH);
    SHELLEXECUTEINFOW sei; ZeroMemory(&sei, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOASYNC | 0x00800000;  // SEE_MASK_NOZONECHECKS：不要跳「安全性警告」
    // 已經是管理員（XP 管理員帳號）直接開；否則要求提升權限（Win7+ 跳 UAC，XP 跳「執行身分」）
    sei.lpVerb = IsAdmin() ? L"open" : L"runas";
    sei.lpFile = self;
    sei.lpParameters = L"/gui /elevated";
    sei.nShow = SW_SHOWNORMAL;
    return ShellExecuteExW(&sei) != FALSE;
}

void CloseTrayIcons() {
    for (int i = 0; i < 20; i++) {
        HWND w = FindWindowW(TRAY_CLASS, NULL);
        if (!w) break;
        SendMessageTimeoutW(w, WM_CLOSE, 0, 0, SMTO_ABORTIFHUNG, 2000, NULL);
    }
}

static LRESULT CALLBACK TrayProc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == gTaskbarCreated && gTaskbarCreated) {  // 檔案總管重新啟動後，把圖示加回來
        AddIcon(wnd);
        return 0;
    }
    switch (msg) {
    case WM_TRAYICON:
        if (lp == WM_LBUTTONUP) {
            LaunchGui();
        } else if (lp == WM_RBUTTONUP) {
            HMENU m = CreatePopupMenu();
            AppendMenuW(m, MF_STRING, ID_OPEN, L"開啟管理畫面");
            SetMenuDefaultItem(m, ID_OPEN, FALSE);
            POINT pt; GetCursorPos(&pt);
            SetForegroundWindow(wnd);
            int cmd = TrackPopupMenu(m, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, wnd, NULL);
            PostMessageW(wnd, WM_NULL, 0, 0);
            DestroyMenu(m);
            if (cmd == ID_OPEN) LaunchGui();
        }
        return 0;
    case WM_CLOSE:
        DestroyWindow(wnd);
        return 0;
    case WM_DESTROY:
        Shell_NotifyIconW(NIM_DELETE, &gNid);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(wnd, msg, wp, lp);
}

int RunTray() {
    HANDLE mtx = CreateMutexW(NULL, TRUE, TRAY_MUTEX);
    if (GetLastError() == ERROR_ALREADY_EXISTS) return 0;  // 已經有圖示了

    WNDCLASSW wc; ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = TrayProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = TRAY_CLASS;
    RegisterClassW(&wc);
    HWND wnd = CreateWindowW(TRAY_CLASS, L"", 0, 0, 0, 0, 0, NULL, NULL, wc.hInstance, NULL);
    if (!wnd) return 1;
    gTaskbarCreated = RegisterWindowMessageW(L"TaskbarCreated");

    // 開機時檔案總管可能還沒準備好，加圖示失敗就多試幾次
    for (int i = 0; i < 30; i++) {
        AddIcon(wnd);
        NOTIFYICONDATAW probe = gNid;
        if (Shell_NotifyIconW(NIM_MODIFY, &probe)) break;
        Sleep(2000);
    }

    MSG m;
    while (GetMessageW(&m, NULL, 0, 0) > 0) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    if (mtx) CloseHandle(mtx);
    return 0;
}

void EnsureTrayRunning() {
    HANDLE h = OpenMutexW(SYNCHRONIZE, FALSE, TRAY_MUTEX);
    if (h) { CloseHandle(h); return; }
    wchar_t exe[MAX_PATH], cmd[MAX_PATH + 32];
    GetInstalledExe(exe, MAX_PATH);
    if (GetFileAttributesW(exe) == INVALID_FILE_ATTRIBUTES) GetModuleFileNameW(NULL, exe, MAX_PATH);
    wsprintfW(cmd, L"\"%s\" /tray", exe);
    STARTUPINFOW si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
}
