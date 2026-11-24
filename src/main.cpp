// PC Lockdown — Windows 權限開關
// 目標：Windows XP SP3 ~ Windows 11，單一 exe、免安裝執行環境
#include <windows.h>
#include <commctrl.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdint.h>
#include "resource.h"
#include "reg.h"
#include "sys.h"
#include "items.h"
#include "service.h"
#include "sha256.h"

#define APP_VERSION L"1.2.0"
static const wchar_t* kAppTitle = L"PC Lockdown 電腦權限管理 v" APP_VERSION;

// ───────── 密碼 ─────────

static void ToHex(const uint8_t* p, int n, wchar_t* out) {
    static const wchar_t* d = L"0123456789abcdef";
    for (int i = 0; i < n; i++) { out[i*2] = d[p[i] >> 4]; out[i*2+1] = d[p[i] & 15]; }
    out[n*2] = 0;
}

// 雜湊 = SHA256 重複 20000 次(salt + 密碼)，降低被暴力破解的速度
static void HashPassword(const wchar_t* salt, const wchar_t* pwd, wchar_t outHex[65]) {
    wchar_t buf[256];
    _snwprintf(buf, 255, L"%ls|%ls", salt, pwd);
    buf[255] = 0;
    uint8_t h[32];
    Sha256(buf, lstrlenW(buf) * sizeof(wchar_t), h);
    for (int i = 0; i < 20000; i++) Sha256(h, 32, h);
    ToHex(h, 32, outHex);
    SecureZeroMemory(buf, sizeof(buf));
}

static bool PasswordIsSet() {
    wchar_t tmp[80];
    return RegReadString(HKEY_LOCAL_MACHINE, kAppKey, L"PwdHash", tmp, 80) && tmp[0];
}

static bool SavePassword(const wchar_t* pwd) {
    uint8_t rnd[16];
    HCRYPTPROV prov;
    bool gotRandom = false;
    if (CryptAcquireContextW(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        gotRandom = CryptGenRandom(prov, sizeof(rnd), rnd) != 0;
        CryptReleaseContext(prov, 0);
    }
    if (!gotRandom) {  // 備援：時間 + 計數器
        LARGE_INTEGER c; QueryPerformanceCounter(&c);
        for (int i = 0; i < 16; i++) rnd[i] = (uint8_t)((c.QuadPart >> (i % 8 * 8)) ^ (GetTickCount() >> i));
    }
    wchar_t salt[33], hash[65];
    ToHex(rnd, 16, salt);
    HashPassword(salt, pwd, hash);
    return RegWriteString(HKEY_LOCAL_MACHINE, kAppKey, L"Salt", salt) &&
           RegWriteString(HKEY_LOCAL_MACHINE, kAppKey, L"PwdHash", hash);
}

static bool CheckPassword(const wchar_t* pwd) {
    wchar_t salt[80], stored[80], hash[65];
    if (!RegReadString(HKEY_LOCAL_MACHINE, kAppKey, L"Salt", salt, 80)) return false;
    if (!RegReadString(HKEY_LOCAL_MACHINE, kAppKey, L"PwdHash", stored, 80)) return false;
    HashPassword(salt, pwd, hash);
    return lstrcmpW(hash, stored) == 0;
}

// 密碼對話框：mode 0 = 驗證，mode 1 = 設定新密碼
struct PwdDlgData { int mode; int failures; };

static INT_PTR CALLBACK PwdDlgProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp) {
    PwdDlgData* d = (PwdDlgData*)GetWindowLongPtrW(dlg, DWLP_USER);
    switch (msg) {
    case WM_INITDIALOG: {
        SetWindowLongPtrW(dlg, DWLP_USER, lp);
        d = (PwdDlgData*)lp;
        SendDlgItemMessageW(dlg, IDC_PWD1, EM_LIMITTEXT, 64, 0);
        SendDlgItemMessageW(dlg, IDC_PWD2, EM_LIMITTEXT, 64, 0);
        SetDlgItemTextW(dlg, IDOK, L"確定");
        SetDlgItemTextW(dlg, IDCANCEL, L"取消");
        if (d->mode == 0) {
            SetWindowTextW(dlg, L"請輸入管理密碼");
            SetDlgItemTextW(dlg, IDC_PWD_LABEL1, L"管理密碼：");
            ShowWindow(GetDlgItem(dlg, IDC_PWD_LABEL2), SW_HIDE);
            ShowWindow(GetDlgItem(dlg, IDC_PWD2), SW_HIDE);
        } else {
            SetWindowTextW(dlg, L"設定管理密碼");
            SetDlgItemTextW(dlg, IDC_PWD_LABEL1, L"新密碼：");
            SetDlgItemTextW(dlg, IDC_PWD_LABEL2, L"再輸入一次：");
            SetDlgItemTextW(dlg, IDC_PWD_MSG, L"密碼至少 4 個字元，請務必記住。");
        }
        SetFocus(GetDlgItem(dlg, IDC_PWD1));
        return FALSE;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK) {
            wchar_t p1[80] = {0}, p2[80] = {0};
            GetDlgItemTextW(dlg, IDC_PWD1, p1, 80);
            GetDlgItemTextW(dlg, IDC_PWD2, p2, 80);
            if (d->mode == 0) {
                if (CheckPassword(p1)) { SecureZeroMemory(p1, sizeof(p1)); EndDialog(dlg, IDOK); return TRUE; }
                d->failures++;
                if (d->failures >= 5) { EndDialog(dlg, IDCANCEL); return TRUE; }
                SetDlgItemTextW(dlg, IDC_PWD_MSG, L"密碼錯誤，請重新輸入。");
                Sleep(800 * d->failures);  // 錯越多次等越久
                SetDlgItemTextW(dlg, IDC_PWD1, L"");
                SetFocus(GetDlgItem(dlg, IDC_PWD1));
            } else {
                if (lstrlenW(p1) < 4) {
                    SetDlgItemTextW(dlg, IDC_PWD_MSG, L"密碼太短，至少要 4 個字元。");
                } else if (lstrcmpW(p1, p2) != 0) {
                    SetDlgItemTextW(dlg, IDC_PWD_MSG, L"兩次輸入的密碼不一樣，請重新輸入。");
                } else if (!SavePassword(p1)) {
                    SetDlgItemTextW(dlg, IDC_PWD_MSG, L"儲存密碼失敗，請確認是用系統管理員身分執行。");
                } else {
                    SecureZeroMemory(p1, sizeof(p1)); SecureZeroMemory(p2, sizeof(p2));
                    EndDialog(dlg, IDOK);
                }
            }
            SecureZeroMemory(p1, sizeof(p1)); SecureZeroMemory(p2, sizeof(p2));
            return TRUE;
        }
        if (LOWORD(wp) == IDCANCEL) { EndDialog(dlg, IDCANCEL); return TRUE; }
        break;
    }
    return FALSE;
}

static bool RunPwdDialog(HWND parent, int mode) {
    PwdDlgData d = { mode, 0 };
    return DialogBoxParamW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(IDD_PWD), parent, PwdDlgProc, (LPARAM)&d) == IDOK;
}

// ───────── 主視窗 ─────────

// 開關按鈕：按下 = 開（可以使用），彈起 = 關（不能使用）
static void ShowToggle(HWND dlg, int id, bool on) {
    CheckDlgButton(dlg, IDC_TOGGLE0 + id, on ? BST_CHECKED : BST_UNCHECKED);
    SetDlgItemTextW(dlg, IDC_TOGGLE0 + id, on ? L"開" : L"關");
}

static void DoUninstall(HWND dlg) {
    if (MessageBoxW(dlg, L"確定要解除安裝嗎？\r\n所有項目都會恢復成「開」，背景服務也會移除。",
                    kAppTitle, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2) != IDYES) return;
    HCURSOR old = SetCursor(LoadCursorW(NULL, IDC_WAIT));
    UninstallService();          // 先停服務，避免它把設定改回去
    ItemAllowAll();
    RegDeleteTreeAt(HKEY_LOCAL_MACHINE, kAppKey);
    SetCursor(old);
    MessageBoxW(dlg, L"已解除安裝。部分項目要重新開機後才會完全恢復。", kAppTitle, MB_ICONINFORMATION);
    EndDialog(dlg, 0);
}

static INT_PTR CALLBACK MainDlgProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp) {
    (void)lp;
    switch (msg) {
    case WM_INITDIALOG: {
        SetWindowTextW(dlg, kAppTitle);
        for (int i = 0; i < ITEM_COUNT; i++) {
            SetDlgItemTextW(dlg, IDC_LABEL0 + i, kItems[i].label);
            ShowToggle(dlg, i, ItemGetAllowed(i));
        }
        SetDlgItemTextW(dlg, IDC_CHPWD, L"變更密碼");
        SetDlgItemTextW(dlg, IDC_UNINSTALL, L"解除安裝");
        SetDlgItemTextW(dlg, IDCANCEL, L"結束");
        wchar_t os[200];
        GetOsText(os, 200);
        SetDlgItemTextW(dlg, IDC_SYSINFO, os);
        HICON ic = LoadIconW(NULL, MAKEINTRESOURCEW(32518));  // IDI_SHIELD，XP 沒有時回傳 NULL
        if (!ic) ic = LoadIconW(NULL, IDI_APPLICATION);
        SendMessageW(dlg, WM_SETICON, ICON_BIG, (LPARAM)ic);
        SendMessageW(dlg, WM_SETICON, ICON_SMALL, (LPARAM)ic);
        return TRUE;
    }
    case WM_COMMAND: {
        int cid = LOWORD(wp);
        if (cid >= IDC_TOGGLE0 && cid < IDC_TOGGLE0 + ITEM_COUNT) {
            int id = cid - IDC_TOGGLE0;
            bool on = IsDlgButtonChecked(dlg, cid) == BST_CHECKED;
            HCURSOR old = SetCursor(LoadCursorW(NULL, IDC_WAIT));
            bool ok = ItemSet(id, on);
            SetCursor(old);
            ShowToggle(dlg, id, ItemGetAllowed(id));
            if (!ok) {
                MessageBoxW(dlg, L"設定失敗。", kAppTitle, MB_ICONERROR);
            } else {
                const wchar_t* note = on ? kItems[id].onNote : kItems[id].offNote;
                if (note) MessageBoxW(dlg, note, kItems[id].label, MB_ICONINFORMATION);
            }
            return TRUE;
        }
        switch (cid) {
        case IDC_CHPWD:
            if (RunPwdDialog(dlg, 1))
                MessageBoxW(dlg, L"密碼已變更。", kAppTitle, MB_ICONINFORMATION);
            return TRUE;
        case IDC_UNINSTALL:
            DoUninstall(dlg);
            return TRUE;
        case IDCANCEL:
            EndDialog(dlg, 0);
            return TRUE;
        }
        break;
    }
    }
    return FALSE;
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR cmd, int) {
    if (cmd && wcsstr(cmd, L"/service")) return RunAsService();

    // 同時只允許開一個
    HANDLE mtx = CreateMutexW(NULL, TRUE, L"PcLockdown_SingleInstance");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        HWND w = FindWindowW(NULL, kAppTitle);
        if (w) SetForegroundWindow(w);
        return 0;
    }

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_STANDARD_CLASSES };
    if (!InitCommonControlsEx(&icc)) InitCommonControls();

    if (!IsAdmin()) {
        MessageBoxW(NULL, L"請用「系統管理員」帳號執行本程式。", kAppTitle, MB_ICONERROR);
        return 1;
    }

    if (!PasswordIsSet()) {
        MessageBoxW(NULL, L"第一次使用，請先設定管理密碼。", kAppTitle, MB_ICONINFORMATION);
        if (!RunPwdDialog(NULL, 1)) return 0;
    } else if (!RunPwdDialog(NULL, 0)) {
        return 0;
    }

    ItemInitDefaults();
    wchar_t err[512] = {0};
    if (!InstallService(err, 512))
        MessageBoxW(NULL, err, L"背景服務安裝失敗", MB_ICONWARNING);

    DialogBoxParamW(inst, MAKEINTRESOURCEW(IDD_MAIN), NULL, MainDlgProc, 0);
    if (mtx) CloseHandle(mtx);
    return 0;
}
