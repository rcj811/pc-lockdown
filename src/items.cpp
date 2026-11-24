#include <windows.h>
#include <ntsecapi.h>
#include <iphlpapi.h>
#include <stdio.h>
#include "items.h"
#include "reg.h"
#include "sys.h"

const wchar_t* kAppKey = L"SOFTWARE\\PcLockdown";
static const wchar_t* kStateKey = L"SOFTWARE\\PcLockdown\\State";

const ItemInfo kItems[ITEM_COUNT] = {
    { L"USB 隨身碟 / 手機",  L"USB",      L"已經插著的裝置，拔掉重插後生效。", NULL },
    { L"光碟機",             L"CDROM",    L"重新開機後生效。", L"重新開機後生效。" },
    { L"安裝軟體",           L"Install",  L"使用者登出再登入後完全生效。", L"使用者登出再登入後完全生效。" },
    { L"調整時間",           L"Time",     L"使用者登出再登入後生效。", L"使用者登出再登入後生效。" },
    { L"上網（內網照常）",   L"Internet", NULL, NULL },
    { L"工作管理員",         L"TaskMgr",  NULL, NULL },
    { L"登錄編輯器",         L"Regedit",  NULL, NULL },
    { L"命令提示字元",       L"Cmd",      NULL, NULL },
    { L"控制台",             L"Control",  L"使用者登出再登入後生效。", L"使用者登出再登入後生效。" },
};

// ═════════ 1. USB 隨身碟 / 手機 ═════════
// USBSTOR（XP~Win11）、UASPStor（Win8+ 的 USB3 隨身碟）Start：3 開 / 4 關
// Vista 以後再加「卸除式存放裝置」原則，擋手機（MTP/WPD）
static const wchar_t* kUsbStor  = L"SYSTEM\\CurrentControlSet\\Services\\USBSTOR";
static const wchar_t* kUaspStor = L"SYSTEM\\CurrentControlSet\\Services\\UASPStor";
static const wchar_t* kRsdPolicy = L"SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices";
static const wchar_t* kWpdClasses[] = {
    L"{6AC27878-A6FA-4155-BA85-F98F491D4F33}",  // WPD 裝置（手機、相機）
    L"{F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE}",  // WPD 裝置
};

static bool UsbIsBlocked() {
    DWORD v = 0;
    return RegReadDword(HKEY_LOCAL_MACHINE, kUsbStor, L"Start", &v) && v == 4;
}

static bool UsbApply(bool allow) {
    bool ok = true;
    DWORD start = allow ? 3 : 4, v;
    if (RegKeyExists(HKEY_LOCAL_MACHINE, kUsbStor) &&
        !(RegReadDword(HKEY_LOCAL_MACHINE, kUsbStor, L"Start", &v) && v == start))
        ok &= RegWriteDword(HKEY_LOCAL_MACHINE, kUsbStor, L"Start", start);
    if (RegKeyExists(HKEY_LOCAL_MACHINE, kUaspStor) &&
        !(RegReadDword(HKEY_LOCAL_MACHINE, kUaspStor, L"Start", &v) && v == start))
        ok &= RegWriteDword(HKEY_LOCAL_MACHINE, kUaspStor, L"Start", start);
    // 清除 v0.1 測試版用過的唯讀設定
    const wchar_t* sdp = L"SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies";
    if (RegReadDword(HKEY_LOCAL_MACHINE, sdp, L"WriteProtect", &v) && v != 0)
        RegWriteDword(HKEY_LOCAL_MACHINE, sdp, L"WriteProtect", 0);
    if (!IsWindowsXP()) {
        for (int i = 0; i < 2; i++) {
            wchar_t p[256];
            _snwprintf(p, 255, L"%ls\\%ls", kRsdPolicy, kWpdClasses[i]); p[255] = 0;
            if (allow) {
                RegDeleteTreeAt(HKEY_LOCAL_MACHINE, p);
            } else {
                RegWriteDword(HKEY_LOCAL_MACHINE, p, L"Deny_Read", 1);
                RegWriteDword(HKEY_LOCAL_MACHINE, p, L"Deny_Write", 1);
            }
        }
    }
    return ok;
}

// ═════════ 2. 光碟機 ═════════
// cdrom 服務 Start：1 開 / 4 關（開機時載入，所以要重新開機）
// Vista 以後再加 CD/DVD 讀寫拒絕原則
static const wchar_t* kCdrom = L"SYSTEM\\CurrentControlSet\\Services\\cdrom";
static const wchar_t* kCdClass = L"{53f56308-b6bf-11d0-94f2-00a0c91efb8b}";

static bool CdromIsBlocked() {
    DWORD v = 0;
    return RegReadDword(HKEY_LOCAL_MACHINE, kCdrom, L"Start", &v) && v == 4;
}

static bool CdromApply(bool allow) {
    bool ok = true;
    DWORD start = allow ? 1 : 4, v;
    if (RegKeyExists(HKEY_LOCAL_MACHINE, kCdrom) &&
        !(RegReadDword(HKEY_LOCAL_MACHINE, kCdrom, L"Start", &v) && v == start))
        ok &= RegWriteDword(HKEY_LOCAL_MACHINE, kCdrom, L"Start", start);
    if (!IsWindowsXP()) {
        wchar_t p[256];
        _snwprintf(p, 255, L"%ls\\%ls", kRsdPolicy, kCdClass); p[255] = 0;
        if (allow) {
            RegDeleteTreeAt(HKEY_LOCAL_MACHINE, p);
        } else {
            RegWriteDword(HKEY_LOCAL_MACHINE, p, L"Deny_Read", 1);
            RegWriteDword(HKEY_LOCAL_MACHINE, p, L"Deny_Write", 1);
            RegWriteDword(HKEY_LOCAL_MACHINE, p, L"Deny_Execute", 1);
        }
    }
    return ok;
}

// ═════════ 3. 安裝軟體 ═════════
// (a) Windows Installer：DisableMSI = 2，所有人都不能安裝 .msi
// (b) 軟體限制原則（SRP）：禁止從使用者資料夾執行程式
//     （桌面、我的文件、下載、AppData、暫存），安裝檔、免安裝程式都跑不起來
//     C:\Windows、C:\Program Files 裡已經安裝好的程式不受影響
static const wchar_t* kMsiPolicy = L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer";
static const wchar_t* kSafer = L"SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers";
static const wchar_t* kSaferPaths = L"SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Paths";
struct SaferRule { const wchar_t* guid; const wchar_t* path; };
static const SaferRule kSaferRules[] = {
    { L"{5c3a1f00-7d2e-4b61-9c00-000000000001}", L"%USERPROFILE%" },
    { L"{5c3a1f00-7d2e-4b61-9c00-000000000002}", L"%APPDATA%" },
    { L"{5c3a1f00-7d2e-4b61-9c00-000000000003}", L"%HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Desktop%" },
    { L"{5c3a1f00-7d2e-4b61-9c00-000000000004}", L"%HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Personal%" },
};
// 受限制的檔案類型（拿掉 LNK、URL，桌面捷徑才能正常使用）
static const wchar_t kSaferTypes[] =
    L"ADE\0ADP\0BAS\0BAT\0CHM\0CMD\0COM\0CPL\0CRT\0EXE\0HLP\0HTA\0INF\0INS\0ISP\0"
    L"MDB\0MDE\0MSC\0MSI\0MSP\0MST\0OCX\0PCD\0PIF\0REG\0SCR\0SHS\0VB\0WSC\0\0";

static bool InstallIsBlocked() {
    DWORD v = 0;
    return RegReadDword(HKEY_LOCAL_MACHINE, kSafer, L"PcLockdown", &v) && v == 1;
}

static bool InstallApply(bool allow) {
    bool ok = true;
    if (allow) {
        RegDeleteValueAt(HKEY_LOCAL_MACHINE, kMsiPolicy, L"DisableMSI");
        // 只移除本程式建立的 SRP 設定
        DWORD mark = 0;
        if (RegReadDword(HKEY_LOCAL_MACHINE, kSafer, L"PcLockdown", &mark) && mark == 1)
            ok &= RegDeleteTreeAt(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\Safer");
        return ok;
    }
    DWORD v = 0;
    if (!(RegReadDword(HKEY_LOCAL_MACHINE, kMsiPolicy, L"DisableMSI", &v) && v == 2))
        ok &= RegWriteDword(HKEY_LOCAL_MACHINE, kMsiPolicy, L"DisableMSI", 2);
    if (InstallIsBlocked()) {
        // 已設定過：只檢查規則有沒有被刪
        wchar_t p[300];
        _snwprintf(p, 299, L"%ls\\%ls", kSaferPaths, kSaferRules[0].guid); p[299] = 0;
        if (RegKeyExists(HKEY_LOCAL_MACHINE, p)) return ok;
    }
    ok &= RegWriteDword(HKEY_LOCAL_MACHINE, kSafer, L"DefaultLevel", 0x40000);  // 預設不限制
    ok &= RegWriteDword(HKEY_LOCAL_MACHINE, kSafer, L"TransparentEnabled", 1);  // 不檢查 DLL
    ok &= RegWriteDword(HKEY_LOCAL_MACHINE, kSafer, L"PolicyScope", 0);         // 管理員也適用
    ok &= RegWriteDword(HKEY_LOCAL_MACHINE, kSafer, L"AuthenticodeEnabled", 0);
    ok &= RegWriteMultiSz(HKEY_LOCAL_MACHINE, kSafer, L"ExecutableTypes", kSaferTypes);
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    ULONGLONG now = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    for (size_t i = 0; i < sizeof(kSaferRules) / sizeof(kSaferRules[0]); i++) {
        wchar_t p[300];
        _snwprintf(p, 299, L"%ls\\%ls", kSaferPaths, kSaferRules[i].guid); p[299] = 0;
        ok &= RegWriteExpandString(HKEY_LOCAL_MACHINE, p, L"ItemData", kSaferRules[i].path);
        ok &= RegWriteDword(HKEY_LOCAL_MACHINE, p, L"SaferFlags", 0);
        ok &= RegWriteString(HKEY_LOCAL_MACHINE, p, L"Description", L"PC Lockdown");
        RegWriteQword(HKEY_LOCAL_MACHINE, p, L"LastModified", now);
    }
    ok &= RegWriteDword(HKEY_LOCAL_MACHINE, kSafer, L"PcLockdown", 1);
    return ok;
}

// ═════════ 4. 調整時間 ═════════
// 從 Administrators / Power Users / Users 移除「變更系統時間」權限（XP~Win11）
// Vista 以後再移除「變更時區」權限。LOCAL SERVICE 保留，自動校時照常運作
static PSID MakeSid(DWORD rid) {
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID sid = NULL;
    AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, rid, 0, 0, 0, 0, 0, 0, &sid);
    return sid;
}

static void InitLsaString(LSA_UNICODE_STRING* s, const wchar_t* text) {
    s->Buffer = (PWSTR)text;
    s->Length = (USHORT)(lstrlenW(text) * sizeof(wchar_t));
    s->MaximumLength = s->Length + sizeof(wchar_t);
}

static LSA_HANDLE OpenLsa() {
    LSA_OBJECT_ATTRIBUTES oa; ZeroMemory(&oa, sizeof(oa));
    LSA_HANDLE h = NULL;
    if (LsaOpenPolicy(NULL, &oa, POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT, &h) != 0) return NULL;
    return h;
}

static bool SidHasRight(LSA_HANDLE lsa, PSID sid, const wchar_t* right) {
    PLSA_UNICODE_STRING rights = NULL;
    ULONG count = 0;
    if (LsaEnumerateAccountRights(lsa, sid, &rights, &count) != 0) return false;
    bool found = false;
    for (ULONG i = 0; i < count; i++) {
        int n = rights[i].Length / sizeof(wchar_t);
        if (n == lstrlenW(right) && wcsncmp(rights[i].Buffer, right, n) == 0) { found = true; break; }
    }
    LsaFreeMemory(rights);
    return found;
}

static void SetRight(LSA_HANDLE lsa, PSID sid, const wchar_t* right, bool grant) {
    if (!sid) return;
    LSA_UNICODE_STRING s; InitLsaString(&s, right);
    if (grant) LsaAddAccountRights(lsa, sid, &s, 1);
    else       LsaRemoveAccountRights(lsa, sid, FALSE, &s, 1);
}

static bool TimeIsBlocked() {
    LSA_HANDLE lsa = OpenLsa();
    if (!lsa) return false;
    PSID admins = MakeSid(DOMAIN_ALIAS_RID_ADMINS);
    bool has = admins && SidHasRight(lsa, admins, L"SeSystemtimePrivilege");
    if (admins) FreeSid(admins);
    LsaClose(lsa);
    return !has;
}

static bool TimeApply(bool allow) {
    LSA_HANDLE lsa = OpenLsa();
    if (!lsa) return false;
    PSID admins = MakeSid(DOMAIN_ALIAS_RID_ADMINS);
    PSID power  = MakeSid(DOMAIN_ALIAS_RID_POWER_USERS);
    PSID users  = MakeSid(DOMAIN_ALIAS_RID_USERS);
    bool xp = IsWindowsXP();
    if (allow) {
        // 還原成 Windows 預設值
        SetRight(lsa, admins, L"SeSystemtimePrivilege", true);
        if (xp) SetRight(lsa, power, L"SeSystemtimePrivilege", true);
        if (!xp) {
            SetRight(lsa, admins, L"SeTimeZonePrivilege", true);
            SetRight(lsa, users, L"SeTimeZonePrivilege", true);
        }
    } else {
        PSID all[3] = { admins, power, users };
        for (int i = 0; i < 3; i++) {
            if (all[i] && SidHasRight(lsa, all[i], L"SeSystemtimePrivilege"))
                SetRight(lsa, all[i], L"SeSystemtimePrivilege", false);
            if (!xp && all[i] && SidHasRight(lsa, all[i], L"SeTimeZonePrivilege"))
                SetRight(lsa, all[i], L"SeTimeZonePrivilege", false);
        }
    }
    bool ok = admins && (SidHasRight(lsa, admins, L"SeSystemtimePrivilege") == allow);
    if (admins) FreeSid(admins);
    if (power) FreeSid(power);
    if (users) FreeSid(users);
    LsaClose(lsa);
    return ok;
}

// ═════════ 5. 上網（內網照常） ═════════
// Vista 以後：防火牆加一條「封鎖所有非內網位址」的輸出規則（封鎖規則優先於任何允許規則）
// XP：XP 防火牆無法擋輸出，改成刪除預設閘道路由；
//     先把 10.x / 172.16-31.x / 192.168.x 加路由指向原閘道，跨網段的內網仍可連線。
//     DHCP 續約會把預設閘道加回來，背景服務每 5 秒檢查一次。
static const wchar_t* kFwRule = L"PcLockdown-BlockInternet";
static const wchar_t* kInternetIPv4 =
    L"1.0.0.0-9.255.255.255,11.0.0.0-126.255.255.255,128.0.0.0-169.253.255.255,"
    L"169.255.0.0-172.15.255.255,172.32.0.0-192.167.255.255,192.169.0.0-223.255.255.255,2000::/3";

static DWORD Netsh(const wchar_t* args) {
    wchar_t exe[MAX_PATH], cmd[1024];
    SystemExePath(L"netsh.exe", exe, MAX_PATH);
    _snwprintf(cmd, 1023, L"\"%ls\" %ls", exe, args); cmd[1023] = 0;
    return RunHidden(cmd);
}

static bool FwRuleExists() {
    wchar_t a[256];
    _snwprintf(a, 255, L"advfirewall firewall show rule name=\"%ls\"", kFwRule); a[255] = 0;
    return Netsh(a) == 0;
}

static bool FwApply(bool allow) {
    wchar_t a[1024];
    _snwprintf(a, 1023, L"advfirewall firewall delete rule name=\"%ls\"", kFwRule); a[1023] = 0;
    Netsh(a);
    if (allow) return !FwRuleExists();
    Netsh(L"advfirewall set allprofiles state on");
    _snwprintf(a, 1023, L"advfirewall firewall add rule name=\"%ls\" dir=out action=block enable=yes "
                        L"profile=any remoteip=%ls", kFwRule, kInternetIPv4); a[1023] = 0;
    return Netsh(a) == 0;
}

static DWORD Ip(BYTE a, BYTE b, BYTE c, BYTE d) { return a | (b << 8) | (c << 16) | ((DWORD)d << 24); }
struct PrivRange { DWORD dest, mask; };
static const PrivRange kPrivRanges[3] = {
    { Ip(10,0,0,0),    Ip(255,0,0,0) },
    { Ip(172,16,0,0),  Ip(255,240,0,0) },
    { Ip(192,168,0,0), Ip(255,255,0,0) },
};

static MIB_IPFORWARDTABLE* GetRoutes() {
    ULONG size = 0;
    GetIpForwardTable(NULL, &size, FALSE);
    if (!size) return NULL;
    MIB_IPFORWARDTABLE* t = (MIB_IPFORWARDTABLE*)HeapAlloc(GetProcessHeap(), 0, size);
    if (t && GetIpForwardTable(t, &size, FALSE) != NO_ERROR) { HeapFree(GetProcessHeap(), 0, t); t = NULL; }
    return t;
}

static void AddRoute(DWORD dest, DWORD mask, DWORD gw, DWORD ifIndex, DWORD metric) {
    MIB_IPFORWARDROW r; ZeroMemory(&r, sizeof(r));
    r.dwForwardDest = dest; r.dwForwardMask = mask; r.dwForwardNextHop = gw;
    r.dwForwardIfIndex = ifIndex;
    r.dwForwardType = 4;   // MIB_IPROUTE_TYPE_INDIRECT
    r.dwForwardProto = 3;  // MIB_IPPROTO_NETMGMT
    r.dwForwardMetric1 = metric ? metric : 1;
    r.dwForwardMetric2 = r.dwForwardMetric3 = r.dwForwardMetric4 = r.dwForwardMetric5 = (DWORD)-1;
    CreateIpForwardEntry(&r);
}

// 移除預設閘道；回傳是否有做任何變更
static bool XpBlockInternet() {
    MIB_IPFORWARDTABLE* t = GetRoutes();
    if (!t) return false;
    bool changed = false;
    for (DWORD i = 0; i < t->dwNumEntries; i++) {
        MIB_IPFORWARDROW* r = &t->table[i];
        if (r->dwForwardDest != 0 || r->dwForwardMask != 0) continue;
        // 記住原閘道，之後恢復用
        RegWriteDword(HKEY_LOCAL_MACHINE, kAppKey, L"SavedGateway", r->dwForwardNextHop);
        RegWriteDword(HKEY_LOCAL_MACHINE, kAppKey, L"SavedIfIndex", r->dwForwardIfIndex);
        RegWriteDword(HKEY_LOCAL_MACHINE, kAppKey, L"SavedMetric", r->dwForwardMetric1);
        for (int k = 0; k < 3; k++)
            AddRoute(kPrivRanges[k].dest, kPrivRanges[k].mask, r->dwForwardNextHop,
                     r->dwForwardIfIndex, r->dwForwardMetric1);
        DeleteIpForwardEntry(r);
        changed = true;
    }
    HeapFree(GetProcessHeap(), 0, t);
    return changed;
}

static void XpAllowInternet() {
    DWORD gw = 0, ifx = 0, metric = 1;
    bool saved = RegReadDword(HKEY_LOCAL_MACHINE, kAppKey, L"SavedGateway", &gw) &&
                 RegReadDword(HKEY_LOCAL_MACHINE, kAppKey, L"SavedIfIndex", &ifx);
    RegReadDword(HKEY_LOCAL_MACHINE, kAppKey, L"SavedMetric", &metric);
    MIB_IPFORWARDTABLE* t = GetRoutes();
    bool hasDefault = false;
    if (t) {
        for (DWORD i = 0; i < t->dwNumEntries; i++) {
            MIB_IPFORWARDROW* r = &t->table[i];
            if (r->dwForwardDest == 0 && r->dwForwardMask == 0) { hasDefault = true; continue; }
            // 刪掉本程式加的內網路由
            for (int k = 0; k < 3; k++)
                if (saved && r->dwForwardDest == kPrivRanges[k].dest && r->dwForwardMask == kPrivRanges[k].mask &&
                    r->dwForwardNextHop == gw)
                    DeleteIpForwardEntry(r);
        }
        HeapFree(GetProcessHeap(), 0, t);
    }
    if (saved && !hasDefault) AddRoute(0, 0, gw, ifx, metric);
}

static bool InternetApply(bool allow) {
    if (IsWindowsXP()) {
        if (allow) XpAllowInternet(); else XpBlockInternet();
        return true;
    }
    return FwApply(allow);
}

// ═════════ 6~9. 工作管理員 / 登錄編輯器 / 命令提示字元 / 控制台 ═════════
// 寫在 HKLM 與每個使用者的 HKCU（管理員帳號也一樣會被擋）
struct PolicyValue { const wchar_t* path; const wchar_t* name; DWORD offValue; };
static const PolicyValue kPolTaskMgr = { L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"DisableTaskMgr", 1 };
static const PolicyValue kPolRegedit = { L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"DisableRegistryTools", 1 };
static const PolicyValue kPolCmd     = { L"Software\\Policies\\Microsoft\\Windows\\System", L"DisableCMD", 2 };  // 2 = 批次檔仍可執行
static const PolicyValue kPolControl = { L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"NoControlPanel", 1 };

struct PolicyCtx { const PolicyValue* pv; bool allow; bool ok; };

static void PolicyHiveFn(HKEY root, void* p) {
    PolicyCtx* c = (PolicyCtx*)p;
    DWORD v = 0;
    bool has = RegReadDword(root, c->pv->path, c->pv->name, &v);
    if (c->allow) {
        if (has) c->ok &= RegDeleteValueAt(root, c->pv->path, c->pv->name);
    } else if (!has || v != c->pv->offValue) {
        bool w = RegWriteDword(root, c->pv->path, c->pv->name, c->pv->offValue);
        if (root == HKEY_LOCAL_MACHINE) c->ok &= w;  // 個別使用者寫入失敗不視為整體失敗
    }
}

static bool PolicyApply(const PolicyValue* pv, bool allow, bool loadUnloaded) {
    PolicyCtx c = { pv, allow, true };
    ForEachUserHive(loadUnloaded, PolicyHiveFn, &c);
    return c.ok;
}

// ═════════ 共用 ═════════

static bool ApplyItem(int id, bool allow, bool full) {
    switch (id) {
    case ITEM_USB:      return UsbApply(allow);
    case ITEM_CDROM:    return CdromApply(allow);
    case ITEM_INSTALL:  return InstallApply(allow);
    case ITEM_TIME:     return TimeApply(allow);
    case ITEM_INTERNET: return InternetApply(allow);
    case ITEM_TASKMGR:  return PolicyApply(&kPolTaskMgr, allow, full);
    case ITEM_REGEDIT:  return PolicyApply(&kPolRegedit, allow, full);
    case ITEM_CMD:      return PolicyApply(&kPolCmd, allow, full);
    case ITEM_CONTROL:  return PolicyApply(&kPolControl, allow, full);
    }
    return false;
}

bool ItemGetAllowed(int id) {
    DWORD v = 1;
    if (!RegReadDword(HKEY_LOCAL_MACHINE, kStateKey, kItems[id].key, &v)) return true;
    return v != 0;
}

bool ItemSet(int id, bool allow) {
    // 先寫設定再套用：背景服務只會強制「關」的項目，不會跟這裡互相打架
    if (!RegWriteDword(HKEY_LOCAL_MACHINE, kStateKey, kItems[id].key, allow ? 1 : 0)) return false;
    bool ok = ApplyItem(id, allow, true);
    if (!ok) RegWriteDword(HKEY_LOCAL_MACHINE, kStateKey, kItems[id].key, allow ? 0 : 1);
    return ok;
}

void ItemEnforceAll() {
    static DWORD lastFwCheck = 0;
    for (int id = 0; id < ITEM_COUNT; id++) {
        if (ItemGetAllowed(id)) continue;
        if (id == ITEM_INTERNET && !IsWindowsXP()) {
            // 防火牆規則檢查較慢，每 60 秒一次
            DWORD now = GetTickCount();
            if (lastFwCheck && now - lastFwCheck < 60000) continue;
            lastFwCheck = now;
            if (!FwRuleExists()) FwApply(false);
            continue;
        }
        ApplyItem(id, false, false);
    }
}

void ItemInitDefaults() {
    if (RegKeyExists(HKEY_LOCAL_MACHINE, kStateKey)) return;
    // 依目前系統狀態建立設定（例如 USB 之前已經被關掉）
    RegWriteDword(HKEY_LOCAL_MACHINE, kStateKey, kItems[ITEM_USB].key, UsbIsBlocked() ? 0 : 1);
    RegWriteDword(HKEY_LOCAL_MACHINE, kStateKey, kItems[ITEM_CDROM].key, CdromIsBlocked() ? 0 : 1);
    RegWriteDword(HKEY_LOCAL_MACHINE, kStateKey, kItems[ITEM_INSTALL].key, InstallIsBlocked() ? 0 : 1);
    RegWriteDword(HKEY_LOCAL_MACHINE, kStateKey, kItems[ITEM_TIME].key, TimeIsBlocked() ? 0 : 1);
    RegWriteDword(HKEY_LOCAL_MACHINE, kStateKey, kItems[ITEM_INTERNET].key,
                  (!IsWindowsXP() && FwRuleExists()) ? 0 : 1);
    for (int id = ITEM_TASKMGR; id < ITEM_COUNT; id++)
        RegWriteDword(HKEY_LOCAL_MACHINE, kStateKey, kItems[id].key, 1);
}

void ItemAllowAll() {
    for (int id = 0; id < ITEM_COUNT; id++) {
        RegWriteDword(HKEY_LOCAL_MACHINE, kStateKey, kItems[id].key, 1);
        ApplyItem(id, true, true);
    }
}
