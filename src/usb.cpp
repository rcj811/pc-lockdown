#include "usb.h"
#include "reg.h"

// USBSTOR：USB 大量儲存裝置驅動程式（XP ~ Win11）
// UASPStor：USB 3.0 UASP 隨身碟驅動程式（Win8 以後才有）
// Start = 3 啟用（需要時載入），Start = 4 停用
static const wchar_t* kUsbStor  = L"SYSTEM\\CurrentControlSet\\Services\\USBSTOR";
static const wchar_t* kUaspStor = L"SYSTEM\\CurrentControlSet\\Services\\UASPStor";
// 舊版曾用過的唯讀設定，開關時一律清除
static const wchar_t* kStoragePolicy = L"SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies";

bool UsbIsEnabled(bool* driverInstalled) {
    DWORD start = 0;
    bool has = RegReadDword(HKEY_LOCAL_MACHINE, kUsbStor, L"Start", &start);
    if (driverInstalled) *driverInstalled = has;
    if (!has) return true;  // 尚未插過隨身碟，驅動程式還沒安裝
    return start != 4;
}

bool UsbSetEnabled(bool on) {
    bool ok = true;
    DWORD start = on ? 3 : 4;
    // 驅動程式機碼不存在時不建立，避免產生不完整的服務設定
    if (RegKeyExists(HKEY_LOCAL_MACHINE, kUsbStor))
        ok &= RegWriteDword(HKEY_LOCAL_MACHINE, kUsbStor, L"Start", start);
    if (RegKeyExists(HKEY_LOCAL_MACHINE, kUaspStor))
        ok &= RegWriteDword(HKEY_LOCAL_MACHINE, kUaspStor, L"Start", start);
    DWORD wp = 0;
    if (RegReadDword(HKEY_LOCAL_MACHINE, kStoragePolicy, L"WriteProtect", &wp) && wp != 0)
        ok &= RegWriteDword(HKEY_LOCAL_MACHINE, kStoragePolicy, L"WriteProtect", 0);
    return ok;
}
