#include "usb.h"
#include "reg.h"

// USBSTOR：USB 大量儲存裝置驅動程式（XP ~ Win11）
// UASPStor：USB 3.0 UASP 隨身碟驅動程式（Win8 以後才有）
// Start = 3 啟用（需要時載入），Start = 4 停用
static const wchar_t* kUsbStor  = L"SYSTEM\\CurrentControlSet\\Services\\USBSTOR";
static const wchar_t* kUaspStor = L"SYSTEM\\CurrentControlSet\\Services\\UASPStor";
// WriteProtect = 1 所有 USB 儲存裝置唯讀（XP SP2 以後）
static const wchar_t* kStoragePolicy = L"SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies";

UsbMode UsbGetMode(bool* driverInstalled) {
    DWORD start = 0, wp = 0;
    bool has = RegReadDword(HKEY_LOCAL_MACHINE, kUsbStor, L"Start", &start);
    if (driverInstalled) *driverInstalled = has;
    if (!has) return USB_ALLOW;  // 尚未插過隨身碟，驅動程式還沒安裝
    if (start == 4) return USB_BLOCK;
    RegReadDword(HKEY_LOCAL_MACHINE, kStoragePolicy, L"WriteProtect", &wp);
    return wp == 1 ? USB_READONLY : USB_ALLOW;
}

bool UsbSetMode(UsbMode mode) {
    bool ok = true;
    DWORD start = (mode == USB_BLOCK) ? 4 : 3;
    DWORD wp = (mode == USB_READONLY) ? 1 : 0;

    // 驅動程式機碼不存在時不建立，避免產生不完整的服務設定
    if (RegKeyExists(HKEY_LOCAL_MACHINE, kUsbStor))
        ok &= RegWriteDword(HKEY_LOCAL_MACHINE, kUsbStor, L"Start", start);
    if (RegKeyExists(HKEY_LOCAL_MACHINE, kUaspStor))
        ok &= RegWriteDword(HKEY_LOCAL_MACHINE, kUaspStor, L"Start", start);
    ok &= RegWriteDword(HKEY_LOCAL_MACHINE, kStoragePolicy, L"WriteProtect", wp);
    return ok;
}
