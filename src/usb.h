#pragma once

enum UsbMode { USB_ALLOW = 0, USB_READONLY = 1, USB_BLOCK = 2, USB_UNKNOWN = -1 };

// 讀取目前 USB 儲存裝置狀態
UsbMode UsbGetMode(bool* driverInstalled);
// 套用 USB 模式，失敗回傳 false
bool UsbSetMode(UsbMode mode);
