#pragma once

// USB 儲存裝置是否允許使用；driverInstalled 回傳這台電腦是否裝過隨身碟驅動程式
bool UsbIsEnabled(bool* driverInstalled);
// 開 = 允許使用，關 = 停用。失敗回傳 false
bool UsbSetEnabled(bool on);
