#pragma once

#define SERVICE_NAME L"PcLockdown"

// 以服務身分執行（PcLockdown.exe /service）
int RunAsService();
// 把程式複製到 Program Files、建立並啟動背景服務、設定開機自動載入右下角圖示
// 回傳 false 時 err 會填入錯誤說明
bool InstallService(wchar_t* err, int cch);
// 停止並刪除服務、刪除複製的檔案與捷徑
void UninstallService();
// 結束：停止背景服務（改為手動啟動）、取消開機自動載入
void StopProtection();
// Program Files 裡安裝的程式路徑
void GetInstalledExe(wchar_t* out, int cch);
