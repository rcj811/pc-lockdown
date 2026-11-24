#pragma once

#define SERVICE_NAME L"PcLockdown"

// 以服務身分執行（PcLockdown.exe /service）
int RunAsService();
// 把程式複製到 Program Files、建立並啟動背景服務、建立開始功能表捷徑
// 回傳 false 時 err 會填入錯誤說明
bool InstallService(wchar_t* err, int cch);
// 停止並刪除服務、刪除複製的檔案與捷徑
void UninstallService();
