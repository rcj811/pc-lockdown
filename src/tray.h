#pragma once

#define TRAY_CLASS L"PcLockdownTray"
#define TRAY_MUTEX L"PcLockdown_Tray"

// 右下角圖示模式（PcLockdown.exe /tray）：開機自動載入，點圖示打開管理畫面
int RunTray();
// 以系統管理員身分開啟管理畫面（需要時跳出 UAC）
bool LaunchGui();
// 右下角圖示沒在執行就啟動它
void EnsureTrayRunning();
