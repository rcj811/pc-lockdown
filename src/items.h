#pragma once

// 每一個開關項目。開 = 允許使用，關 = 禁止
enum ItemId {
    ITEM_USB = 0,      // USB 隨身碟、外接硬碟、手機
    ITEM_CDROM,        // 光碟機
    ITEM_INSTALL,      // 安裝軟體
    ITEM_TIME,         // 調整時間
    ITEM_INTERNET,     // 上網（內網不受影響）
    ITEM_TASKMGR,      // 工作管理員
    ITEM_REGEDIT,      // 登錄編輯器
    ITEM_CMD,          // 命令提示字元
    ITEM_CONTROL,      // 控制台
    ITEM_COUNT
};

struct ItemInfo {
    const wchar_t* label;   // 畫面上顯示的名稱
    const wchar_t* key;     // 存放設定用的名稱
    const wchar_t* offNote; // 關閉後需要提醒的事（NULL = 不用提醒）
    const wchar_t* onNote;  // 打開後需要提醒的事
};

extern const ItemInfo kItems[ITEM_COUNT];
extern const wchar_t* kAppKey;  // HKLM\SOFTWARE\PcLockdown

// 讀取目前設定（開 = true）
bool ItemGetAllowed(int id);
// 切換：寫入設定並立即套用。失敗回傳 false
bool ItemSet(int id, bool allow);
// 背景服務呼叫：所有「關」的項目重新強制套用（被改掉就改回來）
void ItemEnforceAll();
// 第一次執行時，依系統目前狀態建立初始設定
void ItemInitDefaults();
// 全部恢復為「開」（解除安裝用）
void ItemAllowAll();
