# PC Lockdown 電腦權限管理

Windows 電腦權限開關工具，支援 **Windows XP SP3 ~ Windows 11**。
單一 exe（約 30KB），不需要安裝 .NET 或任何執行環境。

## 下載

到 [Releases → latest](../../releases/tag/latest) 下載 `PcLockdown.exe`。

## 使用方式

1. 用**系統管理員**帳號執行 `PcLockdown.exe`（Win7 以後會自動跳出 UAC 確認）。
2. 第一次執行要設定管理密碼，之後每次開啟都要輸入。
3. 每一項一個開關：**開** = 可以使用，**關** = 不能使用，按下去立即生效。

## 目前功能（v0.2）

| 開關 | 做法 | 支援系統 |
|---|---|---|
| USB 隨身碟 | `USBSTOR`、`UASPStor` 服務的 Start 值（3 開 / 4 關） | XP SP3 ~ Win11 |

已經插著的隨身碟要拔掉重插才會生效；從沒插過隨身碟的電腦要先插一次才能關閉。

## 預定功能

- [ ] 禁止安裝軟體（DisableMSI + 軟體限制原則）
- [ ] 禁止調整時間（移除 SeSystemtimePrivilege）
- [ ] 封鎖 Internet、內網照常（XP：移除預設閘道；Win7+：防火牆輸出規則）、白名單
- [ ] 工作管理員 / 登錄編輯器 / 命令提示字元 / 控制台開關
- [ ] 背景服務：設定被改掉時自動恢復
- [ ] 設定匯出 / 匯入、靜默安裝
- [ ] 緊急解鎖碼

## 自行編譯

Linux（或 WSL）：

```sh
sudo apt-get install g++-mingw-w64-i686
./build.sh
```

輸出：`dist/PcLockdown.exe`

## 設定存放位置

`HKLM\SOFTWARE\PcLockdown`（Salt、PwdHash）。忘記密碼時，可用其他管理員帳號刪除這個機碼後重新設定。
