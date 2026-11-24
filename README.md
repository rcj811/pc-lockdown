# PC Lockdown 電腦權限管理

Windows 電腦權限開關工具，支援 **Windows XP SP3 ~ Windows 11**。
單一 exe（約 30KB），不需要安裝 .NET 或任何執行環境。

## 下載

到 [Releases → latest](../../releases/tag/latest) 下載 `PcLockdown.exe`。

## 使用方式

1. 用**系統管理員**帳號執行 `PcLockdown.exe`（Win7 以後會自動跳出 UAC 確認）。
2. 第一次執行要設定管理密碼，之後每次開啟都要輸入。
3. 每一項一個開關：**開** = 可以使用，**關** = 不能使用，按下去立即套用。
4. 第一次執行後，程式會自動複製到 `Program Files\PcLockdown`，並在「開始 → 程式集」建立「PC Lockdown 電腦權限管理」捷徑，之後從捷徑開啟。

## 開關項目（v1.0）

| 開關 | 關閉時的做法 | 生效時機 |
|---|---|---|
| USB 隨身碟 / 手機 | `USBSTOR`、`UASPStor` 停用；Vista+ 另擋手機（WPD） | 拔掉重插 |
| 光碟機 | `cdrom` 停用；Vista+ 另加讀寫拒絕原則 | 重新開機 |
| 安裝軟體 | `DisableMSI=2` + 軟體限制原則：使用者資料夾（桌面、文件、下載、AppData、暫存）的程式不能執行 | 登出再登入 |
| 調整時間 | 移除 Administrators / Power Users / Users 的「變更系統時間」權限（Vista+ 含時區） | 登出再登入 |
| 上網（內網照常） | XP：移除預設閘道，內網網段改走原閘道；Vista+：防火牆封鎖所有非內網位址 | 立即 |
| 工作管理員 | `DisableTaskMgr`（HKLM + 所有使用者） | 立即 |
| 登錄編輯器 | `DisableRegistryTools` | 立即 |
| 命令提示字元 | `DisableCMD=2`（批次檔仍可執行） | 立即 |
| 控制台 | `NoControlPanel` | 登出再登入 |

所有項目對管理員帳號也有效。

## 背景防護服務

「PC Lockdown 防護服務」每 5 秒檢查一次，設定為「關」的項目被別人改回來，會自動再關掉。
XP 斷網也靠它：DHCP 續約時會把預設閘道加回來，服務會再移除。

## 注意事項

- 「安裝軟體」關閉時，裝在使用者資料夾裡的程式（例如 LINE、使用者版 Chrome、OneDrive）也無法執行。
- 「安裝軟體」關閉時，下載到桌面或下載資料夾的 `PcLockdown.exe` 也跑不起來，請從開始功能表的捷徑開啟。
- 要更新本程式：先把「安裝軟體」打開，再執行新版。
- 「解除安裝」會把全部項目恢復成「開」並移除背景服務。

## 自行編譯

Linux（或 WSL）：

```sh
sudo apt-get install g++-mingw-w64-i686
./build.sh
```

輸出：`dist/PcLockdown.exe`

## 設定存放位置

`HKLM\SOFTWARE\PcLockdown`：Salt、PwdHash（管理密碼）、State 子機碼（各項開關，1 開 / 0 關）。

忘記密碼時，刪除 `PwdHash` 這個值，下次開啟就會要求重新設定密碼。
