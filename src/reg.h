#pragma once
#include <windows.h>

// 所有登錄機碼存取都加上 KEY_WOW64_64KEY：
// 32 位元程式在 64 位元 Windows 上才會寫到真正的位置，而不是 Wow6432Node
bool RegReadDword(HKEY root, const wchar_t* path, const wchar_t* name, DWORD* value);
bool RegWriteDword(HKEY root, const wchar_t* path, const wchar_t* name, DWORD value);
// 讀取 REG_SZ 或 REG_EXPAND_SZ（不展開）
bool RegReadString(HKEY root, const wchar_t* path, const wchar_t* name, wchar_t* buf, DWORD cch);
bool RegWriteString(HKEY root, const wchar_t* path, const wchar_t* name, const wchar_t* value);
bool RegWriteExpandString(HKEY root, const wchar_t* path, const wchar_t* name, const wchar_t* value);
// value 為以兩個 \0 結尾的多字串
bool RegWriteMultiSz(HKEY root, const wchar_t* path, const wchar_t* name, const wchar_t* value);
bool RegWriteBinary(HKEY root, const wchar_t* path, const wchar_t* name, const void* data, DWORD size);
// 讀取 REG_BINARY，大小必須剛好等於 size
bool RegReadBinary(HKEY root, const wchar_t* path, const wchar_t* name, void* data, DWORD size);
bool RegWriteQword(HKEY root, const wchar_t* path, const wchar_t* name, ULONGLONG value);
bool RegDeleteValueAt(HKEY root, const wchar_t* path, const wchar_t* name);
// 遞迴刪除整個機碼
bool RegDeleteTreeAt(HKEY root, const wchar_t* path);
bool RegKeyExists(HKEY root, const wchar_t* path);
