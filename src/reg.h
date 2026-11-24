#pragma once
#include <windows.h>

// 所有登錄機碼存取都加上 KEY_WOW64_64KEY：
// 32 位元程式在 64 位元 Windows 上才會寫到真正的位置，而不是 Wow6432Node
bool RegReadDword(HKEY root, const wchar_t* path, const wchar_t* name, DWORD* value);
bool RegWriteDword(HKEY root, const wchar_t* path, const wchar_t* name, DWORD value);
bool RegReadString(HKEY root, const wchar_t* path, const wchar_t* name, wchar_t* buf, DWORD cch);
bool RegWriteString(HKEY root, const wchar_t* path, const wchar_t* name, const wchar_t* value);
bool RegKeyExists(HKEY root, const wchar_t* path);
