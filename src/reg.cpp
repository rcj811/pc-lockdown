#include "reg.h"

#ifndef KEY_WOW64_64KEY
#define KEY_WOW64_64KEY 0x0100
#endif

bool RegReadDword(HKEY root, const wchar_t* path, const wchar_t* name, DWORD* value) {
    HKEY k;
    if (RegOpenKeyExW(root, path, 0, KEY_READ | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS) return false;
    DWORD type = 0, size = sizeof(DWORD);
    LONG r = RegQueryValueExW(k, name, NULL, &type, (BYTE*)value, &size);
    RegCloseKey(k);
    return r == ERROR_SUCCESS && type == REG_DWORD;
}

bool RegWriteDword(HKEY root, const wchar_t* path, const wchar_t* name, DWORD value) {
    HKEY k;
    if (RegCreateKeyExW(root, path, 0, NULL, 0, KEY_WRITE | KEY_WOW64_64KEY, NULL, &k, NULL) != ERROR_SUCCESS)
        return false;
    LONG r = RegSetValueExW(k, name, 0, REG_DWORD, (const BYTE*)&value, sizeof(DWORD));
    RegCloseKey(k);
    return r == ERROR_SUCCESS;
}

bool RegReadString(HKEY root, const wchar_t* path, const wchar_t* name, wchar_t* buf, DWORD cch) {
    HKEY k;
    if (RegOpenKeyExW(root, path, 0, KEY_READ | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS) return false;
    DWORD type = 0, size = (cch - 1) * sizeof(wchar_t);
    LONG r = RegQueryValueExW(k, name, NULL, &type, (BYTE*)buf, &size);
    RegCloseKey(k);
    if (r != ERROR_SUCCESS || type != REG_SZ) return false;
    buf[size / sizeof(wchar_t)] = 0;
    return true;
}

bool RegWriteString(HKEY root, const wchar_t* path, const wchar_t* name, const wchar_t* value) {
    HKEY k;
    if (RegCreateKeyExW(root, path, 0, NULL, 0, KEY_WRITE | KEY_WOW64_64KEY, NULL, &k, NULL) != ERROR_SUCCESS)
        return false;
    LONG r = RegSetValueExW(k, name, 0, REG_SZ, (const BYTE*)value, (DWORD)((lstrlenW(value) + 1) * sizeof(wchar_t)));
    RegCloseKey(k);
    return r == ERROR_SUCCESS;
}

bool RegKeyExists(HKEY root, const wchar_t* path) {
    HKEY k;
    if (RegOpenKeyExW(root, path, 0, KEY_READ | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS) return false;
    RegCloseKey(k);
    return true;
}
