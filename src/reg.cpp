#include "reg.h"

#ifndef KEY_WOW64_64KEY
#define KEY_WOW64_64KEY 0x0100
#endif

static bool WriteRaw(HKEY root, const wchar_t* path, const wchar_t* name, DWORD type, const void* data, DWORD size) {
    HKEY k;
    if (RegCreateKeyExW(root, path, 0, NULL, 0, KEY_WRITE | KEY_WOW64_64KEY, NULL, &k, NULL) != ERROR_SUCCESS)
        return false;
    LONG r = RegSetValueExW(k, name, 0, type, (const BYTE*)data, size);
    RegCloseKey(k);
    return r == ERROR_SUCCESS;
}

bool RegReadDword(HKEY root, const wchar_t* path, const wchar_t* name, DWORD* value) {
    HKEY k;
    if (RegOpenKeyExW(root, path, 0, KEY_READ | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS) return false;
    DWORD type = 0, size = sizeof(DWORD), v = 0;
    LONG r = RegQueryValueExW(k, name, NULL, &type, (BYTE*)&v, &size);
    RegCloseKey(k);
    if (r != ERROR_SUCCESS || type != REG_DWORD) return false;
    *value = v;
    return true;
}

bool RegWriteDword(HKEY root, const wchar_t* path, const wchar_t* name, DWORD value) {
    return WriteRaw(root, path, name, REG_DWORD, &value, sizeof(DWORD));
}

bool RegWriteQword(HKEY root, const wchar_t* path, const wchar_t* name, ULONGLONG value) {
    return WriteRaw(root, path, name, REG_QWORD, &value, sizeof(ULONGLONG));
}

bool RegReadString(HKEY root, const wchar_t* path, const wchar_t* name, wchar_t* buf, DWORD cch) {
    HKEY k;
    if (RegOpenKeyExW(root, path, 0, KEY_READ | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS) return false;
    DWORD type = 0, size = (cch - 1) * sizeof(wchar_t);
    LONG r = RegQueryValueExW(k, name, NULL, &type, (BYTE*)buf, &size);
    RegCloseKey(k);
    if (r != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) return false;
    buf[size / sizeof(wchar_t)] = 0;
    return true;
}

bool RegWriteString(HKEY root, const wchar_t* path, const wchar_t* name, const wchar_t* value) {
    return WriteRaw(root, path, name, REG_SZ, value, (DWORD)((lstrlenW(value) + 1) * sizeof(wchar_t)));
}

bool RegWriteExpandString(HKEY root, const wchar_t* path, const wchar_t* name, const wchar_t* value) {
    return WriteRaw(root, path, name, REG_EXPAND_SZ, value, (DWORD)((lstrlenW(value) + 1) * sizeof(wchar_t)));
}

bool RegWriteMultiSz(HKEY root, const wchar_t* path, const wchar_t* name, const wchar_t* value) {
    const wchar_t* p = value;
    while (*p) p += lstrlenW(p) + 1;
    DWORD size = (DWORD)((p - value + 1) * sizeof(wchar_t));
    return WriteRaw(root, path, name, REG_MULTI_SZ, value, size);
}

bool RegDeleteValueAt(HKEY root, const wchar_t* path, const wchar_t* name) {
    HKEY k;
    LONG r = RegOpenKeyExW(root, path, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &k);
    if (r == ERROR_FILE_NOT_FOUND) return true;
    if (r != ERROR_SUCCESS) return false;
    r = RegDeleteValueW(k, name);
    RegCloseKey(k);
    return r == ERROR_SUCCESS || r == ERROR_FILE_NOT_FOUND;
}

// 在 parent（已用 64 位元檢視開啟）底下遞迴刪除子機碼 name
static bool DeleteSubTree(HKEY parent, const wchar_t* name) {
    HKEY k;
    LONG r = RegOpenKeyExW(parent, name, 0, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, &k);
    if (r == ERROR_FILE_NOT_FOUND) return true;
    if (r != ERROR_SUCCESS) return false;
    wchar_t child[256];
    for (;;) {
        DWORD cch = 256;
        if (RegEnumKeyExW(k, 0, child, &cch, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        if (!DeleteSubTree(k, child)) { RegCloseKey(k); return false; }
    }
    RegCloseKey(k);
    r = RegDeleteKeyW(parent, name);
    return r == ERROR_SUCCESS || r == ERROR_FILE_NOT_FOUND;
}

bool RegDeleteTreeAt(HKEY root, const wchar_t* path) {
    // 拆成「父機碼」與「最後一段名稱」
    wchar_t parentPath[512];
    lstrcpynW(parentPath, path, 512);
    wchar_t* slash = NULL;
    for (wchar_t* p = parentPath; *p; p++) if (*p == L'\\') slash = p;
    if (!slash) return DeleteSubTree(root, path);
    *slash = 0;
    HKEY parent;
    LONG r = RegOpenKeyExW(root, parentPath, 0, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, &parent);
    if (r == ERROR_FILE_NOT_FOUND) return true;
    if (r != ERROR_SUCCESS) return false;
    bool ok = DeleteSubTree(parent, slash + 1);
    RegCloseKey(parent);
    return ok;
}

bool RegKeyExists(HKEY root, const wchar_t* path) {
    HKEY k;
    if (RegOpenKeyExW(root, path, 0, KEY_READ | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS) return false;
    RegCloseKey(k);
    return true;
}
