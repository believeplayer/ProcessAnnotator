#pragma once

#include <Windows.h>
#include <string>

// Local cache directory: %LOCALAPPDATA%\ProcessAnnotator
// Falls back to the executable directory if LOCALAPPDATA is missing.
inline std::wstring GetAnnotatorCacheDir() {
    wchar_t buf[MAX_PATH] = {};
    const DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH);
    std::wstring dir;
    if (n > 0 && n < MAX_PATH) {
        dir.assign(buf, n);
    } else {
        wchar_t exe[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, exe, MAX_PATH);
        dir = exe;
        const size_t pos = dir.find_last_of(L"\\/");
        if (pos != std::wstring::npos)
            dir.resize(pos);
    }
    if (!dir.empty() && dir.back() != L'\\' && dir.back() != L'/')
        dir.push_back(L'\\');
    dir += L"ProcessAnnotator";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir;
}

inline std::wstring GetAnnotatorCacheFile(const wchar_t* fileName) {
    return GetAnnotatorCacheDir() + L"\\" + fileName;
}
