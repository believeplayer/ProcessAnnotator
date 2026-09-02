#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include "Signature.hpp"

enum class ModuleAnomaly {
    None = 0,
    MissingOnDisk,   // path exists in process, file not found on disk (phantom / deleted mapping)
    Pathless,        // no path (reflective / manual map)
    AccessDenied     // cannot check file (not treated as phantom)
};

inline const wchar_t* ModuleAnomalyToString(ModuleAnomaly a) {
    switch (a) {
        case ModuleAnomaly::MissingOnDisk: return L"Missing on disk";
        case ModuleAnomaly::Pathless:      return L"No path";
        case ModuleAnomaly::AccessDenied:  return L"Access denied";
        default:                           return L"";
    }
}

struct ModuleInfo {
    std::wstring name;
    std::wstring path;
    uintptr_t    base = 0;
    size_t       size = 0;
    SignatureInfo signature;
    ModuleAnomaly anomaly = ModuleAnomaly::None;
    std::wstring sha256;
};

// verifySignatures=false — faster; anomaly check is always done
std::vector<ModuleInfo> EnumerateModules(DWORD pid, bool verifySignatures = false);
