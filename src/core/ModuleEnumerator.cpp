#include "ModuleEnumerator.hpp"

#include <Psapi.h>
#include <algorithm>

#pragma comment(lib, "psapi.lib")

namespace {

ModuleAnomaly CheckPathAnomaly(const std::wstring& path) {
    if (path.empty())
        return ModuleAnomaly::Pathless;

    // Skip special device / API set style names that are not real files
    // e.g. \APISET, \\?\ sometimes still valid
    if (path.size() >= 1 && path[0] == L'\\' && path.find(L":\\") == std::wstring::npos) {
        // NT path without drive - try as is; if fails, don't aggressively flag
    }

    DWORD attr = GetFileAttributesW(path.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES)
        return ModuleAnomaly::None;

    DWORD err = GetLastError();
    if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND ||
        err == ERROR_INVALID_NAME || err == ERROR_BAD_NETPATH) {
        // Classic indicator: mapped image, file gone (delete-pending, TxF rollback, etc.)
        return ModuleAnomaly::MissingOnDisk;
    }
    if (err == ERROR_ACCESS_DENIED || err == ERROR_SHARING_VIOLATION)
        return ModuleAnomaly::AccessDenied;

    return ModuleAnomaly::None;
}

} // namespace

std::vector<ModuleInfo> EnumerateModules(DWORD pid, bool verifySignatures) {
    std::vector<ModuleInfo> result;
    if (pid == 0 || pid == 4) return result;

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess)
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return result;

    HMODULE modules[1024];
    DWORD needed = 0;

    if (!EnumProcessModulesEx(hProcess, modules, sizeof(modules), &needed, LIST_MODULES_ALL)) {
        CloseHandle(hProcess);
        return result;
    }

    size_t count = needed / sizeof(HMODULE);
    if (count > 1024) count = 1024;

    wchar_t pathBuf[MAX_PATH] = {};
    MODULEINFO mi{};

    for (size_t i = 0; i < count; ++i) {
        ModuleInfo m;
        m.base = reinterpret_cast<uintptr_t>(modules[i]);

        if (GetModuleFileNameExW(hProcess, modules[i], pathBuf, MAX_PATH)) {
            m.path = pathBuf;
            size_t slash = m.path.find_last_of(L"\\/");
            m.name = (slash != std::wstring::npos) ? m.path.substr(slash + 1) : m.path;
        } else {
            // Try base name only
            if (GetModuleBaseNameW(hProcess, modules[i], pathBuf, MAX_PATH))
                m.name = pathBuf;
        }

        if (GetModuleInformation(hProcess, modules[i], &mi, sizeof(mi)))
            m.size = mi.SizeOfImage;

        m.anomaly = CheckPathAnomaly(m.path);

        if (!m.path.empty() && m.anomaly != ModuleAnomaly::MissingOnDisk
            && m.anomaly != ModuleAnomaly::Pathless) {
            if (verifySignatures)
                m.signature = VerifySignature(m.path);
        }

        result.push_back(std::move(m));
    }

    CloseHandle(hProcess);

    // Suspicious first, then by name
    std::sort(result.begin(), result.end(),
              [](const ModuleInfo& a, const ModuleInfo& b) {
                  auto rank = [](ModuleAnomaly x) {
                      if (x == ModuleAnomaly::MissingOnDisk) return 0;
                      if (x == ModuleAnomaly::Pathless) return 1;
                      return 2;
                  };
                  int ra = rank(a.anomaly), rb = rank(b.anomaly);
                  if (ra != rb) return ra < rb;
                  return a.name < b.name;
              });

    return result;
}
