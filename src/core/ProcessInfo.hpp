#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <optional>
#include "Rule.hpp"
#include "Signature.hpp"

struct ProcessInfo {
    DWORD     pid        = 0;
    DWORD     ppid       = 0;
    uint64_t  createTime = 0;
    std::wstring name;
    std::wstring imagePath;
    std::wstring commandLine;
    int       sessionId  = -1;
    int       basePriority = 0;

    SignatureInfo signature;
    std::optional<RuleMatch> annotation;
    std::wstring serviceName;

    // Extended properties
    std::wstring userName;       // DOMAIN\User
    std::wstring integrity;      // Low / Medium / High / System / ...
    std::wstring arch;           // x64 / x86 / ARM64 / Unknown
    std::wstring startTime;      // local time string
    size_t workingSetBytes = 0;
    size_t privateBytes = 0;
    std::wstring sha256;  // filled on demand, not during Collect/refresh
    bool sha256Computed = false;  // true after a compute attempt, even if sha256 stayed empty

    // Snapshot diff
    bool isNew = false;
    bool parentChanged = false;

    ProcessInfo* parent = nullptr;
    std::vector<ProcessInfo*> children;

    bool isRoot() const noexcept { return parent == nullptr; }
};
