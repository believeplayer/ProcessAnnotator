#pragma once

#include "ProcessInfo.hpp"
#include <vector>
#include <string>
#include <cstdint>
#include <memory>

struct SnapshotEntry {
    DWORD pid = 0;
    uint64_t createTime = 0;
    DWORD ppid = 0;
    std::wstring name;
};

struct DiffResult {
    std::vector<SnapshotEntry> added;    // new processes
    std::vector<SnapshotEntry> removed;  // gone
    std::vector<SnapshotEntry> parentChanged;
};

class SnapshotDiff {
public:
    // Capture lightweight snapshot from current process list
    static std::vector<SnapshotEntry> Capture(
        const std::vector<std::unique_ptr<ProcessInfo>>& processes);

    // Compare previous snapshot with current processes; marks isNew/parentChanged on current
    static DiffResult Compare(
        const std::vector<SnapshotEntry>& previous,
        std::vector<std::unique_ptr<ProcessInfo>>& current);
};
