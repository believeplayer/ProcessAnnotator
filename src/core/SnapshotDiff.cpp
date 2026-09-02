#include "SnapshotDiff.hpp"
#include <unordered_map>
#include <sstream>

namespace {
struct Key {
    DWORD pid;
    uint64_t createTime;
    bool operator==(const Key& o) const {
        return pid == o.pid && createTime == o.createTime;
    }
};
struct KeyHash {
    size_t operator()(const Key& k) const {
        return std::hash<DWORD>{}(k.pid) ^ (std::hash<uint64_t>{}(k.createTime) << 1);
    }
};
} // namespace

std::vector<SnapshotEntry> SnapshotDiff::Capture(
    const std::vector<std::unique_ptr<ProcessInfo>>& processes)
{
    std::vector<SnapshotEntry> out;
    out.reserve(processes.size());
    for (const auto& p : processes) {
        if (!p) continue;
        SnapshotEntry e;
        e.pid = p->pid;
        e.createTime = p->createTime;
        e.ppid = p->ppid;
        e.name = p->name;
        out.push_back(std::move(e));
    }
    return out;
}

DiffResult SnapshotDiff::Compare(
    const std::vector<SnapshotEntry>& previous,
    std::vector<std::unique_ptr<ProcessInfo>>& current)
{
    DiffResult diff;

    std::unordered_map<Key, SnapshotEntry, KeyHash> prevMap;
    for (const auto& e : previous)
        prevMap[{e.pid, e.createTime}] = e;

    std::unordered_map<Key, ProcessInfo*, KeyHash> curMap;
    for (auto& p : current) {
        if (!p) continue;
        Key k{p->pid, p->createTime};
        curMap[k] = p.get();

        auto it = prevMap.find(k);
        if (it == prevMap.end()) {
            p->isNew = true;
            SnapshotEntry e;
            e.pid = p->pid;
            e.createTime = p->createTime;
            e.ppid = p->ppid;
            e.name = p->name;
            diff.added.push_back(std::move(e));
        } else {
            if (it->second.ppid != p->ppid) {
                p->parentChanged = true;
                SnapshotEntry e;
                e.pid = p->pid;
                e.createTime = p->createTime;
                e.ppid = p->ppid;
                e.name = p->name;
                diff.parentChanged.push_back(std::move(e));
            }
        }
    }

    for (const auto& e : previous) {
        Key k{e.pid, e.createTime};
        if (curMap.find(k) == curMap.end())
            diff.removed.push_back(e);
    }

    return diff;
}
