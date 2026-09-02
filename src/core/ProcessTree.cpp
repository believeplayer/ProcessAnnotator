#include "ProcessTree.hpp"

#include <unordered_map>
#include <vector>

std::vector<ProcessInfo*> ProcessTree::Build(
    std::vector<std::unique_ptr<ProcessInfo>>& processes)
{
    // 1. Карта PID → ProcessInfo*
    std::unordered_map<DWORD, ProcessInfo*> byPid;
    byPid.reserve(processes.size());

    for (auto& p : processes) {
        if (p) {
            byPid[p->pid] = p.get();
        }
    }

    // 2. Связываем детей с родителями
    std::vector<ProcessInfo*> roots;
    roots.reserve(32);

    for (auto& p : processes) {
        if (!p) continue;

        bool attached = false;

        if (p->ppid != 0) {
            auto it = byPid.find(p->ppid);
            if (it != byPid.end()) {
                ProcessInfo* candidate = it->second;

                // Защита от PID reuse:
                // настоящий родитель всегда создан раньше (или в то же время) ребёнка
                if (candidate->createTime <= p->createTime) {
                    p->parent = candidate;
                    candidate->children.push_back(p.get());
                    attached = true;
                }
            }
        }

        if (!attached) {
            roots.push_back(p.get());
        }
    }

    return roots;
}
