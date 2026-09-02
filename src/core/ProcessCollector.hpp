#pragma once

#include "ProcessInfo.hpp"
#include <vector>
#include <memory>

class ProcessCollector {
public:
    // Собирает процессы.
    // enrich = true → дополнительно получает полный путь и command line
    // (требует больше прав и чуть медленнее).
    static std::vector<std::unique_ptr<ProcessInfo>> Collect(bool enrich = true);
};
