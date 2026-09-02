#pragma once

#include "ProcessInfo.hpp"
#include <vector>
#include <memory>

class ProcessTree {
public:
    // Строит дерево из плоского списка.
    // Владение процессами остаётся у вектора `processes`.
    // Возвращает список корневых процессов (сырые указатели).
    static std::vector<ProcessInfo*> Build(
        std::vector<std::unique_ptr<ProcessInfo>>& processes);
};
