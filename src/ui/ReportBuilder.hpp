#pragma once

#include "core/ProcessInfo.hpp"
#include "ui/ProcessView.hpp"

#include <QString>
#include <vector>
#include <memory>

QString buildReportText(const std::vector<std::unique_ptr<ProcessInfo>>& processes,
                        const std::vector<ProcessInfo*>& roots,
                        ProcessFilter filter,
                        const QString& searchText,
                        size_t ruleCount);

QString buildReportHtml(const std::vector<std::unique_ptr<ProcessInfo>>& processes,
                        const std::vector<ProcessInfo*>& roots,
                        ProcessFilter filter,
                        const QString& searchText,
                        size_t ruleCount);
