#pragma once

#include "core/ProcessInfo.hpp"
#include "core/Rule.hpp"
#include "ui/Theme.hpp"

#include <QString>
#include <QStringList>
#include <QList>

enum class ProcessFilter {
    All = 0,
    Interesting,
    NoSystem,
    Unsigned,
    Telemetry,
    Vendor,
    Browser,
    Antivirus
};

bool passesFilter(const ProcessInfo* proc, ProcessFilter filter);
bool matchesSearch(const ProcessInfo* proc, const QString& searchText);
bool shouldShowNode(const ProcessInfo* proc, ProcessFilter filter, const QString& searchText);
QString ensureProcessSha256(ProcessInfo* proc);
bool tokenLooksLikeHash(const QString& token);
QList<QStringList> parseSearchGroups(const QString& text);
