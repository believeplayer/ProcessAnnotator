#include "ProcessView.hpp"
#include "core/FileHash.hpp"

#include <QRegularExpression>

bool passesFilter(const ProcessInfo* proc, ProcessFilter filter) {
    if (!proc) return false;
    switch (filter) {
        case ProcessFilter::Interesting:
            if (!proc->annotation)
                return !proc->signature.isSigned && !proc->imagePath.empty();
            return proc->annotation->category != Category::System;
        case ProcessFilter::NoSystem:
            if (proc->annotation && proc->annotation->category == Category::System)
                return false;
            return true;
        case ProcessFilter::Unsigned:
            return !proc->signature.isSigned && !proc->imagePath.empty();
        case ProcessFilter::Telemetry:
            return proc->annotation && proc->annotation->category == Category::Telemetry;
        case ProcessFilter::Vendor:
            return proc->annotation && proc->annotation->category == Category::VendorService;
        case ProcessFilter::Browser:
            return proc->annotation && proc->annotation->category == Category::BrowserWorker;
        case ProcessFilter::Antivirus:
            return proc->annotation && proc->annotation->category == Category::Antivirus;
        default:
            return true;
    }
}

bool tokenLooksLikeHash(const QString& t) {
    if (t.size() < 32)
        return false;
    for (const QChar c : t) {
        const ushort u = c.toLower().unicode();
        const bool hex = (u >= '0' && u <= '9') || (u >= 'a' && u <= 'f');
        if (!hex)
            return false;
    }
    return true;
}

QString ensureProcessSha256(ProcessInfo* proc) {
    if (!proc) return {};
    if (!proc->sha256Computed) {
        if (!proc->imagePath.empty())
            proc->sha256 = FileSha256(proc->imagePath);
        proc->sha256Computed = true;
    }
    return QString::fromStdWString(proc->sha256);
}

QList<QStringList> parseSearchGroups(const QString& text) {
    QList<QStringList> groups;
    const QStringList orParts = text.split(QLatin1Char(','), Qt::SkipEmptyParts);
    for (const QString& part : orParts) {
        const QStringList tokens = QString(part).split(QRegularExpression(QStringLiteral("\\s+")),
                                                       Qt::SkipEmptyParts);
        if (!tokens.isEmpty())
            groups.append(tokens);
    }
    return groups;
}

bool matchesSearch(const ProcessInfo* proc, const QString& searchText) {
    if (searchText.isEmpty()) return true;
    if (!proc) return false;

    const QList<QStringList> groups = parseSearchGroups(searchText);
    if (groups.isEmpty()) return true;

    const QString name = QString::fromStdWString(proc->name);
    const QString path = QString::fromStdWString(proc->imagePath);
    const QString cmd = QString::fromStdWString(proc->commandLine);
    const QString svc = QString::fromStdWString(proc->serviceName);
    const QString pid = QString::number(proc->pid);
    const QString sig = QString::fromStdWString(proc->signature.status);
    const QString pub = QString::fromStdWString(proc->signature.publisher);
    QString hash = QString::fromStdWString(proc->sha256);
    QString ann, cat;
    if (proc->annotation) {
        ann = QString::fromStdWString(proc->annotation->annotation);
        cat = QString::fromWCharArray(CategoryToString(proc->annotation->category));
    }

    auto fieldHitNoHash = [&](const QString& t) {
        return name.contains(t, Qt::CaseInsensitive)
            || path.contains(t, Qt::CaseInsensitive)
            || cmd.contains(t, Qt::CaseInsensitive)
            || svc.contains(t, Qt::CaseInsensitive)
            || sig.contains(t, Qt::CaseInsensitive)
            || pub.contains(t, Qt::CaseInsensitive)
            || ann.contains(t, Qt::CaseInsensitive)
            || cat.contains(t, Qt::CaseInsensitive);
    };

    auto pidToken = [](const QString& t) -> int {
        QString s = t;
        if (s.startsWith(QLatin1String("pid:"), Qt::CaseInsensitive))
            s = s.mid(4);
        else {
            if (s.isEmpty())
                return -1;
            for (const QChar c : s) {
                if (!c.isDigit())
                    return -1;
            }
        }
        if (s.isEmpty())
            return -1;
        bool ok = false;
        const qulonglong v = s.toULongLong(&ok);
        if (!ok || v > 0xFFFFFFFFull)
            return -1;
        return static_cast<int>(v);
    };

    auto* mut = const_cast<ProcessInfo*>(proc);
    auto groupMatches = [&](const QStringList& tokens) {
        for (const QString& t : tokens) {
            const int wantPid = pidToken(t);
            if (wantPid >= 0) {
                if (static_cast<int>(proc->pid) == wantPid)
                    continue;
                return false;
            }
            if (fieldHitNoHash(t))
                continue;
            if (tokenLooksLikeHash(t)) {
                if (hash.isEmpty() && !mut->sha256Computed)
                    hash = ensureProcessSha256(mut);
                if (hash.contains(t, Qt::CaseInsensitive))
                    continue;
            }
            return false;
        }
        return true;
    };

    for (const QStringList& tokens : groups) {
        if (groupMatches(tokens))
            return true;
    }
    return false;
}

bool shouldShowNode(const ProcessInfo* proc, ProcessFilter filter, const QString& searchText) {
    if (!proc) return false;
    if (passesFilter(proc, filter) && matchesSearch(proc, searchText))
        return true;
    for (const ProcessInfo* child : proc->children)
        if (shouldShowNode(child, filter, searchText))
            return true;
    return false;
}
