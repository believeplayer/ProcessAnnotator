#include "RefreshWorker.hpp"

#include "core/ProcessCollector.hpp"
#include "core/ProcessTree.hpp"
#include "core/Signature.hpp"
#include "core/FileHash.hpp"

#include <utility>

RefreshWorker::RefreshWorker(QObject* parent)
    : QObject(parent)
{
}

void RefreshWorker::setPreviousSnapshot(std::vector<SnapshotEntry> previous, bool hadPrevious) {
    previous_ = std::move(previous);
    hadPrevious_ = hadPrevious;
}

RefreshResult RefreshWorker::takeResult() {
    return std::move(result_);
}

void RefreshWorker::run() {
    try {
        emit stage(0);

        result_ = RefreshResult{};
        result_.hadPrevious = hadPrevious_;
        result_.processes = ProcessCollector::Collect(true);

        if (hadPrevious_)
            result_.diff = SnapshotDiff::Compare(previous_, result_.processes);
        else
            result_.diff = DiffResult{};

        result_.roots = ProcessTree::Build(result_.processes);
        result_.snapshot = SnapshotDiff::Capture(result_.processes);

        SaveSignatureCache();
        SaveHashCache();

        emit finished();
    } catch (...) {
        emit failed(QStringLiteral("Refresh failed"));
    }
}
