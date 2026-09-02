#pragma once

#include "core/ProcessInfo.hpp"
#include "core/SnapshotDiff.hpp"
#include "core/AutostartIndex.hpp"

#include <QObject>
#include <memory>
#include <vector>

struct RefreshResult {
    std::vector<std::unique_ptr<ProcessInfo>> processes;
    std::vector<ProcessInfo*> roots;
    std::vector<SnapshotEntry> snapshot;
    DiffResult diff;
    AutostartIndex autostart;
    bool hadPrevious = false;
};

class RefreshWorker : public QObject {
    Q_OBJECT
public:
    explicit RefreshWorker(QObject* parent = nullptr);

    void setPreviousSnapshot(std::vector<SnapshotEntry> previous, bool hadPrevious);
    RefreshResult takeResult();

public slots:
    void run();

signals:
    void stage(int stageIndex);
    void finished();
    void failed(const QString& error);

private:
    std::vector<SnapshotEntry> previous_;
    bool hadPrevious_ = false;
    RefreshResult result_;
};
