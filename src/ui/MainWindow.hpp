#pragma once

#include "core/ProcessInfo.hpp"
#include "core/RuleEngine.hpp"
#include "vt/VirusTotal.hpp"
#include "core/SnapshotDiff.hpp"
#include "core/AutostartIndex.hpp"
#include "core/ModuleEnumerator.hpp"
#include "ui/ProcessView.hpp"

#include <QMainWindow>
#include <QTreeWidget>
#include <QTextEdit>
#include <QLabel>
#include <QComboBox>
#include <QPushButton>
#include <QLineEdit>
#include <QTabWidget>
#include <QCloseEvent>
#include <QThread>
#include <QTimer>
#include <vector>
#include <memory>

class RefreshWorker;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    void onRefresh();
    void onRefreshStage(int stage);
    void onRefreshFinished();
    void onRefreshFailed(const QString& error);
    void onSelectionChanged();
    void onFilterChanged(int index);
    void onSearchTextChanged(const QString& text);
    void applySearch();
    void onExportReport();
    void onExportHtmlReport();
    void onModulesContextMenu(const QPoint& pos);
    void onTreeContextMenu(const QPoint& pos);
    void onLanguageEnglish();
    void onLanguageRussian();
    void onVtApiKey();
    void onAbout();
    void onVtFinished(const VirusTotalResult& result);
    void onVtProgress(const QString& msg);
    void onShowDiff();
    void onToggleAutoDiff(bool checked);
    void onModuleSearchChanged(const QString& text);
    void onThemeDark();
    void onThemeLight();
    void onThemeSystem();
    void filterModulesList();

private:
    void setupUi();
    void retranslateUi();
    void reapplyAnnotations();
    void showDiffDialog();
    void buildTree();
    void addNode(QTreeWidgetItem* parentItem, ProcessInfo* proc);
    void showDetails(ProcessInfo* proc);
    void updateStatistics();
    void updateHiddenTasks();
    void updateRulesList();
    void onReloadRules();
    void loadModules(ProcessInfo* proc);
    void openInExplorer(const QString& path);
    void showFileProperties(const QString& path);
    void checkVirusTotal(const QString& path);
    void setRefreshBusy(bool busy);
    void stopRefreshThread();
    void releaseProcessUi();
    bool passesFilter(const ProcessInfo* proc) const;
    bool matchesSearch(const ProcessInfo* proc) const;
    bool shouldShowNode(const ProcessInfo* proc) const;
    QString buildReportText() const;
    QString buildReportHtml() const;

    QTreeWidget* tree_ = nullptr;
    QTextEdit* details_ = nullptr;
    QTextEdit* statsText_ = nullptr;
    QTabWidget* rightTabs_ = nullptr;
    QTreeWidget* hiddenTasksTree_ = nullptr;
    QTreeWidget* rulesTree_ = nullptr;
    QLabel* rulesStatus_ = nullptr;
    QLabel* rulesErrors_ = nullptr;
    QPushButton* rulesReloadBtn_ = nullptr;
    QLabel* hiddenTasksStatus_ = nullptr;
    QTreeWidget* modulesTree_ = nullptr;
    QLabel* status_ = nullptr;
    QLabel* filterLabel_ = nullptr;
    QLabel* searchLabel_ = nullptr;
    QComboBox* filterCombo_ = nullptr;
    QPushButton* refreshBtn_ = nullptr;
    QPushButton* exportBtn_ = nullptr;
    QLineEdit* searchEdit_ = nullptr;
    QTimer* searchDebounce_ = nullptr;
    QLineEdit* moduleSearchEdit_ = nullptr;

    QMenu* menuFile_ = nullptr;
    QMenu* menuView_ = nullptr;
    QMenu* menuTools_ = nullptr;
    QMenu* menuHelp_ = nullptr;
    QMenu* menuLang_ = nullptr;
    QAction* actRefresh_ = nullptr;
    QAction* actExport_ = nullptr;
    QAction* actVtKey_ = nullptr;
    QAction* actAbout_ = nullptr;
    QAction* actLangEn_ = nullptr;
    QAction* actLangRu_ = nullptr;

    RuleEngine engine_;
    std::vector<std::unique_ptr<ProcessInfo>> processes_;
    std::vector<ProcessInfo*> roots_;
    QString searchText_;
    VirusTotalClient* vt_ = nullptr;
    std::vector<SnapshotEntry> lastSnapshot_;
    DiffResult lastDiff_;
    AutostartIndex autostart_;
    bool hasSnapshot_ = false;
    bool autoShowDiff_ = true;
    bool refreshBusy_ = false;
    RefreshWorker* refreshWorker_ = nullptr;
    QThread* refreshThread_ = nullptr;
    QAction* actAutoDiff_ = nullptr;
    QAction* actThemeDark_ = nullptr;
    QAction* actThemeLight_ = nullptr;
    QAction* actThemeSystem_ = nullptr;
    QString moduleSearchText_;
    struct ModuleRow {
        QString name, sig, anomaly, path, hash;
        ModuleAnomaly anomalyKind = ModuleAnomaly::None;
        bool suspicious = false;
        bool unsignedSig = false;
        bool hashComputed = false;
    };
    std::vector<ModuleRow> moduleRows_;

    ProcessFilter filter_ = ProcessFilter::All;
    DWORD pendingSelectPid_ = 0;
    QString pendingSelectPath_;
};
