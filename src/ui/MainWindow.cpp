#include <algorithm>
#include <map>
#include <functional>
#include <vector>
#include "MainWindow.hpp"
#include "core/ProcessCollector.hpp"
#include "core/ProcessTree.hpp"
#include "core/Privilege.hpp"
#include "core/Signature.hpp"
#include "core/ModuleEnumerator.hpp"
#include "core/SnapshotDiff.hpp"
#include "core/FileHash.hpp"
#include "core/AutostartIndex.hpp"
#include "core/RuleEngine.hpp"
#include "i18n/I18n.hpp"
#include "ui/Theme.hpp"
#include "ui/ProcessView.hpp"
#include "ui/ReportBuilder.hpp"
#include "ui/RefreshWorker.hpp"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QTabWidget>
#include <QHeaderView>
#include <QApplication>
#include <QIcon>
#include <QFont>
#include <QMenu>
#include <QMenuBar>
#include <QAction>
#include <QClipboard>
#include <QDir>
#include <QFileInfo>
#include <QMessageBox>
#include <QFileDialog>
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <QInputDialog>
#include <QSettings>
#include <QRegularExpression>
#include <QDesktopServices>
#include <QUrl>
#include <QThread>
#include <QTimer>
#include <QStringList>

#include <Windows.h>
#include <shellapi.h>

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
{
    setWindowIcon(QIcon(QStringLiteral(":/app.png")));

    vt_ = new VirusTotalClient(this);
    connect(vt_, &VirusTotalClient::finished, this, &MainWindow::onVtFinished);
    connect(vt_, &VirusTotalClient::progress, this, &MainWindow::onVtProgress);

    EnableDebugPrivilege();
    LoadSignatureCache();
    LoadHashCache();

    {
        QSettings s(QStringLiteral("ProcessAnnotator"), QStringLiteral("ProcessAnnotator"));
        autoShowDiff_ = s.value(QStringLiteral("ui/autoShowDiff"), true).toBool();
        const QString lang = s.value(QStringLiteral("ui/language")).toString();
        if (lang == QLatin1String("en"))
            I18n::instance().setLanguage(I18n::English);
        else if (lang == QLatin1String("ru"))
            I18n::instance().setLanguage(I18n::Russian);
        // else: keep system language from I18n constructor
    }

    RuleEngine_SetPreferEnglish(I18n::instance().language() == I18n::English);

    setupUi();
    retranslateUi();
    updateRulesList();
    QTimer::singleShot(0, this, &MainWindow::onRefresh);
}

void MainWindow::setupUi() {
    resize(1280, 800);

    // Menus
    menuFile_ = menuBar()->addMenu(QStringLiteral("File"));
    actRefresh_ = menuFile_->addAction(QStringLiteral("Refresh"));
    connect(actRefresh_, &QAction::triggered, this, &MainWindow::onRefresh);
    actExport_ = menuFile_->addAction(QStringLiteral("Export"));
    connect(actExport_, &QAction::triggered, this, &MainWindow::onExportReport);
    auto* actExportHtml = menuFile_->addAction(QStringLiteral("Export HTML"));
    actExportHtml->setObjectName(QStringLiteral("actExportHtml"));
    connect(actExportHtml, &QAction::triggered, this, &MainWindow::onExportHtmlReport);

    menuView_ = menuBar()->addMenu(QStringLiteral("View"));
    menuLang_ = menuView_->addMenu(QStringLiteral("Language"));
    actLangEn_ = menuLang_->addAction(QStringLiteral("English"));
    actLangRu_ = menuLang_->addAction(QStringLiteral("Русский"));
    connect(actLangEn_, &QAction::triggered, this, &MainWindow::onLanguageEnglish);
    connect(actLangRu_, &QAction::triggered, this, &MainWindow::onLanguageRussian);

    auto* menuTheme = menuView_->addMenu(QStringLiteral("Theme"));
    menuTheme->setObjectName(QStringLiteral("menuTheme"));
    actThemeDark_ = menuTheme->addAction(QStringLiteral("Dark"));
    actThemeLight_ = menuTheme->addAction(QStringLiteral("Light"));
    actThemeSystem_ = menuTheme->addAction(QStringLiteral("System"));
    actThemeDark_->setCheckable(true);
    actThemeLight_->setCheckable(true);
    actThemeSystem_->setCheckable(true);
    {
        AppTheme cur = loadSavedTheme();
        actThemeDark_->setChecked(cur == AppTheme::Dark);
        actThemeLight_->setChecked(cur == AppTheme::Light);
        actThemeSystem_->setChecked(cur == AppTheme::System);
    }
    connect(actThemeDark_, &QAction::triggered, this, &MainWindow::onThemeDark);
    connect(actThemeLight_, &QAction::triggered, this, &MainWindow::onThemeLight);
    connect(actThemeSystem_, &QAction::triggered, this, &MainWindow::onThemeSystem);

    menuView_->addSeparator();
    auto* actDiff = menuView_->addAction(QStringLiteral("Show changes"));
    actDiff->setObjectName(QStringLiteral("actDiff"));
    connect(actDiff, &QAction::triggered, this, &MainWindow::onShowDiff);
    actAutoDiff_ = menuView_->addAction(QStringLiteral("Show changes dialog on refresh"));
    actAutoDiff_->setCheckable(true);
    actAutoDiff_->setChecked(autoShowDiff_);
    connect(actAutoDiff_, &QAction::toggled, this, &MainWindow::onToggleAutoDiff);

    menuTools_ = menuBar()->addMenu(QStringLiteral("Tools"));
    actVtKey_ = menuTools_->addAction(QStringLiteral("VT API key"));
    connect(actVtKey_, &QAction::triggered, this, &MainWindow::onVtApiKey);

    menuHelp_ = menuBar()->addMenu(QStringLiteral("Help"));
    actAbout_ = menuHelp_->addAction(QStringLiteral("About"));
    connect(actAbout_, &QAction::triggered, this, &MainWindow::onAbout);

    auto* central = new QWidget(this);
    setCentralWidget(central);
    auto* mainLayout = new QVBoxLayout(central);
    mainLayout->setContentsMargins(8, 8, 8, 8);

    auto* bar = new QHBoxLayout;
    refreshBtn_ = new QPushButton(this);
    connect(refreshBtn_, &QPushButton::clicked, this, &MainWindow::onRefresh);

    filterLabel_ = new QLabel(this);
    filterCombo_ = new QComboBox(this);
    // items filled in retranslateUi
    connect(filterCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onFilterChanged);

    searchLabel_ = new QLabel(this);
    searchEdit_ = new QLineEdit(this);
    searchEdit_->setClearButtonEnabled(true);
    searchEdit_->setMinimumWidth(220);
    connect(searchEdit_, &QLineEdit::textChanged, this, &MainWindow::onSearchTextChanged);
    searchDebounce_ = new QTimer(this);
    searchDebounce_->setSingleShot(true);
    searchDebounce_->setInterval(180);
    connect(searchDebounce_, &QTimer::timeout, this, &MainWindow::applySearch);

    exportBtn_ = new QPushButton(this);
    connect(exportBtn_, &QPushButton::clicked, this, &MainWindow::onExportReport);

    bar->addWidget(refreshBtn_);
    bar->addWidget(filterLabel_);
    bar->addWidget(filterCombo_);
    bar->addWidget(searchLabel_);
    bar->addWidget(searchEdit_, 1);
    bar->addWidget(exportBtn_);
    mainLayout->addLayout(bar);

    auto* hSplitter = new QSplitter(Qt::Horizontal, this);

    tree_ = new QTreeWidget(this);
    tree_->setColumnCount(4);
    tree_->setColumnWidth(0, 300);
    tree_->setColumnWidth(1, 70);
    tree_->setColumnWidth(2, 110);
    tree_->setColumnWidth(3, 100);
    tree_->setAlternatingRowColors(true);
    tree_->setUniformRowHeights(true);
    tree_->setSelectionMode(QAbstractItemView::SingleSelection);
    tree_->setFont(QFont(QStringLiteral("Segoe UI"), 10));
    tree_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(tree_, &QTreeWidget::itemSelectionChanged, this, &MainWindow::onSelectionChanged);
    connect(tree_, &QTreeWidget::customContextMenuRequested, this, &MainWindow::onTreeContextMenu);

    details_ = new QTextEdit(this);
    details_->setReadOnly(true);
    details_->setFont(QFont(QStringLiteral("Segoe UI"), 10));

    modulesTree_ = new QTreeWidget(this);
    modulesTree_->setColumnCount(4);
    modulesTree_->setColumnWidth(0, 160);
    modulesTree_->setColumnWidth(1, 90);
    modulesTree_->setColumnWidth(2, 120);
    modulesTree_->setAlternatingRowColors(true);
    modulesTree_->setUniformRowHeights(true);
    modulesTree_->setFont(QFont(QStringLiteral("Segoe UI"), 9));
    modulesTree_->setRootIsDecorated(false);
    modulesTree_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(modulesTree_, &QTreeWidget::customContextMenuRequested,
            this, &MainWindow::onModulesContextMenu);

    moduleSearchEdit_ = new QLineEdit(this);
    moduleSearchEdit_->setClearButtonEnabled(true);
    moduleSearchEdit_->setPlaceholderText(QStringLiteral("Filter DLLs..."));
    connect(moduleSearchEdit_, &QLineEdit::textChanged, this, &MainWindow::onModuleSearchChanged);

    auto* modulesPanel = new QWidget(this);
    auto* modulesLayout = new QVBoxLayout(modulesPanel);
    modulesLayout->setContentsMargins(0, 0, 0, 0);
    modulesLayout->setSpacing(4);
    modulesLayout->addWidget(moduleSearchEdit_);
    modulesLayout->addWidget(modulesTree_, 1);

    auto* detailsSplitter = new QSplitter(Qt::Vertical, this);
    detailsSplitter->addWidget(details_);
    detailsSplitter->addWidget(modulesPanel);
    detailsSplitter->setStretchFactor(0, 2);
    detailsSplitter->setStretchFactor(1, 3);

    statsText_ = new QTextEdit(this);
    statsText_->setReadOnly(true);
    statsText_->setFont(QFont(QStringLiteral("Segoe UI"), 10));

    rightTabs_ = new QTabWidget(this);
    // Hidden scheduled tasks panel
    auto* hiddenPanel = new QWidget(this);
    auto* hiddenLayout = new QVBoxLayout(hiddenPanel);
    hiddenLayout->setContentsMargins(4, 4, 4, 4);
    hiddenTasksStatus_ = new QLabel(this);
    hiddenLayout->addWidget(hiddenTasksStatus_);
    hiddenTasksTree_ = new QTreeWidget(this);
    hiddenTasksTree_->setColumnCount(3);
    hiddenTasksTree_->setHeaderLabels({QStringLiteral("Task"), QStringLiteral("Folder"), QStringLiteral("Command")});
    hiddenTasksTree_->setColumnWidth(0, 180);
    hiddenTasksTree_->setColumnWidth(1, 160);
    hiddenTasksTree_->setAlternatingRowColors(true);
    hiddenTasksTree_->setRootIsDecorated(false);
    hiddenTasksTree_->setFont(QFont(QStringLiteral("Segoe UI"), 9));
    hiddenTasksTree_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(hiddenTasksTree_, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
        auto* item = hiddenTasksTree_->itemAt(pos);
        if (!item) return;
        QMenu menu(this);
        QAction* copyCmd = menu.addAction(i18n("copy_path"));
        QAction* chosen = menu.exec(hiddenTasksTree_->viewport()->mapToGlobal(pos));
        if (chosen == copyCmd)
            QApplication::clipboard()->setText(item->text(2));
    });
    hiddenLayout->addWidget(hiddenTasksTree_, 1);

    // Rules list panel
    auto* rulesPanel = new QWidget(this);
    auto* rulesLayout = new QVBoxLayout(rulesPanel);
    rulesLayout->setContentsMargins(4, 4, 4, 4);
    rulesStatus_ = new QLabel(this);
    rulesReloadBtn_ = new QPushButton(this);
    connect(rulesReloadBtn_, &QPushButton::clicked, this, &MainWindow::onReloadRules);
    auto* rulesBar = new QHBoxLayout;
    rulesBar->addWidget(rulesStatus_, 1);
    rulesBar->addWidget(rulesReloadBtn_);
    rulesLayout->addLayout(rulesBar);
    rulesErrors_ = new QLabel(this);
    rulesErrors_->setWordWrap(true);
    rulesErrors_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    rulesErrors_->hide();
    rulesLayout->addWidget(rulesErrors_);
    rulesTree_ = new QTreeWidget(this);
    rulesTree_->setColumnCount(5);
    rulesTree_->setHeaderLabels({QStringLiteral("ID"), QStringLiteral("Pri"),
                                 QStringLiteral("Category"), QStringLiteral("Source"),
                                 QStringLiteral("Annotation")});
    rulesTree_->setColumnWidth(0, 140);
    rulesTree_->setColumnWidth(1, 50);
    rulesTree_->setColumnWidth(2, 100);
    rulesTree_->setColumnWidth(3, 140);
    rulesTree_->setAlternatingRowColors(true);
    rulesTree_->setRootIsDecorated(false);
    rulesTree_->setFont(QFont(QStringLiteral("Segoe UI"), 9));
    rulesTree_->setSortingEnabled(true);
    rulesLayout->addWidget(rulesTree_, 1);

    rightTabs_->addTab(detailsSplitter, QStringLiteral("Details"));
    rightTabs_->addTab(statsText_, QStringLiteral("Statistics"));
    rightTabs_->addTab(hiddenPanel, QStringLiteral("Hidden tasks"));
    rightTabs_->addTab(rulesPanel, QStringLiteral("Rules"));

    hSplitter->addWidget(tree_);
    hSplitter->addWidget(rightTabs_);
    hSplitter->setStretchFactor(0, 3);
    hSplitter->setStretchFactor(1, 2);
    mainLayout->addWidget(hSplitter, 1);

    status_ = new QLabel(this);
    status_->setFont(QFont(QStringLiteral("Segoe UI"), 9));
    mainLayout->addWidget(status_);
}

void MainWindow::retranslateUi() {
    setWindowTitle(i18n("app_title"));
    refreshBtn_->setText(i18n("refresh"));
    exportBtn_->setText(i18n("export_report"));
    filterLabel_->setText(i18n("filter"));
    searchLabel_->setText(i18n("search"));
    searchEdit_->setPlaceholderText(i18n("search_placeholder"));

    const int prev = filterCombo_->currentIndex();
    filterCombo_->blockSignals(true);
    filterCombo_->clear();
    filterCombo_->addItem(i18n("filter_all"), static_cast<int>(ProcessFilter::All));
    filterCombo_->addItem(i18n("filter_interesting"), static_cast<int>(ProcessFilter::Interesting));
    filterCombo_->addItem(i18n("filter_no_system"), static_cast<int>(ProcessFilter::NoSystem));
    filterCombo_->addItem(i18n("filter_unsigned"), static_cast<int>(ProcessFilter::Unsigned));
    filterCombo_->addItem(i18n("filter_telemetry"), static_cast<int>(ProcessFilter::Telemetry));
    filterCombo_->addItem(i18n("filter_vendor"), static_cast<int>(ProcessFilter::Vendor));
    filterCombo_->addItem(i18n("filter_browser"), static_cast<int>(ProcessFilter::Browser));
    filterCombo_->addItem(i18n("filter_antivirus"), static_cast<int>(ProcessFilter::Antivirus));
    if (prev >= 0 && prev < filterCombo_->count())
        filterCombo_->setCurrentIndex(prev);
    filterCombo_->blockSignals(false);

    tree_->setHeaderLabels({i18n("col_process"), i18n("col_pid"),
                            i18n("col_category"), i18n("col_signature")});
    modulesTree_->setHeaderLabels({i18n("col_module"), i18n("col_signature"), i18n("col_anomaly"), i18n("col_path")});

    menuFile_->setTitle(i18n("menu_file"));
    menuView_->setTitle(i18n("menu_view"));
    menuTools_->setTitle(i18n("menu_tools"));
    menuHelp_->setTitle(i18n("menu_help"));
    menuLang_->setTitle(i18n("language"));
    actRefresh_->setText(i18n("refresh"));
    actExport_->setText(i18n("export_report"));
    if (auto* a = findChild<QAction*>(QStringLiteral("actExportHtml")))
        a->setText(i18n("export_html"));
    actVtKey_->setText(i18n("vt_settings"));
    actAbout_->setText(i18n("about"));
    actLangEn_->setText(i18n("lang_english"));
    actLangRu_->setText(i18n("lang_russian"));
    if (auto* a = findChild<QAction*>(QStringLiteral("actDiff")))
        a->setText(i18n("diff_show"));
    if (actAutoDiff_)
        actAutoDiff_->setText(i18n("diff_auto"));
    if (moduleSearchEdit_)
        moduleSearchEdit_->setPlaceholderText(i18n("dll_search"));
    if (actThemeDark_) actThemeDark_->setText(i18n("theme_dark"));
    if (actThemeLight_) actThemeLight_->setText(i18n("theme_light"));
    if (actThemeSystem_) actThemeSystem_->setText(i18n("theme_system"));
    if (auto* mt = findChild<QMenu*>(QStringLiteral("menuTheme")))
        mt->setTitle(i18n("theme"));
    if (rightTabs_) {
        rightTabs_->setTabText(0, i18n("tab_details"));
        rightTabs_->setTabText(1, i18n("tab_stats"));
        if (rightTabs_->count() > 2)
            rightTabs_->setTabText(2, i18n("tab_hidden_tasks"));
        if (rightTabs_->count() > 3)
            rightTabs_->setTabText(3, i18n("tab_rules"));
    }
    if (hiddenTasksTree_)
        hiddenTasksTree_->setHeaderLabels({i18n("col_task_name"), i18n("col_task_loc"), i18n("col_task_cmd")});
    if (rulesTree_)
        rulesTree_->setHeaderLabels({i18n("col_rule_id"), i18n("col_rule_pri"),
                                     i18n("col_rule_cat"), i18n("col_rule_src"),
                                     i18n("col_rule_ann")});
    if (rulesReloadBtn_)
        rulesReloadBtn_->setText(i18n("rules_reload"));
    // Refresh HTML panels that embed translated strings
    updateStatistics();
}

void MainWindow::onLanguageEnglish() {
    I18n::instance().setLanguage(I18n::English);
    RuleEngine_SetPreferEnglish(true);
    {
        QSettings s(QStringLiteral("ProcessAnnotator"), QStringLiteral("ProcessAnnotator"));
        s.setValue(QStringLiteral("ui/language"), QStringLiteral("en"));
    }
    retranslateUi();
    reapplyAnnotations();
    buildTree();
    updateStatistics();
    updateRulesList();
    updateHiddenTasks();
}

void MainWindow::onLanguageRussian() {
    I18n::instance().setLanguage(I18n::Russian);
    RuleEngine_SetPreferEnglish(false);
    {
        QSettings s(QStringLiteral("ProcessAnnotator"), QStringLiteral("ProcessAnnotator"));
        s.setValue(QStringLiteral("ui/language"), QStringLiteral("ru"));
    }
    retranslateUi();
    reapplyAnnotations();
    buildTree();
    updateStatistics();
    updateRulesList();
    updateHiddenTasks();
}

void MainWindow::reapplyAnnotations() {
    for (auto& p : processes_) {
        if (!p) continue;
        p->annotation = engine_.Match(*p);
    }
}

void MainWindow::showDiffDialog() {
    if (!hasSnapshot_) {
        QMessageBox::information(this, i18n("diff_title"), i18n("diff_none"));
        return;
    }
    const auto& d = lastDiff_;
    if (d.added.empty() && d.removed.empty() && d.parentChanged.empty()) {
        QMessageBox::information(this, i18n("diff_title"), i18n("diff_none"));
        return;
    }
    QString text;
    text += i18n("diff_summary")
                .arg(d.added.size())
                .arg(d.removed.size())
                .arg(d.parentChanged.size());
    text += QStringLiteral("\n\n");
    if (!d.added.empty()) {
        text += i18n("diff_added") + QStringLiteral(":\n");
        for (const auto& e : d.added)
            text += QStringLiteral("  + [%1] %2\n")
                        .arg(e.pid)
                        .arg(QString::fromStdWString(e.name));
        text += QStringLiteral("\n");
    }
    if (!d.removed.empty()) {
        text += i18n("diff_removed") + QStringLiteral(":\n");
        for (const auto& e : d.removed)
            text += QStringLiteral("  - [%1] %2\n")
                        .arg(e.pid)
                        .arg(QString::fromStdWString(e.name));
        text += QStringLiteral("\n");
    }
    if (!d.parentChanged.empty()) {
        text += i18n("diff_parent") + QStringLiteral(":\n");
        for (const auto& e : d.parentChanged)
            text += QStringLiteral("  ~ [%1] %2\n")
                        .arg(e.pid)
                        .arg(QString::fromStdWString(e.name));
    }
    QMessageBox::information(this, i18n("diff_title"), text);
}

void MainWindow::onShowDiff() {
    showDiffDialog();
}

void MainWindow::onToggleAutoDiff(bool checked) {
    autoShowDiff_ = checked;
    QSettings s(QStringLiteral("ProcessAnnotator"), QStringLiteral("ProcessAnnotator"));
    s.setValue(QStringLiteral("ui/autoShowDiff"), checked);
}

void MainWindow::onThemeDark() {
    applyTheme(AppTheme::Dark);
    saveTheme(AppTheme::Dark);
    if (actThemeDark_) actThemeDark_->setChecked(true);
    if (actThemeLight_) actThemeLight_->setChecked(false);
    if (actThemeSystem_) actThemeSystem_->setChecked(false);
    buildTree();
    filterModulesList();
    updateHiddenTasks();
    updateRulesList();
}
void MainWindow::onThemeLight() {
    applyTheme(AppTheme::Light);
    saveTheme(AppTheme::Light);
    if (actThemeDark_) actThemeDark_->setChecked(false);
    if (actThemeLight_) actThemeLight_->setChecked(true);
    if (actThemeSystem_) actThemeSystem_->setChecked(false);
    buildTree();
    filterModulesList();
    updateHiddenTasks();
    updateRulesList();
}
void MainWindow::onThemeSystem() {
    applyTheme(AppTheme::System);
    saveTheme(AppTheme::System);
    if (actThemeDark_) actThemeDark_->setChecked(false);
    if (actThemeLight_) actThemeLight_->setChecked(false);
    if (actThemeSystem_) actThemeSystem_->setChecked(true);
    buildTree();
    filterModulesList();
    updateHiddenTasks();
    updateRulesList();
}

void MainWindow::onModuleSearchChanged(const QString& text) {
    moduleSearchText_ = text.trimmed();
    filterModulesList();
}

void MainWindow::filterModulesList() {
    if (!modulesTree_) return;
    modulesTree_->clear();
    const QList<QStringList> groups = parseSearchGroups(moduleSearchText_);
    for (auto& m : moduleRows_) {
        if (!groups.isEmpty()) {
            auto rowHitNoHash = [&](const QString& t) {
                return m.name.contains(t, Qt::CaseInsensitive)
                    || m.path.contains(t, Qt::CaseInsensitive)
                    || m.sig.contains(t, Qt::CaseInsensitive)
                    || m.anomaly.contains(t, Qt::CaseInsensitive);
            };
            auto groupMatches = [&](const QStringList& tokens) {
                for (const QString& t : tokens) {
                    if (rowHitNoHash(t))
                        continue;
                    if (tokenLooksLikeHash(t)) {
                        if (!m.hashComputed) {
                            if (!m.path.isEmpty())
                                m.hash = QString::fromStdWString(FileSha256(m.path.toStdWString()));
                            m.hashComputed = true;
                        }
                        if (m.hash.contains(t, Qt::CaseInsensitive))
                            continue;
                    }
                    return false;
                }
                return true;
            };
            bool any = false;
            for (const QStringList& tokens : groups) {
                if (groupMatches(tokens)) { any = true; break; }
            }
            if (!any) continue;
        }

        auto* item = new QTreeWidgetItem(modulesTree_);
        item->setText(0, m.name);
        item->setText(1, m.sig);
        item->setText(2, m.anomaly);
        item->setText(3, m.path);
        item->setData(0, Qt::UserRole, m.hash);
        item->setData(2, Qt::UserRole, static_cast<int>(m.anomalyKind));
        item->setToolTip(3, m.hash.isEmpty() ? m.path : (m.path + QStringLiteral("\nSHA-256: ") + m.hash));
        const UiColors c = uiColors();
        if (m.anomalyKind == ModuleAnomaly::MissingOnDisk) {
            item->setForeground(2, c.missingFg);
            item->setBackground(0, c.missingBg);
            item->setBackground(2, c.missingBg);
        } else if (m.anomalyKind == ModuleAnomaly::Pathless
                || m.anomalyKind == ModuleAnomaly::AccessDenied) {
            item->setForeground(2, c.warningFg);
        }
        if (m.unsignedSig)
            item->setForeground(1, c.unsignedFg);
    }
}

void MainWindow::onVtApiKey() {
    bool ok = false;
    const QString current = VirusTotalClient::apiKey();
    const QString key = QInputDialog::getText(
        this, i18n("vt_api_title"), i18n("vt_api_prompt"),
        QLineEdit::Normal, current, &ok);
    if (ok)
        VirusTotalClient::setApiKey(key);
}

void MainWindow::onAbout() {
    QMessageBox::about(this, i18n("about"), i18n("about_text"));
}

void MainWindow::checkVirusTotal(const QString& path) {
    if (path.isEmpty()) {
        QMessageBox::warning(this, i18n("error"), i18n("vt_no_path"));
        return;
    }
    if (!VirusTotalClient::hasApiKey()) {
        QMessageBox::information(this, i18n("vt_result_title"), i18n("vt_no_key"));
        onVtApiKey();
        if (!VirusTotalClient::hasApiKey())
            return;
    }
    if (!QFileInfo::exists(path)) {
        QMessageBox::warning(this, i18n("file_not_found"),
                             i18n("path_missing").arg(path));
        return;
    }
    status_->setText(i18n("vt_hashing"));
    vt_->checkFile(path);
}

void MainWindow::onVtProgress(const QString& msg) {
    status_->setText(msg);
}

void MainWindow::onVtFinished(const VirusTotalResult& result) {
    QMessageBox box(this);
    box.setWindowTitle(i18n("vt_result_title"));
    box.setText(result.summary.isEmpty() ? result.error : result.summary);
    box.setIcon(result.ok
                    ? ((result.malicious + result.suspicious > 0)
                           ? QMessageBox::Warning
                           : QMessageBox::Information)
                    : QMessageBox::Critical);
    QPushButton* openBtn = nullptr;
    if (!result.permalink.isEmpty())
        openBtn = box.addButton(i18n("vt_link"), QMessageBox::ActionRole);
    box.addButton(i18n("ok"), QMessageBox::AcceptRole);
    box.exec();
    if (openBtn && box.clickedButton() == openBtn)
        QDesktopServices::openUrl(QUrl(result.permalink));
}

void MainWindow::openInExplorer(const QString& path) {
    if (path.isEmpty()) return;
    QFileInfo fi(path);
    if (!fi.exists()) {
        QMessageBox::warning(this, i18n("file_not_found"), i18n("path_missing").arg(path));
        return;
    }
    const QString native = QDir::toNativeSeparators(fi.absoluteFilePath());
    const QString param = QStringLiteral("/select,\"%1\"").arg(native);
    ShellExecuteW(nullptr, L"open", L"explorer.exe",
                  reinterpret_cast<LPCWSTR>(param.utf16()), nullptr, SW_SHOWNORMAL);
}

void MainWindow::showFileProperties(const QString& path) {
    if (path.isEmpty()) return;
    QFileInfo fi(path);
    if (!fi.exists()) {
        QMessageBox::warning(this, i18n("file_not_found"), i18n("path_missing").arg(path));
        return;
    }
    const QString native = QDir::toNativeSeparators(fi.absoluteFilePath());
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_INVOKEIDLIST;
    sei.hwnd = reinterpret_cast<HWND>(winId());
    sei.lpVerb = L"properties";
    sei.lpFile = reinterpret_cast<LPCWSTR>(native.utf16());
    sei.nShow = SW_SHOW;
    ShellExecuteExW(&sei);
}

void MainWindow::onModulesContextMenu(const QPoint& pos) {
    QTreeWidgetItem* item = modulesTree_->itemAt(pos);
    if (!item) return;
    const QString name = item->text(0);
    const QString path = item->text(3);
    const QString sig  = item->text(1);

    QMenu menu(this);
    QAction* actOpen = menu.addAction(i18n("go_to_file"));
    QAction* actProps = menu.addAction(i18n("properties"));
    QAction* actVt = menu.addAction(i18n("vt_check"));
    menu.addSeparator();
    QAction* actCopyPath = menu.addAction(i18n("copy_path"));
    QAction* actCopyName = menu.addAction(i18n("copy_name"));
    QAction* actCopySig = menu.addAction(i18n("copy_signature"));
    QString hash = item->data(0, Qt::UserRole).toString();
    QAction* actCopyHash = menu.addAction(i18n("copy_hash"));
    actCopyHash->setEnabled(!path.isEmpty());

    QAction* chosen = menu.exec(modulesTree_->viewport()->mapToGlobal(pos));
    if (!chosen) return;
    if (chosen == actOpen) openInExplorer(path);
    else if (chosen == actProps) showFileProperties(path);
    else if (chosen == actVt) checkVirusTotal(path);
    else if (chosen == actCopyPath) QApplication::clipboard()->setText(path);
    else if (chosen == actCopyName) QApplication::clipboard()->setText(name);
    else if (chosen == actCopySig) QApplication::clipboard()->setText(sig);
    else if (chosen == actCopyHash) {
        if (hash.isEmpty() && !path.isEmpty())
            hash = QString::fromStdWString(FileSha256(path.toStdWString()));
        if (!hash.isEmpty())
            QApplication::clipboard()->setText(hash);
    }
}

void MainWindow::onTreeContextMenu(const QPoint& pos) {
    QTreeWidgetItem* item = tree_->itemAt(pos);
    if (!item) return;
    quintptr ptr = item->data(0, Qt::UserRole).value<quintptr>();
    auto* proc = reinterpret_cast<ProcessInfo*>(ptr);
    if (!proc) return;

    const QString path = QString::fromStdWString(proc->imagePath);
    const QString name = QString::fromStdWString(proc->name);
    const QString cmd  = QString::fromStdWString(proc->commandLine);

    QMenu menu(this);
    QAction* actOpen = menu.addAction(i18n("go_to_file"));
    actOpen->setEnabled(!path.isEmpty());
    QAction* actProps = menu.addAction(i18n("properties"));
    actProps->setEnabled(!path.isEmpty());
    QAction* actVt = menu.addAction(i18n("vt_check"));
    actVt->setEnabled(!path.isEmpty());
    menu.addSeparator();
    QAction* actCopyPath = menu.addAction(i18n("copy_path"));
    actCopyPath->setEnabled(!path.isEmpty());
    QAction* actCopyCmd = menu.addAction(i18n("copy_cmdline"));
    actCopyCmd->setEnabled(!cmd.isEmpty());
    QAction* actCopyName = menu.addAction(i18n("copy_name"));
    QAction* actCopyPid = menu.addAction(i18n("copy_pid"));
    QAction* actCopyHash = menu.addAction(i18n("copy_hash"));
    actCopyHash->setEnabled(!path.isEmpty());

    QAction* chosen = menu.exec(tree_->viewport()->mapToGlobal(pos));
    if (!chosen) return;
    if (chosen == actOpen) openInExplorer(path);
    else if (chosen == actProps) showFileProperties(path);
    else if (chosen == actVt) checkVirusTotal(path);
    else if (chosen == actCopyPath) QApplication::clipboard()->setText(path);
    else if (chosen == actCopyCmd) QApplication::clipboard()->setText(cmd);
    else if (chosen == actCopyName) QApplication::clipboard()->setText(name);
    else if (chosen == actCopyPid) QApplication::clipboard()->setText(QString::number(proc->pid));
    else if (chosen == actCopyHash) {
        const QString hash = ensureProcessSha256(proc);
        if (!hash.isEmpty())
            QApplication::clipboard()->setText(hash);
    }
}

bool MainWindow::passesFilter(const ProcessInfo* proc) const {
    return ::passesFilter(proc, filter_);
}

bool MainWindow::matchesSearch(const ProcessInfo* proc) const {
    return ::matchesSearch(proc, searchText_);
}

bool MainWindow::shouldShowNode(const ProcessInfo* proc) const {
    return ::shouldShowNode(proc, filter_, searchText_);
}

void MainWindow::addNode(QTreeWidgetItem* parentItem, ProcessInfo* proc) {
    if (!shouldShowNode(proc)) return;
    const bool selfMatch = passesFilter(proc) && matchesSearch(proc);

    auto* item = parentItem ? new QTreeWidgetItem(parentItem) : new QTreeWidgetItem(tree_);
    QString name = QString::fromStdWString(proc->name);
    if (!proc->children.empty())
        name += QStringLiteral("  (%1)").arg(proc->children.size());
    item->setText(0, name);
    item->setText(1, QString::number(proc->pid));
    if (proc->annotation) {
        item->setText(2, QString::fromWCharArray(CategoryToString(proc->annotation->category)));
        item->setForeground(2, categoryColor(proc->annotation->category));
        item->setForeground(0, categoryColor(proc->annotation->category));
    }
    if (proc->signature.isSigned)
        item->setText(3, QString::fromStdWString(proc->signature.status));
    else if (!proc->imagePath.empty())
        item->setText(3, i18n("unsigned"));

    item->setData(0, Qt::UserRole, QVariant::fromValue(reinterpret_cast<quintptr>(proc)));
    const UiColors c = uiColors();
    if (proc->isNew) {
        item->setBackground(0, c.newProcBg);
        item->setBackground(1, c.newProcBg);
        item->setBackground(2, c.newProcBg);
        item->setBackground(3, c.newProcBg);
    } else if (proc->parentChanged) {
        item->setBackground(0, c.parentChangedBg);
        item->setBackground(1, c.parentChangedBg);
    }
    if (!searchText_.isEmpty() && selfMatch) {
        item->setBackground(0, c.searchHitBg);
        item->setBackground(1, c.searchHitBg);
    }

    std::vector<ProcessInfo*> kids = proc->children;
    std::sort(kids.begin(), kids.end(),
              [](ProcessInfo* a, ProcessInfo* b) { return a->name < b->name; });
    for (ProcessInfo* child : kids)
        addNode(item, child);
    if (!searchText_.isEmpty() && parentItem)
        parentItem->setExpanded(true);
}

void MainWindow::releaseProcessUi() {
    if (searchDebounce_)
        searchDebounce_->stop();
    if (tree_) {
        tree_->blockSignals(true);
        tree_->clear();
        tree_->blockSignals(false);
    }
    if (details_)
        details_->clear();
    if (modulesTree_)
        modulesTree_->clear();
    moduleRows_.clear();
}

void MainWindow::buildTree() {
    DWORD keepPid = pendingSelectPid_;
    QString keepPath = pendingSelectPath_;
    pendingSelectPid_ = 0;
    pendingSelectPath_.clear();
    if (!keepPid && tree_) {
        const auto selected = tree_->selectedItems();
        if (!selected.isEmpty()) {
            const quintptr ptr = selected.first()->data(0, Qt::UserRole).value<quintptr>();
            if (auto* proc = reinterpret_cast<ProcessInfo*>(ptr)) {
                keepPid = proc->pid;
                keepPath = QString::fromStdWString(proc->imagePath);
            }
        }
    }

    tree_->blockSignals(true);
    tree_->clear();
    details_->clear();
    modulesTree_->clear();
    for (ProcessInfo* root : roots_)
        addNode(nullptr, root);
    if (searchText_.isEmpty())
        tree_->expandToDepth(1);
    else
        tree_->expandAll();

    QTreeWidgetItem* found = nullptr;
    if (keepPid) {
        std::function<QTreeWidgetItem*(QTreeWidgetItem*)> walk = [&](QTreeWidgetItem* it) -> QTreeWidgetItem* {
            if (!it) return nullptr;
            const quintptr ptr = it->data(0, Qt::UserRole).value<quintptr>();
            auto* proc = reinterpret_cast<ProcessInfo*>(ptr);
            if (proc && proc->pid == keepPid) {
                if (keepPath.isEmpty() || QString::fromStdWString(proc->imagePath) == keepPath)
                    return it;
            }
            for (int i = 0; i < it->childCount(); ++i) {
                if (auto* hit = walk(it->child(i)))
                    return hit;
            }
            return nullptr;
        };
        for (int i = 0; i < tree_->topLevelItemCount(); ++i) {
            found = walk(tree_->topLevelItem(i));
            if (found) break;
        }
    }
    tree_->blockSignals(false);
    if (found) {
        tree_->setCurrentItem(found);
        found->setSelected(true);
        onSelectionChanged();
    }
}

void MainWindow::showDetails(ProcessInfo* proc) {
    if (!proc) { details_->clear(); return; }
    const UiColors c = uiColors();
    const QString muted = c.muted.name();
    const QString border = c.border.name();
    const QString pathCol = c.codePath.name();
    const QString cmdCol = c.codeCmd.name();
    const QString hashCol = c.codeHash.name();
    const QString unsignedCol = c.unsignedFg.name();
    const QString warnCol = c.warningFg.name();
    QString html;
    html += QStringLiteral("<h2 style='margin:4px 0'>%1 <span style='color:%2'>PID %3</span></h2>")
                .arg(QString::fromStdWString(proc->name).toHtmlEscaped(), muted)
                .arg(proc->pid);
    if (proc->annotation) {
        QString cat = QString::fromWCharArray(CategoryToString(proc->annotation->category));
        QColor col = categoryColor(proc->annotation->category);
        html += QStringLiteral("<p style='margin:4px 0'><b>%1</b> <span style='color:%2;font-weight:bold'>%3</span></p>")
                    .arg(i18n("category"), col.name(), cat);
        html += QStringLiteral("<p style='margin:4px 0'><b>%1</b><br>%2</p>")
                    .arg(i18n("annotation"),
                         QString::fromStdWString(proc->annotation->annotation).toHtmlEscaped());
        if (!proc->annotation->actions.empty()) {
            html += QStringLiteral("<p style='margin:4px 0'><b>%1</b><ul style='margin:2px 0'>").arg(i18n("actions"));
            for (const auto& a : proc->annotation->actions)
                html += QStringLiteral("<li>%1</li>").arg(QString::fromStdWString(a).toHtmlEscaped());
            html += QStringLiteral("</ul></p>");
        }
    } else {
        html += QStringLiteral("<p style='color:%1'><i>%2</i></p>").arg(muted, i18n("no_annotation"));
    }
    html += QStringLiteral("<hr style='border-color:%1'>").arg(border);
    if (!proc->imagePath.empty())
        html += QStringLiteral("<p style='margin:4px 0'><b>%1</b><br><code style='color:%2'>%3</code></p>")
                    .arg(i18n("path"), pathCol, QString::fromStdWString(proc->imagePath).toHtmlEscaped());
    if (!proc->commandLine.empty())
        html += QStringLiteral("<p style='margin:4px 0'><b>%1</b><br><code style='color:%2'>%3</code></p>")
                    .arg(i18n("cmdline"), cmdCol, QString::fromStdWString(proc->commandLine).toHtmlEscaped());
    if (!proc->serviceName.empty())
        html += QStringLiteral("<p style='margin:4px 0'><b>%1</b> %2</p>")
                    .arg(i18n("service"), QString::fromStdWString(proc->serviceName).toHtmlEscaped());
    html += QStringLiteral("<p style='margin:4px 0'><b>%1</b> ").arg(i18n("signature"));
    if (proc->signature.isSigned) {
        html += QString::fromStdWString(proc->signature.status).toHtmlEscaped();
        if (!proc->signature.publisher.empty())
            html += QStringLiteral(" — %1").arg(QString::fromStdWString(proc->signature.publisher).toHtmlEscaped());
    } else if (!proc->imagePath.empty()) {
        html += QStringLiteral("<span style='color:%1'>%2</span>").arg(unsignedCol, i18n("unsigned"));
    } else html += QStringLiteral("—");
    html += QStringLiteral("</p>");
    html += QStringLiteral("<p style='margin:4px 0'><b>PPID:</b> %1 &nbsp; <b>Session:</b> %2</p>")
                .arg(proc->ppid).arg(proc->sessionId);
    if (proc->parent)
        html += QStringLiteral("<p style='margin:4px 0'><b>%1</b> %2 (PID %3)</p>")
                    .arg(i18n("parent"),
                         QString::fromStdWString(proc->parent->name).toHtmlEscaped())
                    .arg(proc->parent->pid);


    html += QStringLiteral("<hr style='border-color:%1'>").arg(border);
    if (!proc->userName.empty())
        html += QStringLiteral("<p style='margin:4px 0'><b>%1</b> %2</p>")
                    .arg(i18n("prop_user"),
                         QString::fromStdWString(proc->userName).toHtmlEscaped());
    if (!proc->integrity.empty())
        html += QStringLiteral("<p style='margin:4px 0'><b>%1</b> %2</p>")
                    .arg(i18n("prop_integrity"),
                         QString::fromStdWString(proc->integrity).toHtmlEscaped());
    if (!proc->arch.empty())
        html += QStringLiteral("<p style='margin:4px 0'><b>%1</b> %2</p>")
                    .arg(i18n("prop_arch"),
                         QString::fromStdWString(proc->arch).toHtmlEscaped());
    if (!proc->startTime.empty())
        html += QStringLiteral("<p style='margin:4px 0'><b>%1</b> %2</p>")
                    .arg(i18n("prop_started"),
                         QString::fromStdWString(proc->startTime).toHtmlEscaped());
    if (proc->workingSetBytes || proc->privateBytes) {
        auto fmt = [](size_t b) -> QString {
            if (b >= 1024ull * 1024ull * 1024ull)
                return QStringLiteral("%1 GB").arg(b / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
            if (b >= 1024ull * 1024ull)
                return QStringLiteral("%1 MB").arg(b / (1024.0 * 1024.0), 0, 'f', 1);
            if (b >= 1024ull)
                return QStringLiteral("%1 KB").arg(b / 1024.0, 0, 'f', 0);
            return QStringLiteral("%1 B").arg(b);
        };
        html += QStringLiteral("<p style='margin:4px 0'><b>%1</b> %2 / %3</p>")
                    .arg(i18n("prop_memory"), fmt(proc->workingSetBytes), fmt(proc->privateBytes));
    }
    const QString sha = ensureProcessSha256(proc);
    if (!sha.isEmpty())
        html += QStringLiteral("<p style='margin:4px 0'><b>%1</b><br>"
                               "<code style='color:%2'>%3</code></p>")
                    .arg(i18n("prop_sha256"), hashCol, sha.toHtmlEscaped());

    // Autostart / persistence
    html += QStringLiteral("<hr style='border-color:%1'>").arg(border);
    html += QStringLiteral("<p style='margin:4px 0'><b>%1</b></p>").arg(i18n("autostart_title"));
    if (!proc->imagePath.empty()) {
        auto hits = autostart_.findForImage(proc->imagePath);
        if (hits.empty()) {
            html += QStringLiteral("<p style='color:%1'><i>%2</i></p>").arg(muted, i18n("autostart_none"));
        } else {
            html += QStringLiteral("<ul style='margin:4px 0'>");
            for (const auto& e : hits) {
                QString typeLabel;
                switch (e.type) {
                    case AutostartType::RunKey: typeLabel = i18n("autostart_run"); break;
                    case AutostartType::Service: typeLabel = i18n("autostart_svc"); break;
                    case AutostartType::ScheduledTask: typeLabel = i18n("autostart_task"); break;
                }
                QString badge;
                if (e.hidden)
                    badge = QStringLiteral(" <span style='color:%1;font-weight:bold'>[%2]</span>")
                                .arg(warnCol, i18n("hidden_badge"));
                html += QStringLiteral("<li><b>[%1]</b> %2%3<br>"
                                       "<span style='color:%4'>%5</span><br>"
                                       "<code style='color:%6'>%7</code></li>")
                            .arg(typeLabel.toHtmlEscaped(),
                                 QString::fromStdWString(e.name).toHtmlEscaped(),
                                 badge,
                                 muted,
                                 QString::fromStdWString(e.location).toHtmlEscaped(),
                                 cmdCol,
                                 QString::fromStdWString(e.command).toHtmlEscaped());
            }
            html += QStringLiteral("</ul>");
        }
    } else {
        html += QStringLiteral("<p style='color:%1'><i>%2</i></p>").arg(muted, i18n("autostart_none"));
    }

    details_->setHtml(html);
}

void MainWindow::loadModules(ProcessInfo* proc) {
    modulesTree_->clear();
    if (!proc || proc->pid == 0 || proc->pid == 4) return;
    status_->setText(i18n("loading_modules").arg(proc->pid));
    QApplication::processEvents();
    auto modules = EnumerateModules(proc->pid, true);
    moduleRows_.clear();
    int suspicious = 0;
    for (const auto& m : modules) {
        ModuleRow row;
        row.name = QString::fromStdWString(m.name);
        row.anomalyKind = m.anomaly;
        if (m.signature.isSigned)
            row.sig = QString::fromStdWString(m.signature.status);
        else if (!m.path.empty() && m.anomaly != ModuleAnomaly::MissingOnDisk) {
            row.sig = i18n("unsigned");
            row.unsignedSig = true;
        }
        if (m.anomaly == ModuleAnomaly::MissingOnDisk) {
            row.anomaly = i18n("anomaly_missing");
            row.suspicious = true;
            ++suspicious;
        } else if (m.anomaly == ModuleAnomaly::Pathless) {
            row.anomaly = i18n("anomaly_pathless");
            row.suspicious = true;
            ++suspicious;
        } else if (m.anomaly == ModuleAnomaly::AccessDenied) {
            row.anomaly = i18n("anomaly_denied");
        }
        row.path = QString::fromStdWString(m.path);
        row.hash = QString::fromStdWString(m.sha256);
        moduleRows_.push_back(row);
    }
    filterModulesList();

    QString st = i18n("status_modules")
                     .arg(processes_.size()).arg(proc->pid).arg(modules.size())
                     .arg(SignatureCacheSize()).arg(SignatureCacheHits());
    if (suspicious > 0)
        st += QStringLiteral("  |  ") + i18n("anomaly_count").arg(suspicious);
    status_->setText(st);
    SaveSignatureCache();
    SaveHashCache();
}

QString MainWindow::buildReportText() const {
    return ::buildReportText(processes_, roots_, filter_, searchText_, engine_.RuleCount());
}

QString MainWindow::buildReportHtml() const {
    return ::buildReportHtml(processes_, roots_, filter_, searchText_, engine_.RuleCount());
}

void MainWindow::onExportHtmlReport() {
    const QString defaultName = QStringLiteral("ProcessAnnotator_%1.html")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));
    QString path = QFileDialog::getSaveFileName(
        this, i18n("export_html"),
        QDir::homePath() + QLatin1Char('/') + defaultName,
        i18n("export_filter_html"));
    if (path.isEmpty()) return;
    if (!path.endsWith(QStringLiteral(".html"), Qt::CaseInsensitive) &&
        !path.endsWith(QStringLiteral(".htm"), Qt::CaseInsensitive))
        path += QStringLiteral(".html");

    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, i18n("error"), i18n("export_error").arg(path));
        return;
    }
    QTextStream ts(&f);
    ts.setEncoding(QStringConverter::Utf8);
    ts << buildReportHtml();
    f.close();
    status_->setText(i18n("export_status").arg(path));
    QMessageBox::information(this, i18n("export_html"), i18n("export_done").arg(path));
}

void MainWindow::onExportReport() {
    const QString defaultName = QStringLiteral("ProcessAnnotator_%1.txt")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));
    QString path = QFileDialog::getSaveFileName(this, i18n("export_title"),
        QDir::homePath() + QLatin1Char('/') + defaultName, i18n("export_filter_html"));
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, i18n("error"), i18n("export_error").arg(path));
        return;
    }
    QTextStream ts(&f);
    ts.setEncoding(QStringConverter::Utf8);
    if (path.endsWith(QStringLiteral(".html"), Qt::CaseInsensitive) ||
        path.endsWith(QStringLiteral(".htm"), Qt::CaseInsensitive))
        ts << buildReportHtml();
    else
        ts << buildReportText();
    f.close();
    status_->setText(i18n("export_status").arg(path));
    QMessageBox::information(this, i18n("export_title"), i18n("export_done").arg(path));
}

void MainWindow::onSearchTextChanged(const QString& text) {
    searchText_ = text.trimmed();
    if (searchDebounce_)
        searchDebounce_->start();
    else
        applySearch();
}

void MainWindow::applySearch() {
    if (refreshBusy_)
        return;
    buildTree();
}






void MainWindow::updateRulesList() {
    if (!rulesTree_) return;
    rulesTree_->setSortingEnabled(false);
    rulesTree_->clear();
    const auto& rules = engine_.rules();
    for (const auto& r : rules) {
        auto* item = new QTreeWidgetItem(rulesTree_);
        item->setText(0, QString::fromStdWString(r.id));
        item->setText(1, QString::number(r.priority));
        item->setData(1, Qt::DisplayRole, r.priority);
        item->setText(2, QString::fromWCharArray(CategoryToString(r.category)));
        item->setText(3, QString::fromStdWString(r.sourceFile));
        QString ann = RuleEngine_PreferEnglish()
            ? QString::fromStdWString(r.annotationEn.empty() ? r.annotation : r.annotationEn)
            : QString::fromStdWString(r.annotation);
        item->setText(4, ann);
        item->setToolTip(4, ann);
        if (r.sourceFile.find(L"rules.d") != std::wstring::npos)
            item->setForeground(3, uiColors().packSrcFg);
    }
    rulesTree_->setSortingEnabled(true);
    if (rulesStatus_) {
        QString text = i18n("rules_count")
            .arg(engine_.RuleCount())
            .arg(engine_.loadedFiles().size());
        if (!engine_.loadErrors().empty())
            text += QStringLiteral("  |  ") + i18n("rules_errors").arg(engine_.loadErrors().size());
        rulesStatus_->setText(text);
    }
    if (rulesErrors_) {
        if (engine_.loadErrors().empty()) {
            rulesErrors_->clear();
            rulesErrors_->hide();
        } else {
            QStringList lines;
            for (const auto& err : engine_.loadErrors()) {
                QString src = QString::fromStdWString(err.source);
                QString msg = QString::fromStdWString(err.message);
                if (err.line > 0)
                    lines << i18n("rules_error_line").arg(src).arg(err.line).arg(msg);
                else
                    lines << i18n("rules_error").arg(src).arg(msg);
            }
            rulesErrors_->setText(lines.join(QLatin1Char('\n')));
            rulesErrors_->setStyleSheet(QStringLiteral("color: %1;").arg(uiColors().unsignedFg.name()));
            rulesErrors_->show();
        }
    }
}

void MainWindow::onReloadRules() {
    engine_.reload();
    RuleEngine_SetPreferEnglish(I18n::instance().language() == I18n::English);
    // Re-annotate processes with new rules
    for (auto& p : processes_) {
        if (!p) continue;
        p->annotation = engine_.Match(*p);
    }
    buildTree();
    updateRulesList();
    updateStatistics();
    QString status = i18n("rules_reloaded").arg(engine_.RuleCount());
    if (!engine_.loadErrors().empty())
        status += QStringLiteral("  |  ") + i18n("rules_errors").arg(engine_.loadErrors().size());
    status_->setText(status);
    if (!engine_.loadErrors().empty()) {
        QStringList lines;
        for (const auto& err : engine_.loadErrors()) {
            QString src = QString::fromStdWString(err.source);
            QString msg = QString::fromStdWString(err.message);
            if (err.line > 0)
                lines << i18n("rules_error_line").arg(src).arg(err.line).arg(msg);
            else
                lines << i18n("rules_error").arg(src).arg(msg);
        }
        QMessageBox::warning(this, i18n("tab_rules"), lines.join(QLatin1Char('\n')));
        if (rightTabs_)
            rightTabs_->setCurrentIndex(3);
    }
}

void MainWindow::updateHiddenTasks() {
    if (!hiddenTasksTree_) return;
    hiddenTasksTree_->clear();
    auto list = autostart_.hiddenTasks();
    if (hiddenTasksStatus_)
        hiddenTasksStatus_->setText(i18n("hidden_count").arg(list.size()));
    if (list.empty()) {
        auto* item = new QTreeWidgetItem(hiddenTasksTree_);
        item->setText(0, i18n("hidden_empty"));
        return;
    }
    for (const auto& e : list) {
        auto* item = new QTreeWidgetItem(hiddenTasksTree_);
        QString name = QString::fromStdWString(e.name).trimmed();
        QString loc = QString::fromStdWString(e.location).trimmed();
        QString cmd = QString::fromStdWString(e.command).trimmed();
        if (name.isEmpty())
            name = QString::fromStdWString(e.imagePath).trimmed();
        if (name.isEmpty())
            name = i18n("hidden_unnamed");
        if (cmd.isEmpty() && !e.imagePath.empty())
            cmd = QString::fromStdWString(e.imagePath);
        item->setText(0, name);
        item->setText(1, loc);
        item->setText(2, cmd);
        item->setForeground(0, uiColors().hiddenTaskFg);
        if (!cmd.isEmpty())
            item->setToolTip(2, cmd);
        item->setToolTip(0, name);
    }
}

void MainWindow::updateStatistics() {
    if (!statsText_) return;

    size_t annotated = 0, unsignedCount = 0, newCount = 0;
    std::map<QString, int> byCat;
    std::map<QString, int> byName;

    for (const auto& p : processes_) {
        if (!p) continue;
        byName[QString::fromStdWString(p->name)]++;
        if (p->isNew) newCount++;
        if (!p->signature.isSigned && !p->imagePath.empty())
            unsignedCount++;
        if (p->annotation) {
            annotated++;
            QString cat = QString::fromWCharArray(CategoryToString(p->annotation->category));
            byCat[cat]++;
        } else {
            byCat[i18n("stats_no_ann")]++;
        }
    }

    QString html;
    html += QStringLiteral("<h2>%1</h2>").arg(i18n("stats_title"));
    html += QStringLiteral("<p>%1</p>").arg(i18n("stats_total").arg(processes_.size()));
    html += QStringLiteral("<p>%1</p>").arg(i18n("stats_annotated").arg(annotated));
    html += QStringLiteral("<p>%1</p>").arg(i18n("stats_unsigned").arg(unsignedCount));
    html += QStringLiteral("<p>%1</p>").arg(i18n("stats_new").arg(newCount));

    html += QStringLiteral("<h3>%1</h3><ul>").arg(i18n("stats_by_cat"));
    std::vector<std::pair<QString,int>> catVec(byCat.begin(), byCat.end());
    std::sort(catVec.begin(), catVec.end(),
              [](auto& a, auto& b){ return a.second > b.second; });
    for (auto& [k,v] : catVec)
        html += QStringLiteral("<li><b>%1</b>: %2</li>").arg(k.toHtmlEscaped()).arg(v);
    html += QStringLiteral("</ul>");

    html += QStringLiteral("<h3>%1</h3><ul>").arg(i18n("stats_top_names"));
    std::vector<std::pair<QString,int>> nameVec(byName.begin(), byName.end());
    std::sort(nameVec.begin(), nameVec.end(),
              [](auto& a, auto& b){ return a.second > b.second; });
    int shown = 0;
    for (auto& [k,v] : nameVec) {
        if (v < 2 && shown > 15) break;
        html += QStringLiteral("<li><b>%1</b>: %2</li>").arg(k.toHtmlEscaped()).arg(v);
        if (++shown >= 25) break;
    }
    html += QStringLiteral("</ul>");

    statsText_->setHtml(html);
}

void MainWindow::setRefreshBusy(bool busy) {
    refreshBusy_ = busy;
    if (refreshBtn_) refreshBtn_->setEnabled(!busy);
    if (actRefresh_) actRefresh_->setEnabled(!busy);
}

void MainWindow::stopRefreshThread() {
    QThread* thread = refreshThread_;
    RefreshWorker* worker = refreshWorker_;
    refreshThread_ = nullptr;
    refreshWorker_ = nullptr;
    if (thread && thread->isRunning()) {
        thread->requestInterruption();
        thread->quit();
        if (!thread->wait(15000)) {
            thread->terminate();
            thread->wait(2000);
        }
    }
    if (worker) {
        worker->moveToThread(thread ? thread->thread() : QThread::currentThread());
        delete worker;
    }
    delete thread;
}

void MainWindow::onRefresh() {
    if (refreshBusy_)
        return;
    if (refreshThread_ && refreshThread_->isRunning())
        return;
    stopRefreshThread();
    setRefreshBusy(true);
    status_->setText(i18n("collecting"));

    auto* thread = new QThread;
    auto* worker = new RefreshWorker;
    refreshWorker_ = worker;
    refreshThread_ = thread;
    worker->setPreviousSnapshot(lastSnapshot_, hasSnapshot_);
    worker->moveToThread(thread);

    connect(thread, &QThread::started, worker, &RefreshWorker::run, Qt::QueuedConnection);
    connect(worker, &RefreshWorker::stage, this, &MainWindow::onRefreshStage, Qt::QueuedConnection);
    connect(worker, &RefreshWorker::finished, this, &MainWindow::onRefreshFinished, Qt::QueuedConnection);
    connect(worker, &RefreshWorker::failed, this, &MainWindow::onRefreshFailed, Qt::QueuedConnection);
    thread->start();
}

void MainWindow::closeEvent(QCloseEvent* event) {
    stopRefreshThread();
    QMainWindow::closeEvent(event);
}

void MainWindow::onRefreshStage(int stage) {
    if (stage == 1)
        status_->setText(i18n("indexing_autostart"));
    else
        status_->setText(i18n("collecting"));
}

void MainWindow::onRefreshFailed(const QString& error) {
    stopRefreshThread();
    setRefreshBusy(false);
    status_->setText(error);
}

void MainWindow::onRefreshFinished() {
    RefreshResult result;
    if (refreshWorker_)
        result = refreshWorker_->takeResult();
    stopRefreshThread();

    const bool hadPrevious = result.hadPrevious;

    pendingSelectPid_ = 0;
    pendingSelectPath_.clear();
    if (tree_) {
        const auto selected = tree_->selectedItems();
        if (!selected.isEmpty()) {
            const quintptr ptr = selected.first()->data(0, Qt::UserRole).value<quintptr>();
            if (auto* proc = reinterpret_cast<ProcessInfo*>(ptr)) {
                pendingSelectPid_ = proc->pid;
                pendingSelectPath_ = QString::fromStdWString(proc->imagePath);
            }
        }
    }
    releaseProcessUi();

    processes_ = std::move(result.processes);
    roots_ = std::move(result.roots);
    lastDiff_ = std::move(result.diff);
    lastSnapshot_ = std::move(result.snapshot);
    hasSnapshot_ = true;

    status_->setText(i18n("indexing_autostart"));
    try {
        autostart_.rebuild();
    } catch (...) {
        status_->setText(i18n("autostart_failed"));
    }

    reapplyAnnotations();
    size_t annotated = 0;
    for (const auto& p : processes_) {
        if (p && p->annotation) ++annotated;
    }

    buildTree();
    updateStatistics();
    updateHiddenTasks();
    updateRulesList();

    QString status = i18n("status_line")
                         .arg(processes_.size()).arg(annotated).arg(engine_.RuleCount())
                         .arg(SignatureCacheSize()).arg(SignatureCacheHits());
    status += QStringLiteral("  |  ") + i18n("autostart_indexed").arg(autostart_.size());
    status += QStringLiteral("  |  ") + i18n("hidden_count").arg(autostart_.hiddenTaskCount());
    if (hadPrevious) {
        status += QStringLiteral("  |  ") + i18n("diff_summary")
                      .arg(lastDiff_.added.size())
                      .arg(lastDiff_.removed.size())
                      .arg(lastDiff_.parentChanged.size());
    }
    status_->setText(status);
    setRefreshBusy(false);

    if (autoShowDiff_ && hadPrevious &&
        (!lastDiff_.added.empty() || !lastDiff_.removed.empty()
         || !lastDiff_.parentChanged.empty())) {
        showDiffDialog();
    }
}

void MainWindow::onSelectionChanged() {
    auto items = tree_->selectedItems();
    if (items.isEmpty()) {
        details_->clear();
        modulesTree_->clear();
        return;
    }
    quintptr ptr = items.first()->data(0, Qt::UserRole).value<quintptr>();
    auto* proc = reinterpret_cast<ProcessInfo*>(ptr);
    showDetails(proc);
    loadModules(proc);
}

void MainWindow::onFilterChanged(int index) {
    filter_ = static_cast<ProcessFilter>(filterCombo_->itemData(index).toInt());
    buildTree();
}
