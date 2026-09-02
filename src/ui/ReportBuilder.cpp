#include "ReportBuilder.hpp"

#include <QDateTime>
#include <algorithm>
#include <functional>

namespace {

void appendProcessReport(QString& out, const ProcessInfo* proc, int depth,
                         ProcessFilter filter, const QString& searchText) {
    if (!shouldShowNode(proc, filter, searchText)) return;
    const QString indent(depth * 2, QLatin1Char(' '));
    out += indent + QStringLiteral("[%1] %2").arg(proc->pid).arg(QString::fromStdWString(proc->name));
    if (proc->annotation)
        out += QStringLiteral("  [%1]").arg(QString::fromWCharArray(CategoryToString(proc->annotation->category)));
    if (proc->signature.isSigned)
        out += QStringLiteral("  {%1}").arg(QString::fromStdWString(proc->signature.status));
    else if (!proc->imagePath.empty())
        out += QStringLiteral("  {Unsigned}");
    out += QLatin1Char('\n');
    if (proc->annotation) {
        out += indent + QStringLiteral("  -> %1\n").arg(QString::fromStdWString(proc->annotation->annotation));
        for (const auto& a : proc->annotation->actions)
            out += indent + QStringLiteral("     Action: %1\n").arg(QString::fromStdWString(a));
    }
    if (!proc->imagePath.empty())
        out += indent + QStringLiteral("  Path: %1\n").arg(QString::fromStdWString(proc->imagePath));
    if (!proc->commandLine.empty())
        out += indent + QStringLiteral("  Cmd:  %1\n").arg(QString::fromStdWString(proc->commandLine));
    if (!proc->serviceName.empty())
        out += indent + QStringLiteral("  Service: %1\n").arg(QString::fromStdWString(proc->serviceName));
    out += QLatin1Char('\n');
    std::vector<ProcessInfo*> kids = proc->children;
    std::sort(kids.begin(), kids.end(), [](ProcessInfo* a, ProcessInfo* b) { return a->name < b->name; });
    for (ProcessInfo* child : kids)
        appendProcessReport(out, child, depth + 1, filter, searchText);
}

} // namespace

QString buildReportText(const std::vector<std::unique_ptr<ProcessInfo>>& processes,
                        const std::vector<ProcessInfo*>& roots,
                        ProcessFilter filter,
                        const QString& searchText,
                        size_t ruleCount) {
    QString out;
    out += QStringLiteral("ProcessAnnotator Report\n=======================\n");
    out += QStringLiteral("Date: %1\n").arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")));
    out += QStringLiteral("Processes: %1\nRules: %2\n").arg(processes.size()).arg(ruleCount);
    if (!searchText.isEmpty())
        out += QStringLiteral("Search: \"%1\"\n").arg(searchText);
    out += QStringLiteral("\n=== Process tree ===\n\n");
    for (const ProcessInfo* root : roots)
        appendProcessReport(out, root, 0, filter, searchText);
    out += QStringLiteral("\n=== End of report ===\n");
    return out;
}

QString buildReportHtml(const std::vector<std::unique_ptr<ProcessInfo>>& processes,
                        const std::vector<ProcessInfo*>& roots,
                        ProcessFilter filter,
                        const QString& searchText,
                        size_t ruleCount) {
    QString html;
    html += QStringLiteral(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
        "<title>ProcessAnnotator Report</title>"
        "<style>"
        "body{font-family:Segoe UI,Tahoma,sans-serif;background:#1e1e1e;color:#ddd;margin:24px;}"
        "h1{color:#fff;} h2{color:#9cdcfe;margin-top:1.5em;}"
        "table{border-collapse:collapse;width:100%;margin:12px 0;}"
        "th,td{border:1px solid #444;padding:6px 10px;text-align:left;vertical-align:top;}"
        "th{background:#333;}"
        "tr:nth-child(even){background:#2a2a2a;}"
        ".cat{font-weight:600;}"
        ".new{background:#1a3a1a !important;}"
        ".unsigned{color:#f44747;}"
        "code{color:#ce9178;word-break:break-all;}"
        ".meta{color:#888;}"
        "</style></head><body>");
    html += QStringLiteral("<h1>ProcessAnnotator Report</h1>");
    html += QStringLiteral("<p class='meta'>%1</p>")
                .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")));
    html += QStringLiteral("<p>Processes: <b>%1</b> &nbsp; Rules: <b>%2</b></p>")
                .arg(processes.size()).arg(ruleCount);
    if (!searchText.isEmpty())
        html += QStringLiteral("<p>Search filter: <code>%1</code></p>").arg(searchText.toHtmlEscaped());

    html += QStringLiteral("<h2>Process tree</h2><table><tr>"
                           "<th>PID</th><th>Name</th><th>Category</th><th>Signature</th>"
                           "<th>PPID</th><th>Path / Cmd</th></tr>");

    std::function<void(const ProcessInfo*, int)> walk;
    walk = [&](const ProcessInfo* proc, int depth) {
        if (!proc || !shouldShowNode(proc, filter, searchText)) return;
        QString cls;
        if (proc->isNew) cls = QStringLiteral("new");
        QString indent = QStringLiteral("&nbsp;").repeated(depth * 4);
        QString cat = proc->annotation
            ? QString::fromWCharArray(CategoryToString(proc->annotation->category))
            : QStringLiteral("—");
        QString sig = proc->signature.isSigned
            ? QString::fromStdWString(proc->signature.status)
            : (proc->imagePath.empty() ? QStringLiteral("—")
                                       : QStringLiteral("<span class='unsigned'>Unsigned</span>"));
        QString pathCmd;
        if (!proc->imagePath.empty())
            pathCmd += QStringLiteral("<code>%1</code><br>")
                           .arg(QString::fromStdWString(proc->imagePath).toHtmlEscaped());
        if (!proc->commandLine.empty())
            pathCmd += QStringLiteral("<code>%1</code>")
                           .arg(QString::fromStdWString(proc->commandLine).toHtmlEscaped());
        if (proc->annotation)
            pathCmd += QStringLiteral("<br><i>%1</i>")
                           .arg(QString::fromStdWString(proc->annotation->annotation).toHtmlEscaped());

        html += QStringLiteral("<tr class='%1'><td>%2</td><td>%3%4</td><td class='cat'>%5</td>"
                               "<td>%6</td><td>%7</td><td>%8</td></tr>")
                    .arg(cls)
                    .arg(proc->pid)
                    .arg(indent)
                    .arg(QString::fromStdWString(proc->name).toHtmlEscaped())
                    .arg(cat.toHtmlEscaped())
                    .arg(sig)
                    .arg(proc->ppid)
                    .arg(pathCmd);

        std::vector<ProcessInfo*> kids = proc->children;
        std::sort(kids.begin(), kids.end(),
                  [](ProcessInfo* a, ProcessInfo* b){ return a->name < b->name; });
        for (auto* c : kids) walk(c, depth + 1);
    };
    for (auto* root : roots)
        walk(root, 0);

    html += QStringLiteral("</table></body></html>");
    return html;
}
