#include "ui/MainWindow.hpp"
#include "ui/Theme.hpp"

#include <QApplication>
#include <QFont>

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("ProcessAnnotator"));
    QApplication::setOrganizationName(QStringLiteral("ProcessAnnotator"));

    applyTheme(loadSavedTheme());
    app.setFont(QFont(QStringLiteral("Segoe UI"), 10));

    MainWindow w;
    w.show();
    return app.exec();
}
