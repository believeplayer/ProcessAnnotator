#pragma once

#include "core/Rule.hpp"

#include <QApplication>
#include <QPalette>
#include <QColor>
#include <QStyle>
#include <QStyleFactory>
#include <QSettings>
#include <QString>

enum class AppTheme { Dark, Light, System };

inline AppTheme g_appliedTheme = AppTheme::Dark;

inline AppTheme themeFromString(const QString& s) {
    if (s == QLatin1String("light")) return AppTheme::Light;
    if (s == QLatin1String("system")) return AppTheme::System;
    return AppTheme::Dark;
}

inline QString themeToString(AppTheme t) {
    switch (t) {
        case AppTheme::Light:  return QStringLiteral("light");
        case AppTheme::System: return QStringLiteral("system");
        default:               return QStringLiteral("dark");
    }
}

inline bool themeIsDark() {
    if (g_appliedTheme == AppTheme::Dark) return true;
    if (g_appliedTheme == AppTheme::Light) return false;
    if (!qApp) return true;
    return qApp->palette().color(QPalette::Window).lightness() < 128;
}

struct UiColors {
    QColor searchHitBg;
    QColor newProcBg;
    QColor parentChangedBg;
    QColor unsignedFg;
    QColor missingBg;
    QColor missingFg;
    QColor warningFg;
    QColor packSrcFg;
    QColor hiddenTaskFg;
    QColor codePath;
    QColor codeCmd;
    QColor codeHash;
    QColor muted;
    QColor border;
};

inline UiColors uiColors() {
    if (themeIsDark()) {
        return UiColors{
            QColor(0, 90, 140),
            QColor(20, 90, 40),
            QColor(90, 70, 20),
            QColor(244, 71, 71),
            QColor(80, 28, 28),
            QColor(255, 120, 120),
            QColor(220, 150, 50),
            QColor(86, 156, 214),
            QColor(255, 160, 40),
            QColor(156, 220, 254),
            QColor(206, 145, 120),
            QColor(181, 206, 168),
            QColor(136, 136, 136),
            QColor(68, 68, 68),
        };
    }
    return UiColors{
        QColor(180, 220, 255),
        QColor(200, 240, 210),
        QColor(255, 230, 180),
        QColor(180, 20, 20),
        QColor(255, 220, 220),
        QColor(180, 30, 30),
        QColor(160, 90, 0),
        QColor(0, 100, 180),
        QColor(180, 90, 0),
        QColor(0, 80, 160),
        QColor(140, 70, 40),
        QColor(30, 110, 50),
        QColor(100, 100, 100),
        QColor(200, 200, 200),
    };
}

inline QColor categoryColor(Category c) {
    if (themeIsDark()) {
        switch (c) {
            case Category::Telemetry:        return QColor(230, 150, 50);
            case Category::Antivirus:        return QColor(80, 200, 100);
            case Category::BrowserWorker:    return QColor(80, 160, 255);
            case Category::VendorService:    return QColor(200, 100, 255);
            case Category::Updater:          return QColor(60, 200, 200);
            case Category::Suspicious:       return QColor(255, 80, 80);
            case Category::LegitimateWorker: return QColor(180, 180, 180);
            case Category::System:           return QColor(140, 140, 140);
            default:                         return QColor(160, 160, 160);
        }
    }
    switch (c) {
        case Category::Telemetry:        return QColor(170, 90, 0);
        case Category::Antivirus:        return QColor(20, 130, 50);
        case Category::BrowserWorker:    return QColor(20, 90, 180);
        case Category::VendorService:    return QColor(130, 40, 180);
        case Category::Updater:          return QColor(10, 130, 130);
        case Category::Suspicious:       return QColor(190, 20, 20);
        case Category::LegitimateWorker: return QColor(90, 90, 90);
        case Category::System:           return QColor(110, 110, 110);
        default:                         return QColor(80, 80, 80);
    }
}

inline void applyTheme(AppTheme theme) {
    QApplication* app = qApp;
    if (!app) return;

    g_appliedTheme = theme;
    app->setStyle(QStyleFactory::create(QStringLiteral("Fusion")));

    if (theme == AppTheme::System) {
        app->setPalette(app->style()->standardPalette());
        return;
    }

    QPalette p;
    if (theme == AppTheme::Dark) {
        p.setColor(QPalette::Window,          QColor(37, 37, 38));
        p.setColor(QPalette::WindowText,      QColor(220, 220, 220));
        p.setColor(QPalette::Base,            QColor(30, 30, 30));
        p.setColor(QPalette::AlternateBase,   QColor(45, 45, 48));
        p.setColor(QPalette::ToolTipBase,     QColor(45, 45, 48));
        p.setColor(QPalette::ToolTipText,     QColor(220, 220, 220));
        p.setColor(QPalette::Text,            QColor(220, 220, 220));
        p.setColor(QPalette::Button,          QColor(45, 45, 48));
        p.setColor(QPalette::ButtonText,      QColor(220, 220, 220));
        p.setColor(QPalette::BrightText,      QColor(255, 80, 80));
        p.setColor(QPalette::Link,            QColor(86, 156, 214));
        p.setColor(QPalette::Highlight,       QColor(0, 122, 204));
        p.setColor(QPalette::HighlightedText, QColor(255, 255, 255));
        p.setColor(QPalette::PlaceholderText, QColor(140, 140, 140));
        p.setColor(QPalette::Disabled, QPalette::WindowText, QColor(110, 110, 110));
        p.setColor(QPalette::Disabled, QPalette::Text,       QColor(110, 110, 110));
        p.setColor(QPalette::Disabled, QPalette::ButtonText, QColor(110, 110, 110));
    } else {
        p.setColor(QPalette::Window,          QColor(245, 245, 245));
        p.setColor(QPalette::WindowText,      QColor(30, 30, 30));
        p.setColor(QPalette::Base,            QColor(255, 255, 255));
        p.setColor(QPalette::AlternateBase,   QColor(240, 240, 240));
        p.setColor(QPalette::ToolTipBase,     QColor(255, 255, 230));
        p.setColor(QPalette::ToolTipText,     QColor(0, 0, 0));
        p.setColor(QPalette::Text,            QColor(30, 30, 30));
        p.setColor(QPalette::Button,          QColor(240, 240, 240));
        p.setColor(QPalette::ButtonText,      QColor(30, 30, 30));
        p.setColor(QPalette::BrightText,      QColor(200, 0, 0));
        p.setColor(QPalette::Link,            QColor(0, 100, 200));
        p.setColor(QPalette::Highlight,       QColor(0, 120, 215));
        p.setColor(QPalette::HighlightedText, QColor(255, 255, 255));
        p.setColor(QPalette::PlaceholderText, QColor(140, 140, 140));
        p.setColor(QPalette::Disabled, QPalette::WindowText, QColor(140, 140, 140));
        p.setColor(QPalette::Disabled, QPalette::Text,       QColor(140, 140, 140));
        p.setColor(QPalette::Disabled, QPalette::ButtonText, QColor(140, 140, 140));
    }
    app->setPalette(p);
}

inline AppTheme loadSavedTheme() {
    QSettings s(QStringLiteral("ProcessAnnotator"), QStringLiteral("ProcessAnnotator"));
    return themeFromString(s.value(QStringLiteral("ui/theme"), QStringLiteral("dark")).toString());
}

inline void saveTheme(AppTheme t) {
    QSettings s(QStringLiteral("ProcessAnnotator"), QStringLiteral("ProcessAnnotator"));
    s.setValue(QStringLiteral("ui/theme"), themeToString(t));
}
