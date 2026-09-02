#pragma once

#include <QString>
#include <QHash>

class I18n {
public:
    enum Lang { English, Russian };

    static I18n& instance();

    void setLanguage(Lang lang);
    void setLanguageFromSystem();
    Lang language() const { return lang_; }

    QString tr(const char* key) const;
    QString tr(const char* key, const QString& fallback) const;

private:
    I18n();
    void loadEnglish();
    void loadRussian();

    Lang lang_ = English;
    QHash<QString, QString> dict_;
};

inline QString i18n(const char* key) {
    return I18n::instance().tr(key);
}
