#pragma once

#include <QObject>
#include <QString>
#include <QNetworkAccessManager>

struct VirusTotalResult {
    bool ok = false;
    bool found = false;
    int malicious = 0;
    int suspicious = 0;
    int undetected = 0;
    int harmeless = 0;
    QString sha256;
    QString permalink;
    QString error;
    QString summary; // human-readable
};

class VirusTotalClient : public QObject {
    Q_OBJECT
public:
    explicit VirusTotalClient(QObject* parent = nullptr);

    static QString apiKey();
    static void setApiKey(const QString& key);
    static bool hasApiKey();

    // Async: hashes file, queries VT by hash
    void checkFile(const QString& filePath);

signals:
    void finished(const VirusTotalResult& result);
    void progress(const QString& message);

private:
    void queryHash(const QString& sha256);
    static QString sha256File(const QString& path);

    QNetworkAccessManager nam_;
};
