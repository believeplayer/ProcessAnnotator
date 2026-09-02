#include "VirusTotal.hpp"
#include "i18n/I18n.hpp"

#include <QSettings>
#include <QFile>
#include <QCryptographicHash>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QUrl>
#include <QDesktopServices>

VirusTotalClient::VirusTotalClient(QObject* parent)
    : QObject(parent)
{
}

QString VirusTotalClient::apiKey() {
    QSettings s(QStringLiteral("ProcessAnnotator"), QStringLiteral("ProcessAnnotator"));
    return s.value(QStringLiteral("virusTotal/apiKey")).toString().trimmed();
}

void VirusTotalClient::setApiKey(const QString& key) {
    QSettings s(QStringLiteral("ProcessAnnotator"), QStringLiteral("ProcessAnnotator"));
    s.setValue(QStringLiteral("virusTotal/apiKey"), key.trimmed());
}

bool VirusTotalClient::hasApiKey() {
    return !apiKey().isEmpty();
}

QString VirusTotalClient::sha256File(const QString& path) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return {};

    QCryptographicHash hash(QCryptographicHash::Sha256);
    const qint64 chunk = 1024 * 1024;
    while (!f.atEnd()) {
        hash.addData(f.read(chunk));
    }
    return QString::fromLatin1(hash.result().toHex());
}

void VirusTotalClient::checkFile(const QString& filePath) {
    emit progress(i18n("vt_hashing"));

    const QString sha = sha256File(filePath);
    if (sha.isEmpty()) {
        VirusTotalResult r;
        r.error = QStringLiteral("Cannot read file");
        r.summary = i18n("vt_error").arg(r.error);
        emit finished(r);
        return;
    }

    queryHash(sha);
}

void VirusTotalClient::queryHash(const QString& sha256) {
    emit progress(i18n("vt_querying"));

    const QString key = apiKey();
    if (key.isEmpty()) {
        VirusTotalResult r;
        r.error = QStringLiteral("No API key");
        r.summary = i18n("vt_no_key");
        emit finished(r);
        return;
    }

    QNetworkRequest req(QUrl(QStringLiteral("https://www.virustotal.com/api/v3/files/%1").arg(sha256)));
    req.setRawHeader("x-apikey", key.toUtf8());
    req.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));

    QNetworkReply* reply = nam_.get(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply, sha256]() {
        reply->deleteLater();
        VirusTotalResult r;
        r.sha256 = sha256;
        r.permalink = QStringLiteral("https://www.virustotal.com/gui/file/%1").arg(sha256);

        if (reply->error() != QNetworkReply::NoError) {
            const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            if (code == 404) {
                r.ok = true;
                r.found = false;
                r.summary = i18n("vt_unknown");
            } else {
                r.error = reply->errorString();
                r.summary = i18n("vt_error").arg(r.error);
            }
            emit finished(r);
            return;
        }

        const QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        const QJsonObject data = doc.object().value(QStringLiteral("data")).toObject();
        const QJsonObject attrs = data.value(QStringLiteral("attributes")).toObject();
        const QJsonObject stats = attrs.value(QStringLiteral("last_analysis_stats")).toObject();

        r.ok = true;
        r.found = true;
        r.malicious = stats.value(QStringLiteral("malicious")).toInt();
        r.suspicious = stats.value(QStringLiteral("suspicious")).toInt();
        r.undetected = stats.value(QStringLiteral("undetected")).toInt();
        r.harmeless = stats.value(QStringLiteral("harmless")).toInt();

        const int total = r.malicious + r.suspicious + r.undetected + r.harmeless
                          + stats.value(QStringLiteral("timeout")).toInt()
                          + stats.value(QStringLiteral("failure")).toInt()
                          + stats.value(QStringLiteral("type-unsupported")).toInt();

        if (r.malicious + r.suspicious == 0)
            r.summary = i18n("vt_clean") + QStringLiteral("\n\nSHA-256: %1").arg(sha256);
        else
            r.summary = i18n("vt_detected")
                            .arg(r.malicious + r.suspicious)
                            .arg(total)
                        + QStringLiteral("\n(malicious: %1, suspicious: %2)\n\nSHA-256: %3")
                              .arg(r.malicious).arg(r.suspicious).arg(sha256);

        emit finished(r);
    });
}
