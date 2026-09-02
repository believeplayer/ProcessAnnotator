#include "Signature.hpp"
#include "AppCache.hpp"

#include <Windows.h>
#include <Softpub.h>
#include <wintrust.h>
#include <mscat.h>
#include <wincrypt.h>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <mutex>
#include <string>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

/* WTHelper* may not be fully declared in all SDK versions */
extern "C" {
    CRYPT_PROVIDER_DATA* WINAPI WTHelperProvDataFromStateData(HANDLE hStateData);
    CRYPT_PROVIDER_SGNR* WINAPI WTHelperGetProvSignerFromChain(
        CRYPT_PROVIDER_DATA* pProvData, DWORD idxSigner, BOOL fCounterSigner, DWORD idxCounterSigner);
}

namespace {

struct CacheKey {
    std::wstring path;
    uint64_t size = 0;
    uint64_t mtime = 0;

    bool operator==(const CacheKey& o) const {
        return path == o.path && size == o.size && mtime == o.mtime;
    }
};

struct CacheKeyHash {
    size_t operator()(const CacheKey& k) const {
        size_t h = std::hash<std::wstring>{}(k.path);
        h ^= std::hash<uint64_t>{}(k.size) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint64_t>{}(k.mtime) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

std::unordered_map<CacheKey, SignatureInfo, CacheKeyHash> g_cache;
std::mutex g_cacheMutex;
size_t g_hits = 0;
bool g_cacheLoaded = false;

std::wstring GetCacheFilePath() {
    return GetAnnotatorCacheFile(L"signature_cache.dat");
}

bool GetFileMeta(const std::wstring& path, uint64_t& size, uint64_t& mtime) {
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad))
        return false;
    size = (static_cast<uint64_t>(fad.nFileSizeHigh) << 32) | fad.nFileSizeLow;
    mtime = (static_cast<uint64_t>(fad.ftLastWriteTime.dwHighDateTime) << 32) |
            fad.ftLastWriteTime.dwLowDateTime;
    return true;
}

std::wstring NormalizePublisher(const std::wstring& publisher) {
    std::wstring pub = publisher;
    for (auto& c : pub) c = static_cast<wchar_t>(towlower(c));

    if (pub.find(L"microsoft") != std::wstring::npos) return L"Microsoft";
    if (pub.find(L"windows publisher") != std::wstring::npos) return L"Microsoft";
    if (pub.find(L"google") != std::wstring::npos) return L"Google";
    if (pub.find(L"mozilla") != std::wstring::npos) return L"Mozilla";
    if (pub.find(L"adobe") != std::wstring::npos) return L"Adobe";
    if (pub.find(L"nvidia") != std::wstring::npos) return L"NVIDIA";
    if (pub.find(L"advanced micro devices") != std::wstring::npos) return L"AMD";
    if (pub.find(L" amd") != std::wstring::npos || pub == L"amd") return L"AMD";
    if (pub.find(L"intel") != std::wstring::npos) return L"Intel";
    if (pub.find(L"valve") != std::wstring::npos) return L"Valve";
    if (pub.find(L"apple") != std::wstring::npos) return L"Apple";
    if (pub.find(L"oracle") != std::wstring::npos) return L"Oracle";
    if (pub.find(L"realtek") != std::wstring::npos) return L"Realtek";
    if (pub.find(L"acer") != std::wstring::npos) return L"Acer";
    return publisher;
}

// Извлечь имя издателя из сертификата контекста
std::wstring PublisherFromCert(PCCERT_CONTEXT pCert) {
    if (!pCert) return {};
    wchar_t nameBuf[512] = {};
    if (CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr,
                           nameBuf, 512) > 1)
        return nameBuf;
    return {};
}

// Издатель из state data после успешного WinVerifyTrust
std::wstring PublisherFromState(HANDLE hWVTStateData) {
    if (!hWVTStateData) return {};

    auto* provData = WTHelperProvDataFromStateData(hWVTStateData);
    if (!provData) return {};

    auto* signer = WTHelperGetProvSignerFromChain(provData, 0, FALSE, 0);
    if (!signer || !signer->csCertChain || !signer->pasCertChain)
        return {};

    return PublisherFromCert(signer->pasCertChain[0].pCert);
}

SignatureInfo VerifyViaWinTrust(const std::wstring& filePath, bool useCatalogHint) {
    SignatureInfo info;

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = filePath.c_str();

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fileInfo;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    // Не используем CACHE_ONLY — иначе часть catalog-подписей не находится
    data.dwProvFlags = WTD_REVOCATION_CHECK_NONE;

    LONG status = WinVerifyTrust(nullptr, &action, &data);

    if (status == ERROR_SUCCESS) {
        info.isSigned = true;
        info.isValid = true;
        info.publisher = PublisherFromState(data.hWVTStateData);
        info.status = info.publisher.empty()
            ? L"Valid"
            : NormalizePublisher(info.publisher);
    } else if (status == TRUST_E_NOSIGNATURE) {
        info.status = L"Unsigned";
    } else {
        // Подпись есть, но проблемы (срок, цепочка и т.д.)
        info.isSigned = true;
        info.isValid = false;
        info.publisher = PublisherFromState(data.hWVTStateData);
        info.status = L"Invalid";
        if (!info.publisher.empty())
            info.status = NormalizePublisher(info.publisher) + L" (invalid)";
    }

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &data);

    (void)useCatalogHint;
    return info;
}

// Явная проверка через catalog API (fallback)
SignatureInfo VerifyViaCatalog(const std::wstring& filePath) {
    SignatureInfo info;
    info.status = L"Unsigned";

    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return info;

    HCATADMIN hCatAdmin = nullptr;
    if (!CryptCATAdminAcquireContext(&hCatAdmin, nullptr, 0)) {
        CloseHandle(hFile);
        return info;
    }

    DWORD hashSize = 0;
    CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, nullptr, 0);
    if (hashSize == 0) {
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        CloseHandle(hFile);
        return info;
    }

    std::vector<BYTE> hash(hashSize);
    if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hash.data(), 0)) {
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        CloseHandle(hFile);
        return info;
    }
    CloseHandle(hFile);

    // Ищем каталог по хэшу
    HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(
        hCatAdmin, hash.data(), hashSize, 0, nullptr);

    if (!hCatInfo) {
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return info;
    }

    CATALOG_INFO catInfo{};
    catInfo.cbStruct = sizeof(catInfo);
    if (!CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0)) {
        CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return info;
    }

    // Проверяем через WINTRUST_CATALOG_INFO
    // Member tag = hex hash
    std::wstring memberTag;
    memberTag.reserve(hashSize * 2);
    static const wchar_t hex[] = L"0123456789ABCDEF";
    for (DWORD i = 0; i < hashSize; ++i) {
        memberTag.push_back(hex[(hash[i] >> 4) & 0xF]);
        memberTag.push_back(hex[hash[i] & 0xF]);
    }

    WINTRUST_CATALOG_INFO catalog{};
    catalog.cbStruct = sizeof(catalog);
    catalog.pcwszCatalogFilePath = catInfo.wszCatalogFile;
    catalog.pcwszMemberFilePath = filePath.c_str();
    catalog.pcwszMemberTag = memberTag.c_str();
    catalog.hMemberFile = nullptr;
    catalog.pbCalculatedFileHash = hash.data();
    catalog.cbCalculatedFileHash = hashSize;
    catalog.pcCatalogContext = nullptr;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_CATALOG;
    data.pCatalog = &catalog;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_REVOCATION_CHECK_NONE;

    LONG status = WinVerifyTrust(nullptr, &action, &data);

    if (status == ERROR_SUCCESS) {
        info.isSigned = true;
        info.isValid = true;
        info.publisher = PublisherFromState(data.hWVTStateData);
        info.status = info.publisher.empty()
            ? L"Microsoft"  // catalog-подписи Windows почти всегда Microsoft
            : NormalizePublisher(info.publisher);
        // Если издатель не извлекся — для System32 считаем Microsoft
        if (info.publisher.empty()) {
            std::wstring lower = filePath;
            for (auto& c : lower) c = static_cast<wchar_t>(towlower(c));
            if (lower.find(L"\\windows\\system32\\") != std::wstring::npos ||
                lower.find(L"\\windows\\syswow64\\") != std::wstring::npos ||
                lower.find(L"\\windows\\winsxs\\") != std::wstring::npos) {
                info.status = L"Microsoft";
                info.publisher = L"Microsoft Windows";
            }
        }
    }

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &data);

    CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
    CryptCATAdminReleaseContext(hCatAdmin, 0);
    return info;
}

SignatureInfo VerifySignatureUncached(const std::wstring& filePath) {
    if (filePath.empty()) {
        SignatureInfo info;
        info.status = L"Unsigned";
        return info;
    }

    // 1) Обычный WinVerifyTrust (embedded + catalog, если OS находит)
    SignatureInfo info = VerifyViaWinTrust(filePath, false);

    // 2) Если «нет подписи» — явный обход catalog API
    if (!info.isSigned && info.status == L"Unsigned") {
        SignatureInfo cat = VerifyViaCatalog(filePath);
        if (cat.isSigned)
            return cat;
    }

    // 3) Fallback: для известных системных путей без подписи в кэше
    //    (редко нужно, если catalog сработал)
    return info;
}

} // namespace

void LoadSignatureCache() {
    std::lock_guard lock(g_cacheMutex);
    if (g_cacheLoaded) return;
    g_cacheLoaded = true;

    std::ifstream in(GetCacheFilePath());
    if (!in) return;

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;

        std::vector<std::string> parts;
        std::string cur;
        bool esc = false;
        for (char c : line) {
            if (esc) { cur += c; esc = false; }
            else if (c == '\\') esc = true;
            else if (c == '|') { parts.push_back(cur); cur.clear(); }
            else cur += c;
        }
        parts.push_back(cur);
        if (parts.size() < 7) continue;

        CacheKey key;
        int needed = MultiByteToWideChar(CP_UTF8, 0, parts[0].c_str(), -1, nullptr, 0);
        if (needed > 0) {
            key.path.resize(needed - 1);
            MultiByteToWideChar(CP_UTF8, 0, parts[0].c_str(), -1, key.path.data(), needed);
        }
        key.size = std::strtoull(parts[1].c_str(), nullptr, 10);
        key.mtime = std::strtoull(parts[2].c_str(), nullptr, 10);

        SignatureInfo info;
        info.isSigned = parts[3] == "1";
        info.isValid = parts[4] == "1";

        auto toWide = [](const std::string& s) {
            int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
            if (n <= 0) return std::wstring{};
            std::wstring w(n - 1, 0);
            MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
            return w;
        };
        info.publisher = toWide(parts[5]);
        info.status = toWide(parts[6]);

        g_cache[key] = info;
    }
}

void SaveSignatureCache() {
    std::lock_guard lock(g_cacheMutex);
    std::ofstream out(GetCacheFilePath(), std::ios::trunc);
    if (!out) return;

    out << "# path|size|mtime|isSigned|isValid|publisher|status\n";

    auto toUtf8 = [](const std::wstring& w) {
        int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (n <= 0) return std::string{};
        std::string s(n - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), n, nullptr, nullptr);
        return s;
    };

    auto esc = [](const std::string& s) {
        std::string o;
        for (char c : s) {
            if (c == '|' || c == '\\' || c == '\n') o += '\\';
            o += c;
        }
        return o;
    };

    for (const auto& [key, info] : g_cache) {
        out << esc(toUtf8(key.path)) << '|'
            << key.size << '|'
            << key.mtime << '|'
            << (info.isSigned ? '1' : '0') << '|'
            << (info.isValid ? '1' : '0') << '|'
            << esc(toUtf8(info.publisher)) << '|'
            << esc(toUtf8(info.status)) << '\n';
    }
}

size_t SignatureCacheSize() {
    std::lock_guard lock(g_cacheMutex);
    return g_cache.size();
}

size_t SignatureCacheHits() {
    return g_hits;
}

SignatureInfo VerifySignature(const std::wstring& filePath) {
    if (filePath.empty()) return {};

    if (!g_cacheLoaded)
        LoadSignatureCache();

    uint64_t size = 0, mtime = 0;
    if (!GetFileMeta(filePath, size, mtime)) {
        SignatureInfo info;
        info.status = L"Unsigned";
        return info;
    }

    CacheKey key{filePath, size, mtime};

    {
        std::lock_guard lock(g_cacheMutex);
        auto it = g_cache.find(key);
        if (it != g_cache.end()) {
            ++g_hits;
            return it->second;
        }
    }

    SignatureInfo info = VerifySignatureUncached(filePath);

    {
        std::lock_guard lock(g_cacheMutex);
        g_cache[key] = info;
    }
    return info;
}
