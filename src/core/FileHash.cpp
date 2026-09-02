#include "FileHash.hpp"
#include "AppCache.hpp"

#include <Windows.h>
#include <wincrypt.h>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <mutex>
#include <string>

#pragma comment(lib, "advapi32.lib")

namespace {

struct Key {
    std::wstring path;
    uint64_t size = 0;
    uint64_t mtime = 0;
    bool operator==(const Key& o) const {
        return path == o.path && size == o.size && mtime == o.mtime;
    }
};
struct KeyHash {
    size_t operator()(const Key& k) const {
        size_t h = std::hash<std::wstring>{}(k.path);
        h ^= std::hash<uint64_t>{}(k.size) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint64_t>{}(k.mtime) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

std::unordered_map<Key, std::wstring, KeyHash> g_cache;
std::mutex g_mu;
bool g_loaded = false;

std::wstring GetCachePath() {
    return GetAnnotatorCacheFile(L"hash_cache.dat");
}

bool Meta(const std::wstring& path, uint64_t& size, uint64_t& mtime) {
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad))
        return false;
    size = (uint64_t(fad.nFileSizeHigh) << 32) | fad.nFileSizeLow;
    mtime = (uint64_t(fad.ftLastWriteTime.dwHighDateTime) << 32) | fad.ftLastWriteTime.dwLowDateTime;
    return true;
}

std::wstring HashUncached(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return {};

    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    std::wstring result;
    if (!CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(h);
        return {};
    }
    if (!CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash)) {
        CryptReleaseContext(prov, 0);
        CloseHandle(h);
        return {};
    }

    BYTE buf[1024 * 64];
    DWORD read = 0;
    bool ok = true;
    while (ReadFile(h, buf, sizeof(buf), &read, nullptr) && read > 0) {
        if (!CryptHashData(hash, buf, read, 0)) { ok = false; break; }
    }
    if (ok) {
        BYTE dig[32];
        DWORD digLen = 32;
        if (CryptGetHashParam(hash, HP_HASHVAL, dig, &digLen, 0)) {
            static const wchar_t hx[] = L"0123456789abcdef";
            result.resize(64);
            for (DWORD i = 0; i < 32; ++i) {
                result[i * 2]     = hx[(dig[i] >> 4) & 0xF];
                result[i * 2 + 1] = hx[dig[i] & 0xF];
            }
        }
    }
    CryptDestroyHash(hash);
    CryptReleaseContext(prov, 0);
    CloseHandle(h);
    return result;
}

} // namespace

void LoadHashCache() {
    std::lock_guard lock(g_mu);
    if (g_loaded) return;
    g_loaded = true;
    std::ifstream in(GetCachePath());
    if (!in) return;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        // path|size|mtime|sha256
        std::vector<std::string> parts;
        std::string cur; bool esc = false;
        for (char c : line) {
            if (esc) { cur += c; esc = false; }
            else if (c == '\\') esc = true;
            else if (c == '|') { parts.push_back(cur); cur.clear(); }
            else cur += c;
        }
        parts.push_back(cur);
        if (parts.size() < 4) continue;
        Key k;
        int n = MultiByteToWideChar(CP_UTF8, 0, parts[0].c_str(), -1, nullptr, 0);
        if (n > 0) {
            k.path.resize(n - 1);
            MultiByteToWideChar(CP_UTF8, 0, parts[0].c_str(), -1, k.path.data(), n);
        }
        k.size = std::strtoull(parts[1].c_str(), nullptr, 10);
        k.mtime = std::strtoull(parts[2].c_str(), nullptr, 10);
        n = MultiByteToWideChar(CP_UTF8, 0, parts[3].c_str(), -1, nullptr, 0);
        std::wstring sha;
        if (n > 0) {
            sha.resize(n - 1);
            MultiByteToWideChar(CP_UTF8, 0, parts[3].c_str(), -1, sha.data(), n);
        }
        g_cache[k] = sha;
    }
}

void SaveHashCache() {
    std::lock_guard lock(g_mu);
    std::ofstream out(GetCachePath(), std::ios::trunc);
    if (!out) return;
    out << "# path|size|mtime|sha256\n";
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
    for (auto& [k, sha] : g_cache) {
        out << esc(toUtf8(k.path)) << '|' << k.size << '|' << k.mtime << '|'
            << esc(toUtf8(sha)) << '\n';
    }
}

size_t HashCacheSize() {
    std::lock_guard lock(g_mu);
    return g_cache.size();
}

std::wstring FileSha256(const std::wstring& path) {
    if (path.empty()) return {};
    if (!g_loaded) LoadHashCache();

    uint64_t size = 0, mtime = 0;
    if (!Meta(path, size, mtime)) return {};

    Key k{path, size, mtime};
    {
        std::lock_guard lock(g_mu);
        auto it = g_cache.find(k);
        if (it != g_cache.end()) return it->second;
    }

    std::wstring sha = HashUncached(path);
    if (!sha.empty()) {
        std::lock_guard lock(g_mu);
        g_cache[k] = sha;
    }
    return sha;
}
