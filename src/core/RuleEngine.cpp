#include "RuleEngine.hpp"

#include <yaml-cpp/yaml.h>
#include <algorithm>
#include <cwctype>
#include <fstream>
#include <Windows.h>

namespace {

std::wstring Utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return {};
    int needed = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), nullptr, 0);
    if (needed <= 0) return {};
    std::wstring result(needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), result.data(), needed);
    return result;
}

std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(n - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), n, nullptr, nullptr);
    return s;
}

bool IEquals(const std::wstring& a, const std::wstring& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (std::towlower(a[i]) != std::towlower(b[i])) return false;
    return true;
}

bool IContains(const std::wstring& haystack, const std::wstring& needle) {
    if (needle.empty()) return false;
    auto it = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(), needle.end(),
        [](wchar_t c1, wchar_t c2) { return std::towlower(c1) == std::towlower(c2); });
    return it != haystack.end();
}

std::wstring GetExeDir() {
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring dir(exePath);
    size_t pos = dir.find_last_of(L"\\/");
    if (pos != std::wstring::npos)
        dir = dir.substr(0, pos);
    return dir;
}

} // namespace

static bool g_preferEnglish = false;

void RuleEngine_SetPreferEnglish(bool preferEnglish) {
    g_preferEnglish = preferEnglish;
}

bool RuleEngine_PreferEnglish() {
    return g_preferEnglish;
}

RuleEngine::RuleEngine(const std::wstring& rulesPath) {
    if (!rulesPath.empty()) {
        mainRulesPath_ = rulesPath;
        // parent dir
        size_t pos = rulesPath.find_last_of(L"\\/");
        rulesDir_ = (pos != std::wstring::npos) ? rulesPath.substr(0, pos) : GetExeDir() + L"\\rules";
    } else {
        rulesDir_ = GetExeDir() + L"\\rules";
        mainRulesPath_ = rulesDir_ + L"\\rules.yaml";
    }
    loadAllFromDisk();
}

void RuleEngine::sortRules() {
    // Deterministic order:
    //   1) higher priority first
    //   2) rules.d (user packs) beat rules.yaml / builtin at the same priority
    //   3) source file name, then id
    std::stable_sort(rules_.begin(), rules_.end(),
        [](const Rule& a, const Rule& b) {
            if (a.priority != b.priority)
                return a.priority > b.priority;
            const bool aUser = a.sourceFile.find(L"rules.d/") != std::wstring::npos;
            const bool bUser = b.sourceFile.find(L"rules.d/") != std::wstring::npos;
            if (aUser != bUser)
                return aUser;
            if (a.sourceFile != b.sourceFile)
                return a.sourceFile < b.sourceFile;
            return a.id < b.id;
        });
}

void RuleEngine::loadAllFromDisk() {
    rules_.clear();
    loadedFiles_.clear();
    loadErrors_.clear();
    loadedFromFile_ = false;

    // 1) Main rules.yaml
    if (LoadFromYaml(mainRulesPath_, L"rules.yaml"))
        loadedFromFile_ = true;

    // 2) rules.d\*.yaml (sorted by name for stable order)
    const std::wstring dropDir = rulesDir_ + L"\\rules.d";
    std::wstring pattern = dropDir + L"\\*.yaml";
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    std::vector<std::wstring> extra;
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                extra.push_back(fd.cFileName);
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    // also .yml
    pattern = dropDir + L"\\*.yml";
    h = FindFirstFileW(pattern.c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                extra.push_back(fd.cFileName);
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    std::sort(extra.begin(), extra.end());

    for (const auto& name : extra) {
        std::wstring label = L"rules.d/" + name;
        std::wstring full = dropDir + L"\\" + name;
        if (LoadFromYaml(full, label))
            loadedFromFile_ = true;
    }

    if (rules_.empty()) {
        LoadBuiltinRules();
        loadedFromFile_ = false;
    }
    sortRules();
}

bool RuleEngine::reload() {
    loadAllFromDisk();
    return !rules_.empty();
}

std::optional<RuleMatch> RuleEngine::Match(const ProcessInfo& proc) const {
    for (const auto& rule : rules_) {
        bool hasAnyCondition = false;
        bool allMatch = true;

        auto check = [&](bool conditionSpecified, bool result) {
            if (conditionSpecified) {
                hasAnyCondition = true;
                if (!result) allMatch = false;
            }
        };

        check(!rule.nameEquals.empty(), IEquals(proc.name, rule.nameEquals));
        check(!rule.nameContains.empty(), IContains(proc.name, rule.nameContains));
        check(!rule.pathContains.empty(), IContains(proc.imagePath, rule.pathContains));
        check(!rule.cmdlineContains.empty(), IContains(proc.commandLine, rule.cmdlineContains));
        check(!rule.parentNameEquals.empty(),
              proc.parent && IEquals(proc.parent->name, rule.parentNameEquals));

        if (hasAnyCondition && allMatch) {
            RuleMatch m;
            m.id = rule.id;
            m.annotationRu = rule.annotation;
            m.annotationEn = rule.annotationEn.empty() ? rule.annotation : rule.annotationEn;
            m.category = rule.category;
            m.severity = rule.severity;

            if (g_preferEnglish) {
                m.annotation = m.annotationEn;
                m.actions = rule.actionsEn.empty() ? rule.actions : rule.actionsEn;
            } else {
                m.annotation = m.annotationRu;
                m.actions = rule.actions;
            }

            if (!proc.serviceName.empty() &&
                (rule.id == L"svchost" || IEquals(proc.name, L"svchost.exe"))) {
                // Service name already shown in details — drop "check cmdline" hints
                auto stripCmdlineHint = [](std::wstring s) {
                    const wchar_t* markers[] = {
                        L"Смотрите cmdline",
                        L"смотрите cmdline",
                        L"Check cmdline",
                        L"check cmdline",
                        L"See cmdline",
                        L"see cmdline",
                    };
                    for (const wchar_t* mk : markers) {
                        size_t pos = s.find(mk);
                        if (pos != std::wstring::npos) {
                            // trim trailing junk before the hint (period/space)
                            while (pos > 0 && (s[pos - 1] == L' ' || s[pos - 1] == L'.'))
                                --pos;
                            s = s.substr(0, pos);
                            while (!s.empty() && (s.back() == L' ' || s.back() == L'.'))
                                s.pop_back();
                            if (!s.empty() && s.back() != L'.')
                                s.push_back(L'.');
                            break;
                        }
                    }
                    return s;
                };
                m.annotation = stripCmdlineHint(m.annotation);
                m.annotationRu = stripCmdlineHint(m.annotationRu);
                m.annotationEn = stripCmdlineHint(m.annotationEn);
                // Avoid "Service Host: X — Service Host — ..."
                std::wstring base = m.annotation;
                const std::wstring prefixes[] = {
                    L"Service Host — ",
                    L"Service Host - ",
                    L"Service Host: ",
                };
                for (const auto& pref : prefixes) {
                    if (base.size() >= pref.size() &&
                        _wcsnicmp(base.c_str(), pref.c_str(), pref.size()) == 0) {
                        base = base.substr(pref.size());
                        break;
                    }
                }
                m.annotation = L"Service Host: " + proc.serviceName + L" — " + base;
            }
            return m;
        }
    }
    return std::nullopt;
}

bool RuleEngine::LoadFromYaml(const std::wstring& path, const std::wstring& sourceLabel) {
    std::string narrowPath = WideToUtf8(path);
    if (narrowPath.empty()) {
        loadErrors_.push_back({sourceLabel, -1, L"Cannot convert path to UTF-8"});
        return false;
    }

    {
        std::ifstream probe(narrowPath);
        if (!probe) {
            loadErrors_.push_back({sourceLabel, -1, L"File not found or cannot be opened"});
            return false;
        }
    }

    try {
        YAML::Node root = YAML::LoadFile(narrowPath);
        if (!root["rules"] || !root["rules"].IsSequence()) {
            loadErrors_.push_back({sourceLabel, -1, L"Missing top-level 'rules:' sequence"});
            return false;
        }

        size_t before = rules_.size();
        size_t index = 0;
        for (const auto& node : root["rules"]) {
            ++index;
            const int line = node.Mark().line >= 0 ? node.Mark().line + 1 : -1;
            Rule r;
            if (node["id"]) r.id = Utf8ToWide(node["id"].as<std::string>());
            if (node["priority"]) r.priority = node["priority"].as<int>();
            if (node["annotation"]) r.annotation = Utf8ToWide(node["annotation"].as<std::string>());
            if (node["annotation_en"]) r.annotationEn = Utf8ToWide(node["annotation_en"].as<std::string>());
            if (node["severity"]) r.severity = Utf8ToWide(node["severity"].as<std::string>());
            if (node["category"]) r.category = CategoryFromString(node["category"].as<std::string>());

            if (node["match"]) {
                const auto& m = node["match"];
                if (m["name_equals"])      r.nameEquals = Utf8ToWide(m["name_equals"].as<std::string>());
                if (m["name_contains"])    r.nameContains = Utf8ToWide(m["name_contains"].as<std::string>());
                if (m["path_contains"])    r.pathContains = Utf8ToWide(m["path_contains"].as<std::string>());
                if (m["cmdline_contains"]) r.cmdlineContains = Utf8ToWide(m["cmdline_contains"].as<std::string>());
                if (m["parent_name_equals"]) r.parentNameEquals = Utf8ToWide(m["parent_name_equals"].as<std::string>());
            }

            if (node["actions"] && node["actions"].IsSequence()) {
                for (const auto& a : node["actions"])
                    r.actions.push_back(Utf8ToWide(a.as<std::string>()));
            }
            if (node["actions_en"] && node["actions_en"].IsSequence()) {
                for (const auto& a : node["actions_en"])
                    r.actionsEn.push_back(Utf8ToWide(a.as<std::string>()));
            }

            r.sourceFile = sourceLabel;

            if (r.id.empty() || r.annotation.empty()) {
                loadErrors_.push_back({sourceLabel, line,
                    L"Skipped rule #" + std::to_wstring(index) +
                    L" (need non-empty id and annotation)"});
                continue;
            }
            rules_.push_back(std::move(r));
        }

        if (rules_.size() > before)
            loadedFiles_.push_back(sourceLabel);
        return rules_.size() > before;
    }
    catch (const YAML::Exception& ex) {
        const int line = ex.mark.line >= 0 ? ex.mark.line + 1 : -1;
        loadErrors_.push_back({sourceLabel, line, Utf8ToWide(ex.what())});
        return false;
    }
    catch (const std::exception& ex) {
        loadErrors_.push_back({sourceLabel, -1, Utf8ToWide(ex.what())});
        return false;
    }
}

void RuleEngine::LoadBuiltinRules() {
    rules_.push_back({
        L"svchost", L"svchost.exe", L"", L"", L"", L"",
        L"Service Host — общий хост для DLL-служб Windows.",
        L"Service Host — shared host process for Windows DLL-based services.",
        Category::System, L"info", {}, {}, 50, L"(builtin)"
    });
    rules_.push_back({
        L"runtimebroker", L"RuntimeBroker.exe", L"", L"", L"", L"",
        L"Runtime Broker — управляет правами UWP/Store-приложений.",
        L"Runtime Broker — manages permissions for UWP/Store apps.",
        Category::System, L"info",
        {L"Если жрёт CPU — проверьте Store-приложения"},
        {L"If using high CPU — check which Store app is waking it"},
        170, L"(builtin)"
    });
    rules_.push_back({
        L"msmpeng", L"MsMpEng.exe", L"", L"", L"", L"",
        L"Microsoft Defender Antivirus",
        L"Microsoft Defender Antivirus",
        Category::Antivirus, L"info", {}, {}, 180, L"(builtin)"
    });
}
