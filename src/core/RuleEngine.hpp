#pragma once

#include "ProcessInfo.hpp"
#include "Rule.hpp"
#include <vector>
#include <optional>
#include <string>

void RuleEngine_SetPreferEnglish(bool preferEnglish);
bool RuleEngine_PreferEnglish();

struct RuleLoadError {
    std::wstring source;
    int line = -1;  // 1-based; -1 if unknown
    std::wstring message;
};

class RuleEngine {
public:
    explicit RuleEngine(const std::wstring& rulesPath = L"");

    std::optional<RuleMatch> Match(const ProcessInfo& proc) const;
    size_t RuleCount() const { return rules_.size(); }
    bool LoadedFromFile() const { return loadedFromFile_; }
    const std::vector<Rule>& rules() const { return rules_; }
    const std::vector<std::wstring>& loadedFiles() const { return loadedFiles_; }
    const std::vector<RuleLoadError>& loadErrors() const { return loadErrors_; }

    // Reload rules.yaml + rules.d/*.yaml from disk
    bool reload();

private:
    std::vector<Rule> rules_;
    std::vector<std::wstring> loadedFiles_;
    std::vector<RuleLoadError> loadErrors_;
    std::wstring rulesDir_;
    std::wstring mainRulesPath_;
    bool loadedFromFile_ = false;

    void LoadBuiltinRules();
    bool LoadFromYaml(const std::wstring& path, const std::wstring& sourceLabel);
    void loadAllFromDisk();
    void sortRules();
};
