#pragma once

#include <string>
#include <vector>
#include <optional>

enum class Category {
    Unknown = 0,
    System,
    Telemetry,
    Updater,
    Antivirus,
    AntivirusSandbox,
    BrowserWorker,
    LegitimateWorker,
    VendorService,
    Suspicious
};

inline const wchar_t* CategoryToString(Category c) {
    switch (c) {
        case Category::System:            return L"System";
        case Category::Telemetry:         return L"Telemetry";
        case Category::Updater:           return L"Updater";
        case Category::Antivirus:         return L"Antivirus";
        case Category::AntivirusSandbox:  return L"AV Sandbox";
        case Category::BrowserWorker:     return L"Browser Worker";
        case Category::LegitimateWorker:  return L"Worker";
        case Category::VendorService:     return L"Vendor";
        case Category::Suspicious:        return L"Suspicious";
        default:                          return L"Unknown";
    }
}

inline Category CategoryFromString(const std::string& s) {
    if (s == "system")           return Category::System;
    if (s == "telemetry")        return Category::Telemetry;
    if (s == "updater")          return Category::Updater;
    if (s == "antivirus")        return Category::Antivirus;
    if (s == "antivirus_sandbox" || s == "av_sandbox") return Category::AntivirusSandbox;
    if (s == "browser_worker")   return Category::BrowserWorker;
    if (s == "worker" || s == "legitimate_worker") return Category::LegitimateWorker;
    if (s == "vendor" || s == "vendor_service") return Category::VendorService;
    if (s == "suspicious")       return Category::Suspicious;
    return Category::Unknown;
}

struct RuleMatch {
    std::wstring id;
    std::wstring annotation;      // already resolved for UI language
    std::wstring annotationRu;
    std::wstring annotationEn;
    Category category = Category::Unknown;
    std::wstring severity;
    std::vector<std::wstring> actions;
};

struct Rule {
    std::wstring id;

    std::wstring nameEquals;
    std::wstring nameContains;
    std::wstring pathContains;
    std::wstring cmdlineContains;
    std::wstring parentNameEquals;

    std::wstring annotation;      // default / Russian
    std::wstring annotationEn;    // English
    Category category = Category::Unknown;
    std::wstring severity = L"info";
    std::vector<std::wstring> actions;
    std::vector<std::wstring> actionsEn;

    int priority = 100;
    std::wstring sourceFile;  // e.g. rules.yaml or rules.d/foo.yaml
};
