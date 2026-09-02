#pragma once

#include <string>
#include <vector>

enum class AutostartType {
    RunKey,
    Service,
    ScheduledTask
};

inline const wchar_t* AutostartTypeToString(AutostartType t) {
    switch (t) {
        case AutostartType::RunKey:         return L"Run";
        case AutostartType::Service:        return L"Service";
        case AutostartType::ScheduledTask:  return L"Task";
        default:                            return L"?";
    }
}

struct AutostartEntry {
    AutostartType type = AutostartType::RunKey;
    std::wstring name;
    std::wstring command;
    std::wstring location;
    std::wstring imagePath;
    bool hidden = false; // scheduled tasks only
};

class AutostartIndex {
public:
    void rebuild();
    std::vector<AutostartEntry> findForImage(const std::wstring& imagePath) const;
    std::vector<AutostartEntry> hiddenTasks() const;
    size_t size() const { return entries_.size(); }
    size_t hiddenTaskCount() const;

private:
    std::vector<AutostartEntry> entries_;

    void collectRunKeys();
    void collectServices();
    void collectTasks();
};
