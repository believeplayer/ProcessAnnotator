#include "AutostartIndex.hpp"

#include <Windows.h>
#include <winsvc.h>
#include <comdef.h>
#include <comutil.h>
#pragma comment(lib, "comsuppw.lib")
#include <taskschd.h>
#include <algorithm>
#include <cwctype>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "taskschd.lib")

namespace {

std::wstring ToLower(std::wstring s) {
    for (auto& c : s) c = static_cast<wchar_t>(towlower(c));
    return s;
}

std::wstring BaseName(const std::wstring& path) {
    size_t slash = path.find_last_of(L"\\/");
    return (slash != std::wstring::npos) ? path.substr(slash + 1) : path;
}

// Extract executable path from a command line (handles quotes)
std::wstring BstrToW(BSTR s) {
    if (!s) return {};
    return std::wstring(s, SysStringLen(s));
}

std::wstring ExtractImagePath(const std::wstring& cmd) {
    if (cmd.empty()) return {};
    std::wstring s = cmd;
    // trim
    while (!s.empty() && (s.front() == L' ' || s.front() == L'\t')) s.erase(s.begin());
    if (s.empty()) return {};

    std::wstring path;
    if (s.front() == L'"') {
        size_t end = s.find(L'"', 1);
        if (end == std::wstring::npos) path = s.substr(1);
        else path = s.substr(1, end - 1);
    } else {
        // stop at space or " -" / " /"
        size_t end = s.find(L' ');
        path = (end == std::wstring::npos) ? s : s.substr(0, end);
    }

    // Expand simple env vars like %SystemRoot%
    wchar_t expanded[MAX_PATH * 2] = {};
    if (ExpandEnvironmentStringsW(path.c_str(), expanded, MAX_PATH * 2))
        path = expanded;

    // Normalize forward slashes
    for (auto& c : path)
        if (c == L'/') c = L'\\';

    return path;
}

void ReadRunKey(HKEY root, const wchar_t* subkey, const wchar_t* locationLabel,
                std::vector<AutostartEntry>& out) {
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return;

    DWORD index = 0;
    wchar_t valueName[512];
    BYTE data[4096];
    for (;;) {
        DWORD nameLen = 512;
        DWORD dataLen = sizeof(data);
        DWORD type = 0;
        LONG rc = RegEnumValueW(hKey, index++, valueName, &nameLen,
                                nullptr, &type, data, &dataLen);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) continue;
        if (type != REG_SZ && type != REG_EXPAND_SZ) continue;

        AutostartEntry e;
        e.type = AutostartType::RunKey;
        e.name = valueName;
        e.command = reinterpret_cast<wchar_t*>(data);
        e.location = locationLabel;
        e.imagePath = ExtractImagePath(e.command);
        if (!e.imagePath.empty() || !e.command.empty())
            out.push_back(std::move(e));
    }
    RegCloseKey(hKey);
}

} // namespace

void AutostartIndex::collectRunKeys() {
    ReadRunKey(HKEY_CURRENT_USER,
               L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
               L"HKCU\\...\\Run", entries_);
    ReadRunKey(HKEY_CURRENT_USER,
               L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
               L"HKCU\\...\\RunOnce", entries_);
    ReadRunKey(HKEY_LOCAL_MACHINE,
               L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
               L"HKLM\\...\\Run", entries_);
    ReadRunKey(HKEY_LOCAL_MACHINE,
               L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
               L"HKLM\\...\\RunOnce", entries_);
    ReadRunKey(HKEY_LOCAL_MACHINE,
               L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
               L"HKLM\\WOW6432Node\\...\\Run", entries_);
}

void AutostartIndex::collectServices() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return;

    DWORD bytesNeeded = 0, count = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                          SERVICE_STATE_ALL, nullptr, 0,
                          &bytesNeeded, &count, &resume, nullptr);
    if (bytesNeeded == 0) {
        CloseServiceHandle(scm);
        return;
    }

    std::vector<BYTE> buf(bytesNeeded);
    resume = 0;
    if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                               SERVICE_STATE_ALL, buf.data(), bytesNeeded,
                               &bytesNeeded, &count, &resume, nullptr)) {
        CloseServiceHandle(scm);
        return;
    }

    auto* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
    for (DWORD i = 0; i < count; ++i) {
        SC_HANDLE svc = OpenServiceW(scm, services[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (!svc) continue;

        DWORD need = 0;
        QueryServiceConfigW(svc, nullptr, 0, &need);
        if (need == 0) {
            CloseServiceHandle(svc);
            continue;
        }
        std::vector<BYTE> cfgBuf(need);
        auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cfgBuf.data());
        if (QueryServiceConfigW(svc, cfg, need, &need)) {
            AutostartEntry e;
            e.type = AutostartType::Service;
            e.name = services[i].lpServiceName;
            if (services[i].lpDisplayName)
                e.name += L" (" + std::wstring(services[i].lpDisplayName) + L")";
            e.command = cfg->lpBinaryPathName ? cfg->lpBinaryPathName : L"";
            e.location = L"Services";
            e.imagePath = ExtractImagePath(e.command);
            if (!e.imagePath.empty())
                entries_.push_back(std::move(e));
        }
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
}

void AutostartIndex::collectTasks() {
    // Task Scheduler string properties often come back empty from an MTA thread.
    HRESULT hrInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const bool needUninit = (hrInit == S_OK);
    if (FAILED(hrInit) && hrInit != RPC_E_CHANGED_MODE)
        return;

    ITaskService* service = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_ITaskService, (void**)&service);
    if (FAILED(hr) || !service) {
        if (needUninit) CoUninitialize();
        return;
    }

    hr = service->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        service->Release();
        if (needUninit) CoUninitialize();
        return;
    }

    ITaskFolder* root = nullptr;
    hr = service->GetFolder(_bstr_t(L"\\"), &root);
    if (FAILED(hr) || !root) {
        service->Release();
        if (needUninit) CoUninitialize();
        return;
    }

    // Recursive enumeration via stack of folders
    std::vector<ITaskFolder*> stack;
    stack.push_back(root);

    while (!stack.empty()) {
        ITaskFolder* folder = stack.back();
        stack.pop_back();

        BSTR folderPathBstr = nullptr;
        folder->get_Path(&folderPathBstr);
        std::wstring folderPath = BstrToW(folderPathBstr);
        if (folderPath.empty())
            folderPath = L"\\";
        if (folderPathBstr) SysFreeString(folderPathBstr);

        // Subfolders
        ITaskFolderCollection* folders = nullptr;
        if (SUCCEEDED(folder->GetFolders(0, &folders)) && folders) {
            LONG fcount = 0;
            folders->get_Count(&fcount);
            for (LONG i = 1; i <= fcount; ++i) {
                ITaskFolder* sub = nullptr;
                if (SUCCEEDED(folders->get_Item(_variant_t(i), &sub)) && sub)
                    stack.push_back(sub);
            }
            folders->Release();
        }

        // Tasks in this folder
        IRegisteredTaskCollection* tasks = nullptr;
        if (SUCCEEDED(folder->GetTasks(TASK_ENUM_HIDDEN, &tasks)) && tasks) {
            LONG tcount = 0;
            tasks->get_Count(&tcount);
            for (LONG i = 1; i <= tcount; ++i) {
                IRegisteredTask* task = nullptr;
                if (FAILED(tasks->get_Item(_variant_t(i), &task)) || !task)
                    continue;

                BSTR taskName = nullptr;
                task->get_Name(&taskName);
                const std::wstring name = BstrToW(taskName);

                ITaskDefinition* def = nullptr;
                bool isHidden = false;
                if (SUCCEEDED(task->get_Definition(&def)) && def) {
                    ITaskSettings* settings = nullptr;
                    if (SUCCEEDED(def->get_Settings(&settings)) && settings) {
                        VARIANT_BOOL hid = VARIANT_FALSE;
                        if (SUCCEEDED(settings->get_Hidden(&hid)))
                            isHidden = (hid == VARIANT_TRUE);
                        settings->Release();
                    }

                    IActionCollection* actions = nullptr;
                    if (SUCCEEDED(def->get_Actions(&actions)) && actions) {
                        LONG acount = 0;
                        actions->get_Count(&acount);
                        for (LONG a = 1; a <= acount; ++a) {
                            IAction* action = nullptr;
                            if (FAILED(actions->get_Item(a, &action)) || !action)
                                continue;
                            TASK_ACTION_TYPE atype = TASK_ACTION_EXEC;
                            action->get_Type(&atype);
                            if (atype == TASK_ACTION_EXEC) {
                                IExecAction* exec = nullptr;
                                if (SUCCEEDED(action->QueryInterface(IID_IExecAction, (void**)&exec)) && exec) {
                                    BSTR path = nullptr;
                                    BSTR args = nullptr;
                                    exec->get_Path(&path);
                                    exec->get_Arguments(&args);
                                    std::wstring pathW = BstrToW(path);
                                    std::wstring argsW = BstrToW(args);
                                    std::wstring cmd = pathW;
                                    if (!argsW.empty()) {
                                        if (!cmd.empty()) cmd += L" ";
                                        cmd += argsW;
                                    }
                                    AutostartEntry e;
                                    e.type = AutostartType::ScheduledTask;
                                    e.name = name;
                                    e.command = cmd;
                                    e.location = L"Task: " + folderPath;
                                    e.imagePath = ExtractImagePath(pathW);
                                    e.hidden = isHidden;
                                    if (!e.imagePath.empty() || isHidden)
                                        entries_.push_back(std::move(e));
                                    if (path) SysFreeString(path);
                                    if (args) SysFreeString(args);
                                    exec->Release();
                                }
                            }
                            action->Release();
                        }
                        actions->Release();
                    }
                    def->Release();
                }
                if (taskName) SysFreeString(taskName);
                task->Release();
            }
            tasks->Release();
        }

        folder->Release();
    }

    service->Release();
    if (needUninit) CoUninitialize();
}

void AutostartIndex::rebuild() {
    entries_.clear();
    collectRunKeys();
    collectServices();
    collectTasks();
}

std::vector<AutostartEntry> AutostartIndex::findForImage(const std::wstring& imagePath) const {
    std::vector<AutostartEntry> result;
    if (imagePath.empty()) return result;

    const std::wstring pathL = ToLower(imagePath);
    const std::wstring nameL = ToLower(BaseName(imagePath));

    for (const auto& e : entries_) {
        if (e.imagePath.empty()) continue;
        std::wstring ep = ToLower(e.imagePath);
        if (ep == pathL || BaseName(ep) == nameL) {
            result.push_back(e);
            continue;
        }
        // Command may contain path as substring
        std::wstring cmdL = ToLower(e.command);
        if (!nameL.empty() && cmdL.find(nameL) != std::wstring::npos)
            result.push_back(e);
    }
    return result;
}

std::vector<AutostartEntry> AutostartIndex::hiddenTasks() const {
    std::vector<AutostartEntry> out;
    for (const auto& e : entries_) {
        if (e.type == AutostartType::ScheduledTask && e.hidden)
            out.push_back(e);
    }
    std::sort(out.begin(), out.end(),
              [](const AutostartEntry& a, const AutostartEntry& b) {
                  return a.name < b.name;
              });
    return out;
}

size_t AutostartIndex::hiddenTaskCount() const {
    size_t n = 0;
    for (const auto& e : entries_)
        if (e.type == AutostartType::ScheduledTask && e.hidden) ++n;
    return n;
}
