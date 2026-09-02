#include "ProcessExtras.hpp"

#include <Windows.h>
#include <Psapi.h>
#include <sddl.h>
#include <cstdio>
#include <vector>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

namespace {

std::wstring IntegrityFromSid(PSID sid) {
    if (!IsValidSid(sid)) return L"Unknown";
    // RID of mandatory label
    auto* sub = GetSidSubAuthority(sid, *GetSidSubAuthorityCount(sid) - 1);
    if (!sub) return L"Unknown";
    DWORD rid = *sub;
    if (rid < SECURITY_MANDATORY_LOW_RID) return L"Untrusted";
    if (rid < SECURITY_MANDATORY_MEDIUM_RID) return L"Low";
    if (rid < SECURITY_MANDATORY_HIGH_RID) return L"Medium";
    if (rid < SECURITY_MANDATORY_SYSTEM_RID) return L"High";
    if (rid < 0x4000) return L"System";
    return L"Protected";
}

void FillUserAndIntegrity(HANDLE hProcess, ProcessInfo& proc) {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
        return;

    // User
    DWORD need = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &need);
    if (need > 0) {
        std::vector<BYTE> buf(need);
        if (GetTokenInformation(hToken, TokenUser, buf.data(), need, &need)) {
            auto* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
            wchar_t name[256] = {}, domain[256] = {};
            DWORD nameLen = 256, domainLen = 256;
            SID_NAME_USE use;
            if (LookupAccountSidW(nullptr, tu->User.Sid, name, &nameLen, domain, &domainLen, &use)) {
                proc.userName = std::wstring(domain) + L"\\" + name;
            }
        }
    }

    // Integrity
    need = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &need);
    if (need > 0) {
        std::vector<BYTE> buf(need);
        if (GetTokenInformation(hToken, TokenIntegrityLevel, buf.data(), need, &need)) {
            auto* til = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buf.data());
            proc.integrity = IntegrityFromSid(til->Label.Sid);
        }
    }

    CloseHandle(hToken);
}

void FillArch(HANDLE hProcess, ProcessInfo& proc) {
    // IsWow64Process2 if available
    using IsWow64Process2_t = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
    static auto pIsWow64Process2 = reinterpret_cast<IsWow64Process2_t>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2"));

    if (pIsWow64Process2) {
        USHORT processMachine = 0, nativeMachine = 0;
        if (pIsWow64Process2(hProcess, &processMachine, &nativeMachine)) {
            auto machineName = [](USHORT m) -> const wchar_t* {
                switch (m) {
                    case 0x014c: return L"x86";
                    case 0x8664: return L"x64";
                    case 0xAA64: return L"ARM64";
                    case 0x01c4: return L"ARM";
                    case 0: return nullptr; // not wow
                    default: return L"Other";
                }
            };
            if (processMachine == 0) {
                // native process
                if (const wchar_t* n = machineName(nativeMachine))
                    proc.arch = n;
                else
                    proc.arch = L"Native";
            } else {
                if (const wchar_t* n = machineName(processMachine))
                    proc.arch = n;
                else
                    proc.arch = L"WOW64";
            }
            return;
        }
    }

    BOOL wow = FALSE;
    if (IsWow64Process(hProcess, &wow)) {
        proc.arch = wow ? L"x86" : L"x64";
    }
}

void FillMemCounters(HANDLE hProcess, ProcessInfo& proc) {
    PROCESS_MEMORY_COUNTERS_EX pmc{};
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(hProcess, reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
        proc.workingSetBytes = pmc.WorkingSetSize;
        proc.privateBytes = pmc.PrivateUsage;
    }
}

void FillStartTime(ProcessInfo& proc) {
    if (proc.createTime == 0) return;
    FILETIME ft{};
    ft.dwLowDateTime = static_cast<DWORD>(proc.createTime & 0xFFFFFFFF);
    ft.dwHighDateTime = static_cast<DWORD>(proc.createTime >> 32);
    FILETIME local{};
    if (!FileTimeToLocalFileTime(&ft, &local)) return;
    SYSTEMTIME st{};
    if (!FileTimeToSystemTime(&local, &st)) return;
    wchar_t buf[64];
    swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u:%02u",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    proc.startTime = buf;
}

} // namespace

void EnrichProcessExtras(ProcessInfo& proc) {
    FillStartTime(proc);
    // SHA-256 is computed on demand (details / copy / VT / hash search),
    // not during refresh.

    if (proc.pid == 0 || proc.pid == 4)
        return;

    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, proc.pid);
    if (!h)
        h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, proc.pid);
    if (!h)
        return;

    FillUserAndIntegrity(h, proc);
    FillArch(h, proc);
    FillMemCounters(h, proc);

    CloseHandle(h);
}
