#include "ProcessCollector.hpp"
#include "Signature.hpp"
#include "ProcessExtras.hpp"

#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>
#include <vector>
#include <memory>
#include <string>
#include <iterator>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Psapi.lib")

// ---------------------------------------------------------------------------
// Минимальная структура SYSTEM_PROCESS_INFORMATION
// ---------------------------------------------------------------------------
typedef struct _SYSTEM_PROCESS_INFORMATION_MIN {
    ULONG               NextEntryOffset;
    ULONG               NumberOfThreads;
    LARGE_INTEGER       WorkingSetPrivateSize;
    ULONG               HardFaultCount;
    ULONG               NumberOfThreadsHighWatermark;
    ULONGLONG           CycleTime;
    LARGE_INTEGER       CreateTime;
    LARGE_INTEGER       UserTime;
    LARGE_INTEGER       KernelTime;
    UNICODE_STRING      ImageName;
    KPRIORITY           BasePriority;
    HANDLE              UniqueProcessId;
    HANDLE              InheritedFromUniqueProcessId;
    ULONG               HandleCount;
    ULONG               SessionId;
} SYSTEM_PROCESS_INFORMATION_MIN, *PSYSTEM_PROCESS_INFORMATION_MIN;

using NtQuerySystemInformation_t = NTSTATUS(NTAPI*)(
    SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

using NtQueryInformationProcess_t = NTSTATUS(NTAPI*)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// ProcessCommandLineInformation = 60 (с Windows 8.1)
#ifndef ProcessCommandLineInformation
#define ProcessCommandLineInformation ((PROCESSINFOCLASS)60)
#endif

// ---------------------------------------------------------------------------
// Получение полного пути
// ---------------------------------------------------------------------------
static std::wstring GetProcessImagePath(DWORD pid) {
    // Самый надёжный современный способ
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) {
        // Попробуем с более широкими правами
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess)
            return {};
    }

    wchar_t buffer[MAX_PATH * 4] = {};
    DWORD size = static_cast<DWORD>(std::size(buffer));

    // QueryFullProcessImageNameW доступен с Vista
    if (QueryFullProcessImageNameW(hProcess, 0, buffer, &size)) {
        CloseHandle(hProcess);
        return buffer;
    }

    // Fallback
    size = static_cast<DWORD>(std::size(buffer));
    if (GetModuleFileNameExW(hProcess, nullptr, buffer, size)) {
        CloseHandle(hProcess);
        return buffer;
    }

    CloseHandle(hProcess);
    return {};
}

// ---------------------------------------------------------------------------
// Получение command line
// ---------------------------------------------------------------------------
static std::wstring GetProcessCommandLine(DWORD pid) {
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, pid);

    if (!hProcess) {
        // Попробуем limited (для ProcessCommandLineInformation иногда хватает)
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess)
            return {};
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto NtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcess_t>(
        GetProcAddress(ntdll, "NtQueryInformationProcess"));

    if (!NtQueryInformationProcess) {
        CloseHandle(hProcess);
        return {};
    }

    // --- Способ 1: ProcessCommandLineInformation (Win 8.1+) ---
    {
        ULONG size = 0;
        NTSTATUS status = NtQueryInformationProcess(
            hProcess, ProcessCommandLineInformation, nullptr, 0, &size);

        if (status == STATUS_INFO_LENGTH_MISMATCH && size > 0) {
            std::vector<BYTE> buffer(size);
            status = NtQueryInformationProcess(
                hProcess, ProcessCommandLineInformation,
                buffer.data(), size, &size);

            if (NT_SUCCESS(status)) {
                // Структура: UNICODE_STRING в начале буфера
                auto* str = reinterpret_cast<UNICODE_STRING*>(buffer.data());
                if (str->Buffer && str->Length > 0) {
                    std::wstring result(str->Buffer, str->Length / sizeof(WCHAR));
                    CloseHandle(hProcess);
                    return result;
                }
            }
        }
    }

    // --- Способ 2: классический через PEB (fallback) ---
    PROCESS_BASIC_INFORMATION pbi{};
    ULONG returnLength = 0;
    NTSTATUS status = NtQueryInformationProcess(
        hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);

    if (!NT_SUCCESS(status) || !pbi.PebBaseAddress) {
        CloseHandle(hProcess);
        return {};
    }

    // Читаем указатель на RTL_USER_PROCESS_PARAMETERS
    PVOID rtlParamsAddr = nullptr;
    SIZE_T bytesRead = 0;

    // Смещение ProcessParameters в PEB (x64 = 0x20, x86 = 0x10)
#ifdef _WIN64
    const ULONG_PTR pebOffset = 0x20;
#else
    const ULONG_PTR pebOffset = 0x10;
#endif

    if (!ReadProcessMemory(hProcess,
                           reinterpret_cast<BYTE*>(pbi.PebBaseAddress) + pebOffset,
                           &rtlParamsAddr, sizeof(rtlParamsAddr), &bytesRead) ||
        !rtlParamsAddr) {
        CloseHandle(hProcess);
        return {};
    }

    // Смещение CommandLine в RTL_USER_PROCESS_PARAMETERS (x64 = 0x70, x86 = 0x40)
#ifdef _WIN64
    const ULONG_PTR cmdOffset = 0x70;
#else
    const ULONG_PTR cmdOffset = 0x40;
#endif

    UNICODE_STRING cmdLine{};
    if (!ReadProcessMemory(hProcess,
                           reinterpret_cast<BYTE*>(rtlParamsAddr) + cmdOffset,
                           &cmdLine, sizeof(cmdLine), &bytesRead)) {
        CloseHandle(hProcess);
        return {};
    }

    if (!cmdLine.Buffer || cmdLine.Length == 0) {
        CloseHandle(hProcess);
        return {};
    }

    std::wstring result(cmdLine.Length / sizeof(WCHAR), L'\0');
    if (!ReadProcessMemory(hProcess, cmdLine.Buffer,
                           result.data(), cmdLine.Length, &bytesRead)) {
        CloseHandle(hProcess);
        return {};
    }

    CloseHandle(hProcess);
    return result;
}

// ---------------------------------------------------------------------------
// Основной сбор
// ---------------------------------------------------------------------------
std::vector<std::unique_ptr<ProcessInfo>> ProcessCollector::Collect(bool enrich) {
    std::vector<std::unique_ptr<ProcessInfo>> result;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return result;

    auto NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformation_t>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (!NtQuerySystemInformation)
        return result;

    ULONG bufferSize = 0x20000;
    std::vector<BYTE> buffer(bufferSize);
    NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;

    while (status == STATUS_INFO_LENGTH_MISMATCH) {
        buffer.resize(bufferSize);
        status = NtQuerySystemInformation(
            SystemProcessInformation,
            buffer.data(),
            static_cast<ULONG>(buffer.size()),
            &bufferSize);
    }

    if (!NT_SUCCESS(status))
        return result;

    auto* spi = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION_MIN>(buffer.data());

    for (;;) {
        auto pi = std::make_unique<ProcessInfo>();

        pi->pid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(spi->UniqueProcessId));
        pi->ppid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(spi->InheritedFromUniqueProcessId));
        pi->createTime = static_cast<uint64_t>(spi->CreateTime.QuadPart);
        pi->basePriority = spi->BasePriority;
        pi->sessionId = static_cast<int>(spi->SessionId);

        if (spi->ImageName.Buffer && spi->ImageName.Length > 0) {
            pi->name.assign(spi->ImageName.Buffer, spi->ImageName.Length / sizeof(WCHAR));
        } else {
            if (pi->pid == 0)
                pi->name = L"[System Idle Process]";
            else
                pi->name = L"System";
        }

        result.push_back(std::move(pi));

        if (spi->NextEntryOffset == 0)
            break;

        spi = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION_MIN>(
            reinterpret_cast<BYTE*>(spi) + spi->NextEntryOffset);
    }

    // Обогащение (путь + cmdline + подпись + service name для svchost)
    if (enrich) {
        for (auto& p : result) {
            if (!p || p->pid == 0)
                continue;

            p->imagePath   = GetProcessImagePath(p->pid);
            p->commandLine = GetProcessCommandLine(p->pid);

            if (!p->imagePath.empty())
                p->signature = VerifySignature(p->imagePath);

            // Парсим имя службы из cmdline svchost: -s ServiceName
            if (_wcsicmp(p->name.c_str(), L"svchost.exe") == 0 && !p->commandLine.empty()) {
                const std::wstring& cmd = p->commandLine;
                // ищем " -s " или " -s"
                size_t pos = cmd.find(L" -s ");
                if (pos == std::wstring::npos)
                    pos = cmd.find(L" -s");
                if (pos != std::wstring::npos) {
                    pos = cmd.find_first_not_of(L" \t", pos + 3);
                    if (pos != std::wstring::npos) {
                        size_t end = cmd.find_first_of(L" \t", pos);
                        p->serviceName = (end == std::wstring::npos)
                            ? cmd.substr(pos)
                            : cmd.substr(pos, end - pos);
                    }
                }
            }

            EnrichProcessExtras(*p);
        }
    }

    return result;
}
