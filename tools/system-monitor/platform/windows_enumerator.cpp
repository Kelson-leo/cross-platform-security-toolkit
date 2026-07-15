#include "IProcessEnumerator.hpp"
#include <spdlog/spdlog.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>   
#include <psapi.h>      
#include <string>
#include <vector>
#include <memory>

#pragma comment(lib, "psapi.lib")

// ------------------------------------------------------------
// 1. Windows implementation
// ------------------------------------------------------------
class WindowsEnumerator : public IProcessEnumerator {
public:
    std::vector<ProcessInfo> enumerate_processes() override {
        std::vector<ProcessInfo> result;

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            spdlog::error("Failed to create process snapshot!");
            return result;
        }

        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(snapshot, &entry)) {
            spdlog::error("Failed to get first process!");
            CloseHandle(snapshot);
            return result;
        }
        do {
            ProcessInfo info;
            info.pid = entry.th32ProcessID;
            info.name = entry.szExeFile; 
            info.cpu_usage_percent = 0.0; 

            HANDLE process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, info.pid);
            if (process_handle) {
                PROCESS_MEMORY_COUNTERS counters;
                if (GetProcessMemoryInfo(process_handle, &counters, sizeof(counters))) {
                    info.memory_usage_kb = counters.WorkingSetSize / 1024;
                } else {
                    info.memory_usage_kb = 0;
                }
                CloseHandle(process_handle);
            } else {
                info.memory_usage_kb = 0;
            }

            result.push_back(info);
        } while (Process32Next(snapshot, &entry));

        CloseHandle(snapshot);
        return result;
    }

    std::unique_ptr<ProcessInfo> get_process_by_pid(int pid) override {
        HANDLE process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!process_handle) {
            return nullptr; 
        }

        auto info = std::make_unique<ProcessInfo>();
        info->pid = pid;

        char exe_path[MAX_PATH];
        DWORD size = sizeof(exe_path);
        if (QueryFullProcessImageNameA(process_handle, 0, exe_path, &size)) {
            std::string full_path(exe_path);
            size_t last_slash = full_path.find_last_of("\\");
            if (last_slash != std::string::npos) {
                info->name = full_path.substr(last_slash + 1);
            } else {
                info->name = full_path;
            }
        } else {
            info->name = "Unknown";
        }

        PROCESS_MEMORY_COUNTERS counters;
        if (GetProcessMemoryInfo(process_handle, &counters, sizeof(counters))) {
            info->memory_usage_kb = counters.WorkingSetSize / 1024;
        } else {
            info->memory_usage_kb = 0;
        }

        info->cpu_usage_percent = 0.0;
        CloseHandle(process_handle);
        return info;
    }
};

// ------------------------------------------------------------
// 2. Factory function (Windows)
// ------------------------------------------------------------
std::unique_ptr<IProcessEnumerator> create_process_enumerator() {
    return std::make_unique<WindowsEnumerator>();
}