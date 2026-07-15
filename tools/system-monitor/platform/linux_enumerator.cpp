#include "IProcessEnumerator.hpp"
#include <spdlog/spdlog.h>

#include <dirent.h>          
#include <sys/types.h>       
#include <unistd.h>          

#include <fstream>           
#include <string>
#include <vector>
#include <cstring>           
#include <algorithm>         
#include <cctype>            

// ------------------------------------------------------------
// 1. Linux implementation
// ------------------------------------------------------------

class LinuxEnumerator : public IProcessEnumerator {
public:
    std::vector<ProcessInfo> enumerate_processes() override {
        std::vector<ProcessInfo> result;

        DIR* proc_dir = opendir("/proc");
        if (!proc_dir) {
            spdlog::error("Failed to open /proc directory!");
            return result;
        }

        struct dirent* entry;
        while ((entry = readdir(proc_dir)) != nullptr) {
            std::string name = entry->d_name;
            if (!is_numeric(name)) {
                continue;
            }

            int pid = std::stoi(name);
            ProcessInfo info = read_process_info(pid);
            
            if (info.pid != -1) {
                result.push_back(info);
            }
        }

        closedir(proc_dir);
        return result;
    }

    std::unique_ptr<ProcessInfo> get_process_by_pid(int pid) override {
        ProcessInfo info = read_process_info(pid);
        if (info.pid == -1) {
            return nullptr;
        }
        return std::make_unique<ProcessInfo>(info);
    }

private:
    static bool is_numeric(const std::string& str) {
        return !str.empty() && std::all_of(str.begin(), str.end(), ::isdigit);
    }

    ProcessInfo read_process_info(int pid) {
        ProcessInfo info;
        info.pid = pid;
        info.memory_usage_kb = 0;
        info.cpu_usage_percent = 0.0;

        std::string comm_path = "/proc/" + std::to_string(pid) + "/comm";
        std::ifstream comm_file(comm_path);
        if (!comm_file.is_open()) {
            info.pid = -1; 
            return info;
        }
        std::getline(comm_file, info.name);
        comm_file.close();

        std::string status_path = "/proc/" + std::to_string(pid) + "/status";
        std::ifstream status_file(status_path);
        if (!status_file.is_open()) {
            info.pid = -1;
            return info;
        }

        std::string line;
        while (std::getline(status_file, line)) {
            if (line.find("VmRSS:") == 0) {
                std::string value_str;
                for (char c : line) {
                    if (std::isdigit(c)) {
                        value_str += c;
                    } else if (!value_str.empty()) {
                        break;
                    }
                }
                if (!value_str.empty()) {
                    info.memory_usage_kb = std::stoul(value_str);
                }
                break;
            }
        }
        status_file.close();
        return info;
    }
};

// ------------------------------------------------------------
// 2. The factory function (connects the interface to the Linux implementation)
// ------------------------------------------------------------
std::unique_ptr<IProcessEnumerator> create_process_enumerator() {
    return std::make_unique<LinuxEnumerator>();
}