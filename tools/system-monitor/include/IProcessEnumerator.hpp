#pragma once

#include <string>
#include <vector>
#include <memory>

// 1. Data structure to store process information (DTO - Data Transfer Object)
struct ProcessInfo {
    int pid;                  
    std::string name;         
    size_t memory_usage_kb;   
    double cpu_usage_percent; 
};

// 2. THE PURE INTERFACE (Abstract class) – Defines "WHAT" to do, not "HOW"
class IProcessEnumerator {
public:
    virtual ~IProcessEnumerator() = default;

    virtual std::vector<ProcessInfo> enumerate_processes() = 0;

    virtual std::unique_ptr<ProcessInfo> get_process_by_pid(int pid) = 0;
};

// Factory function (creates the correct instance for the current OS)
std::unique_ptr<IProcessEnumerator> create_process_enumerator();