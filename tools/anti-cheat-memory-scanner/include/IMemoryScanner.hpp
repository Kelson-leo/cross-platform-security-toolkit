#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <memory>

// Represents memory region of a process
struct MemoryRegion {
    uintptr_t start_address;
    uintptr_t end_address;
    size_t size;
    std::string permissions; 
    std::string path;        
};

// Represents process in execution
struct ProcessInfo {
    int pid;
    std::string name;
    std::string executable_path;
};

// Scanning report
struct ScanReport {
    int pid;
    std::string process_name;
    bool text_section_integrity_ok;   
    std::vector<std::string> injected_regions; 
    std::vector<std::string> hooks_detected;   
    bool has_rwx_regions = false;
};

// Pure interface
class IMemoryScanner {
public:
    virtual ~IMemoryScanner() = default;

    virtual std::vector<ProcessInfo> list_processes() = 0;

    virtual ScanReport scan_process(int pid) = 0;

    virtual bool verify_text_section_integrity(int pid, std::string& out_error) = 0;
};

// Factory function
std::unique_ptr<IMemoryScanner> create_memory_scanner();