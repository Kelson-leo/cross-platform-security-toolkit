#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>

struct FileEntry {
    std::string path;      
    std::string hash_sha256;
    size_t file_size;      
};

struct IntegrityReport {
    std::vector<FileEntry> modified_files;   
    std::vector<FileEntry> new_files;        
    std::vector<std::string> missing_files;  
    size_t total_files_scanned;
};

// Pure interface
class IFileIntegrityMonitor {
public:
    virtual ~IFileIntegrityMonitor() = default;

    virtual bool generate_baseline(const std::string& root_directory, 
                                   const std::string& state_file_path) = 0;

    virtual IntegrityReport verify_integrity(const std::string& root_directory,
                                             const std::string& state_file_path) = 0;

    virtual bool load_baseline(const std::string& state_file_path) = 0;
};

std::unique_ptr<IFileIntegrityMonitor> create_file_integrity_monitor();