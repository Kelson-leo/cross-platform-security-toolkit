#include "IMemoryScanner.hpp"
#include <spdlog/spdlog.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <elf.h>
#include <openssl/evp.h>
#include <iomanip>    
#include <algorithm>  

struct ElfSectionInfo {
    std::vector<unsigned char> data;
    size_t offset;
    size_t size;
    uintptr_t vaddr;  // <--- ADDED: virtual address of the section
};

class LinuxMemoryScanner : public IMemoryScanner {
private:
    // ------------------------------------------------------------
    // 1. Calculates SHA-256 of a buffer
    // ------------------------------------------------------------
    std::string sha256_buffer(const unsigned char* data, size_t len) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return "";

        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len;

        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
            EVP_MD_CTX_free(ctx);
            return "";
        }
        if (EVP_DigestUpdate(ctx, data, len) != 1) {
            EVP_MD_CTX_free(ctx);
            return "";
        }
        if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
            EVP_MD_CTX_free(ctx);
            return "";
        }

        EVP_MD_CTX_free(ctx);

        std::stringstream ss;
        for (unsigned int i = 0; i < hash_len; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return ss.str();
    }

    // ------------------------------------------------------------
    // 2. Reads full file to a vector<unsigned char>
    // ------------------------------------------------------------
    std::vector<unsigned char> read_whole_file(const std::string& path) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            spdlog::error("Could not open file: {}", path);
            return {};
        }
        size_t size = file.tellg();
        file.seekg(0, std::ios::beg);
        std::vector<unsigned char> buffer(size);
        file.read(reinterpret_cast<char*>(buffer.data()), size);
        return buffer;
    }

    // ------------------------------------------------------------
    // 3. Obtains executable path of a process by /proc/[pid]/exe
    // ------------------------------------------------------------
    std::string get_process_exe_path(int pid) {
        std::string link_path = "/proc/" + std::to_string(pid) + "/exe";
        char path[PATH_MAX];
        ssize_t len = readlink(link_path.c_str(), path, sizeof(path) - 1);
        if (len == -1) {
            spdlog::error("Failed to read symbolic link for PID {}", pid);
            return "";
        }
        path[len] = '\0';
        return std::string(path);
    }

    // ------------------------------------------------------------
    // 4. Obtains the name process by /proc/[pid]/comm
    // ------------------------------------------------------------
    std::string get_process_name(int pid) {
        std::string comm_path = "/proc/" + std::to_string(pid) + "/comm";
        std::ifstream file(comm_path);
        if (!file.is_open()) {
            return "unknown";
        }
        std::string name;
        std::getline(file, name);
        return name;
    }

    // ------------------------------------------------------------
    // 5. (Optional) Get .text region from maps (no longer used)
    // Kept for reference only, not used in comparison.
    // ------------------------------------------------------------
    /*bool get_text_region(int pid, uintptr_t& start, uintptr_t& end, size_t& size) {
        std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";
        std::ifstream maps_file(maps_path);
        if (!maps_file.is_open()) {
            spdlog::error("Could not open /proc/{}/maps", pid);
            return false;
        }

        std::string exe_path = get_process_exe_path(pid);
        if (exe_path.empty()) {
            return false;
        }

        std::string line;
        while (std::getline(maps_file, line)) {
            std::istringstream iss(line);
            std::string addr_range, perms, offset, dev, inode, path;
            iss >> addr_range >> perms >> offset >> dev >> inode >> path;

            if (path == exe_path && perms.find('x') != std::string::npos) {
                size_t dash_pos = addr_range.find('-');
                if (dash_pos == std::string::npos) continue;
                std::string start_str = addr_range.substr(0, dash_pos);
                std::string end_str = addr_range.substr(dash_pos + 1);
                start = std::stoull(start_str, nullptr, 16);
                end = std::stoull(end_str, nullptr, 16);
                size = end - start;
                spdlog::debug(".text region found: 0x{:x} - 0x{:x} ({} bytes)", start, end, size);
                return true;
            }
        }
        return false;
    }*/

    std::vector<MemoryRegion> get_rwx_regions(int pid) {
    std::vector<MemoryRegion> rwx_regions;
    std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream maps_file(maps_path);
    if (!maps_file.is_open()) {
        spdlog::error("Could not open /proc/{}/maps", pid);
        return rwx_regions;
    }

    std::string line;
    while (std::getline(maps_file, line)) {
        std::istringstream iss(line);
        std::string addr_range, perms, offset, dev, inode, path;
        iss >> addr_range >> perms >> offset >> dev >> inode >> path;

        // Check if permissions include 'w' (write) and 'x' (execute)
        if (perms.find('w') != std::string::npos && perms.find('x') != std::string::npos) {
            size_t dash_pos = addr_range.find('-');
            if (dash_pos == std::string::npos) continue;
            uintptr_t start = std::stoull(addr_range.substr(0, dash_pos), nullptr, 16);
            uintptr_t end = std::stoull(addr_range.substr(dash_pos + 1), nullptr, 16);

            MemoryRegion region;
            region.start_address = start;
            region.end_address = end;
            region.size = end - start;
            region.permissions = perms;
            region.path = path;
            rwx_regions.push_back(region);
        }
    }
    return rwx_regions;
}

    // ------------------------------------------------------------
    // 6. Extracts .text section from ELF file (disk) and returns struct
    //    Now with vaddr
    // ------------------------------------------------------------
    ElfSectionInfo extract_text_section_from_file(const std::string& exe_path) {
        ElfSectionInfo result;
        result.vaddr = 0; // initialize
        auto file_content = read_whole_file(exe_path);
        if (file_content.empty()) {
            spdlog::error("Could not read file {}", exe_path);
            return result;
        }

        // Check if it's ELF
        if (file_content.size() < 4 ||
            file_content[0] != 0x7F || file_content[1] != 'E' ||
            file_content[2] != 'L' || file_content[3] != 'F') {
            spdlog::error("File {} is not a valid ELF", exe_path);
            return result;
        }

        // Check if 64-bit (EI_CLASS)
        if (file_content[4] != ELFCLASS64) {
            spdlog::error("Only ELF64 supported for now");
            return result;
        }

        // ELF64 header
        Elf64_Ehdr* ehdr = reinterpret_cast<Elf64_Ehdr*>(file_content.data());
        
        // Section header table
        Elf64_Shdr* shdr_table = reinterpret_cast<Elf64_Shdr*>(file_content.data() + ehdr->e_shoff);
        
        // String table (section names)
        Elf64_Shdr* strtab_hdr = &shdr_table[ehdr->e_shstrndx];
        const char* strtab = reinterpret_cast<const char*>(file_content.data() + strtab_hdr->sh_offset);

        // Look for .text section
        for (int i = 0; i < ehdr->e_shnum; ++i) {
            Elf64_Shdr* section = &shdr_table[i];
            const char* section_name = strtab + section->sh_name;
            if (std::strcmp(section_name, ".text") == 0) {
                result.offset = section->sh_offset;
                result.size = section->sh_size;
                result.vaddr = section->sh_addr;  // <--- store virtual address
                result.data.assign(file_content.begin() + result.offset,
                                   file_content.begin() + result.offset + result.size);
                spdlog::debug(".text section extracted from disk: offset={}, size={}, vaddr=0x{:x}", 
                              result.offset, result.size, result.vaddr);
                return result;
            }
        }

        spdlog::error(".text section not found in ELF");
        return result;
    }

    // ------------------------------------------------------------
    // 7. Reads process memory in a specific address
    // ------------------------------------------------------------
    std::vector<unsigned char> read_process_memory(int pid, uintptr_t address, size_t size) {
        std::string mem_path = "/proc/" + std::to_string(pid) + "/mem";
        int mem_fd = open(mem_path.c_str(), O_RDONLY);
        if (mem_fd == -1) {
            spdlog::error("Could not open /proc/{}/mem (need sudo?)", pid);
            return {};
        }

        std::vector<unsigned char> buffer(size);
        ssize_t bytes_read = pread(mem_fd, buffer.data(), size, address);
        close(mem_fd);

        if (bytes_read != static_cast<ssize_t>(size)) {
            spdlog::error("Failed to read process {} memory: read {} bytes, expected {}", pid, bytes_read, size);
            return {};
        }

        return buffer;
    }

public:
    // ------------------------------------------------------------
    // 8. list_processes(): lists all processes through /proc
    // ------------------------------------------------------------
    std::vector<ProcessInfo> list_processes() override {
        std::vector<ProcessInfo> result;
        DIR* proc_dir = opendir("/proc");
        if (!proc_dir) {
            spdlog::error("Could not open /proc");
            return result;
        }

        struct dirent* entry;
        while ((entry = readdir(proc_dir)) != nullptr) {
            if (entry->d_type == DT_DIR) {
                std::string name = entry->d_name;
                bool is_number = !name.empty() && std::all_of(name.begin(), name.end(), ::isdigit);
                if (is_number) {
                    int pid = std::stoi(name);
                    ProcessInfo info;
                    info.pid = pid;
                    info.name = get_process_name(pid);
                    info.executable_path = get_process_exe_path(pid);
                    result.push_back(info);
                }
            }
        }
        closedir(proc_dir);
        spdlog::info("Found {} processes", result.size());
        return result;
    }

    // ------------------------------------------------------------
    // 9. scan_process(): scans a specific process
    // ------------------------------------------------------------
    ScanReport scan_process(int pid) override {
        ScanReport report;
        report.pid = pid;
        report.text_section_integrity_ok = false;

        std::string exe_path = get_process_exe_path(pid);
        if (exe_path.empty()) {
            report.process_name = get_process_name(pid);
            spdlog::error("Could not get executable path for PID {}", pid);
            return report;
        }
        report.process_name = get_process_name(pid);

        // Extract .text section from file on disk (with offset, size and vaddr)
        ElfSectionInfo text_disk_info = extract_text_section_from_file(exe_path);
        if (text_disk_info.data.empty()) {
            spdlog::error("Could not extract .text from disk for {}", exe_path);
            return report;
        }

        spdlog::info(".text section on disk: offset={}, size={}, vaddr=0x{:x}", 
                     text_disk_info.offset, text_disk_info.size, text_disk_info.vaddr);

        // Read .text section from memory using virtual address (vaddr)
        // This is more precise than using the entire maps region.
        auto text_mem = read_process_memory(pid, text_disk_info.vaddr, text_disk_info.size);
        if (text_mem.empty() || text_mem.size() != text_disk_info.size) {
            spdlog::error("Could not read .text from memory for PID {}", pid);
            return report;
        }

        // Compute hashes
        std::string hash_disk = sha256_buffer(text_disk_info.data.data(), text_disk_info.data.size());
        std::string hash_mem = sha256_buffer(text_mem.data(), text_mem.size());

        spdlog::info("Hash .text (disk): {}", hash_disk);
        spdlog::info("Hash .text (memory): {}", hash_mem);

        // Compare
        if (hash_disk == hash_mem) {
            report.text_section_integrity_ok = true;
            spdlog::info("✅ .text section intact for PID {}", pid);
        } else {
            report.text_section_integrity_ok = false;
            spdlog::warn("🚨 .text section compromised for PID {}!", pid);
            report.injected_regions.push_back("Modified .text section");
        }

        auto rwx_regions = get_rwx_regions(pid);
        if (!rwx_regions.empty()) {
            spdlog::warn("🚨 Found {} RWX regions in process PID {}", rwx_regions.size(), pid);
            for (const auto& region : rwx_regions) {
                std::stringstream ss;
                ss << "RWX Region: 0x" << std::hex << region.start_address
                   << " - 0x" << region.end_address << " (" << region.permissions << ")";
                report.injected_regions.push_back(ss.str());
            }
        }

        return report;
    }

    // ------------------------------------------------------------
    // 10. verify_text_section_integrity
    // ------------------------------------------------------------
    bool verify_text_section_integrity(int pid, std::string& out_error) override {
        auto report = scan_process(pid);
        if (report.pid == 0) {
            out_error = "Failed to scan process";
            return false;
        }
        return report.text_section_integrity_ok;
    }
};

// ------------------------------------------------------------
// 11. Factory function
// ------------------------------------------------------------
std::unique_ptr<IMemoryScanner> create_memory_scanner() {
    spdlog::info("🛠️ Creating Memory Scanner for Linux");
    return std::make_unique<LinuxMemoryScanner>();
}