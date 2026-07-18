#include "IMemoryScanner.hpp"
#include <spdlog/spdlog.h>

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>

#include <openssl/evp.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

// ------------------------------------------------------------
// Structure to store PE .text section info
// ------------------------------------------------------------
struct PESectionInfo {
    std::vector<unsigned char> data;
    uintptr_t vaddr;
    size_t size;
};

class WindowsMemoryScanner : public IMemoryScanner {
private:
    // ------------------------------------------------------------
    // 1. SHA-256 of a buffer
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
    // 2. Read entire file into vector<unsigned char>
    // ------------------------------------------------------------
    std::vector<unsigned char> read_whole_file(const std::string& path) {
        HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            spdlog::error("Could not open file: {}", path);
            return {};
        }

        DWORD fileSize = GetFileSize(hFile, nullptr);
        std::vector<unsigned char> buffer(fileSize);
        DWORD bytesRead;
        if (!ReadFile(hFile, buffer.data(), fileSize, &bytesRead, nullptr) || bytesRead != fileSize) {
            spdlog::error("Error reading file: {}", path);
            CloseHandle(hFile);
            return {};
        }

        CloseHandle(hFile);
        return buffer;
    }

    // ------------------------------------------------------------
    // 3. Get process executable path (Win32 API)
    // ------------------------------------------------------------
    std::string get_process_exe_path(HANDLE hProcess) {
        char path[MAX_PATH];
        DWORD size = sizeof(path);
        if (QueryFullProcessImageNameA(hProcess, 0, path, &size)) {
            return std::string(path);
        }
        return "";
    }

    // ------------------------------------------------------------
    // 4. Get process name
    // ------------------------------------------------------------
    std::string get_process_name(HANDLE hProcess) {
        char name[MAX_PATH];
        DWORD size = sizeof(name);
        if (QueryFullProcessImageNameA(hProcess, 0, name, &size)) {
            std::string fullPath(name);
            size_t pos = fullPath.find_last_of("\\");
            if (pos != std::string::npos) {
                return fullPath.substr(pos + 1);
            }
            return fullPath;
        }
        return "unknown";
    }

    // ------------------------------------------------------------
    // 5. Extract .text section from PE (disk)
    // ------------------------------------------------------------
    PESectionInfo extract_text_section_from_pe(const std::vector<unsigned char>& fileContent) {
        PESectionInfo result;
        result.vaddr = 0;
        result.size = 0;

        if (fileContent.size() < sizeof(IMAGE_DOS_HEADER)) return result;

        const IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(fileContent.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            spdlog::error("File is not PE (invalid DOS header)");
            return result;
        }

        const IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            fileContent.data() + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            spdlog::error("Invalid PE signature");
            return result;
        }

        const IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        int numSections = ntHeaders->FileHeader.NumberOfSections;

        for (int i = 0; i < numSections; ++i) {
            const IMAGE_SECTION_HEADER* section = &sectionHeader[i];
            char sectionName[9] = {0};
            memcpy(sectionName, section->Name, 8);

            if (strcmp(sectionName, ".text") == 0 || strcmp(sectionName, ".code") == 0) {
                result.vaddr = section->VirtualAddress;
                result.size = section->SizeOfRawData;
                result.data.assign(fileContent.begin() + section->PointerToRawData,
                                   fileContent.begin() + section->PointerToRawData + section->SizeOfRawData);
                spdlog::debug(".text section found: vaddr=0x{:x}, size={}", result.vaddr, result.size);
                return result;
            }
        }

        spdlog::error(".text section not found in PE");
        return result;
    }

    // ------------------------------------------------------------
    // 6. Read process memory (ReadProcessMemory)
    // ------------------------------------------------------------
    std::vector<unsigned char> read_process_memory(HANDLE hProcess, uintptr_t address, size_t size) {
        std::vector<unsigned char> buffer(size);
        SIZE_T bytesRead;
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(address),
                               buffer.data(), size, &bytesRead) || bytesRead != size) {
            spdlog::error("Failed to read process memory (address: 0x{:x}, size: {})", address, size);
            return {};
        }
        return buffer;
    }

    // ------------------------------------------------------------
    // 7. Get base image of the process main module
    // ------------------------------------------------------------
    uintptr_t get_process_image_base(HANDLE hProcess) {
        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            MODULEINFO modInfo;
            if (GetModuleInformation(hProcess, hMods[0], &modInfo, sizeof(modInfo))) {
                return reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
            }
        }
        return 0;
    }

    // ------------------------------------------------------------
    // 🔥 8. RWX region detection (FIXED)
    // ------------------------------------------------------------
    std::vector<MemoryRegion> get_rwx_regions(HANDLE hProcess) {
        std::vector<MemoryRegion> rwx_regions;
        uintptr_t address = 0;
        MEMORY_BASIC_INFORMATION mbi;

        while (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(address),
                              &mbi, sizeof(mbi)) == sizeof(mbi)) {
            DWORD protect = mbi.Protect;
            if ((protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE ||
                (protect & PAGE_EXECUTE_WRITECOPY) == PAGE_EXECUTE_WRITECOPY) {
                MemoryRegion region;
                region.start_address = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                region.end_address = region.start_address + mbi.RegionSize;
                region.size = mbi.RegionSize;
                region.permissions = "RWX";  // Direct, since we only enter here for RWX
                region.path = "";
                rwx_regions.push_back(region);
            }
            address = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        }
        return rwx_regions;
    }

public:
    // ------------------------------------------------------------
    // 9. list_processes()
    // ------------------------------------------------------------
    std::vector<ProcessInfo> list_processes() override {
        std::vector<ProcessInfo> result;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            spdlog::error("Failed to create process snapshot");
            return result;
        }

        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);
        if (!Process32First(snapshot, &entry)) {
            CloseHandle(snapshot);
            return result;
        }

        do {
            ProcessInfo info;
            info.pid = entry.th32ProcessID;
            info.name = entry.szExeFile;

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                          FALSE, entry.th32ProcessID);
            if (hProcess) {
                info.executable_path = get_process_exe_path(hProcess);
                CloseHandle(hProcess);
            }
            result.push_back(info);
        } while (Process32Next(snapshot, &entry));

        CloseHandle(snapshot);
        spdlog::info("Found {} processes", result.size());
        return result;
    }

    // ------------------------------------------------------------
    // 10. scan_process()
    // ------------------------------------------------------------
    ScanReport scan_process(int pid) override {
        ScanReport report;
        report.pid = pid;
        report.text_section_integrity_ok = false;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                      FALSE, pid);
        if (!hProcess) {
            spdlog::error("Could not open process PID {}", pid);
            report.process_name = "unknown";
            return report;
        }

        report.process_name = get_process_name(hProcess);

        uintptr_t imageBase = get_process_image_base(hProcess);
        if (imageBase == 0) {
            spdlog::error("Could not get base image for PID {}", pid);
            CloseHandle(hProcess);
            return report;
        }

        IMAGE_DOS_HEADER dosHeader;
        IMAGE_NT_HEADERS ntHeaders;
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(imageBase),
                               &dosHeader, sizeof(dosHeader), nullptr) ||
            dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            spdlog::error("Error reading DOS header from memory for PID {}", pid);
            CloseHandle(hProcess);
            return report;
        }

        if (!ReadProcessMemory(hProcess,
                               reinterpret_cast<LPCVOID>(imageBase + dosHeader.e_lfanew),
                               &ntHeaders, sizeof(ntHeaders), nullptr) ||
            ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
            spdlog::error("Error reading NT headers from memory for PID {}", pid);
            CloseHandle(hProcess);
            return report;
        }

        std::string exePath = get_process_exe_path(hProcess);
        if (exePath.empty()) {
            spdlog::error("Could not get executable path for PID {}", pid);
            CloseHandle(hProcess);
            return report;
        }

        auto fileContent = read_whole_file(exePath);
        if (fileContent.empty()) {
            CloseHandle(hProcess);
            return report;
        }

        PESectionInfo textDisk = extract_text_section_from_pe(fileContent);
        if (textDisk.data.empty() || textDisk.vaddr == 0) {
            spdlog::error("Could not extract .text from disk for {}", exePath);
            CloseHandle(hProcess);
            return report;
        }

        spdlog::info(".text section on disk: vaddr=0x{:x}, size={}", textDisk.vaddr, textDisk.size);

        uintptr_t textAddr = imageBase + textDisk.vaddr;
        auto textMem = read_process_memory(hProcess, textAddr, textDisk.size);
        if (textMem.empty() || textMem.size() != textDisk.size) {
            spdlog::error("Could not read .text from memory for PID {}", pid);
            CloseHandle(hProcess);
            return report;
        }

        std::string hashDisk = sha256_buffer(textDisk.data.data(), textDisk.data.size());
        std::string hashMem = sha256_buffer(textMem.data(), textMem.size());

        spdlog::info("Hash .text (disk): {}", hashDisk);
        spdlog::info("Hash .text (memory): {}", hashMem);

        if (hashDisk == hashMem) {
            report.text_section_integrity_ok = true;
            spdlog::info("✅ .text section intact for PID {}", pid);
        } else {
            report.text_section_integrity_ok = false;
            spdlog::warn("🚨 .text section compromised for PID {}!", pid);
            report.injected_regions.push_back("Modified .text section");
        }

        auto rwx_regions = get_rwx_regions(hProcess);
        if (!rwx_regions.empty()) {
            spdlog::warn("🚨 Found {} RWX regions in process PID {}", pid, rwx_regions.size());
            for (const auto& region : rwx_regions) {
                std::stringstream ss;
                ss << "RWX Region: 0x" << std::hex << region.start_address
                   << " - 0x" << region.end_address;
                report.injected_regions.push_back(ss.str());
            }
        }

        CloseHandle(hProcess);
        return report;
    }

    // ------------------------------------------------------------
    // 11. verify_text_section_integrity
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
// 12. Factory function
// ------------------------------------------------------------
std::unique_ptr<IMemoryScanner> create_memory_scanner() {
    spdlog::info("🛠️ Creating Memory Scanner for Windows");
    return std::make_unique<WindowsMemoryScanner>();
}