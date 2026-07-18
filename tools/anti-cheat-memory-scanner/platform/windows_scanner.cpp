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
// Estrutura para armazenar info da seção .text do PE
// ------------------------------------------------------------
struct PESectionInfo {
    std::vector<unsigned char> data;
    uintptr_t vaddr;
    size_t size;
};

class WindowsMemoryScanner : public IMemoryScanner {
private:
    // ------------------------------------------------------------
    // 1. SHA-256 de um buffer
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
    // 2. Ler arquivo inteiro para vector<unsigned char>
    // ------------------------------------------------------------
    std::vector<unsigned char> read_whole_file(const std::string& path) {
        HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            spdlog::error("Não foi possível abrir arquivo: {}", path);
            return {};
        }

        DWORD fileSize = GetFileSize(hFile, nullptr);
        std::vector<unsigned char> buffer(fileSize);
        DWORD bytesRead;
        if (!ReadFile(hFile, buffer.data(), fileSize, &bytesRead, nullptr) || bytesRead != fileSize) {
            spdlog::error("Erro ao ler arquivo: {}", path);
            CloseHandle(hFile);
            return {};
        }

        CloseHandle(hFile);
        return buffer;
    }

    // ------------------------------------------------------------
    // 3. Obter caminho do executável de um processo (Win32 API)
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
    // 4. Obter nome do processo
    // ------------------------------------------------------------
    std::string get_process_name(HANDLE hProcess) {
        char name[MAX_PATH];
        DWORD size = sizeof(name);
        if (QueryFullProcessImageNameA(hProcess, 0, name, &size)) {
            // Extrai apenas o nome do arquivo (remove caminho)
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
    // 5. Extrair a seção .text do PE (disco)
    // ------------------------------------------------------------
    PESectionInfo extract_text_section_from_pe(const std::vector<unsigned char>& fileContent) {
        PESectionInfo result;
        result.vaddr = 0;
        result.size = 0;

        if (fileContent.size() < sizeof(IMAGE_DOS_HEADER)) return result;

        // DOS Header
        const IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(fileContent.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            spdlog::error("Arquivo não é PE (DOS header inválido)");
            return result;
        }

        // NT Headers
        const IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            fileContent.data() + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            spdlog::error("Assinatura PE inválida");
            return result;
        }

        // Section Table
        const IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        int numSections = ntHeaders->FileHeader.NumberOfSections;

        for (int i = 0; i < numSections; ++i) {
            const IMAGE_SECTION_HEADER* section = &sectionHeader[i];
            // Nome da seção (8 bytes, não terminado em null se tiver 8 caracteres)
            char sectionName[9] = {0};
            memcpy(sectionName, section->Name, 8);

            if (strcmp(sectionName, ".text") == 0 || strcmp(sectionName, ".code") == 0) {
                result.vaddr = section->VirtualAddress;
                result.size = section->SizeOfRawData;
                result.data.assign(fileContent.begin() + section->PointerToRawData,
                                   fileContent.begin() + section->PointerToRawData + section->SizeOfRawData);
                spdlog::debug("Seção .text encontrada: vaddr=0x{:x}, size={}", result.vaddr, result.size);
                return result;
            }
        }

        spdlog::error("Seção .text não encontrada no PE");
        return result;
    }

    // ------------------------------------------------------------
    // 6. Ler memória do processo (ReadProcessMemory)
    // ------------------------------------------------------------
    std::vector<unsigned char> read_process_memory(HANDLE hProcess, uintptr_t address, size_t size) {
        std::vector<unsigned char> buffer(size);
        SIZE_T bytesRead;
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(address),
                               buffer.data(), size, &bytesRead) || bytesRead != size) {
            spdlog::error("Falha ao ler memória do processo (endereço: 0x{:x}, tamanho: {})", address, size);
            return {};
        }
        return buffer;
    }

    // ------------------------------------------------------------
    // 7. Obter a imagem base do módulo principal do processo
    // ------------------------------------------------------------
    uintptr_t get_process_image_base(HANDLE hProcess) {
        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            // O primeiro módulo é o executável principal
            MODULEINFO modInfo;
            if (GetModuleInformation(hProcess, hMods[0], &modInfo, sizeof(modInfo))) {
                return reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
            }
        }
        return 0;
    }

public:
    // ------------------------------------------------------------
    // 8. list_processes(): lista todos os processos
    // ------------------------------------------------------------
    std::vector<ProcessInfo> list_processes() override {
        std::vector<ProcessInfo> result;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            spdlog::error("Falha ao criar snapshot de processos");
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
        spdlog::info("Encontrados {} processos", result.size());
        return result;
    }

    // ------------------------------------------------------------
    // 9. scan_process(): escaneia um processo específico
    // ------------------------------------------------------------
    ScanReport scan_process(int pid) override {
        ScanReport report;
        report.pid = pid;
        report.text_section_integrity_ok = false;

        // Abre o processo
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                      FALSE, pid);
        if (!hProcess) {
            spdlog::error("Não foi possível abrir o processo PID {}", pid);
            report.process_name = "unknown";
            return report;
        }

        report.process_name = get_process_name(hProcess);

        // Obtém a imagem base do módulo principal
        uintptr_t imageBase = get_process_image_base(hProcess);
        if (imageBase == 0) {
            spdlog::error("Não foi possível obter imagem base para PID {}", pid);
            CloseHandle(hProcess);
            return report;
        }

        // Lê os cabeçalhos PE da memória
        IMAGE_DOS_HEADER dosHeader;
        IMAGE_NT_HEADERS ntHeaders;
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(imageBase),
                               &dosHeader, sizeof(dosHeader), nullptr) ||
            dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            spdlog::error("Erro ao ler DOS header da memória para PID {}", pid);
            CloseHandle(hProcess);
            return report;
        }

        if (!ReadProcessMemory(hProcess,
                               reinterpret_cast<LPCVOID>(imageBase + dosHeader.e_lfanew),
                               &ntHeaders, sizeof(ntHeaders), nullptr) ||
            ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
            spdlog::error("Erro ao ler NT headers da memória para PID {}", pid);
            CloseHandle(hProcess);
            return report;
        }

        // Extrai a seção .text do disco
        std::string exePath = get_process_exe_path(hProcess);
        if (exePath.empty()) {
            spdlog::error("Não foi possível obter caminho do executável para PID {}", pid);
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
            spdlog::error("Não foi possível extrair .text do disco para {}", exePath);
            CloseHandle(hProcess);
            return report;
        }

        spdlog::info("Seção .text no disco: vaddr=0x{:x}, size={}", textDisk.vaddr, textDisk.size);

        // Lê a seção .text da memória (usando a imagem base + vaddr)
        uintptr_t textAddr = imageBase + textDisk.vaddr;
        auto textMem = read_process_memory(hProcess, textAddr, textDisk.size);
        if (textMem.empty() || textMem.size() != textDisk.size) {
            spdlog::error("Não foi possível ler .text da memória para PID {}", pid);
            CloseHandle(hProcess);
            return report;
        }

        // Calcula hashes
        std::string hashDisk = sha256_buffer(textDisk.data.data(), textDisk.data.size());
        std::string hashMem = sha256_buffer(textMem.data(), textMem.size());

        spdlog::info("Hash .text (disco): {}", hashDisk);
        spdlog::info("Hash .text (memória): {}", hashMem);

        if (hashDisk == hashMem) {
            report.text_section_integrity_ok = true;
            spdlog::info("✅ Seção .text íntegra para PID {}", pid);
        } else {
            report.text_section_integrity_ok = false;
            spdlog::warn("🚨 Seção .text comprometida para PID {}!", pid);
            report.injected_regions.push_back("Seção .text modificada");
        }

        CloseHandle(hProcess);
        return report;
    }

    // ------------------------------------------------------------
    // 10. verify_text_section_integrity
    // ------------------------------------------------------------
    bool verify_text_section_integrity(int pid, std::string& out_error) override {
        auto report = scan_process(pid);
        if (report.pid == 0) {
            out_error = "Falha ao escanear processo";
            return false;
        }
        return report.text_section_integrity_ok;
    }
};

// ------------------------------------------------------------
// 11. Factory function
// ------------------------------------------------------------
std::unique_ptr<IMemoryScanner> create_memory_scanner() {
    spdlog::info("🛠️ Criando Memory Scanner para Windows");
    return std::make_unique<WindowsMemoryScanner>();
}