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

namespace fs = std::filesystem;

struct ElfSectionInfo {
    std::vector<unsigned char> data;
    size_t offset;
    size_t size;
    uintptr_t vaddr;  // <--- ADICIONADO: endereço virtual da seção
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
            spdlog::error("Não foi possível abrir arquivo: {}", path);
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
            spdlog::error("Falha ao ler link simbólico para PID {}", pid);
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
    // 5. (Opcional) Obter a região .text do maps (não mais usado)
    // Mantido apenas para referencia, mas não usado na comparação.
    // ------------------------------------------------------------
    bool get_text_region(int pid, uintptr_t& start, uintptr_t& end, size_t& size) {
        std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";
        std::ifstream maps_file(maps_path);
        if (!maps_file.is_open()) {
            spdlog::error("Não foi possível abrir /proc/{}/maps", pid);
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
                spdlog::debug("Região .text encontrada: 0x{:x} - 0x{:x} ({} bytes)", start, end, size);
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------
    // 6. Extracts .text section from ELF file (disk) and returns struct
    //    Agora com vaddr
    // ------------------------------------------------------------
    ElfSectionInfo extract_text_section_from_file(const std::string& exe_path) {
        ElfSectionInfo result;
        result.vaddr = 0; // inicializa
        auto file_content = read_whole_file(exe_path);
        if (file_content.empty()) {
            spdlog::error("Não foi possível ler o arquivo {}", exe_path);
            return result;
        }

        // Verifica se é ELF
        if (file_content.size() < 4 ||
            file_content[0] != 0x7F || file_content[1] != 'E' ||
            file_content[2] != 'L' || file_content[3] != 'F') {
            spdlog::error("Arquivo {} não é ELF válido", exe_path);
            return result;
        }

        // Verifica se é 64 bits (EI_CLASS)
        if (file_content[4] != ELFCLASS64) {
            spdlog::error("Apenas ELF64 suportado por enquanto");
            return result;
        }

        // Cabeçalho ELF64
        Elf64_Ehdr* ehdr = reinterpret_cast<Elf64_Ehdr*>(file_content.data());
        
        // Tabela de seções
        Elf64_Shdr* shdr_table = reinterpret_cast<Elf64_Shdr*>(file_content.data() + ehdr->e_shoff);
        
        // Tabela de strings (nomes das seções)
        Elf64_Shdr* strtab_hdr = &shdr_table[ehdr->e_shstrndx];
        const char* strtab = reinterpret_cast<const char*>(file_content.data() + strtab_hdr->sh_offset);

        // Procura pela seção .text
        for (int i = 0; i < ehdr->e_shnum; ++i) {
            Elf64_Shdr* section = &shdr_table[i];
            const char* section_name = strtab + section->sh_name;
            if (std::strcmp(section_name, ".text") == 0) {
                result.offset = section->sh_offset;
                result.size = section->sh_size;
                result.vaddr = section->sh_addr;  // <--- guarda o endereço virtual
                result.data.assign(file_content.begin() + result.offset,
                                   file_content.begin() + result.offset + result.size);
                spdlog::debug("Seção .text extraída do disco: offset={}, size={}, vaddr=0x{:x}", 
                              result.offset, result.size, result.vaddr);
                return result;
            }
        }

        spdlog::error("Seção .text não encontrada no ELF");
        return result;
    }

    // ------------------------------------------------------------
    // 7. Reads process memory in a specific address
    // ------------------------------------------------------------
    std::vector<unsigned char> read_process_memory(int pid, uintptr_t address, size_t size) {
        std::string mem_path = "/proc/" + std::to_string(pid) + "/mem";
        int mem_fd = open(mem_path.c_str(), O_RDONLY);
        if (mem_fd == -1) {
            spdlog::error("Não foi possível abrir /proc/{}/mem (precisa de sudo?)", pid);
            return {};
        }

        std::vector<unsigned char> buffer(size);
        ssize_t bytes_read = pread(mem_fd, buffer.data(), size, address);
        close(mem_fd);

        if (bytes_read != static_cast<ssize_t>(size)) {
            spdlog::error("Falha ao ler memória do processo {}: leu {} bytes, esperava {}", pid, bytes_read, size);
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
            spdlog::error("Não foi possível abrir /proc");
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
        spdlog::info("Encontrados {} processos", result.size());
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
            spdlog::error("Não foi possível obter caminho do executável para PID {}", pid);
            return report;
        }
        report.process_name = get_process_name(pid);

        // Extrai a seção .text do arquivo no disco (com offset, size e vaddr)
        ElfSectionInfo text_disk_info = extract_text_section_from_file(exe_path);
        if (text_disk_info.data.empty()) {
            spdlog::error("Não foi possível extrair .text do disco para {}", exe_path);
            return report;
        }

        spdlog::info("Seção .text no disco: offset={}, size={}, vaddr=0x{:x}", 
                     text_disk_info.offset, text_disk_info.size, text_disk_info.vaddr);

        // Lê a seção .text da memória usando o endereço virtual (vaddr)
        // Isso é mais preciso do que usar a região inteira do maps.
        auto text_mem = read_process_memory(pid, text_disk_info.vaddr, text_disk_info.size);
        if (text_mem.empty() || text_mem.size() != text_disk_info.size) {
            spdlog::error("Não foi possível ler .text da memória para PID {}", pid);
            return report;
        }

        // Calcula os hashes
        std::string hash_disk = sha256_buffer(text_disk_info.data.data(), text_disk_info.data.size());
        std::string hash_mem = sha256_buffer(text_mem.data(), text_mem.size());

        spdlog::info("Hash .text (disco): {}", hash_disk);
        spdlog::info("Hash .text (memória): {}", hash_mem);

        // Compara
        if (hash_disk == hash_mem) {
            report.text_section_integrity_ok = true;
            spdlog::info("✅ Seção .text íntegra para PID {}", pid);
        } else {
            report.text_section_integrity_ok = false;
            spdlog::warn("🚨 Seção .text comprometida para PID {}!", pid);
            report.injected_regions.push_back("Seção .text modificada");
        }

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
    spdlog::info("🛠️ Criando Memory Scanner para Linux");
    return std::make_unique<LinuxMemoryScanner>();
}