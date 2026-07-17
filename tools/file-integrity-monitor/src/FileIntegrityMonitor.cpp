#include "IFileIntegrityMonitor.hpp"
#include <spdlog/spdlog.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>

// OpenSSL (for SHA-256)
#include <openssl/evp.h>

// JSON (popular header-only library: nlohmann/json)
#include <nlohmann/json.hpp>

using json = nlohmann::json;
namespace fs = std::filesystem;

// ------------------------------------------------------------
// 1. Actual Class
// ------------------------------------------------------------
class FileIntegrityMonitor : public IFileIntegrityMonitor {
private:
    std::string m_root;           
    json m_baseline_data;         

    std::string compute_file_sha256(const fs::path& file_path) {
        std::ifstream file(file_path, std::ios::binary);
        if (!file.is_open()) {
            spdlog::error("Não foi possível abrir o arquivo: {}", file_path.string());
            return "";
        }

        // SHA-256 (OpenSSL)
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            spdlog::error("Falha ao criar contexto SHA-256");
            return "";
        }

        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
            spdlog::error("Falha ao inicializar SHA-256");
            EVP_MD_CTX_free(ctx);
            return "";
        }

        // Reading Buffer (4KB)
        char buffer[4096];
        while (file.good() && !file.eof()) {
            file.read(buffer, sizeof(buffer));
            std::streamsize bytes_read = file.gcount();
            if (bytes_read > 0) {
                // Updates hash with read bytes
                if (EVP_DigestUpdate(ctx, buffer, bytes_read) != 1) {
                    spdlog::error("Falha ao atualizar hash");
                    EVP_MD_CTX_free(ctx);
                    return "";
                }
            }
        }

        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len;
        if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
            spdlog::error("Falha ao finalizar hash");
            EVP_MD_CTX_free(ctx);
            return "";
        }

        EVP_MD_CTX_free(ctx);

        // Converts bytes array to hexadecimal string
        std::stringstream ss;
        for (unsigned int i = 0; i < hash_len; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return ss.str();
    }

    // Runs through directory and fills JSON object
    bool scan_directory(const fs::path& root, json& files_json) {
        try {
            for (const auto& entry : fs::recursive_directory_iterator(root)) {
                if (fs::is_regular_file(entry)) {
                    fs::path rel_path = fs::relative(entry.path(), root);
                    std::string rel_str = rel_path.string();

                    std::string hash = compute_file_sha256(entry.path());
                    if (hash.empty()) {
                        spdlog::warn("Não foi possível calcular hash para: {}", rel_str);
                        continue;
                    }
                    files_json[rel_str] = hash;
                }
            }
            return true;
        } catch (const fs::filesystem_error& e) {
            spdlog::error("Erro ao percorrer diretório: {}", e.what());
            return false;
        }
    }

public:
    bool generate_baseline(const std::string& root_directory,
                           const std::string& state_file_path) override {
        spdlog::info("Gerando baseline para: {}", root_directory);

        // Verification
        if (!fs::exists(root_directory) || !fs::is_directory(root_directory)) {
            spdlog::error("Diretório raiz não existe ou não é uma pasta: {}", root_directory);
            return false;
        }

        // Creates main JSON object
        json manifest;
        manifest["root"] = root_directory;
        auto now = std::chrono::system_clock::now();
        auto now_seconds = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        manifest["timestamp"] = now_seconds;

        // Archive map (relative path → hash)
        json files_json = json::object();
        if (!scan_directory(root_directory, files_json)) {
            return false;
        }
        manifest["files"] = files_json;

        std::ofstream out_file(state_file_path);
        if (!out_file.is_open()) {
            spdlog::error("Não foi possível abrir o arquivo de estado para escrita: {}", state_file_path);
            return false;
        }

        out_file << manifest.dump(4); 
        out_file.close();

        spdlog::info("Baseline salva com sucesso em: {}", state_file_path);
        spdlog::info("Arquivos processados: {}", files_json.size());

        // Stores in memory for future use
        m_baseline_data = manifest;
        m_root = root_directory;

        return true;
    }

    IntegrityReport verify_integrity(const std::string& root_directory,
                                     const std::string& state_file_path) override {
        IntegrityReport report;
        return report;
    }

    bool load_baseline(const std::string& state_file_path) override {
        std::ifstream in_file(state_file_path);
        if (!in_file.is_open()) {
            spdlog::error("Não foi possível abrir o arquivo de estado: {}", state_file_path);
            return false;
        }
        try {
            in_file >> m_baseline_data;
            m_root = m_baseline_data["root"];
            spdlog::info("Baseline carregada com {} arquivos.", m_baseline_data["files"].size());
            return true;
        } catch (const json::parse_error& e) {
            spdlog::error("Erro ao parsear JSON: {}", e.what());
            return false;
        }
    }
};

// ------------------------------------------------------------
// 2. Factory function
// ------------------------------------------------------------
std::unique_ptr<IFileIntegrityMonitor> create_file_integrity_monitor() {
    return std::make_unique<FileIntegrityMonitor>();
}