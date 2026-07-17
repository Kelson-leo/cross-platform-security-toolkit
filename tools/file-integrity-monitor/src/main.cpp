#include "IFileIntegrityMonitor.hpp"
#include <spdlog/spdlog.h>
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    spdlog::info("🚀 File Integrity Monitor - Baseline Generator");

    std::string target_dir = ".";          
    std::string state_file = "baseline.json"; 

    if (argc >= 2) target_dir = argv[1];
    if (argc >= 3) state_file = argv[2];

    spdlog::info("📁 Monitorando diretório: {}", target_dir);
    spdlog::info("💾 Arquivo de estado: {}", state_file);

    auto monitor = create_file_integrity_monitor();
    if (!monitor) {
        spdlog::error("❌ Falha ao criar monitor.");
        return 1;
    }

    if (monitor->generate_baseline(target_dir, state_file)) {
        spdlog::info("✅ Baseline gerada com sucesso em '{}'!", state_file);
        spdlog::info("   Execute 'cat {}' para ver o JSON gerado.", state_file);
        return 0;
    } else {
        spdlog::error("❌ Falha ao gerar baseline.");
        return 1;
    }
}