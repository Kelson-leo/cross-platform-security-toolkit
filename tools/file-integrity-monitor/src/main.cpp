#include "IFileIntegrityMonitor.hpp"
#include <spdlog/spdlog.h>
#include <iostream>
#include <string>
#include <cstring>

void print_report(const IntegrityReport& report) {
    std::cout << "\n📊 RELATÓRIO DE INTEGRIDADE:\n";
    std::cout << "============================\n";
    std::cout << "🔍 Arquivos escaneados: " << report.total_files_scanned << "\n";
    std::cout << "✅ Íntegros: " << (report.total_files_scanned - report.modified_files.size() - report.new_files.size()) << "\n";

    if (!report.modified_files.empty()) {
        std::cout << "\n🚨 MODIFICADOS (" << report.modified_files.size() << "):\n";
        for (const auto& f : report.modified_files) {
            std::cout << "  - " << f.path << " (hash: " << f.hash_sha256 << ")\n";
        }
    }

    if (!report.new_files.empty()) {
        std::cout << "\n🆕 NOVOS (" << report.new_files.size() << "):\n";
        for (const auto& f : report.new_files) {
            std::cout << "  - " << f.path << " (hash: " << f.hash_sha256 << ")\n";
        }
    }

    if (!report.missing_files.empty()) {
        std::cout << "\n🚫 AUSENTES (" << report.missing_files.size() << "):\n";
        for (const auto& path : report.missing_files) {
            std::cout << "  - " << path << "\n";
        }
    }

    if (report.modified_files.empty() && report.new_files.empty() && report.missing_files.empty()) {
        std::cout << "\n✅ Nenhuma alteração detectada. Sistema íntegro!\n";
    }
    std::cout << "\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Uso:\n";
        std::cerr << "  Para gerar baseline:   " << argv[0] << " --baseline <diretorio> [arquivo_saida.json]\n";
        std::cerr << "  Para verificar:        " << argv[0] << " --verify <diretorio> <arquivo_baseline.json>\n";
        return 1;
    }

    auto monitor = create_file_integrity_monitor();
    if (!monitor) {
        spdlog::error("❌ Falha ao criar monitor.");
        return 1;
    }

    std::string mode = argv[1];

    if (mode == "--baseline") {
        if (argc < 3) {
            spdlog::error("❌ Forneça o diretório para baseline.");
            return 1;
        }
        std::string target_dir = argv[2];
        std::string state_file = (argc >= 4) ? argv[3] : "baseline.json";

        if (monitor->generate_baseline(target_dir, state_file)) {
            spdlog::info("✅ Baseline gerada com sucesso em '{}'!", state_file);
        } else {
            spdlog::error("❌ Falha ao gerar baseline.");
            return 1;
        }
    } else if (mode == "--verify") {
        if (argc < 4) {
            spdlog::error("❌ Forneça o diretório e o arquivo de baseline.");
            std::cerr << "Uso: " << argv[0] << " --verify <diretorio> <arquivo_baseline.json>\n";
            return 1;
        }
        std::string target_dir = argv[2];
        std::string state_file = argv[3];

        IntegrityReport report = monitor->verify_integrity(target_dir, state_file);
        print_report(report);
    } else {
        spdlog::error("❌ Modo desconhecido: {}. Use --baseline ou --verify.", mode);
        return 1;
    }

    return 0;
}