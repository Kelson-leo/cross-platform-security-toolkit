#include "IMemoryScanner.hpp"
#include <spdlog/spdlog.h>
#include <iostream>
#include <string>

void print_usage(const char* prog_name) {
    std::cout << "Uso:\n";
    std::cout << "  " << prog_name << " --list                  # Lista todos os processos\n";
    std::cout << "  " << prog_name << " --scan <PID>            # Escaneia um processo específico\n";
}

int main(int argc, char* argv[]) {
    spdlog::info("🚀 Anti-Cheat Memory Scanner v1.0");

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    auto scanner = create_memory_scanner();
    if (!scanner) {
        spdlog::error("❌ Falha ao criar scanner.");
        return 1;
    }

    std::string mode = argv[1];

    if (mode == "--list") {
        auto processes = scanner->list_processes();
        std::cout << "📋 Processos em execução:\n";
        for (const auto& p : processes) {
            std::cout << "  PID: " << p.pid << " | Nome: " << p.name << "\n";
        }
    } else if (mode == "--scan") {
        if (argc < 3) {
            spdlog::error("❌ Forneça o PID para escanear.");
            return 1;
        }
        int pid = std::stoi(argv[2]);
        spdlog::info("🔍 Escaneando processo PID: {}", pid);
        auto report = scanner->scan_process(pid);
        std::cout << "📊 Relatório:\n";
        std::cout << "  Processo: " << report.process_name << " (PID: " << report.pid << ")\n";
        std::cout << "  Integridade .text: " << (report.text_section_integrity_ok ? "✅ OK" : "🚨 Comprometido!") << "\n";
    } else {
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}