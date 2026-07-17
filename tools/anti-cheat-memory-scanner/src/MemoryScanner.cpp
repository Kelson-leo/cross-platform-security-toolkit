#include "IMemoryScanner.hpp"
#include <spdlog/spdlog.h>
#include <vector>
#include <string>

#ifdef _WIN32
    #include <windows.h>
    #include <tlhelp32.h>
#else
    #include <unistd.h> 
#endif

class PlaceholderScanner : public IMemoryScanner {
public:
    std::vector<ProcessInfo> list_processes() override {
        spdlog::info("📋 Listando processos (placeholder)");
        
        #ifdef _WIN32
            ProcessInfo self;
            self.pid = GetCurrentProcessId();
            self.name = "placeholder.exe";
            self.executable_path = "C:\\placeholder.exe";
            return { self };
        #else
            ProcessInfo self;
            self.pid = getpid();
            self.name = "placeholder";
            self.executable_path = "/usr/bin/placeholder";
            return { self };
        #endif
    }

    ScanReport scan_process(int pid) override {
        spdlog::info("🔍 Escaneando PID {} (placeholder)", pid);
        ScanReport report;
        report.pid = pid;
        #ifdef _WIN32
            report.process_name = "placeholder.exe";
        #else
            report.process_name = "placeholder";
        #endif
        report.text_section_integrity_ok = true;
        return report;
    }

    bool verify_text_section_integrity(int pid, std::string& out_error) override {
        spdlog::info("🔍 Verificando integridade do PID {} (placeholder)", pid);
        out_error = "";
        return true;
    }
};

std::unique_ptr<IMemoryScanner> create_memory_scanner() {
    spdlog::info("🛠️ Criando Memory Scanner (placeholder)");
    return std::make_unique<PlaceholderScanner>();
}