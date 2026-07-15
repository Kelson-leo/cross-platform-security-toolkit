#include "IProcessEnumerator.hpp"
#include <spdlog/spdlog.h>
#include <iostream>

int main() {
    spdlog::info("Starting System Monitor v1.0...");

    auto enumerator = create_process_enumerator();
    auto processes = enumerator->enumerate_processes();

    spdlog::info("Found {} running processes.", processes.size());

    for (const auto& proc : processes) {
        std::cout << "PID: " << proc.pid 
                  << " | Name: " << proc.name 
                  << " | RAM: " << proc.memory_usage_kb << " KB" 
                  << std::endl;
    }

    return 0;
}