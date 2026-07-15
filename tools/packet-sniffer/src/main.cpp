#include "IPacketCapture.hpp"
#include <spdlog/spdlog.h>
#include <iostream>
#include <iomanip>

void print_packet_hex(const RawPacket& packet) {
    std::cout << "[Pacote] Tamanho: " << packet.length << " bytes. Timestamp: ...\n";
    std::cout << "Dados (primeiros 32 bytes): ";
    size_t count = 0;
    for (uint8_t byte : packet.data) {
        if (count >= 32) break;
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
        count++;
    }
    std::cout << std::dec << "\n\n"; 
}

int main() {
    spdlog::info("🚀 Iniciando Packet Sniffer v1.0 (Cross-Platform)");

    auto sniffer = create_packet_capture();
    if (!sniffer) {
        spdlog::error("Falha ao criar o sniffer!");
        return 1;
    }

    spdlog::info("Procurando interfaces de rede...");
    auto interfaces = sniffer->list_interfaces();
    if (interfaces.empty()) {
        spdlog::error("Nenhuma interface de rede encontrada! (Precisa de permissão root?)");
        return 1;
    }

    spdlog::info("Interfaces disponíveis:");
    for (const auto& iface : interfaces) {
        std::cout << "  - " << iface << std::endl;
    }

    std::string chosen_iface = interfaces[0];
    spdlog::info("Capturando na interface: {}", chosen_iface);

    if (!sniffer->start_capture(chosen_iface, "tcp", true)) {
        spdlog::error("Falha ao iniciar captura!");
        return 1;
    }

    spdlog::info("Captura iniciada! Pressione Ctrl+C para parar...");
    spdlog::info("Capturando 10 pacotes para demonstração...");

    int packet_count = 0;
    while (packet_count < 10 && sniffer->is_running()) {
        auto packet = sniffer->get_next_packet(100);
        
        if (packet) {
            packet_count++;
            print_packet_hex(*packet);
        } else {
            // Timeout: nenhum pacote chegou nesse milissegundo, mas continuamos.
            // Isso é bom para não travar o programa.
            // std::cout << "." << std::flush; // (Comentado para não poluir)
        }
    }

    sniffer->stop_capture();
    spdlog::info("✅ Captura finalizada. {} pacotes recebidos.", packet_count);

    return 0;
}