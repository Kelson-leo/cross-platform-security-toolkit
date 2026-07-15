#include "IPacketCapture.hpp"
#include <spdlog/spdlog.h>
#include <vector>

class LinuxPcapCapture : public IPacketCapture {
public:
    std::vector<std::string> list_interfaces() override {
        spdlog::info("[Linux] Listando interfaces (placeholder)");
        return {"eth0", "lo", "wlan0"}; 
    }

    bool start_capture(const std::string& interface, const std::string& filter, bool promiscuous) override {
        spdlog::info("[Linux] Iniciando captura em {} (filtro: '{}', promíscuo: {})", interface, filter, promiscuous);
        return true; 
    }

    void stop_capture() override {
        spdlog::info("[Linux] Parando captura");
    }

    bool is_running() const override {
        return true; 
    }

    std::unique_ptr<RawPacket> get_next_packet(int timeout_ms) override {
        return nullptr;
    }
};

std::unique_ptr<IPacketCapture> create_packet_capture() {
    spdlog::info("[Linux] Criando Packet Sniffer (placeholders)");
    return std::make_unique<LinuxPcapCapture>();
}