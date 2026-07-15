#include "IPacketCapture.hpp"
#include <spdlog/spdlog.h>
#include <pcap.h>
#include <vector>
#include <string>
#include <cstring>     
#include <chrono>       
#include <algorithm>    

// ------------------------------------------------------------
// 1. Linux Implementation
// ------------------------------------------------------------
class LinuxPcapCapture : public IPacketCapture {
private:
    pcap_t* pcap_handle = nullptr;      
    bool running = false;              
    std::string current_interface;      

    char error_buffer[PCAP_ERRBUF_SIZE];

public:
    LinuxPcapCapture() {
        std::memset(error_buffer, 0, PCAP_ERRBUF_SIZE);
    }
    ~LinuxPcapCapture() override {
        if (pcap_handle) {
            pcap_close(pcap_handle);
            pcap_handle = nullptr;
            running = false;
            spdlog::debug("[Linux] Handle do pcap liberado pelo destrutor.");
        }
    }

    // ------------------------------------------------------------
    // 2. Virtual methods
    // ------------------------------------------------------------

    std::vector<std::string> list_interfaces() override {
        std::vector<std::string> result;
        pcap_if_t* interfaces = nullptr;   
        pcap_if_t* current = nullptr;

        if (pcap_findalldevs(&interfaces, error_buffer) == -1) {
            spdlog::error("[Linux] Falha ao listar interfaces: {}", error_buffer);
            return result;
        }

        for (current = interfaces; current != nullptr; current = current->next) {
            result.emplace_back(current->name);
        }

        pcap_freealldevs(interfaces);
        
        spdlog::info("[Linux] {} interfaces encontradas.", result.size());
        return result;
    }

    bool start_capture(const std::string& interface, 
                       const std::string& filter, 
                       bool promiscuous) override {
        if (running) {
            spdlog::warn("[Linux] Captura já está rodando na interface {}.", current_interface);
            return true;
        }

        std::memset(error_buffer, 0, PCAP_ERRBUF_SIZE);

        pcap_handle = pcap_open_live(interface.c_str(), 65536, promiscuous ? 1 : 0, 1000, error_buffer);

        if (pcap_handle == nullptr) {
            spdlog::error("[Linux] Falha ao abrir interface {}: {}", interface, error_buffer);
            return false;
        }

        // ------------------------------------------------------------
        // 3. BPF filter
        // ------------------------------------------------------------
        if (!filter.empty()) {
            struct bpf_program bpf_code; 
            
            if (pcap_compile(pcap_handle, &bpf_code, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
                spdlog::error("[Linux] Erro ao compilar filtro '{}': {}", filter, pcap_geterr(pcap_handle));
                pcap_close(pcap_handle);
                pcap_handle = nullptr;
                return false;
            }

            if (pcap_setfilter(pcap_handle, &bpf_code) == -1) {
                spdlog::error("[Linux] Erro ao aplicar filtro '{}': {}", filter, pcap_geterr(pcap_handle));
                pcap_freecode(&bpf_code); // Libera a memória do filtro compilado
                pcap_close(pcap_handle);
                pcap_handle = nullptr;
                return false;
            }

            pcap_freecode(&bpf_code);
            spdlog::info("[Linux] Filtro BPF '{}' aplicado com sucesso.", filter);
        }

        running = true;
        current_interface = interface;
        spdlog::info("[Linux] Captura iniciada em {} (Modo promíscuo: {}, Filtro: '{}').", 
                     interface, promiscuous ? "ON" : "OFF", filter.empty() ? "Nenhum" : filter);
        return true;
    }

    void stop_capture() override {
        if (pcap_handle) {
            pcap_breakloop(pcap_handle);
            
            pcap_close(pcap_handle);
            pcap_handle = nullptr;
            running = false;
            spdlog::info("[Linux] Captura parada.");
        } else {
            spdlog::warn("[Linux] Tentativa de parar captura, mas nenhuma estava ativa.");
        }
    }

    bool is_running() const override {
        return running;
    }

    std::unique_ptr<RawPacket> get_next_packet(int timeout_ms) override {
        if (!running || pcap_handle == nullptr) {
            return nullptr;
        }

        // ------------------------------------------------------------
        // 4. Next package capture
        // ------------------------------------------------------------
        struct pcap_pkthdr* header = nullptr;  
        const unsigned char* raw_data = nullptr; 

        int result = pcap_next_ex(pcap_handle, &header, &raw_data);

        if (result == 1) {
            // ------------------------------------------------------------
            // 5. RawPacket
            // ------------------------------------------------------------
            auto packet = std::make_unique<RawPacket>();

            packet->timestamp = std::chrono::steady_clock::time_point(
                std::chrono::microseconds(header->ts.tv_sec * 1'000'000 + header->ts.tv_usec)
            );

            packet->data.assign(raw_data, raw_data + header->caplen);
            packet->length = header->caplen;

            return packet;

        } else if (result == 0) {
            return nullptr;

        } else if (result == -2) {
            spdlog::debug("[Linux] Captura interrompida via pcap_breakloop.");
            return nullptr;

        } else {
            spdlog::error("[Linux] Erro ao capturar pacote: {}", pcap_geterr(pcap_handle));
            return nullptr;
        }
    }
};

// ------------------------------------------------------------
// 6. Factory function (Linux)
// ------------------------------------------------------------
std::unique_ptr<IPacketCapture> create_packet_capture() {
    spdlog::info("[Linux] Criando Packet Sniffer com libpcap.");
    return std::make_unique<LinuxPcapCapture>();
}