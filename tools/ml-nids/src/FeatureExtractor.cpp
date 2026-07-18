#include "INids.hpp"
#include <spdlog/spdlog.h>
#include <cmath>

// ------------------------------------------------------------
// Funcao para extrair features numericas de um fluxo
// ------------------------------------------------------------
std::vector<double> extract_flow_features(const NetworkFlow& flow) {
    std::vector<double> features;

    // 1. Duracao (em segundos)
    features.push_back(flow.duration_seconds());

    // 2. Numero total de pacotes (log scale para normalizar)
    features.push_back(std::log1p(flow.packet_count));

    // 3. Numero total de bytes (log scale)
    features.push_back(std::log1p(flow.byte_count));

    // 4. Razao de pacotes origem/destino (src_packets / (dst_packets + 1))
    features.push_back(static_cast<double>(flow.src_packet_count) / (flow.dst_packet_count + 1));

    // 5. Razao de bytes origem/destino
    features.push_back(static_cast<double>(flow.src_byte_count) / (flow.dst_byte_count + 1));

    // 6. Taxa de pacotes por segundo (packets / duration)
    double duration = flow.duration_seconds();
    features.push_back(duration > 0 ? flow.packet_count / duration : 0.0);

    // 7. Tamanho medio do pacote (bytes / packets)
    features.push_back(flow.packet_count > 0 ? flow.byte_count / flow.packet_count : 0.0);

    // 8. Flags TCP (se for TCP)
    if (flow.protocol == 6) { // TCP
        features.push_back(flow.syn_flag ? 1.0 : 0.0);
        features.push_back(flow.ack_flag ? 1.0 : 0.0);
        features.push_back(flow.fin_flag ? 1.0 : 0.0);
        features.push_back(flow.rst_flag ? 1.0 : 0.0);
    } else {
        // Para UDP/ICMP, preenche com 0
        features.push_back(0.0); // syn
        features.push_back(0.0); // ack
        features.push_back(0.0); // fin
        features.push_back(0.0); // rst
    }

    // 9. Protocolo (one-hot encoding simplificado)
    if (flow.protocol == 6) {
        features.push_back(1.0); // TCP
        features.push_back(0.0); // UDP
        features.push_back(0.0); // ICMP
    } else if (flow.protocol == 17) {
        features.push_back(0.0);
        features.push_back(1.0);
        features.push_back(0.0);
    } else if (flow.protocol == 1) {
        features.push_back(0.0);
        features.push_back(0.0);
        features.push_back(1.0);
    } else {
        features.push_back(0.0);
        features.push_back(0.0);
        features.push_back(0.0);
    }

    // Total de features: 14
    return features;
}
