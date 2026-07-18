#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <memory>
#include <chrono>

// Estrutura para representar um fluxo de rede (5-tupla + estatisticas)
struct NetworkFlow {
    // Identificacao
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol; // TCP=6, UDP=17, ICMP=1

    // Estatisticas
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
    size_t packet_count;
    size_t byte_count;
    size_t src_packet_count;
    size_t dst_packet_count;
    size_t src_byte_count;
    size_t dst_byte_count;

    // Flags TCP (se for TCP)
    bool syn_flag;
    bool ack_flag;
    bool fin_flag;
    bool rst_flag;

    // Duracao em segundos
    double duration_seconds() const {
        auto duration = end_time - start_time;
        return std::chrono::duration<double>(duration).count();
    }
};

// Estrutura para alerta
struct NidsAlert {
    std::chrono::system_clock::time_point timestamp;
    NetworkFlow flow;
    std::string classification; // "Malicious" ou "Normal"
    double confidence;          // 0.0 a 1.0
    std::string description;
};

// Callback para alertas
using NidsCallback = std::function<void(const NidsAlert&)>;

class INids {
public:
    virtual ~INids() = default;

    // Inicia a captura em uma interface de rede
    virtual bool start_capture(const std::string& interface, const std::string& filter = "") = 0;

    // Para a captura
    virtual void stop_capture() = 0;

    // Verifica se esta capturando
    virtual bool is_running() const = 0;

    // Carrega um modelo ML (Random Forest) de um arquivo
    virtual bool load_model(const std::string& model_path) = 0;

    // Define o callback para alertas
    virtual void set_alert_callback(NidsCallback callback) = 0;

    // Extrai features de um fluxo para um vetor (para o ML)
    virtual std::vector<double> extract_features(const NetworkFlow& flow) const = 0;

    // Classifica um fluxo (retorna label e confianca)
    virtual std::pair<std::string, double> classify_flow(const NetworkFlow& flow) = 0;
};

// Funcao livre para extracao de features (usada por NidsEngine e testes)
std::vector<double> extract_flow_features(const NetworkFlow& flow);

// Factory
std::unique_ptr<INids> create_nids();
