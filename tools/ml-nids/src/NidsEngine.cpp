#include "INids.hpp"
#include <spdlog/spdlog.h>
#include <mlpack.hpp>
#include <armadillo>
#include <thread>

class NidsEngine : public INids {
private:
    bool running = false;
    NidsCallback callback;
    mlpack::tree::RandomForest<> model; // Modelo ML
    bool model_loaded = false;

    // Placeholder para captura (sera substituido pelos arquivos platform/)
    void dummy_capture_loop() {
        spdlog::info("Iniciando loop de captura (placeholder)");
        // Simula 5 fluxos de teste
        for (int i = 0; i < 5; ++i) {
            NetworkFlow flow;
            flow.src_ip = "192.168.1.1";
            flow.dst_ip = "8.8.8.8";
            flow.src_port = 54321 + i;
            flow.dst_port = 80 + i;
            flow.protocol = 6; // TCP
            flow.packet_count = 100 + i * 10;
            flow.byte_count = flow.packet_count * 1200;
            flow.src_packet_count = flow.packet_count / 2;
            flow.dst_packet_count = flow.packet_count / 2;
            flow.src_byte_count = flow.byte_count / 2;
            flow.dst_byte_count = flow.byte_count / 2;
            flow.syn_flag = true;
            flow.ack_flag = true;
            flow.fin_flag = false;
            flow.rst_flag = false;
            flow.start_time = std::chrono::steady_clock::now();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            flow.end_time = std::chrono::steady_clock::now();

            auto [label, confidence] = classify_flow(flow);
            NidsAlert alert;
            alert.timestamp = std::chrono::system_clock::now();
            alert.flow = flow;
            alert.classification = label;
            alert.confidence = confidence;
            alert.description = "Fluxo classificado como " + label + " (confianca: " + std::to_string(confidence) + ")";
            if (callback) callback(alert);

            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

public:
    bool start_capture(const std::string& interface, const std::string& filter = "") override {
        if (running) {
            spdlog::warn("Captura ja esta rodando.");
            return false;
        }
        running = true;
        spdlog::info("Iniciando NIDS (placeholder) na interface: {}", interface);
        // Em vez de captura real, chamamos o placeholder
        std::thread([this]() { dummy_capture_loop(); running = false; }).detach();
        return true;
    }

    void stop_capture() override {
        running = false;
        spdlog::info("Parando NIDS");
    }

    bool is_running() const override {
        return running;
    }

    bool load_model(const std::string& model_path) override {
        spdlog::info("Carregando modelo ML de: {}", model_path);
        // Placeholder: cria um modelo dummy (Random Forest com 10 arvores)
        // Em um cenario real, carregariamos de um arquivo.
        // Vamos treinar um modelo simples com dados sinteticos para demonstrar.
        try {
            // Gera dados sinteticos para treino (exemplo)
            arma::mat features(14, 100); // 14 features, 100 amostras
            arma::Row<size_t> labels(100);
            for (size_t i = 0; i < 100; ++i) {
                // Amostras normais (label 0) e maliciosas (label 1)
                labels(i) = (i < 50) ? 0 : 1;
                for (size_t f = 0; f < 15; ++f) {
                    features(f, i) = arma::randn() * (labels(i) == 0 ? 0.5 : 1.5) + (labels(i) == 0 ? 1 : 5);
                }
            }
            // Treina Random Forest com 5 arvores
            model = mlpack::tree::RandomForest<>(features, labels, 2, 5);
            model_loaded = true;
            spdlog::info("Modelo ML treinado com dados sinteticos (placeholder)");
            return true;
        } catch (const std::exception& e) {
            spdlog::error("Falha ao treinar modelo: {}", e.what());
            return false;
        }
    }

    void set_alert_callback(NidsCallback cb) override {
        callback = cb;
    }

    std::vector<double> extract_features(const NetworkFlow& flow) const override {
        return extract_flow_features(flow);
    }

    std::pair<std::string, double> classify_flow(const NetworkFlow& flow) override {
        if (!model_loaded) {
            // Se nao tiver modelo carregado, usa heuristica simples
            if (flow.packet_count > 1000 && flow.duration_seconds() < 5.0) {
                return {"Malicious", 0.9};
            }
            return {"Normal", 0.8};
        }

        // Extrai features e converte para matriz Armadillo
        auto features_vec = extract_features(flow);
        arma::mat features_mat(features_vec.data(), features_vec.size(), 1);

        // Prediz
        arma::Row<size_t> predictions;
        model.Classify(features_mat, predictions);

        // Obtem a probabilidade/confianca (simplificada)
        double confidence = 0.7 + 0.3 * arma::randu(); // Placeholder para confianca

        std::string label = (predictions(0) == 1) ? "Malicious" : "Normal";
        return {label, confidence};
    }
};

// ------------------------------------------------------------
// Factory
// ------------------------------------------------------------
std::unique_ptr<INids> create_nids() {
    spdlog::info("Criando NIDS Engine (ML)");
    return std::make_unique<NidsEngine>();
}
