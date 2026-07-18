#include <gtest/gtest.h>
#include "INids.hpp"
#include <cmath>
#include <thread>

// Testa feature extraction
TEST(FeatureExtractorTest, ExtractsCorrectNumberOfFeatures) {
    NetworkFlow flow;
    flow.src_ip = "192.168.1.1";
    flow.dst_ip = "10.0.0.1";
    flow.src_port = 12345;
    flow.dst_port = 80;
    flow.protocol = 6; // TCP
    flow.packet_count = 100;
    flow.byte_count = 120000;
    flow.src_packet_count = 50;
    flow.dst_packet_count = 50;
    flow.src_byte_count = 60000;
    flow.dst_byte_count = 60000;
    flow.syn_flag = true;
    flow.ack_flag = true;
    flow.fin_flag = false;
    flow.rst_flag = false;
    flow.start_time = std::chrono::steady_clock::now();
    flow.end_time = flow.start_time + std::chrono::seconds(10);

    auto features = extract_flow_features(flow);
    EXPECT_EQ(features.size(), 14);
}

// Testa duracao zero (edge case)
TEST(FeatureExtractorTest, ZeroDurationDoesNotCrash) {
    NetworkFlow flow;
    flow.protocol = 6;
    flow.packet_count = 0;
    flow.byte_count = 0;
    flow.src_packet_count = 0;
    flow.dst_packet_count = 0;
    flow.src_byte_count = 0;
    flow.dst_byte_count = 0;
    flow.syn_flag = false;
    flow.ack_flag = false;
    flow.fin_flag = false;
    flow.rst_flag = false;
    auto now = std::chrono::steady_clock::now();
    flow.start_time = now;
    flow.end_time = now; // duracao = 0

    auto features = extract_flow_features(flow);
    EXPECT_EQ(features.size(), 14);

    // Nenhum feature deve ser NaN ou Inf
    for (const auto& f : features) {
        EXPECT_FALSE(std::isnan(f)) << "Feature contem NaN";
        EXPECT_FALSE(std::isinf(f)) << "Feature contem Inf";
    }
}

// Testa protocolo UDP (sem flags TCP)
TEST(FeatureExtractorTest, UdpFlowHasZeroTcpFlags) {
    NetworkFlow flow;
    flow.protocol = 17; // UDP
    flow.packet_count = 50;
    flow.byte_count = 50000;
    flow.src_packet_count = 25;
    flow.dst_packet_count = 25;
    flow.src_byte_count = 25000;
    flow.dst_byte_count = 25000;
    flow.syn_flag = false;
    flow.ack_flag = false;
    flow.fin_flag = false;
    flow.rst_flag = false;
    auto now = std::chrono::steady_clock::now();
    flow.start_time = now;
    flow.end_time = now + std::chrono::seconds(5);

    auto features = extract_flow_features(flow);
    EXPECT_EQ(features.size(), 14);

    // Features 8-11 (indices 7-10) devem ser zero para UDP
    EXPECT_EQ(features[7], 0.0); // syn
    EXPECT_EQ(features[8], 0.0); // ack
    EXPECT_EQ(features[9], 0.0); // fin
    EXPECT_EQ(features[10], 0.0); // rst
}

// Testa factory
TEST(NidsFactoryTest, CreateNidsReturnsValidPointer) {
    auto nids = create_nids();
    EXPECT_NE(nids, nullptr);
    EXPECT_FALSE(nids->is_running());
}

// Testa interface basica
TEST(NidsInterfaceTest, StartStopCapture) {
    auto nids = create_nids();
    ASSERT_NE(nids, nullptr);

    // Carrega modelo primeiro
    nids->load_model("");

    bool started = nids->start_capture("eth0");
    EXPECT_TRUE(started);
    EXPECT_TRUE(nids->is_running());

    // Espera um pouco
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    nids->stop_capture();
    // Nota: a thread detachada pode ainda estar rodando
}

// Testa classificacao sem modelo (heuristica fallback)
TEST(NidsClassificationTest, ClassifyWithoutModel) {
    auto nids = create_nids();
    ASSERT_NE(nids, nullptr);

    NetworkFlow flow;
    flow.packet_count = 2000;
    flow.start_time = std::chrono::steady_clock::now();
    flow.end_time = flow.start_time + std::chrono::seconds(2);

    auto [label, confidence] = nids->classify_flow(flow);
    // Sem modelo, deve cair na heuristica
    EXPECT_EQ(label, "Malicious");
    EXPECT_GT(confidence, 0.5);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
