#include <gtest/gtest.h>
#include "INids.hpp"
#include "FeatureExtractor.hpp"
#include <cmath>
#include <thread>
#include <atomic>
#include <csignal>
#include <cstring>
#ifndef _WIN32
#include <unistd.h>
#include <poll.h>
#endif

// Verify feature count is correct (14 features)
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

// Edge case: zero-duration flow should not produce NaN or Inf
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
    flow.end_time = now; // duration = 0

    auto features = extract_flow_features(flow);
    EXPECT_EQ(features.size(), 14);

    // No feature should be NaN or Inf
    for (const auto& f : features) {
        EXPECT_FALSE(std::isnan(f)) << "Feature contains NaN";
        EXPECT_FALSE(std::isinf(f)) << "Feature contains Inf";
    }
}

// UDP flows should have all TCP flags set to zero
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

    // Indices 7-10 (TCP flags) should be zero for UDP
    EXPECT_EQ(features[7], 0.0);  // syn
    EXPECT_EQ(features[8], 0.0);  // ack
    EXPECT_EQ(features[9], 0.0);  // fin
    EXPECT_EQ(features[10], 0.0); // rst
}

// Factory must return a non-null, non-running engine
TEST(NidsFactoryTest, CreateNidsReturnsValidPointer) {
    auto nids = create_nids();
    EXPECT_NE(nids, nullptr);
    EXPECT_FALSE(nids->is_running());
}

// Start/stop cycle should work correctly
TEST(NidsInterfaceTest, StartStopCapture) {
    auto nids = create_nids();
    ASSERT_NE(nids, nullptr);

    nids->load_model("");

    bool started = nids->start_capture("eth0");
    EXPECT_TRUE(started);
    EXPECT_TRUE(nids->is_running());

    // Give the dummy loop time to produce at least one alert
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    nids->stop_capture();
}

// Without a model, heuristic fallback should classify high-rate flows as malicious
TEST(NidsClassificationTest, ClassifyWithoutModel) {
    auto nids = create_nids();
    ASSERT_NE(nids, nullptr);

    NetworkFlow flow;
    flow.packet_count = 2000;
    flow.start_time = std::chrono::steady_clock::now();
    flow.end_time = flow.start_time + std::chrono::seconds(2);

    auto [label, confidence] = nids->classify_flow(flow);
    EXPECT_EQ(label, "Malicious");
    EXPECT_GT(confidence, 0.5);
}

#ifndef _WIN32
// Self-pipe trick: writing to pipe_wr wakes poll() on pipe_rd immediately.
// This is the mechanism that makes Ctrl+C shutdown instant.
// POSIX-only: pipe() and poll() don't exist on Windows.
TEST(ShutdownMechanismTest, SelfPipeWakesPollInstantly) {
    int pfds[2];
    ASSERT_EQ(pipe(pfds), 0);

    struct pollfd pfd;
    pfd.fd = pfds[0];
    pfd.events = POLLIN;

    // Write from a separate thread to simulate signal handler
    std::thread writer([&pfds]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        char b = 1;
        write(pfds[1], &b, 1);
    });

    // poll should return within ~20ms (10ms sleep + write), not 5000ms
    auto start = std::chrono::steady_clock::now();
    int ret = poll(&pfd, 1, 5000);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();

    writer.join();
    close(pfds[0]);
    close(pfds[1]);

    EXPECT_EQ(ret, 1);
    EXPECT_LT(elapsed, 1000); // should wake in <1s, not the full 5s
}

// Verify that atomic flag + poll loop exits cleanly (simulates main loop)
TEST(ShutdownMechanismTest, AtomicFlagPollLoopExitsOnSignal) {
    int pfds[2];
    ASSERT_EQ(pipe(pfds), 0);

    std::atomic<bool> run{true};

    // Simulate signal handler: set flag + write to pipe
    std::thread signal_sim([&pfds, &run]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        run = false;
        char b = 1;
        write(pfds[1], &b, 1);
    });

    // Main loop (same pattern as main.cpp)
    struct pollfd pfd;
    pfd.fd = pfds[0];
    pfd.events = POLLIN;
    int iterations = 0;
    while (run) {
        poll(&pfd, 1, 100);
        iterations++;
    }

    signal_sim.join();
    close(pfds[0]);
    close(pfds[1]);

    EXPECT_LE(iterations, 2); // should exit in 1-2 iterations
}
#endif // _WIN32

// start_capture/stop_capture cycle with the dummy engine must work correctly
TEST(NidsInterfaceTest, MultipleStartStopCycles) {
    auto nids = create_nids();
    ASSERT_NE(nids, nullptr);

    // First cycle
    EXPECT_TRUE(nids->start_capture("lo"));
    EXPECT_TRUE(nids->is_running());
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    nids->stop_capture();

    // Second cycle
    EXPECT_TRUE(nids->start_capture("lo"));
    EXPECT_TRUE(nids->is_running());
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    nids->stop_capture();
}

// Verify that double stop_capture() is safe (idempotent)
TEST(NidsInterfaceTest, DoubleStopIsSafe) {
    auto nids = create_nids();
    ASSERT_NE(nids, nullptr);

    EXPECT_TRUE(nids->start_capture("lo"));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    nids->stop_capture();
    nids->stop_capture(); // second call should be a no-op
    EXPECT_FALSE(nids->is_running());
}

// Total flows of different types are handled correctly by the heuristic
TEST(NidsClassificationTest, NormalFlowClassifiedCorrectly) {
    auto nids = create_nids();
    ASSERT_NE(nids, nullptr);

    NetworkFlow flow;
    flow.packet_count = 10;
    flow.start_time = std::chrono::steady_clock::now();
    flow.end_time = flow.start_time + std::chrono::seconds(60);

    auto [label, confidence] = nids->classify_flow(flow);
    EXPECT_EQ(label, "Normal");
}

// Heuristic fallback classifies high-packet-count short-duration flows as malicious
TEST(TriggerClassificationTest, HighPacketCountIsMalicious) {
    auto nids = create_nids();
    ASSERT_NE(nids, nullptr);

    NetworkFlow flow;
    flow.packet_count = 5000;
    flow.start_time = std::chrono::steady_clock::now();
    flow.end_time = flow.start_time + std::chrono::seconds(1);
    flow.byte_count = flow.packet_count * 64;

    auto [label, confidence] = nids->classify_flow(flow);
    EXPECT_EQ(label, "Malicious");
    EXPECT_GT(confidence, 0.5);
}

// High packet count + short duration: heuristic fallback flags as malicious
TEST(TriggerClassificationTest, HighPacketCountShortDurationIsMalicious) {
    auto nids = create_nids();
    ASSERT_NE(nids, nullptr);

    NetworkFlow flow;
    flow.packet_count = 2000;
    flow.byte_count = 2000 * 1200;
    flow.start_time = std::chrono::steady_clock::now();
    flow.end_time = flow.start_time + std::chrono::seconds(2);

    auto [label, confidence] = nids->classify_flow(flow);
    EXPECT_EQ(label, "Malicious");
    EXPECT_GT(confidence, 0.5);
}

// Normal flows should not trigger false positives
TEST(TriggerClassificationTest, LongDurationLowPacketsIsNormal) {
    auto nids = create_nids();
    ASSERT_NE(nids, nullptr);

    NetworkFlow flow;
    flow.packet_count = 50;
    flow.byte_count = 50 * 256;
    flow.start_time = std::chrono::steady_clock::now();
    flow.end_time = flow.start_time + std::chrono::seconds(120);

    auto [label, confidence] = nids->classify_flow(flow);
    EXPECT_EQ(label, "Normal");
}

// set_config with all 6 parameters must not crash
TEST(TriggerConfigurationTest, SetConfigAllParameters) {
    auto nids = create_nids();
    ASSERT_NE(nids, nullptr);

    // All params = 0 means "use defaults", must not throw
    EXPECT_NO_THROW(nids->set_config(0, 0, 0, 0, 0, 0));

    // Custom values
    EXPECT_NO_THROW(nids->set_config(30, 5, 120, 1000, 1048576, 60));
}

// NetworkFlow must have last_classified field initialized
TEST(NetworkFlowTest, LastClassifiedIsDefaultConstructible) {
    NetworkFlow flow;
    flow.last_classified = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - flow.last_classified).count();
    EXPECT_GE(elapsed, 0);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
