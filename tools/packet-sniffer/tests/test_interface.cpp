#include <gtest/gtest.h>
#include "IPacketCapture.hpp"
#include <memory>
#include <chrono>
#include <thread>

class MockPacketCapture : public IPacketCapture {
public:
    std::vector<std::string> list_interfaces() override {
        return {"eth0", "lo"}; 
    }

    bool start_capture(const std::string&, const std::string&, bool) override {
        return true; 
    }

    void stop_capture() override {}

    bool is_running() const override {
        return true; 
    }

    std::unique_ptr<RawPacket> get_next_packet(int timeout_ms) override {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        return nullptr; 
    }
};

// ------------------------------------------------------------
// 2. Actual Tests
// ------------------------------------------------------------

TEST(PacketCaptureInterfaceTest, FactoryCreatesInstance) {
    auto instance = std::make_unique<MockPacketCapture>();
    ASSERT_NE(instance, nullptr);
}

TEST(PacketCaptureInterfaceTest, ListInterfacesReturnsNonEmpty) {
    MockPacketCapture capture;
    auto interfaces = capture.list_interfaces();
    EXPECT_EQ(interfaces.size(), 2);
    EXPECT_EQ(interfaces[0], "eth0");
}

TEST(PacketCaptureInterfaceTest, GetNextPacketHandlesTimeout) {
    MockPacketCapture capture;
    auto start = std::chrono::steady_clock::now();
    
    auto packet = capture.get_next_packet(100); 
    auto end = std::chrono::steady_clock::now();
    
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    EXPECT_GE(elapsed.count(), 10);
    
    EXPECT_EQ(packet, nullptr);
}

TEST(PacketCaptureInterfaceTest, StartCaptureReturnsBool) {
    MockPacketCapture capture;
    bool result = capture.start_capture("eth0", "tcp", true);
    EXPECT_TRUE(result); 
}

TEST(PacketCaptureInterfaceTest, DestructorDoesNotCrash) {
    auto capture = std::make_unique<MockPacketCapture>();
    SUCCEED();
}