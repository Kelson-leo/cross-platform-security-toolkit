#pragma once

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <cstdint> 

// ------------------------------------------------------------
// 1. Packate structure (DTO)
// ------------------------------------------------------------
struct RawPacket {
    std::chrono::steady_clock::time_point timestamp; 
    std::vector<uint8_t> data;                       
    size_t length;                                   
};

// ------------------------------------------------------------
// 2. Pure interfaec (Classe Abstrata)
// ------------------------------------------------------------
class IPacketCapture {
public:
    virtual ~IPacketCapture() = default; 

    virtual std::vector<std::string> list_interfaces() = 0;

    virtual bool start_capture(const std::string& interface, 
                               const std::string& filter = "", 
                               bool promiscuous = true) = 0;

    virtual void stop_capture() = 0;

    virtual bool is_running() const = 0; 
    
    virtual std::unique_ptr<RawPacket> get_next_packet(int timeout_ms = 100) = 0;
};

// ------------------------------------------------------------
// 3. Factory function (Right implementation for OS)
// ------------------------------------------------------------
std::unique_ptr<IPacketCapture> create_packet_capture();