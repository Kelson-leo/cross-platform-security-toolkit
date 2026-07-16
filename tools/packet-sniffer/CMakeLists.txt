cmake_minimum_required(VERSION 3.20)
project(PacketSniffer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(spdlog REQUIRED)
find_package(libpcap REQUIRED)
find_package(GTest REQUIRED)

add_executable(packet_sniffer
    src/main.cpp
)

if(UNIX)
    target_sources(packet_sniffer PRIVATE platform/linux_capture.cpp)
    message(STATUS "PacketSniffer: Building for Linux/Unix")
elseif(WIN32)
    target_sources(packet_sniffer PRIVATE platform/windows_capture.cpp)
    message(STATUS "PacketSniffer: Building for Windows")
else()
    message(FATAL_ERROR "Unsupported OS")
endif()

target_include_directories(packet_sniffer PRIVATE include)

target_link_libraries(packet_sniffer
    spdlog::spdlog
    libpcap::libpcap
)

# ------------------------------------------------------------
# Tests using GTest
# ------------------------------------------------------------
enable_testing()

add_executable(test_packet_sniffer
    tests/test_interface.cpp
)

target_link_libraries(test_packet_sniffer
    GTest::gtest_main
)

target_include_directories(test_packet_sniffer PRIVATE include)

# Registra o teste no CTest
add_test(NAME PacketSnifferTests COMMAND test_packet_sniffer)