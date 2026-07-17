cmake_minimum_required(VERSION 3.20)
project(FileIntegrityMonitor VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(spdlog REQUIRED)
find_package(GTest REQUIRED)

add_executable(file_integrity_monitor
    src/main.cpp
    src/FileIntegrityMonitor.cpp
)

target_include_directories(file_integrity_monitor PRIVATE include)

target_link_libraries(file_integrity_monitor
    OpenSSL::Crypto
    spdlog::spdlog
)

enable_testing()
add_executable(test_integrity tests/test_integrity.cpp)
target_link_libraries(test_integrity GTest::gtest_main)
target_include_directories(test_integrity PRIVATE include)
add_test(NAME IntegrityTests COMMAND test_integrity)