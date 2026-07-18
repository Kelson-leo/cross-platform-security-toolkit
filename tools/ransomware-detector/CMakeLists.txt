cmake_minimum_required(VERSION 3.20)
project(RansomwareDetector VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(spdlog REQUIRED)
find_package(GTest REQUIRED)

add_executable(ransomware_detector
    src/main.cpp
    src/RansomwareDetector.cpp
)

target_include_directories(ransomware_detector PRIVATE include)

if(UNIX)
    target_sources(ransomware_detector PRIVATE platform/linux_watcher.cpp)
elseif(WIN32)
    target_sources(ransomware_detector PRIVATE platform/windows_watcher.cpp)
endif()

target_link_libraries(ransomware_detector
    OpenSSL::Crypto
    spdlog::spdlog
)

enable_testing()
add_executable(test_detector
    tests/test_detector.cpp
    src/RansomwareDetector.cpp
)

if(UNIX)
    target_sources(test_detector PRIVATE platform/linux_watcher.cpp)
elseif(WIN32)
    target_sources(test_detector PRIVATE platform/windows_watcher.cpp)
endif()

target_link_libraries(test_detector
    GTest::gtest_main
    OpenSSL::Crypto
    spdlog::spdlog
)

target_include_directories(test_detector PRIVATE include)
add_test(NAME DetectorTests COMMAND test_detector)
