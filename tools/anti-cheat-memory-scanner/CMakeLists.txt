cmake_minimum_required(VERSION 3.20)
project(AntiCheatMemoryScanner VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(spdlog REQUIRED)
find_package(GTest REQUIRED)

add_executable(anti_cheat_scanner
    src/main.cpp
    src/MemoryScanner.cpp
)

target_include_directories(anti_cheat_scanner PRIVATE include)

if(UNIX)
    target_sources(anti_cheat_scanner PRIVATE platform/linux_scanner.cpp)
elseif(WIN32)
    target_sources(anti_cheat_scanner PRIVATE platform/windows_scanner.cpp)
endif()

target_link_libraries(anti_cheat_scanner
    OpenSSL::Crypto
    spdlog::spdlog
)

if(UNIX)
    target_link_libraries(anti_cheat_scanner ${CMAKE_DL_LIBS})
endif()

# ------------------------------------------------------------
# TESTES
# ------------------------------------------------------------

enable_testing()

add_executable(test_scanner
    tests/test_scanner.cpp
    src/MemoryScanner.cpp
)

if(UNIX)
    target_sources(test_scanner PRIVATE platform/linux_scanner.cpp)
elseif(WIN32)
    target_sources(test_scanner PRIVATE platform/windows_scanner.cpp)
endif()

target_link_libraries(test_scanner
    GTest::gtest_main
    OpenSSL::Crypto
    spdlog::spdlog
)

if(UNIX)
    target_link_libraries(test_scanner ${CMAKE_DL_LIBS})
endif()

target_include_directories(test_scanner PRIVATE include)
add_test(NAME ScannerTests COMMAND test_scanner)