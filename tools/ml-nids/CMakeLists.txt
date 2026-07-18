cmake_minimum_required(VERSION 3.20)
project(MLNids VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(spdlog REQUIRED)
find_package(GTest REQUIRED)
find_package(mlpack REQUIRED)
find_package(Armadillo REQUIRED)

# Biblioteca estatica com o core do NIDS (compartilhada entre binario e testes)
add_library(nids_core STATIC
    src/NidsEngine.cpp
    src/FeatureExtractor.cpp
)

target_include_directories(nids_core PUBLIC include)
target_link_libraries(nids_core PUBLIC
    OpenSSL::Crypto
    spdlog::spdlog
    mlpack::mlpack
    Armadillo::Armadillo
)

if(UNIX)
    target_sources(nids_core PRIVATE platform/linux_capture.cpp)
elseif(WIN32)
    target_sources(nids_core PRIVATE platform/windows_capture.cpp)
endif()

# Executavel principal
add_executable(ml_nids src/main.cpp)
target_link_libraries(ml_nids PRIVATE nids_core)

# Testes
enable_testing()
add_executable(test_nids tests/test_nids.cpp)
target_link_libraries(test_nids PRIVATE nids_core GTest::gtest_main)
add_test(NAME NidsTests COMMAND test_nids)
