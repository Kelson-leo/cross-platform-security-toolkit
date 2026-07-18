cmake_minimum_required(VERSION 3.20)
project(MLNids VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(spdlog REQUIRED)
find_package(GTest REQUIRED)
find_package(mlpack REQUIRED)
find_package(Armadillo REQUIRED)
find_package(libpcap REQUIRED)

# Static library with shared core (feature extraction)
add_library(nids_core STATIC
    src/FeatureExtractor.cpp
)
target_include_directories(nids_core PUBLIC include)

# ---- Training utility (generates model file) ----
add_executable(train_model
    src/train_model.cpp
)
target_link_libraries(train_model PRIVATE
    spdlog::spdlog
    mlpack::mlpack
    Armadillo::Armadillo
)

# ---- Main executable (real capture via libpcap) ----
add_executable(ml_nids
    src/main.cpp
)

if(UNIX)
    target_sources(ml_nids PRIVATE platform/linux_capture.cpp)
    message(STATUS "ML-NIDS: Building for Linux with libpcap")
elseif(WIN32)
    target_sources(ml_nids PRIVATE platform/windows_capture.cpp)
    message(STATUS "ML-NIDS: Building for Windows")
endif()

target_link_libraries(ml_nids PRIVATE
    nids_core
    OpenSSL::Crypto
    spdlog::spdlog
    mlpack::mlpack
    Armadillo::Armadillo
    libpcap::libpcap
)

# ---- Tests (dummy engine — no capture dependency) ----
enable_testing()
add_executable(test_nids
    tests/test_nids.cpp
    src/NidsEngine.cpp
)
target_link_libraries(test_nids PRIVATE
    nids_core
    OpenSSL::Crypto
    spdlog::spdlog
    mlpack::mlpack
    Armadillo::Armadillo
    GTest::gtest_main
)
add_test(NAME NidsTests COMMAND test_nids)
