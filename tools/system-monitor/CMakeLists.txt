cmake_minimum_required(VERSION 3.20)
project(SystemMonitor VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Encontra as dependências do Conan (spdlog, gtest)
find_package(spdlog REQUIRED)
find_package(GTest REQUIRED)

# Cria o executável principal
add_executable(system_monitor
    src/main.cpp
)

# --- MÁGICA DO CROSS-PLATFORM: Adiciona o .cpp certo baseado no SO ---
if(UNIX)  # Isso cobre Linux, macOS, BSD, etc.
    target_sources(system_monitor PRIVATE platform/linux_enumerator.cpp)
    message(STATUS "Building for Linux/Unix platform")
elseif(WIN32)  # Windows
    target_sources(system_monitor PRIVATE platform/windows_enumerator.cpp)
    message(STATUS "Building for Windows platform")
else()
    message(FATAL_ERROR "Plataforma não suportada!")
endif()

# Linka as bibliotecas
target_link_libraries(system_monitor 
    spdlog::spdlog
)

# Inclui os cabeçalhos
target_include_directories(system_monitor PRIVATE include)