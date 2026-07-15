cmake_minimum_required(VERSION 3.20)
project(SystemMonitor VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Encontra as dependências do Conan
find_package(spdlog REQUIRED)
find_package(GTest REQUIRED)

# Adiciona o executável
add_executable(system_monitor 
    src/main.cpp
    # Aqui vamos adicionar os arquivos .cpp depois
)

# Linka as bibliotecas
target_link_libraries(system_monitor 
    spdlog::spdlog
    ${CONAN_LIBS} # Para futuras libs
)

# Inclui os cabeçalhos da nossa ferramenta
target_include_directories(system_monitor PRIVATE include)