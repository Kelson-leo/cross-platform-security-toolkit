cmake_minimum_required(VERSION 3.20)
project(HybridBackend VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(hybrid_backend SHARED
    src/status_provider.cpp
)

target_include_directories(hybrid_backend PRIVATE include)

target_compile_definitions(hybrid_backend PRIVATE BUILDING_DLL)

if(WIN32)
    target_link_libraries(hybrid_backend
        advapi32   # Para GetUserName
        kernel32   # Para GetVersionEx, CreateToolhelp32Snapshot
    )
endif()

set_target_properties(hybrid_backend PROPERTIES
    PREFIX ""
    SUFFIX ".dll"
)