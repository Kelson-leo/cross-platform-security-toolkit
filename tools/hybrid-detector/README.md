# 🧩 Hybrid Detector (C++ + C# Interop)

## 🎯 Purpose

This project is designed to demonstrate **multi-language interoperability** in a real-world cybersecurity context. 

- **C++ Backend (DLL)**: Handles low-level system calls (process enumeration, OS version detection) with maximum performance.
- **C# Frontend (Console)**: Consumes the C++ DLL via **P/Invoke** to display system status in a user-friendly interface.

**Why this matters for Security Engineering**:  
Modern security tools (like NordVPN's Threat Protection) often use C++ for performance-critical tasks (packet filtering, encryption, hooking) and C#/Swift for the user interface and integration layers. Mastering this bridge is essential for cross-platform and enterprise-grade security development.

---

## 🏗️ Architecture

```text
┌─────────────────┐      P/Invoke      ┌─────────────────────┐
│   C# Frontend   │ ◄─────────────────► │  C++ Backend (DLL)  │
│  (Console App)  │                     │  (System Internals)  │
└─────────────────┘                     └─────────────────────┘
        ▲                                           ▲
        │                                           │
        └────────────── .NET 8 ─────────────────────┘


🔧 How to Build
Prerequisites

    C++ Compiler: MSVC (Windows) or MinGW (Linux cross-compile).

    .NET 8 SDK: Required to build and run the C# project.

1. Build the C++ DLL

Windows (MSVC):
bash

cd cpp_backend
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
# The DLL will be in build/Release/hybrid_backend.dll

Linux (Cross-compile for Windows):
bash

cd cpp_backend
x86_64-w64-mingw32-g++ -shared -o hybrid_backend.dll src/status_provider.cpp -I./include

2. Build and Run the C# Frontend
bash

cd csharp_frontend
dotnet build
dotnet run

(Note: On Linux, the DLL won't load. Run this on Windows or use Wine for full testing.)