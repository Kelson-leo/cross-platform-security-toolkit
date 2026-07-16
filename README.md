# 🛡️ Cross-Platform Security Toolkit

[![CI Build & Test](https://github.com/Kelson-leo/cross-platform-security-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/Kelson-leo/cross-platform-security-toolkit/actions/workflows/ci.yml)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue?logo=c%2B%2B)](https://en.cppreference.com/w/cpp/20)
[![.NET 8](https://img.shields.io/badge/.NET-8.0-purple?logo=dotnet)](https://dotnet.microsoft.com/en-us/download/dotnet/8.0)
[![License MIT](https://img.shields.io/badge/license-MIT-green)](./LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)]()
[![CMake](https://img.shields.io/badge/CMake-3.20%2B-red?logo=cmake)](https://cmake.org)
[![Conan](https://img.shields.io/badge/Conan-2.x-blue?logo=conan)](https://conan.io)

> *A modular C++20 toolkit for systems programming and threat detection primitives, designed to run natively on both Windows and Linux.*

## 🎯 Purpose & Philosophy

This repository is my engineering portfolio, demonstrating **modern C++ systems programming** applied to cybersecurity. Unlike typical "toy projects," this toolkit focuses on **cross-platform internals**, low-level OS APIs, and production-grade code organization.

**Why a Monorepo?**
- Showcases software architecture (shared `common/` libraries, independent tools).
- Proves ability to manage CI/CD pipelines for multiple platforms simultaneously.
- Single entry point to evaluate technical range.

## 🧰 Toolkit Components

| Tool | Focus | Tech Stack | Cross-Platform |
| :--- | :--- | :--- | :--- |
| **System Monitor** | Process enumeration & memory tracking | WinAPI (`CreateToolhelp32Snapshot`), Linux `/proc` | ✅ Windows, Linux |
| **Packet Sniffer** | Raw network traffic capture & analysis | `libpcap`/WinPcap, TCP/IP parsing | ✅ Windows, Linux |
| **Hybrid Detector** | C++/C# Interop & Threat Hooking | P/Invoke, .NET 8, C++ DLL backend | ⚠️ Windows Native |

*(Check the `/tools` directory for each individual project.)*

## ⚡ Quick Start (No Build Required)

**Want to test without compiling?** Download pre-compiled binaries directly:

1. Go to the [**Actions**](https://github.com/Kelson-leo/cross-platform-security-toolkit/actions) tab
2. Click on the latest workflow run (green ✅)
3. Scroll down to **Artifacts**
4. Download:
   - `linux-binaries` — System Monitor + Packet Sniffer (Linux)
   - `windows-binaries` — System Monitor + Packet Sniffer + Hybrid Detector (Windows)

**Run:**

```bash
# Linux
./system_monitor
sudo ./packet_sniffer    # requires root for packet capture

# Windows (PowerShell)
.\system_monitor.exe
.\packet_sniffer.exe      # run as Administrator
.\HybridDetector.exe      # C# frontend with C++ backend DLL
```

## 🔧 Build Instructions (The Professional Way)

This project uses **Conan 2.0** + **CMake** with a strict separation of build artifacts.

### System Monitor & Packet Sniffer (C++ with Conan)

```bash
cd tools/<tool-name>
mkdir -p build && cd build
conan install .. --build=missing -s build_type=Release --output-folder=.
cmake .. -DCMAKE_TOOLCHAIN_FILE=./conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

### Hybrid Detector (C++ DLL + C# Frontend)

Requires **.NET 8 SDK** and **MSVC** (Windows only).

```bash
# 1. Build the C++ backend DLL
cd tools/hybrid-detector/cpp_backend
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release

# 2. Build and run the C# frontend
cd ../../csharp_frontend
dotnet build -c Release
cp ../cpp_backend/build/Release/hybrid_backend.dll ./bin/Release/net8.0/
dotnet run
```

### Run the executables

```bash
# Linux
./system_monitor
sudo ./packet_sniffer          # requires root

# Windows
./Release/system_monitor.exe
./Release/packet_sniffer.exe   # run as Administrator
./HybridDetector.exe           # from csharp_frontend/bin/Release/net8.0/
```

## 📋 Requirements

- **CMake** 3.20+
- **Conan** 2.0+
- **C++20 compiler** (MSVC 2019+, GCC 11+, Clang 13+)
- **.NET 8 SDK** (Hybrid Detector only, Windows)
- **Linux**: build-essential, cmake, libpcap-dev
- **Windows**: Visual Studio 2022 with C++ workload, Npcap SDK

## 🚀 CI/CD Pipeline

This project features **automated cross-platform builds** via GitHub Actions:
- ✅ Builds on Ubuntu and Windows
- ✅ C++ tools compiled with Conan + CMake (Linux: Makefiles, Windows: MSVC)
- ✅ C# Hybrid Detector built with .NET 8 SDK (Windows only)
- ✅ Runs tests on both platforms
- ✅ Uploads compiled binaries as artifacts for easy access

## 📦 Project Structure

```
cross-platform-security-toolkit/
├── tools/
│   ├── system-monitor/            # Process & memory monitoring
│   │   ├── include/               # IProcessEnumerator interface
│   │   ├── platform/              # linux_enumerator, windows_enumerator
│   │   ├── src/                   # main.cpp
│   │   ├── tests/                 # GTest unit tests
│   │   ├── CMakeLists.txt
│   │   └── conanfile.txt
│   ├── packet-sniffer/            # Raw packet capture & analysis
│   │   ├── include/               # IPacketCapture interface
│   │   ├── platform/              # linux_capture (libpcap), windows_capture (Npcap)
│   │   ├── src/                   # main.cpp
│   │   ├── tests/                 # GTest unit tests
│   │   ├── CMakeLists.txt
│   │   └── conanfile.txt
│   └── hybrid-detector/           # C++/C# interop demo
│       ├── cpp_backend/           # C++ DLL (status provider)
│       │   ├── include/
│       │   ├── src/
│       │   ├── CMakeLists.txt
│       │   └── conanfile.txt
│       └── csharp_frontend/       # .NET 8 console app (P/Invoke)
│           ├── Program.cs
│           └── HybridDetector.csproj
├── common/                        # Shared libraries & utilities
├── .github/workflows/             # CI/CD pipelines
└── README.md
```

## 🎓 Learning Resources

This codebase demonstrates:
- **Modern C++20** — concepts, smart pointers, RAII, STL algorithms
- **Cross-platform systems programming** — WinAPI (`CreateToolhelp32Snapshot`, `GetVersionEx`), Linux (`/proc`, `libpcap`)
- **Multi-language interop** — C++ DLL + C# P/Invoke (`[DllImport]`)
- **Build system mastery** — CMake 3.20+, Conan 2.x, Visual Studio generator
- **Professional CI/CD** — GitHub Actions with OS-specific build matrices
- **Memory safety** — RAII wrappers for OS handles (`CloseHandle`, `pcap_close`)

## 📝 License

MIT © 2026 [Kellow101](https://github.com/Kelson-leo)
