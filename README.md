# 🛡️ Cross-Platform Security Toolkit

[![Cross-Platform Build & Test](https://github.com/Kelson-leo/cross-platform-security-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/Kelson-leo/cross-platform-security-toolkit/actions/workflows/ci.yml)

> *A modular C++20 toolkit for systems programming and threat detection primitives, designed to run natively on both Windows and Linux.*

## 🎯 Purpose & Philosophy

This repository is my engineering portfolio, demonstrating **modern C++ systems programming** applied to cybersecurity. Unlike typical "toy projects," this toolkit focuses on **cross-platform internals**, low-level OS APIs, and production-grade code organization.

**Why a Monorepo?**
- Showcases software architecture (shared `common/` libraries, independent tools).
- Proves ability to manage CI/CD pipelines for multiple platforms simultaneously.
- Gives recruiters a single entry point to evaluate my full technical range.

## 🧰 Toolkit Components

| Tool | Focus | Tech Stack | Cross-Platform |
| :--- | :--- | :--- | :--- |
| **System Monitor** | Process enumeration & memory tracking | WinAPI (`CreateToolhelp32Snapshot`), Linux `/proc` | ✅ Windows, Linux |
| *Packet Sniffer* (WIP) | Raw network traffic analysis | `libpcap`/WinPcap, TCP/IP parsing | ⚡ Planned |
| *Hybrid Detector* (WIP) | C++/C# Interop & Threat Hooking | P/Invoke, WPF GUI | ⚠️ Windows Native |

*(Check the `/tools` directory for each individual project.)*

## ⚡ Quick Start (No Build Required)

**Want to test without compiling?** Download pre-compiled binaries directly:

1. Go to the [**Actions**](https://github.com/Kelson-leo/cross-platform-security-toolkit/actions) tab
2. Click on the latest workflow run (green ✅)
3. Scroll down to **Artifacts**
4. Download:
   - `system_monitor-linux` (Linux)
   - `system_monitor-windows.exe` (Windows)

**Run:**
```bash
# Linux
./system_monitor

# Windows
system_monitor.exe
```

## 🔧 Build Instructions (The Professional Way)

This project uses **Conan 2.0** + **CMake** with a strict separation of build artifacts.

To compile **System Monitor**:

```bash
cd tools/system-monitor
mkdir -p build && cd build
conan install .. --build=missing -s build_type=Release --output-folder=.
cmake .. -DCMAKE_TOOLCHAIN_FILE=./conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

Run it:

```bash
# Linux
./system_monitor

# Windows
./Release/system_monitor.exe
```

## 📋 Requirements

- **CMake** 3.15+
- **Conan** 2.0+
- **C++20 compiler** (MSVC 2019+, GCC 11+, Clang 13+)
- **Linux**: build-essential, cmake
- **Windows**: Visual Studio Build Tools or MSVC

## 🚀 CI/CD Pipeline

This project features **automated cross-platform builds** via GitHub Actions:
- ✅ Builds on Ubuntu and Windows
- ✅ Runs tests on both platforms
- ✅ Uploads compiled binaries as artifacts for easy access

## 📦 Project Structure

```
cross-platform-security-toolkit/
├── tools/
│   ├── system-monitor/          # Process & memory monitoring tool
│   │   ├── src/
│   │   ├── CMakeLists.txt
│   │   └── conanfile.py
│   └── ...                       # Future tools
├── common/                       # Shared libraries & utilities
├── .github/workflows/            # CI/CD pipelines
└── README.md
```

## 🎓 Learning Resources

This codebase demonstrates:
- **Modern C++20** features (concepts, modules, coroutines)
- **Cross-platform systems programming** (WinAPI, POSIX)
- **Build system mastery** (CMake, Conan)
- **Professional CI/CD** (GitHub Actions)
- **Memory safety** and low-level debugging techniques

## 📝 License

This project is part of my professional portfolio. Feel free to explore and provide feedback!

---

**Questions or interested in discussing the implementation?** Feel free to reach out! 🤝
