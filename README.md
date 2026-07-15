# 🛡️ Cross-Platform Security Toolkit

[![Cross-Platform Build & Test](https://github.com/Kelson-leo/cross-platform-security-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/Kelson-leo/cross-platform-security-toolkit/actions/workflows/ci.yml)

> *A modular C++20 toolkit for systems programming and threat detection primitives, designed to run natively on both Windows and Linux.*

## 🎯 Purpose & Philosophy

This repository is my engineering portfolio, demonstrating **modern C++ systems programming** applied to cybersecurity. Unlike typical "toy projects," this toolkit focuses on **cross-platform interoperability**, **low-level OS internals**, and **production-grade build systems** (CMake + Conan 2.0).

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

## 🔧 Build Instructions (The Professional Way)

This project uses **Conan 2.0** + **CMake** with a strict separation of build artifacts.

To compile **System Monitor**:

```bash
cd tools/system-monitor
mkdir -p build && cd build
conan install .. --build=missing -s build_type=Release --output-folder=.
cmake .. -DCMAKE_TOOLCHAIN_FILE=./conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release

Run it:

    Linux: ./system_monitor

    Windows: ./Release/system_monitor.exe