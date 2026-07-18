/*
 * test_signature.cpp — Target process for testing signature-based detection.
 *
 * Allocates a RWX memory region via mmap(), writes a known shellcode into it,
 * and keeps the process alive in a loop so the anti-cheat scanner can detect
 * the signature in executable memory.
 *
 * Compile:
 *   g++ -static -no-pie -o test_signature test_signature.cpp
 *
 * Run:
 *   ./test_signature &
 *   sudo ./anti_cheat_scanner --scan <PID>
 */

#include <iostream>
#include <cstring>
#include <cstdint>
#include <unistd.h>
#include <sys/mman.h>

// Classic x86-64 execve("/bin/sh") shellcode (30 bytes)
// The scanner's signature list contains this exact pattern.
const unsigned char shellcode[] = {
    0x48, 0x31, 0xC0, 0x50, 0x48, 0xBB, 0x2F, 0x62, 0x69, 0x6E,
    0x2F, 0x2F, 0x73, 0x68, 0x53, 0x48, 0x89, 0xE7, 0x50, 0x48,
    0x89, 0xE2, 0x57, 0x48, 0x89, 0xE6, 0xB0, 0x3B, 0x0F, 0x05
};
const size_t SHELLCODE_SIZE = sizeof(shellcode);

int main() {
    // ---------------------------------------------------------------
    // 1. Allocate one page of RWX memory (readable, writable, executable)
    // ---------------------------------------------------------------
    const size_t PAGE_SIZE = 4096;
    void* exec_region = mmap(
        nullptr,
        PAGE_SIZE,
        PROT_READ | PROT_WRITE | PROT_EXEC,   // RWX permissions
        MAP_PRIVATE | MAP_ANONYMOUS,           // private anonymous mapping
        -1,                                    // fd (ignored for anonymous)
        0                                      // offset
    );

    if (exec_region == MAP_FAILED) {
        std::cerr << "mmap() failed" << std::endl;
        return 1;
    }

    // ---------------------------------------------------------------
    // 2. Copy shellcode into the RWX region
    // ---------------------------------------------------------------
    std::memcpy(exec_region, shellcode, SHELLCODE_SIZE);

    // ---------------------------------------------------------------
    // 3. Print PID and address so the operator knows what to scan
    // ---------------------------------------------------------------
    pid_t pid = getpid();
    std::cout << "[+] PID: " << pid << std::endl;
    std::cout << "[+] Shellcode at: " << exec_region << std::endl;
    std::cout << "[+] Shellcode size: " << SHELLCODE_SIZE << " bytes" << std::endl;
    std::cout << "[+] Region permissions: RWX" << std::endl;
    std::cout << "[!] Process running — scan with:" << std::endl;
    std::cout << "    sudo ../build/anti_cheat_scanner --scan " << pid << std::endl;
    std::cout << std::endl;

    // ---------------------------------------------------------------
    // 4. Loop forever so the scanner has time to inspect this process
    // ---------------------------------------------------------------
    while (true) {
        sleep(10);
    }

    // Not reached, but clean up anyway
    munmap(exec_region, PAGE_SIZE);
    return 0;
}
