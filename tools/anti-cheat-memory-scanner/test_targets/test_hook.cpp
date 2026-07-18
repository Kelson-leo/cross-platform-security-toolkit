/*
 * test_hook.cpp — Target process for testing inline hook detection.
 *
 * Overwrites the first 5 bytes of the libc read() function with a
 * JMP rel32 (0xE9 + offset) that redirects execution to a trampoline
 * allocated near libc (since the main executable is >2GB away from libc
 * on 64-bit Linux, making a direct JMP rel32 impossible).
 *
 * The trampoline performs an absolute jump to fake_read() in the main
 * executable. fake_read() prints a detection message and forwards the
 * call via the raw SYS_read syscall.
 *
 * The anti-cheat scanner detects the 0xE9 byte at the start of read(),
 * flagging it as a potential inline hook.
 *
 * Compile:
 *   g++ -o test_hook test_hook.cpp -ldl
 *
 * Run:
 *   ./test_hook &
 *   sudo ../build/anti_cheat_scanner --scan <PID>
 */

#include <iostream>
#include <cstring>
#include <cstdint>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <dlfcn.h>

// ---------------------------------------------------------------
// Global: address of the real read() — set before installing hook
// ---------------------------------------------------------------
static void* g_read_addr = nullptr;

// ---------------------------------------------------------------
// fake_read — called when the hooked read() is invoked.
// Prints a detection message, then forwards to the real syscall.
// ---------------------------------------------------------------
ssize_t fake_read(int fd, void* buf, size_t count) {
    // Use raw write() syscall for output — no risk of recursion
    static const char msg[] = "[!] Hook detected! — fake_read() called\n";
    syscall(SYS_write, STDERR_FILENO, msg, sizeof(msg) - 1);

    // Forward directly to the kernel via syscall, bypassing libc
    return syscall(SYS_read, fd, buf, count);
}

// ---------------------------------------------------------------
// Build a near trampoline (within 2GB of read) that does an
// absolute jump to fake_read in the main executable.
//
// Layout (16 bytes):
//   48 B8 <64-bit addr>    movabs rax, fake_read
//   FF E0                  jmp rax
// ---------------------------------------------------------------
void build_trampoline(unsigned char* tramp, void* target) {
    tramp[0] = 0x48;  // REX.W
    tramp[1] = 0xB8;  // MOV RAX, imm64
    uintptr_t addr = reinterpret_cast<uintptr_t>(target);
    std::memcpy(&tramp[2], &addr, 8);
    tramp[10] = 0xFF;  // JMP RAX
    tramp[11] = 0xE0;
}

// ---------------------------------------------------------------
// Install inline hook on read():
//   1. Allocate a RWX page near read() via mmap
//   2. Write the absolute-jump trampoline into that page
//   3. Overwrite first 5 bytes of read() with JMP rel32 → trampoline
// ---------------------------------------------------------------
void install_hook(void* target_func, void* hook_func) {
    g_read_addr = target_func;

    // ---- Step 1: allocate a trampoline page near read() ----
    // Try to mmap a page within 2GB before read().
    uintptr_t read_page = reinterpret_cast<uintptr_t>(target_func) & ~0xFFF;

    // Search for a free page going backwards from read() in 16MB steps
    void* tramp_addr = nullptr;
    for (int attempt = 0; attempt < 64; attempt++) {
        uintptr_t hint = read_page - (attempt + 1) * 0x1000000;  // 16MB steps
        tramp_addr = mmap(
            reinterpret_cast<void*>(hint),
            4096,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
            -1, 0
        );
        if (tramp_addr != MAP_FAILED) break;
    }

    if (tramp_addr == MAP_FAILED) {
        std::cerr << "mmap() near libc failed" << std::endl;
        return;
    }

    std::cout << "[+] Trampoline page allocated at: " << tramp_addr << std::endl;

    // ---- Step 2: build the trampoline ----
    build_trampoline(reinterpret_cast<unsigned char*>(tramp_addr), hook_func);

    // ---- Step 3: make read() page writable ----
    if (mprotect(reinterpret_cast<void*>(read_page), 4096,
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        std::cerr << "mprotect() failed: " << std::strerror(errno) << std::endl;
        std::cerr << "Try running with: sudo ./test_hook" << std::endl;
        return;
    }

    // ---- Step 4: write JMP rel32 from read() to trampoline ----
    unsigned char jmp[5];
    jmp[0] = 0xE9;
    int32_t rel_offset = static_cast<int32_t>(
        reinterpret_cast<uintptr_t>(tramp_addr) -
        reinterpret_cast<uintptr_t>(target_func) - 5
    );
    std::memcpy(&jmp[1], &rel_offset, sizeof(rel_offset));

    std::memcpy(target_func, jmp, 5);

    std::cout << "[+] Hook installed on read()" << std::endl;
    std::cout << "[+] JMP offset: " << rel_offset << " bytes" << std::endl;
}

int main() {
    pid_t pid = getpid();

    // ---------------------------------------------------------------
    // 1. Get the real address of read() from libc via dlsym
    // ---------------------------------------------------------------
    void* read_addr = dlsym(RTLD_DEFAULT, "read");
    if (!read_addr) {
        std::cerr << "dlsym(\"read\") failed" << std::endl;
        return 1;
    }

    // ---------------------------------------------------------------
    // 2. Install the inline hook (read -> trampoline -> fake_read)
    // ---------------------------------------------------------------
    install_hook(read_addr, reinterpret_cast<void*>(fake_read));

    // ---------------------------------------------------------------
    // 3. Print diagnostic info
    // ---------------------------------------------------------------
    std::cout << std::endl;
    std::cout << "[+] PID: " << pid << std::endl;
    std::cout << "[+] read() address: " << read_addr << std::endl;
    std::cout << "[+] fake_read() address: " << reinterpret_cast<void*>(fake_read) << std::endl;
    std::cout << "[+] First byte of read(): 0x" << std::hex
              << static_cast<int>(*reinterpret_cast<unsigned char*>(read_addr)) << std::dec << std::endl;
    std::cout << "[!] Process running — scan with:" << std::endl;
    std::cout << "    sudo ../build/anti_cheat_scanner --scan " << pid << std::endl;
    std::cout << std::endl;

    // ---------------------------------------------------------------
    // 4. Loop: periodically call read() so the hook is exercised
    // ---------------------------------------------------------------
    char buf[256];
    while (true) {
        std::cout << "[*] Waiting 3 seconds before next read... (send data or Ctrl+D)" << std::endl;

        // Read from stdin — this goes through hooked read()
        ssize_t n = read(STDIN_FILENO, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            std::cout << "[*] read() returned " << n << " bytes: " << buf;
        } else if (n == 0) {
            std::cout << "[*] EOF on stdin, sleeping..." << std::endl;
            sleep(3);
        } else {
            std::cout << "[*] read() returned error, sleeping..." << std::endl;
            sleep(3);
        }
    }

    return 0;
}
