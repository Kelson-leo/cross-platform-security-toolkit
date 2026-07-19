#include "status_provider.h"
#include <cstring>
#include <string>

#ifdef _WIN32
    #include <windows.h>
    #include <tlhelp32.h>   // CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First/Next
    #include <lmcons.h>      // GetUserNameA, UNLEN
#else
    #include <unistd.h>
    #include <pwd.h>
#endif

static std::string g_status_buffer;

extern "C" EXPORT_API const char* get_system_status() {
    std::string result;
    
    #ifdef _WIN32
        char username[UNLEN + 1];
        DWORD size = UNLEN + 1;
        if (GetUserNameA(username, &size)) {
            result += "Usuário: ";
            result += username;
            result += "\n";
        } else {
            result += "Usuário: Desconhecido\n";
        }

        OSVERSIONINFOEXA osvi = { sizeof(osvi), 0, 0, 0, 0, {0} };
        if (GetVersionExA((OSVERSIONINFOA*)&osvi)) {
            result += "Versão Windows: ";
            result += std::to_string(osvi.dwMajorVersion) + ".";
            result += std::to_string(osvi.dwMinorVersion) + " (Build ";
            result += std::to_string(osvi.dwBuildNumber) + ")\n";
        }

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 entry;
            entry.dwSize = sizeof(PROCESSENTRY32);
            int count = 0;
            if (Process32First(snapshot, &entry)) {
                do { count++; } while (Process32Next(snapshot, &entry));
            }
            CloseHandle(snapshot);
            result += "Processos em execução: ";
            result += std::to_string(count);
            result += "\n";
        }
    #else
        struct passwd *pw = getpwuid(getuid());
        if (pw) {
            result += "Usuário: ";
            result += pw->pw_name;
            result += "\n";
        }
        result += "Sistema: Linux/Unix (simulado)\n";
    #endif

    g_status_buffer = result;
    return g_status_buffer.c_str();
}