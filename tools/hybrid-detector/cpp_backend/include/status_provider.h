#pragma once

#ifdef _WIN32
    #ifdef BUILDING_DLL
        #define EXPORT_API __declspec(dllexport)
    #else
        #define EXPORT_API __declspec(dllimport)
    #endif
#else
    #define EXPORT_API 
#endif

extern "C" EXPORT_API const char* get_system_status();