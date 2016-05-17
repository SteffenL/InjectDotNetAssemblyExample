#pragma once

#include <vector>
#include <cstdint>

#include <Windows.h>


class LibraryInjectionPayload
{
public:
    static std::vector<std::vector<uint8_t>> Create(LPVOID remoteLibraryPath, FARPROC loadLibrary, LPVOID remoteIntruderExportName, FARPROC getProcAddress);
};
