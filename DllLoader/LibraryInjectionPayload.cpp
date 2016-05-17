#include "LibraryInjectionPayload.h"
#include "LibraryInjectionPayloadImpl_x86.h"
#include "LibraryInjectionPayloadImpl_x64.h"


using LibraryInjectionPayloadImpl =
#if defined(_WIN64)
LibraryInjectionPayloadImpl_x64;
#elif defined(_WIN32)
LibraryInjectionPayloadImpl_x86;
#else
#error _WIN64 or _WIN32 is not defined
#endif


std::vector<std::vector<uint8_t>> LibraryInjectionPayload::Create(LPVOID remoteLibraryPath, FARPROC loadLibrary, LPVOID remoteIntruderExportName, FARPROC getProcAddress)
{
    return LibraryInjectionPayloadImpl().Create(
        reinterpret_cast<uintptr_t>(remoteLibraryPath),
        reinterpret_cast<uintptr_t>(loadLibrary),
        reinterpret_cast<uintptr_t>(remoteIntruderExportName),
        reinterpret_cast<uintptr_t>(getProcAddress));
}
