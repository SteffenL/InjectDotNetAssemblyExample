#include <cassert>
#include <string>
#include <filesystem>
#include <stdexcept>
#include <iostream>
#include <vector>
#include <sstream>
#include <type_traits>

#include <Windows.h>


class LibraryInjectionPayloadImpl_x86
{
public:
    std::vector<std::vector<uint8_t>> Create(uint32_t remoteLibraryPath, uint32_t loadLibrary, uint32_t remoteIntruderExportName, uint32_t getProcAddress) const
    {
        return {
            // Prologue
            { 0x55 }, // push ebp
            { 0x89, 0xe5 }, // mov ebp, esp

            // Load intruder library
            asm_push_value(remoteLibraryPath),
            asm_mov_eax_value(loadLibrary),
            { 0xff, 0xd0 }, // call eax

            // Get address of intruder exported function
            // Intruder export name
            asm_push_value(remoteIntruderExportName),
            // Intruder module handle
            { 0x50 }, // push eax
            asm_mov_eax_value(getProcAddress),
            { 0xff, 0xd0 }, // call eax
            // Call exported function
            { 0xff, 0xd0 }, // call eax

            // Epilogue
            { 0x89, 0xec }, // mov esp, ebp
            { 0x5d }, // pop ebp
            { 0xc3 } // ret
        };
    }

private:
    std::vector<uint8_t> asm_push_value(uint32_t value) const
    {
        std::vector<uint8_t> data;
        data.resize(1 + sizeof(value));
        data[0] = 0x68;
        *(decltype(value)*)&data[1] = value;
        return data;
    }

    std::vector<uint8_t> asm_mov_eax_value(uint32_t value) const
    {
        std::vector<uint8_t> data;
        data.resize(1 + sizeof(value));
        data[0] = 0xb8;
        *(decltype(value)*)&data[1] = value;
        return data;
    }
};


class LibraryInjectionPayloadImpl_x64
{
public:
    std::vector<std::vector<uint8_t>> Create(uint64_t remoteLibraryPath, uint64_t loadLibrary, uint64_t remoteIntruderExportName, uint64_t getProcAddress) const
    {
        return {
            // Prologue
            { 0x55 }, // push rbp
            { 0x48, 0x89, 0xe5 }, // mov rbp, rsp
            { 0x48, 0x83, 0xec, stackBytesToReserve }, // sub rsp, bytes

            // Load intruder library
            asm_movabs_rcx_value(remoteLibraryPath),
            asm_movabs_rax_value(loadLibrary),
            { 0xff, 0xd0 }, // call rax

            // Get address of intruder exported function
            // Intruder module handle
            { 0x48, 0x89, 0xc1 }, // mov rcx, rax
            // Intruder export name
            asm_movabs_rdx_value(remoteIntruderExportName),
            asm_movabs_rax_value(getProcAddress),
            { 0xff, 0xd0 }, // call rax

            // Call exported function
            { 0xff, 0xd0 }, // call rax

            // Epilogue
            { 0x48, 0x89, 0xec }, // mov rsp, rbp
            { 0x5d }, // pop rbp
            { 0xc3 } // ret
        };
    }

private:
    // We reserve the stack space for the functions we call.
    // The minimum space is 32 bytes (4 x 64-bit values).
    // As none of the functions we call use more than 4, we reserve the minimum space.
    const uint8_t stackBytesToReserve = sizeof(uint64_t) * 4;

    std::vector<uint8_t> asm_movabs_rcx_value(uint64_t value) const
    {
        std::vector<uint8_t> data;
        data.resize(2 + sizeof(value));
        data[0] = 0x48;
        data[1] = 0xb9;
        *(decltype(value)*)&data[2] = value;
        return data;
    }

    std::vector<uint8_t> asm_movabs_rdx_value(uint64_t value) const
    {
        std::vector<uint8_t> data;
        data.resize(2 + sizeof(value));
        data[0] = 0x48;
        data[1] = 0xba;
        *(decltype(value)*)&data[2] = value;
        return data;
    }

    std::vector<uint8_t> asm_mov_r8_value(uint64_t value) const
    {
        std::vector<uint8_t> data;
        data.resize(2 + sizeof(value));
        data[0] = 0x49;
        data[1] = 0xb8;
        *(decltype(value)*)&data[2] = value;
        return data;
    }

    std::vector<uint8_t> asm_mov_r9_value(uint64_t value) const
    {
        std::vector<uint8_t> data;
        data.resize(2 + sizeof(value));
        data[0] = 0x49;
        data[1] = 0xb9;
        *(decltype(value)*)&data[2] = value;
        return data;
    }

    std::vector<uint8_t> asm_movabs_rax_value(uint64_t value) const
    {
        std::vector<uint8_t> data;
        data.resize(2 + sizeof(value));
        data[0] = 0x48;
        data[1] = 0xb8;
        *(decltype(value)*)&data[2] = value;
        return data;
    }
};

using LibraryInjectionPayloadImpl =
#if defined(_WIN64)
LibraryInjectionPayloadImpl_x64;
#elif defined(_WIN32)
LibraryInjectionPayloadImpl_x86;
#else
#error _WIN64 or _WIN32 is not defined
#endif

class LibraryInjectionPayload
{
public:
    static std::vector<std::vector<uint8_t>> Create(LPVOID remoteLibraryPath, FARPROC loadLibrary, LPVOID remoteIntruderExportName, FARPROC getProcAddress)
    {
        return LibraryInjectionPayloadImpl().Create(
            reinterpret_cast<uintptr_t>(remoteLibraryPath),
            reinterpret_cast<uintptr_t>(loadLibrary),
            reinterpret_cast<uintptr_t>(remoteIntruderExportName),
            reinterpret_cast<uintptr_t>(getProcAddress));
    }
};


bool createSuspendedProcess(PROCESS_INFORMATION& pi, const std::string& exePath)
{
    std::wstring exePath_w = std::experimental::filesystem::u8path(exePath).wstring();
    WCHAR exePath_c[MAX_PATH]{ 0 };
    memcpy(exePath_c, exePath_w.data(), exePath_w.size() * sizeof(exePath_w[0]));

    STARTUPINFOW si{ 0 };
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    if (!CreateProcessW(exePath_c, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        //throw std::runtime_error("Failed to create process");
        return false;
    }

    return true;
}

std::string getExeDir()
{
    WCHAR exePath[MAX_PATH]{ 0 };
    GetModuleFileNameW(0, exePath, sizeof(exePath));
    return std::experimental::filesystem::path(exePath).u8string();
}

bool injectLibrary(HANDLE process, const std::string& libraryPath)
{
    if (libraryPath.empty()) {
        throw std::logic_error("Library path must not be empty");
    }

    std::wstring libraryPath_w = std::experimental::filesystem::u8path(libraryPath).wstring();
    libraryPath_w.append(1, L'\0');

    LPVOID remotePayload = NULL;
    LPVOID remoteLibraryPath = NULL;
    LPVOID remoteIntruderExportName = NULL;
    HANDLE thread = NULL;

    bool success = false;

    do {
        auto loadLibraryAddress = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
        if (!loadLibraryAddress) {
            //throw std::runtime_error("Failed to get address of LoadLibraryW.");
            break;
        }

        auto getProcAddressAddress = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetProcAddress");
        if (!getProcAddressAddress) {
            //throw std::runtime_error("Failed to get address of GetProcAddress.");
            break;
        }

        // Write library path

        auto sizeOfLibraryPath = libraryPath_w.size() * sizeof(decltype(libraryPath_w)::value_type);
        remoteLibraryPath = VirtualAllocEx(process, NULL, sizeOfLibraryPath, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!remoteLibraryPath) {
            //throw std::runtime_error("Failed to allocate memory for library path in remote process.");
            break;
        }

        if (!WriteProcessMemory(process, remoteLibraryPath, libraryPath_w.data(), sizeOfLibraryPath, NULL)) {
            //throw std::runtime_error("Failed to write library path in remote process.");
            break;
        }

        // Write function name exported from intruder

        std::string intruderExportName = "Startup";
        intruderExportName.append(1, '\0');
        auto sizeOfIntruderExportName = intruderExportName.size() * sizeof(decltype(intruderExportName)::value_type);
        remoteIntruderExportName = VirtualAllocEx(process, NULL, sizeOfIntruderExportName, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!remoteIntruderExportName) {
            //throw std::runtime_error("Failed to allocate memory for library path in remote process.");
            break;
        }

        if (!WriteProcessMemory(process, remoteIntruderExportName, intruderExportName.data(), sizeOfIntruderExportName, NULL)) {
            //throw std::runtime_error("Failed to write library path in remote process.");
            break;
        }

        // Write payload
        auto payloadLines = LibraryInjectionPayload::Create(remoteLibraryPath, loadLibraryAddress, remoteIntruderExportName, getProcAddressAddress);

        std::stringstream payloadStream;
        for (const auto& data : payloadLines) {
            payloadStream.write(reinterpret_cast<const char*>(data.data()), data.size());
        }

        auto payload = payloadStream.str();
        auto sizeOfPayload = payload.size() * sizeof(decltype(payload)::value_type);

        remotePayload = VirtualAllocEx(process, NULL, sizeOfPayload, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!remotePayload) {
            //throw std::runtime_error("Failed to allocate memory for payload in remote process.");
            break;
        }

        if (!WriteProcessMemory(process, remotePayload, payload.data(), sizeOfPayload, NULL)) {
            //throw std::runtime_error("Failed to write payload in remote process.");
            break;
        }

        FlushInstructionCache(process, remotePayload, sizeOfPayload);

        // Execute payload

        thread = CreateRemoteThread(process, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(remotePayload), NULL, 0, NULL);
        if (!thread) {
            //throw std::runtime_error("Failed to create remote thread.");
            break;
        }

        if (WaitForSingleObject(thread, INFINITE) == WAIT_FAILED) {
            //throw std::runtime_error("Failed to wait for remote thread execution to complete.");
            break;
        }

        success = true;
    } while (0);

    if (thread) {
        CloseHandle(thread);
        thread = NULL;
    }

    if (remotePayload) {
        VirtualFreeEx(process, remotePayload, 0, MEM_RELEASE);
        remotePayload = NULL;
    }

    if (remoteIntruderExportName) {
        VirtualFreeEx(process, remoteIntruderExportName, 0, MEM_RELEASE);
        remoteIntruderExportName = NULL;
    }

    if (remoteLibraryPath) {
        VirtualFreeEx(process, remoteLibraryPath, 0, MEM_RELEASE);
        remoteLibraryPath = NULL;
    }

    return success;
}

std::string getHostExePath()
{
    auto path = std::experimental::filesystem::u8path(getExeDir());
    path.replace_filename("NativeHost.exe");
    return path.u8string();
}

std::string getInjectedLibraryPath()
{
    auto path = std::experimental::filesystem::u8path(getExeDir());
    path.replace_filename("NativeIntruderProxy.dll");
    return path.u8string();
}

bool createSuspendedProcessWithLibrary(PROCESS_INFORMATION& pi, const std::string& exePath, const std::string& libraryPath)
{
    bool success = false;

    do {
        if (!createSuspendedProcess(pi, exePath)) {
            break;
        }

        if (!injectLibrary(pi.hProcess, libraryPath)) {
            break;
        }

        success = true;
    } while (0);

    if (!success && pi.hProcess) {
        TerminateProcess(pi.hProcess, 0);
    }

    return success;
}

int main()
{
    const auto& exePath = getHostExePath();
    const auto& libraryPath = getInjectedLibraryPath();
    const DWORD timeoutInMillisec = 5000;

    std::cout << "[Injector] Creating process with library:\n  exe: " << exePath << "\n  lib: " << libraryPath << std::endl;

    PROCESS_INFORMATION pi{ 0 };

    do {
        if (!createSuspendedProcessWithLibrary(pi, exePath, libraryPath)) {
            break;
        }

        std::cout << "[Injector] Injection completed! Resuming main thread and waiting " << timeoutInMillisec << " ms before terminating the process..." << std::endl;

        if (ResumeThread(pi.hThread) == (DWORD)-1) {
            //throw std::runtime_error("Failed to resume process's main thread");
            break;
        }

        if (WaitForSingleObject(pi.hProcess, timeoutInMillisec) == WAIT_TIMEOUT) {
            std::cout << "[Injector] Terminating process..." << std::endl;
            TerminateProcess(pi.hProcess, 0);
        }
    } while (0);

    if (pi.hProcess) {
        CloseHandle(pi.hProcess);
    }

    if (pi.hThread) {
        CloseHandle(pi.hThread);
    }

    return 0;
}
