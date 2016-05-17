#include "CodeInjector.h"
#include "LibraryInjectionPayload.h"

#include <sstream>
#include <filesystem>

#include <Windows.h>


bool CodeInjector::InjectLibrary(Process& process, const std::string& libraryPath)
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
    auto processHandle = process.NativeHandle();

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
        remoteLibraryPath = VirtualAllocEx(processHandle, NULL, sizeOfLibraryPath, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!remoteLibraryPath) {
            //throw std::runtime_error("Failed to allocate memory for library path in remote process.");
            break;
        }

        if (!WriteProcessMemory(processHandle, remoteLibraryPath, libraryPath_w.data(), sizeOfLibraryPath, NULL)) {
            //throw std::runtime_error("Failed to write library path in remote process.");
            break;
        }

        // Write function name exported from intruder

        std::string intruderExportName = "Startup";
        intruderExportName.append(1, '\0');
        auto sizeOfIntruderExportName = intruderExportName.size() * sizeof(decltype(intruderExportName)::value_type);
        remoteIntruderExportName = VirtualAllocEx(processHandle, NULL, sizeOfIntruderExportName, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!remoteIntruderExportName) {
            //throw std::runtime_error("Failed to allocate memory for library path in remote process.");
            break;
        }

        if (!WriteProcessMemory(processHandle, remoteIntruderExportName, intruderExportName.data(), sizeOfIntruderExportName, NULL)) {
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

        remotePayload = VirtualAllocEx(processHandle, NULL, sizeOfPayload, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!remotePayload) {
            //throw std::runtime_error("Failed to allocate memory for payload in remote process.");
            break;
        }

        if (!WriteProcessMemory(processHandle, remotePayload, payload.data(), sizeOfPayload, NULL)) {
            //throw std::runtime_error("Failed to write payload in remote process.");
            break;
        }

        FlushInstructionCache(processHandle, remotePayload, sizeOfPayload);

        // Execute payload

        thread = CreateRemoteThread(processHandle, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(remotePayload), NULL, 0, NULL);
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
        VirtualFreeEx(processHandle, remotePayload, 0, MEM_RELEASE);
        remotePayload = NULL;
    }

    if (remoteIntruderExportName) {
        VirtualFreeEx(processHandle, remoteIntruderExportName, 0, MEM_RELEASE);
        remoteIntruderExportName = NULL;
    }

    if (remoteLibraryPath) {
        VirtualFreeEx(processHandle, remoteLibraryPath, 0, MEM_RELEASE);
        remoteLibraryPath = NULL;
    }

    return success;
}

std::unique_ptr<Process> CodeInjector::CreateProcessWithLibrary(const std::string& exePath, const std::string& libraryPath)
{
    std::unique_ptr<Process> process;

    try {
        process = Process::Create(exePath, Process::CreationFlag::CreateSuspended);
        if (!InjectLibrary(*process, libraryPath)) {
            throw std::runtime_error("Library injection failed");
        }
    }
    catch (std::runtime_error&) {
        if (process) {
            process->Terminate(0);
        }

        throw;
    }

    return process;
}
