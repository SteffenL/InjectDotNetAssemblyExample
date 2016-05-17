#include "Application.h"
#include "ApplicationPaths.h"
#include "CodeInjector.h"

#include <iostream>

#include <Windows.h>


int Application::Run()
{
    const auto& exePath = ApplicationPaths::InjectionHostExePath();
    const auto& libraryPath = ApplicationPaths::InjectedLibraryPath();
    const DWORD timeoutInMillisec = 5000;

    std::cout << "[Injector] Creating process with library:\n  exe: " << exePath << "\n  lib: " << libraryPath << std::endl;
    auto process = CodeInjector::CreateProcessWithLibrary(exePath, libraryPath);
    std::cout << "[Injector] Injection completed! Resuming main thread and waiting " << timeoutInMillisec << " ms before terminating the process..." << std::endl;

    process->Resume();
    if (process->Wait(timeoutInMillisec) == Process::WaitResult::Timeout) {
        std::cout << "[Injector] Terminating process..." << std::endl;
        process->Terminate(0);
    }

    return 0;
}
