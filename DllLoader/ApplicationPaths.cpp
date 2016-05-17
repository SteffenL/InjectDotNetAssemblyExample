#include "ApplicationPaths.h"

#include <filesystem>

#include <Windows.h>


std::string ApplicationPaths::ExeDir()
{
    WCHAR exePath[MAX_PATH]{ 0 };
    GetModuleFileNameW(0, exePath, sizeof(exePath));
    return std::experimental::filesystem::path(exePath).u8string();
}

std::string ApplicationPaths::InjectionHostExePath()
{
    auto path = std::experimental::filesystem::u8path(ExeDir());
    path.replace_filename("NativeHost.exe");
    return path.u8string();
}

std::string ApplicationPaths::InjectedLibraryPath()
{
    auto path = std::experimental::filesystem::u8path(ExeDir());
    path.replace_filename("NativeIntruderProxy.dll");
    return path.u8string();
}
