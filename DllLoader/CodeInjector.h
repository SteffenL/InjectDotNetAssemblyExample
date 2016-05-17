#pragma once

#include "Process.h"

#include <string>
#include <memory>

class CodeInjector
{
public:
    static bool InjectLibrary(Process& process, const std::string& libraryPath);
    static std::unique_ptr<Process> CreateProcessWithLibrary(const std::string& exePath, const std::string& libraryPath);
};
