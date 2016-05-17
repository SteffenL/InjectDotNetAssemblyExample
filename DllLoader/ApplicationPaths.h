#pragma once

#include <string>


class ApplicationPaths
{
public:
    static std::string ExeDir();
    static std::string InjectionHostExePath();
    static std::string InjectedLibraryPath();
};
