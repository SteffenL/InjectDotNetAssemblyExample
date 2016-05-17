#pragma once

#include <cstdint>
#include <string>
#include <memory>

#include <Windows.h>

class Process
{
public:
    struct CreationFlag
    {
        enum type
        {
            CreateSuspended = 1
        };
    };

    enum class WaitResult
    {
        Signaled,
        Timeout,
        Abandoned
    };

    static const uint32_t WAIT_TIMEOUT_INFINITE;

    virtual ~Process();
    void Resume();
    void Terminate(uint32_t exitCode);
    void* NativeHandle() const;
    WaitResult Wait(uint32_t timeoutInMillisec = WAIT_TIMEOUT_INFINITE);
    static std::unique_ptr<Process> Create(const std::string& exePath, unsigned int creationFlags = 0);

private:
    void cleanup();

    PROCESS_INFORMATION m_processInfo{ 0 };
};
