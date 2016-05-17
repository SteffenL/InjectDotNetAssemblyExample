#include "Process.h"

#include <filesystem>


const uint32_t Process::WAIT_TIMEOUT_INFINITE = -1;

Process::~Process()
{
    cleanup();
}

void Process::Resume()
{
    if (!m_processInfo.hThread) {
        throw std::runtime_error("We do not have a handle for the process' main thread");
    }

    if (ResumeThread(m_processInfo.hThread) == (DWORD)-1) {
        throw std::runtime_error("Failed to resume process's main thread");
    }
}

void Process::Terminate(uint32_t exitCode)
{
    if (!m_processInfo.hProcess) {
        return;
    }

    if (!TerminateProcess(m_processInfo.hProcess, exitCode)) {
        throw std::runtime_error("Failed to Terminate the process");
    }

    cleanup();
}

void* Process::NativeHandle() const
{
    return m_processInfo.hProcess;
}

Process::WaitResult Process::Wait(uint32_t timeoutInMillisec /*= WAIT_TIMEOUT_INFINITE*/)
{
    if (!m_processInfo.hProcess) {
        throw std::runtime_error("We do not have a handle for the process");
    }

    DWORD timeout = timeoutInMillisec == WAIT_TIMEOUT_INFINITE ? INFINITE : timeoutInMillisec;
    auto nativeWaitResult = WaitForSingleObject(m_processInfo.hProcess, timeoutInMillisec);

    if (nativeWaitResult == WAIT_FAILED) {
        throw std::runtime_error("Failed to wait for the process' signaled/timeout state.");
    }

    switch (nativeWaitResult) {
        case WAIT_TIMEOUT:
            return WaitResult::Timeout;
        case WAIT_ABANDONED:
            return WaitResult::Abandoned;
        case WAIT_OBJECT_0:
            return WaitResult::Signaled;
        default:
            throw std::logic_error("Invalid native wait result");
    }
}

std::unique_ptr<Process> Process::Create(const std::string& exePath, unsigned int creationFlags /*= 0*/)
{
    std::wstring exePath_w = std::experimental::filesystem::u8path(exePath).wstring();
    WCHAR exePath_c[MAX_PATH]{ 0 };
    memcpy(exePath_c, exePath_w.data(), exePath_w.size() * sizeof(exePath_w[0]));

    STARTUPINFOW si{ 0 };
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{ 0 };

    if (!CreateProcessW(exePath_c, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        throw std::runtime_error("Failed to create process");
    }

    auto process = std::make_unique<Process>();
    process->m_processInfo = pi;

    try {
        if (!(creationFlags & CreationFlag::CreateSuspended)) {
            if (ResumeThread(pi.hProcess) == (DWORD)-1) {
                throw std::runtime_error("Failed to resume process' main thread");
            }
        }
    }
    catch (std::runtime_error&) {
        process->Terminate(0);
        throw;
    }

    return process;
}

void Process::cleanup()
{
    if (m_processInfo.hProcess) {
        CloseHandle(m_processInfo.hProcess);
        m_processInfo.hProcess = NULL;
    }

    if (m_processInfo.hThread) {
        CloseHandle(m_processInfo.hThread);
        m_processInfo.hThread = NULL;
    }

    m_processInfo = { 0 };
}
