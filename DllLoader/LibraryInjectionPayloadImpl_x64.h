#pragma once

#include <vector>
#include <cstdint>

class LibraryInjectionPayloadImpl_x64
{
public:
    std::vector<std::vector<uint8_t>> Create(uint64_t remoteLibraryPath, uint64_t loadLibrary, uint64_t remoteIntruderExportName, uint64_t getProcAddress) const;

private:
    // We reserve the stack space for the functions we call.
    // The minimum space is 32 bytes (4 x 64-bit values).
    // As none of the functions we call use more than 4, we reserve the minimum space.
    const uint8_t stackBytesToReserve = sizeof(uint64_t) * 4;

    std::vector<uint8_t> asm_movabs_rcx_value(uint64_t value) const;
    std::vector<uint8_t> asm_movabs_rdx_value(uint64_t value) const;
    std::vector<uint8_t> asm_mov_r8_value(uint64_t value) const;
    std::vector<uint8_t> asm_mov_r9_value(uint64_t value) const;
    std::vector<uint8_t> asm_movabs_rax_value(uint64_t value) const;
};
