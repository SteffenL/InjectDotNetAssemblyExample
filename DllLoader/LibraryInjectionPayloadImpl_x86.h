#pragma once

#include <vector>
#include <cstdint>

class LibraryInjectionPayloadImpl_x86
{
public:
    std::vector<std::vector<uint8_t>> Create(uint32_t remoteLibraryPath, uint32_t loadLibrary, uint32_t remoteIntruderExportName, uint32_t getProcAddress) const;

private:
    std::vector<uint8_t> asm_push_value(uint32_t value) const;
    std::vector<uint8_t> asm_mov_eax_value(uint32_t value) const;
};
