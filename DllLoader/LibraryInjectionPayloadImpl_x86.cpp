#include "LibraryInjectionPayloadImpl_x86.h"



std::vector<std::vector<uint8_t>> LibraryInjectionPayloadImpl_x86::Create(uint32_t remoteLibraryPath, uint32_t loadLibrary, uint32_t remoteIntruderExportName, uint32_t getProcAddress) const
{
    return{
        // Prologue
        // push ebp
        { 0x55 },
        // mov ebp, esp
        { 0x89, 0xe5 },

        // Load intruder library
        asm_push_value(remoteLibraryPath),
        asm_mov_eax_value(loadLibrary),
        // call eax
        { 0xff, 0xd0 },

        // Get address of intruder exported function
        // Intruder export name
        asm_push_value(remoteIntruderExportName),
        // Intruder module handle
        // push eax
        { 0x50 },
        asm_mov_eax_value(getProcAddress),
        // call eax
        { 0xff, 0xd0 },
        // Call exported function
        // call eax
        { 0xff, 0xd0 },

        // Epilogue
        // mov esp, ebp
        { 0x89, 0xec },
        // pop ebp
        { 0x5d },
        // ret
        { 0xc3 }
    };
}

std::vector<uint8_t> LibraryInjectionPayloadImpl_x86::asm_push_value(uint32_t value) const
{
    std::vector<uint8_t> data;
    data.resize(1 + sizeof(value));
    data[0] = 0x68;
    *(decltype(value)*)&data[1] = value;
    return data;
}

std::vector<uint8_t> LibraryInjectionPayloadImpl_x86::asm_mov_eax_value(uint32_t value) const
{
    std::vector<uint8_t> data;
    data.resize(1 + sizeof(value));
    data[0] = 0xb8;
    *(decltype(value)*)&data[1] = value;
    return data;
}
