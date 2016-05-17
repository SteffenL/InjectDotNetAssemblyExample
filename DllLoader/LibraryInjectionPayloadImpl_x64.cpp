#include "LibraryInjectionPayloadImpl_x64.h"


std::vector<std::vector<uint8_t>> LibraryInjectionPayloadImpl_x64::Create(uint64_t remoteLibraryPath, uint64_t loadLibrary, uint64_t remoteIntruderExportName, uint64_t getProcAddress) const
{
    return{
        // Prologue
        // push rbp
        { 0x55 },
        // mov rbp, rsp
        { 0x48, 0x89, 0xe5 },
        // sub rsp, bytes
        { 0x48, 0x83, 0xec, stackBytesToReserve },

        // Load intruder library
        asm_movabs_rcx_value(remoteLibraryPath),
        asm_movabs_rax_value(loadLibrary),
        // call rax
        { 0xff, 0xd0 },

        // Get address of intruder exported function
        // Intruder module handle
        // mov rcx, rax
        { 0x48, 0x89, 0xc1 },
        // Intruder export name
        asm_movabs_rdx_value(remoteIntruderExportName),
        asm_movabs_rax_value(getProcAddress),
        // call rax
        { 0xff, 0xd0 },

        // Call exported function
        // call rax
        { 0xff, 0xd0 },

        // Epilogue
        // mov rsp, rbp
        { 0x48, 0x89, 0xec },
        // pop rbp
        { 0x5d },
        // ret
        { 0xc3 }
    };
}

std::vector<uint8_t> LibraryInjectionPayloadImpl_x64::asm_movabs_rcx_value(uint64_t value) const
{
    std::vector<uint8_t> data;
    data.resize(2 + sizeof(value));
    data[0] = 0x48;
    data[1] = 0xb9;
    *(decltype(value)*)&data[2] = value;
    return data;
}

std::vector<uint8_t> LibraryInjectionPayloadImpl_x64::asm_movabs_rdx_value(uint64_t value) const
{
    std::vector<uint8_t> data;
    data.resize(2 + sizeof(value));
    data[0] = 0x48;
    data[1] = 0xba;
    *(decltype(value)*)&data[2] = value;
    return data;
}

std::vector<uint8_t> LibraryInjectionPayloadImpl_x64::asm_mov_r8_value(uint64_t value) const
{
    std::vector<uint8_t> data;
    data.resize(2 + sizeof(value));
    data[0] = 0x49;
    data[1] = 0xb8;
    *(decltype(value)*)&data[2] = value;
    return data;
}

std::vector<uint8_t> LibraryInjectionPayloadImpl_x64::asm_mov_r9_value(uint64_t value) const
{
    std::vector<uint8_t> data;
    data.resize(2 + sizeof(value));
    data[0] = 0x49;
    data[1] = 0xb9;
    *(decltype(value)*)&data[2] = value;
    return data;
}

std::vector<uint8_t> LibraryInjectionPayloadImpl_x64::asm_movabs_rax_value(uint64_t value) const
{
    std::vector<uint8_t> data;
    data.resize(2 + sizeof(value));
    data[0] = 0x48;
    data[1] = 0xb8;
    *(decltype(value)*)&data[2] = value;
    return data;
}
