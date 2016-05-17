#include "AssemblyLoader.h"

#include <string>
#include <iostream>
#include <iomanip>
#include <functional>
#include <codecvt>
#include <type_traits>
#include <vector>

#include <mscoree.h>
#include <metahost.h>
#pragma comment(lib, "mscoree.lib")
#import "mscorlib.tlb" raw_interfaces_only \
    high_property_prefixes("_get","_put","_putref") \
    rename("ReportEvent", "InteropServices_ReportEvent")


HRESULT clrWrapper(LPCWSTR runtimeVersion, std::function<HRESULT(ICLRRuntimeHost* pClrRuntimeHost)> callback)
{
    HRESULT hr = E_FAIL;
    ICLRMetaHost* pMetaHost = nullptr;
    ICLRRuntimeInfo* pRuntimeInfo = nullptr;
    ICLRRuntimeHost* pClrRuntimeHost = nullptr;

    do {
        hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&pMetaHost));
        if (FAILED(hr)) {
            break;
        }

        hr = pMetaHost->GetRuntime(runtimeVersion, IID_PPV_ARGS(&pRuntimeInfo));
        if (FAILED(hr)) {
            break;
        }

        hr = pRuntimeInfo->GetInterface(CLSID_CLRRuntimeHost, IID_PPV_ARGS(&pClrRuntimeHost));
        if (FAILED(hr)) {
            break;
        }

        hr = pClrRuntimeHost->Start();
        if (FAILED(hr)) {
            break;
        }

        if (callback) {
            hr = callback(pClrRuntimeHost);
            if (FAILED(hr)) {
                break;
            }
        }
    } while (false);

    if (pClrRuntimeHost) {
        pClrRuntimeHost->Release();
        pClrRuntimeHost = nullptr;
    }

    if (pRuntimeInfo) {
        pRuntimeInfo->Release();
        pRuntimeInfo = nullptr;
    }

    if (pMetaHost) {
        pMetaHost->Release();
        pMetaHost = nullptr;
    }

    return hr;
}

std::string getClrOrComErrorMessage(HRESULT hr)
{
    std::string msg;
    HMODULE libHandle = NULL;
    std::vector<std::wstring> libNames{ L"mscorrc.dll", L"mscorrc.debug.dll" };
    bool success = false;

    for (auto& libName : libNames) {
        do {
            libHandle = LoadLibraryW(libName.c_str());
            if (!libHandle) {
                break;
            }

            {
                LPWSTR msgFromClr_c = NULL;
                auto stringId = 0x6000 + (hr & 0xffff);
                auto length = LoadStringW(libHandle, stringId, (LPWSTR)&msgFromClr_c, 0);
                if (length) {
                    msg = std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>().to_bytes(msgFromClr_c, msgFromClr_c + length);
                    success = true;
                    break;
                }
            }
        } while (0);

        if (libHandle) {
            FreeLibrary(libHandle);
            libHandle = NULL;
        }

        if (success) {
            break;
        }
    }

    if (!success) {
        _com_error error(hr);
        auto msg_c = error.ErrorMessage();
        static_assert(std::is_same<typename std::decay<decltype(msg_c[0])>::type, wchar_t>::value, "Expected wchar_t");
        msg = std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>().to_bytes(msg_c);
    }

    return msg;
}


ASSEMBLYLOADER_API void __stdcall Startup()
{
    std::cout << "[Native Intruder Proxy] Starting up." << std::endl;
    auto hr = clrWrapper(L"v4.0.30319", [](ICLRRuntimeHost* pClrRuntimeHost) {
        auto hr = pClrRuntimeHost->ExecuteInDefaultAppDomain(L"ManagedIntruder.dll", L"ManagedIntruder.Class1", L"SayHello", NULL, NULL);
        if (FAILED(hr)) {
            std::cerr << "[Native Intruder Proxy] Execution of method in managed assembly failed." << std::endl;
        }

        return hr;
    });

    if (FAILED(hr)) {
        auto nativeErrorMsg = getClrOrComErrorMessage(hr);
        std::cerr << "[Native Intruder Proxy] CLR startup or callback failed: " << nativeErrorMsg << std::endl;
    }
}
