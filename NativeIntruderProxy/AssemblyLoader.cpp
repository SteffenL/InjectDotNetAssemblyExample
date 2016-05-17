#include "AssemblyLoader.h"

#include <cassert>
#include <iostream>
#include <iomanip>
#include <functional>

#include <mscoree.h>
#include <metahost.h>
#pragma comment(lib, "mscoree.lib")
#import "mscorlib.tlb" raw_interfaces_only \
    high_property_prefixes("_get","_put","_putref") \
    rename("ReportEvent", "InteropServices_ReportEvent")


void clrWrapper(std::function<void(ICLRRuntimeHost* pClrRuntimeHost)> callback)
{
    HRESULT hr = E_FAIL;

    ICLRMetaHost* pMetaHost = nullptr;
    ICLRRuntimeInfo* pRuntimeInfo = nullptr;
    ICLRRuntimeHost* pClrRuntimeHost = nullptr;

    do {
        hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&pMetaHost));
        assert(SUCCEEDED(hr));
        hr = pMetaHost->GetRuntime(L"v4.0.30319", IID_PPV_ARGS(&pRuntimeInfo));
        assert(SUCCEEDED(hr));
        hr = pRuntimeInfo->GetInterface(CLSID_CLRRuntimeHost, IID_PPV_ARGS(&pClrRuntimeHost));
        assert(SUCCEEDED(hr));
        hr = pClrRuntimeHost->Start();
        assert(SUCCEEDED(hr));

        if (callback) {
            callback(pClrRuntimeHost);
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
}


ASSEMBLYLOADER_API void __stdcall Startup()
{
    std::cout << "[Native Intruder Proxy] Starting up." << std::endl;
    clrWrapper([](ICLRRuntimeHost* pClrRuntimeHost) {
        auto hr = pClrRuntimeHost->ExecuteInDefaultAppDomain(L"ManagedIntruder.dll", L"ManagedIntruder.Class1", L"SayHello", NULL, NULL);
        assert(SUCCEEDED(hr));
    });
}

