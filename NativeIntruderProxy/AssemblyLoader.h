#ifdef ASSEMBLYLOADER_EXPORTS
#define ASSEMBLYLOADER_API __declspec(dllexport)
#else
#define ASSEMBLYLOADER_API __declspec(dllimport)
#endif

ASSEMBLYLOADER_API void __stdcall Startup();
