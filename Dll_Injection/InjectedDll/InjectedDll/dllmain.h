#pragma once

#ifdef DLL_EXPORT
#define DECLDIR __declspec(dllexport)
#else
#define DECLDIR __declspec(dllimport)
#endif

const WCHAR *HIDDEN_PROCESS_IMAGE = L"notepad.exe";  // TODO: should be read from shared memory
typedef NTSTATUS (WINAPI *_NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

extern "C"
{
	int hook(PCSTR func_to_hook, PCSTR DLL_to_hook, DWORD_PTR new_func_address);
    DECLDIR NTSTATUS WINAPI HookedNtQuerySystemInformation(
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        PVOID                    SystemInformation,
        ULONG                    SystemInformationLength,
        PULONG                   ReturnLength
    );
}