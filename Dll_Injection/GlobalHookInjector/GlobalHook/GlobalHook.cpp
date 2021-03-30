// NOTE: this file must run with admin privileges (to set hook on Taskmgr.exe) !!!
#include "pch.h"
#include <iostream>

const char *PATH_TO_INJECTED_DLL = "..\\..\\..\\InjectedDll\\x64\\Debug\\InjectedDll.dll";

int main()
{
    char fullPath[MAX_PATH];
    DWORD pathLen = GetFullPathNameA(PATH_TO_INJECTED_DLL, MAX_PATH, fullPath, NULL);
    printf("fullPath: %s\n", fullPath);

    HMODULE hModule = LoadLibraryA(fullPath);
    if (hModule == NULL)
    {
        printf("The injected DLL wasn't found.");
        return EXIT_FAILURE;
    }

    HOOKPROC pfn = (HOOKPROC)GetProcAddress(hModule, "CallWndProc");
    if (pfn == NULL)
    {
        printf("The function CallWndProc was not found in the dll.");
        return EXIT_FAILURE;
    }

    HHOOK hHook = SetWindowsHookEx(WH_CALLWNDPROC, pfn, hModule, 0);
    if (hHook == NULL)
    {
        printf("Failed to hook using WH_CALLWNDPROC.");
        return EXIT_FAILURE;
    }

    printf("Hooked successfully.\n");
    printf("Press ENTER key to unhook the function and exit.");
    getchar();
    UnhookWindowsHookEx(hHook);

    return EXIT_SUCCESS;
}
