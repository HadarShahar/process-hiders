#include "pch.h"
#include <iostream>
#include "utils.h"

const WCHAR *PATH_TO_INJECTED_DLL = L"..\\..\\..\\InjectedDll\\x64\\Debug\\InjectedDll.dll";
const WCHAR *TARGET_PROCESS = L"Taskmgr.exe";


BOOL injectDll(HANDLE hProcess, WCHAR *fullDllPath)
{
	HMODULE hKernel32 = GetModuleHandle(L"Kernel32.dll");
	if (!hKernel32)
		return FALSE;
	PVOID pLoadLibrary = (PVOID)GetProcAddress(hKernel32, "LoadLibraryW");
	
	// +1 because the len doesn't include the terminating null character
	PVOID pRemotePath = injectData(hProcess, fullDllPath, (wcslen(fullDllPath) + 1) * sizeof(WCHAR));
	if (!pRemotePath)
		return FALSE;
	
	HANDLE hThread = CreateRemoteThread(
		hProcess,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)pLoadLibrary,
		pRemotePath,
		0,
		NULL);
	if (!hThread)
	{
		VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
		return FALSE;
	}
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	return TRUE;
}


BOOL ejectDll(HANDLE hProcess, WCHAR *fullDllPath)
{
	HMODULE hKernel32 = GetModuleHandle(L"Kernel32.dll");
	if (!hKernel32)
		return FALSE;
	PVOID pFreeLibrary = (PVOID)GetProcAddress(hKernel32, "FreeLibrary");

	HANDLE hInjectedDll = getRemoteDllHandle(GetProcessId(hProcess), fullDllPath);
	if (!hInjectedDll)
	{
		wprintf(L"The dll '%s' wasn't found in the target process.\n", fullDllPath);
		return FALSE;
	}

	HANDLE hThread = CreateRemoteThread(
		hProcess,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)pFreeLibrary,
		(LPVOID)hInjectedDll,
		0,
		NULL);
	if (!hThread)
		return FALSE;
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	return TRUE;
}


int main(int argc, char *argv[])
{
	DWORD targetPID = pidof(TARGET_PROCESS);
	printf("target PID: %d\n", targetPID);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
	if (hProcess == NULL)
	{
		printf("Could not get a handle to the process.");
		return EXIT_FAILURE;
	}

	WCHAR fullDllPath[MAX_PATH];
	DWORD pathLen = GetFullPathNameW(PATH_TO_INJECTED_DLL, MAX_PATH, fullDllPath, NULL);
	wprintf(L"full dll path: %s\n", fullDllPath);

	if (!injectDll(hProcess, fullDllPath))
	{
		printf("Error while injecting the dll.");
		CloseHandle(hProcess);
		return EXIT_FAILURE;
	}

	printf("DLL injected successfully, press ENTER key to eject the dll and exit.\n");
	getchar();
	
	if (!ejectDll(hProcess, fullDllPath))
	{
		printf("Error while ejecting the dll.");
		CloseHandle(hProcess);
		return EXIT_FAILURE;
	}	

	CloseHandle(hProcess);
	return EXIT_SUCCESS;
}
