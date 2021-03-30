#include "pch.h"
#include <iostream>

DWORD pidof(const WCHAR *processImage)
{
	HANDLE hSsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	DWORD pid = NULL;
	if (hSsnapshot != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hSsnapshot, &pe32))
		{
			do {
				if (!wcscmp(processImage, pe32.szExeFile))
				{
					pid = pe32.th32ProcessID;
					break;
				}
			} while (Process32Next(hSsnapshot, &pe32));
		}
		CloseHandle(hSsnapshot);
	}
	return pid;
}


PVOID injectData(HANDLE hProcess, PVOID pLocalData, SIZE_T dataSize)
{
	PVOID pRemoteData = (PVOID)VirtualAllocEx(
		hProcess,
		NULL,
		dataSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	if (pRemoteData == NULL)
	{
		return NULL;
	}
	SIZE_T bytesWritten;
	BOOL success = WriteProcessMemory(hProcess, pRemoteData, pLocalData, dataSize, &bytesWritten);
	if (!success || bytesWritten != dataSize)
	{
		VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
		return NULL;
	}
	return pRemoteData;
}


HANDLE getRemoteDllHandle(DWORD targetPID, WCHAR *fullDllPath)
{
	HANDLE hSsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, targetPID);
	HANDLE hInjectedDll = NULL;
	if (hSsnapshot != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 me32;
		me32.dwSize = sizeof(MODULEENTRY32);
		if (Module32First(hSsnapshot, &me32))
		{
			do {
				if (!wcscmp(fullDllPath, me32.szExePath))
				{
					hInjectedDll = me32.hModule;
					break;
				}
			} while (Module32Next(hSsnapshot, &me32));
		}
		CloseHandle(hSsnapshot);
	}
	return hInjectedDll;
}

