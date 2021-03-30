#include "pch.h"
#include <iostream>
#include "injected.h"

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


PVOID injectCode(HANDLE hProcess, PVOID pLocalCode, SIZE_T codeSize)
{
	PVOID pRemoteCode = (PVOID)VirtualAllocEx(
		hProcess,
		NULL,
		codeSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	if (pRemoteCode == NULL)
	{
		return NULL;
	}
	SIZE_T bytesWritten;
	BOOL success = WriteProcessMemory(hProcess, pRemoteCode, pLocalCode, codeSize, &bytesWritten);
	if (!success || bytesWritten != codeSize)
	{
		VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
		return NULL;
	}
	return pRemoteCode;
}


BOOL patchDummyAddr(HANDLE hProcess, PVOID pLocalFunc, PVOID pRemoteFunc,
	SIZE_T funcSize, PVOID patchedAddr)
{
	PBYTE p = (PBYTE)pLocalFunc;
	PBYTE end = (PBYTE)pLocalFunc + funcSize;
	int offset;
	SIZE_T bytesWritten;
	BOOL success;

	for (; p < end; p++)
	{
		if (*(DWORD_PTR *)p == DUMMY_ADDR)
		{
			offset = p - (PBYTE)pLocalFunc;
			success = WriteProcessMemory(
				hProcess,
				(PBYTE)pRemoteFunc + offset,
				&patchedAddr,
				sizeof(patchedAddr),
				&bytesWritten
			);
			return success && bytesWritten == sizeof(patchedAddr);
		}
	}
	return FALSE;
}
