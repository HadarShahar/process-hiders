#pragma once

DWORD pidof(const WCHAR *processImage);
PVOID injectData(HANDLE hProcess, PVOID pLocalData, SIZE_T dataSize);
HANDLE getRemoteDllHandle(DWORD targetPID, WCHAR *fullDllPath);