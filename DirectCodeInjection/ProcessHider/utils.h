#pragma once

DWORD pidof(const WCHAR *processImage);
PVOID injectCode(HANDLE hProcess, PVOID pLocalCode, SIZE_T codeSize);
BOOL patchDummyAddr(HANDLE hProcess, PVOID pLocalFunc, PVOID pRemoteFunc, SIZE_T funcSize, PVOID patchedAddr);