#include "shd.h"

/*
Taken from: https://github.com/Cr4sh/fwexpl/blob/master/src/driver/src/common.cpp
*/
PVOID ShdKernelGetModuleBase(char *ModuleName);

/*
Taken from: https://github.com/Cr4sh/fwexpl/blob/master/src/driver/src/common.cpp
*/
PVOID ShdKernelGetExportAddress(PVOID Image, char *lpszFunctionName);

NTSTATUS ShdKernelGetImageSize(_In_ PVOID ImageBase, _Inout_ PSIZE_T ImageSize);