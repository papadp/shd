#include "shd.h"

/*
Taken from: https://github.com/Cr4sh/fwexpl/blob/master/src/driver/src/common.cpp
*/
PVOID ShdKernelGetModuleBase(char *ModuleName)
{
	PVOID pModuleBase = NULL;
	UNICODE_STRING usCommonHalName, usCommonNtName;

	RtlInitUnicodeString(&usCommonHalName, L"hal.dll");
	RtlInitUnicodeString(&usCommonNtName, L"ntoskrnl.exe");

#define HAL_NAMES_NUM 6
	wchar_t *wcHalNames[] =
	{
		L"hal.dll",      // Non-ACPI PIC HAL 
		L"halacpi.dll",  // ACPI PIC HAL
		L"halapic.dll",  // Non-ACPI APIC UP HAL
		L"halmps.dll",   // Non-ACPI APIC MP HAL
		L"halaacpi.dll", // ACPI APIC UP HAL
		L"halmacpi.dll"  // ACPI APIC MP HAL
	};

#define NT_NAMES_NUM 4
	wchar_t *wcNtNames[] =
	{
		L"ntoskrnl.exe", // UP
		L"ntkrnlpa.exe", // UP PAE
		L"ntkrnlmp.exe", // MP
		L"ntkrpamp.exe"  // MP PAE
	};

	PRTL_PROCESS_MODULES Info = (PRTL_PROCESS_MODULES)ShdGetSysInf(SystemModuleInformation);
	if (Info)
	{
		ANSI_STRING asModuleName;
		UNICODE_STRING usModuleName;

		RtlInitAnsiString(&asModuleName, ModuleName);

		NTSTATUS ns = RtlAnsiStringToUnicodeString(&usModuleName, &asModuleName, TRUE);
		if (NT_SUCCESS(ns))
		{
			for (ULONG i = 0; i < Info->NumberOfModules; i++)
			{
				ANSI_STRING asEnumModuleName;
				UNICODE_STRING usEnumModuleName;

				RtlInitAnsiString(
					&asEnumModuleName,
					(char *)Info->Modules[i].FullPathName + Info->Modules[i].OffsetToFileName
					);

				NTSTATUS ns = RtlAnsiStringToUnicodeString(&usEnumModuleName, &asEnumModuleName, TRUE);
				if (NT_SUCCESS(ns))
				{
					if (RtlEqualUnicodeString(&usModuleName, &usCommonHalName, TRUE))
					{
						// hal.dll passed as module name
						for (int i_m = 0; i_m < HAL_NAMES_NUM; i_m++)
						{
							UNICODE_STRING usHalName;
							RtlInitUnicodeString(&usHalName, wcHalNames[i_m]);

							// compare module name from list with known HAL module name
							if (RtlEqualUnicodeString(&usEnumModuleName, &usHalName, TRUE))
							{
								pModuleBase = (PVOID)Info->Modules[i].ImageBase;
								break;
							}
						}
					}
					else if (RtlEqualUnicodeString(&usModuleName, &usCommonNtName, TRUE))
					{
						// ntoskrnl.exe passed as module name
						for (int i_m = 0; i_m < NT_NAMES_NUM; i_m++)
						{
							UNICODE_STRING usNtName;
							RtlInitUnicodeString(&usNtName, wcNtNames[i_m]);

							// compare module name from list with known kernel module name
							if (RtlEqualUnicodeString(&usEnumModuleName, &usNtName, TRUE))
							{
								pModuleBase = (PVOID)Info->Modules[i].ImageBase;
								break;
							}
						}
					}
					else if (RtlEqualUnicodeString(&usModuleName, &usEnumModuleName, TRUE))
					{
						pModuleBase = (PVOID)Info->Modules[i].ImageBase;
					}

					RtlFreeUnicodeString(&usEnumModuleName);

					if (pModuleBase)
					{
						// module is found
						break;
					}
				}
			}

			RtlFreeUnicodeString(&usModuleName);
		}

		ExFreePool(Info);
	}

	return pModuleBase;
}

/*
Taken from: https://github.com/Cr4sh/fwexpl/blob/master/src/driver/src/common.cpp
*/
PVOID ShdKernelGetExportAddress(PVOID Image, char *lpszFunctionName)
{
	__try
	{
		PIMAGE_EXPORT_DIRECTORY pExport = NULL;

		PIMAGE_NT_HEADERS32 pHeaders32 = (PIMAGE_NT_HEADERS32)
			((PUCHAR)Image + ((PIMAGE_DOS_HEADER)Image)->e_lfanew);
		if (pHeaders32->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
		{
			// 32-bit image
			if (pHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
			{
				pExport = (PIMAGE_EXPORT_DIRECTORY)RVATOVA(
					Image,
					pHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
					);
			}
		}
		else if (pHeaders32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
		{
			// 64-bit image
			PIMAGE_NT_HEADERS64 pHeaders64 = (PIMAGE_NT_HEADERS64)
				((PUCHAR)Image + ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

			if (pHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
			{
				pExport = (PIMAGE_EXPORT_DIRECTORY)RVATOVA(
					Image,
					pHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
					);
			}
		}
		else
		{
			ShdDebugPrint(DEBUG_LEVEL_MAJOR, "ERROR: Unkown machine type\n");
			return 0;
		}

		if (pExport)
		{
			PULONG AddressOfFunctions = (PULONG)RVATOVA(Image, pExport->AddressOfFunctions);
			PSHORT AddrOfOrdinals = (PSHORT)RVATOVA(Image, pExport->AddressOfNameOrdinals);
			PULONG AddressOfNames = (PULONG)RVATOVA(Image, pExport->AddressOfNames);

			for (ULONG i = 0; i < pExport->NumberOfFunctions; i++)
			{
				if (!strcmp((char *)RVATOVA(Image, AddressOfNames[i]), lpszFunctionName))
				{
					return RVATOVA(Image, AddressOfFunctions[AddrOfOrdinals[i]]);
				}
			}
		}
		else
		{
			ShdDebugPrint(DEBUG_LEVEL_MAJOR, "WARNING: Export directory not found\n");
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ShdDebugPrint(DEBUG_LEVEL_MAJOR, "EXCEPTION\n");
	}

	return NULL;
}

NTSTATUS ShdKernelGetImageSize(_In_ PVOID ImageBase, _Inout_ PSIZE_T ImageSize)
{
	NTSTATUS Status = STATUS_SUCCESS;

	if (ImageBase && ImageSize)
	{
		PIMAGE_NT_HEADERS32 pHeaders32 = (PIMAGE_NT_HEADERS32)((PUCHAR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew);
#ifdef _X86_
		if (pHeaders32->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
		{
			// 32-bit image
			*ImageSize = pHeaders32->OptionalHeader.SizeOfImage;
			Status = STATUS_SUCCESS;
		}
#else
		if (pHeaders32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
		{
			// 64-bit image
			PIMAGE_NT_HEADERS64 pHeaders64 = (PIMAGE_NT_HEADERS64)((PUCHAR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew);
			*ImageSize = pHeaders64->OptionalHeader.SizeOfImage;
			Status = STATUS_SUCCESS;
		}
#endif
		else
		{
			ShdDebugPrint(DEBUG_LEVEL_MAJOR, "Unknown image type");
			Status = STATUS_INVALID_PARAMETER;
		}
	}
	else
	{
		ShdDebugPrint(DEBUG_LEVEL_MAJOR, "Bad pointers passed %p %p", ImageBase, ImageSize);
		Status = STATUS_INVALID_PARAMETER;
	}
	return Status;
}