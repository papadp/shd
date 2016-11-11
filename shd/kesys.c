#include "shd.h"

/*
Taken from: https://github.com/Cr4sh/fwexpl/blob/master/src/driver/src/common.cpp
*/
PVOID ShdGetSysInf(SYSTEM_INFORMATION_CLASS InfoClass)
{
	NTSTATUS ns;
	ULONG RetSize, Size = 0x100;
	PVOID Info;
#pragma push
#pragma warning(disable: 4127)
	while (TRUE)
#pragma pop
	{
		if ((Info = ExAllocatePool(NonPagedPool, Size)) == NULL)
		{
			ShdDebugPrint(DEBUG_LEVEL_MAJOR, "ExAllocatePool() fails\n");
			return NULL;
		}

		RetSize = 0;
		ns = ZwQuerySystemInformation(InfoClass, Info, Size, &RetSize);
		if (ns == STATUS_INFO_LENGTH_MISMATCH)
		{
			ExFreePool(Info);
			Info = NULL;

			if (RetSize > 0)
			{
				Size = RetSize + 0x100;
			}
			else
				break;
		}
		else
			break;
	}

	if (!NT_SUCCESS(ns))
	{
		ShdDebugPrint(DEBUG_LEVEL_MAJOR, "ZwQuerySystemInformation() fails; status: 0x % .8x\n", ns);

		if (Info)
			ExFreePool(Info);

		return NULL;
	}

	return Info;
}

/*
Taken from: http://www.kernelmode.info/forum/viewtopic.php?f=14&t=1146&hilit=keservicedescriptor#p8660
*/
PKESERVICE_DESCRIPTOR_TABLE ShdGetKeServiceDescriptorTable(void)
{
	PVOID Ret = NULL;

#ifdef _X86_

	PVOID KernelBase = ShdKernelGetModuleBase("ntoskrnl.exe");
	if (KernelBase)
	{
		PVOID KeSDT_RVA = ShdKernelGetExportAddress(KernelBase, "KeServiceDescriptorTable");
		if (KeSDT_RVA > 0)
		{
			Ret = KeSDT_RVA;
		}
		else
		{
			ShdDebugPrint(DEBUG_LEVEL_MAJOR, "ERROR: Symbol nt!KeServiceDescriptorTable is not found\n");
		}
	}
	else
	{
		ShdDebugPrint(DEBUG_LEVEL_MAJOR, "() ERROR: Unable to locate kernel base\n");
	}

#elif _AMD64_

#define MAX_INST_LEN 24

	PVOID KernelBase = ShdKernelGetModuleBase("ntoskrnl.exe");
	if (KernelBase)
	{
		size_t Func = (size_t)ShdKernelGetExportAddress(KernelBase, "KeAddSystemServiceTable");
		if (Func > 0)
		{
			ShdDebugPrint(DEBUG_LEVEL_MAJOR, "KernelBase:");
			// initialize disassembler engine
			ud_t ud_obj;
			ud_init(&ud_obj);

			UCHAR ud_mode = 64;

			// set mode, syntax and vendor
			ud_set_mode(&ud_obj, ud_mode);
			ud_set_syntax(&ud_obj, UD_SYN_INTEL);
			ud_set_vendor(&ud_obj, UD_VENDOR_INTEL);

			for (ULONG i = 0; i < 0x40;)
			{

				PUCHAR Inst = (PUCHAR)(Func + i);
				if (!MmIsAddressValid(Inst))
				{
					ShdDebugPrint(DEBUG_LEVEL_MAJOR, "ERROR: Invalid memory at %p", Inst);
					//DbgBreakPoint();
					break;
				}
				ud_set_input_buffer(&ud_obj, Inst, MAX_INST_LEN);

				// get length of the instruction
				ULONG InstLen = ud_disassemble(&ud_obj);
				if (InstLen == 0)
				{
					// error while disassembling instruction
					ShdDebugPrint(DEBUG_LEVEL_MAJOR, "ERROR: Can't disassemble instruction at %p\n", Inst);
					break;
				}

				/*
				Check for the following code

				nt!KeAddSystemServiceTable:
				fffff800`012471c0 448b542428         mov     r10d,dword ptr [rsp+28h]
				fffff800`012471c5 4183fa01           cmp     r10d,1
				fffff800`012471c9 0f871ab70c00       ja      nt!KeAddSystemServiceTable+0x78
				fffff800`012471cf 498bc2             mov     rax,r10
				fffff800`012471d2 4c8d1d278edbff     lea     r11,0xfffff800`01000000
				fffff800`012471d9 48c1e005           shl     rax,5
				fffff800`012471dd 4a83bc1880bb170000 cmp     qword ptr [rax+r11+17BB80h],0
				fffff800`012471e6 0f85fdb60c00       jne     nt!KeAddSystemServiceTable+0x78
				*/

				if ((*(PULONG)Inst & 0x00ffffff) == 0x1d8d4c &&
					(*(PUSHORT)(Inst + 0x0b) == 0x834b || *(PUSHORT)(Inst + 0x0b) == 0x834a))
				{
					ShdDebugPrint(DEBUG_LEVEL_MAJOR, "Found relevant instruction");
					// clculate nt!KeServiceDescriptorTableAddress
					LARGE_INTEGER Addr;
					Addr.QuadPart = (ULONGLONG)Inst + InstLen;
					Addr.LowPart += *(PULONG)(Inst + 0x03) + *(PULONG)(Inst + 0x0f);

					Ret = (PVOID)Addr.QuadPart;

					break;
				}

				i += InstLen;
			}
		}
		else
		{
			ShdDebugPrint(DEBUG_LEVEL_MAJOR, "ERROR: Symbol nt!KeServiceDescriptorTable is not found\n");
		}
	}
	else
	{
		ShdDebugPrint(DEBUG_LEVEL_MAJOR, "ERROR: Unable to locate kernel base\n");
	}

#endif

	if (Ret)
	{
		ShdDebugPrint(DEBUG_LEVEL_MAJOR, "nt!KeServiceDescriptorTable is at %p\n", Ret);
	}

	return Ret;
}