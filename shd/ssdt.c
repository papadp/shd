#include "shd.h"

__inline PVOID ShdStGetEntry(PULONG ServiceTableBase, ULONG Entry)
{
#ifdef _X86_
	return (PVOID)ServiceTableBase[Entry];
#else
	// since right shifting negative integers is not supported for c 
	// we require the following 'hack'
	ULONG EntryValue;

	if (ServiceTableBase)
	{
		EntryValue = ServiceTableBase[Entry];

		if (EntryValue > 0x7fffffff)
		{
			EntryValue = 0xffffffff - EntryValue + 1;
			EntryValue >>= 4;
			return (PVOID)((SIZE_T)ServiceTableBase - EntryValue);
		}
		else
		{
			EntryValue >>= 4;
			return (PVOID)((SIZE_T)ServiceTableBase + (ULONG)EntryValue);
		}
	}
	else
	{
		return 0;
	}
#endif
}

VOID ShdPointerHookCheck(PVOID Function, ULONG EntryNumber, PVOID KernelImageBase, PVOID KernelImageEnd, PVOID Context)
{
	ShdDebugPrint(DEBUG_LEVEL_MAJOR, "function entry");

	if (!(Function > KernelImageBase && Function < KernelImageEnd))
	{
		((PBOOLEAN)Context)[EntryNumber] = TRUE;
		// hooked
		ShdDebugPrint(DEBUG_LEVEL_MAJOR, "function %x at %p is hooked", EntryNumber, Function);
	}
	else
	{
		((PBOOLEAN)Context)[EntryNumber] = FALSE;
	}
}

VOID ShdInlineHookCheck(PVOID Function, ULONG EntryNumber, PVOID KernelImageBase, PVOID KernelImageEnd, PSHD_INLINE_HOOK_CHECK_CONTEXT Context)
{
	UNREFERENCED_PARAMETER(KernelImageBase);
	UNREFERENCED_PARAMETER(KernelImageEnd);

	ShdDebugPrint(DEBUG_LEVEL_MAJOR, "function entry");
	//char abcd[] = { 0xE9, 0x0E, 0xFF, 0xFF, 0xFF };
	//char abcd[] = { 0x56, 0xC2, 0x08, 0x00 };

	ULONG InstLen;

	ud_set_input_buffer(Context->ud_obj, Function, 24);

	// get length of the instruction
	InstLen = ud_disassemble(Context->ud_obj);
	switch (Context->ud_obj->mnemonic)
	{
	case(UD_Ijmp):
		Context->ResultPool[EntryNumber] = TRUE;
		ShdDebugPrint(DEBUG_LEVEL_MAJOR, "function %x at %p is hooked using a jmp", EntryNumber, Function);
		break;
	case(UD_Ipush) :
		ud_set_input_buffer(Context->ud_obj, (PVOID)((SIZE_T)Function + InstLen), 24);
		InstLen = ud_disassemble(Context->ud_obj);
		if (Context->ud_obj->mnemonic == UD_Iret)
		{
			Context->ResultPool[EntryNumber] = TRUE;
			ShdDebugPrint(DEBUG_LEVEL_MAJOR, "function %x at %p is hooked using a push-ret sequence", EntryNumber, Function);
		}
		else
		{
			Context->ResultPool[EntryNumber] = FALSE;
		}
		break;
	default:
		Context->ResultPool[EntryNumber] = FALSE;
		break;
	}
}

NTSTATUS ShdCheckServiceTable(ShdCheckServiceTableCallback Callback, PVOID Context)
{
	ShdDebugPrint(DEBUG_LEVEL_MAJOR, "checking ssdt inline hooks");

	NTSTATUS Status = STATUS_SUCCESS;
	SIZE_T KernelImageSize;
	PVOID KernelBase;
	PVOID KernelImageEnd;
	PVOID CurrentFunction = 0;

	PKESERVICE_DESCRIPTOR_TABLE KeSsdt = ShdGlobalDataRetreiveSsdt();
	if (KeSsdt)
	{
		PULONG NtosServiceTableBase = KeSsdt->Ntoskrnl.ServiceTableBase;
		KernelBase = ShdGlobalDataRetreiveKernelBase();
		Status = ShdKernelGetImageSize(KernelBase, &KernelImageSize);
		if (KernelImageSize && NT_SUCCESS(Status))
		{
			KernelImageEnd = (PVOID)(KernelImageSize + (SIZE_T)KernelBase);
			ShdDebugPrint(DEBUG_LEVEL_MAJOR, "kernel base: %p, kernel end: %p, kernel image size: %x", KernelBase, KernelImageEnd, KernelImageSize);
			for (ULONG i = 0; i < KeSsdt->Ntoskrnl.NumberOfService; i++)
			{
				CurrentFunction = ShdStGetEntry(NtosServiceTableBase, i);
				if (Callback)
				{
					Callback(CurrentFunction, i, KernelBase, KernelImageEnd, Context);
				}
			}
		}
		else
		{
			ShdDebugPrint(DEBUG_LEVEL_MAJOR, "Failed retreiving kernel image size");
		}
	}
	else
	{
		ShdDebugPrint(DEBUG_LEVEL_MAJOR, "Error retreiving ssdt");
	}



	return Status;
}
