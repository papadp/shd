#include "shd.h"

extern PVOID ShdStGetEntry(PULONG ServiceTableBase, ULONG Entry);

typedef VOID(*ShdCheckServiceTableCallback)(PVOID Function, ULONG EntryNumber, PVOID KernelImageBase, PVOID KernelImageEnd, PVOID Context);
NTSTATUS ShdCheckServiceTable(ShdCheckServiceTableCallback Callback, PVOID Context);

typedef struct _SHD_INLINE_HOOK_CHECK_CONTEXT
{
	ud_t* ud_obj;
	PBOOLEAN ResultPool;
}SHD_INLINE_HOOK_CHECK_CONTEXT, *PSHD_INLINE_HOOK_CHECK_CONTEXT;

VOID ShdPointerHookCheck(PVOID Function, ULONG EntryNumber, PVOID KernelImageBase, PVOID KernelImageEnd, PVOID Context);
VOID ShdInlineHookCheck(PVOID Function, ULONG EntryNumber, PVOID KernelImageBase, PVOID KernelImageEnd, PSHD_INLINE_HOOK_CHECK_CONTEXT Context);