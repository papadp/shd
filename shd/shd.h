#pragma once
#include "ntddk.h"
#include "udis86.h"
#include "ntimage.h"
#include "undocnt.h"

#include "dbg.h"
#include "kepe.h"
#include "kesys.h"
#include "ssdt.h"
#include "shdcc.h"


#define DRIVER_NAME "shd.sys"

#define DEVICE_NAME L"shd"
#define DEVICE_NAME_NT L"\\Device\\" DEVICE_NAME
#define DEVICE_NAME_SYMOBLIC_LINK L"\\DosDevices\\" DEVICE_NAME

#define SHD_POOL_TAG 'dhs.'

#define SHD_SYS


#define RVATOVA(_base_, _offset_) ((PUCHAR)(_base_) + (ULONG)(_offset_))

// global data struct to keep track of information already gathered
// so that we don't perform the same actions twice

typedef struct _SHD_GLOBAL_DATA
{
	PKESERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;
	PVOID KernelBase;
	ud_t ud_obj;
}SHD_GLOBAL_DATA, *PSHD_GLOBAL_DATA;

extern PSHD_GLOBAL_DATA ShdGlobalData;

extern PKESERVICE_DESCRIPTOR_TABLE ShdGlobalDataRetreiveSsdt();
extern PVOID ShdGlobalDataRetreiveKernelBase();