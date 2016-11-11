#include "shd.h"

typedef struct _KSYSTEM_SERVICE_TABLE
{
	PULONG  ServiceTableBase;
	PULONG  ServiceCounterTableBase;
	ULONG   NumberOfService;
	PVOID   ParamTableBase;
}KSYSTEM_SERVICE_TABLE, *PKSYSTEM_SERVICE_TABLE;

typedef struct _KESERVICE_DESCRIPTOR_TABLE
{
	KSYSTEM_SERVICE_TABLE   Ntoskrnl;
	KSYSTEM_SERVICE_TABLE   Win32k;
	KSYSTEM_SERVICE_TABLE   NotUsed1;
	KSYSTEM_SERVICE_TABLE   NotUsed2;
}KESERVICE_DESCRIPTOR_TABLE, *PKESERVICE_DESCRIPTOR_TABLE;

/*
Taken from: https://github.com/Cr4sh/fwexpl/blob/master/src/driver/src/common.cpp
*/
PVOID ShdGetSysInf(SYSTEM_INFORMATION_CLASS InfoClass);

/*
Taken from: http://www.kernelmode.info/forum/viewtopic.php?f=14&t=1146&hilit=keservicedescriptor#p8660
*/
PKESERVICE_DESCRIPTOR_TABLE ShdGetKeServiceDescriptorTable(void);