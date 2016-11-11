#include "shd.h"

PSHD_GLOBAL_DATA ShdGlobalData;

__inline PKESERVICE_DESCRIPTOR_TABLE ShdGlobalDataRetreiveSsdt()
{
	return (ShdGlobalData->KeServiceDescriptorTable ? ShdGlobalData->KeServiceDescriptorTable : ShdGetKeServiceDescriptorTable());
}

__inline PVOID ShdGlobalDataRetreiveKernelBase()
{
	return (ShdGlobalData->KernelBase ? ShdGlobalData->KernelBase : ShdKernelGetModuleBase("ntoskrnl.exe"));
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	ShdDebugPrint(DEBUG_LEVEL_MAJOR, "Unloading");

	UNICODE_STRING DosDeviceName;

	RtlInitUnicodeString(&DosDeviceName, DEVICE_NAME_SYMOBLIC_LINK);
	IoDeleteSymbolicLink(&DosDeviceName);
	IoDeleteDevice(DriverObject->DeviceObject);

}

NTSTATUS ShdHandleCheckSsdtPointerHook(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIO_STACK_LOCATION StackLocation, _In_ PIRP Irp)
{
	ShdDebugPrint(DEBUG_LEVEL_MAJOR, "function entry");
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS Status = STATUS_SUCCESS;

	PVOID OutputBuffer;

	OutputBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

	if (OutputBuffer && MmGetMdlByteCount(Irp->MdlAddress) >= StackLocation->Parameters.DeviceIoControl.OutputBufferLength)
	{
		if (StackLocation->Parameters.DeviceIoControl.OutputBufferLength >= ShdGetKeServiceDescriptorTable()->Ntoskrnl.NumberOfService * sizeof(BOOLEAN))
		{
			Status = ShdCheckServiceTable(ShdPointerHookCheck, OutputBuffer);
		}
		else
		{
			ShdDebugPrint(DEBUG_LEVEL_MAJOR, "buffer with invalid size passed");
			Status = STATUS_INVALID_PARAMETER;
		}
	}
	else
	{
		ShdDebugPrint(DEBUG_LEVEL_MAJOR, "invalid buffers passed");
		Status = STATUS_INVALID_PARAMETER;
	}

	return Status;
}

NTSTATUS ShdHandleCheckSsdtInlineHook(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIO_STACK_LOCATION StackLocation, _In_ PIRP Irp)
{
	ShdDebugPrint(DEBUG_LEVEL_MAJOR, "function entry");
	NTSTATUS Status = STATUS_SUCCESS;

	SHD_INLINE_HOOK_CHECK_CONTEXT Context;

	PVOID OutputBuffer;

	OutputBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

	if (OutputBuffer && MmGetMdlByteCount(Irp->MdlAddress) >= StackLocation->Parameters.DeviceIoControl.OutputBufferLength)
	{
		if (StackLocation->Parameters.DeviceIoControl.OutputBufferLength >= ShdGetKeServiceDescriptorTable()->Ntoskrnl.NumberOfService * sizeof(BOOLEAN))
		{
			Context.ud_obj = &((PSHD_GLOBAL_DATA)DeviceObject->DeviceExtension)->ud_obj;
			Context.ResultPool = OutputBuffer;
			Status = ShdCheckServiceTable(ShdInlineHookCheck, (PVOID)&Context);
		}
		else
		{
			ShdDebugPrint(DEBUG_LEVEL_MAJOR, "buffer with invalid size passed");
			Status = STATUS_INVALID_PARAMETER;
		}
	}
	else
	{
		ShdDebugPrint(DEBUG_LEVEL_MAJOR, "invalid buffers passed");
		Status = STATUS_INVALID_PARAMETER;
	}

	return Status;
}

NTSTATUS ShdHandleGetSsdtSize(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIO_STACK_LOCATION StackLocation, _In_ PIRP Irp)
{
	ShdDebugPrint(DEBUG_LEVEL_MAJOR, "function entry");
	NTSTATUS Status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(DeviceObject);

	PVOID OutputBuffer;

	OutputBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

	if (OutputBuffer)
	{
		if (StackLocation->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(ULONG))
		{
			*((PULONG)OutputBuffer) = ShdGetKeServiceDescriptorTable()->Ntoskrnl.NumberOfService;
		}
		else
		{
			Status = STATUS_INVALID_PARAMETER;
		}
	}
	else
	{
		Status = STATUS_INVALID_PARAMETER;
	}
	return Status;
}

NTSTATUS ShdDispatchDeviceClose(_Inout_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS Status = STATUS_SUCCESS;

	Irp->IoStatus.Status = Status;
	IofCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}

NTSTATUS ShdDispatchDeviceCreate(_Inout_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS Status = STATUS_SUCCESS;

	Irp->IoStatus.Status = Status;
	IofCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}

NTSTATUS ShdDispatchDeviceControl(_Inout_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	ShdDebugPrint(DEBUG_LEVEL_MAJOR, "function entry");
	PIO_STACK_LOCATION StackLocation;
	NTSTATUS Status = STATUS_SUCCESS;

	StackLocation = IoGetCurrentIrpStackLocation(Irp);
	if (StackLocation)
	{
		switch (StackLocation->Parameters.DeviceIoControl.IoControlCode)
		{
		case (SHD_IOCTL_CHECK_SSDT_POINTERS) :
			ShdDebugPrint(DEBUG_LEVEL_MAJOR, "Handling SHD_IOCTL_CHECK_SSDT_POINTERS");
			ShdHandleCheckSsdtPointerHook(DeviceObject, StackLocation, Irp);
			break;
		case(SHD_IOCTL_CHECK_SSDT_INLINE):
			ShdDebugPrint(DEBUG_LEVEL_MAJOR, "Handling SHD_IOCTL_CHECK_SSDT_INLINE");
			Status = ShdHandleCheckSsdtInlineHook(DeviceObject, StackLocation, Irp);
			break;
		case(SHD_IOCTL_GET_SSDT_SIZE):
			ShdDebugPrint(DEBUG_LEVEL_MAJOR, "Handling SHD_IOCTL_GET_SSDT_SIZE");
			Status = ShdHandleGetSsdtSize(DeviceObject, StackLocation, Irp);
			break;
		default:
			ShdDebugPrint(DEBUG_LEVEL_MAJOR, "Unknown IOCTL");
			Status = STATUS_INVALID_PARAMETER;
			break;
		}

	}

	Irp->IoStatus.Status = Status;
	IofCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}

NTSTATUS ShdInit(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS Status = STATUS_SUCCESS;
	PDEVICE_OBJECT DeviceObject;
	UNICODE_STRING DeviceName;
	UNICODE_STRING SymbolicDeviceName;

	ShdGlobalData = ExAllocatePoolWithTag(NonPagedPool, sizeof(SHD_GLOBAL_DATA), SHD_POOL_TAG);
	RtlZeroMemory(ShdGlobalData, sizeof(SHD_GLOBAL_DATA));
	// perform other init actions

	RtlInitUnicodeString(&DeviceName, DEVICE_NAME_NT);
	Status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, TRUE, &DeviceObject);

	if (NT_SUCCESS(Status))
	{
		RtlInitUnicodeString(&SymbolicDeviceName, DEVICE_NAME_SYMOBLIC_LINK);
		Status = IoCreateSymbolicLink(&SymbolicDeviceName, &DeviceName);

		if (NT_SUCCESS(Status))
		{
			DeviceObject->Flags |= DO_DIRECT_IO;
			DriverObject->DeviceObject = DeviceObject;

			DeviceObject->DeviceExtension = ShdGlobalData;

			// initialize disassembler engine

			ud_init(&ShdGlobalData->ud_obj);

#ifdef _X86_
			UCHAR ud_mode = 32;
#elif _WIN64
			UCHAR ud_mode = 64;
#else
#error "This architecture is not supported"
#endif
			// set mode, syntax and vendor
			ud_set_mode(&ShdGlobalData->ud_obj, ud_mode);
			ud_set_syntax(&ShdGlobalData->ud_obj, UD_SYN_INTEL);
			ud_set_vendor(&ShdGlobalData->ud_obj, UD_VENDOR_INTEL);

			for (size_t i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
			{
				DriverObject->MajorFunction[i] = 0;
			}
			
			DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ShdDispatchDeviceControl;
			DriverObject->MajorFunction[IRP_MJ_CREATE] = ShdDispatchDeviceCreate;
			DriverObject->MajorFunction[IRP_MJ_CLOSE] = ShdDispatchDeviceClose;

		}
	}
	return Status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS Status = STATUS_SUCCESS;

	ShdDebugPrint(DEBUG_LEVEL_MAJOR, "Loading");

	DriverObject->DriverUnload = DriverUnload;

	Status = ShdInit(DriverObject, RegistryPath);

	return Status;
}