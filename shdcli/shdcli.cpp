// shdcli.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

SHD_DRIVER_RESOURCE DriverResource732Bit = SHD_RESOURCE_DRV_7_32;
SHD_DRIVER_RESOURCE DriverResource764Bit = SHD_RESOURCE_DRV_7_64;

/*
	Taken from: http://stackoverflow.com/questions/2140619/correct-way-to-check-if-windows-is-64-bit-or-not-on-runtime-c
*/
BOOL Is64BitWindows()
{
#if defined(_WIN64)
	return TRUE;  // 64-bit programs run only on Win64
#elif defined(_WIN32)
	// 32-bit programs run on both 32-bit and 64-bit Windows
	// so must sniff
	BOOL f64 = FALSE;
	return IsWow64Process(GetCurrentProcess(), &f64) && f64;
#else
	return FALSE; // Win64 does not support Win16
#endif
}

BOOL ExtractResource(SHD_DRIVER_RESOURCE* DriverResource, LPWSTR lpszOutputPath)
{
	HRSRC Rsrc;
	HGLOBAL Global;
	LPVOID Lock;
	BOOL Return = true;
	DWORD Size;
	HANDLE File;
	DWORD BytesWritten;

	Rsrc = FindResourceW(GetModuleHandleA(NULL), MAKEINTRESOURCEW(DriverResource->ResourceId), DriverResource->Name);
	if (HANDLE_CHECK(Rsrc))
	{
		Global = LoadResource(NULL, Rsrc);
		if (HANDLE_CHECK(Global))
		{
			Lock = LockResource(Global);
			if (Lock)
			{
				Size = SizeofResource(NULL, Rsrc);
				File = CreateFileW(lpszOutputPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
				if (HANDLE_CHECK(File))
				{
					if (!WriteFile(File, Lock, Size, &BytesWritten, NULL))
					{
						Return = false;
					}
					CloseHandle(File);
				}
				else
				{
					Return = false;
				}
			}
			else
			{
				Return = false;
			}
			FreeResource(Global);
		}
		else
		{
			Return = false;
		}
	}
	else
	{
		Return = false;
	}

	return Return;
}

BOOL ShdInstallService()
{
	SC_HANDLE SCManager;
	SC_HANDLE Service;

	wchar_t DriverOutFormat[MAX_PATH] = { 0x00 };
	wchar_t DriverOutDestination[MAX_PATH] = { 0x00 };

	SHD_DRIVER_RESOURCE DriverResource;

	BOOL Is64Bit;
	BOOL Return = true;

	if (!ExpandEnvironmentStringsW(L"%windir%\\system32\\drivers\\%s", DriverOutFormat, MAX_PATH))
	{
		wprintf(L"Error expanding environment strings.\n");
		return false;
	}
	if (!wsprintfW(DriverOutDestination, DriverOutFormat, SHD_BASE_NAME))
	{
		wprintf(L"Error formatting out path.\n");
		return false;
	}
	if (!(IsWindows7OrGreater() && !IsWindows8OrGreater())) // shd hasn't been tested on anything other then windows 7
	{
		wprintf(L"Windows version isn't supported, currently only windows 7 is supported.\n");
		return false;
	}

	Is64Bit = Is64BitWindows();

	DriverResource = Is64Bit ? DriverResource764Bit : DriverResource732Bit;

#ifdef _X86_
	if (Is64Bit)
	{
		if (!Wow64EnableWow64FsRedirection(FALSE))
		{
			wprintf(L"Couldnt disable fs redirection.\n");
			return false;
		}
	}
#endif

	if (!ExtractResource(&DriverResource, DriverOutDestination))
	{
		wprintf(L"Failed extracting the driver,\n");
		return false;
	}

#ifdef _X86_
	if (Is64Bit)
	{
		Wow64EnableWow64FsRedirection(FALSE);
	}
#endif

	SCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (HANDLE_CHECK(SCManager))
	{
		Service = CreateServiceW(SCManager, SHD_SERVICE_NAME, SHD_DISPLAY_NAME, SC_MANAGER_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_SYSTEM_START, SERVICE_ERROR_IGNORE, DriverOutDestination, NULL, NULL, NULL, NULL, NULL);
		if (HANDLE_CHECK(Service))
		{
			if (!StartServiceW(Service, 0, NULL))
			{
				wprintf(L"Service failed to start, error: %d.\n", GetLastError());
				Return = false;
			}
			CloseServiceHandle(Service);
		}
		else
		{
			wprintf(L"Could not create service, error: %d.\n", GetLastError());
			Return = false;
		}

		CloseServiceHandle(SCManager);
	}
	else
	{
		wprintf(L"Failed opening SCManager, error: %d.\n", GetLastError());
		Return = false;
	}
	
	if (Return)
	{
		wprintf(L"[+] Successfully loaded\n");
	}
	else
	{
		wprintf(L"[+] Failed to load\n");
	}

	return Return;
}

BOOL ShdUninstallService()
{
	SC_HANDLE SCManager;
	SC_HANDLE Service;

	SERVICE_STATUS ServiceStatus;

	BOOL Return = true;

	SCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (HANDLE_CHECK(SCManager))
	{
		Service = OpenServiceW(SCManager, SHD_SERVICE_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS | DELETE);
		if (HANDLE_CHECK(Service))
		{
			if (ControlService(Service, SERVICE_CONTROL_STOP, &ServiceStatus))
			{
				if (!DeleteService(Service))
				{
					wprintf(L"Failed to delete service, error: %d.\n", GetLastError());
					Return = false;
				}
			}
			else
			{
				wprintf(L"Failed to stop service, error: %d.\n", GetLastError());
				Return = false;
			}
		}
		else
		{
			wprintf(L"Failed opening service for stop, error: %d.\n", GetLastError());
			Return = false;
		}
	}
	else
	{
		wprintf(L"Failed opening SCManager for stop, error: %d.\n", GetLastError());
		Return = false;
	}

	if (Return)
	{
		wprintf(L"[-] Successfully cleaned up\n");
	}
	else
	{
		wprintf(L"[-] Failed to clean up\n");
	}

	return true;
}

bool ShdCheckAllHooks()
{
	BOOL Return = true;

	HANDLE DeviceHandle;

	ULONG SsdtSize;
	ULONG BytesReturned;
	PBOOL ResultPool;
	ULONG PoolSize;

	DeviceHandle = CreateFileW(SHD_DEVICE_NAME, FILE_ALL_ACCESS, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_DEVICE, NULL);



	if (HANDLE_CHECK(DeviceHandle))
	{
		if (DeviceIoControl(DeviceHandle, SHD_IOCTL_GET_SSDT_SIZE, NULL, 0, &SsdtSize, sizeof(SsdtSize), &BytesReturned, NULL))
		{
			PoolSize = SsdtSize * sizeof(BOOL);
			ResultPool = (PBOOL)malloc(PoolSize);
			memset(ResultPool, 0, PoolSize);
			wprintf(L"\t[+] Performing pointer scan\n");
			if (DeviceIoControl(DeviceHandle, SHD_IOCTL_CHECK_SSDT_POINTERS, NULL, 0, ResultPool, PoolSize, &BytesReturned, NULL))
			{
				for (size_t i = 0; i < SsdtSize; i++)
				{
					if (ResultPool[i])
					{
						wprintf(L"\t\t[!] Function %d is hooked\n", i);
					}
				}
			}
			else
			{
				wprintf(L"Failed to communicate with device\n");
				Return = false;
			}
			wprintf(L"\t[-] Finished pointer scan\n");

			wprintf(L"\t[+] Performing inline scan\n");
			if (DeviceIoControl(DeviceHandle, SHD_IOCTL_CHECK_SSDT_INLINE, NULL, 0, ResultPool, PoolSize, &BytesReturned, NULL))
			{
				for (size_t i = 0; i < SsdtSize; i++)
				{
					if (ResultPool[i])
					{
						wprintf(L"\t\t[!] Function %d is hooked\n", i);
					}
				}
			}
			else
			{
				wprintf(L"Failed to communicate with device\n");
				Return = false;
			}
			wprintf(L"\t[-] Finished inline scan\n");

		}
		else
		{
			wprintf(L"Failed to communicate with device\n");
			Return = false;
		}
		CloseHandle(DeviceHandle);
	}
	else
	{
		wprintf(L"Failed to open device handle\n");
		Return = false;
	}

	return Return;
}

int _tmain(int argc, _TCHAR* argv[])
{
	if (argc > 1)
	{
		if (!lstrcmpW(argv[1], L"/u")) // this switch will just uninstall shd - this is incase a previous uninstall has failed
		{
			ShdUninstallService();
			return 0;
		}
		if (!lstrcmpW(argv[1], L"/i")) // install only
		{
			ShdInstallService();
			return 0;
		}
		if (!lstrcmpW(argv[1], L"/c")) // communicate only
		{
			ShdCheckAllHooks();
			return 0;
		}
	}

	if (ShdInstallService())
	{
		ShdCheckAllHooks();
		ShdUninstallService();
	}
	
	return 0;
}

