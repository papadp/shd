#define SHD_UM

#define SHD_BASE_NAME L"shd.sys"
#define SHD_SERVICE_NAME L"shdsvc"
#define SHD_DISPLAY_NAME L"Shd Service"

#define SHD_DEVICE_NAME L"\\\\.\\shd"

#define HANDLE_CHECK(_handle_) _handle_ && _handle_ != INVALID_HANDLE_VALUE

struct SHD_DRIVER_RESOURCE
{
	LPWSTR Name;
	WORD ResourceId;
};

#define SHD_RESOURCE_DRV_7_32 {L"DRV7_32", (WORD)103}
#define SHD_RESOURCE_DRV_7_64 {L"DRV7_64", (WORD)106}

extern SHD_DRIVER_RESOURCE DriverResource732Bit;
extern SHD_DRIVER_RESOURCE DriverResource764Bit;
