#include "shd.h"

#define DEBUG_LEVEL_MAJOR 0
#define DEBUG_LEVEL_WARNING 1
#define DEBUG_LEVEL_MINOR 2

#define DEBUG_LEVEL DEBUG_LEVEL_MAJOR

#ifdef _DEBUG
#pragma push
#pragma warning(disable: 4127)
#define ShdDebugPrint(DebugLevel, format, ...) if (DebugLevel >= DEBUG_LEVEL) {DbgPrint("["DRIVER_NAME"]: " __FUNCTION__ " " format "\n", __VA_ARGS__);}
#pragma pop
#else
#define ShdDebugPrint(format, ...) ;
#endif