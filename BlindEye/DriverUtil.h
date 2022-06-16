#pragma once
#include <intrin.h>
#include "Types.h"
#include "Memory.h"

namespace DriverUtil
{
	PDRIVER_OBJECT GetDriverObject(PUNICODE_STRING lpDriverName);
	PVOID GetDriverBase(LPCSTR module_name);
	PVOID IATHook(PVOID lpBaseAddress, CHAR* lpcStrImport, PVOID lpFuncAddress);
	PVOID DriverIATHook(PDRIVER_OBJECT pDriverObject, CHAR* lpcStrImport, PVOID lpFuncAddress);

	PVOID GetSystemModuleExport(LPCSTR ModName, LPCSTR RoutineName);
	VOID DumpDriver(PVOID lpBaseAddress);
	VOID DumpDriver(PDRIVER_OBJECT lpDriverObject);
	void MemDump(void* BaseAddress, unsigned Size);
}