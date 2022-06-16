#include "Hooks.h"
#include <fltKernel.h>

namespace Hooks
{
	PVOID gh_ExAllocatePoolWithTag(
		POOL_TYPE PoolType,
		SIZE_T NumberOfBytes,
		ULONG Tag
	) {
		const int WhiteListSize = 1000;
		static void* WhiteList[WhiteListSize]{};
		static int size = 0;
		void* ReturnAddress = _ReturnAddress();

		for (int i = 0; i < size; i++) {
			if (WhiteList[i] == ReturnAddress) {
				return ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);
			}
		}
		if (PoolType == 1 && NumberOfBytes == 24) {
			DBG_PRINT("ExAllocatePoolWithTag called from: 0x%p rejected!", ReturnAddress);
			return nullptr;
		}
		else {
			if (size < WhiteListSize) {
				WhiteList[size++] = ReturnAddress;
				return ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);
			}
			else {
				DBG_PRINT("ExAllocatePoolWithTag WhiteList is full");
				return nullptr;
			}
		}
	}

	PVOID gh_ExAllocatePool(
		POOL_TYPE PoolType,
		SIZE_T NumberOfBytes
	) {
		const int WhiteListSize = 1000;
		static void* WhiteList[WhiteListSize]{};
		static int size = 0;
		void* ReturnAddress = _ReturnAddress();

		for (int i = 0; i < size; i++) {
			if (WhiteList[i] == ReturnAddress) {
				return ExAllocatePool(PoolType, NumberOfBytes);
			}
		}
		if (PoolType == 1 && NumberOfBytes == 24) {
			DBG_PRINT("ExAllocatePool called from: 0x%p rejected!", ReturnAddress);
			return nullptr;
		}
		else {
			if (size < WhiteListSize) {
				WhiteList[size++] = ReturnAddress;
				return ExAllocatePool(PoolType, NumberOfBytes);
			}
			else {
				DBG_PRINT("ExAllocatePool WhiteList is full");
				return nullptr;
			}
		}
	}

    PVOID gh_MmGetSystemRoutineAddress(
        PUNICODE_STRING SystemRoutineName
    )
    {
        DBG_PRINT("MmGetSystemRoutineAddress: %ws", SystemRoutineName->Buffer);
        if (wcsstr(SystemRoutineName->Buffer, L"ExAllocatePoolWithTag"))
        {
            DBG_PRINT("Hooking ExAllocatePoolWithTag...");
            return &gh_ExAllocatePoolWithTag;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"ExAllocatePool"))
        {
            DBG_PRINT("Hooking ExAllocatePool...");
            return &gh_ExAllocatePool;
        }
        return MmGetSystemRoutineAddress(SystemRoutineName);
    }

    VOID LoadImageNotifyRoutine(
        PUNICODE_STRING FullImageName,
        HANDLE ProcessId,
        PIMAGE_INFO ImageInfo
    )
    {
        if (!ProcessId && FullImageName && wcsstr(FullImageName->Buffer, L"BEDaisy.sys"))
        {
            DBG_PRINT("> ============= Driver %ws ================", FullImageName->Buffer);
            DriverUtil::IATHook(
                ImageInfo->ImageBase,
                "MmGetSystemRoutineAddress",
                &gh_MmGetSystemRoutineAddress
            );
        }
    }
}