#pragma once
#include "Types.h"
#include "DriverUtil.h"

namespace Hooks
{
    BOOLEAN gh_ExEnumHandleTable(
        PVOID HandleTable,
        PVOID EnumHandleProcedure,
        PVOID EnumParameter,
        PHANDLE Handle OPTIONAL
    );

    NTSTATUS gh_ZwAllocateVirtualMemory(
        _In_    HANDLE    ProcessHandle,
        _Inout_ PVOID* BaseAddress,
        _In_    ULONG_PTR ZeroBits,
        _Inout_ PSIZE_T   RegionSize,
        _In_    ULONG     AllocationType,
        _In_    ULONG     Protect
    );

    NTSTATUS gh_PsSetLoadImageNotifyRoutine(
        PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
    );

    NTSTATUS gh_ObRegisterCallbacks(
        POB_CALLBACK_REGISTRATION CallbackRegistration,
        PVOID* RegistrationHandle
    );

    NTSTATUS gh_ZwQuerySystemInformation(
        _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
        _Inout_   PVOID                    SystemInformation,
        _In_      ULONG                    SystemInformationLength,
        _Out_opt_ PULONG                   ReturnLength
    );

    NTSTATUS gh_PsSetCreateProcessNotifyRoutineEx(
        PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine,
        BOOLEAN                           Remove
    );

    NTSTATUS gh_IoCreateDevice(
        PDRIVER_OBJECT  DriverObject,
        ULONG           DeviceExtensionSize,
        PUNICODE_STRING DeviceName,
        DEVICE_TYPE     DeviceType,
        ULONG           DeviceCharacteristics,
        BOOLEAN         Exclusive,
        PDEVICE_OBJECT* DeviceObject
    );

    NTSTATUS gh_PsSetCreateThreadNotifyRoutine(
        PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine
    );

    PHYSICAL_ADDRESS gh_MmGetPhysicalAddress(
        PVOID BaseAddress
    );

    BOOLEAN gh_MmIsAddressValid(
        PVOID VirtualAddress
    );

    NTSTATUS gh_ZwDeviceIoControlFile(
        HANDLE           FileHandle,
        HANDLE           Event,
        PIO_APC_ROUTINE  ApcRoutine,
        PVOID            ApcContext,
        PIO_STATUS_BLOCK IoStatusBlock,
        ULONG            IoControlCode,
        PVOID            InputBuffer,
        ULONG            InputBufferLength,
        PVOID            OutputBuffer,
        ULONG            OutputBufferLength
    );

    VOID gh_RtlInitAnsiString(
        PANSI_STRING          DestinationString,
        PCSZ SourceString
    );

    VOID gh_RtlInitUnicodeString(
        PUNICODE_STRING         DestinationString,
        PCWSTR SourceString
    );

    PVOID gh_MmMapIoSpace(
        PHYSICAL_ADDRESS    PhysicalAddress,
        SIZE_T              NumberOfBytes,
        MEMORY_CACHING_TYPE CacheType
    );

    NTSTATUS gh_ZwOpenFile(
        PHANDLE            FileHandle,
        ACCESS_MASK        DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PIO_STATUS_BLOCK   IoStatusBlock,
        ULONG              ShareAccess,
        ULONG              OpenOptions
    );

    void gh_KeStackAttachProcess(
        PRKPROCESS   PROCESS,
        PRKAPC_STATE ApcState
    );

    NTSTATUS gh_ZwCreateSection(
        PHANDLE            SectionHandle,
        ACCESS_MASK        DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PLARGE_INTEGER     MaximumSize,
        ULONG              SectionPageProtection,
        ULONG              AllocationAttributes,
        HANDLE             FileHandle
    );

    NTSTATUS gh_ObOpenObjectByName(
        __in POBJECT_ATTRIBUTES ObjectAttributes,
        __in_opt POBJECT_TYPE ObjectType,
        __in KPROCESSOR_MODE AccessMode,
        __inout_opt PACCESS_STATE AccessState,
        __in_opt ACCESS_MASK DesiredAccess,
        __inout_opt PVOID ParseContext,
        __out PHANDLE Handle
    );

    NTSTATUS gh_ZwMapViewOfSection(
        HANDLE          SectionHandle,
        HANDLE          ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR       ZeroBits,
        SIZE_T          CommitSize,
        PLARGE_INTEGER  SectionOffset,
        PSIZE_T         ViewSize,
        SECTION_INHERIT InheritDisposition,
        ULONG           AllocationType,
        ULONG           Win32Protect
    );

    NTSTATUS gh_MmCopyVirtualMemory
    (
        PEPROCESS SourceProcess,
        PVOID SourceAddress,
        PEPROCESS TargetProcess,
        PVOID TargetAddress,
        SIZE_T BufferSize,
        KPROCESSOR_MODE PreviousMode,
        PSIZE_T ReturnSize
    );

    void gh_IofCompleteRequest(
        PIRP  Irp,
        CCHAR PriorityBoost
    );

    PVOID gh_MmGetSystemRoutineAddress(
        PUNICODE_STRING SystemRoutineName
    );

    PVOID gh_FltGetRoutineAddress(
        PCSTR FltMgrRoutineName
    );

    VOID gh_KeBugCheckEx(
        ULONG     BugCheckCode,
        ULONG_PTR BugCheckParameter1,
        ULONG_PTR BugCheckParameter2,
        ULONG_PTR BugCheckParameter3,
        ULONG_PTR BugCheckParameter4
    );

    int gh_strnicmp(
        const char* string1,
        const char* string2,
        size_t count
    );

    int gh_stricmp(
        const char* string1,
        const char* string2
    );

    VOID LoadImageNotifyRoutine(
        PUNICODE_STRING FullImageName,
        HANDLE ProcessId,
        PIMAGE_INFO ImageInfo
    );
}