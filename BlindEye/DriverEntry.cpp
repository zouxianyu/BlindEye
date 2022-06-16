#include "Types.h"
#include "DriverUtil.h"
#include "Hooks.h"

using namespace DriverUtil;
using namespace Hooks;

void TdDeviceUnload(
    DRIVER_OBJECT* DriverObject
)
{
    PsRemoveLoadImageNotifyRoutine(&LoadImageNotifyRoutine);
}

NTSTATUS TdDeviceClose(
    IN PDEVICE_OBJECT  DeviceObject,
    IN PIRP  Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

extern "C"
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = &TdDeviceClose;
    DriverObject->DriverUnload = &TdDeviceUnload;

    PsSetLoadImageNotifyRoutine(&LoadImageNotifyRoutine);
	DBG_PRINT("Installed ImageNotifyRoutine... 0x%p", &LoadImageNotifyRoutine);
    return STATUS_SUCCESS;
}