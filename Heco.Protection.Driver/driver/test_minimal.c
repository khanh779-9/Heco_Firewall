/*++
    Minimal test driver for Heco Firewall
    Just returns STATUS_SUCCESS from DriverEntry.
--*/

#include <ntddk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     DriverUnload;

NTSTATUS DriverEntry(
    PDRIVER_OBJECT  DriverObject,
    PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "HecoTest: Minimal test driver loaded successfully!\n");

    DriverObject->DriverUnload = DriverUnload;

    return STATUS_SUCCESS;
}

VOID DriverUnload(
    PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "HecoTest: Driver unloaded\n");
}
