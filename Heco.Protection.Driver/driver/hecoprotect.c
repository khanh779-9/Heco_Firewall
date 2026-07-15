/*++
Module Name: hecoprotect.c
Abstract:   Heco Firewall Self-Defense Kernel Driver

Protects the Heco Firewall process from being terminated or tampered with
by using ObRegisterCallbacks to intercept and block dangerous handle operations.

Usage:
    - User-mode app sends its PID + protection level via IOCTL
    - Driver blocks PROCESS_TERMINATE, PROCESS_SUSPEND_RESUME, etc.
    - Protection is removed when driver unloads or via UNPROTECT IOCTL

Based on Microsoft ObCallback sample (MS-PL).
--*/

#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>
#include "shared.h"

// Process access rights (defined in winnt.h but may not be included in kernel mode)
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE                  (0x0001)
#define PROCESS_CREATE_THREAD              (0x0002)
#define PROCESS_VM_OPERATION               (0x0008)
#define PROCESS_VM_READ                    (0x0010)
#define PROCESS_VM_WRITE                   (0x0020)
#define PROCESS_DUP_HANDLE                 (0x0040)
#define PROCESS_SET_QUOTA                  (0x0100)
#define PROCESS_SET_INFORMATION            (0x0200)
#define PROCESS_QUERY_INFORMATION          (0x0400)
#define PROCESS_SUSPEND_RESUME             (0x0800)
#endif

// Thread access rights
#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE                   (0x0001)
#define THREAD_SUSPEND_RESUME              (0x0002)
#define THREAD_SET_CONTEXT                 (0x0010)
#define THREAD_SET_INFORMATION             (0x0020)
#define THREAD_QUERY_INFORMATION           (0x0040)
#endif

// =========================================================================
//  Globals
// =========================================================================

static PDEVICE_OBJECT           g_DeviceObject      = NULL;
static PVOID                    g_RegistrationHandle = NULL;
static BOOLEAN                  g_CallbacksInstalled = FALSE;

// Protected process info
static volatile LONG            g_ProtectedPid      = 0;
static volatile LONG            g_ProtectionLevel   = HECO_PROTECT_LEVEL_NONE;
static WCHAR                    g_ProtectedPath[HECO_NAME_SIZE + 1] = {0};

// Process notify registration
static BOOLEAN                  g_ProcessNotifySet  = FALSE;

// Statistics
static volatile LONG            g_BlockedAttempts   = 0;

// Mutex for path protection
static KGUARDED_MUTEX           g_PathMutex;

// Forward declarations
static NTSTATUS HecoInstallCallbacks();

// =========================================================================
//  Forward declarations
// =========================================================================

DRIVER_INITIALIZE               DriverEntry;
DRIVER_UNLOAD                   HecoUnload;
_Dispatch_type_(IRP_MJ_CREATE)  DRIVER_DISPATCH HecoCreateClose;
_Dispatch_type_(IRP_MJ_CLOSE)   DRIVER_DISPATCH HecoCreateClose;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH HecoDeviceControl;

static NTSTATUS HecoCreateDevice(PDRIVER_OBJECT DriverObject);
static VOID     HecoDeleteDevice();

static OB_PREOP_CALLBACK_STATUS
HecoPreOperationCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION PreInfo);

static VOID
HecoPostOperationCallback(
    PVOID RegistrationContext,
    POB_POST_OPERATION_INFORMATION PostInfo);

static VOID
HecoCreateProcessNotifyRoutine(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo);

static BOOLEAN HecoIsProcessProtected(PEPROCESS Process);
static BOOLEAN HecoMatchPathByName(PCUNICODE_STRING ImageFileName);

// =========================================================================
//  Driver Entry
// =========================================================================

NTSTATUS
DriverEntry(
    PDRIVER_OBJECT  DriverObject,
    PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "HecoProtect: DriverEntry - loading Heco Firewall self-defense driver\n");

    //
    // Initialize synchronization
    //
    KeInitializeGuardedMutex(&g_PathMutex);

    //
    // Set dispatch routines
    //
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = HecoCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = HecoCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HecoDeviceControl;
    DriverObject->DriverUnload                         = HecoUnload;

    //
    // Create device
    //
    status = HecoCreateDevice(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "HecoProtect: Failed to create device: 0x%08X\n", status);
        return status;
    }

    //
    // Register process creation notification (optional)
    // Requires WHQL/Attestation signature on Windows 11 24H2+.
    // If it fails, the driver still loads but won't auto-protect processes.
    //
    status = PsSetCreateProcessNotifyRoutineEx(HecoCreateProcessNotifyRoutine, FALSE);
    if (NT_SUCCESS(status)) {
        g_ProcessNotifySet = TRUE;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "HecoProtect: Process notify registered\n");
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "HecoProtect: Process notify not available (0x%08X) - continuing\n", status);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "HecoProtect: Driver loaded successfully\n");

    return STATUS_SUCCESS;
}

// =========================================================================
//  Driver Unload
// =========================================================================

VOID
HecoUnload(
    PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "HecoProtect: Unloading - removing protection\n");

    //
    // Remove OB callbacks
    //
    if (g_CallbacksInstalled) {
        ObUnRegisterCallbacks(g_RegistrationHandle);
        g_CallbacksInstalled = FALSE;
        g_RegistrationHandle = NULL;
    }

    //
    // Unregister process notify
    //
    if (g_ProcessNotifySet) {
        PsSetCreateProcessNotifyRoutineEx(HecoCreateProcessNotifyRoutine, TRUE);
        g_ProcessNotifySet = FALSE;
    }

    //
    // Delete device
    //
    HecoDeleteDevice();

    g_ProtectedPid = 0;
    g_ProtectionLevel = HECO_PROTECT_LEVEL_NONE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "HecoProtect: Driver unloaded, attempts blocked: %ld\n",
        InterlockedCompareExchange(&g_BlockedAttempts, 0, 0));
}

// =========================================================================
//  Device I/O
// =========================================================================

NTSTATUS
HecoCreateClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS
HecoDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
    PIO_STACK_LOCATION irpStack;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG ioctlCode;
    ULONG inputLen, outputLen;
    PVOID systemBuf;

    UNREFERENCED_PARAMETER(DeviceObject);

    irpStack = IoGetCurrentIrpStackLocation(Irp);
    ioctlCode  = irpStack->Parameters.DeviceIoControl.IoControlCode;
    inputLen   = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    outputLen  = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
    systemBuf  = Irp->AssociatedIrp.SystemBuffer;

    Irp->IoStatus.Information = 0;

    switch (ioctlCode)
    {
    case HECO_IOCTL_PROTECT_PID:
    {
        //
        // Protect a specific process by PID
        //
        PHECO_PROTECT_PID_INPUT input = (PHECO_PROTECT_PID_INPUT)systemBuf;
        if (inputLen < sizeof(HECO_PROTECT_PID_INPUT) || input == NULL) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (input->ProtectionLevel > HECO_PROTECT_LEVEL_HARDENED) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        //
        // Set the protected PID
        //
        InterlockedExchange(&g_ProtectedPid, input->ProcessId);
        InterlockedExchange(&g_ProtectionLevel, input->ProtectionLevel);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "HecoProtect: Protecting PID %lu at level %lu\n",
            input->ProcessId, input->ProtectionLevel);

        //
        // Install OB callbacks if not already installed
        //
        if (!g_CallbacksInstalled) {
            HecoInstallCallbacks();
        }
        if (!g_CallbacksInstalled) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "HecoProtect: OB callbacks unavailable - PID set but filtering disabled\n");
        }

        break;
    }

    case HECO_IOCTL_UNPROTECT:
    {
        //
        // Remove protection
        //
        if (g_CallbacksInstalled) {
            ObUnRegisterCallbacks(g_RegistrationHandle);
            g_CallbacksInstalled = FALSE;
            g_RegistrationHandle = NULL;
        }

        InterlockedExchange(&g_ProtectedPid, 0);
        InterlockedExchange(&g_ProtectionLevel, HECO_PROTECT_LEVEL_NONE);
        RtlZeroMemory(g_ProtectedPath, sizeof(g_ProtectedPath));

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "HecoProtect: Protection removed\n");
        break;
    }

    case HECO_IOCTL_QUERY_STATUS:
    {
        //
        // Return current protection status
        //
        PHECO_STATUS_OUTPUT output = (PHECO_STATUS_OUTPUT)systemBuf;
        if (outputLen < sizeof(HECO_STATUS_OUTPUT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        output->Active          = g_CallbacksInstalled;
        output->ProtectedPid    = (ULONG)InterlockedCompareExchange(&g_ProtectedPid, 0, 0);
        output->ProtectionLevel = (ULONG)InterlockedCompareExchange(&g_ProtectionLevel, 0, 0);
        output->BlockedAttempts = (ULONG)InterlockedCompareExchange(&g_BlockedAttempts, 0, 0);
        Irp->IoStatus.Information = sizeof(HECO_STATUS_OUTPUT);
        break;
    }

    case HECO_IOCTL_PROTECT_PATH:
    {
        //
         // Protect by image path match (for future auto-protect)
         //
        PHECO_PROTECT_PATH_INPUT input = (PHECO_PROTECT_PATH_INPUT)systemBuf;
        if (inputLen < sizeof(HECO_PROTECT_PATH_INPUT) || input == NULL) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        KeAcquireGuardedMutex(&g_PathMutex);
        RtlCopyMemory(g_ProtectedPath, input->ImagePath, sizeof(g_ProtectedPath));
        g_ProtectedPath[FIELD_OFFSET(HECO_PROTECT_PATH_INPUT, ImagePath) /
                        sizeof(WCHAR) + HECO_NAME_SIZE] = L'\0';
        if (input->ProtectionLevel > 0) {
            InterlockedExchange(&g_ProtectionLevel, input->ProtectionLevel);
        }
        KeReleaseGuardedMutex(&g_PathMutex);
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// =========================================================================
//  Callback Installation
// =========================================================================

static NTSTATUS HecoInstallCallbacks()
{
    NTSTATUS status;
    OB_CALLBACK_REGISTRATION obReg = {0};
    OB_OPERATION_REGISTRATION opReg[2] = {{0}, {0}};
    UNICODE_STRING altitude;

    //
    // Register for process handle operations
    //
    opReg[0].ObjectType   = PsProcessType;
    opReg[0].Operations   = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg[0].PreOperation = HecoPreOperationCallback;
    opReg[0].PostOperation = HecoPostOperationCallback;

    //
    // Also register for thread handle operations (to prevent thread injection)
    //
    opReg[1].ObjectType   = PsThreadType;
    opReg[1].Operations   = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg[1].PreOperation = HecoPreOperationCallback;
    opReg[1].PostOperation = HecoPostOperationCallback;

    //
    // Our altitude: 370030 (in the "Anti-Virus" range, suitable for security products)
    //
    RtlInitUnicodeString(&altitude, L"370030");

    obReg.Version                    = OB_FLT_REGISTRATION_VERSION;
    obReg.OperationRegistrationCount = 2;
    obReg.Altitude                   = altitude;
    obReg.RegistrationContext        = NULL;
    obReg.OperationRegistration      = opReg;

    status = ObRegisterCallbacks(&obReg, &g_RegistrationHandle);
    if (NT_SUCCESS(status)) {
        g_CallbacksInstalled = TRUE;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "HecoProtect: OB callbacks installed at altitude 370030\n");
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "HecoProtect: ObRegisterCallbacks not available (0x%08X) - continuing\n", status);
    }

    return STATUS_SUCCESS;
}

// =========================================================================
//  Pre-Operation Callback (core protection logic)
// =========================================================================

OB_PREOP_CALLBACK_STATUS
HecoPreOperationCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION PreInfo)
{
    ACCESS_MASK accessToClear = 0;
    PACCESS_MASK desiredAccess = NULL;
    PEPROCESS targetProcess = NULL;
    BOOLEAN isProtected = FALSE;

    UNREFERENCED_PARAMETER(RegistrationContext);

    //
    // Quick check - is any process protected?
    //
    if (g_ProtectedPid == 0) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Handle process object
    //
    if (PreInfo->ObjectType == *PsProcessType) {
        targetProcess = (PEPROCESS)PreInfo->Object;

        //
        // Check if this is our protected process
        //
        isProtected = HecoIsProcessProtected(targetProcess);
        if (!isProtected) {
            return OB_PREOP_SUCCESS;
        }

        //
        // Ignore if the requesting process is our own protected process
        // (it should be able to open itself)
        //
        if (targetProcess == PsGetCurrentProcess()) {
            return OB_PREOP_SUCCESS;
        }

        //
        // Determine which access rights to block based on protection level
        //
        ULONG level = (ULONG)InterlockedCompareExchange(&g_ProtectionLevel, 0, 0);

        switch (level) {
        case HECO_PROTECT_LEVEL_HARDENED:
            accessToClear |= PROCESS_VM_READ;
            accessToClear |= PROCESS_VM_WRITE;
            accessToClear |= PROCESS_VM_OPERATION;
            accessToClear |= PROCESS_SET_INFORMATION;
            accessToClear |= PROCESS_QUERY_INFORMATION;
            accessToClear |= PROCESS_DUP_HANDLE;
            accessToClear |= PROCESS_SUSPEND_RESUME;
            accessToClear |= PROCESS_TERMINATE;
            accessToClear |= PROCESS_CREATE_THREAD;
            accessToClear |= PROCESS_SET_QUOTA;
            // Fall through to STANDARD

        case HECO_PROTECT_LEVEL_STANDARD:
            accessToClear |= PROCESS_VM_WRITE;
            accessToClear |= PROCESS_VM_OPERATION;
            accessToClear |= PROCESS_SET_INFORMATION;
            accessToClear |= PROCESS_SUSPEND_RESUME;
            accessToClear |= PROCESS_TERMINATE;
            accessToClear |= PROCESS_CREATE_THREAD;
            // Fall through to BASIC

        case HECO_PROTECT_LEVEL_BASIC:
        default:
            accessToClear |= PROCESS_TERMINATE;
            accessToClear |= PROCESS_SUSPEND_RESUME;
            break;
        }
    }
    //
    // Handle thread object (protect threads belonging to our process)
    //
    else if (PreInfo->ObjectType == *PsThreadType) {
        HANDLE threadPid = PsGetThreadProcessId((PETHREAD)PreInfo->Object);
        ULONG protectedPid = (ULONG)InterlockedCompareExchange(&g_ProtectedPid, 0, 0);

        if ((ULONG_PTR)threadPid != protectedPid) {
            return OB_PREOP_SUCCESS;
        }

        //
        // Block thread termination and suspension
        //
        accessToClear |= THREAD_TERMINATE;
        accessToClear |= THREAD_SUSPEND_RESUME;
        accessToClear |= THREAD_SET_CONTEXT;
    }
    else {
        return OB_PREOP_SUCCESS;
    }

    //
    // Get the desired access
    //
    switch (PreInfo->Operation) {
    case OB_OPERATION_HANDLE_CREATE:
        desiredAccess = &PreInfo->Parameters->CreateHandleInformation.DesiredAccess;
        break;
    case OB_OPERATION_HANDLE_DUPLICATE:
        desiredAccess = &PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess;
        break;
    default:
        return OB_PREOP_SUCCESS;
    }

    //
    // Only filter user-mode requests (not kernel-mode)
    //
    if (!PreInfo->KernelHandle && desiredAccess != NULL) {
        //
        // Check if the request has any of the blocked access bits
        //
        if (*desiredAccess & accessToClear) {
            InterlockedIncrement(&g_BlockedAttempts);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "HecoProtect: BLOCKED dangerous access to protected PID %lu, "
                "requestor PID %lu, requested 0x%lX, cleared 0x%lX\n",
                (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
                (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
                *desiredAccess, accessToClear);

            //
            // Strip the dangerous access rights
            //
            *desiredAccess &= ~accessToClear;
        }
    }

    return OB_PREOP_SUCCESS;
}

// =========================================================================
//  Post-Operation Callback
// =========================================================================

VOID
HecoPostOperationCallback(
    PVOID RegistrationContext,
    POB_POST_OPERATION_INFORMATION PostInfo)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    UNREFERENCED_PARAMETER(PostInfo);
    // No post-processing needed for our use case
}

// =========================================================================
//  Process Creation Notification
//  Auto-protects Heco processes when they start (e.g. after boot)
// =========================================================================

VOID
HecoCreateProcessNotifyRoutine(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);

    //
    // Process creation
    //
    if (CreateInfo != NULL) {
        //
        // Check if the new process matches our protected image path
        //
        BOOLEAN match = FALSE;
        KeAcquireGuardedMutex(&g_PathMutex);
        if (g_ProtectedPath[0] != L'\0' && CreateInfo->ImageFileName != NULL) {
            match = HecoMatchPathByName(CreateInfo->ImageFileName);
        }
        KeReleaseGuardedMutex(&g_PathMutex);

        if (match) {
            //
            // Auto-protect this process
            //
            InterlockedExchange(&g_ProtectedPid, (LONG)(ULONG_PTR)ProcessId);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "HecoProtect: Auto-protected process PID %lu (path match)\n",
                (ULONG)(ULONG_PTR)ProcessId);

            //
            // Install OB callbacks if needed
            //
            if (!g_CallbacksInstalled) {
                HecoInstallCallbacks();
            }
        }
    }
    else {
        //
        // Process termination - check if this is our protected process
        //
        ULONG protectedPid = (ULONG)InterlockedCompareExchange(&g_ProtectedPid, 0, 0);
        if ((ULONG)(ULONG_PTR)ProcessId == protectedPid) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "HecoProtect: Protected process (PID %lu) terminating. "
                "If you see this, something managed to bypass protection.\n",
                protectedPid);
        }
    }
}

// =========================================================================
//  Helper functions
// =========================================================================

static BOOLEAN
HecoIsProcessProtected(PEPROCESS Process)
{
    ULONG protectedPid = (ULONG)InterlockedCompareExchange(&g_ProtectedPid, 0, 0);
    if (protectedPid == 0) return FALSE;

    HANDLE processId = PsGetProcessId(Process);
    return ((ULONG)(ULONG_PTR)processId == protectedPid);
}

static BOOLEAN
HecoMatchPathByName(PCUNICODE_STRING ImageFileName)
{
    if (ImageFileName == NULL || ImageFileName->Buffer == NULL || g_ProtectedPath[0] == L'\0') {
        return FALSE;
    }

    //
    // Case-insensitive substring match against the protected path
    // We check if the image file name ends with our protected executable name
    //
    SIZE_T protectedLen = wcslen(g_ProtectedPath);
    if (ImageFileName->Length / sizeof(WCHAR) < protectedLen) {
        return FALSE;
    }

    //
    // Compare the end of the image file name with our protected path
    // (handles both full paths and simple exe names)
    //
    SIZE_T offset = (ImageFileName->Length / sizeof(WCHAR)) - protectedLen;
    const WCHAR* imageEnd = ImageFileName->Buffer + offset;

    return (_wcsnicmp(imageEnd, g_ProtectedPath, protectedLen) == 0);
}

// =========================================================================
//  Device lifecycle
// =========================================================================

static NTSTATUS
HecoCreateDevice(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    UNICODE_STRING ntDeviceName;
    UNICODE_STRING dosLinkName;

    RtlInitUnicodeString(&ntDeviceName, HECO_NT_DEVICE_NAME);
    RtlInitUnicodeString(&dosLinkName, HECO_DOS_DEVICES_LINK_NAME);

    //
    // Create device
    //
    status = IoCreateDevice(
        DriverObject,
        0,
        &ntDeviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &g_DeviceObject);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Create symbolic link for user-mode access
    //
    status = IoCreateSymbolicLink(&dosLinkName, &ntDeviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    //
    // Set device flags - allow buffered IO and handle non-EXECUTE alignment
    //
    g_DeviceObject->Flags |= DO_BUFFERED_IO;

    return STATUS_SUCCESS;
}

static VOID
HecoDeleteDevice()
{
    UNICODE_STRING dosLinkName;

    if (g_DeviceObject != NULL) {
        RtlInitUnicodeString(&dosLinkName, HECO_DOS_DEVICES_LINK_NAME);
        IoDeleteSymbolicLink(&dosLinkName);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }
}
