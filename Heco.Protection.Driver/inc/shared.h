/*++
    Shared definitions for Heco Firewall Self-Defense Driver.
    License: MIT
--*/

#pragma once

#pragma warning(disable:4214) // bit field types other than int
#pragma warning(disable:4201) // nameless struct/union

//
// Device names
//
#define HECO_DRIVER_NAME             L"HecoProtect"
#define HECO_NT_DEVICE_NAME          L"\\Device\\HecoProtect"
#define HECO_DOS_DEVICES_LINK_NAME   L"\\DosDevices\\HecoProtect"
#define HECO_WIN32_DEVICE_NAME       L"\\\\.\\HecoProtect"

#define HECO_NAME_SIZE   260

//
// IOCTL codes
//
#define HECO_IOCTL_PROTECT_PID      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define HECO_IOCTL_UNPROTECT        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define HECO_IOCTL_QUERY_STATUS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define HECO_IOCTL_PROTECT_PATH     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

//
// Protection levels
//
#define HECO_PROTECT_LEVEL_NONE     0
#define HECO_PROTECT_LEVEL_BASIC    1   // Block PROCESS_TERMINATE only
#define HECO_PROTECT_LEVEL_STANDARD 2   // Block TERMINATE + SUSPEND + VM_WRITE
#define HECO_PROTECT_LEVEL_HARDENED 3   // Block all dangerous access (except from SYSTEM)

//
// Input structures
//
typedef struct _HECO_PROTECT_PID_INPUT {
    ULONG ProcessId;
    ULONG ProtectionLevel;
} HECO_PROTECT_PID_INPUT, *PHECO_PROTECT_PID_INPUT;

typedef struct _HECO_PROTECT_PATH_INPUT {
    WCHAR ImagePath[HECO_NAME_SIZE + 1];
    ULONG ProtectionLevel;
} HECO_PROTECT_PATH_INPUT, *PHECO_PROTECT_PATH_INPUT;

//
// Query status output
//
typedef struct _HECO_STATUS_OUTPUT {
    BOOLEAN Active;
    ULONG   ProtectedPid;
    ULONG   ProtectionLevel;
    ULONG   BlockedAttempts;
} HECO_STATUS_OUTPUT, *PHECO_STATUS_OUTPUT;
