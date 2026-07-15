# HecoProtect Kernel Driver

Self-defense kernel driver for Heco Firewall using `ObRegisterCallbacks` to prevent process termination and tampering.

## Architecture

```
┌─────────────────────────────────────────────┐
│           User Mode (Ring 3)                │
│                                              │
│  Heco Firewall (GUI)                         │
│    └─ SelfDefenseDriver.cs                   │
│         │  CreateFile("\\.\HecoProtect")     │
│         │  DeviceIoControl(IOCTL)            │
│         ▼                                    │
├─────────────────────────────────────────────┤
│           Kernel Mode (Ring 0)               │
│                                              │
│  HecoProtect.sys                             │
│    ├─ DriverEntry / Unload                   │
│    ├─ ObRegisterCallbacks ◄──── CORE         │
│    │    └─ PreOperationCallback              │
│    │         └─ Blocks PROCESS_TERMINATE     │
│    │            PROCESS_SUSPEND_RESUME       │
│    │            PROCESS_VM_WRITE             │
│    │            PROCESS_CREATE_THREAD        │
│    │            (configurable per level)     │
│    ├─ PsSetCreateProcessNotifyRoutineEx     │
│    │    └─ Auto-protects on process start    │
│    └─ IOCTL interface                        │
│         ├─ HECO_IOCTL_PROTECT_PID           │
│         ├─ HECO_IOCTL_UNPROTECT             │
│         ├─ HECO_IOCTL_QUERY_STATUS          │
│         └─ HECO_IOCTL_PROTECT_PATH          │
└─────────────────────────────────────────────┘
```

## Protection Levels

| Level | Value | Blocks |
|-------|-------|--------|
| None | 0 | No protection |
| Basic | 1 | PROCESS_TERMINATE, PROCESS_SUSPEND_RESUME |
| Standard | 2 | + PROCESS_VM_WRITE, PROCESS_SET_INFORMATION, PROCESS_CREATE_THREAD |
| Hardened | 3 | + PROCESS_VM_READ, PROCESS_QUERY_INFORMATION, PROCESS_DUP_HANDLE, PROCESS_SET_QUOTA |

## How It Works

1. **User-mode** sends its PID to the driver via `HECO_IOCTL_PROTECT_PID`
2. **Driver** registers `ObRegisterCallbacks` for `PsProcessType` and `PsThreadType`
3. **Pre-operation callback** intercepts every handle open/duplicate to the protected PID
4. **Dangerous access rights** (e.g., `PROCESS_TERMINATE`) are stripped from the desired access mask
5. **Result**: `OpenProcess(PROCESS_TERMINATE)` returns `STATUS_ACCESS_DENIED` — process cannot be killed
6. **Auto-protection**: `PsSetCreateProcessNotifyRoutineEx` monitors process creation — if Heco restarts, it auto-protects the new PID

### What's NOT blocked

- The protected process can still open itself (self-access is allowed)
- Kernel-mode code can still access the process (only user-mode handles are filtered)
- `TerminateProcess()` on a handle obtained BEFORE protection was enabled

## Prerequisites

- Windows 10/11 (x64)
- Visual Studio 2022 + WDK (Windows Driver Kit)
- Test signing enabled: `bcdedit /set testsigning on`
- Admin privileges for installation

## Building

### Option 1: Visual Studio (recommended)
1. Open `HecoProtect.vcxproj` in Visual Studio
2. Select `x64` or `x86`
3. Build → Build Solution

### Option 2: Command line
```bat
build_driver.bat x64
```

## Installation

### Test environment
```bat
bcdedit /set testsigning on
reboot

# Copy driver
copy build\x64\HecoProtect.sys C:\Windows\System32\drivers\

# Install service
sc create HecoProtect type= kernel binPath= C:\Windows\System32\drivers\HecoProtect.sys

# Start
sc start HecoProtect

# Check status
sc query HecoProtect
```

### Signing (for production)
```bat
# Sign with your EV certificate
signtool sign /v /fd SHA256 /a /ph /ac crosschain.cer /n "Your Company" build\x64\HecoProtect.sys
```

## Integration with Heco Firewall

The `SelfDefenseDriver` class in `Heco.Core.Engine` handles everything:

```csharp
var defense = new SelfDefenseDriver();

// One-shot: install + start + protect
await defense.EnableAsync(@"Drivers\x64\HecoProtect.sys",
    SelfDefenseDriver.ProtectionLevel.Standard);

// Check blocked attempts
defense.QueryStatus();
Console.WriteLine($"Blocked: {defense.BlockedAttempts}");

// Disable
defense.Disable();
```

Wire it in `App.xaml.cs` or your service startup.

## Important Notes

- **Driver signing**: Windows 10/11 requires signed kernel drivers. For testing, enable test signing mode. For production, submit to the Windows Hardware Dev Center.
- **Altitude**: Uses `370030` (Anti-Virus range). If another security product uses the same altitude, adjust in the source.
- **PatchGuard**: This driver uses documented APIs (`ObRegisterCallbacks`, `PsSetCreateProcessNotifyRoutineEx`). It does NOT hook SSDT, IDT, or patch kernel code. Safe under Kernel Patch Protection (PatchGuard).
- **BSoD safety**: If the driver crashes, Windows will bugcheck. The code is minimal and well-tested — ensure thorough testing before production use.
