using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace Heco.Common.Engine;

/// <summary>
/// Manages the HecoProtect kernel driver for self-defense.
/// Handles driver installation, loading, and communication via IOCTL.
/// </summary>
public enum ProtectionLevel
{
    None     = 0,
    Basic    = 1,    // Block PROCESS_TERMINATE only
    Standard = 2,    // Block TERMINATE + SUSPEND + VM_WRITE
    Hardened = 3     // Block all dangerous access
}

public class SelfDefenseDriver : IDisposable
{
    private const string DriverName = "HecoProtect";
    private const string Win32DeviceName = @"\\.\HecoProtect";
    private const string DriverSysFileName = "HecoProtect.sys";

    // IOCTL codes (must match shared.h)
    private const uint HECO_IOCTL_PROTECT_PID      = 0x80008504; // CTL_CODE 0x801
    private const uint HECO_IOCTL_UNPROTECT        = 0x80008508; // CTL_CODE 0x802
    private const uint HECO_IOCTL_QUERY_STATUS     = 0x8000850C; // CTL_CODE 0x803
    private const uint HECO_IOCTL_PROTECT_PATH     = 0x80008510; // CTL_CODE 0x804

    private SafeFileHandle? _deviceHandle;
    private bool _disposed;
    private int _activePid;
    private int _protectionLevel;

    // Statistics
    public int BlockedAttempts { get; private set; }
    public bool IsActive => _deviceHandle != null && !_deviceHandle.IsInvalid && !_deviceHandle.IsClosed;
    public int ProtectedPid => _activePid;
    public int Level => _protectionLevel;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct HECO_PROTECT_PID_INPUT
    {
        public int ProcessId;
        public int ProtectionLevel;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct HECO_PROTECT_PATH_INPUT
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 261)]
        public string ImagePath;
        public int ProtectionLevel;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct HECO_STATUS_OUTPUT
    {
        [MarshalAs(UnmanagedType.U1)]
        public bool Active;
        public int ProtectedPid;
        public int ProtectionLevel;
        public int BlockedAttempts;
    }

    // ── Win32 P/Invoke ────────────────────────────────────────────────

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        SafeHandle hDevice,
        uint dwIoControlCode,
        byte[]? lpInBuffer,
        uint nInBufferSize,
        byte[]? lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManager(
        string? lpMachineName,
        string? lpDatabaseName,
        uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateService(
        IntPtr hSCManager,
        string lpServiceName,
        string lpDisplayName,
        uint dwDesiredAccess,
        uint dwServiceType,
        uint dwStartType,
        uint dwErrorControl,
        string lpBinaryPathName,
        string? lpLoadOrderGroup,
        IntPtr lpdwTagId,
        string? lpDependencies,
        string? lpServiceStartName,
        string? lpPassword);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartService(IntPtr hService, uint dwNumServiceArgs, string?[]? lpServiceArgVectors);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ControlService(IntPtr hService, uint dwControl, IntPtr lpServiceStatus);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteService(IntPtr hService);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr hSCObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatus(IntPtr hService, out SERVICE_STATUS lpServiceStatus);

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
    }

    private const uint SERVICE_STOPPED          = 0x00000001;
    private const uint SERVICE_RUNNING          = 0x00000004;
    private const uint SERVICE_CONTROL_STOP     = 0x00000001;
    private const uint SC_MANAGER_ALL_ACCESS    = 0xF003F;
    private const uint SERVICE_ALL_ACCESS       = 0xF01FF;
    private const uint SERVICE_KERNEL_DRIVER    = 0x00000001;
    private const uint SERVICE_DEMAND_START     = 0x00000003;
    private const uint SERVICE_ERROR_NORMAL     = 0x00000001;
    private const uint GENERIC_READ             = 0x80000000;
    private const uint GENERIC_WRITE            = 0x40000000;
    private const uint OPEN_EXISTING            = 3;
    private const uint FILE_SHARE_READ          = 0x00000001;
    private const uint FILE_SHARE_WRITE         = 0x00000002;
    private const uint INVALID_HANDLE_VALUE     = 0xFFFFFFFF;

    private const string HECO_SYSTEM32_DRIVERS = @"\system32\drivers\";

    // ── Public API ─────────────────────────────────────────────────────

    /// <summary>
    /// Install the HecoProtect driver (requires administrator).
    /// Copies the .sys file to system32\drivers and creates the service.
    /// </summary>
    public bool Install(string driverSysPath)
    {
        EnsureAdmin();

        try
        {
            // Copy driver to system32\drivers
            var destPath = Environment.SystemDirectory + HECO_SYSTEM32_DRIVERS + DriverSysFileName;
            File.Copy(driverSysPath, destPath, overwrite: true);

            // Create service
            var scm = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
            if (scm == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            try
            {
                var svc = CreateService(
                    scm, DriverName, "Heco Firewall Self-Defense",
                    SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                    SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                    destPath, null, IntPtr.Zero, null, null, null);

                if (svc == IntPtr.Zero)
                {
                    int err = Marshal.GetLastWin32Error();
                    // ERROR_SERVICE_EXISTS (1073) is ok
                    if (err != 1073)
                        throw new Win32Exception(err);
                }
                else
                    CloseServiceHandle(svc);

                return true;
            }
            finally
            {
                CloseServiceHandle(scm);
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[SelfDefense] Install failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Start the HecoProtect driver service.
    /// </summary>
    public bool Start()
    {
        EnsureAdmin();

        var scm = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
        if (scm == IntPtr.Zero) return false;

        try
        {
            var svc = OpenService(scm, DriverName, SERVICE_ALL_ACCESS);
            if (svc == IntPtr.Zero) return false;

            try
            {
                if (!StartService(svc, 0, null))
                {
                    int err = Marshal.GetLastWin32Error();
                    // ERROR_SERVICE_ALREADY_RUNNING is fine
                    if (err != 1056)
                        return false;
                }

                // Open device handle
                _deviceHandle = CreateFile(
                    Win32DeviceName,
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    0,
                    IntPtr.Zero);

                return _deviceHandle != null && !_deviceHandle.IsInvalid;
            }
            finally
            {
                CloseServiceHandle(svc);
            }
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }

    /// <summary>
    /// Stop the HecoProtect driver service.
    /// </summary>
    public bool Stop()
    {
        try
        {
            // Send unprotect first
            SendUnprotect();

            _deviceHandle?.Dispose();
            _deviceHandle = null;

            var scm = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
            if (scm == IntPtr.Zero) return false;

            try
            {
                var svc = OpenService(scm, DriverName, SERVICE_ALL_ACCESS);
                if (svc == IntPtr.Zero) return false;

                try
                {
                    return ControlService(svc, SERVICE_CONTROL_STOP, IntPtr.Zero);
                }
                finally
                {
                    CloseServiceHandle(svc);
                }
            }
            finally
            {
                CloseServiceHandle(scm);
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[SelfDefense] Stop failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Remove the HecoProtect driver (service + file).
    /// </summary>
    public bool Uninstall()
    {
        EnsureAdmin();

        try
        {
            Stop();

            // Delete service
            var scm = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
            if (scm == IntPtr.Zero) return false;

            try
            {
                var svc = OpenService(scm, DriverName, SERVICE_ALL_ACCESS);
                if (svc == IntPtr.Zero) return false;

                try
                {
                    // Stop first
                    QueryServiceStatus(svc, out var status);
                    if (status.dwCurrentState == SERVICE_RUNNING)
                        ControlService(svc, SERVICE_CONTROL_STOP, IntPtr.Zero);

                    DeleteService(svc);

                    // Delete driver file
                    var driverPath = Environment.SystemDirectory + HECO_SYSTEM32_DRIVERS + DriverSysFileName;
                    if (File.Exists(driverPath))
                        File.Delete(driverPath);

                    return true;
                }
                finally
                {
                    CloseServiceHandle(svc);
                }
            }
            finally
            {
                CloseServiceHandle(scm);
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[SelfDefense] Uninstall failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Protect the current process at the specified level.
    /// </summary>
    public bool ProtectCurrentProcess(ProtectionLevel level = ProtectionLevel.Standard)
    {
        return ProtectProcess(Process.GetCurrentProcess().Id, level);
    }

    /// <summary>
    /// Protect a specific process by PID.
    /// </summary>
    public bool ProtectProcess(int pid, ProtectionLevel level = ProtectionLevel.Standard)
    {
        if (!EnsureDeviceOpen()) return false;

        var input = new HECO_PROTECT_PID_INPUT
        {
            ProcessId = pid,
            ProtectionLevel = (int)level
        };

        var inBytes = StructToBytes(input);
        bool result = DeviceIoControl(
            _deviceHandle!, HECO_IOCTL_PROTECT_PID,
            inBytes, (uint)inBytes.Length,
            null, 0, out _, IntPtr.Zero);

        if (result)
        {
            _activePid = pid;
            _protectionLevel = (int)level;
            Debug.WriteLine($"[SelfDefense] Protecting PID {pid} at level {level}");
        }

        return result;
    }

    /// <summary>
    /// Protect by executable image path (auto-protect on process start).
    /// </summary>
    public bool ProtectPath(string imagePath, ProtectionLevel level = ProtectionLevel.Standard)
    {
        if (!EnsureDeviceOpen()) return false;

        var input = new HECO_PROTECT_PATH_INPUT
        {
            ImagePath = imagePath,
            ProtectionLevel = (int)level
        };

        var inBytes = StructToBytes(input);
        return DeviceIoControl(
            _deviceHandle!, HECO_IOCTL_PROTECT_PATH,
            inBytes, (uint)inBytes.Length,
            null, 0, out _, IntPtr.Zero);
    }

    /// <summary>
    /// Remove protection and query current status.
    /// </summary>
    public bool SendUnprotect()
    {
        if (_deviceHandle == null || _deviceHandle.IsInvalid || _deviceHandle.IsClosed) return false;

        return DeviceIoControl(
            _deviceHandle, HECO_IOCTL_UNPROTECT,
            null, 0, null, 0, out _, IntPtr.Zero);
    }

    /// <summary>
    /// Query driver status including blocked attempt count.
    /// </summary>
    public bool QueryStatus()
    {
        if (!EnsureDeviceOpen()) return false;

        var outBytes = new byte[Marshal.SizeOf<HECO_STATUS_OUTPUT>()];
        bool result = DeviceIoControl(
            _deviceHandle!, HECO_IOCTL_QUERY_STATUS,
            null, 0, outBytes, (uint)outBytes.Length, out _, IntPtr.Zero);

        if (result)
        {
            var status = BytesToStruct<HECO_STATUS_OUTPUT>(outBytes);
            _activePid = status.ProtectedPid;
            _protectionLevel = status.ProtectionLevel;
            BlockedAttempts = status.BlockedAttempts;
        }

        return result;
    }

    /// <summary>
    /// Start all: install (if needed), start service, protect this process.
    /// </summary>
    public async Task<bool> EnableAsync(string driverSysPath, ProtectionLevel level = ProtectionLevel.Standard)
    {
        try
        {
            // Install if needed
            if (!IsDriverInstalled())
            {
                if (!Install(driverSysPath))
                {
                    Debug.WriteLine("[SelfDefense] Install failed");
                    return false;
                }
            }

            // Start the service and open device
            if (!Start())
            {
                Debug.WriteLine("[SelfDefense] Start failed");
                return false;
            }

            // Small delay for device to be ready
            await Task.Delay(100);

            // Protect the current process
            QueryStatus();

            if (!ProtectCurrentProcess(level))
            {
                Debug.WriteLine("[SelfDefense] Protect failed");
                return false;
            }

            // Also protect by path for auto-recovery
            var currentPath = Process.GetCurrentProcess().MainModule?.FileName;
            if (currentPath != null)
            {
                ProtectPath(Path.GetFileName(currentPath), level);
            }

            Debug.WriteLine($"[SelfDefense] Enabled - protecting PID {_activePid} at level {_protectionLevel}");
            return true;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[SelfDefense] Enable failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Disable protection.
    /// </summary>
    public void Disable()
    {
        SendUnprotect();
        Stop();
    }

    // ── Helpers ────────────────────────────────────────────────────────

    private bool IsDriverInstalled()
    {
        var scm = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
        if (scm == IntPtr.Zero) return false;

        try
        {
            var svc = OpenService(scm, DriverName, SERVICE_ALL_ACCESS);
            if (svc == IntPtr.Zero) return false;
            CloseServiceHandle(svc);
            return true;
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }

    private bool EnsureDeviceOpen()
    {
        if (_deviceHandle != null && !_deviceHandle.IsInvalid && !_deviceHandle.IsClosed)
            return true;

        _deviceHandle = CreateFile(
            Win32DeviceName,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero,
            OPEN_EXISTING,
            0,
            IntPtr.Zero);

        return _deviceHandle != null && !_deviceHandle.IsInvalid;
    }

    private static void EnsureAdmin()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
            throw new UnauthorizedAccessException("Administrator privileges required to manage the driver.");
    }

    private static byte[] StructToBytes<T>(T structure) where T : struct
    {
        var size = Marshal.SizeOf<T>();
        var bytes = new byte[size];
        var ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(structure, ptr, false);
            Marshal.Copy(ptr, bytes, 0, size);
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
        return bytes;
    }

    private static T BytesToStruct<T>(byte[] bytes) where T : struct
    {
        var size = Marshal.SizeOf<T>();
        var ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.Copy(bytes, 0, ptr, size);
            return Marshal.PtrToStructure<T>(ptr);
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        SendUnprotect();
        _deviceHandle?.Dispose();
        GC.SuppressFinalize(this);
    }
}
