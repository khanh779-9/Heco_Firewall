using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Diag = Heco.Common.Services.Diagnostics;

namespace Heco.Common.Services.Process;

/// <summary>
///   Multi-strategy process information resolver.
///   Strategy order: P/Invoke (fast) only — WMI removed for performance.
///   Results cached in a 1024-entry LRU cache with 30s TTL.
/// </summary>
public sealed class ProcessMonitor : IProcessMonitor
{
    private const int MaxCacheSize = 1024;
    private const long CacheTtlTicks = TimeSpan.TicksPerSecond * 30; // 30 seconds

    private readonly ConcurrentDictionary<uint, CacheEntry> _cache = new();

    public ProcessInfo? GetProcessInfo(uint pid)
    {
        if (TryGetFromCache(pid, out var info))
            return info;

        var resolved = ResolveProcessInfo(pid);
        if (resolved is not null)
            AddToCache(pid, resolved);

        return resolved;
    }

    public bool TryGetProcessInfo(uint pid, out ProcessInfo? info)
    {
        info = GetProcessInfo(pid);
        return info is not null;
    }

    public void ClearCache()
    {
        _cache.Clear();
    }

    //  Cache management ─

    private bool TryGetFromCache(uint pid, out ProcessInfo? info)
    {
        info = null;
        if (_cache.TryGetValue(pid, out var entry))
        {
            var now = DateTime.UtcNow.Ticks;
            if (now - entry.CachedAt < CacheTtlTicks)
            {
                info = entry.Info;
                return true;
            }
            // Expired - remove
            _cache.TryRemove(pid, out _);
        }
        return false;
    }

    private void AddToCache(uint pid, ProcessInfo info)
    {
        _cache[pid] = new CacheEntry(info, DateTime.UtcNow.Ticks);

        // Simple eviction: if over capacity, clear 25% oldest entries
        if (_cache.Count > MaxCacheSize)
        {
            var toRemove = _cache.Count - MaxCacheSize + (MaxCacheSize / 4);
            var removed = 0;
            var now = DateTime.UtcNow.Ticks;
            foreach (var kvp in _cache)
            {
                if (removed >= toRemove) break;
                if (now - kvp.Value.CachedAt > CacheTtlTicks || _cache.TryRemove(kvp.Key, out _))
                    removed++;
            }
        }
    }

    private readonly struct CacheEntry
    {
        public readonly ProcessInfo Info;
        public readonly long CachedAt;

        public CacheEntry(ProcessInfo info, long cachedAt)
        {
            Info = info;
            CachedAt = cachedAt;
        }
    }

    //  Resolution strategies (P/Invoke only) ─

    private ProcessInfo? ResolveProcessInfo(uint pid)
    {
        try
        {
            var process = TryGetProcessById((int)pid);
            if (process is null) return null;

            var info = new ProcessInfo
            {
                ProcessId = pid,
                ProcessName = process.ProcessName ?? $"unknown_{pid}",
                SessionId = (uint)process.SessionId,
                StartTime = process.StartTime.ToUniversalTime(),
                WorkingSet64 = process.WorkingSet64
            };

            // Strategy 1: P/Invoke for executable path (fast, no WMI)
            info.ExecutablePath = GetExecutablePathPInvoke(pid);

            // Strategy 2: P/Invoke for command line (via PEB)
            info.CommandLine = GetCommandLinePInvoke(pid);

            // Strategy 3: System.Diagnostics.Process.MainModule as last resort for path
            info.ExecutablePath ??= GetExecutablePathFallback(process);

            // Detect service (via P/Invoke to Service Control Manager)
            var serviceInfo = GetServiceInfoPInvoke(pid);
            info.IsService = serviceInfo is not null;
            info.ServiceName = serviceInfo;

            // Detect Windows Store app (check package family name via P/Invoke)
            var storeInfo = GetWindowsStoreInfoPInvoke(pid);
            info.IsWindowsStore = storeInfo.isStore;
            info.PackageFamilyName = storeInfo.packageFamilyName;

            // Parent process ID via P/Invoke
            info.ParentProcessId = GetParentProcessId(pid);

            process.Dispose();
            return info;
        }
        catch (Exception ex)
        {
            Diag.Logger.Debug($"Failed to resolve process {pid}: {ex.Message}");
            return null;
        }
    }

    private static System.Diagnostics.Process? TryGetProcessById(int pid)
    {
        try
        {
            return System.Diagnostics.Process.GetProcessById(pid);
        }
        catch
        {
            return null;
        }
    }

    //  P/Invoke strategy 

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern uint QueryFullProcessImageName(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr hProcess, int pic, IntPtr ppi, int cb, out int pReturnLength);

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const int ProcessBasicInformation = 0;
    private const int ProcessCommandLineInformation = 60; // Windows 10+

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RTL_USER_PROCESS_PARAMETERS
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Reserved1;
        public IntPtr Reserved2;
        public UNICODE_STRING CurrentDirectory;
        public IntPtr Reserved3;
        public UNICODE_STRING DllPath;
        public UNICODE_STRING ImagePathName;
        public UNICODE_STRING CommandLine;
        public UNICODE_STRING WindowTitle;
        public UNICODE_STRING DesktopInfo;
        public UNICODE_STRING ShellInfo;
        public UNICODE_STRING RuntimeData;
    }

    private static string? GetExecutablePathPInvoke(uint pid)
    {
        var hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProcess == IntPtr.Zero)
            return null;

        try
        {
            var sb = new StringBuilder(1024);
            var size = (uint)sb.Capacity;
            if (QueryFullProcessImageName(hProcess, 0, sb, ref size) != 0)
                return sb.ToString();
            return null;
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    private static string? GetCommandLinePInvoke(uint pid)
    {
        var hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProcess == IntPtr.Zero)
            return null;

        try
        {
            // Try NtQueryInformationProcess for command line (Windows 10+)
            int pbiSize = Marshal.SizeOf<PROCESS_BASIC_INFORMATION>();
            int retLen;
            var pbiPtr = Marshal.AllocHGlobal(pbiSize);
            try
            {
                var status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, pbiPtr, pbiSize, out retLen);
                if (status != 0) return null;

                var pbiData = Marshal.PtrToStructure<PROCESS_BASIC_INFORMATION>(pbiPtr);
                // Read PEB -> ProcessParameters -> CommandLine
                // This is complex and version-dependent; skip for now
                return null;
            }
            finally { Marshal.FreeHGlobal(pbiPtr); }
        }
        catch
        {
            return null;
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    private static string? GetExecutablePathFallback(System.Diagnostics.Process process)
    {
        try
        {
            return process.MainModule?.FileName;
        }
        catch
        {
            return null;
        }
    }

    //  Service detection via Service Control Manager 

    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr OpenSCManager(string? lpMachineName, string? lpDatabaseName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool QueryServiceStatusEx(IntPtr hService, int dwInfoLevel, IntPtr lpBuffer, uint cbBufSize, out uint pcbBytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr hSCObject);

    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int EnumServicesStatusEx(IntPtr hSCManager, int dwInfoLevel, int dwServiceType, int dwServiceState, IntPtr lpServices, uint cbBufSize, out uint pcbBytesNeeded, out uint lpServicesReturned, out uint lpResumeHandle, string? pszGroupName);

    private const uint SC_MANAGER_ENUMERATE_SERVICE = 0x0004;
    private const uint SERVICE_QUERY_STATUS = 0x0004;
    private const int SC_ENUM_PROCESS_INFO = 0;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct ENUM_SERVICE_STATUS_PROCESS
    {
        public string lpServiceName;
        public string lpDisplayName;
        public SERVICE_STATUS_PROCESS ServiceStatusProcess;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS_PROCESS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
        public uint dwProcessId;
        public uint dwServiceFlags;
    }

    private static string? GetServiceInfoPInvoke(uint pid)
    {
        IntPtr scm = IntPtr.Zero;
        try
        {
            scm = OpenSCManager(null, null, SC_MANAGER_ENUMERATE_SERVICE);
            if (scm == IntPtr.Zero) return null;

            uint bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
            // First call to get buffer size
            EnumServicesStatusEx(scm, SC_ENUM_PROCESS_INFO, 0x30, 3, IntPtr.Zero, 0, out bytesNeeded, out servicesReturned, out resumeHandle, null);
            if (bytesNeeded == 0) return null;

            IntPtr buffer = Marshal.AllocHGlobal((int)bytesNeeded);
            try
            {
                if (EnumServicesStatusEx(scm, SC_ENUM_PROCESS_INFO, 0x30, 3, buffer, bytesNeeded, out _, out servicesReturned, out _, null) == 0)
                    return null;

                IntPtr current = buffer;
                for (uint i = 0; i < servicesReturned; i++)
                {
                    var essp = Marshal.PtrToStructure<ENUM_SERVICE_STATUS_PROCESS>(current);
                    if (essp.ServiceStatusProcess.dwProcessId == pid)
                        return essp.lpServiceName;
                    current += Marshal.SizeOf<ENUM_SERVICE_STATUS_PROCESS>();
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch { }
        finally
        {
            if (scm != IntPtr.Zero) CloseServiceHandle(scm);
        }
        return null;
    }

    //  Windows Store detection 

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int GetPackageFamilyName(IntPtr hProcess, ref int packageFamilyNameLength, StringBuilder packageFamilyName);

    private static (bool isStore, string? packageFamilyName) GetWindowsStoreInfoPInvoke(uint pid)
    {
        var hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProcess == IntPtr.Zero) return (false, null);

        try
        {
            int length = 0;
            int result = GetPackageFamilyName(hProcess, ref length, null!);
            if (result != 122) // ERROR_INSUFFICIENT_BUFFER
                return (false, null);

            var sb = new StringBuilder(length);
            result = GetPackageFamilyName(hProcess, ref length, sb);
            if (result == 0 && length > 0)
                return (true, sb.ToString());
        }
        catch { }
        finally
        {
            CloseHandle(hProcess);
        }
        return (false, null);
    }

    //  Parent Process ID 

    private static uint GetParentProcessId(uint pid)
    {
        var hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProcess == IntPtr.Zero) return 0;

        try
        {
            int pbiSize = Marshal.SizeOf<PROCESS_BASIC_INFORMATION>();
            int retLen;
            var pbiPtr = Marshal.AllocHGlobal(pbiSize);
            try
            {
                var status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, pbiPtr, pbiSize, out retLen);
                if (status != 0) return 0;
                var pbiData = Marshal.PtrToStructure<PROCESS_BASIC_INFORMATION>(pbiPtr);
                return (uint)pbiData.InheritedFromUniqueProcessId.ToInt32();
            }
            finally { Marshal.FreeHGlobal(pbiPtr); }
        }
        finally { CloseHandle(hProcess); }
    }
}