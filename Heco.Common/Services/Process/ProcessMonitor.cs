using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Management;
using System.Runtime.InteropServices;
using Heco.Common.Services.Process;
using Heco.Common.Services.Diagnostics;

namespace Heco.Common.Services.Process;

/// <summary>
///   Multi-strategy process information resolver.
///   Strategy order: P/Invoke (fast) → WMI (fallback).
///   Results cached in a 1024-entry LRU cache.
/// </summary>
public sealed class ProcessMonitor : IProcessMonitor
{
    private const int MaxCacheSize = 1024;
    private readonly ConcurrentDictionary<uint, ProcessInfo> _cache = new();
    private readonly ConcurrentQueue<uint> _cacheOrder = new();

    public ProcessInfo? GetProcessInfo(uint pid)
    {
        if (TryGetFromCache(pid, out var cached))
            return cached;

        var info = ResolveProcessInfo(pid);
        if (info is not null)
            AddToCache(pid, info);

        return info;
    }

    public bool TryGetProcessInfo(uint pid, out ProcessInfo? info)
    {
        info = GetProcessInfo(pid);
        return info is not null;
    }

    public void ClearCache()
    {
        _cache.Clear();
        while (_cacheOrder.TryDequeue(out _)) { }
    }

    // ── Cache management ──────────────────────────────────────────

    private bool TryGetFromCache(uint pid, out ProcessInfo? info)
    {
        return _cache.TryGetValue(pid, out info);
    }

    private void AddToCache(uint pid, ProcessInfo info)
    {
        _cache[pid] = info;
        _cacheOrder.Enqueue(pid);

        // Evict oldest if over capacity
        while (_cache.Count > MaxCacheSize && _cacheOrder.TryDequeue(out var oldest))
        {
            _cache.TryRemove(oldest, out _);
        }
    }

    // ── Resolution strategies ─────────────────────────────────────

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

            // Strategy 1: P/Invoke for executable path (fast)
            info.ExecutablePath = GetExecutablePathPInvoke(pid);

            // Strategy 2: WMI fallback for command line
            var wmiInfo = GetWmiProcessInfo(pid);
            if (wmiInfo is not null)
            {
                info.CommandLine = wmiInfo.CommandLine ?? info.CommandLine;
                info.ExecutablePath ??= wmiInfo.ExecutablePath;
                info.ParentProcessId = wmiInfo.ParentProcessId;
            }

            // Strategy 3: Process.MainModule as last resort for path
            info.ExecutablePath ??= GetExecutablePathFallback(process);

            // Detect service
            var serviceInfo = GetServiceInfo(pid);
            info.IsService = serviceInfo is not null;
            info.ServiceName = serviceInfo;

            // Detect Windows Store
            var storeInfo = GetWindowsStoreInfo(pid);
            info.IsWindowsStore = storeInfo.isStore;
            info.PackageFamilyName = storeInfo.packageFamilyName;

            process.Dispose();
            return info;
        }
        catch (Exception ex)
        {
            Logger.Debug($"Failed to resolve process {pid}: {ex.Message}");
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

    // ── P/Invoke strategy ────────────────────────────────────────

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern uint QueryFullProcessImageName(IntPtr hProcess, uint dwFlags, System.Text.StringBuilder lpExeName, ref uint lpdwSize);

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    private static string? GetExecutablePathPInvoke(uint pid)
    {
        var hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProcess == IntPtr.Zero)
            return null;

        try
        {
            var sb = new System.Text.StringBuilder(1024);
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

    // ── WMI strategy ─────────────────────────────────────────────

    private static WmiProcessInfo? GetWmiProcessInfo(uint pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT CommandLine, ExecutablePath, ParentProcessId FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (var obj in searcher.Get())
            {
                return new WmiProcessInfo
                {
                    CommandLine = obj["CommandLine"]?.ToString(),
                    ExecutablePath = obj["ExecutablePath"]?.ToString(),
                    ParentProcessId = (uint)(obj["ParentProcessId"] is ushort ppid ? ppid : 0)
                };
            }
        }
        catch { }
        return null;
    }

    private sealed class WmiProcessInfo
    {
        public string? CommandLine { get; set; }
        public string? ExecutablePath { get; set; }
        public uint ParentProcessId { get; set; }
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

    // ── Service detection ────────────────────────────────────────

    private static string? GetServiceInfo(uint pid)
    {
        try
        {
            using (var searcher = new ManagementObjectSearcher($"SELECT Name FROM Win32_Service WHERE ProcessId = {pid}"))
            foreach (var obj in searcher.Get())
                return obj["Name"]?.ToString();
        }
        catch { }
        return null;
    }

    // ── Windows Store detection ───────────────────────────────────

    private static (bool isStore, string? packageFamilyName) GetWindowsStoreInfo(uint pid)
    {
        try
        {
                using (var searcher = new ManagementObjectSearcher("SELECT PackageFamilyName FROM Win32_Process WHERE ProcessId = " + pid))
            foreach (var obj in searcher.Get())
            {
                var pfn = obj["PackageFamilyName"]?.ToString();
                if (!string.IsNullOrEmpty(pfn))
                    return (true, pfn);
            }
        }
        catch { }
        return (false, null);
    }
}
