using System;
using System.Collections.Generic;

namespace Heco.Common.Services.Process;

/// <summary>
///   Resolves detailed process information from a PID using multiple strategies.
///   Multi-strategy: P/Invoke (fast) → WMI (fallback) → PEB reading (command line).
///   Results are cached in a 1024-entry LRU cache.
/// </summary>
public interface IProcessMonitor
{
    /// <summary>Get process info by PID. Returns null if the process no longer exists.</summary>
    ProcessInfo? GetProcessInfo(uint pid);

    /// <summary>Try to get process info — returns false if not found.</summary>
    bool TryGetProcessInfo(uint pid, out ProcessInfo? info);

    /// <summary>Clear the internal cache.</summary>
    void ClearCache();
}

/// <summary>
///   Detailed information about a running process.
/// </summary>
public sealed class ProcessInfo
{
    /// <summary>Process ID.</summary>
    public uint ProcessId { get; set; }

    /// <summary>Executable file name (e.g. "chrome.exe").</summary>
    public string ProcessName { get; set; } = string.Empty;

    /// <summary>Full path to the executable.</summary>
    public string? ExecutablePath { get; set; }

    /// <summary>Full command line including arguments.</summary>
    public string? CommandLine { get; set; }

    /// <summary>Windows service name if this process is a service.</summary>
    public string? ServiceName { get; set; }

    /// <summary>Whether this process is a Windows service.</summary>
    public bool IsService { get; set; }

    /// <summary>Whether this process is a Windows Store / UWP app.</summary>
    public bool IsWindowsStore { get; set; }

    /// <summary>Windows Store AUMID (Application User Model ID).</summary>
    public string? PackageFamilyName { get; set; }

    /// <summary>Base64-encoded PNG icon (16x16).</summary>
    public string? IconBase64 { get; set; }

    /// <summary>Parent process ID.</summary>
    public uint ParentProcessId { get; set; }

    /// <summary>Session ID.</summary>
    public uint SessionId { get; set; }

    /// <summary>Process start time (UTC).</summary>
    public DateTime? StartTime { get; set; }

    /// <summary>Memory usage in bytes.</summary>
    public long WorkingSet64 { get; set; }

    /// <summary>Whether this is the SYSTEM process (PID 4).</summary>
    public bool IsSystem => ProcessId == 4;

    /// <summary>Whether this is the Idle process (PID 0).</summary>
    public bool IsIdle => ProcessId == 0;

    public override string ToString() => $"[{ProcessId}] {ProcessName}";
}
