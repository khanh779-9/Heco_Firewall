using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Management;
using System.Runtime.Versioning;

namespace Heco.Common.Recon;

/// <summary>
///   Resolves detailed process information from a PID,
///   including command-line arguments and executable path.
/// </summary>
public static class ProcessResolver
{
    private static readonly ConcurrentDictionary<int, CacheEntry> _cache = new();
    private static readonly TimeSpan _cacheTtl = TimeSpan.FromSeconds(30);

    private sealed class CacheEntry
    {
        public string? Path { get; set; }
        public DateTime CachedAt { get; set; }
    }

    /// <summary>Get the full command line for a process.</summary>
    [SupportedOSPlatform("windows")]
    public static string? GetCommandLine(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (var obj in searcher.Get())
                return obj["CommandLine"]?.ToString();
        }
        catch { }
        return null;
    }

    /// <summary>Get the full executable path for a process (cached).</summary>
    public static string? GetExecutablePath(int pid)
    {
        // Check cache first
        if (_cache.TryGetValue(pid, out var entry) && (DateTime.UtcNow - entry.CachedAt) < _cacheTtl)
            return entry.Path;

        try
        {
            using var proc = Process.GetProcessById(pid);
            var path = proc.MainModule?.FileName;
            
            _cache[pid] = new CacheEntry { Path = path, CachedAt = DateTime.UtcNow };
            return path;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    ///   Enumerate all processes matching the given executable name (e.g. "chrome").
    /// </summary>
    public static Process[] GetProcessesByName(string name)
    {
        return Process.GetProcessesByName(name);
    }
}
