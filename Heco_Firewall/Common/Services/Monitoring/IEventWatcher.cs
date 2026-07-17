using System;
using System.Collections.Generic;

namespace Heco.Common.Services.Monitoring;

/// <summary>
///   Watches Windows Security Event Log 5157 (connection blocked) and
///   DNS client ETW events (3006/3008).
/// </summary>
public interface IEventWatcher
{
    /// <summary>Event raised when a block event (5157) is captured.</summary>
    event EventHandler<BlockEventInfo> BlockEventCaptured;

    /// <summary>Event raised when a DNS query event is captured.</summary>
    event EventHandler<DnsQueryEventInfo> DnsQueryCaptured;

    /// <summary>Whether the watcher is running.</summary>
    bool IsRunning { get; }

    /// <summary>Recently captured events (max 5000).</summary>
    IReadOnlyList<BlockEventInfo> RecentBlockEvents { get; }

    /// <summary>Recently captured DNS queries (max 1000).</summary>
    IReadOnlyList<DnsQueryEventInfo> RecentDnsQueries { get; }

    /// <summary>Start watching events.</summary>
    void Start();

    /// <summary>Stop watching.</summary>
    void Stop();

    /// <summary>Clear all recent events.</summary>
    void ClearEvents();

    /// <summary>Log an external block event (e.g., from verdict engine).</summary>
    void LogBlockEvent(BlockEventInfo info);
}

/// <summary>
///   Information about a Windows Security Event 5157 (connection blocked).
/// </summary>
public sealed class BlockEventInfo
{
    public long EventId { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string Protocol { get; set; } = string.Empty;
    public string SourceAddress { get; set; } = string.Empty;
    public ushort SourcePort { get; set; }
    public string DestAddress { get; set; } = string.Empty;
    public ushort DestPort { get; set; }
    public string ApplicationPath { get; set; } = string.Empty;
    public string? Direction { get; set; }
    public uint ProcessId { get; set; }
    public string? ProfileName { get; set; }
    public string? RuleName { get; set; }
    public string? Country { get; set; }
}

/// <summary>
///   Information about a DNS query event (ETW 3006/3008).
/// </summary>
public sealed class DnsQueryEventInfo
{
    public long EventId { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string QueryName { get; set; } = string.Empty;
    public string? QueryResults { get; set; }
    public uint ProcessId { get; set; }
    public string? ProcessName { get; set; }
    public string? ProfileName { get; set; }
    public bool IsBlocked { get; set; }
}
