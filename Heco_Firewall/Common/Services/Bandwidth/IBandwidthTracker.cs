using System;
using System.Collections.Generic;

namespace Heco.Common.Services.Bandwidth;

/// <summary>
///   Tracks bandwidth (sent/received bytes) per connection and per process.
///   Uses IP Helper API counters for accurate measurement.
/// </summary>
public interface IBandwidthTracker
{
    /// <summary>Current bandwidth stats per connection.</summary>
    IReadOnlyDictionary<long, BandwidthStats> ConnectionStats { get; }

    /// <summary>Bandwidth stats aggregated by process.</summary>
    IReadOnlyDictionary<uint, BandwidthStats> ProcessStats { get; }

    /// <summary>Event raised when stats are updated.</summary>
    event EventHandler<BandwidthUpdatedEventArgs> StatsUpdated;

    /// <summary>Start tracking.</summary>
    void Start(int intervalMs = 1000);

    /// <summary>Stop tracking.</summary>
    void Stop();

    /// <summary>Get stats for a specific connection.</summary>
    BandwidthStats? GetConnectionStats(long connectionId);

    /// <summary>Get stats for a specific process.</summary>
    BandwidthStats? GetProcessStats(uint processId);

    /// <summary>Report byte counts for a connection (populated by ConnectionPatrol).</summary>
    void ReportBytes(long connectionId, uint processId, long sentBytes, long receivedBytes);

    /// <summary>Remove a connection from tracking when it ends.</summary>
    void RemoveConnection(long connectionId);
}

/// <summary>
///   Bandwidth statistics for a connection or process.
/// </summary>
public sealed class BandwidthStats
{
    public long SentBytes { get; set; }
    public long ReceivedBytes { get; set; }
    public long TotalBytes => SentBytes + ReceivedBytes;
    public double SentKbps { get; set; }
    public double ReceivedKbps { get; set; }
    public uint ProcessId { get; set; }

    /// <summary>Formatted string for UI display.</summary>
    public string SentFormatted => FormatBytes(SentBytes);
    public string ReceivedFormatted => FormatBytes(ReceivedBytes);

    private static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        if (bytes < 1024 * 1024 * 1024) return $"{bytes / (1024.0 * 1024):F1} MB";
        return $"{bytes / (1024.0 * 1024 * 1024):F1} GB";
    }
}

public sealed class BandwidthUpdatedEventArgs : EventArgs
{
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}
