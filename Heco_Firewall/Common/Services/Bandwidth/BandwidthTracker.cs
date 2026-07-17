using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using Heco.Common.Services.Bandwidth;
using Heco.Common.Services.Diagnostics;

namespace Heco.Common.Services.Bandwidth;

/// <summary>
///   Tracks bandwidth (sent/received bytes) per connection and per process.
///   Uses delta tracking to compute per-interval rates.
/// </summary>
public sealed class BandwidthTracker : IBandwidthTracker, IDisposable
{
    private readonly ConcurrentDictionary<long, BandwidthStats> _connectionStats = new();
    private readonly ConcurrentDictionary<uint, BandwidthStats> _processStats = new();
    private readonly ConcurrentDictionary<long, Snapshot> _previousSnapshots = new();
    private Timer? _timer;
    private bool _disposed;

    public IReadOnlyDictionary<long, BandwidthStats> ConnectionStats => _connectionStats;
    public IReadOnlyDictionary<uint, BandwidthStats> ProcessStats => _processStats;

    public event EventHandler<BandwidthUpdatedEventArgs>? StatsUpdated;

    public void Start(int intervalMs = 1000)
    {
        _timer = new Timer(_ => UpdateStats(), null, intervalMs, intervalMs);
        Logger.Info("BandwidthTracker started");
    }

    public void Stop()
    {
        _timer?.Dispose();
        _timer = null;
        Logger.Info("BandwidthTracker stopped");
    }

    public BandwidthStats? GetConnectionStats(long connectionId)
    {
        _connectionStats.TryGetValue(connectionId, out var stats);
        return stats;
    }

    public BandwidthStats? GetProcessStats(uint processId)
    {
        _processStats.TryGetValue(processId, out var stats);
        return stats;
    }

    private void UpdateStats()
    {
        try
        {
            var now = DateTime.UtcNow;

            // Compute deltas for each connection by comparing with previous snapshot
            foreach (var kvp in _connectionStats)
            {
                var connectionId = kvp.Key;
                var current = kvp.Value;

                if (_previousSnapshots.TryGetValue(connectionId, out var previous))
                {
                    var sentDelta = current.SentBytes - previous.SentBytes;
                    var recvDelta = current.ReceivedBytes - previous.ReceivedBytes;

                    if (sentDelta < 0) sentDelta = 0; // handle counter wrap/reset
                    if (recvDelta < 0) recvDelta = 0;

                    var elapsedSec = (now - previous.Timestamp).TotalSeconds;
                    if (elapsedSec > 0)
                    {
                        // Convert bytes/sec to Kbps (kilobits per second)
                        current.SentKbps = (sentDelta * 8) / elapsedSec / 1024.0;
                        current.ReceivedKbps = (recvDelta * 8) / elapsedSec / 1024.0;

                        // Aggregate to process level (use deltas, not absolute)
                        if (current.ProcessId > 0)
                        {
                            var procStats = _processStats.GetOrAdd(current.ProcessId, _ => new BandwidthStats());
                            procStats.SentKbps += current.SentKbps;
                            procStats.ReceivedKbps += current.ReceivedKbps;
                        }
                    }
                }

                _previousSnapshots[connectionId] = new Snapshot
                {
                    SentBytes = current.SentBytes,
                    ReceivedBytes = current.ReceivedBytes,
                    Timestamp = now
                };
            }

            // Clean up stale snapshots for connections that no longer exist
            var staleKeys = _previousSnapshots.Keys.Where(k => !_connectionStats.ContainsKey(k)).ToList();
            foreach (var key in staleKeys)
            {
                _previousSnapshots.TryRemove(key, out _);
            }

            StatsUpdated?.Invoke(this, new BandwidthUpdatedEventArgs { Timestamp = now });
        }
        catch (Exception ex)
        {
            Logger.Debug($"BandwidthTracker.UpdateStats: {ex.Message}");
        }
    }

    /// <summary>
    ///   Called externally when connection byte counts are available (e.g., from ConnectionPatrol).
    ///   <paramref name="sentBytes"/> and <paramref name="receivedBytes"/> should be
    ///   absolute cumulative counters for the connection.
    /// </summary>
    public void ReportBytes(long connectionId, uint processId, long sentBytes, long receivedBytes)
    {
        var stats = _connectionStats.GetOrAdd(connectionId, _ => new BandwidthStats());
        stats.SentBytes = sentBytes;
        stats.ReceivedBytes = receivedBytes;
        stats.ProcessId = processId;
    }

    public void RemoveConnection(long connectionId)
    {
        _connectionStats.TryRemove(connectionId, out _);
        _previousSnapshots.TryRemove(connectionId, out _);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
    }

    private sealed class Snapshot
    {
        public long SentBytes { get; set; }
        public long ReceivedBytes { get; set; }
        public DateTime Timestamp { get; set; }
    }
}
