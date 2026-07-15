using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using Heco.Common.Services.Detection;
using Heco.Common.Services.Diagnostics;

namespace Heco.Common.Services.Detection;

/// <summary>
///   Detects potential threats from connection patterns using behavioral analysis.
/// </summary>
public sealed class ThreatDetector : IThreatDetector, IDisposable
{
    private readonly ConcurrentDictionary<uint, ProcessConnectionTracker> _trackers = new();
    private readonly TimeSpan _trackingWindow = TimeSpan.FromMinutes(5);
    private readonly Timer _cleanupTimer;

    public ThreatDetector()
    {
        _cleanupTimer = new Timer(_ => Cleanup(), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
    }

    /// <summary>
    ///   Analyze a connection for threat indicators.
    /// </summary>
    public ThreatResultV2 Analyze(
        IPAddress localAddress,
        ushort localPort,
        IPAddress remoteAddress,
        ushort remotePort,
        uint processId)
    {
        var result = new ThreatResultV2();
        var indicators = new List<ThreatIndicatorV2>();

        // Check for suspicious remote ports
        if (IsSuspiciousPort(remotePort))
        {
            indicators.Add(new ThreatIndicatorV2
            {
                Description = $"Connection to suspicious port {remotePort}",
                Level = ThreatLevelV2.Medium
            });
            result.Level = ThreatLevelV2.Medium;
        }

        // Check for connections to known malicious IP ranges
        if (IsKnownMaliciousIp(remoteAddress))
        {
            indicators.Add(new ThreatIndicatorV2
            {
                Description = $"Connection to known malicious IP {remoteAddress}",
                Level = ThreatLevelV2.High
            });
            result.Level = ThreatLevelV2.High;
        }

        // Check process behavior
        if (!_trackers.TryGetValue(processId, out var tracker))
        {
            tracker = new ProcessConnectionTracker();
            _trackers[processId] = tracker;
        }

        tracker.RecordConnection(remoteAddress, remotePort);

        // Check for port scanning behavior
        if (tracker.UniqueRemotePortsCount > 20)
        {
            indicators.Add(new ThreatIndicatorV2
            {
                Description = $"Process {processId} connecting to {tracker.UniqueRemotePortsCount} unique ports (possible port scan)",
                Level = ThreatLevelV2.High
            });
            result.Level = ThreatLevelV2.High;
        }

        // Check for rapid connection attempts
        if (tracker.RecentConnectionCount > 50)
        {
            indicators.Add(new ThreatIndicatorV2
            {
                Description = $"Process {processId} made {tracker.RecentConnectionCount} connections in last minute",
                Level = ThreatLevelV2.Medium
            });
            if (result.Level < ThreatLevelV2.Medium) result.Level = ThreatLevelV2.Medium;
        }

        // Check for connections to many different IPs (possible botnet C2)
        if (tracker.UniqueRemoteIpsCount > 15)
        {
            indicators.Add(new ThreatIndicatorV2
            {
                Description = $"Process {processId} connected to {tracker.UniqueRemoteIpsCount} unique remote IPs",
                Level = ThreatLevelV2.Medium
            });
            if (result.Level < ThreatLevelV2.Medium) result.Level = ThreatLevelV2.Medium;
        }

        result.Indicators = indicators;
        result.IsThreat = indicators.Count > 0;

        return result;
    }

    /// <summary>
    ///   Register a connection for behavioral tracking.
    /// </summary>
    public void TrackConnection(uint processId, IPAddress remoteAddress, ushort remotePort)
    {
        if (!_trackers.TryGetValue(processId, out var tracker))
        {
            tracker = new ProcessConnectionTracker();
            _trackers[processId] = tracker;
        }

        tracker.RecordConnection(remoteAddress, remotePort);
    }

    /// <summary>
    ///   Clean up expired trackers.
    /// </summary>
    private void Cleanup()
    {
        var cutoff = DateTime.UtcNow - _trackingWindow;
        var expired = _trackers
            .Where(kvp => kvp.Value.LastActivity < cutoff)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var pid in expired)
        {
            _trackers.TryRemove(pid, out _);
        }
    }

    private static bool IsSuspiciousPort(ushort port)
    {
        // Common ports used by malware/botnets
        return port switch
        {
            4444 or 5555 or 6666 or 6667 or 6668 or 6669 or  // IRC/malware
            31337 or 12345 or 54321 or  // Back Orifice, NetBus, etc.
            1234 or 2345 or 4567 or  // Common backdoors
            135 or 139 or 445 or  // SMB/RPC (if unexpected)
            1433 or 3306 or 5432 or 6379 or 27017 => true, // Database ports (if unexpected)
            _ => false
        };
    }

    private static bool IsKnownMaliciousIp(IPAddress address)
    {
        // In production, this would check against threat intelligence feeds
        // For now, return false - placeholder for threat intelligence integration
        return false;
    }

    public void Dispose()
    {
        _cleanupTimer?.Dispose();
        _trackers.Clear();
    }

    /// <summary>
    ///   Tracks connection behavior for a single process.
    /// </summary>
    private sealed class ProcessConnectionTracker
    {
        private readonly ConcurrentDictionary<IPAddress, byte> _remoteIps = new();
        private readonly ConcurrentDictionary<ushort, byte> _remotePorts = new();
        private readonly ConcurrentQueue<DateTime> _connectionTimes = new();
        public DateTime LastActivity { get; private set; } = DateTime.UtcNow;

        public int UniqueRemoteIpsCount => _remoteIps.Count;
        public int UniqueRemotePortsCount => _remotePorts.Count;

        public int RecentConnectionCount
        {
            get
            {
                var cutoff = DateTime.UtcNow - TimeSpan.FromMinutes(1);
                var count = 0;
                foreach (var dt in _connectionTimes)
                {
                    if (dt > cutoff) count++;
                }
                return count;
            }
        }

        public void RecordConnection(IPAddress remoteAddress, ushort remotePort)
        {
            LastActivity = DateTime.UtcNow;
            _remoteIps.TryAdd(remoteAddress, 0);
            _remotePorts.TryAdd(remotePort, 0);
            _connectionTimes.Enqueue(DateTime.UtcNow);

            // Clean old timestamps
            var cutoff = DateTime.UtcNow - TimeSpan.FromMinutes(2);
            while (_connectionTimes.TryPeek(out var dt) && dt < cutoff)
            {
                _connectionTimes.TryDequeue(out _);
            }
        }
    }
}