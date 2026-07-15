using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Threading;
using Heco.Common.Services.Monitoring;
using Heco.Common.Services.Process;
using Heco.Common.Services.Profiles;
using Heco.Common.Services.Diagnostics;

namespace Heco.Common.Services.Monitoring;

/// <summary>
///   Watches Windows Security Event Log 5157 (connection blocked) and
///   DNS client events. Uses EventLogWatcher for Event 5157 and Event 3008.
/// </summary>
public sealed class EventWatcher : IEventWatcher, IDisposable
{
    private const int MaxBlockEvents = 5000;
    private const int MaxDnsQueries = 1000;

    private readonly List<BlockEventInfo> _blockEvents = new();
    private readonly List<DnsQueryEventInfo> _dnsQueries = new();
    private readonly object _sync = new();
    private readonly IProcessMonitor? _processMonitor;
    private readonly IProfileManager? _profileManager;
    private EventLogWatcher? _watcher;
    private EventLogWatcher? _dnsWatcher;
    private long _eventCounter;
    private bool _isRunning;

    public EventWatcher(IProcessMonitor? processMonitor = null, IProfileManager? profileManager = null)
    {
        _processMonitor = processMonitor;
        _profileManager = profileManager;
    }

    public bool IsRunning => _isRunning;

    public event EventHandler<BlockEventInfo>? BlockEventCaptured;
    public event EventHandler<DnsQueryEventInfo>? DnsQueryCaptured;

    public IReadOnlyList<BlockEventInfo> RecentBlockEvents => _blockEvents.AsReadOnly();
    public IReadOnlyList<DnsQueryEventInfo> RecentDnsQueries => _dnsQueries.AsReadOnly();

    public void Start()
    {
        try
        {
            // Subscribe to Security Event Log 5157 (Blocked connection)
            var query = new EventLogQuery("Security", PathType.LogName, "*[System[EventID=5157]]");
            _watcher = new EventLogWatcher(query);
            _watcher.EventRecordWritten += OnEventRecordWritten;
            _watcher.Enabled = true;

            // Subscribe to DNS Client Operational Log Event 3008 (DNS resolution response)
            try
            {
                var dnsQuery = new EventLogQuery("Microsoft-Windows-DNS-Client/Operational", PathType.LogName, "*[System[EventID=3008]]");
                _dnsWatcher = new EventLogWatcher(dnsQuery);
                _dnsWatcher.EventRecordWritten += OnDnsEventRecordWritten;
                _dnsWatcher.Enabled = true;
                Logger.Info("DNS EventWatcher started — watching Event 3008");
            }
            catch (Exception ex)
            {
                Logger.Warn($"Failed to start DNS EventWatcher: {ex.Message}");
            }

            _isRunning = true;
            Logger.Info("EventWatcher started — watching Event 5157");
        }
        catch (Exception ex)
        {
            Logger.Error("Failed to start EventWatcher (may need admin rights)", ex);
            _isRunning = false;
        }
    }

    public void Stop()
    {
        if (_watcher is not null)
        {
            _watcher.Enabled = false;
            _watcher.EventRecordWritten -= OnEventRecordWritten;
            _watcher.Dispose();
            _watcher = null;
        }
        if (_dnsWatcher is not null)
        {
            _dnsWatcher.Enabled = false;
            _dnsWatcher.EventRecordWritten -= OnDnsEventRecordWritten;
            _dnsWatcher.Dispose();
            _dnsWatcher = null;
        }
        _isRunning = false;
        Logger.Info("EventWatcher stopped");
    }

    public void ClearEvents()
    {
        lock (_sync)
        {
            _blockEvents.Clear();
            _dnsQueries.Clear();
        }
    }

    /// <summary>
    ///   Log an external block event (e.g., verdict engine dynamic block).
    ///   Applies the same limits and notifications as native Event 5157.
    /// </summary>
    public void LogBlockEvent(BlockEventInfo info)
    {
        if (info == null) return;

        lock (_sync)
        {
            _blockEvents.Add(info);
            while (_blockEvents.Count > MaxBlockEvents)
                _blockEvents.RemoveAt(0);
        }

        BlockEventCaptured?.Invoke(this, info);
    }

    // ── Event handling ──────────────────────────────────────────

    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventRecord is null) return;

        try
        {
            var blockEvent = ParseEvent5157(e.EventRecord);
            if (blockEvent is null) return;

            lock (_sync)
            {
                _blockEvents.Add(blockEvent);
                while (_blockEvents.Count > MaxBlockEvents)
                    _blockEvents.RemoveAt(0);
            }

            BlockEventCaptured?.Invoke(this, blockEvent);
        }
        catch (Exception ex)
        {
            Logger.Debug($"Parse Event 5157 error: {ex.Message}");
        }
    }

    private BlockEventInfo? ParseEvent5157(EventRecord record)
    {
        try
        {
            var info = new BlockEventInfo
            {
                EventId = Interlocked.Increment(ref _eventCounter),
                Timestamp = record.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow
            };

            if (record.Properties is not null)
            {
                // Event 5157 property order (varies by Windows version):
                // Common: ProcessId, ApplicationPath, SourceAddress, SourcePort,
                // DestAddress, DestPort, Protocol, Direction
                foreach (var prop in record.Properties)
                {
                    var val = prop.Value?.ToString() ?? string.Empty;

                    if (string.IsNullOrEmpty(val) || val == "%%" || val.Length > 256)
                        continue;

                    // Rough heuristic: assign values based on pattern
                    if (info.SourceAddress is null && val.Contains('.'))
                        info.SourceAddress = val;
                    else if (info.DestAddress is null && val.Contains('.'))
                        info.DestAddress = val;
                    else if (val.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                        info.ApplicationPath = val;
                }
            }

            // Try to parse from XML directly for more reliable results
            var xml = record.ToXml();
            info.ApplicationPath = ExtractXmlField(xml, "Application") ?? info.ApplicationPath;
            info.SourceAddress = ExtractXmlField(xml, "SourceAddress") ?? info.SourceAddress!;
            info.DestAddress = ExtractXmlField(xml, "DestAddress") ?? info.DestAddress!;

            // Parse ports from XML
            if (ExtractXmlField(xml, "SourcePort") is { } srcPort && ushort.TryParse(srcPort, out var sp))
                info.SourcePort = sp;
            if (ExtractXmlField(xml, "DestPort") is { } dstPort && ushort.TryParse(dstPort, out var dp))
                info.DestPort = dp;
            if (ExtractXmlField(xml, "Protocol") is { } proto)
                info.Protocol = proto;
            if (ExtractXmlField(xml, "ProcessId") is { } pid && uint.TryParse(pid, out var p))
                info.ProcessId = p;

            // Direction
            if (ExtractXmlField(xml, "Direction") is { } dir)
            {
                info.Direction = dir switch
                {
                    "%%14592" or "1" => "Inbound",
                    "%%14593" or "2" => "Outbound",
                    _ => dir
                };
            }

            return info;
        }
        catch
        {
            return null;
        }
    }

    private static string? ExtractXmlField(string xml, string fieldName)
    {
        var pattern = $"<Data Name=\"{fieldName}\">";
        var start = xml.IndexOf(pattern, StringComparison.Ordinal);
        if (start < 0) return null;

        start += pattern.Length;
        var end = xml.IndexOf("</Data>", start, StringComparison.Ordinal);
        if (end < 0) return null;

        var value = xml.Substring(start, end - start).Trim();
        return string.IsNullOrEmpty(value) || value.StartsWith("%%") ? null : value;
    }

    private void OnDnsEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventRecord is null) return;

        try
        {
            var dnsQuery = ParseDnsEvent3008(e.EventRecord);
            if (dnsQuery is null) return;

            lock (_sync)
            {
                _dnsQueries.Add(dnsQuery);
                while (_dnsQueries.Count > MaxDnsQueries)
                    _dnsQueries.RemoveAt(0);
            }

            DnsQueryCaptured?.Invoke(this, dnsQuery);
        }
        catch (Exception ex)
        {
            Logger.Debug($"Parse DNS Event 3008 error: {ex.Message}");
        }
    }

    private DnsQueryEventInfo? ParseDnsEvent3008(EventRecord record)
    {
        try
        {
            var xml = record.ToXml();
            var queryName = ExtractXmlField(xml, "QueryName");
            if (string.IsNullOrEmpty(queryName)) return null;

            var queryResults = ExtractXmlField(xml, "QueryResults");
            var queryStatusStr = ExtractXmlField(xml, "QueryStatus");
            bool isBlocked = false;

            if (ushort.TryParse(queryStatusStr, out var status) && status != 0)
            {
                isBlocked = true;
            }

            var info = new DnsQueryEventInfo
            {
                EventId = Interlocked.Increment(ref _eventCounter),
                Timestamp = record.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow,
                QueryName = queryName!,
                QueryResults = queryResults,
                ProcessId = record.ProcessId.HasValue ? (uint)record.ProcessId.Value : 0,
                IsBlocked = isBlocked
            };

            if (info.ProcessId > 0 && _processMonitor != null)
            {
                var procInfo = _processMonitor.GetProcessInfo(info.ProcessId);
                if (procInfo != null)
                {
                    info.ProcessName = procInfo.ProcessName;
                }
            }

            if (info.ProcessId > 0 && _profileManager != null)
            {
                var profile = _profileManager.MatchProcess(info.ProcessId);
                info.ProfileName = profile?.Name;
            }

            return info;
        }
        catch
        {
            return null;
        }
    }

    public void Dispose()
    {
        Stop();
    }
}

/// <summary>
///   Extension to create an XmlReader-like string reader for simple XML scanning.
/// </summary>
internal static class StringXmlExtensions
{
    public static SimpleXmlReader AsReader(this string xml) => new(xml);
}

internal sealed class SimpleXmlReader
{
    private readonly string _xml;
    private int _pos;

    public SimpleXmlReader(string xml) { _xml = xml; _pos = 0; }

    public bool ReadToFollowing(string tagName)
    {
        var pattern = $"<{tagName}";
        _pos = _xml.IndexOf(pattern, _pos, StringComparison.Ordinal);
        return _pos >= 0;
    }
}
