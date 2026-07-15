using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using Heco.Common.Services.Bandwidth;
using Heco.Common.Services.GeoIp;
using Heco.Common.Models;
using Heco.Common.Enums;
using Heco.Common.Interfaces;
using Heco.Common.Services.Profiles;
using Heco.Surveillance.Patrol;
using Heco_Firewall.Helpers;
using Heco_Firewall.Windows;

namespace Heco_Firewall.ViewModels;

internal sealed class ConnectionsViewModel : ObservableObject
{
    private readonly ConnectionMonitor _monitor;
    private readonly IProfileManager? _profileManager;
    private readonly IGeoLookup? _geoLookup;
    private readonly IBandwidthTracker? _bandwidthTracker;
    private readonly object _sync = new();
    private readonly Dispatcher _uiDispatcher;
    private readonly Queue<ConnectionEntry> _pendingEnrichment = new();
    private readonly Queue<Action> _uiUpdateQueue = new();
    private bool _uiUpdateScheduled;
    private bool _isMonitoring;
    private ConnectionEntry? _selectedConnection;
    private string _searchText = string.Empty;
    private string _connectionStatus = "Idle";
    private int _refreshInterval = 2000;

    public ConnectionsViewModel(IProfileManager? profileManager = null, IGeoLookup? geoLookup = null, IBandwidthTracker? bandwidthTracker = null)
    {
        _uiDispatcher = Dispatcher.CurrentDispatcher;
        _monitor = new ConnectionMonitor();
        _profileManager = profileManager;
        _geoLookup = geoLookup;
        _bandwidthTracker = bandwidthTracker;
        _monitor.ConnectionsUpdated += OnConnectionsUpdated;

        ConnectionsView = new CollectionViewSource();
        ConnectionsView.Source = Connections;
        ConnectionsView.View!.Filter = FilterConnection;

        StartCommand = new RelayCommand(_ => StartMonitoring(), _ => !IsMonitoring);
        StopCommand = new RelayCommand(_ => StopMonitoring(), _ => IsMonitoring);
        RefreshCommand = new RelayCommand(_ => ForceRefresh());
        DnsCacheCommand = new RelayCommand(_ => ShowDnsCache());
        DnsCacheCloseCommand = new RelayCommand(_ => IsDnsCacheVisible = false);
    }

    //  Collections ─

    public ObservableCollection<ConnectionEntry> Connections { get; } = new();
    public CollectionViewSource ConnectionsView { get; }

    //  Exposed for VerdictEngine integration 

    /// <summary>Expose the underlying monitor so MainViewModel can subscribe to ConnectionAdded for real-time verdict evaluation.</summary>
    public ConnectionMonitor ConnectionMonitor => _monitor;

    //  Properties 

    public bool IsMonitoring
    {
        get => _isMonitoring;
        set
        {
            if (SetProperty(ref _isMonitoring, value))
            {
                ConnectionStatus = value ? "Monitoring" : "Stopped";
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }

    public ConnectionEntry? SelectedConnection
    {
        get => _selectedConnection;
        set => SetProperty(ref _selectedConnection, value);
    }

    public string SearchText
    {
        get => _searchText;
        set
        {
            if (SetProperty(ref _searchText, value))
                ConnectionsView.View?.Refresh();
        }
    }

    public string ConnectionStatus
    {
        get => _connectionStatus;
        set => SetProperty(ref _connectionStatus, value);
    }

    public int RefreshInterval
    {
        get => _refreshInterval;
        set => SetProperty(ref _refreshInterval, value);
    }

    //  DNS Cache ─

    public ObservableCollection<DnsCacheEntry> DnsCacheEntries { get; } = new();
    private bool _isDnsCacheVisible;
    public bool IsDnsCacheVisible
    {
        get => _isDnsCacheVisible;
        set => SetProperty(ref _isDnsCacheVisible, value);
    }

    private string _dnsCacheStatus = "DNS cache";
    public string DnsCacheStatus
    {
        get => _dnsCacheStatus;
        set => SetProperty(ref _dnsCacheStatus, value);
    }

    public void ShowDnsCache()
    {
        try
        {
            DnsCacheEntries.Clear();
            var entries = ConnectionMonitor.GetDnsCache();
            foreach (var e in entries.OrderBy(x => x.DomainName))
                DnsCacheEntries.Add(e);

            DnsCacheStatus = $"DNS cache: {entries.Count} entries";
            IsDnsCacheVisible = true;
        }
        catch (Exception ex)
        {
            DialogWindow.ShowError($"Failed to read DNS cache: {ex.Message}", "DNS Error");
        }
    }

    //  DHCP Info ─

    public int DhcpAdapterCount
    {
        get
        {
            try
            {
                var info = ConnectionMonitor.GetDhcpInfo();
                return info.Count(i => i.DhcpEnabled);
            }
            catch { return 0; }
        }
    }

    //  Stats 

    public int TotalConnections => Connections.Count;
    public int TcpConnections => Connections.Count(c => c.Protocol == NetworkProtocol.TCP);
    public int UdpConnections => Connections.Count(c => c.Protocol == NetworkProtocol.UDP);
    public int ArpEntries => Connections.Count(c => c.Protocol == NetworkProtocol.ARP);
    public int IcmpConnections => Connections.Count(c => c.Protocol == NetworkProtocol.ICMP || c.Protocol == NetworkProtocol.IPv6_ICMP);
    public int OtherProtocols => Connections.Count(c => c.Protocol != NetworkProtocol.TCP && c.Protocol != NetworkProtocol.UDP && c.Protocol != NetworkProtocol.ARP && c.Protocol != NetworkProtocol.ICMP && c.Protocol != NetworkProtocol.IPv6_ICMP);
    public int EstablishedCount => Connections.Count(c => c.TcpState == TcpState.Established);
    public int ListeningCount => Connections.Count(c => c.TcpState == TcpState.Listen);

    //  Commands 

    public ICommand StartCommand { get; }
    public ICommand StopCommand { get; }
    public ICommand RefreshCommand { get; }
    public ICommand DnsCacheCommand { get; }
    public ICommand DnsCacheCloseCommand { get; }

    //  Monitoring 

    public void StartMonitoring()
    {
        if (IsMonitoring) return;
        _monitor.Start(_refreshInterval);
        IsMonitoring = true;
    }

    public void StopMonitoring()
    {
        if (!IsMonitoring) return;
        _monitor.Stop();
        IsMonitoring = false;
    }

    public void ForceRefresh()
    {
        if (IsMonitoring)
        {
            _monitor.Stop();
            _monitor.Start(_refreshInterval);
        }
    }

    private void OnConnectionsUpdated(object? sender, IReadOnlyList<ConnectionEntry> entries)
    {
        // Queue all entries for background enrichment
        foreach (var entry in entries)
            _pendingEnrichment.Enqueue(entry);

        // Process enrichment in background
        Task.Run(() => ProcessEnrichmentQueue());

        // Schedule batched UI update
        ScheduleUiUpdate(entries);
    }

    private void ProcessEnrichmentQueue()
    {
        while (_pendingEnrichment.TryDequeue(out var entry))
            EnrichConnection(entry);
    }

    private void ScheduleUiUpdate(IReadOnlyList<ConnectionEntry> entries)
    {
        lock (_uiUpdateQueue)
        {
            // Store the latest snapshot for UI update
            _uiUpdateQueue.Enqueue(() =>
            {
                ApplyConnectionsSnapshot(entries);
            });

            if (!_uiUpdateScheduled)
            {
                _uiUpdateScheduled = true;
                _uiDispatcher.BeginInvoke(() => FlushUiUpdates(), DispatcherPriority.Background);
            }
        }
    }

    private void FlushUiUpdates()
    {
        List<Action> actions;
        lock (_uiUpdateQueue)
        {
            _uiUpdateScheduled = false;
            actions = _uiUpdateQueue.ToList();
            _uiUpdateQueue.Clear();
        }

        foreach (var action in actions)
            action();

        // Single property change notification for all computed properties
        OnPropertyChanged(nameof(TotalConnections));
        OnPropertyChanged(nameof(TcpConnections));
        OnPropertyChanged(nameof(UdpConnections));
        OnPropertyChanged(nameof(ArpEntries));
        OnPropertyChanged(nameof(IcmpConnections));
        OnPropertyChanged(nameof(OtherProtocols));
        OnPropertyChanged(nameof(EstablishedCount));
        OnPropertyChanged(nameof(ListeningCount));
        OnPropertyChanged(nameof(DhcpAdapterCount));
    }

    private void ApplyConnectionsSnapshot(IReadOnlyList<ConnectionEntry> entries)
    {
        lock (_sync)
        {
            var incomingIds = new HashSet<long>(entries.Count);
            foreach (var e in entries)
                incomingIds.Add(e.Id);

            // Remove stale connections
            for (int i = Connections.Count - 1; i >= 0; i--)
            {
                if (!incomingIds.Contains(Connections[i].Id))
                    Connections.RemoveAt(i);
            }

            // Index remaining items
            var existingById = new Dictionary<long, int>(Connections.Count);
            for (int i = 0; i < Connections.Count; i++)
                existingById[Connections[i].Id] = i;

            // Replace existing items in-place; add new ones
            foreach (var entry in entries)
            {
                if (existingById.TryGetValue(entry.Id, out var idx))
                    Connections[idx] = entry;
                else
                    Connections.Add(entry);
            }

            ConnectionStatus = $"Monitoring — {entries.Count} active connections";
        }
    }

    /// <summary>Enrich a connection with profile + GeoIP + bandwidth data.</summary>
    private void EnrichConnection(ConnectionEntry entry)
    {
        // Resolve profile by PID
        if (_profileManager != null && entry.ProcessId > 0)
        {
            var profile = _profileManager.MatchProcess(entry.ProcessId);
            entry.ProfileName = profile?.Name;
        }

        // Resolve GeoIP for remote address
        if (_geoLookup is { IsReady: true } && entry.RemoteAddress != null)
        {
            var geo = _geoLookup.Lookup(entry.RemoteAddress);
            if (geo != null)
            {
                entry.CountryCode = geo.CountryCode;
                entry.CountryName = geo.CountryName;
                entry.Asn = geo.Asn;
                entry.Organization = geo.Organization;
            }
        }

        // Report bytes to bandwidth tracker and retrieve rate stats
        if (_bandwidthTracker != null && entry.Id > 0)
        {
            _bandwidthTracker.ReportBytes(entry.Id, entry.ProcessId, entry.BytesSent, entry.BytesReceived);
            var bwStats = _bandwidthTracker.GetConnectionStats(entry.Id);
            if (bwStats != null)
            {
                entry.SentKbps = bwStats.SentKbps;
                entry.ReceivedKbps = bwStats.ReceivedKbps;
            }
        }
    }

    private bool FilterConnection(object obj)
    {
        if (string.IsNullOrWhiteSpace(_searchText))
            return true;

        if (obj is not ConnectionEntry c)
            return false;

        var s = _searchText.Trim();

        // .NET Framework 4.7.2: string.Contains(StringComparison) not available — use IndexOf
        return (c.ProcessName is not null &&
                c.ProcessName.IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0) ||
               (c.ProfileName is not null &&
                c.ProfileName.IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0) ||
               (c.CountryCode is not null &&
                c.CountryCode.IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0) ||
               (c.CountryName is not null &&
                c.CountryName.IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0) ||
               (c.RemoteAddress is not null &&
                c.RemoteAddress.ToString().IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0) ||
               (c.LocalAddress is not null &&
                c.LocalAddress.ToString().IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0) ||
               c.LocalPort.ToString().IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0 ||
               c.RemotePort.ToString().IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0 ||
               c.ProcessId.ToString().IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0;
    }
}
