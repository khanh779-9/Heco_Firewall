using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Input;
using Heco.Common.Services.Monitoring;
using Heco.Common.Services.Notifications;
using Heco_Firewall.Helpers;

namespace Heco_Firewall.ViewModels;

internal sealed class ActivityViewModel : ObservableObject
{
    private readonly IEventWatcher _eventWatcher;
    private readonly INotificationService _notificationService;
    private BlockEventInfo? _selectedBlockEvent;
    private string _statusText = string.Empty;

    public ActivityViewModel(IEventWatcher eventWatcher, INotificationService notificationService)
    {
        _eventWatcher = eventWatcher;
        _notificationService = notificationService;

        StartCommand = new RelayCommand(_ => Start(), _ => !_eventWatcher.IsRunning);
        StopCommand = new RelayCommand(_ => Stop(), _ => _eventWatcher.IsRunning);
        ClearCommand = new RelayCommand(_ => Clear());
        RefreshCommand = new RelayCommand(_ => RefreshStatus());

        _eventWatcher.BlockEventCaptured += OnBlockEventCaptured;

        UpdateStatus();
    }

    //  Properties 

    public IReadOnlyList<BlockEventInfo> BlockEvents => _eventWatcher.RecentBlockEvents;
    public IReadOnlyList<DnsQueryEventInfo> DnsQueries => _eventWatcher.RecentDnsQueries;

    public BlockEventInfo? SelectedBlockEvent
    {
        get => _selectedBlockEvent;
        set => SetProperty(ref _selectedBlockEvent, value);
    }

    public bool IsRunning => _eventWatcher.IsRunning;

    public string StatusText
    {
        get => _statusText;
        set => SetProperty(ref _statusText, value);
    }

    public int BlockEventCount => BlockEvents.Count;
    public int DnsQueryCount => DnsQueries.Count;

    //  Commands 

    public ICommand StartCommand { get; }
    public ICommand StopCommand { get; }
    public ICommand ClearCommand { get; }
    public ICommand RefreshCommand { get; }

    //  Methods ─

    public void Start()
    {
        _eventWatcher.Start();
        OnPropertyChanged(nameof(IsRunning));
        CommandManager.InvalidateRequerySuggested();
        UpdateStatus();
    }

    public void Stop()
    {
        _eventWatcher.Stop();
        OnPropertyChanged(nameof(IsRunning));
        CommandManager.InvalidateRequerySuggested();
        UpdateStatus();
    }

    public void Clear()
    {
        _eventWatcher.ClearEvents();
        RefreshStatus();
    }

    public void RefreshStatus()
    {
        OnPropertyChanged(nameof(BlockEventCount));
        OnPropertyChanged(nameof(DnsQueryCount));
        OnPropertyChanged(nameof(BlockEvents));
        OnPropertyChanged(nameof(DnsQueries));
        UpdateStatus();
    }

    private void OnBlockEventCaptured(object? sender, BlockEventInfo e)
    {
        RefreshStatus();
    }

    private void UpdateStatus()
    {
        var running = IsRunning ? "● Running" : "○ Stopped";
        StatusText = $"{running} · {BlockEventCount} block events";
    }
}
