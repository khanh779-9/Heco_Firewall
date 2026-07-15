using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using Heco.Common.Services.Bandwidth;
using Heco.Common.Services.Blocklists;
using Heco.Common.Services.GeoIp;
using Heco.Common.Services.Monitoring;
using Heco.Common.Models;
using Heco.Common.Enums;
using Heco.Common.Interfaces;
using Heco.Common.Services.Notifications;
using Heco.Common.Services.Process;
using Heco.Common.Services.Profiles;
using Heco.Common.Data;
// [WFP DISABLED] using Heco.Core.Engine;
using Heco.Common.Services.Diagnostics;
// [WFP DISABLED] using Heco.Core.Diagnostics;
using Heco.Common.Services.Settings;
using Heco_Firewall.Windows;
using Heco.Common.Services.Verdict;
using Heco_Firewall.Helpers;
using WinDivert = Heco.WinDivert.Models;
using Heco.WinDivert.Filtering;

namespace Heco_Firewall.ViewModels;

internal sealed class MainViewModel : ObservableObject
{
    // [WFP DISABLED] private readonly WfpEngine _engine;
    private readonly FirewallRuleRepository _repository;
    private readonly RulesViewModel _rulesVm;
    private readonly ConnectionsViewModel _connectionsVm;
    private readonly SettingsViewModel _settingsVm;
    private readonly SettingsService _settingsService;
    private readonly IProcessMonitor _processMonitor;
    private readonly IProfileManager _profileManager;
    private readonly IBlocklistManager _blocklistManager;
    private readonly IEventWatcher _eventWatcher;
    private readonly INotificationService _notificationService;
    private readonly ProfilesViewModel _profilesVm;
    private readonly BlocklistsViewModel _blocklistsVm;
    private readonly ActivityViewModel _activityVm;
    private readonly IVerdictEngine _verdictEngine;
    private readonly IBandwidthTracker _bandwidthTracker;
    private readonly IGeoLookup _geoLookup;
    private readonly HashSet<string> _promptedApps = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _promptLock = new();
    private readonly Queue<(ConnectionEntry connection, Action<RuleAction>? onVerdict)> _promptQueue = new();
    private bool _isPromptShowing;

    private string _statusText = "Disconnected";
    private bool _isEngineOpen;
    private bool _isBusy;
    private int _selectedTabIndex;
    private int _blockedConnectionsToday;
    private int _dynamicFilterCount;
    private string? _warningText;
    private bool _hasWarning;

    // ── Dynamic filter limits ──────────────────────────────────
    private const int MaxDynamicFilters = 100;
    private WinDivertFilter? _winDivertFilter;
    private WinDivertDnsRedirector? _dnsRedirector;

    public MainViewModel()
    {
        // [WFP DISABLED] _engine = new WfpEngine();
        _repository = new FirewallRuleRepository();
        _settingsService = new SettingsService();

        // Initialize service modules
        _processMonitor = new ProcessMonitor();
        _profileManager = new ProfileManager(_processMonitor, _settingsService);
        _blocklistManager = new BlocklistManager();
        _eventWatcher = new EventWatcher(_processMonitor, _profileManager);
        _notificationService = new NotificationService();

        // Initialize verdict pipeline (blocklists → profiles → rules)
        _verdictEngine = new VerdictEngine(_profileManager, _blocklistManager);

        // Initialize bandwidth tracker
        _bandwidthTracker = new BandwidthTracker();

        // Load settings at startup (before creating ViewModels that depend on them)
        _settingsService.Load();

        // Initialize GeoIP lookup with absolute path from settings
        _geoLookup = new GeoLookup();
        var geoIpPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, _settingsService.AppSettings.GeoIpDatabasePath);
        _ = _geoLookup.LoadAsync(geoIpPath);

        _rulesVm = new RulesViewModel(_repository);
        _rulesVm.LoadRules();
        _connectionsVm = new ConnectionsViewModel(_profileManager, _geoLookup, _bandwidthTracker);
        _settingsVm = new SettingsViewModel(_settingsService);

        // Initialize UI ViewModels for services
        _profilesVm = new ProfilesViewModel(_profileManager);
        _blocklistsVm = new BlocklistsViewModel(_blocklistManager);
        _activityVm = new ActivityViewModel(_eventWatcher, _notificationService);

        OpenEngineCommand = new RelayCommand(async _ => await OpenEngineAsync(), _ => !IsEngineOpen && !IsBusy);
        CloseEngineCommand = new RelayCommand(async _ => await CloseEngineAsync(), _ => IsEngineOpen && !IsBusy);
        ToggleEngineCommand = new RelayCommand(_ => { _ = ToggleEngineAsync(); }, _ => !IsBusy);

        // Auto-enable self-defense if configured
        _ = _settingsVm.TryAutoEnableAsync();

        // Auto-start WinDivert engine + connection monitoring on launch (if was active)
        if (_settingsService.AppSettings.FirewallActive)
            _ = OpenEngineAsync();

        // Initialize logger
        Logger.Initialize();
        Logger.Info("Heco Firewall started");
    }

    // ── Properties ───────────────────────────────────────────────

    public RulesViewModel Rules => _rulesVm;
    public ConnectionsViewModel Connections => _connectionsVm;
    public SettingsViewModel Settings => _settingsVm;
    public ProfilesViewModel Profiles => _profilesVm;
    public BlocklistsViewModel Blocklists => _blocklistsVm;
    public ActivityViewModel Activity => _activityVm;

    /// <summary>Cleanup all services on shutdown.</summary>
    public void Cleanup()
    {
        _settingsVm.Cleanup();
    }

    /// <summary>Notification service for showing block notifications.</summary>
    public INotificationService NotificationService => _notificationService;

    public string StatusText
    {
        get => _statusText;
        set => SetProperty(ref _statusText, value);
    }

    public string? WarningText
    {
        get => _warningText;
        set
        {
            if (SetProperty(ref _warningText, value))
                HasWarning = !string.IsNullOrEmpty(value);
        }
    }

    public bool HasWarning
    {
        get => _hasWarning;
        set => SetProperty(ref _hasWarning, value);
    }

    public bool IsEngineOpen
    {
        get => _isEngineOpen;
        set
        {
            if (SetProperty(ref _isEngineOpen, value))
            {
                StatusText = value ? "Engine connected — running as Administrator" : "Disconnected";
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }

    public bool IsBusy
    {
        get => _isBusy;
        set
        {
            if (SetProperty(ref _isBusy, value))
                CommandManager.InvalidateRequerySuggested();
        }
    }

    public int SelectedTabIndex
    {
        get => _selectedTabIndex;
        set => SetProperty(ref _selectedTabIndex, value);
    }

    /// <summary>How many connections were blocked by the verdict engine this session.</summary>
    public int BlockedConnectionsToday
    {
        get => _blockedConnectionsToday;
        set => SetProperty(ref _blockedConnectionsToday, value);
    }

    // ── Commands ─────────────────────────────────────────────────

public ICommand OpenEngineCommand { get; }
        public ICommand CloseEngineCommand { get; }
        public ICommand ToggleEngineCommand { get; }

    // ── Engine Lifecycle ──────────────────────────────────────────

    public async Task OpenEngineAsync()
    {
        if (IsBusy) return;
        IsBusy = true;
        try
        {
            // Set state immediately so UI responds
            IsEngineOpen = true;

            // Load rules from disk (lightweight)
            _rulesVm.LoadRules();

            // Subscribe to connection-time verdict evaluation
            _connectionsVm.ConnectionMonitor.ConnectionAdded += OnConnectionVerdict;
            _connectionsVm.StartMonitoring();
            Logger.Info("Connection verdict monitoring active");

            // Initialize and start WinDivert on background thread (heavy I/O)
            await Task.Run(() =>
            {
                _winDivertFilter = new WinDivertFilter(
                    processResolver: (pid) => _processMonitor.GetProcessInfo(pid)?.ExecutablePath,
                    verdictChecker: (wdConnection) =>
                    {
                        var connection = new ConnectionEntry
                        {
                            Protocol = (NetworkProtocol)(byte)wdConnection.Protocol,
                            LocalAddress = wdConnection.LocalAddress,
                            LocalPort = wdConnection.LocalPort,
                            RemoteAddress = wdConnection.RemoteAddress,
                            RemotePort = wdConnection.RemotePort,
                            ProcessId = wdConnection.ProcessId,
                            ProcessName = wdConnection.ProcessName,
                            ProcessPath = wdConnection.ProcessPath,
                            IsInbound = wdConnection.IsInbound,
                            FirstSeen = wdConnection.FirstSeen,
                            LastSeen = wdConnection.LastSeen
                        };
                        var engineVerdict = _verdictEngine.Evaluate(connection);
                        if (engineVerdict.Action == RuleAction.Block)
                            return new VerdictDecision { Action = WinDivert.RuleAction.Block, ShouldCache = false };

                        var appPath = wdConnection.ProcessPath;
                        if (!string.IsNullOrEmpty(appPath))
                        {
                            if (HasRuleForApp(appPath!))
                            {
                                var rule = _repository.LoadAll().FirstOrDefault(r => string.Equals(r.ApplicationPath, appPath, StringComparison.OrdinalIgnoreCase));
                                if (rule != null)
                                    return new VerdictDecision { Action = (WinDivert.RuleAction)rule.Action, ShouldCache = true };
                            }
                            foreach (var profile in _profileManager.Profiles)
                            {
                                if (profile.IsSpecial || profile.ActionOverride == null) continue;
                                var matches = profile.Fingerprints?.Any(fp =>
                                    !string.IsNullOrEmpty(fp.Value) &&
                                    appPath!.IndexOf(fp.Value!, StringComparison.OrdinalIgnoreCase) >= 0) == true;
                                if (matches)
                                {
                                    if (profile.ActionOverride.BlockOutbound == true)
                                        return new VerdictDecision { Action = WinDivert.RuleAction.Block, ShouldCache = true };
                                    if (profile.ActionOverride.AllowOutbound == true)
                                        return new VerdictDecision { Action = WinDivert.RuleAction.Permit, ShouldCache = true };
                                }
                            }
                        }
                        return null;
                    },
                    promptAction: (wdConnection, onVerdict) =>
                    {
                        var connection = new ConnectionEntry
                        {
                            Protocol = (NetworkProtocol)(byte)wdConnection.Protocol,
                            LocalAddress = wdConnection.LocalAddress,
                            LocalPort = wdConnection.LocalPort,
                            RemoteAddress = wdConnection.RemoteAddress,
                            RemotePort = wdConnection.RemotePort,
                            ProcessId = wdConnection.ProcessId,
                            ProcessName = wdConnection.ProcessName,
                            ProcessPath = wdConnection.ProcessPath,
                            IsInbound = wdConnection.IsInbound,
                            FirstSeen = wdConnection.FirstSeen,
                            LastSeen = wdConnection.LastSeen
                        };
                        EnqueuePrompt(connection, (v) => onVerdict((WinDivert.RuleAction)v));
                    }
                );
                _winDivertFilter.Start();
            });

            if (!_winDivertFilter.IsRunning)
            {
                Logger.Warn("WinDivert not active — driver may not be installed.");
                StatusText = "Engine connected — WinDivert unavailable";
                WarningText = "WinDivert driver not installed";
            }

            // Start DNS redirector on background thread
            await Task.Run(() =>
            {
                _dnsRedirector = new WinDivertDnsRedirector(
                    blockChecker: (domain) => _blocklistManager.IsDomainBlocked(domain),
                    dohEnabledProvider: () => _settingsService.AppSettings.SecureDnsEnabled,
                    dohUrlProvider: () => _settingsService.AppSettings.DnsOverHttpsProvider
                );
                _dnsRedirector.Start();
            });

            _bandwidthTracker.Start();

            _settingsService.AppSettings.FirewallActive = true;

            ToastWindow.Show(Application.Current.MainWindow,
                "Firewall Active", "Protection and connection monitoring are now enabled.",
                ToastType.Success, 4000);
        }
        catch (Exception ex)
        {
            IsEngineOpen = false;
            DialogWindow.ShowError($"Failed to start firewall: {ex.Message}", "Error");
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task CloseEngineAsync()
    {
        if (IsBusy) return;
        IsBusy = true;
        try
        {
            // Stop WinDivert on background thread
            await Task.Run(() =>
            {
                if (_winDivertFilter != null)
                {
                    _winDivertFilter.Stop();
                    _winDivertFilter.Dispose();
                    _winDivertFilter = null;
                }
                if (_dnsRedirector != null)
                {
                    _dnsRedirector.Stop();
                    _dnsRedirector.Dispose();
                    _dnsRedirector = null;
                }
            });

            _connectionsVm.ConnectionMonitor.ConnectionAdded -= OnConnectionVerdict;
            _connectionsVm.StopMonitoring();
            _bandwidthTracker.Stop();
            IsEngineOpen = false;
            _settingsService.AppSettings.FirewallActive = false;
            WarningText = null;
            BlockedConnectionsToday = 0;
            _dynamicFilterCount = 0;

            ToastWindow.Show(Application.Current.MainWindow,
                "Firewall Disabled", "Protection and connection monitoring have been turned off.",
                ToastType.Warning, 4000);
        }
        catch (Exception ex)
        {
            DialogWindow.ShowWarning($"Error closing engine: {ex.Message}", "Engine");
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task ToggleEngineAsync()
    {
        if (IsEngineOpen)
            await CloseEngineAsync();
        else
            await OpenEngineAsync();
    }

        // [WFP DISABLED]
    // public async Task ApplyRulesAsync()
    // {
    //     IsBusy = true;
    //     try
    //     {
    //         List<FirewallRule>? enhancedRules = null;
    //
    //         await Task.Run(() =>
    //         {
    //             _engine.ClearAllRules();
    //             var userRules = _repository.LoadAll();
    //             enhancedRules = _verdictEngine.GenerateRuleSet(userRules);
    //             _engine.ApplyRules(enhancedRules ?? (IEnumerable<FirewallRule>)Array.Empty<FirewallRule>());
    //         });
    //
    //         _winDivertFilter?.ClearCache();
    //
    //         var userCount = _rulesVm.Rules.Count(r => r.IsEnabled);
    //         var totalCount = enhancedRules?.Count ?? userCount;
    //         StatusText = $"Rules applied — {userCount} user rules ({totalCount} total with blocklists/profiles)";
    //
    //         Logger.Info($"Verdict pipeline: {userCount} user rules → {totalCount} WFP filters applied");
    //     }
    //     catch (HecoException ex)
    //     {
    //         DialogWindow.ShowError($"Failed to apply rules.\n\nError: {ex.Message}", "Apply Rules");
    //     }
    //     finally
    //     {
    //         IsBusy = false;
    //     }
    // }

    // [WFP DISABLED]
    // public async Task ClearRulesAsync()
    // {
    //     IsBusy = true;
    //     try
    //     {
    //         await Task.Run(() => _engine.ClearAllRules());
    //         _winDivertFilter?.ClearCache();
    //         _rulesVm.ClearWfpFilterIds();
    //         StatusText = "All WFP filters cleared";
    //     }
    //     catch (Exception ex)
    //     {
    //         DialogWindow.ShowWarning($"Error clearing rules: {ex.Message}", "Clear Rules");
    //     }
    //     finally
    //     {
    //         IsBusy = false;
    //     }
    // }

    // [WFP DISABLED] Dynamic WFP Block Filters
    // private void AddDynamicBlockFilter(ConnectionEntry connection)
    // {
    //     if (_dynamicFilterCount >= MaxDynamicFilters)
    //         return;
    //
    //     if (connection.RemoteAddress is null)
    //         return;
    //
    //     try
    //     {
    //         var ipStr = connection.RemoteAddress.ToString();
    //
    //         var blockRule = new FirewallRule
    //         {
    //             Name = $"[Dynamic] Block {ipStr}",
    //             Description = $"Auto-generated by verdict engine — blocked {connection.ProcessName ?? $"PID:{connection.ProcessId}"}",
    //             Action = RuleAction.Block,
    //             Direction = TrafficDirection.Outbound,
    //             RemoteAddress = ipStr,
    //             Protocol = NetworkProtocol.Any,
    //             IsEnabled = true,
    //             CreatedAt = DateTime.UtcNow
    //         };
    //
    //         _engine.AddRule(blockRule);
    //         _dynamicFilterCount++;
    //
    //         Logger.Debug($"Dynamic block filter added for {ipStr} ({_dynamicFilterCount}/{MaxDynamicFilters})");
    //     }
    //     catch (Exception ex)
    //     {
    //         Logger.Debug($"AddDynamicBlockFilter error: {ex.Message}");
    //     }
    // }

    // ── Connection-time Verdict Evaluation ─────────────────────────

    private bool HasRuleForApp(string appPath)
    {
        if (string.IsNullOrEmpty(appPath)) return false;
        return _repository.LoadAll().Any(r => string.Equals(r.ApplicationPath, appPath, StringComparison.OrdinalIgnoreCase));
    }

    private void HandlePromptVerdict(ConnectionEntry connection, Windows.PromptVerdict verdict)
    {
        switch (verdict)
        {
            case Windows.PromptVerdict.AllowOnce:
                Logger.Info($"Interactive: User allowed connection once for {connection.ProcessName}");
                break;

            case Windows.PromptVerdict.BlockOnce:
                // [WFP DISABLED] AddDynamicBlockFilter(connection);
                Logger.Info($"Interactive: User blocked connection once for {connection.ProcessName}");
                break;

            case Windows.PromptVerdict.AlwaysAllow:
                var allowRule = new FirewallRule
                {
                    Name = $"Allow {connection.ProcessName} Outbound",
                    Description = $"Auto-generated via Interactive Prompt",
                    Action = RuleAction.Permit,
                    Direction = TrafficDirection.Outbound,
                    IsEnabled = true,
                    ApplicationPath = connection.ProcessPath,
                    Protocol = NetworkProtocol.Any
                };
                _rulesVm.AddAndApplyRule(allowRule);
                Logger.Info($"Interactive: User allowed connection permanently for {connection.ProcessName}");
                break;

            case Windows.PromptVerdict.AlwaysBlock:
                var blockRule = new FirewallRule
                {
                    Name = $"Block {connection.ProcessName} Outbound",
                    Description = $"Auto-generated via Interactive Prompt",
                    Action = RuleAction.Block,
                    Direction = TrafficDirection.Outbound,
                    IsEnabled = true,
                    ApplicationPath = connection.ProcessPath,
                    Protocol = NetworkProtocol.Any
                };
                _rulesVm.AddAndApplyRule(blockRule);
                Logger.Info($"Interactive: User blocked connection permanently for {connection.ProcessName}");
                break;
        }
    }

    // ── Prompt Queue (one at a time) ─────────────────────────────

    private void EnqueuePrompt(ConnectionEntry connection, Action<RuleAction>? onVerdict)
    {
        lock (_promptLock)
        {
            _promptQueue.Enqueue((connection, onVerdict));
        }
        TryShowNextPrompt();
    }

    private void TryShowNextPrompt()
    {
        ConnectionEntry connection;
        Action<RuleAction>? onVerdict;

        lock (_promptLock)
        {
            if (_isPromptShowing || _promptQueue.Count == 0) return;
            _isPromptShowing = true;
            (connection, onVerdict) = _promptQueue.Dequeue();
        }

        System.Windows.Application.Current?.Dispatcher?.BeginInvoke(new Action(() =>
        {
            try
            {
                var promptWin = new Windows.PromptWindow(connection);
                promptWin.Owner = System.Windows.Application.Current.MainWindow;
                if (promptWin.ShowDialog() == true)
                {
                    var selection = promptWin.Verdict;
                    HandlePromptVerdict(connection, selection);

                    var action = (selection == Windows.PromptVerdict.AlwaysAllow || selection == Windows.PromptVerdict.AllowOnce)
                        ? RuleAction.Permit
                        : RuleAction.Block;

                    onVerdict?.Invoke(action);
                }
                else
                {
                    onVerdict?.Invoke(RuleAction.Permit);
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Prompt error: {ex.Message}");
                onVerdict?.Invoke(RuleAction.Block);
            }
            finally
            {
                lock (_promptLock)
                {
                    _isPromptShowing = false;
                }
                TryShowNextPrompt();
            }
        }));
    }

    /// <summary>
    ///   Called when a new connection is detected by ConnectionPatrol.
    ///   Evaluates it through the verdict pipeline and blocks if matched.
    /// </summary>
    private void OnConnectionVerdict(object? sender, ConnectionEntry connection)
    {
        try
        {
            var verdict = _verdictEngine.Evaluate(connection);

            // Handle Interactive Connection Mode prompting
            if (verdict.Action != RuleAction.Block && 
                _settingsService.AppSettings.InteractiveMode && 
                connection.ProcessId > 4 && 
                !string.IsNullOrEmpty(connection.ProcessPath))
            {
                var appPath = connection.ProcessPath!;
                bool alreadyPrompted;
                lock (_promptedApps)
                {
                    alreadyPrompted = _promptedApps.Contains(appPath);
                }

                // Check if process has an actionable profile (not the built-in "Unknown" special profile)
                var matchedProfile = _profileManager.MatchProcess(connection.ProcessId);
                bool hasActionableProfile = matchedProfile != null &&
                    !string.Equals(matchedProfile.Name, "Unknown", StringComparison.OrdinalIgnoreCase);

                if (!alreadyPrompted && !HasRuleForApp(appPath) && !hasActionableProfile)
                {
                    lock (_promptedApps)
                    {
                        _promptedApps.Add(appPath);
                    }

                    EnqueuePrompt(connection, null);
                }
            }

            if (verdict.Action != RuleAction.Block)
                return;

            // Must dispatch to UI thread for property changes
            System.Windows.Application.Current?.Dispatcher?.BeginInvoke(new Action(() =>
            {
                BlockedConnectionsToday++;

                // Log as a verdict block event for the Activity page
                var blockEvent = new BlockEventInfo
                {
                    EventId = DateTime.UtcNow.Ticks,
                    Timestamp = DateTime.UtcNow,
                    Protocol = connection.Protocol.ToString(),
                    SourceAddress = connection.LocalAddress.ToString(),
                    SourcePort = connection.LocalPort,
                    DestAddress = connection.RemoteAddress.ToString(),
                    DestPort = connection.RemotePort,
                    ApplicationPath = connection.ProcessPath ?? connection.ProcessName ?? "Unknown",
                    ProcessId = connection.ProcessId,
                    Direction = connection.IsInbound ? "Inbound" : "Outbound",
                    ProfileName = verdict.Source
                };

                _eventWatcher.LogBlockEvent(blockEvent);
                Logger.Info($"VERDICT BLOCK [{verdict.Source}]: {connection.ProcessName ?? $"PID:{connection.ProcessId}"} → {connection.RemoteAddress}:{connection.RemotePort}");

                // [WFP DISABLED] Add dynamic WFP block filter for this remote IP
                // AddDynamicBlockFilter(connection);

                // Also show notification if enabled
                if (_settingsService.AppSettings.ShowNotifications)
                {
                    _notificationService.ShowBlockNotification(new BlockNotificationInfo
                    {
                        ProcessName = connection.ProcessName ?? "Unknown",
                        ProcessId = connection.ProcessId,
                        Protocol = connection.Protocol.ToString(),
                        LocalAddress = connection.LocalAddress.ToString(),
                        LocalPort = connection.LocalPort,
                        RemoteAddress = connection.RemoteAddress.ToString(),
                        RemotePort = connection.RemotePort,
                        Direction = connection.IsInbound ? "Inbound" : "Outbound",
                        ProfileName = verdict.Source,
                        Timestamp = DateTime.Now
                    });
                }
            }));
        }
        catch (Exception ex)
        {
            Logger.Debug($"OnConnectionVerdict error: {ex.Message}");
        }
    }
}
