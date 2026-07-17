using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.Versioning;
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
using Heco.Common.Services.Diagnostics;
using Heco.Common.Services.Settings;
using Heco_Firewall.Windows;
using Heco.Common.Services.Verdict;
using Heco_Firewall.Helpers;
using Heco.WinDivert.Filtering;
using Heco.WinDivert.Services;
using WinDivert = Heco.WinDivert.Models;

namespace Heco_Firewall.ViewModels;

/// <summary>
///   Root ViewModel for the application.
///   Orchestrates service dependencies and child ViewModels.
///
///   Sections:
///   1. Fields + Constructor
///   2. Child ViewModel Accessors + Observable Properties + Commands
///   3. Engine Lifecycle (OpenEngine / CloseEngine / Toggle)
///   4. Interactive Prompt Queue (Enqueue / Show / HandleVerdict)
///   5. Connection Verdict Handler (OnConnectionVerdict)
///   6. Default Profile Seeding (SeedDefaultProfilesAsync)
///   7. Helper Methods
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class MainViewModel : ObservableObject
{
    // ── Service dependencies ─────────────────────────────────────────
    private readonly FirewallRuleRepository _repository;
    private readonly SettingsService _settingsService;
    private readonly IProcessMonitor _processMonitor;
    private readonly IProfileManager _profileManager;
    private readonly IBlocklistManager _blocklistManager;
    private readonly IEventWatcher _eventWatcher;
    private readonly INotificationService _notificationService;
    private readonly IVerdictEngine _verdictEngine;
    private readonly IBandwidthTracker _bandwidthTracker;
    private readonly IGeoLookup _geoLookup;

    // ── Child ViewModels ─────────────────────────────────────────────
    private readonly RulesViewModel _rulesVm;
    private readonly ConnectionsViewModel _connectionsVm;
    private readonly SettingsViewModel _settingsVm;
    private readonly ProfilesViewModel _profilesVm;
    private readonly BlocklistsViewModel _blocklistsVm;
    private readonly ActivityViewModel _activityVm;

    // ── Prompt queue state ───────────────────────────────────────────
    private readonly HashSet<string> _promptedApps = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _promptLock = new();
    private readonly Queue<(ConnectionEntry connection, Action<RuleAction>? onVerdict)> _promptQueue = new();
    private bool _isPromptShowing;

    // ── Engine state ─────────────────────────────────────────────────
    private WinDivertFilter? _winDivertFilter;
    private WinDivertDnsRedirector? _dnsRedirector;

    // ── Observable backing fields ────────────────────────────────────
    private string _statusText = "Disconnected";
    private bool _isEngineOpen;
    private bool _isBusy;
    private int _selectedTabIndex;
    private int _blockedConnectionsToday;
    private string? _warningText;
    private bool _hasWarning;

    // ═════════════════════════════════════════════════════════════════
    //  1. Constructor
    // ═════════════════════════════════════════════════════════════════

    [SupportedOSPlatform("windows")]
    public MainViewModel()
    {
        // 1. Core services
        _repository = new FirewallRuleRepository();
        _settingsService = new SettingsService();
        _processMonitor = new ProcessMonitor();
        _profileManager = new ProfileManager(_processMonitor, _settingsService);
        _blocklistManager = new BlocklistManager();
        _eventWatcher = new EventWatcher(_processMonitor, _profileManager);
        _notificationService = new NotificationService();
        _verdictEngine = new VerdictEngine(_profileManager, _blocklistManager);
        _bandwidthTracker = new BandwidthTracker();

        // 2. Load persisted settings (before ViewModels that depend on them)
        _settingsService.Load();

        // 3. GeoIP lookup
        _geoLookup = new GeoLookup();
        var geoIpPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, _settingsService.AppSettings.GeoIpDatabasePath);
        _ = _geoLookup.LoadAsync(geoIpPath);

        // 4. Child ViewModels
        _rulesVm = new RulesViewModel(_repository);
        _rulesVm.LoadRules();

        _connectionsVm = new ConnectionsViewModel(_profileManager, _geoLookup, _bandwidthTracker);
        _connectionsVm.StartMonitoring();
        _connectionsVm.ConnectionMonitor.ConnectionAdded += OnConnectionVerdict;

        _settingsVm = new SettingsViewModel(_settingsService);
        _profilesVm = new ProfilesViewModel(_profileManager);
        _blocklistsVm = new BlocklistsViewModel(_blocklistManager);
        _activityVm = new ActivityViewModel(_eventWatcher, _notificationService);

        // 5. Commands
        OpenEngineCommand = new RelayCommand(async _ => await OpenEngineAsync(), _ => !IsEngineOpen && !IsBusy);
        CloseEngineCommand = new RelayCommand(async _ => await CloseEngineAsync(), _ => IsEngineOpen && !IsBusy);
        ToggleEngineCommand = new RelayCommand(_ => { _ = ToggleEngineAsync(); }, _ => !IsBusy);
        CopyErrorDetailCommand = new RelayCommand(_ => CopyErrorDetailToClipboard(), _ => HasWarning);

        // 6. Auto-start engine if it was active last session
        if (_settingsService.AppSettings.FirewallActive)
            _ = OpenEngineAsync();

        // 7. Seed default profiles (background)
        _ = Task.Run(() => SeedDefaultProfilesAsync());

        // 8. Logger
        Logger.Initialize();
        Logger.Info("Heco Firewall started");
    }

    // ═════════════════════════════════════════════════════════════════
    //  2. Child ViewModel Accessors + Observable Properties + Commands
    // ═════════════════════════════════════════════════════════════════

    public RulesViewModel Rules => _rulesVm;
    public ConnectionsViewModel Connections => _connectionsVm;
    public SettingsViewModel Settings => _settingsVm;
    public ProfilesViewModel Profiles => _profilesVm;
    public BlocklistsViewModel Blocklists => _blocklistsVm;
    public ActivityViewModel Activity => _activityVm;

    /// <summary>Notification service for showing block notifications (used by TrayService).</summary>
    public INotificationService NotificationService => _notificationService;

    /// <summary>Status bar text shown at the bottom of the main window.</summary>
    public string StatusText
    {
        get => _statusText;
        set => SetProperty(ref _statusText, value);
    }

    /// <summary>Warning/error detail text shown when the engine fails to start.</summary>
    public string? WarningText
    {
        get => _warningText;
        set
        {
            if (SetProperty(ref _warningText, value))
                HasWarning = !string.IsNullOrEmpty(value);
        }
    }

    /// <summary>Whether a warning/error is currently active.</summary>
    public bool HasWarning
    {
        get => _hasWarning;
        set => SetProperty(ref _hasWarning, value);
    }

    /// <summary>Whether the WinDivert engine is currently running.</summary>
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

    /// <summary>Whether an engine operation (start/stop) is in progress.</summary>
    public bool IsBusy
    {
        get => _isBusy;
        set
        {
            if (SetProperty(ref _isBusy, value))
                CommandManager.InvalidateRequerySuggested();
        }
    }

    /// <summary>Currently selected tab index in the main window.</summary>
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

    public ICommand OpenEngineCommand { get; }
    public ICommand CloseEngineCommand { get; }
    public ICommand ToggleEngineCommand { get; }
    public ICommand CopyErrorDetailCommand { get; }

    // ═════════════════════════════════════════════════════════════════
    //  3. Engine Lifecycle
    // ═════════════════════════════════════════════════════════════════

    /// <summary>
    ///   Start the WinDivert packet filter and DNS redirector.
    ///   Loads rules, begins connection monitoring, and enables real-time verdict evaluation.
    /// </summary>
    public async Task OpenEngineAsync()
    {
        if (IsBusy) return;
        IsBusy = true;
        try
        {
            // Load rules from disk (lightweight)
            _rulesVm.LoadRules();

            // Connection monitoring already subscribed in constructor
            _connectionsVm.StartMonitoring();
            Logger.Info("Connection verdict monitoring active");

            // Let WinDivert's own DLL install and start the driver via WinDivertOpen.
            await Task.Run(() =>
            {
                var driverVersion = WinDivertDriverManager.GetDriverVersion();
                if (driverVersion != null)
                    Logger.Info($"WinDivert driver version: {driverVersion}");

                _winDivertFilter = new WinDivertFilter(
                    processResolver: (pid) => _processMonitor.GetProcessInfo(pid)?.ExecutablePath,
                    verdictChecker: EvaluateWinDivertVerdict,
                    promptAction: (wdConnection, onVerdict) =>
                    {
                        var connection = MapConnection(wdConnection);
                        EnqueuePrompt(connection, (v) => onVerdict(ToWinDivertAction(v)));
                    }
                );
                _winDivertFilter.Start();
            });

            if (_winDivertFilter == null || !_winDivertFilter.IsRunning)
            {
                ReportWinDivertFailure();
                _connectionsVm.StopMonitoring();
                return;
            }

            IsEngineOpen = true;

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
            _connectionsVm.StopMonitoring();
            var errCode = WinDivertDriverManager.LastErrorCode;
            var errInfo = errCode.HasValue
                ? $"\nError code: 0x{errCode.Value:X8} ({errCode.Value}) — {WinDivert.Win32Errors.GetDescription(errCode.Value)}"
                : "";
            DialogWindow.ShowError($"Failed to start firewall: {ex.Message}{errInfo}", "Error");
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>
    ///   Stop the WinDivert packet filter and DNS redirector.
    ///   Unsubscribes connection events and resets engine state.
    /// </summary>
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
            _bandwidthTracker.Stop();
            IsEngineOpen = false;
            _settingsService.AppSettings.FirewallActive = false;
            WarningText = null;
            BlockedConnectionsToday = 0;

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

    /// <summary>Toggle engine on/off based on current state.</summary>
    public async Task ToggleEngineAsync()
    {
        if (IsEngineOpen)
            await CloseEngineAsync();
        else
            await OpenEngineAsync();
    }

    /// <summary>
    ///   Evaluate a WinDivert connection against the verdict pipeline.
    ///   Called by the WinDivert filter thread for each intercepted packet.
    /// </summary>
    /// <returns>A <see cref="VerdictDecision"/> to apply, or null to prompt the user.</returns>
    private VerdictDecision? EvaluateWinDivertVerdict(WinDivert.ConnectionEntry wdConnection)
    {
        var connection = MapConnection(wdConnection);
        var engineVerdict = _verdictEngine.Evaluate(connection);

        // Blocklist/profile said Block → block immediately
        if (engineVerdict.Action == RuleAction.Block)
            return new VerdictDecision { Action = WinDivert.RuleAction.Block, ShouldCache = false };

        // Check user-defined rules by application path
        var appPath = wdConnection.ProcessPath;
        if (!string.IsNullOrEmpty(appPath))
        {
            if (HasRuleForApp(appPath!))
            {
                var rule = _repository.LoadAll()
                    .FirstOrDefault(r => string.Equals(r.ApplicationPath, appPath, StringComparison.OrdinalIgnoreCase));
                if (rule != null)
                    return new VerdictDecision { Action = ToWinDivertAction(rule.Action), ShouldCache = true };
            }

            // Check profile fingerprints
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

        // No match — let WinDivert decide (prompt or pass)
        return null;
    }

    /// <summary>Report a WinDivert driver failure to the user via status bar and warning text.</summary>
    private void ReportWinDivertFailure()
    {
        var errCode = WinDivertFilter.LastOpenError != 0
            ? WinDivertFilter.LastOpenError
            : (WinDivertDriverManager.LastErrorCode ?? 0);
        var errDetail = errCode != 0
            ? $" (0x{errCode:X8})"
            : " (unknown error)";
        var errDesc = WinDivert.Win32Errors.GetDescription(errCode);
        var hint = WinDivertDriverManager.GetErrorHint(errCode);
        var hintSuffix = hint != null ? $"\n{hint}" : "";

        Logger.Warn($"WinDivert not active — failed to open device (error {errCode})");
        StatusText = "Engine idle — WinDivert unavailable";
        WarningText = $"WinDivert driver error: failed to open device{errDetail}\n{errDesc}{hintSuffix}";
    }

    /// <summary>Copy the current warning/error details to clipboard for diagnostics.</summary>
    private void CopyErrorDetailToClipboard()
    {
        try
        {
            var detail = WarningText;
            var errCode = WinDivertDriverManager.LastErrorCode;
            if (errCode.HasValue)
                detail += $"\nError code: 0x{errCode.Value:X8} ({errCode.Value}) — {WinDivert.Win32Errors.GetDescription(errCode.Value)}";
            var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            detail = $"Heco Firewall — Driver Error\nTimestamp: {timestamp}\n{detail}";
            System.Windows.Clipboard.SetText(detail);
        }
        catch { }
    }

    // ═════════════════════════════════════════════════════════════════
    //  4. Interactive Prompt Queue
    // ═════════════════════════════════════════════════════════════════

    /// <summary>
    ///   Enqueue a connection for interactive user prompting.
    ///   The prompt window will be shown on the UI thread, one at a time.
    /// </summary>
    private void EnqueuePrompt(ConnectionEntry connection, Action<RuleAction>? onVerdict)
    {
        lock (_promptLock)
        {
            _promptQueue.Enqueue((connection, onVerdict));
        }
        TryShowNextPrompt();
    }

    /// <summary>
    ///   Dequeue and display the next prompt if none is currently showing.
    ///   Runs on the UI thread via Dispatcher.BeginInvoke.
    /// </summary>
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

        Application.Current?.Dispatcher?.BeginInvoke(new Action(() =>
        {
            try
            {
                var promptWin = new Windows.PromptWindow(connection);
                promptWin.Owner = Application.Current.MainWindow;
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
                    // Dialog cancelled — default to Permit
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
    ///   Apply the user's interactive verdict — create persistent rules for
    ///   "Always Allow" / "Always Block", or log one-time decisions.
    /// </summary>
    private void HandlePromptVerdict(ConnectionEntry connection, Windows.PromptVerdict verdict)
    {
        switch (verdict)
        {
            case Windows.PromptVerdict.AllowOnce:
                Logger.Info($"Interactive: User allowed connection once for {connection.ProcessName}");
                break;

            case Windows.PromptVerdict.BlockOnce:
                Logger.Info($"Interactive: User blocked connection once for {connection.ProcessName}");
                break;

            case Windows.PromptVerdict.AlwaysAllow:
                var allowRule = new FirewallRule
                {
                    Name = $"Allow {connection.ProcessName} Outbound",
                    Description = "Auto-generated via Interactive Prompt",
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
                    Description = "Auto-generated via Interactive Prompt",
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

    // ═════════════════════════════════════════════════════════════════
    //  5. Connection Verdict Handler
    // ═════════════════════════════════════════════════════════════════

    /// <summary>
    ///   Called when a new connection is detected by ConnectionMonitor.
    ///   Evaluates it through the verdict pipeline and blocks/prompts as needed.
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
            Application.Current?.Dispatcher?.BeginInvoke(new Action(() =>
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

                // Show notification if enabled
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

    // ═════════════════════════════════════════════════════════════════
    //  6. Default Profile Seeding
    // ═════════════════════════════════════════════════════════════════

    /// <summary>
    ///   Seeds default category-based profiles on first run.
    ///   Each category groups multiple related executables with a shared action policy.
    ///   Runs on a background thread, dispatches UI updates to the main thread.
    /// </summary>
    private async Task SeedDefaultProfilesAsync()
    {
        try
        {
            await Task.Delay(2000); // Wait for startup to settle

            var categoryProfiles = BuildDefaultCategoryProfiles();

            // Must run on UI thread because Profiles is an ObservableCollection (not thread-safe)
            await Application.Current.Dispatcher.InvokeAsync(() =>
            {
                int added = 0;
                foreach (var (name, allowOut, allowIn, processNames) in categoryProfiles)
                {
                    // Only add if doesn't already exist (by name, case-insensitive)
                    if (_profileManager.Profiles.Any(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    var profile = new Profile
                    {
                        Name = name,
                        IsAutoGenerated = false,
                        ActionOverride = new NetworkActionSettings
                        {
                            AllowOutbound = allowOut,
                            AllowInbound = allowIn
                        }
                    };

                    // Add fingerprints for each process name
                    foreach (var procName in processNames)
                    {
                        profile.Fingerprints.Add(new ProfileFingerprint
                        {
                            Type = FingerprintType.ProcessName,
                            Operator = MatchOperator.Equals,
                            Value = procName
                        });
                    }

                    _profileManager.SaveProfile(profile);
                    added++;
                }

                Logger.Info($"Seeded {added}/{categoryProfiles.Length} default category profiles");

                if (added > 0)
                {
                    ToastWindow.Show(Application.Current.MainWindow,
                        "Profiles Seeded", $"Added {added} default category profiles.",
                        ToastType.Info, 4000);
                }
            });
        }
        catch (Exception ex)
        {
            Logger.Warn($"SeedDefaultProfilesAsync failed: {ex.Message}");
            await Application.Current.Dispatcher.InvokeAsync(() =>
            {
                ToastWindow.Show(Application.Current.MainWindow,
                    "Seed Error", $"Failed to seed default profiles: {ex.Message}",
                    ToastType.Error, 5000);
            });
        }
    }

    /// <summary>
    ///   Build the default category profile definitions.
    ///   Returns an array of (Name, AllowOutbound, AllowInbound, ProcessNames[]).
    /// </summary>
    private static (string Name, bool AllowOutbound, bool AllowInbound, string[] ProcessNames)[] BuildDefaultCategoryProfiles()
    {
        return new (string, bool, bool, string[])[]
        {
            // Web Browsers — Allow outbound, block inbound
            ("Web Browsers", true, false, new[]
            {
                "msedge", "chrome", "firefox", "iexplore", "brave", "opera", "vivaldi", "safari"
            }),

            // Email & Chat — Allow outbound, block inbound
            ("Email & Chat", true, false, new[]
            {
                "outlook", "thunderbird", "msimn", "teams", "slack", "discord", "zoom", "skype", "telegram", "whatsapp"
            }),

            // Cloud Storage / Sync — Allow both (need sync both ways)
            ("Cloud Storage", true, true, new[]
            {
                "onedrive", "googledrivesync", "dropbox", "nextcloud", "resiliosync"
            }),

            // Development Tools — Allow both (dev tools need full network)
            ("Development", true, true, new[]
            {
                "devenv", "code", "rider", "phpstorm", "idea", "webstorm", "pycharm", "clion",
                "git", "docker", "node", "python", "dotnet", "npm", "yarn", "pnpm", "cargo", "go", "java",
                "postman", "fiddler", "wireshark", "dotnetwatch", "msbuild", "gradle", "mvn"
            }),

            // System Core (kernel-level, PID 0/4) — Allow both
            ("System Core", true, true, new[]
            {
                "system", "system idle process", "registry", "memory compression"
            }),

            // Windows System Services — Allow outbound, block inbound
            ("System Services", true, false, new[]
            {
                "svchost", "lsass", "services", "winlogon", "csrss", "wininit", "smss",
                "dwm", "explorer", "runtimebroker", "searchindexer", "wmiprvse", "dllhost",
                "taskhostw", "securityhealthservice", "mousocoreworker", "officeclicktorun", "yourphone"
            }),

            // Gaming — Allow outbound, block inbound
            ("Gaming", true, false, new[]
            {
                "steam", "steamwebhelper", "epicgameslauncher", "origin", "battle.net", "riotclientservices",
                "ubisoftconnect", "gog", "eaapp", "xbox", "gamingservices", "gamingservicesnet",
                "lolclient", "valiant", "overwatch", "wow", "diablo", "pathofexile"
            }),

            // Media Players — Allow outbound, block inbound
            ("Media Players", true, false, new[]
            {
                "vlc", "mpc-hc", "mpc-be", "potplayer", "wmplayer", "spotify", "itunes", "musicbee",
                "foobar2000", "plex", "jellyfin", "kodi", "netflix", "youtube", "twitch"
            }),

            // Security / Antivirus — Allow both
            ("Security", true, true, new[]
            {
                "msmpeng", "mrt", "windowsdefender", "malwarebytes", "mbamservice", "bitdefender",
                "kaspersky", "avast", "avg", "eset", "norton", "mcafee", "trendmicro", "crowdstrike",
                "sophos", "sentinelone", "cortex", "defender"
            }),

            // Windows Store / Updates — Allow outbound, block inbound
            ("Windows Store & Updates", true, false, new[]
            {
                "winstore.app", "usoclient", "siagent", "wuauclt", "systemsettings", "setsync",
                "windowsupdate", "deliveryoptimization", "bkupexec"
            }),

            // Office Suite — Allow outbound, block inbound
            ("Office", true, false, new[]
            {
                "winword", "excel", "powerpnt", "outlook", "onenote", "mspub", "msaccess", "lync", "teams"
            }),

            // System Utilities — Allow outbound, block inbound
            ("Utilities", true, false, new[]
            {
                "taskmgr", "regedit", "cmd", "powershell", "pwsh", "mmc", "control", "msconfig",
                "notepad++", "7zfm", "winrar", "everything", "sharex", "greenshot", "snippingtool",
                "calculator", "calendar", "photos", "maps", "weather", "news", "store"
            }),

            // Remote / VPN / Network tools — Allow both
            ("Network & Remote", true, true, new[]
            {
                "rasdial", "vpn", "openvpn", "wireguard", "tailscale", "zerotier", "teamviewer",
                "anydesk", "rustdesk", "rdp", "mstsc", "putty", "winscp", "filezilla",
                "netsh", "ipconfig", "ping", "tracert", "nslookup", "curl", "wget", "ssh",
                "mobaxterm", "termius", "tabby", "windowsTerminal", "wt"
            }),

            // Print / Peripheral services — Allow outbound, block inbound
            ("Print & Peripherals", true, false, new[]
            {
                "spoolsv", "printisolation", "printfilter", "wia", "stisvc", "dot3svc", "eabfiltersrv"
            })
        };
    }

    // ═════════════════════════════════════════════════════════════════
    //  7. Helper Methods
    // ═════════════════════════════════════════════════════════════════

    /// <summary>Check if a persistent user rule already exists for the given application path.</summary>
    private bool HasRuleForApp(string appPath)
    {
        if (string.IsNullOrEmpty(appPath)) return false;
        return _repository.LoadAll().Any(r => string.Equals(r.ApplicationPath, appPath, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Convert a Common RuleAction to the WinDivert-layer RuleAction enum.</summary>
    private static WinDivert.RuleAction ToWinDivertAction(RuleAction action) => action switch
    {
        RuleAction.Permit => WinDivert.RuleAction.Permit,
        RuleAction.Block => WinDivert.RuleAction.Block,
        _ => WinDivert.RuleAction.Block
    };

    /// <summary>Map a WinDivert ConnectionEntry to the Common-layer ConnectionEntry model.</summary>
    private static ConnectionEntry MapConnection(WinDivert.ConnectionEntry src) => new()
    {
        Protocol = (NetworkProtocol)(byte)src.Protocol,
        LocalAddress = src.LocalAddress,
        LocalPort = src.LocalPort,
        RemoteAddress = src.RemoteAddress,
        RemotePort = src.RemotePort,
        ProcessId = src.ProcessId,
        ProcessName = src.ProcessName,
        ProcessPath = src.ProcessPath,
        IsInbound = src.IsInbound,
        FirstSeen = src.FirstSeen,
        LastSeen = src.LastSeen
    };
}
