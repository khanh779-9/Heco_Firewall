using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using Heco.Common.Services.Settings;
using Heco.Common.Engine;
using Heco.Common.Services.Diagnostics;
using Heco_Firewall.Helpers;
using Heco_Firewall.Windows;

namespace Heco_Firewall.ViewModels;

internal sealed class SettingsViewModel : ObservableObject
{
    private readonly SettingsService _settingsService;
    private readonly SelfDefenseDriver _selfDefense = new();
    private bool _isSelfDefenseBusy;
    private string _selfDefenseStatus = "Not active";
    private int _blockedAttempts;

    public SettingsViewModel(SettingsService settingsService)
    {
        _settingsService = settingsService;

        // Expose the settings objects for binding
        AppSettings = _settingsService.AppSettings;

        SaveCommand = new RelayCommand(_ => { _settingsService.Save(); OnSettingsSaved?.Invoke(); });
        ToggleSelfDefenseCommand = new RelayCommand(async _ => await ToggleSelfDefenseAsync(), _ => !IsSelfDefenseBusy);
        OpenGeoIpDownloadCommand = new RelayCommand(_ => OpenGeoIpDownload());
        OpenMmdbViewerCommand = new RelayCommand(_ => OpenMmdbViewer());
    }

    // ── Settings objects (bound directly from XAML) ──────────────

    public SettingsApplication AppSettings { get; }

    // ── Self-Defense Properties ─────────────────────────────────

    public bool IsSelfDefenseBusy
    {
        get => _isSelfDefenseBusy;
        set
        {
            if (SetProperty(ref _isSelfDefenseBusy, value))
                CommandManager.InvalidateRequerySuggested();
        }
    }

    public string SelfDefenseStatus
    {
        get => _selfDefenseStatus;
        set => SetProperty(ref _selfDefenseStatus, value);
    }

    public int BlockedAttempts
    {
        get => _blockedAttempts;
        set => SetProperty(ref _blockedAttempts, value);
    }

    // ── GeoIP ────────────────────────────────────────────────────

    public ICommand OpenGeoIpDownloadCommand { get; }

    public string GeoIpPath =>
        Path.Combine(AppDomain.CurrentDomain.BaseDirectory, AppSettings.GeoIpDatabasePath);

    public bool GeoIpFilesExist =>
        File.Exists(Path.Combine(GeoIpPath, "GeoLite2-City.mmdb")) ||
        File.Exists(Path.Combine(GeoIpPath, "GeoLite2-ASN.mmdb"));

    private void OpenGeoIpDownload()
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data",
                UseShellExecute = true
            });
        }
        catch { }
    }

    private void OpenMmdbViewer()
    {
        try
        {
            var viewer = new MmdbViewerWindow(GeoIpPath);
            viewer.Owner = Application.Current.MainWindow;
            viewer.ShowDialog();
        }
        catch (Exception ex)
        {
            Logger.Error($"Failed to open MMDB Viewer: {ex.Message}");
        }
    }

    // ── Commands ─────────────────────────────────────────────────

    public ICommand SaveCommand { get; }
    public ICommand ToggleSelfDefenseCommand { get; }
    public ICommand OpenMmdbViewerCommand { get; }

    /// <summary>Called by MainViewModel after settings are saved — triggers rule re-application.</summary>
    public Action? OnSettingsSaved { get; set; }

    // ── Self-Defense Logic ──────────────────────────────────────

    private async Task ToggleSelfDefenseAsync()
    {
        IsSelfDefenseBusy = true;
        try
        {
            if (AppSettings.EnableSelfDefense)
            {
                await DisableSelfDefenseAsync();
            }
            else
            {
                await EnableSelfDefenseAsync();
            }
        }
        catch (Exception ex)
        {
            Logger.Error($"Self-defense toggle failed: {ex.Message}");
            SelfDefenseStatus = $"Error: {ex.Message}";
        }
        finally
        {
            IsSelfDefenseBusy = false;
        }
    }

    private async Task EnableSelfDefenseAsync()
    {
        try
        {
            SelfDefenseStatus = "Starting…";

            // Path to the driver .sys file (copied to output by csproj)
            var arch = IntPtr.Size == 8 ? "x64" : "x86";
            var driverPath = Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                "Drivers", arch, "HecoProtect.sys");

            if (!File.Exists(driverPath))
            {
                driverPath = Path.Combine(
                    AppDomain.CurrentDomain.BaseDirectory,
                    "HecoProtect.sys");
            }

            if (!File.Exists(driverPath))
            {
                DialogWindow.ShowWarning(
                    "Driver file (HecoProtect.sys) not found.\n\n" +
                    "Make sure the driver is built and copied to the output directory.",
                    "Self-Defense Driver");
                SelfDefenseStatus = "Driver not found";
                AppSettings.EnableSelfDefense = false;
                return;
            }

            var level = (ProtectionLevel)AppSettings.SelfDefenseLevel;
            bool success = await _selfDefense.EnableAsync(driverPath, level);

            if (success)
            {
                AppSettings.EnableSelfDefense = true;
                SelfDefenseStatus = $"Active — PID {_selfDefense.ProtectedPid}, Level {level}";
                _settingsService.Save();
                Logger.Info($"Self-defense enabled at {level} level, protecting PID {_selfDefense.ProtectedPid}");

                // Query status to get blocked count
                RefreshStatus();
            }
            else
            {
                AppSettings.EnableSelfDefense = false;
                SelfDefenseStatus = "Failed to start driver — try running as Administrator";
                Logger.Warn("Self-defense enable failed");
            }
        }
        catch (Exception ex)
        {
            AppSettings.EnableSelfDefense = false;
            SelfDefenseStatus = $"Error: {ex.Message}";
            Logger.Error($"Self-defense enable error: {ex.Message}");
        }
    }

    private async Task DisableSelfDefenseAsync()
    {
        try
        {
            SelfDefenseStatus = "Stopping…";
            await Task.Run(() => _selfDefense.Disable());
            AppSettings.EnableSelfDefense = false;
            SelfDefenseStatus = "Not active";
            BlockedAttempts = 0;
            _settingsService.Save();
            Logger.Info("Self-defense disabled");
        }
        catch (Exception ex)
        {
            Logger.Error($"Self-defense disable error: {ex.Message}");
            SelfDefenseStatus = $"Error stopping: {ex.Message}";
        }
    }

    /// <summary>
    /// Refresh the driver status (blocked count, etc.)
    /// </summary>
    public void RefreshStatus()
    {
        try
        {
            if (_selfDefense.IsActive)
            {
                _selfDefense.QueryStatus();
                BlockedAttempts = _selfDefense.BlockedAttempts;
                SelfDefenseStatus = $"Active — PID {_selfDefense.ProtectedPid}, Blocked: {_selfDefense.BlockedAttempts}";
            }
        }
        catch
        {
            // Silently ignore if driver is not available
        }
    }

    /// <summary>
    /// Auto-enable self-defense if the setting is active (called at app startup).
    /// </summary>
    public async Task TryAutoEnableAsync()
    {
        if (!AppSettings.EnableSelfDefense)
            return;

        // Check if driver is already installed and running
        try
        {
            var driverPath = Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                "Drivers", "x64", "HecoProtect.sys");

            if (!File.Exists(driverPath))
            {
                driverPath = Path.Combine(
                    AppDomain.CurrentDomain.BaseDirectory,
                    "HecoProtect.sys");
            }

            if (File.Exists(driverPath))
            {
                var level = (ProtectionLevel)AppSettings.SelfDefenseLevel;
                bool success = await _selfDefense.EnableAsync(driverPath, level);
                if (success)
                {
                    SelfDefenseStatus = $"Active — PID {_selfDefense.ProtectedPid}, Level {level}";
                    RefreshStatus();
                    Logger.Info("Self-defense auto-enabled at startup");
                }
                else
                {
                    AppSettings.EnableSelfDefense = false;
                    SelfDefenseStatus = "Auto-start failed (not admin?)";
                }
            }
            else
            {
                AppSettings.EnableSelfDefense = false;
                SelfDefenseStatus = "Driver file missing";
            }
        }
        catch (Exception ex)
        {
            AppSettings.EnableSelfDefense = false;
            SelfDefenseStatus = $"Auto-start error: {ex.Message}";
            Logger.Warn($"Self-defense auto-start failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Cleanup when the view model is no longer needed.
    /// </summary>
    public void Cleanup()
    {
        if (_selfDefense.IsActive)
        {
            _selfDefense.Disable();
            Logger.Info("Self-defense disabled during cleanup");
        }
        _selfDefense.Dispose();
    }
}
