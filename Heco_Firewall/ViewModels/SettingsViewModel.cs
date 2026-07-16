using System;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Input;
using Heco.Common.Services.Settings;
using Heco.Common.Services.Diagnostics;
using Heco_Firewall.Helpers;
using Heco_Firewall.Windows;

namespace Heco_Firewall.ViewModels;

internal sealed class SettingsViewModel : ObservableObject
{
    private readonly SettingsService _settingsService;

    public SettingsViewModel(SettingsService settingsService)
    {
        _settingsService = settingsService;

        AppSettings = _settingsService.AppSettings;

        SaveCommand = new RelayCommand(_ => { _settingsService.Save(); OnSettingsSaved?.Invoke(); });
        OpenGeoIpDownloadCommand = new RelayCommand(_ => OpenGeoIpDownload());
        OpenMmdbViewerCommand = new RelayCommand(_ => OpenMmdbViewer());
    }

    public SettingsApplication AppSettings { get; }

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

    public ICommand SaveCommand { get; }
    public ICommand OpenMmdbViewerCommand { get; }

    public Action? OnSettingsSaved { get; set; }
}
