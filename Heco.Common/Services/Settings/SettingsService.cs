using System;
using System.IO;
using System.Threading;
using Microsoft.Win32;
using System.Runtime.Versioning;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using Heco.Common.Services.Settings;
using Heco.Common.Services.Diagnostics;

namespace Heco.Common.Services.Settings;

/// <summary>
///   Manages application and profile settings with YAML persistence.
///   Auto-saves when any property changes via INotifyPropertyChanged.
///   Thread-safe writes with retry.
/// </summary>
public sealed class SettingsService : ISettingsService, IDisposable
{
    private readonly string _appSettingsPath;
    private readonly string _profilesPath;
    private readonly IDeserializer _deserializer;
    private readonly ISerializer _serializer;
    private const int SaveDelayMs = 500; // Debounce auto-save
    private const int MaxRetries = 3;
    private int _pendingSave;

    public SettingsApplication AppSettings { get; }
    public SettingsProfilesCollection ProfileSettings { get; }

    public SettingsService()
    {
        var appData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Heco");

        Directory.CreateDirectory(appData);

        _appSettingsPath = Path.Combine(appData, "AppSettings.yaml");
        _profilesPath = Path.Combine(appData, "AppProfiles.yaml");

        _deserializer = new DeserializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();

        _serializer = new SerializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .Build();

        AppSettings = new SettingsApplication();
        ProfileSettings = new SettingsProfilesCollection();

        // Wire up auto-save callback (debounced) + registry sync
        AppSettings.OnPropertyChangedCallback = () =>
        {
            ScheduleSave();
            if (OperatingSystem.IsWindows())
                SyncAutoStartRegistry();
        };
    }

    public void Load()
    {
        LoadFile(_appSettingsPath, AppSettings);
        LoadFile(_profilesPath, ProfileSettings);
        Logger.Info("Settings loaded");
    }

    public void Save()
    {
        SaveFile(_appSettingsPath, AppSettings);
        SaveFile(_profilesPath, ProfileSettings);
        Logger.Debug("Settings saved");
    }

    private void ScheduleSave()
    {
        if (Interlocked.CompareExchange(ref _pendingSave, 1, 0) == 0)
        {
            // Use a simple approach — save after a short delay via Timer
            ThreadPool.QueueUserWorkItem(_ =>
            {
                Thread.Sleep(SaveDelayMs);
                Save();
                Interlocked.Exchange(ref _pendingSave, 0);
            });
        }
    }

    private void LoadFile<T>(string path, T target) where T : class
    {
        try
        {
            if (!File.Exists(path)) return;

            var yaml = File.ReadAllText(path);
            if (string.IsNullOrWhiteSpace(yaml)) return;

            var loaded = _deserializer.Deserialize<T>(yaml);
            if (loaded is null) return;

            // Copy properties from loaded into target
            foreach (var prop in typeof(T).GetProperties())
            {
                if (prop.CanWrite && prop.CanRead)
                {
                    var value = prop.GetValue(loaded);
                    if (value is not null)
                        prop.SetValue(target, value);
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Warn($"Failed to load {path}: {ex.Message}");
        }
    }

    private void SaveFile<T>(string path, T source)
    {
        for (int attempt = 0; attempt < MaxRetries; attempt++)
        {
            try
            {
                var yaml = _serializer.Serialize(source);
                File.WriteAllText(path, yaml);
                return;
            }
            catch (IOException) when (attempt < MaxRetries - 1)
            {
                Thread.Sleep(100 * (attempt + 1));
            }
            catch (Exception ex)
            {
                Logger.Error($"Failed to save {path}", ex);
                return;
            }
        }
    }

    // ════════════════════════════════════════════════════════════════
    //  Auto-start (Windows registry)
    // ════════════════════════════════════════════════════════════════

    private const string AutoStartRegPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private const string AutoStartValueName = "Heco Firewall";

    /// <summary>
    ///   Sync the auto-start registry entry with the current setting.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private void SyncAutoStartRegistry()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(AutoStartRegPath, writable: true);
            if (key == null) return;

            if (AppSettings.StartWithWindows)
            {
                var exePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
                // For .NET Framework apps, Location returns the .exe path
                key.SetValue(AutoStartValueName, $"\"{exePath}\"");
                Logger.Debug($"Auto-start enabled: {exePath}");
            }
            else
            {
                if (key.GetValue(AutoStartValueName) != null)
                    key.DeleteValue(AutoStartValueName);
                Logger.Debug("Auto-start disabled");
            }
        }
        catch (Exception ex)
        {
            Logger.Warn($"Failed to sync auto-start registry: {ex.Message}");
        }
    }

    public void Dispose()
    {
        // No managed resources to dispose
    }
}
