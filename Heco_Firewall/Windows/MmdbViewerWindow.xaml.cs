using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using MaxMind.Db;

namespace Heco_Firewall.Windows;

public partial class MmdbViewerWindow : Window
{
    private Reader? _reader;

    public MmdbViewerWindow()
    {
        InitializeComponent();
        TxtIpAddress.Focus();
    }

    public MmdbViewerWindow(string? databaseDirectory) : this()
    {
        if (!string.IsNullOrEmpty(databaseDirectory) && Directory.Exists(databaseDirectory))
        {
            TxtDatabasePath.Text = databaseDirectory;
            Loaded += (_, _) => _ = LoadDatabaseAsync(databaseDirectory);
        }
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Select MMDB Database",
            Filter = "MMDB files (*.mmdb)|*.mmdb|All files (*.*)|*.*",
            CheckFileExists = true
        };

        if (dlg.ShowDialog(this) == true)
        {
            TxtDatabasePath.Text = dlg.FileName;
            _ = LoadDatabaseAsync(dlg.FileName);
        }
    }

    private async Task LoadDatabaseAsync(string path)
    {
        try
        {
            _reader?.Dispose();
            _reader = null;

            if (!File.Exists(path))
            {
                TxtDbStatus.Text = "File not found.";
                return;
            }

            TxtLoadingStatus.Text = "Loading database…";
            LoadingOverlay.Visibility = Visibility.Visible;

            var info = new FileInfo(path);
            var reader = await Task.Run(() => new MaxMind.Db.Reader(path));
            _reader = reader;

            TxtDbStatus.Text = $"Loaded: {info.Name} ({FormatSize(info.Length)})";
            ResultsCard.Visibility = Visibility.Collapsed;
            ErrorCard.Visibility = Visibility.Collapsed;
        }
        catch (Exception ex)
        {
            TxtDbStatus.Text = $"Failed to load: {ex.Message}";
            ShowError(ex.Message);
        }
        finally
        {
            LoadingOverlay.Visibility = Visibility.Collapsed;
        }
    }

    private void TxtIpAddress_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
            _ = LookupAsync();
    }

    private void Lookup_Click(object sender, RoutedEventArgs e)
    {
        _ = LookupAsync();
    }

    private async Task LookupAsync()
    {
        ResultsCard.Visibility = Visibility.Collapsed;
        ErrorCard.Visibility = Visibility.Collapsed;

        var path = TxtDatabasePath.Text.Trim();
        if (string.IsNullOrEmpty(path))
        {
            ShowError("Please select a database file first.");
            return;
        }

        if (_reader is null)
        {
            await LoadDatabaseAsync(path);
            if (_reader is null)
                return;
        }

        var ipText = TxtIpAddress.Text.Trim();
        if (string.IsNullOrEmpty(ipText))
        {
            ShowError("Please enter an IP address.");
            return;
        }

        if (!IPAddress.TryParse(ipText, out var address))
        {
            ShowError("Invalid IP address format.");
            return;
        }

        TxtLoadingStatus.Text = "Looking up IP…";
        LoadingOverlay.Visibility = Visibility.Visible;

        try
        {
            Dictionary<string, object>? data = await Task.Run(() =>
                _reader!.Find<Dictionary<string, object>>(address));

            if (data is null || data.Count == 0)
            {
                ShowError("No data found for this IP address in the database.");
                return;
            }

            var flat = FlattenDictionary(data);
            ResultsList.ItemsSource = flat.Select(kv => new KeyValuePair<string, string>(kv.Key, kv.Value ?? "(null)"));
            ResultsCard.Visibility = Visibility.Visible;
            TxtDbStatus.Text = "";
        }
        catch (Exception ex)
        {
            ShowError($"Lookup failed: {ex.Message}");
        }
        finally
        {
            LoadingOverlay.Visibility = Visibility.Collapsed;
        }
    }

    private static List<KeyValuePair<string, string>> FlattenDictionary(Dictionary<string, object> data, string prefix = "")
    {
        var result = new List<KeyValuePair<string, string>>();

        foreach (var kv in data)
        {
            var key = string.IsNullOrEmpty(prefix) ? kv.Key : $"{prefix}.{kv.Key}";

            if (kv.Value is Dictionary<string, object> nested)
            {
                result.AddRange(FlattenDictionary(nested, key));
            }
            else if (kv.Value is List<object> list)
            {
                for (int i = 0; i < list.Count; i++)
                {
                    if (list[i] is Dictionary<string, object> nestedItem)
                        result.AddRange(FlattenDictionary(nestedItem, $"{key}[{i}]"));
                    else
                        result.Add(new KeyValuePair<string, string>($"{key}[{i}]", list[i]?.ToString() ?? "(null)"));
                }
            }
            else
            {
                result.Add(new KeyValuePair<string, string>(key, kv.Value?.ToString() ?? "(null)"));
            }
        }

        return result;
    }

    private void ShowError(string message)
    {
        TxtError.Text = message;
        ResultsCard.Visibility = Visibility.Collapsed;
        ErrorCard.Visibility = Visibility.Visible;
    }

    private static string FormatSize(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        return $"{bytes / (1024.0 * 1024.0):F1} MB";
    }

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }

    private void Window_MouseDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton == MouseButton.Left)
            DragMove();
    }

    protected override void OnClosed(EventArgs e)
    {
        _reader?.Dispose();
        base.OnClosed(e);
    }
}
