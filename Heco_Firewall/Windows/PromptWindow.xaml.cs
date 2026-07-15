using System;
using System.Runtime.Versioning;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Heco.Common.Models;

namespace Heco_Firewall.Windows;

public enum PromptVerdict
{
    AllowOnce,
    AlwaysAllow,
    BlockOnce,
    AlwaysBlock
}

public partial class PromptWindow : Window
{
    private readonly ConnectionEntry _connection;
    private readonly DispatcherTimer _timer;
    private int _secondsRemaining = 30;

    public PromptVerdict Verdict { get; private set; } = PromptVerdict.AllowOnce;

    [SupportedOSPlatform("windows")]
    public PromptWindow(ConnectionEntry connection)
    {
        InitializeComponent();

        Topmost = true;

        _connection = connection;

        TxtProcess.Text = connection.ProcessName ?? "Unknown Process";
        TxtPath.Text = string.IsNullOrEmpty(connection.ProcessPath) ? "Unknown Path" : connection.ProcessPath;

        string destStr = connection.RemoteAddress.ToString();
        if (!string.IsNullOrEmpty(connection.RemoteHostName))
            destStr += $" ({connection.RemoteHostName})";
        if (!string.IsNullOrEmpty(connection.CountryCode))
            destStr += $" [{connection.CountryCode}]";
        TxtDestination.Text = destStr;

        TxtPort.Text = $"{connection.Protocol} / Port {connection.RemotePort}";

        LoadProcessIcon(connection.ProcessPath);

        // Position at bottom right corner
        Loaded += (s, e) =>
        {
            Left = SystemParameters.WorkArea.Width - ActualWidth - 16;
            Top = SystemParameters.WorkArea.Height - ActualHeight - 16;
        };

        // Timer setup
        _timer = new DispatcherTimer();
        _timer.Interval = TimeSpan.FromSeconds(1);
        _timer.Tick += Timer_Tick;
        _timer.Start();
    }

    [SupportedOSPlatform("windows")]
    private void LoadProcessIcon(string? processPath)
    {
        if (string.IsNullOrEmpty(processPath) || !System.IO.File.Exists(processPath))
            return;

        try
        {
            using var icon = System.Drawing.Icon.ExtractAssociatedIcon(processPath);
            if (icon != null)
            {
                var imgSrc = Imaging.CreateBitmapSourceFromHIcon(
                    icon.Handle,
                    Int32Rect.Empty,
                    BitmapSizeOptions.FromEmptyOptions());
                ProcessIcon.Source = imgSrc;
                ProcessIcon.Visibility = Visibility.Visible;
            }
        }
        catch
        {
            // Ignore icon extraction failures
        }
    }

    private void Timer_Tick(object? sender, EventArgs e)
    {
        _secondsRemaining--;
        if (_secondsRemaining <= 0)
        {
            _timer.Stop();
            Verdict = PromptVerdict.AllowOnce;
            DialogResult = true;
            Close();
            return;
        }

        TxtCountdown.Text = $"{_secondsRemaining}s";
        ProgressTime.Value = _secondsRemaining;
    }

    private void AllowOnce_Click(object sender, RoutedEventArgs e)
    {
        _timer.Stop();
        Verdict = PromptVerdict.AllowOnce;
        DialogResult = true;
        Close();
    }

    private void AlwaysAllow_Click(object sender, RoutedEventArgs e)
    {
        _timer.Stop();
        Verdict = PromptVerdict.AlwaysAllow;
        DialogResult = true;
        Close();
    }

    private void BlockOnce_Click(object sender, RoutedEventArgs e)
    {
        _timer.Stop();
        Verdict = PromptVerdict.BlockOnce;
        DialogResult = true;
        Close();
    }

    private void AlwaysBlock_Click(object sender, RoutedEventArgs e)
    {
        _timer.Stop();
        Verdict = PromptVerdict.AlwaysBlock;
        DialogResult = true;
        Close();
    }
}
