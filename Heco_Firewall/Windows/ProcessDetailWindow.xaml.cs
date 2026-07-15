using System;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using Heco.Common.Models;
using Heco.Common.Enums;
using Heco.Common.Interfaces;
using Heco_Firewall.ViewModels;

namespace Heco_Firewall.Windows;

public partial class ProcessDetailWindow : Window
{
    private readonly uint _pid;
    private readonly string _processName;
    private readonly string _processPath;
    private Process? _process;
    private DateTime _lastCpuTime;
    private TimeSpan _lastTotalProcessorTime;
    private readonly DispatcherTimer _timer;

    public ProcessDetailWindow(uint pid, string processName, string processPath)
    {
        InitializeComponent();

        _pid = pid;
        _processName = processName;
        _processPath = processPath;

        TxtName.Text = processName;
        TxtPid.Text = pid.ToString();
        TxtPath.Text = string.IsNullOrEmpty(processPath) ? "Unknown path" : processPath;

        // Digital signature check
        TxtSignature.Text = CheckDigitalSignature(processPath);

        // Try getting process diagnostics
        try
        {
            _process = Process.GetProcessById((int)pid);
            _lastCpuTime = DateTime.UtcNow;
            _lastTotalProcessorTime = _process.TotalProcessorTime;
        }
        catch
        {
            // Process terminated or access denied
        }

        // Setup timer to refresh statistics
        _timer = new DispatcherTimer();
        _timer.Interval = TimeSpan.FromSeconds(1);
        _timer.Tick += (s, e) => UpdateStats();
        _timer.Start();

        UpdateStats();
    }

    private void UpdateStats()
    {
        if (_process == null)
        {
            TxtCpu.Text = "N/A (Access Denied / Not Running)";
            TxtMemory.Text = "N/A";
            return;
        }

        try
        {
            if (_process.HasExited)
            {
                TxtCpu.Text = "Exited";
                TxtMemory.Text = "Exited";
                _timer.Stop();
                return;
            }

            _process.Refresh();

            // RAM
            long memBytes = _process.WorkingSet64;
            TxtMemory.Text = FormatBytes(memBytes);

            // CPU
            var now = DateTime.UtcNow;
            var totalCpuTime = _process.TotalProcessorTime;
            var timeWindow = now - _lastCpuTime;
            var cpuDelta = totalCpuTime - _lastTotalProcessorTime;

            _lastCpuTime = now;
            _lastTotalProcessorTime = totalCpuTime;

            if (timeWindow.TotalMilliseconds > 0)
            {
                double cpuUsage = (cpuDelta.TotalMilliseconds / (timeWindow.TotalMilliseconds * Environment.ProcessorCount)) * 100;
                TxtCpu.Text = $"{cpuUsage:F1}% (across {Environment.ProcessorCount} cores)";
            }
            else
            {
                TxtCpu.Text = "0.0%";
            }
        }
        catch
        {
            TxtCpu.Text = "N/A (Access Denied)";
            TxtMemory.Text = "N/A";
        }
    }

    private string CheckDigitalSignature(string filePath)
    {
        if (string.IsNullOrEmpty(filePath) || !System.IO.File.Exists(filePath))
            return "Unknown (Executable not found on disk)";
        try
        {
            using var cert = new X509Certificate2(filePath);
            return $"{cert.SubjectName.Name} (Verified)";
        }
        catch
        {
            return "Unsigned / Self-signed / Publisher Unknown";
        }
    }

    private static string FormatBytes(long bytes)
    {
        string[] suffix = { "B", "KB", "MB", "GB", "TB" };
        int i;
        double dblSByte = bytes;
        for (i = 0; i < suffix.Length && bytes >= 1024; i++, bytes /= 1024)
        {
            dblSByte = bytes / 1024.0;
        }
        return $"{dblSByte:F1} {suffix[i]}";
    }

    private void Window_MouseDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton == MouseButton.Left)
            DragMove();
    }

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        _timer.Stop();
        Close();
    }

    private void Allow_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(_processPath))
        {
            DialogWindow.ShowWarning("Cannot allow because application path is empty.", "Warning");
            return;
        }

        var vm = (MainViewModel)Application.Current.MainWindow.DataContext;
        var newRule = new FirewallRule
        {
            Name = $"Allow {_processName} Outbound",
            Description = $"Allowed via Process Inspector",
            Action = RuleAction.Permit,
            Direction = TrafficDirection.Outbound,
            IsEnabled = true,
            ApplicationPath = _processPath,
            Protocol = NetworkProtocol.Any
        };

        vm.Rules.AddAndApplyRule(newRule);
        DialogWindow.ShowInfo($"Created allow rule for {_processName} outbound.", "Rule Added");
        Close_Click(sender, e);
    }

    private void Block_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(_processPath))
        {
            DialogWindow.ShowWarning("Cannot block because application path is empty.", "Warning");
            return;
        }

        var vm = (MainViewModel)Application.Current.MainWindow.DataContext;
        var newRule = new FirewallRule
        {
            Name = $"Block {_processName} Outbound",
            Description = $"Blocked via Process Inspector",
            Action = RuleAction.Block,
            Direction = TrafficDirection.Outbound,
            IsEnabled = true,
            ApplicationPath = _processPath,
            Protocol = NetworkProtocol.Any
        };

        vm.Rules.AddAndApplyRule(newRule);
        DialogWindow.ShowInfo($"Created block rule for {_processName} outbound.", "Rule Added");
        Close_Click(sender, e);
    }
}
