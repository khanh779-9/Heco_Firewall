using System;
using System.Windows;
using System.Windows.Controls;
using Heco.Common.Models;
using Heco.Common.Enums;
using Heco.Common.Interfaces;
using Heco_Firewall.ViewModels;
using Heco_Firewall.Windows;

namespace Heco_Firewall.Views;

public partial class ConnectionsView : UserControl
{
    public ConnectionsView()
    {
        InitializeComponent();
    }

    private void InspectProcess_Click(object sender, RoutedEventArgs e)
    {
        if (ConGrid.SelectedItem is ConnectionEntry entry)
        {
            var win = new ProcessDetailWindow(entry.ProcessId, entry.ProcessName ?? "Unknown", entry.ProcessPath ?? "");
            win.Owner = Window.GetWindow(this);
            win.ShowDialog();
        }
    }

    private void BlockProcessOutbound_Click(object sender, RoutedEventArgs e)
    {
        if (ConGrid.SelectedItem is ConnectionEntry entry)
        {
            if (string.IsNullOrEmpty(entry.ProcessPath))
            {
                DialogWindow.ShowWarning("Cannot block because process path is empty.", "Warning");
                return;
            }

            var vm = (MainViewModel)Application.Current.MainWindow.DataContext;
            var newRule = new FirewallRule
            {
                Name = $"Block {entry.ProcessName} Outbound",
                Description = $"Blocked via Connections context menu",
                Action = RuleAction.Block,
                Direction = TrafficDirection.Outbound,
                IsEnabled = true,
                ApplicationPath = entry.ProcessPath,
                Protocol = NetworkProtocol.Any
            };

            vm.Rules.AddAndApplyRule(newRule);
            DialogWindow.ShowInfo($"Created block rule for {entry.ProcessName} outbound.", "Rule Added");
        }
    }

    private void AllowProcessOutbound_Click(object sender, RoutedEventArgs e)
    {
        if (ConGrid.SelectedItem is ConnectionEntry entry)
        {
            if (string.IsNullOrEmpty(entry.ProcessPath))
            {
                DialogWindow.ShowWarning("Cannot allow because process path is empty.", "Warning");
                return;
            }

            var vm = (MainViewModel)Application.Current.MainWindow.DataContext;
            var newRule = new FirewallRule
            {
                Name = $"Allow {entry.ProcessName} Outbound",
                Description = $"Allowed via Connections context menu",
                Action = RuleAction.Permit,
                Direction = TrafficDirection.Outbound,
                IsEnabled = true,
                ApplicationPath = entry.ProcessPath,
                Protocol = NetworkProtocol.Any
            };

            vm.Rules.AddAndApplyRule(newRule);
            DialogWindow.ShowInfo($"Created allow rule for {entry.ProcessName} outbound.", "Rule Added");
        }
    }
}
