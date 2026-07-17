using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using Heco.Common.Models;
using Heco.Common.Enums;
using Heco.Common.Interfaces;
using Heco.Common.Data;
using Heco_Firewall.Helpers;
using Heco_Firewall.Windows;

namespace Heco_Firewall.ViewModels;

/// <summary>
///   ViewModel for the Firewall Rules management page.
///   Handles CRUD operations, batch selection, and rule persistence.
/// </summary>
internal sealed class RulesViewModel : ObservableObject
{
    private readonly FirewallRuleRepository _repository;
    private FirewallRule? _selectedRule;
    private FirewallRule? _editingRule;
    private bool _isEditing;
    private bool _selectAll;

    public RulesViewModel(FirewallRuleRepository repository)
    {
        _repository = repository;

        AddRuleCommand = new RelayCommand(AddRule);
        EditRuleCommand = new RelayCommand(EditRule, _ => SelectedRule is not null);
        DeleteRuleCommand = new RelayCommand(_ => DeleteRule(), _ => SelectedRule is not null);
        ToggleRuleCommand = new RelayCommand(_ => ToggleRule(), _ => SelectedRule is not null);
        DeleteSelectedCommand = new RelayCommand(_ => DeleteSelected());
        ToggleSelectedCommand = new RelayCommand(_ => ToggleSelected());
        SaveCommand = new RelayCommand(SaveChanges);
        DiscardCommand = new RelayCommand(DiscardChanges);
    }

    // ── Collections ──────────────────────────────────────────────────

    public ObservableCollection<FirewallRule> Rules { get; } = new();
    public ObservableCollection<RuleAction> AvailableActions { get; } = new([RuleAction.Permit, RuleAction.Block]);
    public ObservableCollection<TrafficDirection> AvailableDirections { get; } = new([TrafficDirection.Outbound, TrafficDirection.Inbound]);
    public ObservableCollection<NetworkProtocol> AvailableProtocols { get; } = new([
        NetworkProtocol.Any,
        NetworkProtocol.TCP,
        NetworkProtocol.UDP,
        NetworkProtocol.ICMP,
        NetworkProtocol.IGMP,
        NetworkProtocol.GRE,
        NetworkProtocol.ESP,
        NetworkProtocol.AH,
        NetworkProtocol.IPv6_ICMP,
        NetworkProtocol.L2TP,
        NetworkProtocol.SCTP,
        NetworkProtocol.EGP,
        NetworkProtocol.OSPF,
        NetworkProtocol.EIGRP,
        NetworkProtocol.RSVP,
        NetworkProtocol.VRRP,
        NetworkProtocol.IP_in_IP,
        NetworkProtocol.IPv6,
        NetworkProtocol.IPv6_Route,
        NetworkProtocol.IPv6_Frag,
        NetworkProtocol.PIM,
        NetworkProtocol.UDPLite,
        NetworkProtocol.MPLS_in_IP,
        NetworkProtocol.DCCP,
        NetworkProtocol.PGM,
        NetworkProtocol.IPComp,
    ]);
    public ObservableCollection<AddressFamily> AvailableAddressFamilies { get; } = new([AddressFamily.Both, AddressFamily.IPv4, AddressFamily.IPv6]);

    // ── Selection ────────────────────────────────────────────────────

    /// <summary>Toggle all rules' selection state.</summary>
    public bool SelectAll
    {
        get => _selectAll;
        set
        {
            if (SetProperty(ref _selectAll, value))
            {
                foreach (var rule in Rules)
                    rule.IsSelected = value;
                RefreshSelectedRules();
            }
        }
    }

    /// <summary>Currently selected rule in the DataGrid. Setting this creates an editing clone.</summary>
    public FirewallRule? SelectedRule
    {
        get => _selectedRule;
        set
        {
            if (SetProperty(ref _selectedRule, value))
            {
                EditingRule = value is not null
                    ? new FirewallRule
                    {
                        Id = value.Id,
                        Name = value.Name,
                        Description = value.Description,
                        IsEnabled = value.IsEnabled,
                        Action = value.Action,
                        Direction = value.Direction,
                        AddressFamily = value.AddressFamily,
                        Protocol = value.Protocol,
                        LocalPort = value.LocalPort,
                        RemotePort = value.RemotePort,
                        LocalAddress = value.LocalAddress,
                        RemoteAddress = value.RemoteAddress,
                        ApplicationPath = value.ApplicationPath,
                        UserName = value.UserName,
                        ServiceName = value.ServiceName,
                        CreatedAt = value.CreatedAt,
                        WfpFilterId = value.WfpFilterId,
                        HitCount = value.HitCount
                    }
                    : null;
                IsEditing = EditingRule is not null;
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }

    /// <summary>Editing clone of the selected rule (bound to the edit panel).</summary>
    public FirewallRule? EditingRule
    {
        get => _editingRule;
        set => SetProperty(ref _editingRule, value);
    }

    /// <summary>Whether the edit panel is currently visible.</summary>
    public bool IsEditing
    {
        get => _isEditing;
        set => SetProperty(ref _isEditing, value);
    }

    // ── Stats ────────────────────────────────────────────────────────

    public int TotalRules => Rules.Count;
    public int ActiveRules => Rules.Count(r => r.IsEnabled);
    public int BlockRules => Rules.Count(r => r.Action == RuleAction.Block);
    public int PermitRules => Rules.Count(r => r.Action == RuleAction.Permit);

    // ── Commands ─────────────────────────────────────────────────────

    public ICommand AddRuleCommand { get; }
    public ICommand EditRuleCommand { get; }
    public ICommand DeleteRuleCommand { get; }
    public ICommand ToggleRuleCommand { get; }
    public ICommand DeleteSelectedCommand { get; }
    public ICommand ToggleSelectedCommand { get; }
    public ICommand SaveCommand { get; }
    public ICommand DiscardCommand { get; }

    // ── Load / Persist ───────────────────────────────────────────────

    /// <summary>Reload all rules from the JSON repository.</summary>
    public void LoadRules()
    {
        Rules.Clear();
        foreach (var rule in _repository.LoadAll())
            Rules.Add(rule);
        _selectAll = false;
        RefreshStats();
    }

    /// <summary>Save or create the currently editing rule.</summary>
    public void SaveChanges(object? obj)
    {
        if (EditingRule is null) return;

        var existing = Rules.FirstOrDefault(r => r.Id == EditingRule.Id);
        if (existing is not null)
        {
            var idx = Rules.IndexOf(existing);
            Rules[idx] = EditingRule;
            _repository.Save(EditingRule);
        }
        else
        {
            EditingRule.Id = Guid.NewGuid();
            Rules.Add(EditingRule);
            _repository.Save(EditingRule);
        }

        SelectedRule = null;
        RefreshStats();
    }

    /// <summary>Discard editing changes and close the edit panel.</summary>
    public void DiscardChanges(object? obj)
    {
        SelectedRule = null;
    }

    /// <summary>Create a new blank rule and open the edit panel.</summary>
    public void AddRule(object? obj)
    {
        var newRule = new FirewallRule
        {
            Name = "New Rule",
            IsEnabled = true,
            Action = RuleAction.Block,
            Direction = TrafficDirection.Outbound,
            Protocol = NetworkProtocol.TCP,
            AddressFamily = AddressFamily.IPv4
        };
        EditingRule = newRule;
        IsEditing = true;
    }

    /// <summary>Open the edit panel for the currently selected rule.</summary>
    public void EditRule(object? obj)
    {
        if (SelectedRule is not null)
        {
            IsEditing = true;
        }
    }

    // ── Single Operations ────────────────────────────────────────────

    /// <summary>Delete the currently selected rule after user confirmation.</summary>
    public void DeleteRule()
    {
        if (SelectedRule is null) return;

        var result = DialogWindow.ShowQuestion(
            $"Delete rule '{SelectedRule.Name}'?\n\nThis cannot be undone.",
            "Confirm Delete");
        if (result != DialogBoxResult.Yes) return;

        _repository.Delete(SelectedRule.Id);
        Rules.Remove(SelectedRule);
        SelectedRule = null;
        RefreshStats();
    }

    /// <summary>Toggle the enabled/disabled state of the currently selected rule.</summary>
    public void ToggleRule()
    {
        if (SelectedRule is null) return;

        var rule = SelectedRule;
        rule.IsEnabled = !rule.IsEnabled;
        var idx = Rules.IndexOf(rule);
        if (idx >= 0)
        {
            Rules[idx] = rule;
            _repository.Save(rule);
        }
        RefreshStats();
    }

    // ── Batch Operations ─────────────────────────────────────────────

    /// <summary>Delete all selected (checked) rules after user confirmation.</summary>
    public void DeleteSelected()
    {
        var selected = Rules.Where(r => r.IsSelected).ToList();
        if (selected.Count == 0) return;

        var result = DialogWindow.ShowQuestion(
            $"Delete {selected.Count} selected rule(s)?\n\nThis cannot be undone.",
            "Confirm Delete");
        if (result != DialogBoxResult.Yes) return;

        foreach (var rule in selected)
        {
            _repository.Delete(rule.Id);
            Rules.Remove(rule);
        }

        SelectedRule = null;
        _selectAll = false;
        OnPropertyChanged(nameof(SelectAll));
        RefreshStats();
    }

    /// <summary>Toggle enabled/disabled state for all selected (checked) rules.</summary>
    public void ToggleSelected()
    {
        var selected = Rules.Where(r => r.IsSelected).ToList();
        if (selected.Count == 0) return;

        foreach (var rule in selected)
        {
            rule.IsEnabled = !rule.IsEnabled;
            _repository.Save(rule);
        }

        RefreshRulesCollection();
        RefreshStats();
    }

    // ── Helpers ───────────────────────────────────────────────────────

    /// <summary>
    ///   Add a rule and persist it immediately (used by interactive prompt).
    /// </summary>
    public void AddAndApplyRule(FirewallRule rule)
    {
        rule.Id = Guid.NewGuid();
        Rules.Add(rule);
        _repository.Save(rule);
        RefreshStats();
    }

    private void RefreshSelectedRules()
    {
        RefreshRulesCollection();
        var allSelected = Rules.All(r => r.IsSelected);
        if (_selectAll != allSelected)
        {
            _selectAll = allSelected;
            OnPropertyChanged(nameof(SelectAll));
        }
    }

    private void RefreshRulesCollection()
    {
        // Force DataGrid to refresh bound controls by re-creating the collection
        var items = Rules.ToList();
        Rules.Clear();
        foreach (var r in items)
            Rules.Add(r);
    }

    private void RefreshStats()
    {
        OnPropertyChanged(nameof(TotalRules));
        OnPropertyChanged(nameof(ActiveRules));
        OnPropertyChanged(nameof(BlockRules));
        OnPropertyChanged(nameof(PermitRules));
    }
}

/// <summary>Helper for parsing port/address strings from UI text inputs.</summary>
internal sealed class RuleEditingHelper
{
    public static ushort? ParsePort(string? text) =>
        ushort.TryParse(text, out var p) ? p : null;

    public static string? ParseAddress(string? text) =>
        string.IsNullOrWhiteSpace(text) ? null : text!.Trim();
}
