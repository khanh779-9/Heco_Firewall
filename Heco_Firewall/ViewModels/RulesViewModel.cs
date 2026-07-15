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
// [WFP DISABLED] using Heco.Core.Engine;
using Heco_Firewall.Helpers;
using Heco_Firewall.Windows;

namespace Heco_Firewall.ViewModels;

internal sealed class RulesViewModel : ObservableObject
{
    // [WFP DISABLED] private readonly WfpEngine _engine;
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
        DeleteRuleCommand = new RelayCommand(async _ => await DeleteRuleAsync(), _ => SelectedRule is not null);
        ToggleRuleCommand = new RelayCommand(async _ => await ToggleRuleAsync(), _ => SelectedRule is not null);
        DeleteSelectedCommand = new RelayCommand(async _ => await DeleteSelectedAsync());
        ToggleSelectedCommand = new RelayCommand(async _ => await ToggleSelectedAsync());
        SaveCommand = new RelayCommand(SaveChanges);
        DiscardCommand = new RelayCommand(DiscardChanges);
    }

    // ── Collections ──────────────────────────────────────────────

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

    // ── Selection ────────────────────────────────────────────────

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

    public FirewallRule? EditingRule
    {
        get => _editingRule;
        set => SetProperty(ref _editingRule, value);
    }

    public bool IsEditing
    {
        get => _isEditing;
        set => SetProperty(ref _isEditing, value);
    }

    // ── Stats ────────────────────────────────────────────────────

    public int TotalRules => Rules.Count;
    public int ActiveRules => Rules.Count(r => r.IsEnabled);
    public int BlockRules => Rules.Count(r => r.Action == RuleAction.Block);
    public int PermitRules => Rules.Count(r => r.Action == RuleAction.Permit);

    // ── Commands ─────────────────────────────────────────────────

    public ICommand AddRuleCommand { get; }
    public ICommand EditRuleCommand { get; }
    public ICommand DeleteRuleCommand { get; }
    public ICommand ToggleRuleCommand { get; }
    public ICommand DeleteSelectedCommand { get; }
    public ICommand ToggleSelectedCommand { get; }
    public ICommand SaveCommand { get; }
    public ICommand DiscardCommand { get; }

    // ── Load / Persist ───────────────────────────────────────────

    public void LoadRules()
    {
        Rules.Clear();
        foreach (var rule in _repository.LoadAll())
            Rules.Add(rule);
        _selectAll = false;
        RefreshStats();
    }

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

    public void DiscardChanges(object? obj)
    {
        SelectedRule = null;
    }

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

    public void EditRule(object? obj)
    {
        if (SelectedRule is not null)
        {
            IsEditing = true;
        }
    }

    // ── Single Operations ────────────────────────────────────────

    public async System.Threading.Tasks.Task DeleteRuleAsync()
    {
        if (SelectedRule is null) return;

        var result = DialogWindow.ShowQuestion(
            $"Delete rule '{SelectedRule.Name}'?\n\nThis cannot be undone.",
            "Confirm Delete");
        if (result != DialogBoxResult.Yes) return;

        // [WFP DISABLED] await RemoveRuleFromEngine(SelectedRule);
        _repository.Delete(SelectedRule.Id);
        Rules.Remove(SelectedRule);
        SelectedRule = null;
        RefreshStats();
    }

    public async System.Threading.Tasks.Task ToggleRuleAsync()
    {
        if (SelectedRule is null) return;

        var rule = SelectedRule;
        rule.IsEnabled = !rule.IsEnabled;
        var idx = Rules.IndexOf(rule);
        if (idx >= 0)
        {
            Rules[idx] = rule;
            _repository.Save(rule);

            // [WFP DISABLED]
            // if (rule.IsEnabled)
            // {
            //     try { await System.Threading.Tasks.Task.Run(() => _engine.ApplyRules(new[] { rule })); }
            //     catch { }
            // }
            // else if (rule.WfpFilterId != 0)
            // {
            //     try
            //     {
            //         await System.Threading.Tasks.Task.Run(() => _engine.RemoveRule(rule.WfpFilterId));
            //         rule.WfpFilterId = 0;
            //     }
            //     catch { }
            // }
        }
        RefreshStats();
    }

    // ── Batch Operations ─────────────────────────────────────────

    public async System.Threading.Tasks.Task DeleteSelectedAsync()
    {
        var selected = Rules.Where(r => r.IsSelected).ToList();
        if (selected.Count == 0) return;

        var result = DialogWindow.ShowQuestion(
            $"Delete {selected.Count} selected rule(s)?\n\nThis cannot be undone.",
            "Confirm Delete");
        if (result != DialogBoxResult.Yes) return;

        foreach (var rule in selected)
        {
            // [WFP DISABLED] await RemoveRuleFromEngine(rule);
            _repository.Delete(rule.Id);
            Rules.Remove(rule);
        }

        SelectedRule = null;
        _selectAll = false;
        OnPropertyChanged(nameof(SelectAll));
        RefreshStats();
    }

    public async System.Threading.Tasks.Task ToggleSelectedAsync()
    {
        var selected = Rules.Where(r => r.IsSelected).ToList();
        if (selected.Count == 0) return;

        foreach (var rule in selected)
        {
            rule.IsEnabled = !rule.IsEnabled;
            _repository.Save(rule);

            // [WFP DISABLED]
            // if (rule.IsEnabled)
            // {
            //     try { await System.Threading.Tasks.Task.Run(() => _engine.ApplyRules(new[] { rule })); }
            //     catch { }
            // }
            // else if (rule.WfpFilterId != 0)
            // {
            //     try
            //     {
            //         await System.Threading.Tasks.Task.Run(() => _engine.RemoveRule(rule.WfpFilterId));
            //         rule.WfpFilterId = 0;
            //     }
            //     catch { }
            // }
        }

        RefreshRulesCollection();
        RefreshStats();
    }

    // ── Helpers ──────────────────────────────────────────────────

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

    // [WFP DISABLED]
    // private async System.Threading.Tasks.Task RemoveRuleFromEngine(FirewallRule rule)
    // {
    //     if (rule.WfpFilterId != 0)
    //     {
    //         try
    //         {
    //             await System.Threading.Tasks.Task.Run(() => _engine.RemoveRule(rule.WfpFilterId));
    //         }
    //         catch { }
    //     }
    // }

    public void ClearWfpFilterIds()
    {
        foreach (var rule in Rules)
            rule.WfpFilterId = 0;
    }

    public void AddAndApplyRule(FirewallRule rule)
    {
        rule.Id = Guid.NewGuid();
        Rules.Add(rule);
        _repository.Save(rule);

        // [WFP DISABLED]
        // try
        // {
        //     if (rule.IsEnabled && _engine.IsConnected)
        //     {
        //         _engine.ApplyRules(new[] { rule });
        //     }
        // }
        // catch (Exception ex)
        // {
        //     System.Diagnostics.Debug.WriteLine($"[RulesViewModel] Failed to apply quick rule: {ex.Message}");
        // }

        RefreshStats();
    }

    private void RefreshStats()
    {
        OnPropertyChanged(nameof(TotalRules));
        OnPropertyChanged(nameof(ActiveRules));
        OnPropertyChanged(nameof(BlockRules));
        OnPropertyChanged(nameof(PermitRules));
    }
}

internal sealed class RuleEditingHelper
{
    public static ushort? ParsePort(string? text) =>
        ushort.TryParse(text, out var p) ? p : null;

    public static string? ParseAddress(string? text) =>
        string.IsNullOrWhiteSpace(text) ? null : text!.Trim();
}
