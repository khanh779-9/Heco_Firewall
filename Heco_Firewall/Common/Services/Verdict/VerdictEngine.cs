using System;
using System.Collections.Generic;
using System.Linq;
using Heco.Common.Models;
using Heco.Common.Enums;
using Heco.Common.Interfaces;
using Heco.Common.Services.Blocklists;
using Heco.Common.Services.Diagnostics;
using Heco.Common.Services.Profiles;
using Heco.Common.Services.Settings;

namespace Heco.Common.Services.Verdict;

/// <summary>
///   Multi-level verdict pipeline that combines blocklist, profile,
///   and user-rule policy into a single decision engine.
/// </summary>
public sealed class VerdictEngine : IVerdictEngine
{
    private readonly IProfileManager _profileManager;
    private readonly IBlocklistManager _blocklistManager;
    private readonly object _sync = new();

    private const int MaxBlocklistRules = 500;

    public event EventHandler<EventArgs>? PolicyChanged;

    public VerdictEngine(IProfileManager profileManager, IBlocklistManager blocklistManager)
    {
        _profileManager = profileManager ?? throw new ArgumentNullException(nameof(profileManager));
        _blocklistManager = blocklistManager ?? throw new ArgumentNullException(nameof(blocklistManager));

        // Re-fire when underlying policy changes
        _profileManager.ProfileChanged += (_, _) => OnPolicyChanged();
        _blocklistManager.BlocklistUpdated += (_, _) => OnPolicyChanged();
    }

    // ════════════════════════════════════════════════════════════════
    //  Rule-set generation
    // ════════════════════════════════════════════════════════════════

    /// <inheritdoc />
    public List<FirewallRule> GenerateRuleSet(
        IEnumerable<FirewallRule> userRules,
        bool includeBlocklists = true,
        bool includeProfiles = true)
    {
        var result = new List<FirewallRule>();
        var seenIds = new HashSet<Guid>();

        // Level 3: User-defined rules (only enabled)
        foreach (var rule in userRules)
        {
            if (!rule.IsEnabled) continue;

            // Check if a profile with action override applies
            if (includeProfiles && ShouldApplyOverride(rule, out var overrideAction))
            {
                var enhanced = CloneRule(rule);
                enhanced.Action = overrideAction!.Value;
                enhanced.Name = $"{rule.Name} [profile]";
                enhanced.Description = $"Overridden by profile — original action was {rule.Action}";
                AddIfUnique(result, enhanced, seenIds);
            }
            else
            {
                AddIfUnique(result, rule, seenIds);
            }
        }

        // Level 1: Blocklist-based rules (highest priority)
        if (includeBlocklists)
        {
            var blocklistRules = GenerateBlocklistRules();
            foreach (var rule in blocklistRules)
                AddIfUnique(result, rule, seenIds);
        }

        Logger.Debug($"VerdictEngine.GenerateRuleSet: {userRules.Count()} user rules → {result.Count} enhanced rules");
        return result;
    }

    /// <summary>
    ///   Generate block rules from IP-type blocklists.
    /// </summary>
    private List<FirewallRule> GenerateBlocklistRules()
    {
        var rules = new List<FirewallRule>();
        var blocklists = _blocklistManager.Blocklists
            .Where(b => b.IsEnabled && (b.ContentType == BlocklistContentType.IP || b.ContentType == BlocklistContentType.Domain))
            .ToList();

        if (blocklists.Count == 0) return rules;

        // For IP blocklists, we can't enumerate all IPs — the bloom filter doesn't support iteration.
        // Instead we add a catch-all block rule that marks blocklist enforcement.
        // Actual per-IP blocking happens at connection time via Evaluate().
        //
        // For WFP-level blocklist enforcement, a separate mechanism would be needed
        // (e.g., subscribing to connection events and dynamically adding per-IP filters).
        // For now, add a placeholder rule that documents the blocklist coverage.
        foreach (var bl in blocklists)
        {
            if (bl.EntryCount > 0)
            {
                rules.Add(new FirewallRule
                {
                    Name = $"[Blocklist] {bl.Name}",
                    Description = $"Auto-generated from blocklist '{bl.Name}' — {bl.EntryCount} entries. Enforced at connection time.",
                    Action = RuleAction.Block,
                    Direction = TrafficDirection.Outbound,
                    IsEnabled = true,
                    CreatedAt = DateTime.UtcNow
                });
            }
        }

        return rules;
    }

    /// <summary>
    ///   Check if a profile with action override applies to this rule.
    /// </summary>
    private bool ShouldApplyOverride(FirewallRule rule, out RuleAction? overrideAction)
    {
        overrideAction = null;

        if (string.IsNullOrEmpty(rule.ApplicationPath))
            return false;

        var appPath = rule.ApplicationPath!;

        foreach (var profile in _profileManager.Profiles)
        {
            if (profile.IsSpecial || profile.ActionOverride == null)
                continue;

            // Check if fingerprint matches the rule's application path
            var matches = profile.Fingerprints?.Any(fp =>
                !string.IsNullOrEmpty(fp.Value) &&
                appPath.IndexOf(fp.Value, StringComparison.OrdinalIgnoreCase) >= 0) == true;

            if (!matches)
                continue;

            // Determine override action based on direction
            if (rule.Direction == TrafficDirection.Outbound && profile.ActionOverride.BlockOutbound == true)
            {
                overrideAction = RuleAction.Block;
                return true;
            }
            if (rule.Direction == TrafficDirection.Inbound && profile.ActionOverride.BlockInbound == true)
            {
                overrideAction = RuleAction.Block;
                return true;
            }
            if (rule.Direction == TrafficDirection.Outbound && profile.ActionOverride.AllowOutbound == true)
            {
                overrideAction = RuleAction.Permit;
                return true;
            }
            if (rule.Direction == TrafficDirection.Inbound && profile.ActionOverride.AllowInbound == true)
            {
                overrideAction = RuleAction.Permit;
                return true;
            }
        }

        return false;
    }

    // ════════════════════════════════════════════════════════════════
    //  Connection evaluation
    // ════════════════════════════════════════════════════════════════

    /// <inheritdoc />
    public VerdictResult Evaluate(ConnectionEntry connection)
    {
        // Level 1: Blocklist check
        if (connection.RemoteAddress != null)
        {
            var addrStr = connection.RemoteAddress.ToString();
            if (_blocklistManager.IsIpBlocked(addrStr))
            {
                return new VerdictResult
                {
                    Action = RuleAction.Block,
                    Source = "Blocklist",
                    Reason = $"Remote IP {addrStr} matched a blocklist"
                };
            }

            // Also check RemoteHostName against domain blocklists
            if (!string.IsNullOrEmpty(connection.RemoteHostName) &&
                _blocklistManager.IsDomainBlocked(connection.RemoteHostName!))
            {
                return new VerdictResult
                {
                    Action = RuleAction.Block,
                    Source = "Blocklist",
                    Reason = $"Domain '{connection.RemoteHostName}' matched a blocklist"
                };
            }
        }

        // Level 2: Profile check
        if (connection.ProcessId > 0)
        {
            var profile = _profileManager.MatchProcess(connection.ProcessId);
            if (profile != null && profile.ActionOverride != null)
            {
                var action = GetActionFromOverride(profile.ActionOverride, connection.IsInbound);
                if (action.HasValue)
                {
                    profile.HitCount++;
                    return new VerdictResult
                    {
                        Action = action.Value,
                        Source = "Profile",
                        Reason = $"Profile '{profile.Name}' action override"
                    };
                }
            }
        }

        // Level 3: No specific match — pass through to user rules
        return new VerdictResult
        {
            Action = null,
            Source = "Pass",
            Reason = "No blocklist or profile match — deferring to user rules"
        };
    }

    /// <inheritdoc />
    public bool IsAddressBlocked(string? ipAddress)
    {
        if (string.IsNullOrEmpty(ipAddress))
            return false;
        return _blocklistManager.IsIpBlocked(ipAddress!);
    }

    /// <inheritdoc />
    public RuleAction? GetProfileAction(uint processId)
    {
        if (processId == 0)
            return null;

        var profile = _profileManager.MatchProcess(processId);
        if (profile?.ActionOverride == null)
            return null;

        // For outbound (the common case for process-level blocking)
        if (profile.ActionOverride.BlockOutbound == true)
            return RuleAction.Block;
        if (profile.ActionOverride.AllowOutbound == true)
            return RuleAction.Permit;

        return null;
    }

    // ════════════════════════════════════════════════════════════════
    //  Helpers
    // ════════════════════════════════════════════════════════════════

    private static RuleAction? GetActionFromOverride(NetworkActionSettings settings, bool isInbound)
    {
        if (isInbound)
        {
            if (settings.BlockInbound == true) return RuleAction.Block;
            if (settings.AllowInbound == true) return RuleAction.Permit;
        }
        else
        {
            if (settings.BlockOutbound == true) return RuleAction.Block;
            if (settings.AllowOutbound == true) return RuleAction.Permit;
        }
        return null;
    }

    private static FirewallRule CloneRule(FirewallRule rule)
    {
        return new FirewallRule
        {
            Id = Guid.NewGuid(),
            Name = rule.Name,
            Description = rule.Description,
            IsEnabled = rule.IsEnabled,
            Action = rule.Action,
            Direction = rule.Direction,
            AddressFamily = rule.AddressFamily,
            Protocol = rule.Protocol,
            LocalPort = rule.LocalPort,
            RemotePort = rule.RemotePort,
            LocalAddress = rule.LocalAddress,
            RemoteAddress = rule.RemoteAddress,
            ApplicationPath = rule.ApplicationPath,
            UserName = rule.UserName,
            ServiceName = rule.ServiceName,
            CreatedAt = rule.CreatedAt,
            UpdatedAt = rule.UpdatedAt
        };
    }

    private static void AddIfUnique(List<FirewallRule> rules, FirewallRule rule, HashSet<Guid> seenIds)
    {
        if (seenIds.Add(rule.Id))
            rules.Add(rule);
    }

    private void OnPolicyChanged()
    {
        PolicyChanged?.Invoke(this, EventArgs.Empty);
    }
}
