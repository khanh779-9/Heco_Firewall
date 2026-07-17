using System;
using System.Collections.Generic;
using Heco.Common.Models;
using Heco.Common.Enums;

namespace Heco.Common.Services.Verdict;

/// <summary>
///   Multi-level decision pipeline for firewall policy.
///   Evaluates connections against blocklists → profiles → user rules → default,
///   and generates enhanced WFP rule sets for the engine.
/// </summary>
public interface IVerdictEngine
{
    /// <summary>
    ///   Generate the complete rule set from user rules + blocklists + profiles.
    ///   Called before passing rules to <c>HecoEngine.ApplyRules()</c>.
    /// </summary>
    List<FirewallRule> GenerateRuleSet(IEnumerable<FirewallRule> userRules, bool includeBlocklists = true, bool includeProfiles = true);

    /// <summary>
    ///   Evaluate a connection against the full policy stack (blocklist → profile → pass).
    /// </summary>
    VerdictResult Evaluate(ConnectionEntry connection);

    /// <summary>
    ///   Quick check: is this IP address blocked by any blocklist?
    /// </summary>
    bool IsAddressBlocked(string? ipAddress);

    /// <summary>
    ///   Quick check: does a profile override exist for this process?
    ///   Returns the action override or null.
    /// </summary>
    RuleAction? GetProfileAction(uint processId);

    /// <summary>
    ///   Raised when the policy changes (profiles or blocklists modified).
    /// </summary>
    event EventHandler<EventArgs>? PolicyChanged;
}

/// <summary>
///   Result of a single verdict evaluation.
/// </summary>
public sealed class VerdictResult
{
    /// <summary>
    ///   The action to take. <c>null</c> means "no verdict — pass to next level".
    /// </summary>
    public RuleAction? Action { get; set; }

    /// <summary>
    ///   Which policy level produced this verdict: "Blocklist", "Profile", "Rule", "Pass".
    /// </summary>
    public string Source { get; set; } = "Pass";

    /// <summary>
    ///   Human-readable reason for the verdict.
    /// </summary>
    public string Reason { get; set; } = string.Empty;
}