using System;
using System.Collections.Generic;
using Heco.Common.Models;

namespace Heco.Common.Interfaces;

/// <summary>
///   Persistence layer for firewall rules.
/// </summary>
public interface IFirewallRuleRepository
{
    /// <summary>Load all rules from storage.</summary>
    IReadOnlyList<FirewallRule> LoadAll();

    /// <summary>Save a single rule (add or update).</summary>
    void Save(FirewallRule rule);

    /// <summary>Delete a rule by its Guid identifier.</summary>
    void Delete(Guid ruleId);

    /// <summary>Persist the entire rule set (atomically replace).</summary>
    void SaveAll(IEnumerable<FirewallRule> rules);
}
