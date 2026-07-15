using System;
using Heco.Common.Models;

namespace Heco.Core.Engine;

//  Partial: high-level rule management ─
public partial class WfpEngine
{
    /// <summary>Add a single rule to the WFP engine.</summary>
    public void AddRule(FirewallRule rule)
    {
        if (rule == null)
            throw new ArgumentNullException(nameof(rule));

        ApplyRules(new[] { rule });
    }

    /// <summary>Remove a rule from the WFP engine by its rule GUID.</summary>
    public void RemoveRule(Guid ruleId)
    {
        lock (_lock)
        {
            if (_ruleIdToFilterId.TryGetValue(ruleId, out var filterId))
            {
                RemoveRule(filterId);
                _ruleIdToFilterId.Remove(ruleId);
            }
        }
    }
}
