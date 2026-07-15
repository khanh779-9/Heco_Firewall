using System.Collections.Generic;
using Heco.Common.Models;

namespace Heco.Common.Interfaces;

/// <summary>
///   Central service for managing the WFP engine lifecycle.
/// </summary>
public interface IWfpEngine
{
    /// <summary>Whether the engine session is currently open.</summary>
    bool IsConnected { get; }

    /// <summary>Open a session to the WFP engine. Must be called with Administrator privileges.</summary>
    void Open(string? serverName = null);

    /// <summary>Close the WFP engine session and release all handles.</summary>
    void Close();

    /// <summary>Apply all enabled rules to the WFP engine.</summary>
    void ApplyRules(IEnumerable<FirewallRule> rules);

    /// <summary>Remove a specific rule from the WFP engine by its filter ID.</summary>
    void RemoveRule(ulong wfpFilterId);

    /// <summary>Clear all rules registered by this application from the WFP engine.</summary>
    void ClearAllRules();
}
