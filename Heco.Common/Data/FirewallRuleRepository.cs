using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Heco.Common.Models;
using Heco.Common.Interfaces;

namespace Heco.Common.Data;

/// <summary>
///   JSON-file-backed persistence for firewall rules.
///   Uses <see cref="System.Runtime.Serialization.Json.DataContractJsonSerializer"/> to avoid
///   external dependencies while targeting .NET Framework 4.7.2.
/// </summary>
public sealed class FirewallRuleRepository : IFirewallRuleRepository
{
    private readonly string _filePath;

    /// <summary>Default data directory under %LOCALAPPDATA%\Heco\Firewall.</summary>
    public static readonly string DefaultDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Heco", "Firewall");

    public FirewallRuleRepository(string? filePath = null)
    {
        _filePath = filePath ?? Path.Combine(DefaultDirectory, "rules.json");
    }

    public IReadOnlyList<FirewallRule> LoadAll()
    {
        if (!File.Exists(_filePath))
            return Array.Empty<FirewallRule>();

        try
        {
            var serializer = new System.Runtime.Serialization.Json.DataContractJsonSerializer(
                typeof(FirewallRule[]));
            using var fs = File.OpenRead(_filePath);
            return (FirewallRule[]?)serializer.ReadObject(fs) ?? Array.Empty<FirewallRule>();
        }
        catch
        {
            return Array.Empty<FirewallRule>();
        }
    }

    public void Save(FirewallRule rule)
    {
        var rules = LoadAll().ToList();
        var idx = rules.FindIndex(r => r.Id == rule.Id);
        if (idx >= 0)
            rules[idx] = rule;
        else
            rules.Add(rule);

        SaveAll(rules);
    }

    public void Delete(Guid ruleId)
    {
        var rules = LoadAll().ToList();
        rules.RemoveAll(r => r.Id == ruleId);
        SaveAll(rules);
    }

    public void SaveAll(IEnumerable<FirewallRule> rules)
    {
        var dir = Path.GetDirectoryName(_filePath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        var serializer = new System.Runtime.Serialization.Json.DataContractJsonSerializer(
            typeof(FirewallRule[]));
        using var fs = File.Create(_filePath);
        serializer.WriteObject(fs, rules.ToArray());
    }
}
