using System;
using Heco.Common.Enums;

namespace Heco.Common.Models;

/// <summary>
///   Represents a single firewall rule — the core policy unit.
/// </summary>
public sealed class FirewallRule
{
    /// <summary>Unique identifier.</summary>
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Human-readable name shown in the UI.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Optional description.</summary>
    public string? Description { get; set; }

    /// <summary>Whether this rule is currently enforced.</summary>
    public bool IsEnabled { get; set; } = true;

    /// <summary>Permit or Block.</summary>
    public RuleAction Action { get; set; } = RuleAction.Block;

    /// <summary>Inbound or Outbound.</summary>
    public TrafficDirection Direction { get; set; } = TrafficDirection.Outbound;

    /// <summary>IPv4, IPv6, or Both.</summary>
    public AddressFamily AddressFamily { get; set; } = AddressFamily.Both;

    /// <summary>Protocol to match (Any, TCP, UDP, ICMP…).</summary>
    public NetworkProtocol Protocol { get; set; } = NetworkProtocol.Any;

    //  Ports 

    /// <summary>Local port filter. Null = any.</summary>
    public ushort? LocalPort { get; set; }

    /// <summary>Remote port filter. Null = any.</summary>
    public ushort? RemotePort { get; set; }

    //  Addresses ─

    /// <summary>Local address in CIDR notation ("192.168.1.0/24"). Null = any.</summary>
    public string? LocalAddress { get; set; }

    /// <summary>Remote address in CIDR notation. Null = any.</summary>
    public string? RemoteAddress { get; set; }

    //  Application / Identity 

    /// <summary>Full path to the executable. Null = any application.</summary>
    public string? ApplicationPath { get; set; }

    /// <summary>Windows account name (DOMAIN\User). Null = any user.</summary>
    public string? UserName { get; set; }

    /// <summary>Windows service short name. Null = any.</summary>
    public string? ServiceName { get; set; }

    //  Metadata 

    /// <summary>When this rule was created.</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>When this rule was last modified.</summary>
    public DateTime? UpdatedAt { get; set; }

    /// <summary>WFP filter identifier assigned by the engine (0 = not applied).</summary>
    public ulong WfpFilterId { get; set; }

    /// <summary>How many times this rule has matched traffic.</summary>
    public long HitCount { get; set; }

    /// <summary>UI-only selection flag for batch operations.</summary>
    public bool IsSelected { get; set; }

    /// <summary>Returns a concise display string.</summary>
    public override string ToString() =>
        $"{(IsEnabled ? "✓" : "✗")} {Action} {Direction} {Protocol} {LocalAddress ?? "*"}:{LocalPort?.ToString() ?? "*"} → {RemoteAddress ?? "*"}:{RemotePort?.ToString() ?? "*"} [{Name}]";
}
