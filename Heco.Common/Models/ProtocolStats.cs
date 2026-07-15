namespace Heco.Common.Models;

/// <summary>
///   Aggregate protocol statistics from the OS (ICMP, IP).
///   Updated each refresh cycle by <c>ConnectionMonitor</c>.
/// </summary>
public sealed class ProtocolStats
{
    // ── ICMP ─────────────────────────────────────────────────────

    /// <summary>Total incoming ICMP messages.</summary>
    public uint IcmpInMsgs { get; set; }
    /// <summary>Incoming ICMP errors.</summary>
    public uint IcmpInErrors { get; set; }
    /// <summary>Total outgoing ICMP messages.</summary>
    public uint IcmpOutMsgs { get; set; }
    /// <summary>Outgoing ICMP errors.</summary>
    public uint IcmpOutErrors { get; set; }
    /// <summary>Echo (ping) replies received.</summary>
    public uint IcmpEchoRecv { get; set; }
    /// <summary>Echo (ping) requests sent.</summary>
    public uint IcmpEchoSent { get; set; }
    /// <summary>Destination unreachable messages received.</summary>
    public uint IcmpDestUnreachRecv { get; set; }
    /// <summary>Destination unreachable messages sent.</summary>
    public uint IcmpDestUnreachSent { get; set; }

    // ── IP ───────────────────────────────────────────────────────

    /// <summary>Total incoming IP datagrams received.</summary>
    public uint IpInReceives { get; set; }
    /// <summary>Total outgoing IP datagrams sent.</summary>
    public uint IpOutRequests { get; set; }
    /// <summary>Incoming datagrams discarded.</summary>
    public uint IpInDiscards { get; set; }
    /// <summary>Outgoing datagrams discarded.</summary>
    public uint IpOutDiscards { get; set; }
    /// <summary>Successfully reassembled IP fragments.</summary>
    public uint IpReassemblyOks { get; set; }
    /// <summary>Failed IP fragment reassemblies.</summary>
    public uint IpReassemblyFails { get; set; }
    /// <summary>IP fragments created.</summary>
    public uint IpFragCreates { get; set; }
}
