using System.Net;

namespace Heco.Common.Models;

/// <summary>
///   DHCP lease information for a network adapter.
/// </summary>
public sealed class DhcpLeaseInfo
{
    /// <summary>Adapter interface index.</summary>
    public uint IfIndex { get; set; }

    /// <summary>Adapter description/name.</summary>
    public string? AdapterName { get; set; }

    /// <summary>Whether DHCP is enabled on this adapter.</summary>
    public bool DhcpEnabled { get; set; }

    /// <summary>DHCP server address (IPv4).</summary>
    public IPAddress? DhcpServer { get; set; }

    /// <summary>Lease lifetime in seconds.</summary>
    public ulong LeaseLifetime { get; set; }

    /// <summary>Assigned IPv4 address.</summary>
    public IPAddress? Ipv4Address { get; set; }

    /// <summary>Subnet mask.</summary>
    public IPAddress? SubnetMask { get; set; }

    public override string ToString() =>
        $"{AdapterName ?? $"If{IfIndex}"}: DHCP={DhcpEnabled}, Server={DhcpServer}, Lease={LeaseLifetime}s";
}
