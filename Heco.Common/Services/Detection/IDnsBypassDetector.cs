using System.Collections.Generic;
using System.Net;

namespace Heco.Common.Services.Detection;

/// <summary>
///   Detects DNS bypass attempts — connections using DoT (port 853),
///   known DoH IPs, or non-standard DNS servers.
/// </summary>
public interface IDnsBypassDetector
{
    /// <summary>Known DoH provider IPs, populated on initialization.</summary>
    IReadOnlyList<IPAddress> KnownDohIps { get; }

    /// <summary>Check if a connection is using DNS bypass.</summary>
    DnsBypassResult Check(IPAddress remoteAddress, ushort remotePort);

    /// <summary>Check if an IP is a known DoH server.</summary>
    bool IsKnownDohServer(IPAddress address);

    /// <summary>Check if a port is DoT (853). Implementations should return port == 853.</summary>
    bool IsDotPort(ushort port);

    /// <summary>Update the list of network adapter DNS servers to compare against.</summary>
    void UpdateNetworkDnsServers(IEnumerable<IPAddress> dnsServers);
}

/// <summary>
///   Result of a DNS bypass check.
/// </summary>
public sealed class DnsBypassResult
{
    public bool IsDnsBypass { get; set; }
    public DnsBypassType BypassType { get; set; } = DnsBypassType.None;
    public string? Description { get; set; }
    public string? MatchedProvider { get; set; }
}

public enum DnsBypassType
{
    None,
    DotPort853,
    KnownDohIp,
    NonStandardDnsServer
}
