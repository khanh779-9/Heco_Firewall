using System;
using System.Net;
using Heco.Common.Enums;

namespace Heco.Common.Models;

/// <summary>
///   A live network connection snapshot from the OS.
/// </summary>
public sealed class ConnectionEntry
{
    /// <summary>Composite key for equality (protocol + 5-tuple hash).</summary>
    public long Id { get; set; }

    /// <summary>Network protocol (TCP, UDP, ICMP, ARP, etc.).</summary>
    public NetworkProtocol Protocol { get; set; }

    /// <summary>Local endpoint.</summary>
    public IPAddress LocalAddress { get; set; } = IPAddress.Any;

    /// <summary>Local port.</summary>
    public ushort LocalPort { get; set; }

    /// <summary>Remote endpoint.</summary>
    public IPAddress RemoteAddress { get; set; } = IPAddress.Any;

    /// <summary>Remote port.</summary>
    public ushort RemotePort { get; set; }

    /// <summary>Local MAC address (ARP/IPNET).</summary>
    public string? LocalMacAddress { get; set; }

    /// <summary>Remote MAC address (ARP).</summary>
    public string? RemoteMacAddress { get; set; }

    /// <summary>ARP entry type (Static/Dynamic/Invalid).</summary>
    public string? ArpType { get; set; }

    /// <summary>Interface index (ARP/IPNET).</summary>
    public int InterfaceIndex { get; set; }

    /// <summary>TCP state machine state (for non-TCP this is <c>Unknown</c>).</summary>
    public TcpState TcpState { get; set; } = TcpState.Unknown;

    /// <summary>Owning process identifier.</summary>
    public uint ProcessId { get; set; }

    /// <summary>Owning process name (resolved lazily).</summary>
    public string? ProcessName { get; set; }

    /// <summary>Full executable path.</summary>
    public string? ProcessPath { get; set; }

    /// <summary>Reverse-DNS host name (resolved lazily).</summary>
    public string? RemoteHostName { get; set; }

    /// <summary>Whether the direction is inbound.</summary>
    public bool IsInbound { get; set; }

    /// <summary>Bytes received on this connection.</summary>
    public long BytesReceived { get; set; }

    /// <summary>Bytes sent on this connection.</summary>
    public long BytesSent { get; set; }

    /// <summary>Time the connection was first seen.</summary>
    public DateTime FirstSeen { get; set; } = DateTime.UtcNow;

    /// <summary>Time of last activity.</summary>
    public DateTime LastSeen { get; set; } = DateTime.UtcNow;

    //  Enriched fields (populated by UI layer) 

    /// <summary>Resolved profile name from ProfileManager.</summary>
    public string? ProfileName { get; set; }

    /// <summary>ISO 3166-1 alpha-2 country code from GeoIP lookup.</summary>
    public string? CountryCode { get; set; }

    /// <summary>Full country name from GeoIP lookup.</summary>
    public string? CountryName { get; set; }

    /// <summary>Autonomous System Number (e.g. "AS15169") from GeoIP lookup.</summary>
    public string? Asn { get; set; }

    /// <summary>Organization name from GeoIP lookup.</summary>
    public string? Organization { get; set; }

    //  Bandwidth enrichment (populated by BandwidthTracker) ─

    /// <summary>Current send rate in KB/s.</summary>
    public double SentKbps { get; set; }

    /// <summary>Current receive rate in KB/s.</summary>
    public double ReceivedKbps { get; set; }

    /// <summary>Returns a formatted string representing this connection.</summary>
    public override string ToString() =>
        $"[{Protocol}] {LocalAddress}:{LocalPort} → {RemoteAddress}:{RemotePort}  PID:{ProcessId} {ProcessName}";
}
