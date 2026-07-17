using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using Heco.Common.Enums;

namespace Heco.Common.Services.Monitoring;

/// <summary>
///   Monitors network tables (TCP/UDP connections) and network adapters.
///   Provides IP scope classification and dual PID verification.
/// </summary>
public interface INetworkMonitor
{
    /// <summary>Current active connections (TCP + UDP).</summary>
    IReadOnlyList<NetworkTableEntry> ActiveConnections { get; }

    /// <summary>Current network adapters.</summary>
    IReadOnlyList<NetworkAdapterInfo> Adapters { get; }

    /// <summary>Event raised when connections are updated.</summary>
    event EventHandler<NetworkTableUpdatedEventArgs> ConnectionsUpdated;

    /// <summary>Event raised when adapters change (added/removed/dns changed).</summary>
    event EventHandler<NetworkAdaptersChangedEventArgs> AdaptersChanged;

    /// <summary>Start monitoring.</summary>
    void Start(int tableIntervalMs = 1000, int adapterIntervalMs = 60000);

    /// <summary>Stop monitoring.</summary>
    void Stop();

    /// <summary>Classify an IP address into a scope category.</summary>
    IpScope GetIpScope(IPAddress address);

    /// <summary>Verify a PID against the current OS table (cross-reference check).</summary>
    bool VerifyPid(uint pid);
}

/// <summary>
///   A single entry from the OS network table.
/// </summary>
public sealed class NetworkTableEntry
{
    public long Id { get; set; }
    public NetworkProtocol Protocol { get; set; }
    public IPAddress LocalAddress { get; set; } = IPAddress.Any;
    public ushort LocalPort { get; set; }
    public IpScope LocalScope { get; set; }
    public IPAddress RemoteAddress { get; set; } = IPAddress.Any;
    public ushort RemotePort { get; set; }
    public IpScope RemoteScope { get; set; }
    public TcpState TcpState { get; set; } = TcpState.Unknown;
    public uint ProcessId { get; set; }
    public bool IsInbound { get; set; }
    public DateTime FirstSeen { get; set; } = DateTime.UtcNow;
    public DateTime LastSeen { get; set; } = DateTime.UtcNow;
    public bool IsEnded { get; set; }
}

/// <summary>
///   IP address scope classification.
/// </summary>
public enum IpScope
{
    Loopback = 0,
    Multicast = 1,
    Lan = 2,
    Internet = 3
}

/// <summary>
///   TCP state machine states.
/// </summary>
public enum TcpState
{
    Unknown = 0,
    Closed = 1,
    Listen = 2,
    SynSent = 3,
    SynReceived = 4,
    Established = 5,
    FinWait1 = 6,
    FinWait2 = 7,
    CloseWait = 8,
    Closing = 9,
    LastAck = 10,
    TimeWait = 11,
    DeleteTcb = 12
}

/// <summary>
///   Information about a network adapter.
/// </summary>
public sealed class NetworkAdapterInfo
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string? AdapterId { get; set; }
    public OperationalStatus Status { get; set; }
    public long Speed { get; set; }
    public List<IPAddress> DnsServers { get; set; } = new();
    public List<UnicastIPAddressInformation> UnicastAddresses { get; set; } = new();
    public bool IsDefaultGateway { get; set; }
}

public sealed class NetworkTableUpdatedEventArgs : EventArgs
{
    public List<NetworkTableEntry> Added { get; } = new();
    public List<NetworkTableEntry> Removed { get; } = new();
    public List<NetworkTableEntry> Updated { get; } = new();
}

public sealed class NetworkAdaptersChangedEventArgs : EventArgs
{
    public List<NetworkAdapterInfo> Added { get; } = new();
    public List<NetworkAdapterInfo> Removed { get; } = new();
    public List<NetworkAdapterInfo> DnsChanged { get; } = new();
}