using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using Heco.Common.Enums;
using Heco.Common.Services.Monitoring;
using Heco.Common.Services.Diagnostics;
using TcpStateMonitoring = Heco.Common.Services.Monitoring.TcpState;

namespace Heco.Common.Services.Network;

/// <summary>
///   Monitors network tables (TCP/UDP connections) and network adapters.
///   Uses P/Invoke for GetExtendedTcpTable/GetExtendedUdpTable with PID tracking,
///   and BCL NetworkInterface for adapter monitoring.
/// </summary>
public sealed class NetworkMonitor : INetworkMonitor, IDisposable
{
    private readonly List<NetworkTableEntry> _activeConnections = new();
    private readonly List<NetworkAdapterInfo> _adapters = new();
    private readonly Dictionary<long, NetworkTableEntry> _connectionCache = new();
    private readonly object _sync = new();
    private System.Threading.Timer? _tableTimer;
    private System.Threading.Timer? _adapterTimer;
    private const int MaxCacheSize = 1024;

    public IReadOnlyList<NetworkTableEntry> ActiveConnections => _activeConnections.AsReadOnly();
    public IReadOnlyList<NetworkAdapterInfo> Adapters => _adapters.AsReadOnly();

    public event EventHandler<NetworkTableUpdatedEventArgs>? ConnectionsUpdated;
    public event EventHandler<NetworkAdaptersChangedEventArgs>? AdaptersChanged;

    public void Start(int tableIntervalMs = 1000, int adapterIntervalMs = 60000)
    {
        _tableTimer = new System.Threading.Timer(_ => UpdateNetworkTables(), null, 0, tableIntervalMs);
        _adapterTimer = new System.Threading.Timer(_ => UpdateAdapters(), null, 0, adapterIntervalMs);
        Logger.Info("NetworkMonitor started");
    }

    public void Stop()
    {
        _tableTimer?.Dispose();
        _adapterTimer?.Dispose();
        _tableTimer = null;
        _adapterTimer = null;
        Logger.Info("NetworkMonitor stopped");
    }

    public IpScope GetIpScope(IPAddress address)
    {
        if (IPAddress.IsLoopback(address)) return IpScope.Loopback;
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            // Multicast: 224.0.0.0/4
            if (bytes[0] >= 224 && bytes[0] <= 239) return IpScope.Multicast;
            // LAN: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            if (bytes[0] == 10) return IpScope.Lan;
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return IpScope.Lan;
            if (bytes[0] == 192 && bytes[1] == 168) return IpScope.Lan;
            return IpScope.Internet;
        }
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            // IPv6 loopback
            if (address.Equals(IPAddress.IPv6Loopback)) return IpScope.Loopback;
            // IPv6 multicast (ff00::/8)
            var bytes = address.GetAddressBytes();
            if (bytes[0] == 0xff) return IpScope.Multicast;
            // Unique local address (fc00::/7)
            if ((bytes[0] & 0xfe) == 0xfc) return IpScope.Lan;
            // Link-local (fe80::/10)
            if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80) return IpScope.Lan;
            return IpScope.Internet;
        }
        return IpScope.Internet;
    }

    public bool VerifyPid(uint pid)
    {
        lock (_sync)
        {
            return _activeConnections.Any(c => c.ProcessId == pid);
        }
    }

    //  Network table update ─

    private void UpdateNetworkTables()
    {
        try
        {
            var currentEntries = new List<NetworkTableEntry>();
            currentEntries.AddRange(GetTcpEntries());
            currentEntries.AddRange(GetUdpEntries());

            var args = new NetworkTableUpdatedEventArgs();

            lock (_sync)
            {
                var currentIds = new HashSet<long>(currentEntries.Select(e => e.Id));
                var cachedIds = new HashSet<long>(_connectionCache.Keys);

                // Find removed
                foreach (var id in cachedIds)
                {
                    if (!currentIds.Contains(id) && _connectionCache.TryGetValue(id, out var removed))
                    {
                        removed.IsEnded = true;
                        args.Removed.Add(removed);
                        _connectionCache.Remove(id);
                    }
                }

                // Find added/updated
                foreach (var entry in currentEntries)
                {
                    if (_connectionCache.TryGetValue(entry.Id, out var existing))
                    {
                        existing.LastSeen = DateTime.UtcNow;
                        args.Updated.Add(existing);
                    }
                    else
                    {
                        entry.FirstSeen = DateTime.UtcNow;
                        _connectionCache[entry.Id] = entry;
                        args.Added.Add(entry);
                    }
                }

                // Enforce cache size limit
                if (_connectionCache.Count > MaxCacheSize)
                {
                    var toRemove = _connectionCache
                        .OrderBy(kvp => kvp.Value.LastSeen)
                        .Take(_connectionCache.Count - MaxCacheSize)
                        .Select(kvp => kvp.Key)
                        .ToList();

                    foreach (var id in toRemove)
                        _connectionCache.Remove(id);
                }

                _activeConnections.Clear();
                _activeConnections.AddRange(_connectionCache.Values.Where(e => !e.IsEnded));
            }

            if (args.Added.Count > 0 || args.Removed.Count > 0)
                ConnectionsUpdated?.Invoke(this, args);
        }
        catch (Exception ex)
        {
            Logger.Debug($"UpdateNetworkTables: {ex.Message}");
        }
    }

    //  P/Invoke: GetExtendedTcpTable ─

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, TcpTableClass tblClass, uint reserved = 0);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int dwOutBufLen, bool sort, int ipVersion, UdpTableClass tblClass, uint reserved = 0);

    private enum TcpTableClass { BasicTable, OwnerPidTable, OwnerModuleTable }
    private enum UdpTableClass { BasicTable, OwnerPidTable, OwnerModuleTable }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPTABLE_OWNER_PID
    {
        public uint NumEntries;
        // Followed by MIB_TCPROW_OWNER_PID[NumEntries]
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct MIB_TCP6ROW_OWNER_PID
    {
        public fixed byte LocalAddr[16];
        public uint LocalScopeId;
        public uint LocalPort;
        public fixed byte RemoteAddr[16];
        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID
    {
        public uint LocalAddr;
        public uint LocalPort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct MIB_UDP6ROW_OWNER_PID
    {
        public fixed byte LocalAddr[16];
        public uint LocalScopeId;
        public uint LocalPort;
        public uint OwningPid;
    }

    private List<NetworkTableEntry> GetTcpEntries()
    {
        var entries = new List<NetworkTableEntry>();
        entries.AddRange(GetTcp4Entries());
        entries.AddRange(GetTcp6Entries());
        return entries;
    }

    private List<NetworkTableEntry> GetTcp4Entries()
    {
        var entries = new List<NetworkTableEntry>();
        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, false, 2, TcpTableClass.OwnerPidTable);

        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            var result = GetExtendedTcpTable(buffer, ref bufferSize, true, 2, TcpTableClass.OwnerPidTable);
            if (result != 0) return entries;

            var numEntries = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
            var rowPtr = buffer + 4; // Skip NumEntries

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                entries.Add(new NetworkTableEntry
                {
                    Id = HashIds(Protocol.TCP, row.LocalAddr, row.LocalPort, row.RemoteAddr, row.RemotePort),
                    Protocol = NetworkProtocol.TCP,
                    LocalAddress = new IPAddress((long)IPAddress.NetworkToHostOrder((int)row.LocalAddr)),
                    LocalPort = PortNetToHost(row.LocalPort),
                    LocalScope = GetIpScope(new IPAddress((long)IPAddress.NetworkToHostOrder((int)row.LocalAddr))),
                    RemoteAddress = new IPAddress((long)IPAddress.NetworkToHostOrder((int)row.RemoteAddr)),
                    RemotePort = PortNetToHost(row.RemotePort),
                    RemoteScope = GetIpScope(new IPAddress((long)IPAddress.NetworkToHostOrder((int)row.RemoteAddr))),
                    TcpState = (TcpStateMonitoring)row.State,
                    ProcessId = row.OwningPid,
                    IsInbound = row.State == (uint)TcpStateMonitoring.Listen
                });
                rowPtr += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        return entries;
    }

    private unsafe List<NetworkTableEntry> GetTcp6Entries()
    {
        var entries = new List<NetworkTableEntry>();
        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, false, 23, TcpTableClass.OwnerPidTable);

        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            var result = GetExtendedTcpTable(buffer, ref bufferSize, true, 23, TcpTableClass.OwnerPidTable);
            if (result != 0) return entries;

            var numEntries = *(int*)buffer;
            var rowPtr = (byte*)buffer + 4;

            for (int i = 0; i < numEntries; i++)
            {
                // MIB_TCP6ROW_OWNER_PID layout:
                // offset 0: localAddr (16 bytes)
                // offset 16: localScopeId (4 bytes)
                // offset 20: localPort (4 bytes)
                // offset 24: remoteAddr (16 bytes)
                // offset 40: remoteScopeId (4 bytes)
                // offset 44: remotePort (4 bytes)
                // offset 48: state (4 bytes)
                // offset 52: owningPid (4 bytes)
                // Row size = 56 bytes

                var localBytes = new byte[16];
                Marshal.Copy((IntPtr)rowPtr, localBytes, 0, 16);
                var localScopeId = *(uint*)(rowPtr + 16);
                var localPortVal = *(uint*)(rowPtr + 20);

                var remoteBytes = new byte[16];
                Marshal.Copy((IntPtr)(rowPtr + 24), remoteBytes, 0, 16);
                var remoteScopeId = *(uint*)(rowPtr + 40);
                var remotePortVal = *(uint*)(rowPtr + 44);

                var state = *(uint*)(rowPtr + 48);
                var owningPid = *(uint*)(rowPtr + 52);

                IPAddress localAddr = new IPAddress(localBytes, localScopeId);
                IPAddress remoteAddr = new IPAddress(remoteBytes, remoteScopeId);

                entries.Add(new NetworkTableEntry
                {
                    Id = HashIds(Protocol.TCP, localAddr, localPortVal, remoteAddr, remotePortVal),
                    Protocol = NetworkProtocol.TCP,
                    LocalAddress = localAddr,
                    LocalPort = PortNetToHost(localPortVal),
                    LocalScope = GetIpScope(localAddr),
                    RemoteAddress = remoteAddr,
                    RemotePort = PortNetToHost(remotePortVal),
                    RemoteScope = GetIpScope(remoteAddr),
                    TcpState = (TcpStateMonitoring)state,
                    ProcessId = owningPid,
                    IsInbound = state == (uint)TcpStateMonitoring.Established
                });
                rowPtr += 56;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        return entries;
    }

    private List<NetworkTableEntry> GetUdpEntries()
    {
        var entries = new List<NetworkTableEntry>();
        entries.AddRange(GetUdp4Entries());
        entries.AddRange(GetUdp6Entries());
        return entries;
    }

    private List<NetworkTableEntry> GetUdp4Entries()
    {
        var entries = new List<NetworkTableEntry>();
        int bufferSize = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, false, 2, UdpTableClass.OwnerPidTable);

        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            var result = GetExtendedUdpTable(buffer, ref bufferSize, true, 2, UdpTableClass.OwnerPidTable);
            if (result != 0) return entries;

            var numEntries = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();
            var rowPtr = buffer + 4;

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                entries.Add(new NetworkTableEntry
                {
                    Id = HashIds(Protocol.UDP, row.LocalAddr, row.LocalPort, 0, 0),
                    Protocol = NetworkProtocol.UDP,
                    LocalAddress = new IPAddress((long)IPAddress.NetworkToHostOrder((int)row.LocalAddr)),
                    LocalPort = PortNetToHost(row.LocalPort),
                    LocalScope = GetIpScope(new IPAddress((long)IPAddress.NetworkToHostOrder((int)row.LocalAddr))),
                    RemoteAddress = IPAddress.Any,
                    RemotePort = 0,
                    RemoteScope = IpScope.Internet,
                    TcpState = TcpStateMonitoring.Unknown,
                    ProcessId = row.OwningPid
                });
                rowPtr += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        return entries;
    }

    private unsafe List<NetworkTableEntry> GetUdp6Entries()
    {
        var entries = new List<NetworkTableEntry>();
        int bufferSize = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, false, 23, UdpTableClass.OwnerPidTable);

        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            var result = GetExtendedUdpTable(buffer, ref bufferSize, true, 23, UdpTableClass.OwnerPidTable);
            if (result != 0) return entries;

            var numEntries = *(int*)buffer;
            var rowPtr = (byte*)buffer + 4;

            for (int i = 0; i < numEntries; i++)
            {
                // MIB_UDP6ROW_OWNER_PID layout:
                // offset 0: localAddr (16 bytes)
                // offset 16: localScopeId (4 bytes)
                // offset 20: localPort (4 bytes)
                // offset 24: owningPid (4 bytes)
                // Row size = 28 bytes

                var localBytes = new byte[16];
                Marshal.Copy((IntPtr)rowPtr, localBytes, 0, 16);
                var localScopeId = *(uint*)(rowPtr + 16);
                var localPortVal = *(uint*)(rowPtr + 20);
                var owningPid = *(uint*)(rowPtr + 24);

                IPAddress localAddr = new IPAddress(localBytes, localScopeId);
                entries.Add(new NetworkTableEntry
                {
                    Id = HashIds(Protocol.UDP, localAddr, localPortVal, IPAddress.IPv6None, 0),
                    Protocol = NetworkProtocol.UDP,
                    LocalAddress = localAddr,
                    LocalPort = PortNetToHost(localPortVal),
                    LocalScope = GetIpScope(localAddr),
                    RemoteAddress = IPAddress.IPv6None,
                    RemotePort = 0,
                    RemoteScope = IpScope.Internet,
                    TcpState = TcpStateMonitoring.Unknown,
                    ProcessId = owningPid
                });
                rowPtr += 28;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        return entries;
    }

    //  Adapter monitoring ─

    private void UpdateAdapters()
    {
        try
        {
            var currentAdapters = GetCurrentAdapters();
            var args = new NetworkAdaptersChangedEventArgs();

            // Find removed
            foreach (var existing in _adapters)
            {
                if (!currentAdapters.Any(a => a.Name == existing.Name))
                    args.Removed.Add(existing);
            }

            // Find added and DNS-changed
            foreach (var current in currentAdapters)
            {
                var existing = _adapters.FirstOrDefault(a => a.Name == current.Name);
                if (existing is null)
                {
                    args.Added.Add(current);
                }
                else
                {
                    var oldDns = string.Join(",", existing.DnsServers.Select(d => d.ToString()));
                    var newDns = string.Join(",", current.DnsServers.Select(d => d.ToString()));
                    if (oldDns != newDns)
                        args.DnsChanged.Add(current);
                }
            }

            if (args.Added.Count > 0 || args.Removed.Count > 0 || args.DnsChanged.Count > 0)
            {
                _adapters.Clear();
                _adapters.AddRange(currentAdapters);
                AdaptersChanged?.Invoke(this, args);
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"UpdateAdapters: {ex.Message}");
        }
    }

    private static List<NetworkAdapterInfo> GetCurrentAdapters()
    {
        var adapters = new List<NetworkAdapterInfo>();

        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                var ipProps = ni.GetIPProperties();
                adapters.Add(new NetworkAdapterInfo
                {
                    Name = ni.Name,
                    Description = ni.Description,
                    Status = ni.OperationalStatus,
                    Speed = ni.Speed,
                    DnsServers = ipProps.DnsAddresses?.ToList() ?? new List<IPAddress>(),
                    UnicastAddresses = ipProps.UnicastAddresses?.ToList() ?? new List<UnicastIPAddressInformation>(),
                    IsDefaultGateway = ipProps.GatewayAddresses?.Count > 0
                });
            }
        }
        catch { }

        return adapters;
    }

    //  Helpers 

    private static ushort PortNetToHost(uint netPort)
    {
        return (ushort)(((netPort & 0xFF) << 8) | ((netPort >> 8) & 0xFF));
    }

    private static long HashIds(Protocol proto, IPAddress localAddr, uint localPort, IPAddress remoteAddr, uint remotePort)
    {
        var hash = proto.GetHashCode();
        hash = hash * 397 ^ localAddr.GetHashCode();
        hash = hash * 397 ^ localPort.GetHashCode();
        hash = hash * 397 ^ remoteAddr.GetHashCode();
        hash = hash * 397 ^ remotePort.GetHashCode();
        return hash & 0x7FFFFFFFFFFFFFFF; // Ensure positive
    }

    private static long HashIds(Protocol proto, uint localAddr, uint localPort, uint remoteAddr, uint remotePort)
    {
        var hash = proto.GetHashCode();
        hash = hash * 397 ^ (int)localAddr;
        hash = hash * 397 ^ (int)localPort;
        hash = hash * 397 ^ (int)remoteAddr;
        hash = hash * 397 ^ (int)remotePort;
        return hash & 0x7FFFFFFFFFFFFFFF;
    }

    private static unsafe byte[] ToByteArray(byte* fixedBuffer)
    {
        var result = new byte[16];
        for (int i = 0; i < 16; i++)
            result[i] = fixedBuffer[i];
        return result;
    }

    private enum Protocol
    {
        TCP = 6,
        UDP = 17
    }

    public void Dispose()
    {
        Stop();
    }
}
