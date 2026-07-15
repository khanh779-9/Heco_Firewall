using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Heco.Common.Models;
using Heco.Common.Enums;
using Heco.Common.Interfaces;
using Heco.Surveillance.Native;
using Heco.WinDivert.Native;
using Heco.WinDivert.Sniffer;
using static Heco.Surveillance.Native.IpHlpApi;
using static Heco.WinDivert.Native.WinDivertStructs;

namespace Heco.Surveillance.Patrol;

/// <summary>
///   Polls the system connection table via IP Helper API and emits
///   connection-snapshot events. Runs on a background thread.
///   Monitors TCP, UDP, ARP cache, and raw non-TCP/UDP traffic.
/// </summary>
public sealed class ConnectionMonitor : IConnectionMonitor, IDisposable
{
    private readonly ConcurrentDictionary<long, ConnectionEntry> _connections = new();
    private readonly ConcurrentDictionary<long, ConnectionEntry> _rawConnections = new();
    private volatile nint _winDivertSniffHandle = IntPtr.Zero;
    private readonly object _sniffHandleLock = new();
    private readonly object _sync = new();
    private volatile bool _useApiFallback;
    private CancellationTokenSource? _cts;
    private Task? _poller;
    private bool _disposed;

    // ── Buffer pooling for IP Helper API calls ────────────────────
    private static readonly ThreadLocal<byte[]> _tableBuffer = new(() => new byte[65536]);
    private static readonly ThreadLocal<byte[]> _ipv6Buffer = new(() => new byte[65536]);

    // ── PID Resolution Cache (TTL: 2 seconds) ─────────────────────
    private static readonly ConcurrentDictionary<ushort, (uint Pid, long Timestamp)> _tcpPidCache = new();
    private static readonly ConcurrentDictionary<ushort, (uint Pid, long Timestamp)> _udpPidCache = new();
    private const long PidCacheTtlTicks = 2 * TimeSpan.TicksPerSecond; // 2 seconds

    // ── Reusable unmanaged buffer for IP Helper API ──────────────
    private static IntPtr _sharedApiBuffer = IntPtr.Zero;
    private static int _sharedApiBufferSize = 0;
    private static readonly object _apiBufferLock = new();

    private static IntPtr GetSharedApiBuffer(uint requiredSize)
    {
        lock (_apiBufferLock)
        {
            if (_sharedApiBufferSize < requiredSize)
            {
                if (_sharedApiBuffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(_sharedApiBuffer);
                _sharedApiBuffer = Marshal.AllocHGlobal((int)requiredSize);
                _sharedApiBufferSize = (int)requiredSize;
            }
            return _sharedApiBuffer;
        }
    }

    /// <summary>Fired each refresh cycle with the full snapshot.</summary>
    public event EventHandler<IReadOnlyList<ConnectionEntry>>? ConnectionsUpdated;

    /// <summary>Fired when a new connection appears.</summary>
    public event EventHandler<ConnectionEntry>? ConnectionAdded;

    /// <summary>Fired when a connection disappears.</summary>
    public event EventHandler<ConnectionEntry>? ConnectionRemoved;

    /// <summary>Fired each refresh cycle with aggregate protocol statistics.</summary>
    public event EventHandler<ProtocolStats>? StatsUpdated;

    /// <summary>Gets a value indicating whether the connection monitor is currently running.</summary>
    public bool IsRunning => _poller?.IsCompleted == false;

    /// <summary>Gets the current list of active network connections.</summary>
    public IReadOnlyList<ConnectionEntry> CurrentConnections
    {
        get
        {
            lock (_sync) { return _connections.Values.ToArray(); }
        }
    }

    /// <summary>Latest aggregate protocol statistics.</summary>
    public ProtocolStats CurrentStats { get; private set; } = new();

    /// <summary>Start the polling loop.</summary>
    public void Start(int intervalMs = 4000)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(ConnectionMonitor));
        if (IsRunning) return;

        _cts = new CancellationTokenSource();
        _useApiFallback = false;
        var token = _cts.Token;

        // Start sniffing ALL network traffic via WinDivert (passive sniff, no blocking)
        try
        {
            _winDivertSniffHandle = WinDivertNative.WinDivertOpen(
                "true",
                (int)WinDivertLayer.Network,

                priority: 0,
                flags: (ulong)WinDivertFlag.Sniff);
            if (_winDivertSniffHandle != IntPtr.Zero && _winDivertSniffHandle != new IntPtr(-1))
            {
                Task.Run(() => RunWinDivertSniffLoop(token), token);
            }
            else
            {
                _useApiFallback = true;
                System.Diagnostics.Debug.WriteLine("[ConnectionMonitor] WinDivert sniff handle invalid — falling back to IP Helper API");
            }
        }
        catch (Exception ex)
        {
            _useApiFallback = true;
            System.Diagnostics.Debug.WriteLine($"[ConnectionMonitor] WinDivert sniff failed to start: {ex.Message} — falling back to IP Helper API");
        }

        _poller = Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(intervalMs, token).ConfigureAwait(false);
                    if (token.IsCancellationRequested) break;

                    Refresh();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[ConnectionMonitor] Error: {ex.Message}");
                }
            }
        }, token);
    }

    /// <summary>Stop the polling loop.</summary>
    public void Stop()
    {
        _cts?.Cancel();
        _poller = null;

        lock (_sniffHandleLock)
        {
            var handle = _winDivertSniffHandle;
            if (handle != IntPtr.Zero && handle != new IntPtr(-1))
            {
                _winDivertSniffHandle = IntPtr.Zero;
                try { WinDivertNative.WinDivertClose(handle); }
                catch { }
            }
        }
        _rawConnections.Clear();
    }

    /// <summary>Refresh the connection table and fire events.</summary>
    private void Refresh()
    {
        var arpEntries = GetArpTable();
        var ipnet6Entries = GetIpnet6Table();
        
        // Reuse lists instead of allocating new ones each cycle
        var all = _sharedAllList;
        all.Clear();

        if (_useApiFallback)
        {
            // WinDivert unavailable — fall back to IP Helper API for TCP/UDP
            all.AddRange(GetTcpConnections());
            all.AddRange(GetUdpConnections());
            all.AddRange(GetTcp6Connections());
            all.AddRange(GetUdp6Connections());
        }
        else
        {
            // WinDivert sniff captures ALL protocols (TCP, UDP, ICMP, GRE, ESP, etc.)
            // as the primary connection source
            var now = DateTime.UtcNow;
            var expiredRawKeys = _sharedExpiredKeysList;
            expiredRawKeys.Clear();
            
            foreach (var kvp in _rawConnections)
            {
                if ((now - kvp.Value.LastSeen).TotalSeconds > 15)
                    expiredRawKeys.Add(kvp.Key);
            }
            foreach (var key in expiredRawKeys)
                _rawConnections.TryRemove(key, out _);

            all.AddRange(_rawConnections.Values);
        }

        // Add ARP + IPNET cache entries (no lifecycle tracking — snapshot only)
        all.AddRange(arpEntries);
        all.AddRange(ipnet6Entries);

        // Reuse HashSet and List instead of allocating new
        var updated = _sharedUpdatedSet;
        updated.Clear();
        foreach (var c in all)
            updated.Add(c.Id);

        var removed = _sharedRemovedList;
        removed.Clear();
        
        var newlyAdded = _sharedNewlyAddedList;
        newlyAdded.Clear();

        lock (_sync)
        {
            // Detect removed
            foreach (var kvp in _connections)
            {
                if (!updated.Contains(kvp.Key))
                    removed.Add(kvp.Value);
            }

            foreach (var r in removed)
                _connections.TryRemove(r.Id, out _);

            // Add or update
            foreach (var c in all)
            {
                if (_connections.TryGetValue(c.Id, out var existing))
                {
                    existing.LastSeen = DateTime.UtcNow;
                    existing.TcpState = c.TcpState;
                }
                else
                {
                    if (_connections.TryAdd(c.Id, c))
                        newlyAdded.Add(c);
                }
            }
        }

        // Fire events outside lock
        foreach (var r in removed)
            ConnectionRemoved?.Invoke(this, r);

        foreach (var c in newlyAdded)
            ConnectionAdded?.Invoke(this, c);

        ConnectionsUpdated?.Invoke(this, all);

        // Refresh aggregate protocol statistics
        RefreshStats();
    }

    // ── Shared reusable collections (avoid allocations per Refresh cycle) ────────
    private readonly List<ConnectionEntry> _sharedAllList = new();
    private readonly HashSet<long> _sharedUpdatedSet = new();
    private readonly List<long> _sharedExpiredKeysList = new();
    private readonly List<ConnectionEntry> _sharedRemovedList = new();
    private readonly List<ConnectionEntry> _sharedNewlyAddedList = new();

    /// <summary>Query aggregate ICMP and IP statistics from the OS.</summary>
    private void RefreshStats()
    {
        try
        {
            var stats = new ProtocolStats();

            var icmpInfo = default(IpHlpApi.MIB_ICMPINFO);
            if (IpHlpApi.GetIcmpStatistics(ref icmpInfo) == 0)
            {
                stats.IcmpInMsgs = icmpInfo.icmpInStats.dwMsgs;
                stats.IcmpInErrors = icmpInfo.icmpInStats.dwErrors;
                stats.IcmpOutMsgs = icmpInfo.icmpOutStats.dwMsgs;
                stats.IcmpOutErrors = icmpInfo.icmpOutStats.dwErrors;
                stats.IcmpEchoRecv = icmpInfo.icmpInStats.dwEchos;
                stats.IcmpEchoSent = icmpInfo.icmpOutStats.dwEchos;
                stats.IcmpDestUnreachRecv = icmpInfo.icmpInStats.dwDestUnreachs;
                stats.IcmpDestUnreachSent = icmpInfo.icmpOutStats.dwDestUnreachs;
            }

            var ipStats = default(IpHlpApi.MIB_IPSTATS);
            if (IpHlpApi.GetIpStatistics(ref ipStats) == 0)
            {
                stats.IpInReceives = ipStats.dwInReceives;
                stats.IpOutRequests = ipStats.dwOutRequests;
                stats.IpInDiscards = ipStats.dwInDiscards;
                stats.IpOutDiscards = ipStats.dwOutDiscards;
                stats.IpReassemblyOks = ipStats.dwReasmOks;
                stats.IpReassemblyFails = ipStats.dwReasmFails;
                stats.IpFragCreates = ipStats.dwFragCreates;
            }

            CurrentStats = stats;
            StatsUpdated?.Invoke(this, stats);
        }
        catch { }
    }

    /// <summary>Enumerate all TCP connections via GetExtendedTcpTable.</summary>
    private static List<ConnectionEntry> GetTcpConnections()
    {
        var result = new List<ConnectionEntry>();

        uint size = 0;
        var hr = IpHlpApi.GetExtendedTcpTable(IntPtr.Zero, ref size, false,
            (uint)System.Net.Sockets.AddressFamily.InterNetwork, IpHlpApi.TCP_TABLE_OWNER_PID_ALL, 0);
        if (hr != 0 && hr != 122) return result; // ERROR_INSUFFICIENT_BUFFER

        var ptr = GetSharedApiBuffer(size);
        try
        {
            hr = IpHlpApi.GetExtendedTcpTable(ptr, ref size, false,
                (uint)System.Net.Sockets.AddressFamily.InterNetwork, IpHlpApi.TCP_TABLE_OWNER_PID_ALL, 0);
            if (hr != 0) return result;

            var numEntries = Marshal.ReadInt32(ptr);
            var rowSize = Marshal.SizeOf<IpHlpApi.MIB_TCPROW_OWNER_PID>();

            for (var i = 0; i < numEntries; i++)
            {
                var rowPtr = ptr + 4 + i * rowSize;
                var row = Marshal.PtrToStructure<IpHlpApi.MIB_TCPROW_OWNER_PID>(rowPtr);

                var entry = MapTcpRow(row);
                if (entry != null) result.Add(entry);
            }
        }
        finally
        {
            // No FreeHGlobal - buffer is reused
        }

        return result;
    }

    /// <summary>Enumerate all UDP listeners via GetExtendedUdpTable.</summary>
    private static List<ConnectionEntry> GetUdpConnections()
    {
        var result = new List<ConnectionEntry>();

        uint size = 0;
        var hr = IpHlpApi.GetExtendedUdpTable(IntPtr.Zero, ref size, false,
            (uint)System.Net.Sockets.AddressFamily.InterNetwork, IpHlpApi.UDP_TABLE_OWNER_PID, 0);
        if (hr != 0 && hr != 122) return result;

        var ptr = GetSharedApiBuffer(size);
        try
        {
            hr = IpHlpApi.GetExtendedUdpTable(ptr, ref size, false,
                (uint)System.Net.Sockets.AddressFamily.InterNetwork, IpHlpApi.UDP_TABLE_OWNER_PID, 0);
            if (hr != 0) return result;

            var numEntries = Marshal.ReadInt32(ptr);
            var rowSize = Marshal.SizeOf<IpHlpApi.MIB_UDPROW_OWNER_PID>();

            for (var i = 0; i < numEntries; i++)
            {
                var rowPtr = ptr + 4 + i * rowSize;
                var row = Marshal.PtrToStructure<IpHlpApi.MIB_UDPROW_OWNER_PID>(rowPtr);

                var entry = MapUdpRow(row);
                if (entry != null) result.Add(entry);
            }
        }
        finally
        {
            // No FreeHGlobal - buffer is reused
        }

        return result;
    }

    private static ConnectionEntry? MapTcpRow(IpHlpApi.MIB_TCPROW_OWNER_PID row)
    {
        try
        {
            return new ConnectionEntry
            {
                Id = HashConnection(row.localAddr, row.localPort, row.remoteAddr, row.remotePort, 6),
                Protocol = NetworkProtocol.TCP,
                LocalAddress = new IPAddress((long)IPAddress.NetworkToHostOrder((int)row.localAddr)),
                LocalPort = (ushort)IPAddress.NetworkToHostOrder((short)row.localPort),
                RemoteAddress = new IPAddress((long)IPAddress.NetworkToHostOrder((int)row.remoteAddr)),
                RemotePort = (ushort)IPAddress.NetworkToHostOrder((short)row.remotePort),
                TcpState = MapTcpState(row.state),
                ProcessId = row.owningPid,
                ProcessName = ResolveProcessName(row.owningPid),
                ProcessPath = Recon.ProcessResolver.GetExecutablePath((int)row.owningPid),
                IsInbound = row.remoteAddr != 0,
                FirstSeen = DateTime.UtcNow,
                LastSeen = DateTime.UtcNow
            };
        }
        catch
        {
            return null;
        }
    }

    private static ConnectionEntry? MapUdpRow(IpHlpApi.MIB_UDPROW_OWNER_PID row)
    {
        try
        {
            return new ConnectionEntry
            {
                Id = row.localAddr ^ row.localPort ^ row.owningPid,
                Protocol = NetworkProtocol.UDP,
                LocalAddress = new IPAddress((long)IPAddress.NetworkToHostOrder((int)row.localAddr)),
                LocalPort = (ushort)IPAddress.NetworkToHostOrder((short)row.localPort),
                RemoteAddress = IPAddress.Any,
                RemotePort = 0,
                ProcessId = row.owningPid,
                ProcessName = ResolveProcessName(row.owningPid),
                ProcessPath = Recon.ProcessResolver.GetExecutablePath((int)row.owningPid),
                IsInbound = false,
                FirstSeen = DateTime.UtcNow,
                LastSeen = DateTime.UtcNow
            };
        }
        catch
        {
            return null;
        }
    }

    private static unsafe List<ConnectionEntry> GetTcp6Connections()
    {
        var result = new List<ConnectionEntry>();

        uint size = 0;
        var hr = IpHlpApi.GetExtendedTcpTable(IntPtr.Zero, ref size, false,
            23, // AF_INET6
            IpHlpApi.TCP_TABLE_OWNER_PID_ALL, 0);
        if (hr != 0 && hr != 122) return result;

        var ptr = GetSharedApiBuffer(size);
        try
        {
            hr = IpHlpApi.GetExtendedTcpTable(ptr, ref size, false,
                23, // AF_INET6
                IpHlpApi.TCP_TABLE_OWNER_PID_ALL, 0);
            if (hr != 0) return result;

            var numEntries = *(int*)ptr;
            var rowPtr = (byte*)ptr + 4;
            for (var i = 0; i < numEntries; i++)
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

                var localIp = new IPAddress(localBytes, localScopeId);
                var remoteIp = new IPAddress(remoteBytes, remoteScopeId);

                var entry = new ConnectionEntry
                {
                    Id = HashConnectionV6(localBytes, localPortVal, remoteBytes, remotePortVal, 6),
                    Protocol = NetworkProtocol.TCP,
                    LocalAddress = localIp,
                    LocalPort = (ushort)IPAddress.NetworkToHostOrder((short)localPortVal),
                    RemoteAddress = remoteIp,
                    RemotePort = (ushort)IPAddress.NetworkToHostOrder((short)remotePortVal),
                    TcpState = MapTcpState(state),
                    ProcessId = owningPid,
                    ProcessName = ResolveProcessName(owningPid),
                    ProcessPath = Recon.ProcessResolver.GetExecutablePath((int)owningPid),
                    IsInbound = !IPAddress.IsLoopback(remoteIp) && !remoteIp.Equals(IPAddress.IPv6Any),
                    FirstSeen = DateTime.UtcNow,
                    LastSeen = DateTime.UtcNow
                };

                result.Add(entry);
                rowPtr += 56;
            }
        }
        finally
        {
            // No FreeHGlobal - buffer is reused
        }

        return result;
    }

    private static unsafe List<ConnectionEntry> GetUdp6Connections()
    {
        var result = new List<ConnectionEntry>();
        var buffer = _tableBuffer.Value;

        uint size = 0;
        var hr = IpHlpApi.GetExtendedUdpTable(IntPtr.Zero, ref size, false,
            23, // AF_INET6
            IpHlpApi.UDP_TABLE_OWNER_PID, 0);
        if (hr != 0 && hr != 122) return result;

        if (size > (uint)buffer.Length)
            Array.Resize(ref buffer, (int)size);

        var ptr = Marshal.AllocHGlobal((int)size);
        try
        {
            hr = IpHlpApi.GetExtendedUdpTable(ptr, ref size, false,
                23, // AF_INET6
                IpHlpApi.UDP_TABLE_OWNER_PID, 0);
            if (hr != 0) return result;

            var numEntries = *(int*)ptr;
            var rowPtr = (byte*)ptr + 4;
            for (var i = 0; i < numEntries; i++)
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

                var localIp = new IPAddress(localBytes, localScopeId);

                long id = 17; // UDP
                foreach (var b in localBytes) id = id * 31 ^ b;
                id = id * 31 ^ localPortVal ^ owningPid;

                var entry = new ConnectionEntry
                {
                    Id = id & 0x7FFFFFFFFFFFFFFF,
                    Protocol = NetworkProtocol.UDP,
                    LocalAddress = localIp,
                    LocalPort = (ushort)IPAddress.NetworkToHostOrder((short)localPortVal),
                    RemoteAddress = IPAddress.IPv6Any,
                    RemotePort = 0,
                    ProcessId = owningPid,
                    ProcessName = ResolveProcessName(owningPid),
                    ProcessPath = Recon.ProcessResolver.GetExecutablePath((int)owningPid),
                    IsInbound = false,
                    FirstSeen = DateTime.UtcNow,
                    LastSeen = DateTime.UtcNow
                };

                result.Add(entry);
                rowPtr += 28;
            }
        }
        finally
        {
            // No FreeHGlobal - buffer is reused
        }

        return result;
    }

    // ── ARP Cache ──────────────────────────────────────────────────

    /// <summary>Enumerate the ARP cache (IP→MAC mappings via GetIpNetTable).</summary>
    private static List<ConnectionEntry> GetArpTable()
    {
        var result = new List<ConnectionEntry>();

        int size = 0;
        var hr = IpHlpApi.GetIpNetTable(IntPtr.Zero, ref size, false);
        if (hr != 0 && size == 0) return result;

        var ptr = Marshal.AllocHGlobal(size);
        try
        {
            hr = IpHlpApi.GetIpNetTable(ptr, ref size, false);
            if (hr != 0) return result;

            var numEntries = Marshal.ReadInt32(ptr);
            var rowSize = Marshal.SizeOf<IpHlpApi.MIB_IPNETROW>();

            for (var i = 0; i < numEntries; i++)
            {
                var rowPtr = ptr + 4 + i * rowSize;
                var row = Marshal.PtrToStructure<IpHlpApi.MIB_IPNETROW>(rowPtr);

                // Skip invalid entries
                if (row.dwType == IpHlpApi.MIB_IPNET_TYPE.Invalid) continue;

                var entry = MapArpRow(row);
                if (entry != null) result.Add(entry);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }

        return result;
    }

    private static ConnectionEntry? MapArpRow(IpHlpApi.MIB_IPNETROW row)
    {
        try
        {
            var ip = new IPAddress((long)IPAddress.NetworkToHostOrder((int)row.dwAddr));
            var mac = FormatMacAddress(row.bPhysAddr, row.dwPhysAddrLen);
            if (mac == null) return null;

            long id = 257; // ARP constant
            id = id * 31 ^ row.dwAddr;
            id = id * 31 ^ (uint)row.dwIndex;

            var typeName = row.dwType switch
            {
                IpHlpApi.MIB_IPNET_TYPE.Static => "Static",
                IpHlpApi.MIB_IPNET_TYPE.Dynamic => "Dynamic",
                IpHlpApi.MIB_IPNET_TYPE.Other => "Other",
                _ => "Unknown"
            };

            return new ConnectionEntry
            {
                Id = id & 0x7FFFFFFFFFFFFFFF,
                Protocol = NetworkProtocol.ARP,
                LocalAddress = ip,
                LocalPort = 0,
                LocalMacAddress = mac,
                RemoteAddress = IPAddress.Any,
                RemotePort = 0,
                ArpType = typeName,
                InterfaceIndex = row.dwIndex,
                ProcessId = 0,
                ProcessName = null,
                ProcessPath = null,
                IsInbound = false,
                FirstSeen = DateTime.UtcNow,
                LastSeen = DateTime.UtcNow
            };
        }
        catch
        {
            return null;
        }
    }

    private static string? FormatMacAddress(byte[] addr, int len)
    {
        if (addr == null || len < 1 || len > 8) return null;
        return string.Join(":", addr.Take(len).Select(b => b.ToString("X2")));
    }

    // ── IPNET (IPv6 Neighbor Cache) ───────────────────────────────

    /// <summary>Enumerate the IPv6 neighbor discovery cache via GetIpNetTable2.</summary>
    private static List<ConnectionEntry> GetIpnet6Table()
    {
        var result = new List<ConnectionEntry>();

        try
        {
            var hr = GetIpNetTable2(AF_INET6, out var tablePtr);
            if (hr != 0 || tablePtr == 0) return result;

            try
            {
                var numEntries = Marshal.ReadInt32(tablePtr);
                var rowSize = Marshal.SizeOf<MIB_IPNET_ROW2>();

                for (var i = 0; i < numEntries; i++)
                {
                    var rowPtr = tablePtr + 4 + i * rowSize;
                    var entry = MapIpnet6Row(rowPtr);
                    if (entry != null) result.Add(entry);
                }
            }
            finally
            {
                FreeMibTable(tablePtr);
            }
        }
        catch { }

        return result;
    }

    private static unsafe ConnectionEntry? MapIpnet6Row(nint rowPtr)
    {
        try
        {
            var si_family = Marshal.ReadInt16(rowPtr);
            if (si_family != AF_INET6) return null;

            var ipBytes = new byte[16];
            Marshal.Copy(rowPtr + 8, ipBytes, 0, 16);
            var ip = new IPAddress(ipBytes);

            var ifIndex = (uint)Marshal.ReadInt32(rowPtr + 24);
            var macLen = (uint)Marshal.ReadInt32(rowPtr + 36);
            if (macLen < 1) return null;

            var macBytes = new byte[Math.Min((int)macLen, 8)];
            Marshal.Copy(rowPtr + 28, macBytes, 0, macBytes.Length);
            var mac = string.Join(":", macBytes.Select(b => b.ToString("X2")));
            if (string.IsNullOrEmpty(mac)) return null;

            var state = Marshal.ReadInt32(rowPtr + 40);
            var stateName = (NL_NEIGHBOR_STATE)state switch
            {
                NL_NEIGHBOR_STATE.Reachable => "Reachable",
                NL_NEIGHBOR_STATE.Stale => "Stale",
                NL_NEIGHBOR_STATE.Delay => "Delay",
                NL_NEIGHBOR_STATE.Probe => "Probe",
                NL_NEIGHBOR_STATE.Incomplete => "Incomplete",
                NL_NEIGHBOR_STATE.Permanent => "Permanent",
                _ => "Unreachable"
            };

            long id = 258; // IPNET constant
            id = id * 31 ^ ifIndex;
            id = id * 31 ^ (uint)ip.GetAddressBytes().GetHashCode();

            return new ConnectionEntry
            {
                Id = id & 0x7FFFFFFFFFFFFFFF,
                Protocol = NetworkProtocol.IPv6_ICMP,
                LocalAddress = ip,
                LocalPort = 0,
                LocalMacAddress = mac,
                RemoteAddress = IPAddress.Any,
                RemotePort = 0,
                ArpType = stateName,
                InterfaceIndex = (int)ifIndex,
                ProcessId = 0,
                ProcessName = null,
                ProcessPath = null,
                IsInbound = false,
                FirstSeen = DateTime.UtcNow,
                LastSeen = DateTime.UtcNow
            };
        }
        catch
        {
            return null;
        }
    }

    // ── DNS Cache ──────────────────────────────────────────────────

    /// <summary>Query the Windows DNS client cache.</summary>
    public static List<DnsCacheEntry> GetDnsCache()
    {
        var result = new List<DnsCacheEntry>();

        try
        {
            var hr = DnsApi.DnsGetCacheDataTable(out var headPtr);
            if (hr != 0 || headPtr == 0) return result;

            var current = headPtr;
            while (current != 0)
            {
                try
                {
                    var entry = Marshal.PtrToStructure<DnsApi.DNS_CACHE_ENTRY>(current);
                    var name = DnsApi.ReadDnsEntryName(entry);
                    var addr = DnsApi.ReadDnsEntryAddress(current, entry);

                    if (!string.IsNullOrEmpty(name) && addr != null)
                    {
                        result.Add(new DnsCacheEntry
                        {
                            DomainName = name,
                            Type = entry.wType,
                            Address = addr
                        });
                    }

                    current = entry.pNext;
                }
                catch { break; }
            }

            DnsApi.DnsFree(headPtr, 0);
        }
        catch { }

        return result;
    }

    // ── DHCP Info ──────────────────────────────────────────────────

    /// <summary>Query adapter DHCP configuration via GetAdaptersAddresses.</summary>
    public static List<DhcpLeaseInfo> GetDhcpInfo()
    {
        var result = new List<DhcpLeaseInfo>();

        try
        {
            uint size = 0;
            var hr = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_MULTICAST, 0, 0, ref size);
            if (hr != 0 && hr != 122) return result;

            var ptr = Marshal.AllocHGlobal((int)size);
            try
            {
                hr = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_MULTICAST, 0, ptr, ref size);
                if (hr != 0) return result;

                var current = ptr;
                while (current != 0)
                {
                    var adapter = Marshal.PtrToStructure<IP_ADAPTER_ADDRESSES>(current);

                    IPAddress? ipv4 = null;
                    if (adapter.FirstUnicastAddress != 0)
                    {
                        var ua = adapter.FirstUnicastAddress;
                        // Read the unicast address's SOCKADDR
                        // First 8 bytes of the address structure is the SOCKADDR ptr in older structs
                        // Actually in IP_ADAPTER_UNICAST_ADDRESS_LH:
                        //   Alignment(8)
                        //   SOCKADDR union at start, so read first 8 bytes as the SOCKADDR ptr
                        var sockAddrPtr = Marshal.ReadIntPtr(ua);
                        ipv4 = ReadSockAddr(sockAddrPtr);
                    }

                    IPAddress? dhcpServer = null;
                    if (adapter.Dhcpv4Server != 0)
                    {
                        dhcpServer = ReadSockAddr(adapter.Dhcpv4Server);
                    }

                    result.Add(new DhcpLeaseInfo
                    {
                        IfIndex = adapter.IfIndex,
                        AdapterName = null, // name not included in this struct version
                        DhcpEnabled = adapter.Dhcpv4Enabled != 0,
                        DhcpServer = dhcpServer,
                        LeaseLifetime = adapter.LeaseLifetime,
                        Ipv4Address = ipv4
                    });

                    current = adapter.Next;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }
        catch { }

        return result;
    }

    /// <summary>
    ///   Copy 16 bytes from a fixed buffer field into a managed byte array.
    /// </summary>
    private static unsafe byte[] ToByteArray16(byte* fixedBuffer)
    {
        var arr = new byte[16];
        for (int i = 0; i < 16; i++)
            arr[i] = fixedBuffer[i];
        return arr;
    }

    private static ConnectionEntry? MapTcp6Row(IpHlpApi.MIB_TCP6ROW_OWNER_PID row)
    {
        try
        {
            unsafe
            {
                var localBytes = ToByteArray16(row.localAddr);
                var remoteBytes = ToByteArray16(row.remoteAddr);
                var localIp = new IPAddress(localBytes, row.localScopeId);
                var remoteIp = new IPAddress(remoteBytes, row.remoteScopeId);

                return new ConnectionEntry
                {
                    Id = HashConnectionV6(localBytes, row.localPort, remoteBytes, row.remotePort, 6),
                    Protocol = NetworkProtocol.TCP,
                    LocalAddress = localIp,
                    LocalPort = (ushort)IPAddress.NetworkToHostOrder((short)row.localPort),
                    RemoteAddress = remoteIp,
                    RemotePort = (ushort)IPAddress.NetworkToHostOrder((short)row.remotePort),
                    TcpState = MapTcpState(row.state),
                    ProcessId = row.owningPid,
                    ProcessName = ResolveProcessName(row.owningPid),
                    ProcessPath = Recon.ProcessResolver.GetExecutablePath((int)row.owningPid),
                    IsInbound = !IPAddress.IsLoopback(remoteIp) && !remoteIp.Equals(IPAddress.IPv6Any),
                    FirstSeen = DateTime.UtcNow,
                    LastSeen = DateTime.UtcNow
                };
            }
        }
        catch
        {
            return null;
        }
    }

    private static ConnectionEntry? MapUdp6Row(IpHlpApi.MIB_UDP6ROW_OWNER_PID row)
    {
        try
        {
            unsafe
            {
                var localBytes = ToByteArray16(row.localAddr);
                var localIp = new IPAddress(localBytes, row.localScopeId);
                long id = 17; // UDP
                foreach (var b in localBytes) id = id * 31 ^ b;
                id = id * 31 ^ row.localPort ^ row.owningPid;

                return new ConnectionEntry
                {
                    Id = id & 0x7FFFFFFFFFFFFFFF,
                    Protocol = NetworkProtocol.UDP,
                    LocalAddress = localIp,
                    LocalPort = (ushort)IPAddress.NetworkToHostOrder((short)row.localPort),
                    RemoteAddress = IPAddress.IPv6Any,
                    RemotePort = 0,
                    ProcessId = row.owningPid,
                    ProcessName = ResolveProcessName(row.owningPid),
                    ProcessPath = Recon.ProcessResolver.GetExecutablePath((int)row.owningPid),
                    IsInbound = false,
                    FirstSeen = DateTime.UtcNow,
                    LastSeen = DateTime.UtcNow
                };
            }
        }
        catch
        {
            return null;
        }
    }

    private static long HashConnectionV6(byte[] localAddr, uint localPort, byte[] remoteAddr, uint remotePort, byte proto)
    {
        long hash = proto;
        for (int i = 0; i < 16; i++)
        {
            hash = hash * 31 ^ localAddr[i];
            hash = hash * 31 ^ remoteAddr[i];
        }
        hash = hash * 31 ^ localPort;
        hash = hash * 31 ^ remotePort;
        return hash & 0x7FFFFFFFFFFFFFFF;
    }

    private static TcpState MapTcpState(uint state) => state switch
    {
        IpHlpApi.MIB_TCP_STATE_CLOSED     => TcpState.Closed,
        IpHlpApi.MIB_TCP_STATE_LISTEN     => TcpState.Listen,
        IpHlpApi.MIB_TCP_STATE_SYN_SENT   => TcpState.SynSent,
        IpHlpApi.MIB_TCP_STATE_SYN_RCVD   => TcpState.SynReceived,
        IpHlpApi.MIB_TCP_STATE_ESTAB      => TcpState.Established,
        IpHlpApi.MIB_TCP_STATE_FIN_WAIT1  => TcpState.FinWait1,
        IpHlpApi.MIB_TCP_STATE_FIN_WAIT2  => TcpState.FinWait2,
        IpHlpApi.MIB_TCP_STATE_CLOSE_WAIT => TcpState.CloseWait,
        IpHlpApi.MIB_TCP_STATE_CLOSING    => TcpState.Closing,
        IpHlpApi.MIB_TCP_STATE_LAST_ACK   => TcpState.LastAck,
        IpHlpApi.MIB_TCP_STATE_TIME_WAIT  => TcpState.TimeWait,
        IpHlpApi.MIB_TCP_STATE_DELETE_TCB => TcpState.DeleteTcb,
        _                                 => TcpState.Unknown
    };

    private static long HashConnection(uint localAddr, uint localPort, uint remoteAddr, uint remotePort, byte proto)
    {
        // Use a order-sensitive hash so that A:p -> B:q and B:q -> A:p produce
        // different IDs.  Rotate remote components before XORing to avoid the
        // symmetry where local ^ remote == 0.
        long hash = localAddr;
        hash = (hash << 5) | (hash >> 27); // rotate
        hash ^= localPort;
        hash = (hash << 5) | (hash >> 27);
        hash ^= remoteAddr;
        hash = (hash << 5) | (hash >> 27);
        hash ^= remotePort;
        hash = (hash << 5) | (hash >> 27);
        hash ^= (long)proto << 48;
        return hash & 0x7FFFFFFFFFFFFFFF;
    }

    private static string? ResolveProcessName(uint pid)
    {
        try
        {
            using var proc = System.Diagnostics.Process.GetProcessById((int)pid);
            return proc.ProcessName;
        }
        catch
        {
            return $"(pid:{pid})";
        }
    }

    private static void ResolveProcessInfo(uint pid, out string? name, out string? path)
    {
        try
        {
            using var proc = System.Diagnostics.Process.GetProcessById((int)pid);
            name = proc.ProcessName;
            path = Recon.ProcessResolver.GetExecutablePath((int)pid);
        }
        catch
        {
            name = $"(pid:{pid})";
            path = null;
        }
    }

    // ── WinDivert PID Resolution (port → PID lookup) ──────────────

    private static unsafe uint FindTcpPid(ushort localPort)
    {
        var now = DateTime.UtcNow.Ticks;
        if (_tcpPidCache.TryGetValue(localPort, out var cached) && now - cached.Timestamp < PidCacheTtlTicks)
            return cached.Pid;

        var pid = FindTcpPidUncached(localPort);
        _tcpPidCache[localPort] = (pid, now);
        return pid;
    }

    private static unsafe uint FindUdpPid(ushort localPort)
    {
        var now = DateTime.UtcNow.Ticks;
        if (_udpPidCache.TryGetValue(localPort, out var cached) && now - cached.Timestamp < PidCacheTtlTicks)
            return cached.Pid;

        var pid = FindUdpPidUncached(localPort);
        _udpPidCache[localPort] = (pid, now);
        return pid;
    }

    private static unsafe uint FindTcpPidUncached(ushort localPort)
    {
        uint size = 0;
        var hr = IpHlpApi.GetExtendedTcpTable(IntPtr.Zero, ref size, false,
            (uint)System.Net.Sockets.AddressFamily.InterNetwork, IpHlpApi.TCP_TABLE_OWNER_PID_ALL, 0);
        if ((hr == 0 || hr == 122) && size > 0)
        {
            var ptr = Marshal.AllocHGlobal((int)size);
            try
            {
                if (IpHlpApi.GetExtendedTcpTable(ptr, ref size, false,
                    (uint)System.Net.Sockets.AddressFamily.InterNetwork, IpHlpApi.TCP_TABLE_OWNER_PID_ALL, 0) == 0)
                {
                    var numEntries = *(int*)ptr;
                    var rows = (IpHlpApi.MIB_TCPROW_OWNER_PID*)((byte*)ptr + 4);
                    for (var i = 0; i < numEntries; i++)
                    {
                        var port = (ushort)IPAddress.NetworkToHostOrder((short)rows[i].localPort);
                        if (port == localPort)
                            return rows[i].owningPid;
                    }
                }
            }
            finally { Marshal.FreeHGlobal(ptr); }
        }

        // IPv6
        size = 0;
        hr = IpHlpApi.GetExtendedTcpTable(IntPtr.Zero, ref size, false, 23, IpHlpApi.TCP_TABLE_OWNER_PID_ALL, 0);
        if ((hr == 0 || hr == 122) && size > 0)
        {
            var ptr = Marshal.AllocHGlobal((int)size);
            try
            {
                if (IpHlpApi.GetExtendedTcpTable(ptr, ref size, false, 23, IpHlpApi.TCP_TABLE_OWNER_PID_ALL, 0) == 0)
                {
                    var numEntries = *(int*)ptr;
                    var rowPtr = (byte*)ptr + 4;
                    for (var i = 0; i < numEntries; i++)
                    {
                        var portVal = *(uint*)(rowPtr + 20);
                        var port = (ushort)IPAddress.NetworkToHostOrder((short)portVal);
                        var owningPid = *(uint*)(rowPtr + 52);
                        if (port == localPort)
                            return owningPid;
                        rowPtr += 56;
                    }
                }
            }
            finally { Marshal.FreeHGlobal(ptr); }
        }
        return 0;
    }

    private static unsafe uint FindUdpPidUncached(ushort localPort)
    {
        uint size = 0;
        var hr = IpHlpApi.GetExtendedUdpTable(IntPtr.Zero, ref size, false,
            (uint)System.Net.Sockets.AddressFamily.InterNetwork, IpHlpApi.UDP_TABLE_OWNER_PID, 0);
        if ((hr == 0 || hr == 122) && size > 0)
        {
            var ptr = Marshal.AllocHGlobal((int)size);
            try
            {
                if (IpHlpApi.GetExtendedUdpTable(ptr, ref size, false,
                    (uint)System.Net.Sockets.AddressFamily.InterNetwork, IpHlpApi.UDP_TABLE_OWNER_PID, 0) == 0)
                {
                    var numEntries = *(int*)ptr;
                    var rowPtr = (byte*)ptr + 4;
                    for (var i = 0; i < numEntries; i++)
                    {
                        var portVal = *(uint*)(rowPtr + 20);
                        var port = (ushort)IPAddress.NetworkToHostOrder((short)portVal);
                        var owningPid = *(uint*)(rowPtr + 24);
                        if (port == localPort)
                            return owningPid;
                        rowPtr += 28;
                    }
                }
            }
            finally { Marshal.FreeHGlobal(ptr); }
        }

        // IPv6
        size = 0;
        hr = IpHlpApi.GetExtendedUdpTable(IntPtr.Zero, ref size, false, 23, IpHlpApi.UDP_TABLE_OWNER_PID, 0);
        if ((hr == 0 || hr == 122) && size > 0)
        {
            var ptr = Marshal.AllocHGlobal((int)size);
            try
            {
                if (IpHlpApi.GetExtendedUdpTable(ptr, ref size, false, 23, IpHlpApi.UDP_TABLE_OWNER_PID, 0) == 0)
                {
                    var numEntries = *(int*)ptr;
                    var rowPtr = (byte*)ptr + 4;
                    for (var i = 0; i < numEntries; i++)
                    {
                        var portVal = *(uint*)(rowPtr + 20);
                        var port = (ushort)IPAddress.NetworkToHostOrder((short)portVal);
                        var owningPid = *(uint*)(rowPtr + 24);
                        if (port == localPort)
                            return owningPid;
                        rowPtr += 28;
                    }
                }
            }
            finally { Marshal.FreeHGlobal(ptr); }
        }
        return 0;
    }

    private void RunWinDivertSniffLoop(CancellationToken token)
    {
        var buffer = new byte[65536];
        var addr = new WINDIVERT_ADDRESS();
        uint recvLen = 0;

        while (!token.IsCancellationRequested)
        {
            nint handle;
            lock (_sniffHandleLock)
            {
                handle = _winDivertSniffHandle;
            }
            if (handle == IntPtr.Zero || handle == new IntPtr(-1))
            {
                _useApiFallback = true;
                break;
            }

            try
            {
                if (WinDivertNative.WinDivertRecv(handle, buffer, (uint)buffer.Length, ref recvLen, ref addr))
                {
                    if (token.IsCancellationRequested) break;

                    var packet = PacketParser.Parse(buffer, recvLen);
                    if (packet == null) continue;

                    var protocol = (NetworkProtocol)packet.Protocol;

                    var srcIp = packet.SourceAddress;
                    var dstIp = packet.DestinationAddress;

                    // Unique ID based on Protocol, SrcIP, DstIP, ports
                    byte[] srcIpBytes = srcIp.GetAddressBytes();
                    byte[] dstIpBytes = dstIp.GetAddressBytes();
                    long id = (long)packet.Protocol;
                    for (int i = 0; i < srcIpBytes.Length; i++)
                        id = id * 31 ^ srcIpBytes[i];
                    for (int i = 0; i < dstIpBytes.Length; i++)
                        id = id * 31 ^ dstIpBytes[i];
                    id = id * 31 ^ packet.SourcePort;
                    id = id * 31 ^ packet.DestinationPort;

                    // Resolve PID for TCP/UDP via port lookup (WinDivert NETWORK layer doesn't provide PID)
                    uint pid = 0;
                    string? processName = null;
                    string? processPath = null;
                    if (protocol == NetworkProtocol.TCP)
                    {
                        pid = FindTcpPid(packet.SourcePort);
                        if (pid > 0) ResolveProcessInfo(pid, out processName, out processPath);
                    }
                    else if (protocol == NetworkProtocol.UDP)
                    {
                        pid = FindUdpPid(packet.SourcePort);
                        if (pid > 0) ResolveProcessInfo(pid, out processName, out processPath);
                    }

                    // Build process name with protocol-specific info
                    string processLabel;
                    if (pid > 0 && processName != null)
                    {
                        processLabel = $"{processName} (PID:{pid})";
                    }
                    else if (protocol == NetworkProtocol.ICMP || protocol == NetworkProtocol.IPv6_ICMP)
                    {
                        processLabel = $"ICMP Type={packet.IcmpType} Code={packet.IcmpCode}";
                    }
                    else
                    {
                        processLabel = $"{protocol}";
                    }

                    var entry = new ConnectionEntry
                    {
                        Id = id & 0x7FFFFFFFFFFFFFFF,
                        Protocol = protocol,
                        LocalAddress = srcIp,
                        LocalPort = packet.SourcePort,
                        RemoteAddress = dstIp,
                        RemotePort = packet.DestinationPort,
                        TcpState = TcpState.Unknown,
                        ProcessId = pid,
                        ProcessName = processName ?? processLabel,
                        ProcessPath = processPath,
                        IsInbound = addr.Inbound,
                        FirstSeen = DateTime.UtcNow,
                        LastSeen = DateTime.UtcNow
                    };

                    _rawConnections.AddOrUpdate(id, entry, (k, existing) =>
                    {
                        existing.LastSeen = DateTime.UtcNow;
                        existing.BytesSent += packet.SourcePort > 0 ? 64u : 0u;
                        existing.BytesReceived += packet.DestinationPort > 0 ? 64u : 0u;
                        return existing;
                    });
                }
                else
                {
                    // WinDivertRecv returned false — no packet or transient error.
                    // Briefly yield to avoid a 100% CPU busy-spin.
                    System.Threading.Thread.Sleep(10);
                }
            }
            catch
            {
                System.Threading.Thread.Sleep(10);
            }
        }
    }

    /// <summary>Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        Stop();
        _cts?.Dispose();
        _disposed = true;
    }
}