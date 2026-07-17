using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Heco.WinDivert.Models;
using Heco.WinDivert.Structs;
using Heco.WinDivert.Interop;
using Heco.WinDivert.Packet;
using Heco.WinDivert.StreamReassembly;
using static Heco.WinDivert.Enums.WinDivertLayer;
using static Heco.WinDivert.Enums.WinDivertFlag;
using System.Runtime.Versioning;

namespace Heco.WinDivert.Filtering;

/// <summary>
/// Thread-safe buffer pool for reusing byte arrays in the filter loop.
/// </summary>
internal static class BufferPool
{
    private const int BufferSize = 65536;
    private static readonly ConcurrentQueue<byte[]> _pool = new();
    private static int _poolCount;

    public static byte[] Rent()
    {
        if (_pool.TryDequeue(out var buffer))
        {
            Interlocked.Decrement(ref _poolCount);
            return buffer;
        }
        return new byte[BufferSize];
    }

    public static void Return(byte[] buffer)
    {
        if (buffer.Length != BufferSize) return;
        if (Interlocked.Increment(ref _poolCount) <= 32)
            _pool.Enqueue(buffer);
    }

    /// <summary>Rent multiple buffers for batch processing.</summary>
    public static byte[][] RentBatch(int count)
    {
        var batch = new byte[count][];
        for (int i = 0; i < count; i++)
            batch[i] = Rent();
        return batch;
    }

    /// <summary>Return batch of buffers.</summary>
    public static void ReturnBatch(byte[][] buffers)
    {
        foreach (var buf in buffers)
            Return(buf);
    }
}

public struct VerdictDecision
{
    public RuleAction Action { get; set; }
    public bool ShouldCache { get; set; }

    public VerdictDecision(RuleAction action, bool shouldCache)
    {
        Action = action;
        ShouldCache = shouldCache;
    }
}

/// <summary>
///   Asynchronous packet filtering engine using WinDivert.
///   Intercepts outbound connection requests and decides whether to block or allow them in real-time.
/// </summary>
public sealed class WinDivertFilter : IDisposable
{
    /// <summary>Last Win32 error from the most recent WinDivertOpen call.</summary>
    public static int LastOpenError { get; private set; }

    private volatile nint _filterHandle = IntPtr.Zero;
    private readonly object _handleLock = new();
    private CancellationTokenSource? _cts;
    private Task? _filterTask;
    private bool _disposed;
    
    private readonly ConcurrentDictionary<string, VerdictDecision> _verdictCache = new(StringComparer.OrdinalIgnoreCase);

    private readonly ConcurrentDictionary<string, VerdictDecision> _nonTcpVerdictCache = new();

    private TcpStreamReassembler? _streamReassembler;

    private static readonly ConcurrentDictionary<ushort, (uint Pid, long Timestamp)> _tcpPidCache = new();
    private static readonly ConcurrentDictionary<ushort, (uint Pid, long Timestamp)> _udpPidCache = new();
    private const long PidCacheTtlTicks = 2 * TimeSpan.TicksPerSecond;

    private static IntPtr _sharedPidBuffer = IntPtr.Zero;
    private static int _sharedPidBufferSize = 0;
    private static readonly object _pidBufferLock = new();

    private static IntPtr GetSharedPidBuffer(uint requiredSize)
    {
        lock (_pidBufferLock)
        {
            if (_sharedPidBufferSize < requiredSize)
            {
                if (_sharedPidBuffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(_sharedPidBuffer);
                _sharedPidBuffer = Marshal.AllocHGlobal((int)requiredSize);
                _sharedPidBufferSize = (int)requiredSize;
            }
            return _sharedPidBuffer;
        }
    }

    private readonly Func<uint, string?> _processResolver;

    private readonly Func<ConnectionEntry, VerdictDecision?> _verdictChecker;

    private readonly Action<ConnectionEntry, Action<RuleAction>> _promptAction;

    private readonly Action<HttpRequestInfo, Action<RuleAction>>? _httpVerdictCallback;

    public bool IsRunning => _filterTask?.IsCompleted == false;

    public WinDivertFilter(
        Func<uint, string?> processResolver,
        Func<ConnectionEntry, VerdictDecision?> verdictChecker,
        Action<ConnectionEntry, Action<RuleAction>> promptAction)
        : this(processResolver, verdictChecker, promptAction, null)
    {
    }

    public WinDivertFilter(
        Func<uint, string?> processResolver,
        Func<ConnectionEntry, VerdictDecision?> verdictChecker,
        Action<ConnectionEntry, Action<RuleAction>> promptAction,
        Action<HttpRequestInfo, Action<RuleAction>>? httpVerdictCallback)
    {
        _processResolver = processResolver ?? throw new ArgumentNullException(nameof(processResolver));
        _verdictChecker = verdictChecker ?? throw new ArgumentNullException(nameof(verdictChecker));
        _promptAction = promptAction ?? throw new ArgumentNullException(nameof(promptAction));
        _httpVerdictCallback = httpVerdictCallback;
    }

    /// <summary>
    ///   Clear cached verdicts. Called when user rules are modified.
    /// </summary>
    public void ClearCache()
    {
        _verdictCache.Clear();
        _nonTcpVerdictCache.Clear();
    }

    /// <summary>
    ///   Start the active interception loop.
    /// </summary>
    public void Start()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(WinDivertFilter));
        if (IsRunning) return;

        if (_httpVerdictCallback != null)
        {
            _streamReassembler = new TcpStreamReassembler();
            _streamReassembler.OnHttpRequest += httpReq =>
            {
                _httpVerdictCallback(httpReq, _ => { });
            };
        }

        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        try
        {
            _filterHandle = WinDivertNative.WinDivertOpen(
                "true",
                (int)Network,
                priority: 100,
                flags: 0);

            if (_filterHandle != IntPtr.Zero && _filterHandle != new IntPtr(-1))
            {
                LastOpenError = 0;
                _filterTask = Task.Run(() => RunFilterLoop(token), token);
                Debug.WriteLine("[WinDivertFilter] Active interception loop started");
            }
            else
            {
                LastOpenError = Marshal.GetLastWin32Error();
                Debug.WriteLine($"[WinDivertFilter] WinDivertOpen failed: {LastOpenError}");
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[WinDivertFilter] Failed to start handle: {ex.Message}");
        }
    }

    /// <summary>
    ///   Stop the active interception loop.
    /// </summary>
    public void Stop()
    {
        _cts?.Cancel();

        if (_filterTask != null)
        {
            try
            {
                if (!_filterTask.Wait(TimeSpan.FromSeconds(5)))
                {
                    Debug.WriteLine("[WinDivertFilter] Filter loop did not exit within timeout");
                }
            }
            catch (AggregateException ex)
            {
                Debug.WriteLine($"[WinDivertFilter] Exception during stop: {ex.Message}");
            }
            finally
            {
                _filterTask = null;
            }
        }

        lock (_handleLock)
        {
            var handle = _filterHandle;
            if (handle != IntPtr.Zero && handle != new IntPtr(-1))
            {
                _filterHandle = IntPtr.Zero;
                try { WinDivertNative.WinDivertClose(handle); }
                catch { }
            }
        }
        _streamReassembler?.Dispose();
        _streamReassembler = null;
        _verdictCache.Clear();
        _nonTcpVerdictCache.Clear();
        Debug.WriteLine("[WinDivertFilter] Active interception loop stopped");
    }

    [SupportedOSPlatform("windows")]
    private void RunFilterLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            nint handle;
            lock (_handleLock)
            {
                handle = _filterHandle;
            }
            if (handle == IntPtr.Zero || handle == new IntPtr(-1)) break;

            try
            {
                const int batchSize = 32;
                var packets = BufferPool.RentBatch(batchSize);
                var addresses = new WINDIVERT_ADDRESS[batchSize];
                var lengths = new uint[batchSize];
                int receivedCount = 0;

                for (int i = 0; i < batchSize; i++)
                {
                    uint aLen = (uint)Marshal.SizeOf<WINDIVERT_ADDRESS>();
                    if (!WinDivertNative.WinDivertRecvEx(handle, packets[i], (uint)packets[i].Length, ref lengths[i], 0UL, ref addresses[i], ref aLen, IntPtr.Zero))
                        break;
                    if (lengths[i] == 0) break;
                    receivedCount++;
                    if (token.IsCancellationRequested) break;
                }

                if (receivedCount == 0)
                {
                    BufferPool.ReturnBatch(packets);
                    Thread.Sleep(1);
                    continue;
                }

                for (int i = 0; i < receivedCount; i++)
                {
                    if (token.IsCancellationRequested) break;

                    var packet = PacketParser.Parse(packets[i], lengths[i]);
                    if (packet == null)
                    {
                        Reinject(packets[i], lengths[i], addresses[i], token);
                        continue;
                    }

                    bool isOutbound = addresses[i].Outbound;

                    if (packet.Protocol == Protocol.TCP)
                    {
                        if (_streamReassembler != null)
                        {
                            int ipHeaderLen = GetIpHeaderLength(packets[i], lengths[i]);
                            int tcpHeaderOffset = GetTcpHeaderLength(packets[i], ipHeaderLen);
                            int payloadOffset = ipHeaderLen + tcpHeaderOffset;
                            int payloadLength = (int)lengths[i] - payloadOffset;

                            if (payloadLength > 0 && payloadOffset < lengths[i])
                            {
                                _streamReassembler.ProcessPacket(packet, packets[i], payloadOffset, payloadLength, isOutbound, addresses[i]);
                            }
                        }

                        if (!packet.IsTcpSyn)
                        {
                            Reinject(packets[i], lengths[i], addresses[i], token);
                            continue;
                        }
                        ushort lookupPort = isOutbound ? packet.SourcePort : packet.DestinationPort;
                        uint pid = FindTcpPid(lookupPort);
                        HandleTcpUdpPacket(packets[i], lengths[i], addresses[i], packet, pid, !isOutbound, token);
                    }
                    else if (packet.Protocol == Protocol.UDP)
                    {
                        ushort lookupPort = isOutbound ? packet.SourcePort : packet.DestinationPort;
                        uint pid = FindUdpPid(lookupPort);
                        HandleTcpUdpPacket(packets[i], lengths[i], addresses[i], packet, pid, !isOutbound, token);
                    }
                    else
                    {
                        HandleNonTcpUdpPacket(packets[i], lengths[i], addresses[i], packet, token);
                    }
                }
                BufferPool.ReturnBatch(packets);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[WinDivertFilter] Interception error: {ex.Message}");
                System.Threading.Thread.Sleep(10);
            }
        }
    }

    private void HandleTcpUdpPacket(byte[] buffer, uint length, WINDIVERT_ADDRESS addr, PacketInfo packet, uint pid, bool isInbound, CancellationToken token)
    {
        if (pid <= 4)
        {
            Reinject(buffer, length, addr, token);
            return;
        }

        var appPath = _processResolver(pid);
        if (string.IsNullOrEmpty(appPath))
        {
            Reinject(buffer, length, addr, token);
            return;
        }

        var cacheKey = $"{appPath}|{(isInbound ? "IN" : "OUT")}";
        if (_verdictCache.TryGetValue(cacheKey, out var cachedDecision))
        {
            if (cachedDecision.Action == RuleAction.Permit)
                Reinject(buffer, length, addr, token);
            return;
        }

        var pending = new PendingPacket(buffer, length, addr);
        var connection = new ConnectionEntry
        {
            Protocol = packet.Protocol,
            LocalAddress = isInbound ? packet.DestinationAddress : packet.SourceAddress,
            LocalPort = isInbound ? packet.DestinationPort : packet.SourcePort,
            RemoteAddress = isInbound ? packet.SourceAddress : packet.DestinationAddress,
            RemotePort = isInbound ? packet.SourcePort : packet.DestinationPort,
            ProcessId = pid,
            ProcessName = ResolveProcessName(pid),
            ProcessPath = appPath,
            IsInbound = isInbound,
            FirstSeen = DateTime.UtcNow,
            LastSeen = DateTime.UtcNow
        };

        var decision = _verdictChecker(connection);
        if (decision.HasValue)
        {
            if (decision.Value.ShouldCache)
                _verdictCache[cacheKey] = new VerdictDecision(decision.Value.Action, true);

            if (decision.Value.Action == RuleAction.Permit)
                Reinject(buffer, length, addr, token);
            pending.Dispose();
            return;
        }

        _promptAction(connection, (verdict) =>
        {
            _verdictCache[cacheKey] = new VerdictDecision(verdict, true);
            if (verdict == RuleAction.Permit)
            {
                Reinject(pending.PacketData, pending.Length, pending.Address, token);
            }
            pending.Dispose();
        });
    }

    private void HandleNonTcpUdpPacket(byte[] buffer, uint length, WINDIVERT_ADDRESS addr, PacketInfo packet, CancellationToken token)
    {
        var cacheKey = $"{(byte)packet.Protocol}:{packet.SourceAddress}:{packet.DestinationAddress}";

        if (_nonTcpVerdictCache.TryGetValue(cacheKey, out var cachedDecision))
        {
            if (cachedDecision.Action == RuleAction.Permit)
                Reinject(buffer, length, addr, token);
            return;
        }

        var connection = new ConnectionEntry
        {
            Protocol = packet.Protocol,
            LocalAddress = packet.SourceAddress,
            LocalPort = 0,
            RemoteAddress = packet.DestinationAddress,
            RemotePort = 0,
            ProcessId = 0,
            ProcessName = packet.Protocol.ToString(),
            ProcessPath = null,
            IsInbound = addr.Inbound,
            FirstSeen = DateTime.UtcNow,
            LastSeen = DateTime.UtcNow
        };

        var decision = _verdictChecker(connection);
        if (decision.HasValue)
        {
            if (decision.Value.ShouldCache)
                _nonTcpVerdictCache[cacheKey] = new VerdictDecision(decision.Value.Action, true);

            if (decision.Value.Action == RuleAction.Permit)
                Reinject(buffer, length, addr, token);
            return;
        }

        Reinject(buffer, length, addr, token);
    }

    private void Reinject(byte[] packet, uint length, WINDIVERT_ADDRESS addr, CancellationToken token)
    {
        if (_disposed || token.IsCancellationRequested) return;

        nint handle;
        lock (_handleLock)
        {
            handle = _filterHandle;
        }
        if (handle == IntPtr.Zero || handle == new IntPtr(-1)) return;

        try
        {
            uint sendLen = 0;
            WinDivertNative.WinDivertSend(handle, packet, length, ref sendLen, ref addr);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[WinDivertFilter] Reinject error: {ex.Message}");
        }
    }

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
        return FindPidInTcpTable(localPort, 2u) ?? FindPidInTcpTable(localPort, 23u) ?? 0;
    }

    private static unsafe uint FindUdpPidUncached(ushort localPort)
    {
        return FindPidInUdpTable(localPort, 2u) ?? FindPidInUdpTable(localPort, 23u) ?? 0;
    }

    private static unsafe uint? FindPidInTcpTable(ushort localPort, uint addressFamily)
    {
        uint size = 0;
        var hr = IPHelpApiNative.GetExtendedTcpTable(IntPtr.Zero, ref size, false, addressFamily, IPHelpApiNative.TCP_TABLE_OWNER_PID_ALL, 0);
        if ((hr != 0 && hr != 122) || size == 0) return null;

        var ptr = GetSharedPidBuffer(size);
        if (IPHelpApiNative.GetExtendedTcpTable(ptr, ref size, false, addressFamily, IPHelpApiNative.TCP_TABLE_OWNER_PID_ALL, 0) != 0)
            return null;

        return addressFamily == 2
            ? FindTcpPidInV4Rows(ptr, localPort)
            : FindTcpPidInV6Rows(ptr, localPort);
    }

    private static unsafe uint? FindPidInUdpTable(ushort localPort, uint addressFamily)
    {
        uint size = 0;
        var hr = IPHelpApiNative.GetExtendedUdpTable(IntPtr.Zero, ref size, false, addressFamily, IPHelpApiNative.UDP_TABLE_OWNER_PID, 0);
        if ((hr != 0 && hr != 122) || size == 0) return null;

        var ptr = GetSharedPidBuffer(size);
        if (IPHelpApiNative.GetExtendedUdpTable(ptr, ref size, false, addressFamily, IPHelpApiNative.UDP_TABLE_OWNER_PID, 0) != 0)
            return null;

        return addressFamily == 2
            ? FindUdpPidInV4Rows(ptr, localPort)
            : FindUdpPidInV6Rows(ptr, localPort);
    }

    private static unsafe uint? FindTcpPidInV4Rows(IntPtr ptr, ushort localPort)
    {
        var numEntries = *(int*)ptr;
        var rows = (IPHelpApiNative.MIB_TCPROW_OWNER_PID*)((byte*)ptr + 4);
        for (var i = 0; i < numEntries; i++)
        {
            var port = (ushort)IPAddress.NetworkToHostOrder((short)rows[i].LocalPort);
            if (port == localPort)
                return rows[i].OwningPid;
        }

        return null;
    }

    private static unsafe uint? FindTcpPidInV6Rows(IntPtr ptr, ushort localPort)
    {
        var numEntries = *(int*)ptr;
        var rows = (IPHelpApiNative.MIB_TCP6ROW_OWNER_PID*)((byte*)ptr + 4);
        for (var i = 0; i < numEntries; i++)
        {
            var port = (ushort)IPAddress.NetworkToHostOrder((short)rows[i].LocalPort);
            if (port == localPort)
                return rows[i].OwningPid;
        }

        return null;
    }

    private static unsafe uint? FindUdpPidInV4Rows(IntPtr ptr, ushort localPort)
    {
        var numEntries = *(int*)ptr;
        var rows = (IPHelpApiNative.MIB_UDPROW_OWNER_PID*)((byte*)ptr + 4);
        for (var i = 0; i < numEntries; i++)
        {
            var port = (ushort)IPAddress.NetworkToHostOrder((short)rows[i].LocalPort);
            if (port == localPort)
                return rows[i].OwningPid;
        }

        return null;
    }

    private static unsafe uint? FindUdpPidInV6Rows(IntPtr ptr, ushort localPort)
    {
        var numEntries = *(int*)ptr;
        var rows = (IPHelpApiNative.MIB_UDP6ROW_OWNER_PID*)((byte*)ptr + 4);
        for (var i = 0; i < numEntries; i++)
        {
            var port = (ushort)IPAddress.NetworkToHostOrder((short)rows[i].LocalPort);
            if (port == localPort)
                return rows[i].OwningPid;
        }

        return null;
    }

    private static string? ResolveProcessName(uint pid)
    {
        try
        {
            var process = Process.GetProcessById((int)pid);
            return process.ProcessName;
        }
        catch
        {
            return $"(pid:{pid})";
        }
    }

    private static int GetIpHeaderLength(byte[] buffer, uint length)
    {
        if (length < 1) return 0;
        var version = buffer[0] >> 4;
        return version == 4
            ? (buffer[0] & 0x0F) * 4
            : version == 6 ? 40 : 0;
    }

    private static int GetTcpHeaderLength(byte[] buffer, int ipHeaderOffset)
    {
        if (buffer.Length < ipHeaderOffset + 13) return 20;
        var dataOffset = (buffer[ipHeaderOffset + 12] >> 4) & 0x0F;
        return dataOffset * 4;
    }

    public void Dispose()
    {
        if (_disposed) return;
        Stop();
        _streamReassembler?.Dispose();
        _cts?.Dispose();
        _disposed = true;
    }
}

internal sealed class PendingPacket : IDisposable
{
    public byte[] PacketData { get; }
    public uint Length { get; }
    public WINDIVERT_ADDRESS Address;

    public PendingPacket(byte[] data, uint length, WINDIVERT_ADDRESS addr)
    {
        PacketData = BufferPool.Rent();
        Array.Copy(data, PacketData, length);
        Length = length;
        Address = addr;
    }

    public void Dispose()
    {
        BufferPool.Return(PacketData);
    }
}


