using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Heco.WinDivert.Filtering;
using Heco.WinDivert.Models;
using Heco.WinDivert.Structs;
using Heco.WinDivert.Interop;
using Heco.WinDivert.Services;
using Heco.WinDivert.Packet;
using Heco.WinDivert.StreamReassembly;


namespace Heco.WinDivert.Filtering;

/// <summary>
/// Main packet filtering engine integrating WinDivert capture, stream reassembly,
/// HTTP/HTTPS inspection, and packet modification capabilities.
/// Supports Network, Flow, Socket, and Reflect layers.
/// </summary>
public sealed class WinDivertFilterEngine : IDisposable
{
    private readonly TcpStreamReassembler _streamReassembler;
    private readonly FilterRuleSet _rules;
    private readonly CancellationTokenSource _cts = new();
    private Task? _processingTask;
    private IntPtr _handle = IntPtr.Zero;
    private bool _isRunning;
    private bool _disposed;
    private short _priority = 1000;
    private WinDivertLayer _currentLayer = WinDivertLayer.Network;
    private WinDivertFlag _currentFlags = WinDivertFlag.Sniff | WinDivertFlag.RecvOnly;
    private string _currentFilter = "true";

    // Statistics
    private long _packetsProcessed;
    private long _packetsModified;
    private long _packetsBlocked;
    private long _packetsRedirected;
    private long _httpRequestsInspected;
    private long _flowEstablished;
    private long _flowDeleted;
    private long _socketEvents;
    private long _errors;

    // Callbacks
    public event Action<PacketEventArgs>? PacketProcessed;
    public event Action<HttpRequestEventArgs>? HttpRequestDetected;
    public event Action<FilterStatsEventArgs>? StatsUpdated;
    public event Action<FlowEventArgs>? FlowEstablished;
    public event Action<FlowEventArgs>? FlowDeleted;
    public event Action<SocketEventArgs>? SocketEvent;

    public WinDivertFilterEngine(FilterRuleSet? rules = null)
    {
        _rules = rules ?? new FilterRuleSet();
        _streamReassembler = new TcpStreamReassembler();

        // Wire up stream reassembler events
        _streamReassembler.OnHttpRequest += OnStreamHttpRequest;
    }

    /// <summary>
    /// Start the filter engine with a WinDivert filter string.
    /// </summary>
    /// <param name="filter">WinDivert filter expression (e.g., "true", "tcp", "tcp.DstPort == 80")</param>
    /// <param name="layer">WinDivert layer: Network, Forward, Flow, Socket, Reflect</param>
    /// <param name="flags">WinDivert flags (Sniff, RecvOnly, SendOnly, NoInstall, Fragments, Drop)</param>
    /// <param name="priority">Filter priority (-30000 to 30000, higher = earlier)</param>
    /// <returns>True if started successfully</returns>
    public bool Start(string filter = "true", WinDivertLayer layer = WinDivertLayer.Network,
        WinDivertFlag flags = WinDivertFlag.Sniff | WinDivertFlag.RecvOnly, short priority = 1000)
    {
        if (_isRunning) return true;
        if (_disposed) throw new ObjectDisposedException(nameof(WinDivertFilterEngine));

        // Validate layer-specific flags
        if (!ValidateLayerFlags(layer, flags))
        {
            Debug.WriteLine($"[WinDivertFilterEngine] Invalid flags for layer {layer}");
            return false;
        }

        _priority = priority;
        _currentLayer = layer;
        _currentFlags = flags;
        _currentFilter = filter;

        // Open WinDivert handle
        _handle = WinDivertNative.WinDivertOpen(filter, (int)layer, priority, (ulong)flags);
        if (_handle == IntPtr.Zero || _handle == new IntPtr(-1))
        {
            var error = Marshal.GetLastWin32Error();
            Debug.WriteLine($"[WinDivertFilterEngine] WinDivertOpen failed: {error} (0x{error:X})");
            return false;
        }

        SetDefaultQueueParams();

        _isRunning = true;
        _processingTask = Task.Run(ProcessPacketsAsync, _cts.Token);
        Debug.WriteLine($"[WinDivertFilterEngine] Started with filter: {filter}, layer: {layer}, flags: {flags}, priority: {priority}");
        return true;
    }

    /// <summary>
    /// Validate that flags are compatible with the selected layer.
    /// </summary>
    private static bool ValidateLayerFlags(WinDivertLayer layer, WinDivertFlag flags)
    {
        // Fragments only valid for Network/Forward layers
        if ((flags & WinDivertFlag.Fragments) != 0 && layer != WinDivertLayer.Network && layer != WinDivertLayer.Forward)
            return false;

        // Drop not valid for Socket/Reflect
        if ((flags & WinDivertFlag.Drop) != 0 && (layer == WinDivertLayer.Socket || layer == WinDivertLayer.Reflect))
            return false;

        return true;
    }

    /// <summary>
    /// Set default queue parameters for optimal throughput.
    /// </summary>
    private void SetDefaultQueueParams()
    {
        // Increase queue length for high throughput
        WinDivertNative.WinDivertSetParam(_handle, WinDivertParam.QueueLength, 8192);
        // 2 second queue time
        WinDivertNative.WinDivertSetParam(_handle, WinDivertParam.QueueTime, 2000);
        // 8MB queue size
        WinDivertNative.WinDivertSetParam(_handle, WinDivertParam.QueueSize, 8 * 1024 * 1024);
    }

    /// <summary>
    /// Get or set queue length (number of packets).
    /// </summary>
    public bool SetQueueLength(uint length)
    {
        if (!_isRunning) return false;
        return WinDivertNative.WinDivertSetParam(_handle, WinDivertParam.QueueLength, length);
    }

    /// <summary>
    /// Get current queue length.
    /// </summary>
    public bool GetQueueLength(out uint length)
    {
        length = 0;
        if (!_isRunning) return false;
        return WinDivertNative.WinDivertGetParam(_handle, WinDivertParam.QueueLength, out var val) && (length = (uint)val) >= 0;
    }

    /// <summary>
    /// Get or set queue time (milliseconds).
    /// </summary>
    public bool SetQueueTime(uint milliseconds)
    {
        if (!_isRunning) return false;
        return WinDivertNative.WinDivertSetParam(_handle, WinDivertParam.QueueTime, milliseconds);
    }

    /// <summary>
    /// Get current queue time.
    /// </summary>
    public bool GetQueueTime(out uint milliseconds)
    {
        milliseconds = 0;
        if (!_isRunning) return false;
        return WinDivertNative.WinDivertGetParam(_handle, WinDivertParam.QueueTime, out var val) && (milliseconds = (uint)val) >= 0;
    }

    /// <summary>
    /// Get or set queue size (bytes).
    /// </summary>
    public bool SetQueueSize(ulong size)
    {
        if (!_isRunning) return false;
        return WinDivertNative.WinDivertSetParam(_handle, WinDivertParam.QueueSize, size);
    }

    /// <summary>
    /// Get current queue size.
    /// </summary>
    public bool GetQueueSize(out ulong size)
    {
        size = 0;
        if (!_isRunning) return false;
        return WinDivertNative.WinDivertGetParam(_handle, WinDivertParam.QueueSize, out size);
    }

    /// <summary>
    /// Get WinDivert driver version.
    /// </summary>
    public Version? GetDriverVersion()
    {
        if (!_isRunning) return null;

        if (WinDivertNative.WinDivertGetParam(_handle, WinDivertParam.VersionMajor, out var major) &&
            WinDivertNative.WinDivertGetParam(_handle, WinDivertParam.VersionMinor, out var minor))
        {
            return new Version((int)major, (int)minor);
        }
        return null;
    }

    /// <summary>
    /// Stop the filter engine gracefully.
    /// </summary>
    /// <param name="graceful">If true, shutdown send/recv before closing handle</param>
    public void Stop(bool graceful = true)
    {
        if (!_isRunning) return;

        _isRunning = false;
        _cts.Cancel();

        if (_handle != IntPtr.Zero && _handle != new IntPtr(-1))
        {
            if (graceful)
            {
                // Graceful shutdown: stop receiving and sending
                WinDivertNative.WinDivertShutdown(_handle, WinDivertShutdown.Both);
            }

            WinDivertNative.WinDivertClose(_handle);
            _handle = IntPtr.Zero;
        }

        if (_processingTask != null)
        {
            try
            {
                _processingTask.Wait(TimeSpan.FromSeconds(5));
            }
            catch (AggregateException)
            {
                // Task cancelled is expected
            }
        }

        Debug.WriteLine("[WinDivertFilterEngine] Stopped");
    }

    /// <summary>
    /// Main packet processing loop.
    /// </summary>
    private async Task ProcessPacketsAsync()
    {
        var packetBuffer = new byte[65536];
        var addr = new WINDIVERT_ADDRESS();

        while (!_cts.Token.IsCancellationRequested)
        {
            try
            {
                uint packetLen = 0;
                bool result;

                if (_currentLayer == WinDivertLayer.Flow || _currentLayer == WinDivertLayer.Socket)
                {
                    // For Flow/Socket layers, use RecvEx to get full address info including events
                    uint addrLen = (uint)Marshal.SizeOf<WINDIVERT_ADDRESS>();
                    result = WinDivertNative.WinDivertRecvEx(_handle, packetBuffer, (uint)packetBuffer.Length,
                        ref packetLen, 0UL, ref addr, ref addrLen, IntPtr.Zero);
                }
                else
                {
                    result = WinDivertNative.WinDivertRecv(_handle, packetBuffer, (uint)packetBuffer.Length,
                        ref packetLen, ref addr);
                }

                if (!result)
                {
                    var error = Marshal.GetLastWin32Error();
                    if (error != 995) // ERROR_OPERATION_ABORTED
                    {
                        Debug.WriteLine($"[WinDivertFilterEngine] WinDivertRecv error: {error}");
                        Interlocked.Increment(ref _errors);
                    }
                    continue;
                }

                if (packetLen == 0) continue;

                // Handle layer-specific events (Flow, Socket, Reflect)
                if (_currentLayer == WinDivertLayer.Flow || _currentLayer == WinDivertLayer.Socket || _currentLayer == WinDivertLayer.Reflect)
                {
                    if (HandleLayerEvents(addr, packetBuffer, packetLen))
                    {
                        continue; // Event handled, no further packet processing needed
                    }
                }

                // Clone packet for processing
                var packet = new byte[packetLen];
                Array.Copy(packetBuffer, packet, packetLen);

                // Process packet
                var action = ProcessPacket(packet, packetLen, ref addr);

                // Take action based on filter decision
                uint sendLen = 0;
                switch (action)
                {
                    case FilterAction.Pass:
                        WinDivertNative.WinDivertSend(_handle, packet, packetLen, ref sendLen, ref addr);
                        break;

                    case FilterAction.Block:
                        Interlocked.Increment(ref _packetsBlocked);
                        // Drop packet (don't send)
                        break;

                    case FilterAction.Modify:
                        Interlocked.Increment(ref _packetsModified);
                        WinDivertNative.WinDivertSend(_handle, packet, packetLen, ref sendLen, ref addr);
                        break;

                    case FilterAction.Redirect:
                        Interlocked.Increment(ref _packetsRedirected);
                        WinDivertNative.WinDivertSend(_handle, packet, packetLen, ref sendLen, ref addr);
                        break;

                    case FilterAction.Inject:
                        // Custom packet already sent, drop original
                        Interlocked.Increment(ref _packetsModified);
                        break;
                }

                Interlocked.Increment(ref _packetsProcessed);

                // Raise event
                PacketProcessed?.Invoke(new PacketEventArgs
                {
                    Packet = packet,
                    Length = packetLen,
                    Address = addr,
                    Action = action,
                    Timestamp = DateTime.UtcNow
                });

                // Periodic stats update
                if ((_packetsProcessed % 1000) == 0)
                {
                    StatsUpdated?.Invoke(new FilterStatsEventArgs
                    {
                        PacketsProcessed = _packetsProcessed,
                        PacketsModified = _packetsModified,
                        PacketsBlocked = _packetsBlocked,
                        PacketsRedirected = _packetsRedirected,
                        HttpRequestsInspected = _httpRequestsInspected,
                        FlowEstablished = _flowEstablished,
                        FlowDeleted = _flowDeleted,
                        SocketEvents = _socketEvents,
                        Errors = _errors
                    });
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref _errors);
                Debug.WriteLine($"[WinDivertFilterEngine] Process error: {ex.Message}");
                await Task.Delay(10, _cts.Token);
            }
        }
    }

    /// <summary>
    /// Handle layer-specific events (Flow, Socket, Reflect).
    /// Returns true if event was handled and packet should not be processed further.
    /// </summary>
    private bool HandleLayerEvents(WINDIVERT_ADDRESS addr, byte[] packet, uint packetLen)
    {
        var layer = (WinDivertLayer)addr.Layer;
        var evt = (WinDivertEvent)addr.Event;

        if (layer == WinDivertLayer.Flow)
        {
            switch (evt)
            {
                case WinDivertEvent.FlowEstablished:
                    Interlocked.Increment(ref _flowEstablished);
                    FlowEstablished?.Invoke(new FlowEventArgs
                    {
                        EndpointId = addr.Flow_EndpointId,
                        ParentEndpointId = addr.Flow_ParentEndpointId,
                        ProcessId = addr.Flow_ProcessId,
                        LocalAddress = GetIPAddress(addr.Flow_LocalAddr0, addr.Flow_LocalAddr1, addr.Flow_LocalAddr2, addr.Flow_LocalAddr3, addr.IPv6),
                        RemoteAddress = GetIPAddress(addr.Flow_RemoteAddr0, addr.Flow_RemoteAddr1, addr.Flow_RemoteAddr2, addr.Flow_RemoteAddr3, addr.IPv6),
                        LocalPort = addr.Flow_LocalPort,
                        RemotePort = addr.Flow_RemotePort,
                        Protocol = addr.Flow_Protocol,
                        Timestamp = DateTime.UtcNow,
                        Layer = layer
                    });
                    return true;

                case WinDivertEvent.FlowDeleted:
                    Interlocked.Increment(ref _flowDeleted);
                    FlowDeleted?.Invoke(new FlowEventArgs
                    {
                        EndpointId = addr.Flow_EndpointId,
                        ParentEndpointId = addr.Flow_ParentEndpointId,
                        ProcessId = addr.Flow_ProcessId,
                        LocalAddress = GetIPAddress(addr.Flow_LocalAddr0, addr.Flow_LocalAddr1, addr.Flow_LocalAddr2, addr.Flow_LocalAddr3, addr.IPv6),
                        RemoteAddress = GetIPAddress(addr.Flow_RemoteAddr0, addr.Flow_RemoteAddr1, addr.Flow_RemoteAddr2, addr.Flow_RemoteAddr3, addr.IPv6),
                        LocalPort = addr.Flow_LocalPort,
                        RemotePort = addr.Flow_RemotePort,
                        Protocol = addr.Flow_Protocol,
                        Timestamp = DateTime.UtcNow,
                        Layer = layer
                    });
                    return true;
            }
        }
        else if (layer == WinDivertLayer.Socket)
        {
            Interlocked.Increment(ref _socketEvents);
            var socketEvt = evt switch
            {
                WinDivertEvent.SocketBind => SocketEventType.Bind,
                WinDivertEvent.SocketConnect => SocketEventType.Connect,
                WinDivertEvent.SocketListen => SocketEventType.Listen,
                WinDivertEvent.SocketAccept => SocketEventType.Accept,
                WinDivertEvent.SocketClose => SocketEventType.Close,
                _ => SocketEventType.Unknown
            };

            SocketEvent?.Invoke(new SocketEventArgs
            {
                EventType = socketEvt,
                EndpointId = addr.Socket_EndpointId,
                ParentEndpointId = addr.Socket_ParentEndpointId,
                ProcessId = addr.Socket_ProcessId,
                LocalAddress = GetIPAddress(addr.Socket_LocalAddr0, addr.Socket_LocalAddr1, addr.Socket_LocalAddr2, addr.Socket_LocalAddr3, addr.IPv6),
                RemoteAddress = GetIPAddress(addr.Socket_RemoteAddr0, addr.Socket_RemoteAddr1, addr.Socket_RemoteAddr2, addr.Socket_RemoteAddr3, addr.IPv6),
                LocalPort = addr.Socket_LocalPort,
                RemotePort = addr.Socket_RemotePort,
                Protocol = addr.Socket_Protocol,
                Timestamp = DateTime.UtcNow
            });
            return true;
        }
        else if (layer == WinDivertLayer.Reflect)
        {
            // Reflect layer events: handle open/close
            return true;
        }

        return false; // Not a layer event, process as regular packet
    }

    private static IPAddress GetIPAddress(uint a0, uint a1, uint a2, uint a3, bool ipv6)
    {
        if (ipv6)
        {
            var bytes = new byte[16];
            BitConverter.GetBytes(a0).CopyTo(bytes, 0);
            BitConverter.GetBytes(a1).CopyTo(bytes, 4);
            BitConverter.GetBytes(a2).CopyTo(bytes, 8);
            BitConverter.GetBytes(a3).CopyTo(bytes, 12);
            return new IPAddress(bytes);
        }
        else
        {
            return new IPAddress(a0);
        }
    }

    /// <summary>
    /// Process a single packet through the filter pipeline.
    /// </summary>
    private FilterAction ProcessPacket(byte[] packet, uint packetLen, ref WINDIVERT_ADDRESS addr)
    {
        try
        {
            // Parse packet headers
            var packetInfo = ParsePacket(packet, packetLen);
            if (packetInfo == null) return FilterAction.Pass;

            // Feed ALL TCP packets to stream reassembler for HTTP parsing
            if (packetInfo.Protocol == Protocol.TCP)
            {
                int ipHeaderLen = GetIpHeaderLength(packet, packetLen);
                if (ipHeaderLen > 0)
                {
                    int tcpHeaderOffset = GetTcpHeaderLength(packet, ipHeaderLen);
                    int payloadOffset = ipHeaderLen + tcpHeaderOffset;
                    int payloadLength = (int)packetLen - payloadOffset;

                    if (payloadLength > 0 && payloadOffset < packetLen)
                    {
                        _streamReassembler.ProcessPacket(packetInfo, packet, payloadOffset, payloadLength, addr.Outbound, addr);
                    }
                }
            }

            // Check rules for this packet
            var ruleMatch = _rules.Match(packetInfo, addr.Outbound);
            if (ruleMatch == null) return FilterAction.Pass;

            // Apply rule action
            return ruleMatch.Action switch
            {
                RuleAction.Permit => FilterAction.Pass,
                RuleAction.Block => FilterAction.Block,
                RuleAction.Redirect => ApplyRedirect(packet, packetLen, ruleMatch, ref addr)
                    ? FilterAction.Redirect : FilterAction.Block,
                RuleAction.Modify => ApplyModification(packet, packetLen, ruleMatch, ref addr)
                    ? FilterAction.Modify : FilterAction.Pass,
                RuleAction.Inject => ApplyInjection(packet, packetLen, ruleMatch, ref addr)
                    ? FilterAction.Inject : FilterAction.Pass,
                RuleAction.Inspect => ApplyInspection(packet, packetLen, packetInfo, ref addr)
                    ? FilterAction.Modify : FilterAction.Pass,
                _ => FilterAction.Pass
            };
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[WinDivertFilterEngine] Packet processing error: {ex.Message}");
            Interlocked.Increment(ref _errors);
            return FilterAction.Pass;
        }
    }

    /// <summary>
    /// Parse packet headers into Packet.PacketInfo.
    /// </summary>
    private Packet.PacketInfo? ParsePacket(byte[] packet, uint packetLen)
    {
        if (packetLen < 20) return null;

        try
        {
            unsafe
            {
                fixed (byte* p = packet)
                {
                    var version = packet[0] >> 4;
                    int ipHeaderLen = 0;
                    IPAddress srcIp, dstIp;
                    ushort srcPort = 0, dstPort = 0;
                    Protocol protocol = Protocol.HOPOPT;
                    byte tcpFlags = 0;

                    if (version == 4)
                    {
                        if (packetLen < 20) return null;
                        var ipv4 = (V4Header*)p;
                        ipHeaderLen = ipv4->IHL * 4;
                        srcIp = new IPAddress(new ReadOnlySpan<byte>(&ipv4->SrcAddr, 4));
                        dstIp = new IPAddress(new ReadOnlySpan<byte>(&ipv4->DstAddr, 4));
                        protocol = ipv4->Protocol;

                        if (protocol == Protocol.TCP && packetLen >= ipHeaderLen + 20)
                        {
                            var tcp = (TcpHeader*)(p + ipHeaderLen);
                            srcPort = Ntohs(tcp->SrcPort);
                            dstPort = Ntohs(tcp->DstPort);
                            tcpFlags = tcp->Flags;
                        }
                    }
                    else if (version == 6)
                    {
                        if (packetLen < 40) return null;
                        var ipv6 = (V6Header*)p;
                        ipHeaderLen = 40;
                        srcIp = new IPAddress(new ReadOnlySpan<byte>(ipv6->SrcAddr, 16));
                        dstIp = new IPAddress(new ReadOnlySpan<byte>(ipv6->DstAddr, 16));
                        protocol = ipv6->NextHdr;

                        if (protocol == Protocol.TCP && packetLen >= ipHeaderLen + 20)
                        {
                            var tcp = (TcpHeader*)(p + ipHeaderLen);
                            srcPort = Ntohs(tcp->SrcPort);
                            dstPort = Ntohs(tcp->DstPort);
                            tcpFlags = tcp->Flags;
                        }
                    }
                    else
                    {
                        return null;
                    }

                    return new Packet.PacketInfo
                    {
                        Version = (byte)version,
                        Protocol = protocol,
                        SourceAddress = srcIp,
                        DestinationAddress = dstIp,
                        SourcePort = srcPort,
                        DestinationPort = dstPort,
                        TcpFlags = tcpFlags,
                        IsTcpSyn = (tcpFlags & (byte)TcpFlag.Syn) != 0
                    };
                }
            }
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Apply redirect action - change destination IP/port.
    /// </summary>
    private bool ApplyRedirect(byte[] packet, uint packetLen, FilterRuleMatch match, ref WINDIVERT_ADDRESS addr)
    {
        if (match.RedirectTarget == null) return false;

        return PacketModifier.RedirectTcpPacket(packet, packetLen,
            match.RedirectTarget.Ip, match.RedirectTarget.Port, ref addr);
    }

    /// <summary>
    /// Apply modification action - modify packet payload.
    /// </summary>
    private bool ApplyModification(byte[] packet, uint packetLen, FilterRuleMatch match, ref WINDIVERT_ADDRESS addr)
    {
        if (match.Modification == null) return false;

        // For HTTP request modification
        if (match.Modification.Type == ModificationType.HttpRequest)
        {
            return PacketModifier.ModifyHttpRequest(packet, packetLen,
                match.Modification.ModifyFunc!, ref addr, out _);
        }

        // For generic payload tampering
        if (match.Modification.Type == ModificationType.PayloadReplace &&
            match.Modification.ReplaceData != null)
        {
            var payloadOffset = GetPayloadOffset(packet, packetLen);
            if (payloadOffset >= 0)
            {
                return PacketModifier.TamperPayload(packet, packetLen, payloadOffset,
                    match.Modification.ReplaceData, ref addr);
            }
        }

        return false;
    }

    /// <summary>
    /// Apply injection action - inject custom packet (e.g., HTTP response).
    /// </summary>
    private bool ApplyInjection(byte[] packet, uint packetLen, FilterRuleMatch match, ref WINDIVERT_ADDRESS addr)
    {
        if (match.Injection == null) return false;

        if (match.Injection.Type == InjectionType.HttpResponse)
        {
            return PacketModifier.InjectHttpResponse(packet, packetLen,
                match.Injection.HttpResponse!, ref addr, out _);
        }

        if (match.Injection.Type == InjectionType.TcpReset)
        {
            return PacketModifier.InjectTcpReset(packet, packetLen, ref addr, out _);
        }

        return false;
    }

    /// <summary>
    /// Apply deep packet inspection (HTTP/HTTPS).
    /// </summary>
    private bool ApplyInspection(byte[] packet, uint packetLen, Packet.PacketInfo info, ref WINDIVERT_ADDRESS addr)
    {
        // The stream reassembler handles HTTP parsing via callbacks
        // This method can be extended for custom inspection logic
        return false;
    }

    private int GetIpHeaderLength(byte[] packet, uint packetLen)
    {
        if (packetLen < 1) return -1;
        var version = packet[0] >> 4;
        return version == 4 ? (packet[0] & 0x0F) * 4 : version == 6 ? 40 : -1;
    }

    private int GetTcpHeaderLength(byte[] packet, int ipHeaderLen)
    {
        if (packet.Length < ipHeaderLen + 20) return 20;
        unsafe
        {
            fixed (byte* p = packet)
            {
                var tcp = (TcpHeader*)(p + ipHeaderLen);
                return (tcp->DataOffset & 0xF0) >> 2;
            }
        }
    }

    private int GetPayloadOffset(byte[] packet, uint packetLen)
    {
        if (packetLen < 1) return -1;
        var version = packet[0] >> 4;
        int ipHeaderLen = version == 4 ? (packet[0] & 0x0F) * 4 : version == 6 ? 40 : 0;
        if (ipHeaderLen <= 0 || packetLen < ipHeaderLen + 20) return -1;

        unsafe
        {
            fixed (byte* p = packet)
            {
                var tcp = (TcpHeader*)(p + ipHeaderLen);
                int tcpHeaderLen = (tcp->DataOffset & 0xF0) >> 2;
                return ipHeaderLen + tcpHeaderLen;
            }
        }
    }

    private void OnStreamHttpRequest(HttpRequestInfo request)
    {
        Interlocked.Increment(ref _httpRequestsInspected);
        HttpRequestDetected?.Invoke(new HttpRequestEventArgs
        {
            Request = request,
            Timestamp = DateTime.UtcNow
        });
    }

    private static ushort Ntohs(ushort netShort)
    {
        return (ushort)(((netShort & 0xFF) << 8) | ((netShort >> 8) & 0xFF));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        Stop();
        _streamReassembler?.Dispose();
        _cts?.Dispose();
    }

    // Properties for stats
    public long PacketsProcessed => _packetsProcessed;
    public long PacketsModified => _packetsModified;
    public long PacketsBlocked => _packetsBlocked;
    public long PacketsRedirected => _packetsRedirected;
    public long HttpRequestsInspected => _httpRequestsInspected;
    public long TotalFlowEstablished => _flowEstablished;
    public long TotalFlowDeleted => _flowDeleted;
    public long SocketEvents => _socketEvents;
    public long Errors => _errors;
    public bool IsRunning => _isRunning;
    public WinDivertLayer CurrentLayer => _currentLayer;
    public string CurrentFilter => _currentFilter;
}

/// <summary>
/// Filter action enum.
/// </summary>
public enum FilterAction
{
    Pass,
    Block,
    Modify,
    Redirect,
    Inject
}

/// <summary>
/// Filter rule action.
/// </summary>

/// <summary>
/// Modification types.
/// </summary>
public enum ModificationType
{
    HttpRequest,
    PayloadReplace,
    HeaderInject,
    HeaderRemove
}

/// <summary>
/// Injection types.
/// </summary>
public enum InjectionType
{
    HttpResponse,
    TcpReset,
    CustomPacket
}

/// <summary>
/// Redirect target.
/// </summary>
public class RedirectTarget
{
    public IPAddress Ip { get; set; } = IPAddress.Loopback;
    public ushort Port { get; set; } = 8080;
}

/// <summary>
/// Modification specification.
/// </summary>
public class ModificationSpec
{
    public ModificationType Type { get; set; }
    public Func<string, string>? ModifyFunc { get; set; }
    public byte[]? ReplaceData { get; set; }
    public string? HeaderName { get; set; }
    public string? HeaderValue { get; set; }
}

/// <summary>
/// Injection specification.
/// </summary>
public class InjectionSpec
{
    public InjectionType Type { get; set; }
    public string? HttpResponse { get; set; }
    public byte[]? CustomPacket { get; set; }
}

/// <summary>
/// Filter rule match result.
/// </summary>
public class FilterRuleMatch
{
    public RuleAction Action { get; set; }
    public RedirectTarget? RedirectTarget { get; set; }
    public ModificationSpec? Modification { get; set; }
    public InjectionSpec? Injection { get; set; }
    public string RuleName { get; set; } = "";
    public string Description { get; set; } = "";
}

/// <summary>
/// Filter rule set for matching packets.
/// </summary>
public class FilterRuleSet
{
    private readonly List<FilterRule> _rules = new();

    public void AddRule(FilterRule rule) => _rules.Add(rule);
    public void RemoveRule(string name) => _rules.RemoveAll(r => r.Name == name);
    public void Clear() => _rules.Clear();

    public FilterRuleMatch? Match(Packet.PacketInfo packet, bool outbound)
    {
        foreach (var rule in _rules.OrderBy(r => r.Priority))
        {
            if (rule.Matches(packet, outbound))
            {
                return new FilterRuleMatch
                {
                    Action = rule.Action,
                    RedirectTarget = rule.RedirectTarget,
                    Modification = rule.Modification,
                    Injection = rule.Injection,
                    RuleName = rule.Name,
                    Description = rule.Description
                };
            }
        }
        return null;
    }
}

/// <summary>
/// Individual filter rule.
/// </summary>
public class FilterRule
{
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public int Priority { get; set; } = 0;
    public RuleAction Action { get; set; } = RuleAction.Permit;
    public IPAddress? SourceIp { get; set; }
    public IPAddress? DestIp { get; set; }
    public ushort? SourcePort { get; set; }
    public ushort? DestPort { get; set; }
    public Protocol? Protocol { get; set; }
    public bool? Outbound { get; set; }
    public string? HostContains { get; set; }
    public string? UrlContains { get; set; }
    public string? ProcessName { get; set; }
    public uint? ProcessId { get; set; }
    public RedirectTarget? RedirectTarget { get; set; }
    public ModificationSpec? Modification { get; set; }
    public InjectionSpec? Injection { get; set; }

    public bool Matches(Packet.PacketInfo packet, bool outbound)
    {
        if (SourceIp != null && !packet.SourceAddress.Equals(SourceIp)) return false;
        if (DestIp != null && !packet.DestinationAddress.Equals(DestIp)) return false;
        if (SourcePort != null && packet.SourcePort != SourcePort) return false;
        if (DestPort != null && packet.DestinationPort != DestPort) return false;
        if (Protocol != null && packet.Protocol != Protocol) return false;
        if (Outbound != null && outbound != Outbound) return false;
        return true;
    }
}

/// <summary>
/// Event args for packet processed.
/// </summary>
public class PacketEventArgs : EventArgs
{
    public byte[] Packet { get; set; } = Array.Empty<byte>();
    public uint Length { get; set; }
    public WINDIVERT_ADDRESS Address { get; set; }
    public FilterAction Action { get; set; }
    public DateTime Timestamp { get; set; }
}

/// <summary>
/// Event args for HTTP request detected.
/// </summary>
public class HttpRequestEventArgs : EventArgs
{
    public HttpRequestInfo Request { get; set; } = new();
    public DateTime Timestamp { get; set; }
}

/// <summary>
/// Event args for filter statistics.
/// </summary>
public class FilterStatsEventArgs : EventArgs
{
    public long PacketsProcessed { get; set; }
    public long PacketsModified { get; set; }
    public long PacketsBlocked { get; set; }
    public long PacketsRedirected { get; set; }
    public long HttpRequestsInspected { get; set; }
    public long FlowEstablished { get; set; }
    public long FlowDeleted { get; set; }
    public long SocketEvents { get; set; }
    public long Errors { get; set; }
}

/// <summary>
/// Event args for flow events (established/deleted).
/// </summary>
public class FlowEventArgs : EventArgs
{
    public ulong EndpointId { get; set; }
    public ulong ParentEndpointId { get; set; }
    public uint ProcessId { get; set; }
    public IPAddress LocalAddress { get; set; } = IPAddress.None;
    public IPAddress RemoteAddress { get; set; } = IPAddress.None;
    public ushort LocalPort { get; set; }
    public ushort RemotePort { get; set; }
    public Protocol Protocol { get; set; }
    public DateTime Timestamp { get; set; }
    public WinDivertLayer Layer { get; set; }
}

/// <summary>
/// Socket event types.
/// </summary>
public enum SocketEventType
{
    Unknown,
    Bind,
    Connect,
    Listen,
    Accept,
    Close
}

/// <summary>
/// Event args for socket events.
/// </summary>
public class SocketEventArgs : EventArgs
{
    public SocketEventType EventType { get; set; }
    public ulong EndpointId { get; set; }
    public ulong ParentEndpointId { get; set; }
    public uint ProcessId { get; set; }
    public IPAddress LocalAddress { get; set; } = IPAddress.None;
    public IPAddress RemoteAddress { get; set; } = IPAddress.None;
    public ushort LocalPort { get; set; }
    public ushort RemotePort { get; set; }
    public Protocol Protocol { get; set; }
    public DateTime Timestamp { get; set; }
}