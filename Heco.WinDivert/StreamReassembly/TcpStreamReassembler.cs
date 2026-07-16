using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using Heco.WinDivert.Models;
using Heco.WinDivert.Structs;
using Heco.WinDivert.Packet;


namespace Heco.WinDivert.StreamReassembly;

/// <summary>
/// TCP stream reassembly engine for HTTP Host/URL filtering.
/// Tracks bidirectional TCP streams and reassembles application-layer payloads.
/// </summary>
public sealed class TcpStreamReassembler : IDisposable
{
    private readonly ConcurrentDictionary<FlowKey, StreamState> _streams = new();
    private readonly int _maxStreamCount = 10000;
    private readonly Timer _cleanupTimer;

    // Session callbacks
    public event Action<HttpRequestInfo>? OnHttpRequest;

    public TcpStreamReassembler()
    {
        // Periodic cleanup of stale/inactive streams
        _cleanupTimer = new Timer(CleanupStaleStreams, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    /// <summary>
    /// Process a TCP packet from WinDivert. Call for every packet (inbound/outbound).
    /// </summary>
    public void ProcessPacket(PacketInfo packet, byte[] payload, int payloadOffset, int payloadLength, bool isOutbound, WINDIVERT_ADDRESS addr)
    {
        if (payloadLength == 0) return;
        if (packet.Protocol != Protocol.TCP) return;

        var key = new FlowKey(
            packet.SourceAddress, packet.SourcePort,
            packet.DestinationAddress, packet.DestinationPort,
            isOutbound
        );

        var state = _streams.GetOrAdd(key, _ => new StreamState(key));

        lock (state.SyncRoot)
        {
            if (state.IsClosed) return;

            // Track sequence numbers for reassembly
            uint seq = GetTcpSeq(payload, payloadOffset);
            uint ack = GetTcpAck(payload, payloadOffset);
            byte flags = packet.TcpFlags;

            // Handle TCP flags
            if ((flags & (byte)TcpFlag.Syn) != 0)
            {
                state.InitSeq(isOutbound ? Direction.Outbound : Direction.Inbound, seq);
            }

            if ((flags & (byte)TcpFlag.Fin) != 0 || (flags & (byte)TcpFlag.Rst) != 0)
            {
                state.MarkClosed(isOutbound ? Direction.Outbound : Direction.Inbound);
            }

            // Process payload (payloadLength == 0 already returned at entry)
            state.AppendPayload(isOutbound ? Direction.Outbound : Direction.Inbound, payload, payloadOffset, payloadLength, seq);

            // Try to parse HTTP requests from outbound stream (client -> server)
            if (isOutbound && state.TryParseHttpRequest(out var httpRequest))
            {
                httpRequest.ProcessId = GetProcessIdFromAddr(addr);
                httpRequest.Timestamp = DateTime.UtcNow;
                OnHttpRequest?.Invoke(httpRequest);
            }

            // Cleanup if both directions closed
            if (state.IsFullyClosed)
            {
                _streams.TryRemove(key, out _);
            }
        }
    }

    private static uint GetTcpSeq(byte[] buffer, int offset)
    {
        // TCP header starts at offset; seq is at offset + 4 (bytes 4-7)
        // offset is after IP header, so TCP header starts there
        return (uint)((buffer[offset + 4] << 24) | (buffer[offset + 5] << 16) | (buffer[offset + 6] << 8) | buffer[offset + 7]);
    }

    private static uint GetTcpAck(byte[] buffer, int offset)
    {
        // ACK is at offset + 8
        return (uint)((buffer[offset + 8] << 24) | (buffer[offset + 9] << 16) | (buffer[offset + 10] << 8) | buffer[offset + 11]);
    }

    private static uint GetProcessIdFromAddr(WINDIVERT_ADDRESS addr)
    {
        // FLOW layer provides PID in address; NETWORK layer doesn't
        // If using NETWORK layer, return 0 (unknown)
        if (addr.Layer == (byte)WinDivertLayer.Flow)
        {
            return addr.Flow_ProcessId;
        }
        return 0;
    }

    private void CleanupStaleStreams(object? state)
    {
        var now = DateTime.UtcNow;
        var toRemove = new List<FlowKey>();

        foreach (var kvp in _streams)
        {
            if (kvp.Value.IsStale(now) || kvp.Value.IsFullyClosed)
            {
                toRemove.Add(kvp.Key);
            }
        }

        foreach (var key in toRemove)
        {
            _streams.TryRemove(key, out _);
        }

        // Hard limit
        if (_streams.Count > _maxStreamCount)
        {
            var excess = _streams.Count - _maxStreamCount;
            foreach (var key in _streams.Keys.Take(excess))
            {
                _streams.TryRemove(key, out _);
            }
        }
    }

    public void Dispose()
    {
        _cleanupTimer?.Dispose();
        _streams.Clear();
    }

    #region Internal State

    internal enum Direction { Inbound, Outbound }

    internal sealed class StreamState
    {
        // Reassembly bookkeeping per direction. RFC 793: SYN consumes one sequence
        // number, so the first payload byte after a SYN has SEQ = ISN + 1. We store
        // expectedSeq = ISN + 1 in InitSeq so that relativeSeq for the first byte
        // of payload is 0 (matches buffer.Length on the very first segment).
        private const int MaxBufferBytes = 1 << 20;          // 1 MB per direction (contiguous)
        private const int MaxPendingSegments = 32;          // Max out-of-order segments queued per direction
        private const int MaxPendingBytes = 1 << 19;        // 512 KB pending out-of-order per direction

        public readonly FlowKey Key;
        public readonly object SyncRoot = new();

        private readonly ByteBuffer _inbound = new();
        private readonly ByteBuffer _outbound = new();

        // Out-of-order segments awaiting a gap fill. Key = relativeSeq (offset from
        // expectedSeq), Value = PendingSegment. We copy the payload slice on
        // enqueue so the caller may reuse/pool its packet buffer safely.
        private readonly Dictionary<uint, PendingSegment> _inboundPending = new();
        private readonly Dictionary<uint, PendingSegment> _outboundPending = new();

        private uint? _inboundSeqStart;
        private uint? _outboundSeqStart;
        private bool _inboundClosed;
        private bool _outboundClosed;
        private DateTime _lastActivity = DateTime.UtcNow;
        private int _inboundPendingBytes;
        private int _outboundPendingBytes;

        public bool InboundClosed => _inboundClosed;
        public bool OutboundClosed => _outboundClosed;
        public bool IsClosed => _inboundClosed && _outboundClosed;
        public bool IsFullyClosed => _inboundClosed && _outboundClosed;

        public StreamState(FlowKey key)
        {
            Key = key;
        }

        public void InitSeq(Direction dir, uint seq)
        {
            // SYN consumes one sequence number (RFC 793 §3.3). The first payload
            // byte arrives with SEQ = ISN + 1, so we anchor expectedSeq there.
            // uint arithmetic handles 32-bit sequence wraparound correctly.
            if (dir == Direction.Inbound)
                _inboundSeqStart ??= seq + 1u;
            else
                _outboundSeqStart ??= seq + 1u;
        }

        public void AppendPayload(Direction dir, byte[] data, int offset, int length, uint seq)
        {
            if (length <= 0) return;

            var buffer = dir == Direction.Inbound ? _inbound : _outbound;
            var pending = dir == Direction.Inbound ? _inboundPending : _outboundPending;
            ref int pendingBytes = ref (dir == Direction.Inbound ? ref _inboundPendingBytes : ref _outboundPendingBytes);
            var expectedSeq = dir == Direction.Inbound ? _inboundSeqStart : _outboundSeqStart;

            if (!expectedSeq.HasValue)
            {
                // No SYN observed yet — we cannot anchor this segment. Flush it
                // directly so HTTP parsing still has a best-effort chance instead
                // of dropping the entire flow (rare: SYN was missed).
                buffer.Append(data, offset, length);
                _lastActivity = DateTime.UtcNow;
                CapBuffer(buffer);
                return;
            }

            // Unsigned subtraction yields correct wraparound distance for any
            // uint seq + uint expectedSeq pair (modular arithmetic).
            uint relativeSeq = seq - expectedSeq.Value;

            // Reject segments that are entirely before the contiguous prefix —
            // pure retransmits already absorbed into the buffer. (A non-empty
            // overlap with the prefix is rare and is handled by the partial
            // overlap adjustment below.)
            if ((int)relativeSeq < buffer.Length && (int)relativeSeq + length <= buffer.Length)
            {
                // Entirely duplicate retransmit — ignore.
                return;
            }

            if ((int)relativeSeq == buffer.Length)
            {
                // In-order: append directly to the contiguous buffer, then
                // opportunistically drain any queued segments that now connect.
                buffer.Append(data, offset, length);
                DrainPending(buffer, pending, ref pendingBytes);
            }
            else
            {
                // Out-of-order: spool for later merge. Trim any overlap with
                // the contiguous prefix so the stored slice starts exactly at
                // the gap.
                int overlap = buffer.Length - (int)relativeSeq;
                int storeOffset = offset;
                int storeLength = length;
                if (overlap > 0)
                {
                    storeOffset += overlap;
                    storeLength -= overlap;
                    if (storeLength <= 0) return; // fully absorbed by prefix
                    relativeSeq = (uint)buffer.Length;
                }

                EnqueuePending(pending, ref pendingBytes, relativeSeq, data, storeOffset, storeLength);
            }

            _lastActivity = DateTime.UtcNow;
            CapBuffer(buffer);
        }

        private void DrainPending(
            ByteBuffer buffer,
            Dictionary<uint, PendingSegment> pending,
            ref int pendingBytes)
        {
            // Repeatedly merge queued segments whose relativeSeq now equals the
            // contiguous buffer length. Loop handles the case where merging one
            // segment closes a gap that the next queued segment was waiting on.
            while (pending.TryGetValue((uint)buffer.Length, out var seg))
            {
                pending.Remove((uint)buffer.Length);
                pendingBytes -= seg.Length;
                buffer.Append(seg.Data, seg.Offset, seg.Length);
            }

            // Also collapse any segment that now overlaps the prefix (a queued
            // segment whose stored offset was recorded relative to an old gap
            // might be a retransmit that now starts before buffer.Length).
            if (pending.Count == 0) return;
            var keysToRemove = new List<uint>();
            foreach (var kvp in pending)
            {
                int rel = (int)kvp.Key;
                if (rel <= buffer.Length && rel + kvp.Value.Length <= buffer.Length)
                {
                    // Entirely absorbed by the contiguous prefix — duplicate.
                    pendingBytes -= kvp.Value.Length;
                    keysToRemove.Add(kvp.Key);
                }
            }
            foreach (var key in keysToRemove)
                pending.Remove(key);
        }

        private void EnqueuePending(
            Dictionary<uint, PendingSegment> pending,
            ref int pendingBytes,
            uint relativeSeq,
            byte[] data,
            int offset,
            int length)
        {
            // Coalesce with an existing entry that shares the same relativeSeq
            // (the new one wins; duplicates are rare but possible under heavy
            // retransmission) and enforce capacity caps to bound memory use.
            if (pending.Count >= MaxPendingSegments) return;
            if (pendingBytes + length > MaxPendingBytes) return;

            // Copy the slice so the caller's packet buffer can be returned to the
            // pool without aliasing the queued data.
            var slice = new byte[length];
            Array.Copy(data, offset, slice, 0, length);

            if (pending.TryGetValue(relativeSeq, out var existing))
            {
                pendingBytes -= existing.Length;
            }
            pending[relativeSeq] = new PendingSegment(slice, 0, length);
            pendingBytes += length;
        }

        private void CapBuffer(ByteBuffer buffer)
        {
            if (buffer.Length > MaxBufferBytes)
            {
                buffer.Discard(buffer.Length - MaxBufferBytes);
            }
        }

        /// <summary>
        /// Immutable slice of an out-of-order TCP segment held until its gap
        /// is filled. The byte array is owned by this segment (copied on
        /// enqueue) so the caller's packet buffer can be returned to a pool.
        /// </summary>
        private readonly struct PendingSegment
        {
            public readonly byte[] Data;
            public readonly int Offset;
            public readonly int Length;

            public PendingSegment(byte[] data, int offset, int length)
            {
                Data = data;
                Offset = offset;
                Length = length;
            }
        }

        public void MarkClosed(Direction dir)
        {
            if (dir == Direction.Inbound) _inboundClosed = true;
            else _outboundClosed = true;
        }

        public bool TryParseHttpRequest(out HttpRequestInfo request)
        {
            request = null!;
            if (_outbound.Length == 0) return false;

            var start = _outbound.FindHttpRequestStart();
            if (start < 0) return false; // No HTTP request found yet

            var end = _outbound.FindHttpRequestEnd(start);
            if (end < 0) return false; // Incomplete request

            var requestBytes = _outbound.ReadSpan(start, end - start);
            var parsed = HttpParser.ParseRequest(requestBytes, Key);

            if (parsed != null)
            {
                _outbound.Discard(end); // Consume parsed data
                request = parsed;
                return true;
            }

            return false;
        }

        public bool IsStale(DateTime now)
        {
            return (now - _lastActivity).TotalSeconds > 120; // 2 min inactivity
        }
    }

    internal sealed class ByteBuffer
    {
        private byte[] _buffer = Array.Empty<byte>();
        private int _start = 0;
        private int _length = 0;

        public int Length => _length;
        public ReadOnlySpan<byte> Span => _buffer.AsSpan(_start, _length);

        public void Append(byte[] data, int offset, int count)
        {
            EnsureCapacity(_length + count);
            Array.Copy(data, offset, _buffer, _start + _length, count);
            _length += count;
        }

        public void Discard(int count)
        {
            _start += count;
            _length -= count;
            if (_start > _buffer.Length / 2) Compact();
        }

        public ReadOnlySpan<byte> ReadSpan(int offset, int count)
        {
            return _buffer.AsSpan(_start + offset, count);
        }

        public byte[] ToArray(int offset, int count)
        {
            var result = new byte[count];
            Array.Copy(_buffer, _start + offset, result, 0, count);
            return result;
        }

        private void EnsureCapacity(int needed)
        {
            if (_buffer.Length - _start - _length >= needed) return;

            var newSize = Math.Max(_buffer.Length * 2, _start + _length + needed);
            var newBuffer = new byte[newSize];
            if (_length > 0) Array.Copy(_buffer, _start, newBuffer, 0, _length);
            _buffer = newBuffer;
            _start = 0;
        }

        private void Compact()
        {
            if (_start > 0 && _length > 0)
                Array.Copy(_buffer, _start, _buffer, 0, _length);
            _start = 0;
        }

        /// <summary>Find start of HTTP request (GET, POST, PUT, DELETE, HEAD, OPTIONS, CONNECT, TRACE, PATCH)</summary>
        public int FindHttpRequestStart()
        {
            if (_length < 4) return -1;

            // Look for HTTP method at start of buffer or after previous request
            for (int i = _start; i <= _start + _length - 4; i++)
            {
                // Check common HTTP methods
                if ((_buffer[i] == 'G' && _buffer[i+1] == 'E' && _buffer[i+2] == 'T' && _buffer[i+3] == ' ') ||   // GET
                    (_buffer[i] == 'P' && _buffer[i+1] == 'O' && _buffer[i+2] == 'S' && _buffer[i+3] == 'T') ||     // POST
                    (_buffer[i] == 'P' && _buffer[i+1] == 'U' && _buffer[i+2] == 'T' && _buffer[i+3] == ' ') ||     // PUT
                    (_buffer[i] == 'H' && _buffer[i+1] == 'E' && _buffer[i+2] == 'A' && _buffer[i+3] == 'D') ||     // HEAD
                    (_buffer[i] == 'D' && _buffer[i+1] == 'E' && _buffer[i+2] == 'L' && _buffer[i+3] == 'E') ||     // DELETE
                    (_buffer[i] == 'O' && _buffer[i+1] == 'P' && _buffer[i+2] == 'T' && _buffer[i+3] == 'I') ||     // OPTIONS
                    (_buffer[i] == 'C' && _buffer[i+1] == 'O' && _buffer[i+2] == 'N' && _buffer[i+3] == 'N') ||     // CONNECT
                    (_buffer[i] == 'T' && _buffer[i+1] == 'R' && _buffer[i+2] == 'A' && _buffer[i+3] == 'C') ||     // TRACE
                    (_buffer[i] == 'P' && _buffer[i+1] == 'A' && _buffer[i+2] == 'T' && _buffer[i+3] == 'C'))       // PATCH
                {
                    return i - _start;
                }
            }
            return -1;
        }

        /// <summary>Find end of HTTP request (double CRLF or CRLFCRLF)</summary>
        public int FindHttpRequestEnd(int startOffset)
        {
            for (int i = startOffset; i <= _length - 4; i++)
            {
                if (_buffer[_start + i] == '\r' && _buffer[_start + i + 1] == '\n' &&
                    _buffer[_start + i + 2] == '\r' && _buffer[_start + i + 3] == '\n')
                {
                    return i + 4; // End of headers
                }
                if (_buffer[_start + i] == '\n' && _buffer[_start + i + 1] == '\n')
                {
                    return i + 2; // LF-only (some clients)
                }
            }
            return -1; // Not found
        }
    }

    internal readonly struct FlowKey : IEquatable<FlowKey>
    {
        public readonly IPAddress SrcAddr;
        public readonly ushort SrcPort;
        public readonly IPAddress DstAddr;
        public readonly ushort DstPort;
        public readonly bool Outbound;

        public FlowKey(IPAddress srcAddr, ushort srcPort, IPAddress dstAddr, ushort dstPort, bool outbound)
        {
            SrcAddr = srcAddr;
            SrcPort = srcPort;
            DstAddr = dstAddr;
            DstPort = dstPort;
            Outbound = outbound;
        }

        public bool Equals(FlowKey other)
            => SrcPort == other.SrcPort && DstPort == other.DstPort && Outbound == other.Outbound
            && SrcAddr.Equals(other.SrcAddr) && DstAddr.Equals(other.DstAddr);

        public override bool Equals(object? obj) => obj is FlowKey other && Equals(other);
        public override int GetHashCode() => HashCode.Combine(SrcAddr, SrcPort, DstAddr, DstPort, Outbound);
        public static bool operator ==(FlowKey a, FlowKey b) => a.Equals(b);
        public static bool operator !=(FlowKey a, FlowKey b) => !a.Equals(b);
    }

    #endregion
}

/// <summary>
/// Parsed HTTP request information for filtering decisions.
/// </summary>
public sealed class HttpRequestInfo
{
    public string Method { get; init; } = "";
    public string Host { get; init; } = "";
    public string Url { get; init; } = "";
    public string Path { get; init; } = "";
    public string Query { get; init; } = "";
    public Dictionary<string, string> Headers { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public uint ProcessId { get; set; }
    public DateTime Timestamp { get; set; }
    public string SourceIp { get; init; } = "";
    public string DestIp { get; init; } = "";
    public ushort SourcePort { get; init; }
    public ushort DestPort { get; init; }
    public bool IsHttps => DestPort == 443 || (Headers.TryGetValue("CONNECT", out var v) && v.StartsWith("CONNECT"));

    public override string ToString() => $"{Method} {Url} [{Host}]";
}

/// <summary>
/// Minimal HTTP/1.x request parser for Host/URL extraction.
/// </summary>
internal static class HttpParser
{
    public static HttpRequestInfo? ParseRequest(ReadOnlySpan<byte> data, TcpStreamReassembler.FlowKey key)
    {
        try
        {
            var text = Encoding.ASCII.GetString(data);
            var lines = text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
            if (lines.Length == 0) return null;

            // Parse request line: METHOD PATH HTTP/VERSION
            var requestLine = lines[0].Split(' ', 3);
            if (requestLine.Length < 3) return null;

            var method = requestLine[0];
            var path = requestLine[1];
            var version = requestLine[2];

            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string host = "";

            for (int i = 1; i < lines.Length; i++)
            {
                var colon = lines[i].IndexOf(':');
                if (colon > 0)
                {
                    var name = lines[i].Substring(0, colon).Trim();
                    var value = lines[i].Substring(colon + 1).Trim();
                    headers[name] = value;
                    if (string.Equals(name, "Host", StringComparison.OrdinalIgnoreCase))
                        host = value;
                }
            }

            // Fallback: CONNECT method for HTTPS
            if (method == "CONNECT" && path.Contains(':'))
            {
                host = path.Split(':')[0];
            }

            // Parse URL
            string url;
            if (path.StartsWith("http://") || path.StartsWith("https://"))
            {
                url = path;
                var uri = new Uri(path);
                host = uri.Host;
                path = uri.AbsolutePath;
            }
            else
            {
                url = $"http://{host}{path}";
            }

            // Parse query string
            string query = "";
            var qidx = path.IndexOf('?');
            if (qidx >= 0)
            {
                query = path.Substring(qidx + 1);
                path = path.Substring(0, qidx);
            }

            return new HttpRequestInfo
            {
                Method = method,
                Host = host,
                Url = url,
                Path = path,
                Query = query,
                Headers = headers,
                SourceIp = key.SrcAddr.ToString(),
                DestIp = key.DstAddr.ToString(),
                SourcePort = key.SrcPort,
                DestPort = key.DstPort
            };
        }
        catch
        {
            return null;
        }
    }
}