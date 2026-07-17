using Microsoft.Win32.SafeHandles;
using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Heco.WinDivert.Interop;

using Heco.WinDivert.Structs;

namespace Heco.WinDivert.Packet;

[DebuggerDisplay("Length = {Length}, Capacity = {Capacity}")]
public sealed class WinDivertPacket : SafeHandleZeroOrMinusOneIsInvalid, IEquatable<WinDivertPacket>
{
    private int _length;

    public int Capacity { get; }
    public int Length
    {
        get => _length;
        set
        {
            if ((uint)value > (uint)Capacity)
                throw new ArgumentOutOfRangeException(nameof(value));
            _length = value;
        }
    }

    public unsafe Span<byte> Span => new(handle.ToPointer(), _length);

    public WinDivertPacket(int capacity = WinDivertConst.MtuMax) : base(ownsHandle: true)
    {
        Capacity = capacity;
        handle = MemoryNative.AllocZeroed(capacity);
    }

    private unsafe WinDivertPacket(IntPtr ptr, int length) : base(ownsHandle: false)
    {
        handle = ptr;
        _length = length;
        Capacity = length;
    }

    protected override bool ReleaseHandle()
    {
        MemoryNative.Free(handle);
        return true;
    }

    public void Clear()
    {
        unsafe { new Span<byte>(handle.ToPointer(), Capacity).Clear(); }
        _length = 0;
    }

    public unsafe Span<byte> GetSpan(int offset, int count)
    {
        if ((uint)offset > (uint)Capacity)
            throw new ArgumentOutOfRangeException(nameof(offset));
        if (count < 0 || Capacity - offset < count)
            throw new ArgumentOutOfRangeException(nameof(count));
        return new Span<byte>((byte*)handle + offset, count);
    }

    public unsafe WinDivertPacket Slice(int offset, int count)
    {
        if ((uint)offset > (uint)Capacity)
            throw new ArgumentOutOfRangeException(nameof(offset));
        if (count < 0 || Capacity - offset < count)
            throw new ArgumentOutOfRangeException(nameof(count));
        return new WinDivertPacket(handle + offset, count);
    }

    public PacketWriter GetWriter(int offset = 0)
    {
        return new PacketWriter(this, offset);
    }

    public WinDivertPacket Clone()
    {
        var target = new WinDivertPacket(Capacity);
        CopyTo(target);
        return target;
    }

    public void CopyTo(WinDivertPacket target)
    {
        if (target.Capacity < _length)
            throw new ArgumentOutOfRangeException(nameof(target));
        unsafe { new Span<byte>(handle.ToPointer(), _length).CopyTo(new Span<byte>(target.handle.ToPointer(), _length)); }
        target._length = _length;
    }

    public bool Equals(WinDivertPacket? other)
    {
        if (other is null) return false;
        if (_length != other._length) return false;
        return Span.SequenceEqual(other.Span);
    }

    public override bool Equals(object? obj) => Equals(obj as WinDivertPacket);
    public override int GetHashCode() => GetHashCode(0);

    // ── Checksums (copy-back to native buffer) ──

    public bool CalcChecksums(ref WINDIVERT_ADDRESS addr, ulong flags = 0)
    {
        var arr = ToArray();
        var result = WinDivertNative.WinDivertHelperCalcChecksums(arr, (uint)_length, ref addr, flags);
        if (result) CopyFromArray(arr);
        return result;
    }

    public bool CalcChecksums(ref WINDIVERT_ADDRESS addr, ChecksumsFlag flags)
    {
        var arr = ToArray();
        var result = WinDivertNative.WinDivertHelperCalcChecksums(arr, (uint)_length, ref addr, (ulong)flags);
        if (result) CopyFromArray(arr);
        return result;
    }

    // ── TTL (copy-back) ──

    public bool DecrementTTL()
    {
        var arr = ToArray();
        var result = WinDivertNative.WinDivertHelperDecrementTTL(arr, (uint)_length);
        if (result) CopyFromArray(arr);
        return result;
    }

    // ── Hash (read-only, no copy-back) ──

    public int GetHashCode(long seed)
    {
        return (int)WinDivertNative.WinDivertHelperHashPacket(ToArray(), (uint)_length, (ulong)seed);
    }

    // ── Parse (read-only) ──

    public PacketInfo? GetParseResult()
    {
        return PacketParser.Parse(ToArray(), (uint)_length);
    }

    public unsafe WinDivertParseResult? GetRichParseResult()
    {
        var buffer = ToArray();
        var length = (uint)_length;
        V4Header* v4 = null;
        V6Header* v6 = null;
        byte rawProtocol = 0;
        byte* icmp4 = null;
        byte* icmp6 = null;
        byte* tcp = null;
        byte* udp = null;
        byte* data = null;
        int dataLen = 0;
        byte* next = null;
        int nextLen = 0;

        if (WinDivertNative.WinDivertHelperParsePacket(buffer, length,
                out v4, out v6, out rawProtocol,
                out icmp4, out icmp6,
                out tcp, out udp,
                out data, out dataLen,
                out next, out nextLen))
        {
            return new WinDivertParseResult(
                v4, v6, (Protocol)rawProtocol,
                icmp4, icmp6, tcp, udp,
                data, dataLen, next, nextLen);
        }
        return null;
    }

    // ── Reverse endpoints (swap src/dst IPs and ports) ──

    public unsafe bool ReverseEndPoint()
    {
        if (_length < 1) return false;
        var ptr = (byte*)handle;
        var version = ptr[0] >> 4;

        if (version == 4)
        {
            if (_length < sizeof(V4Header)) return false;
            var ipv4 = (V4Header*)ptr;
            (ipv4->SrcAddr, ipv4->DstAddr) = (ipv4->DstAddr, ipv4->SrcAddr);
            (ipv4->SrcPort, ipv4->DstPort) = (ipv4->DstPort, ipv4->SrcPort);
            return true;
        }

        if (version == 6)
        {
            if (_length < 40 + 8) return false;
            var ipv6 = (V6Header*)ptr;
            var tmp = stackalloc byte[16];
            Buffer.MemoryCopy(ipv6->SrcAddr, tmp, 16, 16);
            Buffer.MemoryCopy(ipv6->DstAddr, ipv6->SrcAddr, 16, 16);
            Buffer.MemoryCopy(tmp, ipv6->DstAddr, 16, 16);
            (ipv6->SrcPort, ipv6->DstPort) = (ipv6->DstPort, ipv6->SrcPort);
            return true;
        }

        return false;
    }

    // ── Apply length to IP/UDP headers ──

    public unsafe int ApplyLengthToHeaders()
    {
        if (_length < 20) return 0;
        var ptr = (byte*)handle;
        var version = ptr[0] >> 4;
        int count = 0;

        if (version == 4)
        {
            var ipv4 = (V4Header*)ptr;
            ipv4->Length = (ushort)_length;
            count++;

            if (ipv4->Protocol == Protocol.UDP && _length >= (ipv4->IHL * 4 + 8))
            {
                var udpLen = (ushort*)(ptr + ipv4->IHL * 4 + 4);
                *udpLen = (ushort)(_length - ipv4->IHL * 4);
                count++;
            }
        }
        else if (version == 6)
        {
            var ipv6 = (V6Header*)ptr;
            ipv6->PayloadLength = (ushort)(_length - 40);
            count++;

            if (ipv6->NextHdr == Protocol.UDP && _length >= 48)
            {
                var udpLen = (ushort*)(ptr + 40 + 4);
                *udpLen = (ushort)(_length - 40);
                count++;
            }
        }

        return count;
    }

    // ── Recalculate Network IfIdx after address change ──

    [SupportedOSPlatform("windows")]
    public unsafe bool CalcNetworkIfIdx(ref WINDIVERT_ADDRESS addr)
    {
        if (addr.Layer != (byte)WinDivertLayer.Network) return false;
        if (!TryParseIPAddress(out _, out var dstAddr)) return false;

        addr.IfIdx = (uint)RouteResolver.GetInterfaceIndex(dstAddr);
        return true;
    }

    // ── Recalculate outbound flag after address change ──

    [SupportedOSPlatform("windows")]
    public unsafe bool CalcOutboundFlag(ref WINDIVERT_ADDRESS addr)
    {
        if (addr.Layer != (byte)WinDivertLayer.Network) return false;
        if (!TryParseIPAddress(out var srcAddr, out var dstAddr)) return false;

        var router = new RouteResolver(dstAddr, srcAddr, (int)addr.IfIdx);
        addr.Outbound = router.IsOutbound;
        return true;
    }

    // ── Recalculate loopback flag after address change ──

    public unsafe bool CalcLoopbackFlag(ref WINDIVERT_ADDRESS addr)
    {
        if (!TryParseIPAddress(out var srcAddr, out var dstAddr)) return false;

        addr.Loopback = IPAddress.IsLoopback(srcAddr) && srcAddr.Equals(dstAddr);
        return true;
    }

    // ── Internal helpers ──

    private unsafe bool TryParseIPAddress(out IPAddress srcAddr, out IPAddress dstAddr)
    {
        srcAddr = IPAddress.None;
        dstAddr = IPAddress.None;
        if (_length < 1) return false;

        var ptr = (byte*)handle;
        var version = ptr[0] >> 4;

        if (version == 4 && _length >= 20)
        {
            srcAddr = new IPAddress(new ReadOnlySpan<byte>(ptr + 12, 4));
            dstAddr = new IPAddress(new ReadOnlySpan<byte>(ptr + 16, 4));
            return true;
        }

        if (version == 6 && _length >= 40)
        {
            srcAddr = new IPAddress(new ReadOnlySpan<byte>(ptr + 8, 16));
            dstAddr = new IPAddress(new ReadOnlySpan<byte>(ptr + 24, 16));
            return true;
        }

        return false;
    }

    internal unsafe byte[] ToArray()
    {
        var arr = new byte[_length];
        Marshal.Copy(handle, arr, 0, _length);
        return arr;
    }

    internal unsafe void CopyFromArray(byte[] source)
    {
        Marshal.Copy(source, 0, handle, Math.Min(source.Length, _length));
    }
}
