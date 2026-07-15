using System;
using Heco.WinDivert.Native;
using static Heco.WinDivert.Native.WinDivertStructs;
using Native = Heco.WinDivert.Native;

namespace Heco.WinDivert.Sniffer;

public class WinDivertPacket : IDisposable
{
    private byte[] _buffer;
    private int _length;
    private bool _disposed;

    public int Capacity { get; }

    public int Length
    {
        get => _length;
        set
        {
            if ((uint)value > (uint)Capacity)
                throw new ArgumentOutOfRangeException(nameof(Length));
            _length = value;
        }
    }

    public byte[] Buffer
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _buffer;
        }
    }

    public WinDivertPacket(int capacity = Native.WinDivertConst.MtuMax)
    {
        Capacity = capacity;
        _buffer = new byte[capacity];
        _length = 0;
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _buffer = null!;
            _length = 0;
            _disposed = true;
        }
    }

    public void Clear()
    {
        _length = 0;
    }

    public Span<byte> GetSpan(int offset, int count)
    {
        if ((uint)offset > (uint)Capacity)
            throw new ArgumentOutOfRangeException(nameof(offset));
        if (count < 0 || Capacity - offset < count)
            throw new ArgumentOutOfRangeException(nameof(count));
        return new Span<byte>(_buffer, offset, count);
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
            throw new ArgumentOutOfRangeException(nameof(target), "Target capacity is too small");
        Array.Copy(_buffer, target._buffer, _length);
        target._length = _length;
    }

    public bool CalcChecksums(ref WINDIVERT_ADDRESS addr, ulong flags = 0)
    {
        return WinDivertNative.WinDivertHelperCalcChecksums(_buffer, (uint)_length, ref addr, flags);
    }

    public bool CalcChecksums(ref WINDIVERT_ADDRESS addr, ChecksumsFlag flags)
    {
        return WinDivertNative.WinDivertHelperCalcChecksums(_buffer, (uint)_length, ref addr, (ulong)flags);
    }

    public bool DecrementTTL()
    {
        return WinDivertNative.WinDivertHelperDecrementTTL(_buffer, (uint)_length);
    }

    public ulong HashPacket(ulong seed)
    {
        return WinDivertNative.WinDivertHelperHashPacket(_buffer, (uint)_length, seed);
    }

    public PacketInfo? GetParseResult()
    {
        return PacketParser.Parse(_buffer, (uint)_length);
    }

    public unsafe WinDivertParseResult? GetRichParseResult()
    {
        return WinDivertNative.ParsePacket(_buffer, (uint)_length);
    }
}
