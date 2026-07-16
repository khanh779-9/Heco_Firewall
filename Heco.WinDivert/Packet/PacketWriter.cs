using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Heco.WinDivert.Packet;

namespace Heco.WinDivert.Packet;

public class PacketWriter : IBufferWriter<byte>
{
    private int _index;
    private readonly WinDivertPacket _packet;

    public PacketWriter(WinDivertPacket packet, int offset)
    {
        _packet = packet;
        _index = offset;
    }

    public unsafe void WriteReverse<T>(T value) where T : unmanaged
    {
        var span = GetSpan(sizeof(T))[..sizeof(T)];
        Unsafe.WriteUnaligned(ref MemoryMarshal.GetReference(span), value);
        span.Reverse();
        Advance(sizeof(T));
    }

    public unsafe void Write<T>(T value) where T : unmanaged
    {
        var span = GetSpan(sizeof(T));
        Unsafe.WriteUnaligned(ref MemoryMarshal.GetReference(span), value);
        Advance(sizeof(T));
    }

    public void Write(ReadOnlySpan<byte> value)
    {
        value.CopyTo(GetSpan(value.Length));
        Advance(value.Length);
    }

    public void Write(byte value)
    {
        GetSpan(1)[0] = value;
        Advance(1);
    }

    public void Advance(int count)
    {
        var size = _index + count;
        _packet.Length = size;
        _index = size;
    }

    public Span<byte> GetSpan(int sizeHint = 0)
    {
        if (sizeHint <= 0)
            sizeHint = _packet.Capacity - _index;
        return _packet.GetSpan(_index, sizeHint);
    }

    public Memory<byte> GetMemory(int sizeHint)
    {
        throw new NotSupportedException();
    }
}
