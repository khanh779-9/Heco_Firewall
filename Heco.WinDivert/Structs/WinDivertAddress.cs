using System.Runtime.InteropServices;

namespace Heco.WinDivert.Structs;

[StructLayout(LayoutKind.Explicit, Size = 80)]
public unsafe struct WINDIVERT_ADDRESS
{
    [FieldOffset(0)]  public long Timestamp;
    [FieldOffset(8)]  public uint FlagsBitfield;
    [FieldOffset(12)] public uint Reserved1;
    [FieldOffset(16)] public fixed byte Reserved3[64];

    [FieldOffset(16)] public uint IfIdx;
    [FieldOffset(20)] public uint SubIfIdx;

    [FieldOffset(16)] public ulong Flow_EndpointId;
    [FieldOffset(24)] public ulong Flow_ParentEndpointId;
    [FieldOffset(32)] public uint  Flow_ProcessId;
    [FieldOffset(36)] public uint  Flow_LocalAddr0;
    [FieldOffset(40)] public uint  Flow_LocalAddr1;
    [FieldOffset(44)] public uint  Flow_LocalAddr2;
    [FieldOffset(48)] public uint  Flow_LocalAddr3;
    [FieldOffset(52)] public uint  Flow_RemoteAddr0;
    [FieldOffset(56)] public uint  Flow_RemoteAddr1;
    [FieldOffset(60)] public uint  Flow_RemoteAddr2;
    [FieldOffset(64)] public uint  Flow_RemoteAddr3;
    [FieldOffset(68)] public ushort Flow_LocalPort;
    [FieldOffset(70)] public ushort Flow_RemotePort;
    [FieldOffset(72)] public Protocol Flow_Protocol;

    [FieldOffset(16)] public ulong Socket_EndpointId;
    [FieldOffset(24)] public ulong Socket_ParentEndpointId;
    [FieldOffset(32)] public uint  Socket_ProcessId;
    [FieldOffset(36)] public uint  Socket_LocalAddr0;
    [FieldOffset(40)] public uint  Socket_LocalAddr1;
    [FieldOffset(44)] public uint  Socket_LocalAddr2;
    [FieldOffset(48)] public uint  Socket_LocalAddr3;
    [FieldOffset(52)] public uint  Socket_RemoteAddr0;
    [FieldOffset(56)] public uint  Socket_RemoteAddr1;
    [FieldOffset(60)] public uint  Socket_RemoteAddr2;
    [FieldOffset(64)] public uint  Socket_RemoteAddr3;
    [FieldOffset(68)] public ushort Socket_LocalPort;
    [FieldOffset(70)] public ushort Socket_RemotePort;
    [FieldOffset(72)] public Protocol Socket_Protocol;

    [FieldOffset(16)] public long   Reflect_Timestamp;
    [FieldOffset(24)] public uint   Reflect_ProcessId;
    [FieldOffset(28)] public uint   Reflect_Layer;
    [FieldOffset(32)] public ulong  Reflect_Flags;
    [FieldOffset(40)] public short  Reflect_Priority;

    public byte Layer
    {
        readonly get => (byte)(FlagsBitfield & 0xFF);
        set => FlagsBitfield = (FlagsBitfield & ~0xFFu) | value;
    }

    public byte Event
    {
        readonly get => (byte)((FlagsBitfield >> 8) & 0xFF);
        set => FlagsBitfield = (FlagsBitfield & ~0xFF00u) | ((uint)value << 8);
    }

    public bool Sniffed
    {
        readonly get => (FlagsBitfield & 0x10000) != 0;
        set => FlagsBitfield = value ? FlagsBitfield | 0x10000 : FlagsBitfield & ~0x10000u;
    }

    public bool Outbound
    {
        readonly get => (FlagsBitfield & 0x20000) != 0;
        set => FlagsBitfield = value ? FlagsBitfield | 0x20000 : FlagsBitfield & ~0x20000u;
    }

    public bool Loopback
    {
        readonly get => (FlagsBitfield & 0x40000) != 0;
        set => FlagsBitfield = value ? FlagsBitfield | 0x40000 : FlagsBitfield & ~0x40000u;
    }

    public bool Impostor
    {
        readonly get => (FlagsBitfield & 0x80000) != 0;
        set => FlagsBitfield = value ? FlagsBitfield | 0x80000 : FlagsBitfield & ~0x80000u;
    }

    public bool IPv6
    {
        readonly get => (FlagsBitfield & 0x100000) != 0;
        set => FlagsBitfield = value ? FlagsBitfield | 0x100000 : FlagsBitfield & ~0x100000u;
    }

    public bool IPChecksum
    {
        readonly get => (FlagsBitfield & 0x200000) != 0;
        set => FlagsBitfield = value ? FlagsBitfield | 0x200000 : FlagsBitfield & ~0x200000u;
    }

    public bool TCPChecksum
    {
        readonly get => (FlagsBitfield & 0x400000) != 0;
        set => FlagsBitfield = value ? FlagsBitfield | 0x400000 : FlagsBitfield & ~0x400000u;
    }

    public bool UDPChecksum
    {
        readonly get => (FlagsBitfield & 0x800000) != 0;
        set => FlagsBitfield = value ? FlagsBitfield | 0x800000 : FlagsBitfield & ~0x800000u;
    }

    public readonly bool Inbound => !Outbound;
}
