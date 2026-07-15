using System.Runtime.InteropServices;

namespace Heco.WinDivert.Native;

public static class WinDivertStructs
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct DATA_NETWORK
    {
        public uint IfIdx;
        public uint SubIfIdx;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct DATA_FLOW
    {
        public ulong EndpointId;
        public ulong ParentEndpointId;
        public uint ProcessId;
        public uint LocalAddr0;
        public uint LocalAddr1;
        public uint LocalAddr2;
        public uint LocalAddr3;
        public uint RemoteAddr0;
        public uint RemoteAddr1;
        public uint RemoteAddr2;
        public uint RemoteAddr3;
        public ushort LocalPort;
        public ushort RemotePort;
        public Protocol Protocol;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct DATA_SOCKET
    {
        public ulong EndpointId;
        public ulong ParentEndpointId;
        public uint ProcessId;
        public uint LocalAddr0;
        public uint LocalAddr1;
        public uint LocalAddr2;
        public uint LocalAddr3;
        public uint RemoteAddr0;
        public uint RemoteAddr1;
        public uint RemoteAddr2;
        public uint RemoteAddr3;
        public ushort LocalPort;
        public ushort RemotePort;
        public Protocol Protocol;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct DATA_REFLECT
    {
        public long Timestamp;
        public uint ProcessId;
        public uint Layer;
        public ulong Flags;
        public short Priority;
    }

    [StructLayout(LayoutKind.Explicit, Size = 80)]
    public unsafe struct WINDIVERT_ADDRESS
    {
        [FieldOffset(0)]  public long Timestamp;

        // Bitfield (32 bits): Layer(8) | Event(8) | flags(8 bits) | Reserved1(8)
        [FieldOffset(8)]  public uint FlagsBitfield;
        [FieldOffset(12)] public uint Reserved1;

        // Union at offset 16 (64 bytes)
        [FieldOffset(16)] public fixed byte Reserved3[64];

        // -- Network layer (8 bytes at 16) --
        [FieldOffset(16)] public uint IfIdx;
        [FieldOffset(20)] public uint SubIfIdx;

        // -- Flow layer (57 bytes at 16) --
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

        // -- Socket layer (57 bytes at 16) --
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

        // -- Reflect layer (26 bytes at 16) --
        [FieldOffset(16)] public long   Reflect_Timestamp;
        [FieldOffset(24)] public uint   Reflect_ProcessId;
        [FieldOffset(28)] public uint   Reflect_Layer;
        [FieldOffset(32)] public ulong  Reflect_Flags;
        [FieldOffset(40)] public short  Reflect_Priority;

        // -- Bitfield accessors --

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
}
