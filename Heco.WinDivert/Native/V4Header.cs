using System.Runtime.InteropServices;

namespace Heco.WinDivert.Native;

[StructLayout(LayoutKind.Explicit)]
public struct V4Header
{
    //  IPv4 ─
    [FieldOffset(0)]  public byte VersionAndIhl;
    [FieldOffset(1)]  public byte TOS;
    [FieldOffset(2)]  public ushort Length;
    [FieldOffset(4)]  public ushort Id;
    [FieldOffset(6)]  public ushort FragOff0;
    [FieldOffset(8)]  public byte TTL;
    [FieldOffset(9)]  public Protocol Protocol;
    [FieldOffset(10)] public ushort Checksum;
    [FieldOffset(12)] public uint SrcAddr;
    [FieldOffset(16)] public uint DstAddr;

    public readonly byte Version => (byte)(VersionAndIhl >> 4);
    public readonly byte IHL => (byte)(VersionAndIhl & 0x0F);

    //  TCP / UDP ─
    [FieldOffset(20)] public ushort SrcPort;
    [FieldOffset(22)] public ushort DstPort;

    //  TCP 
    [FieldOffset(24)] public uint TcpSeqNum;
    [FieldOffset(28)] public uint TcpAckNum;
    [FieldOffset(32)] public ushort TcpReservedAndFlags;
    [FieldOffset(34)] public ushort TcpWindow;
    [FieldOffset(38)] public ushort TcpUrgPtr;

    public readonly byte TcpDataOffset => (byte)((TcpReservedAndFlags >> 12) & 0x0F);
    public readonly byte TcpFlags => (byte)(TcpReservedAndFlags & 0x00FF);

    //  ICMPv4 ─
    [FieldOffset(20)] public byte IcmpType;
    [FieldOffset(21)] public byte IcmpCode;
    [FieldOffset(24)] public uint IcmpBody;

    //  Fragmentation ─
    public readonly ushort FragOff => (ushort)(FragOff0 & 0xFF1F);
    public readonly bool MF  => (FragOff0 & 0x0020) != 0;
    public readonly bool DF  => (FragOff0 & 0x0040) != 0;
    public readonly bool FragReserved => (FragOff0 & 0x0080) != 0;
}
