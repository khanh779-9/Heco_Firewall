using System.Runtime.InteropServices;

namespace Heco.WinDivert.Structs;

[StructLayout(LayoutKind.Explicit)]
public unsafe struct V6Header
{
    [FieldOffset(0)]  public uint   VersionAndFlow;
    [FieldOffset(4)]  public ushort PayloadLength;
    [FieldOffset(6)]  public Protocol NextHdr;
    [FieldOffset(7)]  public byte   HopLimit;
    [FieldOffset(8)]  public fixed byte SrcAddr[16];
    [FieldOffset(24)] public fixed byte DstAddr[16];

    public readonly byte Version => (byte)(VersionAndFlow >> 28);
    public readonly byte TrafficClass => (byte)(VersionAndFlow >> 20);
    public readonly uint FlowLabel => VersionAndFlow & 0x000FFFFF;

    [FieldOffset(40)] public ushort SrcPort;
    [FieldOffset(42)] public ushort DstPort;

    [FieldOffset(44)] public uint   TcpSeqNum;
    [FieldOffset(48)] public uint   TcpAckNum;
    [FieldOffset(52)] public ushort TcpReservedAndFlags;
    [FieldOffset(54)] public ushort TcpWindow;
    [FieldOffset(56)] public ushort TcpChecksum;
    [FieldOffset(58)] public ushort TcpUrgPtr;

    public readonly byte TcpDataOffset => (byte)((TcpReservedAndFlags >> 12) & 0x0F);
    public readonly byte TcpFlags      => (byte)(TcpReservedAndFlags & 0x00FF);

    [FieldOffset(44)] public ushort UdpLength;
    [FieldOffset(46)] public ushort UdpChecksum;

    [FieldOffset(40)] public byte   IcmpType;
    [FieldOffset(41)] public byte   IcmpCode;
    [FieldOffset(42)] public ushort IcmpChecksum;
    [FieldOffset(44)] public ushort IcmpIdentifier;
    [FieldOffset(46)] public ushort IcmpSequenceNumber;
    [FieldOffset(44)] public uint   IcmpBody;
}
