using System.Runtime.InteropServices;

namespace Heco.WinDivert.Structs;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct TcpHeader
{
    public ushort SrcPort;
    public ushort DstPort;
    public uint SeqNumber;
    public uint AckNumber;
    public ushort DataOffset;
    public ushort Window;
    public ushort Checksum;
    public ushort UrgentPointer;

    public readonly byte Flags => (byte)(DataOffset & 0xFF);
    public readonly int DataOffsetBytes => ((DataOffset >> 12) & 0xF) * 4;
}
