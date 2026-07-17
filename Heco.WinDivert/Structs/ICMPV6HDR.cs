using System.Runtime.InteropServices;

namespace Heco.WinDivert.Structs;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct ICMPV6HDR
{
    public byte Type;
    public byte Code;
    public ushort Checksum;
    public uint Body;
}