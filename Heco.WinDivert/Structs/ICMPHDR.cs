using System.Runtime.InteropServices;

namespace Heco.WinDivert.Structs;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct ICMPHDR
{
    public byte Type;
    public byte Code;
    public ushort Checksum;
    public uint Body;
}