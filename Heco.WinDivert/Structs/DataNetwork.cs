using System.Runtime.InteropServices;

namespace Heco.WinDivert.Structs;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct DATA_NETWORK
{
    public uint IfIdx;
    public uint SubIfIdx;
}
