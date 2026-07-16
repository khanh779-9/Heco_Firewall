using System.Runtime.InteropServices;

namespace Heco.WinDivert.Structs;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct DATA_REFLECT
{
    public long Timestamp;
    public uint ProcessId;
    public uint Layer;
    public ulong Flags;
    public short Priority;
}
