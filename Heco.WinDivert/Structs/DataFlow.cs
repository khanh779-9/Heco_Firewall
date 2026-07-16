using System.Runtime.InteropServices;

namespace Heco.WinDivert.Structs;

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
