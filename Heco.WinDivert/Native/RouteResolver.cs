using System;
using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using static Heco.WinDivert.Native.WinDivertStructs;

namespace Heco.WinDivert.Native;

[SupportedOSPlatform("windows")]
public class RouteResolver
{
    private const int MIB_IPFORWARD_ROW2_SIZE = 103;

    public IPAddress DstAddress { get; }
    public IPAddress SrcAddress { get; }
    public int InterfaceIndex { get; }
    public bool IsOutbound { get; }
    public bool IsLoopback { get; }

    public RouteResolver(IPAddress dstAddr)
        : this(dstAddr, null, null) { }

    public RouteResolver(IPAddress dstAddr, IPAddress? srcAddr)
        : this(dstAddr, srcAddr, null) { }

    public RouteResolver(IPAddress dstAddr, IPAddress? srcAddr, int interfaceIndex)
        : this(dstAddr, srcAddr, (int?)interfaceIndex) { }

    private unsafe RouteResolver(IPAddress dstAddr, IPAddress? srcAddr, int? interfaceIndex)
    {
        if (IsAny(dstAddr))
            throw new ArgumentException($"Destination cannot be {dstAddr}", nameof(dstAddr));

        if (srcAddr != null && srcAddr.AddressFamily != dstAddr.AddressFamily)
            throw new ArgumentException("Address family mismatch", nameof(srcAddr));

        if (IsAny(srcAddr))
            srcAddr = null;

        var dstSockAddr = new SocketAddress();
        dstSockAddr.SetIPAddress(dstAddr);

        interfaceIndex ??= GetInterfaceIndex(ref dstSockAddr);

        var pBestRoute = stackalloc byte[MIB_IPFORWARD_ROW2_SIZE];
        var bestSrcSockAddr = new SocketAddress();

        nint pSrcSockAddr = IntPtr.Zero;
        if (srcAddr != null)
        {
            var srcSockAddr = new SocketAddress();
            srcSockAddr.SetIPAddress(srcAddr);
            pSrcSockAddr = new IntPtr(&srcSockAddr);
        }

        var errorCode = IPHelpApiNative.GetBestRoute2(
            IntPtr.Zero,
            interfaceIndex.Value,
            pSrcSockAddr,
            ref dstSockAddr,
            0U,
            new IntPtr(pBestRoute),
            ref bestSrcSockAddr);

        if (errorCode != 0 && srcAddr == null)
            throw new Win32Exception((int)errorCode);

        SrcAddress = srcAddr ?? bestSrcSockAddr.GetIPAddress();
        DstAddress = dstAddr;
        InterfaceIndex = interfaceIndex.Value;
        IsOutbound = errorCode == 0;
        IsLoopback = IPAddress.IsLoopback(dstAddr) && dstAddr.Equals(SrcAddress);
    }

    private static bool IsAny(IPAddress? address)
    {
        return address != null && (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any));
    }

    public static int GetInterfaceIndex(IPAddress dstAddr)
    {
        if (dstAddr.Equals(IPAddress.Any) || dstAddr.Equals(IPAddress.IPv6Any))
            throw new ArgumentException($"Destination cannot be {dstAddr}", nameof(dstAddr));

        var dstSockAddr = new SocketAddress();
        dstSockAddr.SetIPAddress(dstAddr);
        return GetInterfaceIndex(ref dstSockAddr);
    }

    private static int GetInterfaceIndex(ref SocketAddress dstSockAddr)
    {
        var errorCode = IPHelpApiNative.GetBestInterfaceEx(ref dstSockAddr, out var ifIdx);
        return errorCode == 0 ? ifIdx : throw new NetworkInformationException((int)errorCode);
    }

    public void ApplyToAddress(ref WINDIVERT_ADDRESS addr)
    {
        addr.IfIdx = (uint)InterfaceIndex;
        addr.Outbound = IsOutbound;
    }
}
