using System;
using System.Runtime.InteropServices;
using Heco.WinDivert.Structs;

namespace Heco.WinDivert.Interop;

internal static class IPHelpApiNative
{
    public const int TCP_TABLE_OWNER_PID_ALL = 5;
    public const int UDP_TABLE_OWNER_PID = 1;

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW_OWNER_PID
    {
        public StateType State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct MIB_TCP6ROW_OWNER_PID
    {
        public fixed byte LocalAddr[16];
        public uint LocalScopeId;
        public uint LocalPort;
        public fixed byte RemoteAddr[16];
        public uint RemoteScopeId;
        public uint RemotePort;
        public StateType State;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UDPROW_OWNER_PID
    {
        public uint LocalAddr;
        public uint LocalPort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct MIB_UDP6ROW_OWNER_PID
    {
        public fixed byte LocalAddr[16];
        public uint LocalScopeId;
        public uint LocalPort;
        public uint OwningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    public static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref uint pdwSize,
        [MarshalAs(UnmanagedType.Bool)] bool bOrder,
        uint ulAf,
        int tableClass,
        uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    public static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable,
        ref uint pdwSize,
        [MarshalAs(UnmanagedType.Bool)] bool bOrder,
        uint ulAf,
        int tableClass,
        uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    public static extern uint GetBestInterfaceEx(
        ref SocketAddress destAddr,
        out int bestIfIndex);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    public static extern unsafe uint GetBestRoute2(
        IntPtr interfaceLuid,
        int interfaceIndex,
        IntPtr sourceAddress,
        ref SocketAddress destAddress,
        uint protocol,
        IntPtr bestRoute,
        ref SocketAddress bestSourceAddress);
}
