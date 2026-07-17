using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Heco.WinDivert.Enums;
using Heco.WinDivert.Structs;

namespace Heco.WinDivert.Interop;

[SupportedOSPlatform("windows")]
public static partial class WinDivertNative
{
    private const string DllName = "WinDivert.dll";

    static WinDivertNative()
    {
        var baseDir = AppDomain.CurrentDomain.BaseDirectory;

        var dllPath = Path.Combine(baseDir, "WinDivert.dll");
        if (!File.Exists(dllPath))
        {
            var arch = Environment.Is64BitProcess ? "x64" : "x86";
            dllPath = Path.Combine(baseDir, "Drivers", arch, "WinDivert.dll");
        }

        if (File.Exists(dllPath))
            NativeLibrary.Load(dllPath);
    }

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern IntPtr WinDivertOpen(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        int layer,
        short priority,
        ulong flags);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertClose(IntPtr handle);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertShutdown(IntPtr handle, WinDivertShutdown how);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertRecv(
        IntPtr handle,
        byte[] pPacket,
        uint packetLen,
        ref uint pRecvLen,
        ref WINDIVERT_ADDRESS pAddr);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertSend(
        IntPtr handle,
        byte[] pPacket,
        uint packetLen,
        ref uint pSendLen,
        ref WINDIVERT_ADDRESS pAddr);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertRecvEx(
        IntPtr handle,
        byte[] pPacket,
        uint packetLen,
        ref uint pRecvLen,
        ulong flags,
        ref WINDIVERT_ADDRESS pAddr,
        ref uint pAddrLen,
        IntPtr lpOverlapped);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertRecvEx(
        IntPtr handle,
        IntPtr pPacket,
        uint packetLen,
        ref uint pRecvLen,
        ulong flags,
        ref WINDIVERT_ADDRESS pAddr,
        ref uint pAddrLen,
        IntPtr lpOverlapped);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertSendEx(
        IntPtr handle,
        byte[] pPacket,
        uint packetLen,
        ref uint pSendLen,
        ulong flags,
        ref WINDIVERT_ADDRESS pAddr,
        uint addrLen,
        IntPtr lpOverlapped);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertSendEx(
        IntPtr handle,
        IntPtr pPacket,
        uint packetLen,
        ref uint pSendLen,
        ulong flags,
        ref WINDIVERT_ADDRESS pAddr,
        uint addrLen,
        IntPtr lpOverlapped);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertSetParam(IntPtr handle, WinDivertParam param, ulong value);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertGetParam(IntPtr handle, WinDivertParam param, out ulong pValue);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertHelperCalcChecksums(
        byte[] pPacket,
        uint packetLen,
        ref WINDIVERT_ADDRESS pAddr,
        ulong flags);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern unsafe bool WinDivertHelperParsePacket(
        byte[] pPacket,
        uint packetLen,
        out V4Header* ppIpHdr,
        out V6Header* ppIpv6Hdr,
        out byte pProtocol,
        out byte* ppIcmpHdr,
        out byte* ppIcmpv6Hdr,
        out byte* ppTcpHdr,
        out byte* ppUdpHdr,
        out byte* ppData,
        out int pDataLen,
        out byte* ppNext,
        out int pNextLen);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern ulong WinDivertHelperHashPacket(
        byte[] pPacket,
        uint packetLen,
        ulong seed);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertHelperDecrementTTL(
        byte[] pPacket,
        uint packetLen);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertHelperCompileFilter(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        int layer,
        IntPtr obj,
        int objLen,
        out IntPtr errorStr,
        out int errorPos);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertHelperEvalFilter(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        byte[] pPacket,
        uint packetLen,
        ref WINDIVERT_ADDRESS pAddr);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertHelperFormatFilter(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        int layer,
        IntPtr buffer,
        int bufLen);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertHelperParseIPv4Address(
        [MarshalAs(UnmanagedType.LPStr)] string addrStr,
        out uint pAddr);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern unsafe bool WinDivertHelperParseIPv6Address(
        [MarshalAs(UnmanagedType.LPStr)] string addrStr,
        uint* pAddr);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertHelperFormatIPv4Address(
        uint addr,
        IntPtr buffer,
        uint bufLen);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern unsafe bool WinDivertHelperFormatIPv6Address(
        uint* pAddr,
        IntPtr buffer,
        uint bufLen);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern ushort WinDivertHelperNtohs(ushort x);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern ushort WinDivertHelperHtons(ushort x);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern uint WinDivertHelperNtohl(uint x);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern uint WinDivertHelperHtonl(uint x);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern ulong WinDivertHelperNtohll(ulong x);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern ulong WinDivertHelperHtonll(ulong x);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe void WinDivertHelperNtohIPv6Address(
        uint* inAddr,
        uint* outAddr);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe void WinDivertHelperHtonIPv6Address(
        uint* inAddr,
        uint* outAddr);
}
