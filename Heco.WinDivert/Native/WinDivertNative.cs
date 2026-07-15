using System;
using System.Runtime.InteropServices;
using static Heco.WinDivert.Native.WinDivertStructs;

namespace Heco.WinDivert.Native;

public static class WinDivertNative
{
    // ── DLL loading ────────────────────────────────────────────────

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern nint LoadLibrary(string lpFileName);

    static WinDivertNative()
    {
        try
        {
            var baseDir = AppDomain.CurrentDomain.BaseDirectory;
            var arch = IntPtr.Size == 8 ? "x64" : "x86";
            var dllPath = System.IO.Path.Combine(baseDir, "Drivers", arch, "WinDivert.dll");
            if (System.IO.File.Exists(dllPath))
                LoadLibrary(dllPath);
        }
        catch { }
    }

    // ── Core API ───────────────────────────────────────────────────

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern nint WinDivertOpen(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        int layer,
        short priority,
        ulong flags);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertClose(nint handle);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertShutdown(nint handle, byte how);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertRecv(
        nint handle,
        byte[] pPacket,
        uint packetLen,
        ref uint pRecvLen,
        ref WINDIVERT_ADDRESS pAddr);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertSend(
        nint handle,
        byte[] pPacket,
        uint packetLen,
        ref uint pSendLen,
        ref WINDIVERT_ADDRESS pAddr);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertRecvEx(
        nint handle,
        byte[] pPacket,
        uint packetLen,
        ref uint pRecvLen,
        ref ulong pFlags,
        ref WINDIVERT_ADDRESS pAddr,
        ref int pAddrLen,
        nint lpOverlapped);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertSendEx(
        nint handle,
        byte[] pPacket,
        uint packetLen,
        ref uint pSendLen,
        ulong flags,
        ref WINDIVERT_ADDRESS pAddr,
        int addrLen,
        nint lpOverlapped);

    // ── Params ─────────────────────────────────────────────────────

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertSetParam(nint handle, uint param, ulong value);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertGetParam(nint handle, uint param, out ulong pValue);

    // ── Helper: Checksums ──────────────────────────────────────────

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertHelperCalcChecksums(
        byte[] pPacket,
        uint packetLen,
        ref WINDIVERT_ADDRESS pAddr,
        ulong flags);

    // ── Helper: Parse packet ───────────────────────────────────────

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
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

    // ── Helper: Hash ───────────────────────────────────────────────

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern ulong WinDivertHelperHashPacket(
        byte[] pPacket,
        uint packetLen,
        ulong seed);

    // ── Helper: Decrement TTL ──────────────────────────────────────

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertHelperDecrementTTL(
        byte[] pPacket,
        uint packetLen);

    // ── Helper: Filter compile ─────────────────────────────────────

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertHelperCompileFilter(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        int layer,
        IntPtr obj,
        int objLen,
        out IntPtr errorStr,
        out int errorPos);

    // ── Helper: Filter eval ────────────────────────────────────────

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertHelperEvalFilter(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        byte[] pPacket,
        uint packetLen,
        ref WINDIVERT_ADDRESS pAddr);

    // ── Helper: Filter format ──────────────────────────────────────

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertHelperFormatFilter(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        int layer,
        IntPtr buffer,
        int bufLen);

    // ── Helper: Address parsing ────────────────────────────────────

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertHelperParseIPv4Address(
        [MarshalAs(UnmanagedType.LPStr)] string addrStr,
        out uint pAddr);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern unsafe bool WinDivertHelperParseIPv6Address(
        [MarshalAs(UnmanagedType.LPStr)] string addrStr,
        uint* pAddr);

    // ── Helper: Address formatting ─────────────────────────────────

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertHelperFormatIPv4Address(
        uint addr,
        IntPtr buffer,
        uint bufLen);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern unsafe bool WinDivertHelperFormatIPv6Address(
        uint* pAddr,
        IntPtr buffer,
        uint bufLen);

    // ── Helper: Byte ordering ──────────────────────────────────────

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern ushort WinDivertHelperNtohs(ushort x);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern ushort WinDivertHelperHtons(ushort x);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern uint WinDivertHelperNtohl(uint x);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern uint WinDivertHelperHtonl(uint x);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern ulong WinDivertHelperNtohll(ulong x);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern ulong WinDivertHelperHtonll(ulong x);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe void WinDivertHelperNtohIPv6Address(
        uint* inAddr,
        uint* outAddr);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe void WinDivertHelperHtonIPv6Address(
        uint* inAddr,
        uint* outAddr);

    // ── Managed wrappers ──────────────────────────────────────────

    public static unsafe byte[] CompileFilter(string filter, WinDivertLayer layer)
    {
        int bufSize = 4096;
        var obj = Marshal.AllocHGlobal(bufSize);
        try
        {
            new Span<byte>(obj.ToPointer(), bufSize).Clear();
            IntPtr errorStr;
            int errorPos;
            if (WinDivertHelperCompileFilter(filter, (int)layer, obj, bufSize, out errorStr, out errorPos))
            {
                var result = new byte[bufSize];
                Marshal.Copy(obj, result, 0, bufSize);
                return result;
            }
            var msg = errorStr != IntPtr.Zero
                ? Marshal.PtrToStringAnsi(errorStr)
                : "Unknown error";
            throw new InvalidOperationException($"Filter compilation failed at position {errorPos}: {msg}");
        }
        finally
        {
            Marshal.FreeHGlobal(obj);
        }
    }

    public static unsafe string FormatFilter(string filter, WinDivertLayer layer)
    {
        int bufSize = 4096;
        var buffer = Marshal.AllocHGlobal(bufSize);
        try
        {
            new Span<byte>(buffer.ToPointer(), bufSize).Clear();
            if (WinDivertHelperFormatFilter(filter, (int)layer, buffer, bufSize))
                return Marshal.PtrToStringAnsi(buffer) ?? string.Empty;
            throw new InvalidOperationException("Failed to format filter string.");
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static unsafe string FormatIPv4Address(uint addr)
    {
        var buffer = stackalloc byte[32];
        var ptr = new IntPtr(buffer);
        return WinDivertHelperFormatIPv4Address(addr, ptr, 32)
            ? Marshal.PtrToStringAnsi(ptr) ?? ""
            : addr.ToString();
    }

    public static unsafe string FormatIPv6Address(uint* addr)
    {
        var buffer = stackalloc byte[64];
        var ptr = new IntPtr(buffer);
        return WinDivertHelperFormatIPv6Address(addr, ptr, 64)
            ? Marshal.PtrToStringAnsi(ptr) ?? ""
            : "";
    }

    public static unsafe uint? ParseIPv4Address(string str)
    {
        if (WinDivertHelperParseIPv4Address(str, out uint addr))
            return addr;
        return null;
    }

    public static unsafe uint[]? ParseIPv6Address(string str)
    {
        var addr = stackalloc uint[4];
        if (WinDivertHelperParseIPv6Address(str, addr))
            return [addr[0], addr[1], addr[2], addr[3]];
        return null;
    }

    public static unsafe Sniffer.WinDivertParseResult? ParsePacket(byte[] buffer, uint length)
    {
        V4Header* v4 = null;
        V6Header* v6 = null;
        byte rawProtocol = 0;
        byte* icmp4 = null;
        byte* icmp6 = null;
        byte* tcp = null;
        byte* udp = null;
        byte* data = null;
        int dataLen = 0;
        byte* next = null;
        int nextLen = 0;

        if (WinDivertHelperParsePacket(buffer, length,
                out v4, out v6, out rawProtocol,
                out icmp4, out icmp6,
                out tcp, out udp,
                out data, out dataLen,
                out next, out nextLen))
        {
            return new Sniffer.WinDivertParseResult(
                v4, v6, (Protocol)rawProtocol,
                icmp4, icmp6, tcp, udp,
                data, dataLen, next, nextLen);
        }
        return null;
    }
}
