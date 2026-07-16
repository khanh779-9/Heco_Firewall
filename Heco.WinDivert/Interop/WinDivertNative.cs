using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Heco.WinDivert.Structs;
using Heco.WinDivert.Packet;

namespace Heco.WinDivert.Interop;

public static class WinDivertNative
{
    //  DLL loading ─

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern nint LoadLibrary(string lpFileName);

    static WinDivertNative()
    {
        try
        {
            var baseDir = AppDomain.CurrentDomain.BaseDirectory;
            var is64BitProc = Environment.Is64BitProcess;
            var is64BitOS = Environment.Is64BitOperatingSystem;
            var procArch = is64BitProc ? "x64" : "x86";

            // Following WindivertDotnet pattern:
            // - 64-bit process: deploy WinDivert64.sys
            // - 32-bit process on 64-bit OS: deploy BOTH WinDivert32.sys AND WinDivert64.sys
            // - 32-bit process on 32-bit OS: deploy WinDivert32.sys
            var sysFilesToDeploy = new System.Collections.Generic.List<string>();
            if (is64BitProc)
            {
                sysFilesToDeploy.Add("WinDivert64.sys");
            }
            else if (is64BitOS)
            {
                // 32-bit process on 64-bit OS needs BOTH drivers
                sysFilesToDeploy.Add("WinDivert32.sys");
                sysFilesToDeploy.Add("WinDivert64.sys");
            }
            else
            {
                sysFilesToDeploy.Add("WinDivert32.sys");
            }

            // Deployment target directories
            var deployDirs = new System.Collections.Generic.List<string>();
            if (!string.IsNullOrEmpty(baseDir))
                deployDirs.Add(baseDir);
            try
            {
                var curDir = Environment.CurrentDirectory;
                if (!string.IsNullOrEmpty(curDir) && !string.Equals(curDir, baseDir, StringComparison.OrdinalIgnoreCase))
                    deployDirs.Add(curDir);
            }
            catch { }

            // Source directories to look for driver files
            var x64DriverDir = System.IO.Path.Combine(baseDir, "Drivers", "x64");
            var x86DriverDir = System.IO.Path.Combine(baseDir, "Drivers", "x86");

            foreach (var sysFile in sysFilesToDeploy)
            {
                // Find source: WinDivert64.sys comes from x64 folder, WinDivert32.sys from x86 folder
                var srcDir = sysFile.Contains("64") ? x64DriverDir : x86DriverDir;
                var srcPath = System.IO.Path.Combine(srcDir, sysFile);

                if (!System.IO.File.Exists(srcPath))
                    continue;

                foreach (var deployDir in deployDirs)
                {
                    try
                    {
                        var targetPath = System.IO.Path.Combine(deployDir, sysFile);
                        if (!System.IO.File.Exists(targetPath))
                            System.IO.File.Copy(srcPath, targetPath);
                    }
                    catch { }
                }
            }

            // Load the WinDivert.dll matching the process architecture
            var dllPath = System.IO.Path.Combine(baseDir, "Drivers", procArch, "WinDivert.dll");
            if (System.IO.File.Exists(dllPath))
            {
                try { LoadLibrary(dllPath); } catch { }
            }
        }
        catch { }
    }

    //  Core API ─

    [DllImport("WinDivert.dll", EntryPoint = "WinDivertOpen", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    private static extern nint WinDivertOpenNative(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        int layer,
        short priority,
        ulong flags);

    /// <summary>
    /// Opens a WinDivert handle with automatic stale driver cleanup.
    /// If the first attempt fails with ERROR_FILE_NOT_FOUND (0x2), the old driver
    /// service is removed via sc.exe and a retry is performed.
    /// </summary>
    public static nint WinDivertOpen(string filter, int layer, short priority, ulong flags)
    {
        var handle = WinDivertOpenNative(filter, layer, priority, flags);
        if (handle != IntPtr.Zero && handle != new IntPtr(-1))
            return handle;

        var err = Marshal.GetLastWin32Error();

        // ERROR_FILE_NOT_FOUND (2): stale driver service pointing to a deleted path
        // ERROR_SERVICE_MARKED_FOR_DELETE (1072): previous service not fully cleaned up
        if (err == 2 || err == 1072)
        {
            // Clean up stale WinDivert driver service via sc.exe
            // (WinDivert 2.2 does not export Install/Uninstall helper functions)
            try
            {
                RunSc("stop WinDivert");
                RunSc("delete WinDivert");
            }
            catch { }
            System.Threading.Thread.Sleep(200);

            // Retry opening the device
            handle = WinDivertOpenNative(filter, layer, priority, flags);
        }
        return handle;
    }

    /// <summary>
    /// Runs sc.exe with the given arguments silently.
    /// </summary>
    private static void RunSc(string arguments)
    {
        try
        {
            using var proc = new Process();
            proc.StartInfo.FileName = "sc.exe";
            proc.StartInfo.Arguments = arguments;
            proc.StartInfo.UseShellExecute = false;
            proc.StartInfo.CreateNoWindow = true;
            proc.StartInfo.RedirectStandardOutput = true;
            proc.StartInfo.RedirectStandardError = true;
            proc.Start();
            proc.WaitForExit(3000);
        }
        catch { }
    }


    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertClose(nint handle);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertShutdown(nint handle, byte how);

    // ── byte[]-based DllImports (used by filter engine) ──

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
        ulong flags,
        ref WINDIVERT_ADDRESS pAddr,
        ref uint pAddrLen,
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
        uint addrLen,
        nint lpOverlapped);

    // ── IntPtr-based DllImports (for native memory / overlapped I/O) ──

    [DllImport("WinDivert.dll", EntryPoint = "WinDivertRecvEx", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinDivertRecvExNative(
        nint handle,
        nint pPacket,
        uint packetLen,
        ref uint pRecvLen,
        ulong flags,
        ref WINDIVERT_ADDRESS pAddr,
        ref uint pAddrLen,
        nint lpOverlapped);

    [DllImport("WinDivert.dll", EntryPoint = "WinDivertSendEx", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinDivertSendExNative(
        nint handle,
        nint pPacket,
        uint packetLen,
        ref uint pSendLen,
        ulong flags,
        ref WINDIVERT_ADDRESS pAddr,
        uint addrLen,
        nint lpOverlapped);

    //  Params ─

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertSetParam(nint handle, uint param, ulong value);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertGetParam(nint handle, uint param, out ulong pValue);

    // NOTE: WinDivert 2.2 does NOT export WinDivertHelperInstallDriver/UninstallDriver.
    // Driver installation is handled automatically by WinDivertOpen().
    // For manual cleanup, use sc.exe (see RunSc helper above).

    //  Helper: Checksums ─

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertHelperCalcChecksums(
        byte[] pPacket,
        uint packetLen,
        ref WINDIVERT_ADDRESS pAddr,
        ulong flags);

    //  Helper: Parse packet ─

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

    //  Helper: Hash 

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern ulong WinDivertHelperHashPacket(
        byte[] pPacket,
        uint packetLen,
        ulong seed);

    //  Helper: Decrement TTL 

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertHelperDecrementTTL(
        byte[] pPacket,
        uint packetLen);

    //  Helper: Filter compile ─

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertHelperCompileFilter(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        int layer,
        IntPtr obj,
        int objLen,
        out IntPtr errorStr,
        out int errorPos);

    //  Helper: Filter eval 

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertHelperEvalFilter(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        byte[] pPacket,
        uint packetLen,
        ref WINDIVERT_ADDRESS pAddr);

    //  Helper: Filter format 

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertHelperFormatFilter(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        int layer,
        IntPtr buffer,
        int bufLen);

    //  Helper: Address parsing 

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

    //  Helper: Address formatting 

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

    //  Helper: Byte ordering 

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

    //  Managed wrappers ─

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

    public static unsafe Packet.WinDivertParseResult? ParsePacket(byte[] buffer, uint length)
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
            return new Packet.WinDivertParseResult(
                v4, v6, (Protocol)rawProtocol,
                icmp4, icmp6, tcp, udp,
                data, dataLen, next, nextLen);
        }
        return null;
    }

    //  Shutdown control
    public static bool Shutdown(nint handle, WinDivertShutdown how)
    {
        return WinDivertShutdown(handle, (byte)how);
    }

    //  Extended API (RecvEx/SendEx)
    public static bool RecvEx(nint handle, byte[] packet, uint packetLen,
        ref uint recvLen, ref ulong flags, ref WINDIVERT_ADDRESS addr,
        ref int addrLen, nint overlapped = default)
    {
        uint uAddrLen = (uint)addrLen;
        bool result = WinDivertRecvEx(handle, packet, packetLen, ref recvLen,
            flags, ref addr, ref uAddrLen, overlapped);
        addrLen = (int)uAddrLen;
        return result;
    }

    public static bool SendEx(nint handle, byte[] packet, uint packetLen,
        ref uint sendLen, ulong flags, ref WINDIVERT_ADDRESS addr,
        int addrLen, nint overlapped = default)
    {
        return WinDivertSendEx(handle, packet, packetLen, ref sendLen,
            flags, ref addr, (uint)addrLen, overlapped);
    }

    //  IntPtr-based RecvEx/SendEx (for native memory + overlapped I/O)
    public static bool RecvEx(nint handle, nint pPacket, uint packetLen,
        ref uint recvLen, ref ulong flags, ref WINDIVERT_ADDRESS addr,
        ref int addrLen, nint overlapped)
    {
        uint uAddrLen = (uint)addrLen;
        bool result = WinDivertRecvExNative(handle, pPacket, packetLen, ref recvLen,
            flags, ref addr, ref uAddrLen, overlapped);
        addrLen = (int)uAddrLen;
        return result;
    }

    public static bool SendEx(nint handle, nint pPacket, uint packetLen,
        ref uint sendLen, ulong flags, ref WINDIVERT_ADDRESS addr,
        int addrLen, nint overlapped)
    {
        return WinDivertSendExNative(handle, pPacket, packetLen, ref sendLen,
            flags, ref addr, (uint)addrLen, overlapped);
    }

    public static int SendExBatch(nint handle, byte[][] packets, uint[] lengths, WINDIVERT_ADDRESS[] addresses, int count)
    {
        int sentCount = 0;
        for (int i = 0; i < count; i++)
        {
            uint sendLen = 0;
            if (WinDivertSendEx(handle, packets[i], lengths[i], ref sendLen, 0, ref addresses[i], (uint)Marshal.SizeOf<WINDIVERT_ADDRESS>(), IntPtr.Zero))
                sentCount++;
        }
        return sentCount;
    }

    //  Hash & TTL
    public static ulong HashPacket(byte[] packet, uint packetLen, ulong seed = 0)
    {
        return WinDivertHelperHashPacket(packet, packetLen, seed);
    }

    public static bool DecrementTTL(byte[] packet, uint packetLen)
    {
        return WinDivertHelperDecrementTTL(packet, packetLen);
    }

    //  Dynamic filter evaluation
    public static bool EvalFilter(string filter, byte[] packet, uint packetLen, ref WINDIVERT_ADDRESS addr)
    {
        return WinDivertHelperEvalFilter(filter, packet, packetLen, ref addr);
    }

    //  Params (queue len, timeouts, etc.)
    public static bool SetParam(nint handle, WinDivertParam param, ulong value)
    {
        return WinDivertSetParam(handle, (uint)param, value);
    }

    public static bool GetParam(nint handle, WinDivertParam param, out ulong value)
    {
        return WinDivertGetParam(handle, (uint)param, out value);
    }

    //  Driver management ─
    public static bool InstallDriver()
    {
        // In WinDivert 2.2, driver is auto-installed on WinDivertOpen,
        // so this is a no-op returning true.
        return true;
    }

    public static bool UninstallDriver()
    {
        try
        {
            RunSc("stop WinDivert");
            RunSc("delete WinDivert");
            return true;
        }
        catch
        {
            return false;
        }
    }
}
