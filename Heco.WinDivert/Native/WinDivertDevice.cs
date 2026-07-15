using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using static Heco.WinDivert.Native.WinDivertStructs;

namespace Heco.WinDivert.Native;

[SupportedOSPlatform("windows")]
[DebuggerDisplay("Filter = {Filter}, Layer = {Layer}")]
public class WinDivertDevice : SafeHandleZeroOrMinusOneIsInvalid
{
    public string Filter { get; }
    public WinDivertLayer Layer { get; }
    public short Priority { get; }
    public WinDivertFlag Flags { get; }

    public Version Version
    {
        get
        {
            var major = GetParam(WinDivertParam.VersionMajor);
            var minor = GetParam(WinDivertParam.VersionMinor);
            return new Version((int)major, (int)minor);
        }
    }

    public long QueueLength
    {
        get => GetParam(WinDivertParam.QueueLength);
        set => SetParam(WinDivertParam.QueueLength, value);
    }

    public long QueueTime
    {
        get => GetParam(WinDivertParam.QueueTime);
        set => SetParam(WinDivertParam.QueueTime, value);
    }

    public long QueueSize
    {
        get => GetParam(WinDivertParam.QueueSize);
        set => SetParam(WinDivertParam.QueueSize, value);
    }

    public WinDivertDevice(string filter, WinDivertLayer layer, short priority = 0, WinDivertFlag flags = WinDivertFlag.None)
        : base(ownsHandle: true)
    {
        if (layer != WinDivertLayer.Network && flags == WinDivertFlag.None)
            flags = WinDivertFlag.Sniff | WinDivertFlag.RecvOnly;

        var rawHandle = WinDivertNative.WinDivertOpen(filter, (int)layer, priority, (ulong)flags);
        var lastError = Marshal.GetLastWin32Error();
        SetHandle(rawHandle);

        if (IsInvalid)
            throw new Win32Exception(lastError);

        try { Filter = WinDivertNative.FormatFilter(filter, layer); }
        catch { Filter = filter; }

        Layer = layer;
        Priority = priority;
        Flags = flags;
    }

    public int Recv(byte[] packet, ref uint recvLen, ref WINDIVERT_ADDRESS addr)
    {
        if (!WinDivertNative.WinDivertRecv(handle, packet, (uint)packet.Length, ref recvLen, ref addr))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return (int)recvLen;
    }

    public int Send(byte[] packet, uint length, ref WINDIVERT_ADDRESS addr)
    {
        uint sendLen = 0;
        if (!WinDivertNative.WinDivertSend(handle, packet, length, ref sendLen, ref addr))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return (int)sendLen;
    }

    public bool Shutdown(WinDivertShutdown how = WinDivertShutdown.Both)
    {
        return WinDivertNative.WinDivertShutdown(handle, (byte)how);
    }

    public long GetParam(WinDivertParam param)
    {
        ulong value;
        if (!WinDivertNative.WinDivertGetParam(handle, (uint)param, out value))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return (long)value;
    }

    public void SetParam(WinDivertParam param, long value)
    {
        if (!WinDivertNative.WinDivertSetParam(handle, (uint)param, (ulong)value))
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    protected override bool ReleaseHandle()
    {
        return WinDivertNative.WinDivertClose(handle);
    }
}
