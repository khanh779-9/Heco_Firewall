using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using Heco.WinDivert.Interop;
using Heco.WinDivert.Packet;
using Heco.WinDivert.Structs;

namespace Heco.WinDivert.Device;

[SupportedOSPlatform("windows")]
[DebuggerDisplay("Filter = {Filter}, Layer = {Layer}")]
public class WinDivertDevice : SafeHandleZeroOrMinusOneIsInvalid
{
    private ThreadPoolBoundHandle? _boundHandle;

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

    internal ThreadPoolBoundHandle GetThreadPoolBoundHandle()
    {
        if (_boundHandle == null)
        {
            Interlocked.CompareExchange(ref _boundHandle, ThreadPoolBoundHandle.BindHandle(this), null);
        }
        return _boundHandle!;
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

        Filter = filter;

        Layer = layer;
        Priority = priority;
        Flags = flags;
    }

    // ── Synchronous I/O (byte[] based, for backward compat) ──

    public int Recv(byte[] packet, ref uint recvLen, ref WINDIVERT_ADDRESS addr)
    {
        if (!WinDivertNative.WinDivertRecv(GetHandle(), packet, (uint)packet.Length, ref recvLen, ref addr))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return (int)recvLen;
    }

    public int Send(byte[] packet, uint length, ref WINDIVERT_ADDRESS addr)
    {
        uint sendLen = 0;
        if (!WinDivertNative.WinDivertSend(GetHandle(), packet, length, ref sendLen, ref addr))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return (int)sendLen;
    }

    // ── Async I/O with native memory (true overlapped) ──

    public ValueTask<int> RecvAsync(WinDivertPacket packet, ref WINDIVERT_ADDRESS addr, CancellationToken ct = default)
    {
        var operation = new WinDivertRecvOperation(this, packet, ref addr);
        return operation.IOControlAsync(ct);
    }

    public ValueTask<int> SendAsync(WinDivertPacket packet, ref WINDIVERT_ADDRESS addr, CancellationToken ct = default)
    {
        return SendAsync(packet, (uint)packet.Length, ref addr, ct);
    }

    public ValueTask<int> SendAsync(WinDivertPacket packet, uint length, ref WINDIVERT_ADDRESS addr, CancellationToken ct = default)
    {
        if (length == 0)
            throw new ArgumentOutOfRangeException(nameof(length));

        var operation = new WinDivertSendOperation(this, packet, ref addr);
        return operation.IOControlAsync(ct);
    }

    // ── Shutdown ──

    public bool Shutdown(WinDivertShutdown how = WinDivertShutdown.Both)
    {
        return WinDivertNative.WinDivertShutdown(GetHandle(), how);
    }

    // ── Params ──

    public long GetParam(WinDivertParam param)
    {
        if (!WinDivertNative.WinDivertGetParam(GetHandle(), param, out var value))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return (long)value;
    }

    public void SetParam(WinDivertParam param, long value)
    {
        if (param == WinDivertParam.QueueSize && (value < 65535 || value > 33554432))
            throw new ArgumentOutOfRangeException(nameof(value));
        if (param == WinDivertParam.QueueTime && (value < 100 || value > 16000))
            throw new ArgumentOutOfRangeException(nameof(value));
        if (param == WinDivertParam.QueueLength && (value < 32 || value > 16384))
            throw new ArgumentOutOfRangeException(nameof(value));

        if (!WinDivertNative.WinDivertSetParam(GetHandle(), param, (ulong)value))
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    // ── Handle management ──

    internal nint GetHandle()
    {
        if (IsInvalid || IsClosed)
            throw new ObjectDisposedException(nameof(WinDivertDevice));
        return handle;
    }

    protected override bool ReleaseHandle()
    {
        Interlocked.Exchange(ref _boundHandle, null)?.Dispose();
        return WinDivertNative.WinDivertClose(handle);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            Interlocked.Exchange(ref _boundHandle, null)?.Dispose();
        base.Dispose(disposing);
    }
}
