using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using Heco.WinDivert.Interop;
using Heco.WinDivert.Packet;
using Heco.WinDivert.Structs;

namespace Heco.WinDivert.Device;

[SupportedOSPlatform("windows")]
internal sealed class WinDivertSendOperation : WinDivertOperation
{
    private readonly WinDivertPacket _packet;
    private readonly WINDIVERT_ADDRESS _addr;

    public WinDivertSendOperation(WinDivertDevice device, WinDivertPacket packet, ref WINDIVERT_ADDRESS addr)
        : base(device)
    {
        _packet = packet;
        _addr = addr;
    }

    protected override unsafe bool IOControl(int* pLength, NativeOverlapped* nativeOverlapped)
    {
        if (_packet.Length == 0)
            throw new ArgumentOutOfRangeException(nameof(_packet), "Packet length cannot be 0");

        uint sendLen = 0;
        var result = WinDivertNative.WinDivertSendEx(
            Device.DangerousGetHandle(),
            _packet.DangerousGetHandle(),
            (uint)_packet.Length,
            ref sendLen,
            0UL,
            ref Unsafe.AsRef(in _addr),
            (uint)sizeof(WINDIVERT_ADDRESS),
            (IntPtr)nativeOverlapped);

        if (result)
            *pLength = (int)sendLen;

        return result;
    }
}
