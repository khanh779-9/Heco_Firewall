using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using Heco.WinDivert.Interop;
using Heco.WinDivert.Packet;
using Heco.WinDivert.Structs;

namespace Heco.WinDivert.Device;

[SupportedOSPlatform("windows")]
internal sealed class WinDivertRecvOperation : WinDivertOperation
{
    private readonly WinDivertPacket _packet;
    private WINDIVERT_ADDRESS _addr;

    public WinDivertRecvOperation(WinDivertDevice device, WinDivertPacket packet, ref WINDIVERT_ADDRESS addr)
        : base(device)
    {
        _packet = packet;
        _addr = addr;
    }

    public override async ValueTask<int> IOControlAsync(CancellationToken cancellationToken)
    {
        var length = await base.IOControlAsync(cancellationToken);
        _packet.Length = length;
        return length;
    }

    public WINDIVERT_ADDRESS GetAddress() => _addr;

    protected override unsafe bool IOControl(int* pLength, NativeOverlapped* nativeOverlapped)
    {
        int addrLen = sizeof(WINDIVERT_ADDRESS);
        ulong flags = 0;
        uint recvLen = 0;
        uint cap = (uint)_packet.Capacity;

        var result = WinDivertNative.RecvEx(
            Device.DangerousGetHandle(),
            _packet.DangerousGetHandle(),
            cap,
            ref recvLen,
            ref flags,
            ref _addr,
            ref addrLen,
            (nint)nativeOverlapped);

        if (result)
        {
            _packet.Length = (int)recvLen;
            *pLength = (int)recvLen;
        }

        return result;
    }
}
