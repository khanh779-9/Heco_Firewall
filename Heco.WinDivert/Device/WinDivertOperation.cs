using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using System.Threading.Tasks.Sources;
using Heco.WinDivert.Interop;
using Heco.WinDivert.Structs;

namespace Heco.WinDivert.Device;

[SupportedOSPlatform("windows")]
internal abstract class WinDivertOperation : IDisposable, IValueTaskSource<int>
{
    protected readonly WinDivertDevice Device;
    private readonly unsafe NativeOverlapped* _nativeOverlapped;
    private ManualResetValueTaskSourceCore<int> _taskSource;
    private static readonly unsafe IOCompletionCallback _completionCallback = IOCompletionCallback;

    public unsafe WinDivertOperation(WinDivertDevice device)
    {
        Device = device;
        _nativeOverlapped = device.GetThreadPoolBoundHandle().AllocateNativeOverlapped(_completionCallback, this, null);
    }

    public virtual async ValueTask<int> IOControlAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using (cancellationToken.Register(CancelIoEx))
        {
            return await IOControlAsyncCore();
        }

        unsafe void CancelIoEx()
        {
            Kernel32Native.CancelIoEx(Device.DangerousGetHandle(), _nativeOverlapped);
        }

        unsafe ValueTask<int> IOControlAsyncCore()
        {
            int length = 0;
            return IOControl(&length, _nativeOverlapped)
                ? new ValueTask<int>(length)
                : new ValueTask<int>(this, _taskSource.Version);
        }
    }

    protected abstract unsafe bool IOControl(int* pLength, NativeOverlapped* nativeOverlapped);

    private static unsafe void IOCompletionCallback(uint errorCode, uint numBytes, NativeOverlapped* pOVERLAP)
    {
        var operation = (WinDivertOperation)ThreadPoolBoundHandle.GetNativeOverlappedState(pOVERLAP)!;
        if (errorCode == 0)
        {
            operation._taskSource.SetResult((int)numBytes);
        }
        else if (errorCode == 995)
        {
            operation._taskSource.SetException(new TaskCanceledException());
        }
        else
        {
            operation._taskSource.SetException(new Win32Exception((int)errorCode));
        }
    }

    public virtual unsafe void Dispose()
    {
        Device.GetThreadPoolBoundHandle().FreeNativeOverlapped(_nativeOverlapped);
    }

    int IValueTaskSource<int>.GetResult(short token) => _taskSource.GetResult(token);
    ValueTaskSourceStatus IValueTaskSource<int>.GetStatus(short token) => _taskSource.GetStatus(token);
    void IValueTaskSource<int>.OnCompleted(Action<object?> continuation, object? state, short token, ValueTaskSourceOnCompletedFlags flags)
        => _taskSource.OnCompleted(continuation, state, token, flags);
}
