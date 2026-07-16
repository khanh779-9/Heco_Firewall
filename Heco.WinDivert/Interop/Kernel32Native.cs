using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace Heco.WinDivert.Interop;

internal static class Kernel32Native
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern unsafe bool CancelIoEx(nint hFile, NativeOverlapped* lpOverlapped);
}
