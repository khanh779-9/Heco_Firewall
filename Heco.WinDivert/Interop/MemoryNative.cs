using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Heco.WinDivert.Interop;

internal static unsafe class MemoryNative
{
    public static IntPtr AllocZeroed(int size)
    {
#if NET6_0_OR_GREATER
        return (IntPtr)NativeMemory.AllocZeroed((nuint)size);
#else
        var ptr = Marshal.AllocHGlobal(size);
        new Span<byte>(ptr.ToPointer(), size).Clear();
        return ptr;
#endif
    }

    public static void Free(IntPtr ptr)
    {
#if NET6_0_OR_GREATER
        NativeMemory.Free(ptr.ToPointer());
#else
        Marshal.FreeHGlobal(ptr);
#endif
    }
}
