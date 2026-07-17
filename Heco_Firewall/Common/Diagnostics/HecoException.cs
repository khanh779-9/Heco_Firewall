using System;

namespace Heco.Common.Diagnostics;

/// <summary>
///   Base exception for all Heco Firewall errors.
///   Wraps a WFP / Win32 error code with contextual information.
/// </summary>
public class HecoException : Exception
{
    /// <summary>The native error code returned by the WFP API.</summary>
    public uint NativeErrorCode { get; }

    public HecoException(uint nativeErrorCode, string message)
        : base($"{message} (0x{nativeErrorCode:X8})")
    {
        NativeErrorCode = nativeErrorCode;
    }

    public HecoException(uint nativeErrorCode, string message, Exception inner)
        : base($"{message} (0x{nativeErrorCode:X8})", inner)
    {
        NativeErrorCode = nativeErrorCode;
    }

    /// <summary>
    ///   Throw if <paramref name="nativeErrorCode"/> is not Success (0).
    /// </summary>
    public static void ThrowOnFailure(uint nativeErrorCode, string context)
    {
        if (nativeErrorCode == 0)
            return;

        throw new HecoException(nativeErrorCode,
            $"{context} failed with code 0x{nativeErrorCode:X8}");
    }
}
