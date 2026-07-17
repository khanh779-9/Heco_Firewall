using System;
using System.Diagnostics;
using Heco.WinDivert.Models;
using Heco.WinDivert.Structs;
using Heco.WinDivert.Interop;

namespace Heco.WinDivert.Services;

public static class WinDivertDriverManager
{
    public static int? LastErrorCode { get; private set; }
    public static string? LastErrorMessage { get; private set; }

    public static Version? GetDriverVersion()
    {
        try
        {
            var handle = WinDivertNative.WinDivertOpen("true", (int)WinDivertLayer.Network, 0, (ulong)WinDivertFlag.Sniff | (ulong)WinDivertFlag.RecvOnly);
            if (handle == IntPtr.Zero || handle == new IntPtr(-1))
                return null;

            try
            {
                ulong major = 0, minor = 0;
                if (WinDivertNative.WinDivertGetParam(handle, WinDivertParam.VersionMajor, out major) &&
                    WinDivertNative.WinDivertGetParam(handle, WinDivertParam.VersionMinor, out minor))
                {
                    return new Version((int)major, (int)minor);
                }
                return null;
            }
            finally
            {
                WinDivertNative.WinDivertClose(handle);
            }
        }
        catch
        {
            return null;
        }
    }

    public static string? GetErrorHint(int? errorCode) => Win32Errors.GetHint(errorCode);

    internal static void SetError(int? code, string detail)
    {
        LastErrorCode = code;
        LastErrorMessage = detail;
        Debug.WriteLine($"[WinDivertDriverManager] Error {code}: {detail}");
    }

    internal static void ClearError()
    {
        LastErrorCode = null;
        LastErrorMessage = null;
    }
}
