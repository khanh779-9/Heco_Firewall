namespace Heco.WinDivert.Models;

/// <summary>Win32 system error codes commonly encountered when working with WinDivert.
/// Reference: https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes</summary>
public enum Win32ErrorCode
{
    #region 0xxx — Success & basic file/device errors
    /// <summary>ERROR_SUCCESS (0) — The operation completed successfully.</summary>
    ERROR_SUCCESS = 0,
    /// <summary>ERROR_FILE_NOT_FOUND (2) — WinDivert driver .sys not found.</summary>
    ERROR_FILE_NOT_FOUND = 2,
    /// <summary>ERROR_PATH_NOT_FOUND (3) — DLL/helper path not found.</summary>
    ERROR_PATH_NOT_FOUND = 3,
    /// <summary>ERROR_ACCESS_DENIED (5) — Admin privilege required for driver operations.</summary>
    ERROR_ACCESS_DENIED = 5,
    /// <summary>ERROR_INVALID_HANDLE (6) — WinDivert handle is invalid (closed or not opened).</summary>
    ERROR_INVALID_HANDLE = 6,
    /// <summary>ERROR_NOT_ENOUGH_MEMORY (8) — Insufficient memory for buffer allocation.</summary>
    ERROR_NOT_ENOUGH_MEMORY = 8,
    /// <summary>ERROR_BAD_FORMAT (11) — DLL architecture mismatch (e.g. 32-bit process loading 64-bit DLL).</summary>
    ERROR_BAD_FORMAT = 11,
    /// <summary>ERROR_INVALID_DATA (13) — Invalid filter string or malformed packet data.</summary>
    ERROR_INVALID_DATA = 13,
    /// <summary>ERROR_OUTOFMEMORY (14) — Out of memory.</summary>
    ERROR_OUTOFMEMORY = 14,
    /// <summary>ERROR_NOT_READY (21) — Device/driver not ready.</summary>
    ERROR_NOT_READY = 21,
    /// <summary>ERROR_SHARING_VIOLATION (32) — File/DLL in use by another process.</summary>
    ERROR_SHARING_VIOLATION = 32,
    /// <summary>ERROR_HANDLE_EOF (38) — Unexpected end of packet data.</summary>
    ERROR_HANDLE_EOF = 38,
    #endregion

    #region 08x–13x — Parameter, buffer, IO
    /// <summary>ERROR_FILE_EXISTS (80) — File already exists.</summary>
    ERROR_FILE_EXISTS = 80,
    /// <summary>ERROR_INVALID_PARAMETER (87) — Bad filter string, layer, priority, or flags.</summary>
    ERROR_INVALID_PARAMETER = 87,
    /// <summary>ERROR_INSUFFICIENT_BUFFER (122) — Packet buffer too small.</summary>
    ERROR_INSUFFICIENT_BUFFER = 122,
    /// <summary>ERROR_MOD_NOT_FOUND (126) — WinDivert.dll not found on disk.</summary>
    ERROR_MOD_NOT_FOUND = 126,
    /// <summary>ERROR_PROC_NOT_FOUND (127) — WinDivert export function not found in DLL.</summary>
    ERROR_PROC_NOT_FOUND = 127,
    /// <summary>ERROR_ALREADY_EXISTS (183) — Driver handle already open in this process.</summary>
    ERROR_ALREADY_EXISTS = 183,
    #endregion

    #region 2xx–5xx — IO, timeout, service
    /// <summary>ERROR_WAIT_TIMEOUT (258) — Wait timeout reached.</summary>
    ERROR_WAIT_TIMEOUT = 258,
    /// <summary>ERROR_IO_PENDING (997) — Overlapped IO not yet completed.</summary>
    ERROR_IO_PENDING = 997,
    /// <summary>ERROR_SERVICE_DOES_NOT_EXIST (1060) — WinDivert kernel service not installed.</summary>
    ERROR_SERVICE_DOES_NOT_EXIST = 1060,
    /// <summary>ERROR_SERVICE_NOT_ACTIVE (1062) — Driver service not started.</summary>
    ERROR_SERVICE_NOT_ACTIVE = 1062,
    /// <summary>ERROR_SERVICE_REQUEST_TIMEOUT (1053) — WinDivert service did not respond in time.</summary>
    ERROR_SERVICE_REQUEST_TIMEOUT = 1053,
    /// <summary>ERROR_SERVICE_ALREADY_RUNNING (1056) — Driver already running.</summary>
    ERROR_SERVICE_ALREADY_RUNNING = 1056,
    /// <summary>ERROR_DLL_INIT_FAILED (1114) — WinDivert.dll failed to initialise (DllMain returned FALSE).</summary>
    ERROR_DLL_INIT_FAILED = 1114,
    /// <summary>ERROR_DEVICE_NOT_CONNECTED (1167) — Kernel driver not started or has been removed.</summary>
    ERROR_DEVICE_NOT_CONNECTED = 1167,
    /// <summary>ERROR_CANCELLED (1223) — Operation cancelled by user or shutdown.</summary>
    ERROR_CANCELLED = 1223,
    /// <summary>ERROR_TIMEOUT (1460) — Generic timeout waiting for driver response.</summary>
    ERROR_TIMEOUT = 1460,
    #endregion

    #region 9xx — IO abort & completion
    /// <summary>ERROR_IO_INCOMPLETE (996) — Overlapped IO incomplete.</summary>
    ERROR_IO_INCOMPLETE = 996,
    /// <summary>ERROR_OPERATION_ABORTED (995) — IO cancelled due to handle close or shutdown.</summary>
    ERROR_OPERATION_ABORTED = 995,
    #endregion

    #region 10xxx — WinSock errors (returned by WinDivertRecv/Send)
    /// <summary>WSAEACCES (10013) — Socket permission denied.</summary>
    WSAEACCES = 10013,
    /// <summary>WSAEADDRINUSE (10048) — Address already in use.</summary>
    WSAEADDRINUSE = 10048,
    /// <summary>WSAENETUNREACH (10051) — Network is unreachable.</summary>
    WSAENETUNREACH = 10051,
    /// <summary>WSAEHOSTUNREACH (10065) — Host is unreachable.</summary>
    WSAEHOSTUNREACH = 10065,
    /// <summary>WSAETIMEDOUT (10060) — Connection timed out.</summary>
    WSAETIMEDOUT = 10060,
    /// <summary>WSAECONNREFUSED (10061) — Connection refused.</summary>
    WSAECONNREFUSED = 10061,
    /// <summary>WSAECONNRESET (10054) — Connection reset by peer.</summary>
    WSAECONNRESET = 10054,
    /// <summary>WSAENOBUFS (10055) — No buffer space available.</summary>
    WSAENOBUFS = 10055,
    #endregion
}

/// <summary>Helper to look up Win32 error codes and provide hints.</summary>
public static class Win32Errors
{
    /// <summary>Returns a description for the given error code.</summary>
    public static string GetDescription(int errorCode) => ((Win32ErrorCode)errorCode) switch
    {
        Win32ErrorCode.ERROR_SUCCESS                => "The operation completed successfully",
        Win32ErrorCode.ERROR_FILE_NOT_FOUND          => "WinDivert driver not installed — run as Administrator to auto-install",
        Win32ErrorCode.ERROR_PATH_NOT_FOUND          => "Path not found",
        Win32ErrorCode.ERROR_ACCESS_DENIED           => "Access denied — Administrator privileges required",
        Win32ErrorCode.ERROR_INVALID_HANDLE          => "WinDivert handle is not valid",
        Win32ErrorCode.ERROR_NOT_ENOUGH_MEMORY       => "Not enough memory",
        Win32ErrorCode.ERROR_BAD_FORMAT              => "DLL architecture mismatch (32-bit vs 64-bit)",
        Win32ErrorCode.ERROR_INVALID_DATA            => "Invalid data (filter string or packet)",
        Win32ErrorCode.ERROR_SHARING_VIOLATION       => "File locked by another process",
        Win32ErrorCode.ERROR_HANDLE_EOF              => "End of packet data reached",
        Win32ErrorCode.ERROR_FILE_EXISTS             => "File already exists",
        Win32ErrorCode.ERROR_INVALID_PARAMETER       => "Invalid parameter (filter/layer/priority/flags)",
        Win32ErrorCode.ERROR_INSUFFICIENT_BUFFER     => "Buffer is too small",
        Win32ErrorCode.ERROR_MOD_NOT_FOUND           => "WinDivert.dll not found in output directory",
        Win32ErrorCode.ERROR_PROC_NOT_FOUND          => "Export function not found in WinDivert.dll",
        Win32ErrorCode.ERROR_ALREADY_EXISTS          => "Already exists",
        Win32ErrorCode.ERROR_WAIT_TIMEOUT            => "Wait timeout",
        Win32ErrorCode.ERROR_IO_PENDING              => "I/O pending",
        Win32ErrorCode.ERROR_SERVICE_DOES_NOT_EXIST  => "WinDivert service is not installed",
        Win32ErrorCode.ERROR_SERVICE_NOT_ACTIVE      => "WinDivert service is not running",
        Win32ErrorCode.ERROR_SERVICE_REQUEST_TIMEOUT => "WinDivert service did not respond",
        Win32ErrorCode.ERROR_SERVICE_ALREADY_RUNNING => "WinDivert service is already running",
        Win32ErrorCode.ERROR_IO_INCOMPLETE           => "I/O incomplete",
        Win32ErrorCode.ERROR_DLL_INIT_FAILED         => "WinDivert.dll initialisation failed",
        Win32ErrorCode.ERROR_DEVICE_NOT_CONNECTED    => "WinDivert device not ready (driver not started)",
        Win32ErrorCode.ERROR_CANCELLED               => "Operation cancelled",
        Win32ErrorCode.ERROR_TIMEOUT                 => "Driver response timeout",
        Win32ErrorCode.ERROR_OPERATION_ABORTED       => "I/O aborted",
        Win32ErrorCode.WSAEACCES                     => "Connection denied — insufficient permissions",
        Win32ErrorCode.WSAEADDRINUSE                 => "Address already in use",
        Win32ErrorCode.WSAENETUNREACH                => "Network is unreachable",
        Win32ErrorCode.WSAEHOSTUNREACH               => "Host is unreachable",
        Win32ErrorCode.WSAETIMEDOUT                  => "Connection timed out",
        Win32ErrorCode.WSAECONNREFUSED               => "Connection refused",
        Win32ErrorCode.WSAECONNRESET                 => "Connection reset by peer",
        Win32ErrorCode.WSAENOBUFS                    => "No network buffer space available",
        _ when errorCode > 0 && errorCode < 1000     => $"Windows error: {errorCode}",
        _                                            => $"Unknown error code: {errorCode} (0x{errorCode:X8})"
    };

    /// <summary>Returns a remediation hint for the given error code, or null.</summary>
    public static string? GetHint(int? errorCode) => errorCode is null ? null : ((Win32ErrorCode)errorCode) switch
    {
        Win32ErrorCode.ERROR_FILE_NOT_FOUND          => "Run the application as Administrator so WinDivert can auto-install its driver",
        Win32ErrorCode.ERROR_ACCESS_DENIED           => "Right-click → Run as Administrator",
        Win32ErrorCode.ERROR_BAD_FORMAT              => "Build target must be x64 — check the project configuration",
        Win32ErrorCode.ERROR_MOD_NOT_FOUND           => "Make sure WinDivert.dll is present in the output directory",
        Win32ErrorCode.ERROR_SERVICE_DOES_NOT_EXIST  => "Install the driver: sc create WinDivert type=kernel binPath=...",
        Win32ErrorCode.ERROR_DLL_INIT_FAILED         => "VC++ redistributable may be missing — reinstall or copy the correct DLL version",
        Win32ErrorCode.ERROR_DEVICE_NOT_CONNECTED    => "Driver has not been started — WinDivertOpen has not been called successfully yet",
        Win32ErrorCode.WSAEACCES                     => "Windows Firewall or admin policy is blocking the connection",
        _ => null
    };
}
