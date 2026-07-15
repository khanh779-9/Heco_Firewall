using System;
using System.IO;

namespace Heco.Common.Services.Diagnostics;

/// <summary>
///   Simple file-based logger for Heco Services.
///   Writes to %APPDATA%\Heco\logs\hecoview.log with rotation.
/// </summary>
public static class Logger
{
    private static readonly object _sync = new();
    private static string? _logPath;
    private static long _maxSize = 5 * 1024 * 1024; // 5 MB

    /// <summary>Initialize the logger. Called once at startup.</summary>
    public static void Initialize(string? customPath = null)
    {
        if (customPath is not null)
        {
            _logPath = customPath;
        }
        else
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var logDir = Path.Combine(appData, "Heco", "logs");
            Directory.CreateDirectory(logDir);
            _logPath = Path.Combine(logDir, "hecoview.log");
        }
    }

    /// <summary>Write an info-level message.</summary>
    public static void Info(string message)
    {
        Write("INFO", message);
    }

    /// <summary>Write a warning-level message.</summary>
    public static void Warn(string message)
    {
        Write("WARN", message);
    }

    /// <summary>Write an error-level message.</summary>
    public static void Error(string message, Exception? ex = null)
    {
        Write("ERROR", ex is null ? message : $"{message} | {ex.GetType().Name}: {ex.Message}");
    }

    /// <summary>Write a debug-level message.</summary>
    public static void Debug(string message)
    {
#if DEBUG
        Write("DEBUG", message);
#endif
    }

    private static void Write(string level, string message)
    {
        if (_logPath is null) return;

        lock (_sync)
        {
            try
            {
                RotateIfNeeded();
                File.AppendAllText(_logPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{level}] {message}{Environment.NewLine}");
            }
            catch
            {
                // Swallow logger errors — never crash the app
            }
        }
    }

    private static void RotateIfNeeded()
    {
        if (_logPath is null) return;
        var fi = new FileInfo(_logPath);
        if (fi.Exists && fi.Length >= _maxSize)
        {
            var rotated = _logPath + ".old";
            if (File.Exists(rotated))
                File.Delete(rotated);
            File.Move(_logPath, rotated);
        }
    }
}
