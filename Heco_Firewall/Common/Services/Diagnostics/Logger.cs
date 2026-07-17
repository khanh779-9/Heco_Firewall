using System;
using System.IO;

namespace Heco.Common.Services.Diagnostics;

public static class Logger
{
    private static readonly object _sync = new();
    private static string? _logPath;
    private static long _maxSize = 5 * 1024 * 1024;

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

    public static void Info(string message)
    {
        Write("INFO", message);
    }

    public static void Warn(string message)
    {
        Write("WARN", message);
    }

    public static void Error(string message, Exception? ex = null)
    {
        Write("ERROR", ex is null ? message : $"{message} | {ex.GetType().Name}: {ex.Message}");
    }

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
