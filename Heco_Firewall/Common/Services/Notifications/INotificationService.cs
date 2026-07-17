using System;

namespace Heco.Common.Services.Notifications;

/// <summary>
///   Shows block notifications via balloon tips or toasts.
///   Triggered by Event 5157 watcher and WFP block events.
/// </summary>
public interface INotificationService
{
    /// <summary>Whether notifications are enabled.</summary>
    bool IsEnabled { get; set; }

    /// <summary>Show a block notification for a connection.</summary>
    void ShowBlockNotification(BlockNotificationInfo info);

    /// <summary>Show a general information notification.</summary>
    void ShowInfo(string title, string message);

    /// <summary>Show a warning notification.</summary>
    void ShowWarning(string title, string message);

    /// <summary>Clear all pending notifications.</summary>
    void ClearAll();
}

/// <summary>
///   Information about a blocked connection for notification display.
/// </summary>
public sealed class BlockNotificationInfo
{
    public string ProcessName { get; set; } = string.Empty;
    public uint ProcessId { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public string LocalAddress { get; set; } = string.Empty;
    public ushort LocalPort { get; set; }
    public string RemoteAddress { get; set; } = string.Empty;
    public ushort RemotePort { get; set; }
    public string? Direction { get; set; }
    public string? RuleName { get; set; }
    public string? ProfileName { get; set; }
    public string? Country { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.Now;
}
