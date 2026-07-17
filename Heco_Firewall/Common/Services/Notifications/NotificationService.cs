using System;
using System.Collections.Generic;
using Heco.Common.Services.Notifications;
using Heco.Common.Services.Diagnostics;

namespace Heco.Common.Services.Notifications;

/// <summary>
///   Shows block notifications. In a WPF app, this integrates with the system tray
///   (via Hardcodet.NotifyIcon.Wpf) or uses Windows balloon tips.
///   This is the service layer — UI integration happens in Heco_Firewall.
/// </summary>
public sealed class NotificationService : INotificationService
{
    private readonly List<BlockNotificationInfo> _notificationHistory = new();
    private readonly int _maxHistory = 1000;

    public bool IsEnabled { get; set; } = true;

    /// <summary>Event raised when a block notification should be shown.</summary>
    public event EventHandler<BlockNotificationInfo>? BlockNotification;

    /// <summary>Event raised for info/warning notifications.</summary>
    public event EventHandler<NotificationEventArgs>? InfoNotification;

    /// <summary>History of recent block notifications.</summary>
    public IReadOnlyList<BlockNotificationInfo> NotificationHistory => _notificationHistory.AsReadOnly();

    public void ShowBlockNotification(BlockNotificationInfo info)
    {
        if (!IsEnabled) return;

        // Add to history
        lock (_notificationHistory)
        {
            _notificationHistory.Add(info);
            while (_notificationHistory.Count > _maxHistory)
                _notificationHistory.RemoveAt(0);
        }

        BlockNotification?.Invoke(this, info);
        Logger.Info($"Block notification: {info.ProcessName} → {info.RemoteAddress}:{info.RemotePort}");
    }

    public void ShowInfo(string title, string message)
    {
        if (!IsEnabled) return;
        InfoNotification?.Invoke(this, new NotificationEventArgs(title, message, NotificationType.Info));
    }

    public void ShowWarning(string title, string message)
    {
        if (!IsEnabled) return;
        InfoNotification?.Invoke(this, new NotificationEventArgs(title, message, NotificationType.Warning));
    }

    public void ClearAll()
    {
        lock (_notificationHistory)
        {
            _notificationHistory.Clear();
        }
    }
}

public sealed class NotificationEventArgs : EventArgs
{
    public string Title { get; }
    public string Message { get; }
    public NotificationType Type { get; }

    public NotificationEventArgs(string title, string message, NotificationType type)
    {
        Title = title;
        Message = message;
        Type = type;
    }
}

public enum NotificationType
{
    Info,
    Warning,
    Error
}
