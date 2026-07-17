using System;
using System.ComponentModel;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.Versioning;
using System.Windows;
using Hardcodet.Wpf.TaskbarNotification;
using Heco_Firewall.ViewModels;
using Heco_Firewall.Windows;

namespace Heco_Firewall.Tray;

/// <summary>
///   System tray icon service using Hardcodet.NotifyIcon.Wpf.
///   Dynamically changes the tray icon based on firewall state:
///   - Green shield  = active (protection ON)
///   - Gray shield   = disabled (protection OFF)
///   - Red shield    = error / WinDivert unavailable
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class TrayService : IDisposable
{
    private readonly MainViewModel _mainVm;
    private TaskbarIcon? _trayIcon;

    public TrayService(MainViewModel mainVm)
    {
        _mainVm = mainVm;
    }

    /// <summary>Initialize the tray icon and context menu.</summary>
    public void Initialize()
    {
        _trayIcon = new TaskbarIcon
        {
            Icon = GenerateShieldIcon(TrayIconState.Disabled),
            ToolTipText = "Heco Firewall — Disabled",
            Visibility = Visibility.Visible
        };

        // Context menu
        var menu = new System.Windows.Controls.ContextMenu();
        menu.SetResourceReference(System.Windows.Controls.Control.StyleProperty, typeof(System.Windows.Controls.ContextMenu));

        var showItem = new System.Windows.Controls.MenuItem
        {
            Header = "Show Window"
        };
        showItem.SetResourceReference(System.Windows.Controls.Control.StyleProperty, typeof(System.Windows.Controls.MenuItem));
        showItem.Click += (_, _) => ShowWindow();
        menu.Items.Add(showItem);

        menu.Items.Add(new System.Windows.Controls.Separator());

        var toggleItem = new System.Windows.Controls.MenuItem
        {
            Header = "Toggle Firewall"
        };
        toggleItem.SetResourceReference(System.Windows.Controls.Control.StyleProperty, typeof(System.Windows.Controls.MenuItem));
        toggleItem.Click += async (_, _) => await _mainVm.ToggleEngineAsync();
        menu.Items.Add(toggleItem);

        menu.Items.Add(new System.Windows.Controls.Separator());

        var exitItem = new System.Windows.Controls.MenuItem
        {
            Header = "Exit"
        };
        exitItem.SetResourceReference(System.Windows.Controls.Control.StyleProperty, typeof(System.Windows.Controls.MenuItem));
        exitItem.Click += async (_, _) =>
        {
            var confirm = DialogWindow.ShowQuestion(
                "Are you sure you want to exit Heco Firewall?",
                "Exit Heco Firewall");
            if (confirm != DialogBoxResult.Yes) return;

            _trayIcon?.Dispose();
            Application.Current.Shutdown();
        };
        menu.Items.Add(exitItem);

        _trayIcon.ContextMenu = menu;

        // Double-click restores window
        _trayIcon.TrayMouseDoubleClick += (_, _) => ShowWindow();

        // Subscribe to engine state changes
        _mainVm.PropertyChanged += OnMainVmPropertyChanged;
        UpdateIcon();
    }

    /// <summary>Show a toast notification.</summary>
    public void ShowNotification(string title, string message)
    {
        ToastWindow.Show(Application.Current.MainWindow, title, message, ToastType.Info, 4000);
    }

    /// <summary>Show a toast for blocked connections.</summary>
    public void ShowBlockNotification(string processName, string remoteAddress, ushort remotePort)
    {
        ToastWindow.Show(Application.Current.MainWindow, "Blocked Connection",
            $"{processName} → {remoteAddress}:{remotePort}", ToastType.Blocked, 6000);
    }

    private void OnMainVmPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainViewModel.IsEngineOpen)
            || e.PropertyName == nameof(MainViewModel.HasWarning))
        {
            UpdateIcon();
        }
    }

    private void UpdateIcon()
    {
        if (_trayIcon == null) return;

        TrayIconState state;
        string tooltip;

        if (_mainVm.HasWarning)
        {
            state = TrayIconState.Error;
            tooltip = "Heco Firewall — Error";
        }
        else if (_mainVm.IsEngineOpen)
        {
            state = TrayIconState.Active;
            tooltip = "Heco Firewall — Active";
        }
        else
        {
            state = TrayIconState.Disabled;
            tooltip = "Heco Firewall — Disabled";
        }

        var oldIcon = _trayIcon.Icon;
        _trayIcon.Icon = GenerateShieldIcon(state);
        _trayIcon.ToolTipText = tooltip;
        oldIcon?.Dispose();
    }

    private static void ShowWindow()
    {
        foreach (Window window in Application.Current.Windows)
        {
            if (window is MainWindow main)
            {
                main.Show();
                main.WindowState = WindowState.Normal;
                main.Activate();
                return;
            }
        }
    }

    /// <summary>
    ///   Generate a 16×16 shield icon with state-dependent color.
    ///   - <see cref="TrayIconState.Active"/>   → green shield
    ///   - <see cref="TrayIconState.Disabled"/> → gray shield
    ///   - <see cref="TrayIconState.Error"/>    → red shield
    /// </summary>
    private static Icon GenerateShieldIcon(TrayIconState state)
    {
        var (fillColor, strokeColor) = state switch
        {
            TrayIconState.Active   => (Color.FromArgb(34, 197, 94),  Color.FromArgb(22, 163, 74)),   // green
            TrayIconState.Error    => (Color.FromArgb(239, 68, 68),  Color.FromArgb(220, 38, 38)),   // red
            _                      => (Color.FromArgb(156, 163, 175), Color.FromArgb(107, 114, 128)), // gray
        };

        var bmp = new Bitmap(16, 16);
        using var g = Graphics.FromImage(bmp);
        g.Clear(Color.Transparent);
        g.SmoothingMode = SmoothingMode.AntiAlias;

        // Shield path: pointed bottom, curved top
        using var fillBrush = new SolidBrush(fillColor);
        using var strokePen = new Pen(strokeColor, 1.2f);

        var pts = new[]
        {
            new PointF(3, 1.5f),
            new PointF(8, 1),
            new PointF(13, 1.5f),
            new PointF(14, 5),
            new PointF(13, 9),
            new PointF(8, 14),
            new PointF(3, 9),
            new PointF(2, 5),
        };
        g.FillPolygon(fillBrush, pts);
        g.DrawPolygon(strokePen, pts);

        // Inner highlight (subtle)
        using var highlightPen = new Pen(Color.FromArgb(60, 255, 255, 255), 0.8f);
        var hl = new[]
        {
            new PointF(4, 3),
            new PointF(8, 2.5f),
            new PointF(12, 3),
            new PointF(12.5f, 5),
        };
        g.DrawCurve(highlightPen, hl);

        var hIcon = bmp.GetHicon();
        return Icon.FromHandle(hIcon);
    }

    public void Dispose()
    {
        if (_trayIcon != null)
        {
            _mainVm.PropertyChanged -= OnMainVmPropertyChanged;
            _trayIcon.Dispose();
            _trayIcon = null;
        }
    }
}
