using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.Versioning;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Heco_Firewall.ViewModels;
using Heco_Firewall.Windows;

namespace Heco_Firewall;

/// <summary>
///   Main application window — hosts navigation sidebar and page content.
/// </summary>
[SupportedOSPlatform("windows")]
public partial class MainWindow : Window
{
    private readonly MainViewModel _vm;
    private readonly Dictionary<string, PageConfig> _pages;

    public MainWindow()
    {
        InitializeComponent();

        _vm = (MainViewModel)DataContext;

        // Build the page navigation map after InitializeComponent
        // so all named elements are available.
        _pages = new Dictionary<string, PageConfig>(StringComparer.OrdinalIgnoreCase)
        {
            ["Dashboard"]   = new(PageDashboard,   NavDashboard,   "Dashboard"),
            ["Rules"]       = new(PageRules,        NavRules,       "Firewall Rules",      () => _vm.Rules.LoadRules()),
            ["Connections"] = new(PageConnections,  NavConnections, "Live Connections"),
            ["Settings"]    = new(PageSettings,     NavSettings,    "Settings"),
            ["Profiles"]    = new(PageProfiles,     NavProfiles,    "Application Profiles", () => _vm.Profiles.Refresh()),
            ["Blocklists"]  = new(PageBlocklists,   NavBlocklists,  "Blocklists",           () => _vm.Blocklists.Refresh()),
            ["Activity"]    = new(PageActivity,     NavActivity,    "Activity Log",         () => _vm.Activity.RefreshStatus()),
        };

        // Allow dragging the window via the title bar
        MouseDown += OnTitleBarMouseDown;

        // Show default page at startup
        ShowPage("Dashboard");

        // Initialize system tray icon once the window is fully loaded
        // (StartupUri hasn't finished creating the window during App.OnStartup)
        Loaded += (_, _) =>
        {
            if (Application.Current is App app)
                app.InitializeTray(_vm);
        };
    }

    // ═════════════════════════════════════════════════════════════════
    //  Navigation
    // ═════════════════════════════════════════════════════════════════

    /// <summary>
    ///   Navigate to the specified page by name.
    ///   Collapses all pages, then shows the target page and highlights its nav button.
    /// </summary>
    private void ShowPage(string pageName)
    {
        // Reset all pages and nav buttons
        foreach (var cfg in _pages.Values)
        {
            cfg.Page.Visibility = Visibility.Collapsed;
            cfg.NavButton.Tag = null;
        }

        // Activate the target page
        if (_pages.TryGetValue(pageName, out var active))
        {
            active.Page.Visibility = Visibility.Visible;
            PageTitle.Text = active.Title;
            active.NavButton.Tag = "Active";
            active.OnActivated?.Invoke();
        }
    }

    private void NavDashboard_Click(object sender, RoutedEventArgs e) => ShowPage("Dashboard");
    private void NavRules_Click(object sender, RoutedEventArgs e) => ShowPage("Rules");
    private void NavConnections_Click(object sender, RoutedEventArgs e) => ShowPage("Connections");
    private void NavSettings_Click(object sender, RoutedEventArgs e) => ShowPage("Settings");
    private void NavProfiles_Click(object sender, RoutedEventArgs e) => ShowPage("Profiles");
    private void NavBlocklists_Click(object sender, RoutedEventArgs e) => ShowPage("Blocklists");
    private void NavActivity_Click(object sender, RoutedEventArgs e) => ShowPage("Activity");

    // ═════════════════════════════════════════════════════════════════
    //  Window Controls
    // ═════════════════════════════════════════════════════════════════

    private void OnTitleBarMouseDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton == MouseButton.Left)
            DragMove();
    }

    private void Minimize_Click(object sender, RoutedEventArgs e)
    {
        WindowState = WindowState.Minimized;
    }

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        // Close button hides to tray instead of exiting the app
        if (_vm.Settings.AppSettings.MinimizeToTray)
        {
            Hide();
        }
        else
        {
            // Fallback: minimize if tray is disabled
            WindowState = WindowState.Minimized;
        }
    }

    private void OnStateChanged(object? sender, EventArgs e)
    {
        if (WindowState == WindowState.Minimized &&
            _vm.Settings.AppSettings.MinimizeToTray)
        {
            Hide();
        }
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        // Intercept window close (Alt+F4, taskbar close) to hide to tray
        if (_vm.Settings.AppSettings.MinimizeToTray)
        {
            e.Cancel = true;
            Hide();
            return;
        }

        // If tray mode is off, confirm before shutdown
        var confirm = DialogWindow.ShowQuestion(
            "Are you sure you want to exit Heco Firewall?",
            "Exit Heco Firewall");
        if (confirm != DialogBoxResult.Yes)
        {
            e.Cancel = true;
            return;
        }

        base.OnClosing(e);
    }

    // ═════════════════════════════════════════════════════════════════
    //  Page Configuration Record
    // ═════════════════════════════════════════════════════════════════

    /// <summary>
    ///   Associates a page element with its navigation button, display title,
    ///   and an optional callback invoked when the page is activated.
    /// </summary>
    private readonly record struct PageConfig(
        FrameworkElement Page,
        Button NavButton,
        string Title,
        Action? OnActivated = null);
}
