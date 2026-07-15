using System;
using System.ComponentModel;
using System.Windows;
using System.Windows.Input;
using Heco_Firewall.ViewModels;
using Heco_Firewall.Windows;

namespace Heco_Firewall;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm;

    public MainWindow()
    {
        InitializeComponent();

        _vm = (MainViewModel)DataContext;
        // [WFP DISABLED] _vm.PropertyChanged += OnViewModelPropertyChanged;

        // Allow dragging the window via the title bar
        MouseDown += OnTitleBarMouseDown;

        // Show default page and sync indicator at startup
        ShowPage("Dashboard");

        // Initialize system tray icon (deferred from App.OnStartup because
        // StartupUri has not finished creating the window at that point)
        Loaded += (_, _) =>
        {
            if (Application.Current is App app)
                app.InitializeTray(_vm);
        };
    }

    // [WFP DISABLED]
    // private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    // {
    //     if (e.PropertyName == nameof(MainViewModel.IsEngineOpen))
    //         UpdateEngineStatus();
    // }

    // [WFP DISABLED]
    // private void UpdateEngineStatus()
    // {
    //     EngineStatus.Text = "● Disconnected";
    //     EngineStatus.Foreground = System.Windows.Media.Brushes.Red;
    // }

    // [WFP DISABLED]
    // private async void BtnToggleEngine_Click(object sender, RoutedEventArgs e)
    // {
    //     if (_vm.IsBusy) return;
    //     var wantOn = BtnToggleEngine.IsChecked == true;
    //     if (wantOn && !_vm.IsEngineOpen)
    //         await _vm.OpenEngineAsync();
    //     else if (!wantOn && _vm.IsEngineOpen)
    //         await _vm.CloseEngineAsync();
    // }

    // ── Navigation ───────────────────────────────────────────────

    private void ShowPage(string pageName)
    {
        // Reset tag of all navigation buttons
        NavDashboard.Tag = null;
        NavRules.Tag = null;
        NavConnections.Tag = null;
        NavSettings.Tag = null;
        NavProfiles.Tag = null;
        NavBlocklists.Tag = null;
        NavActivity.Tag = null;

        PageDashboard.Visibility = Visibility.Collapsed;
        PageRules.Visibility = Visibility.Collapsed;
        PageConnections.Visibility = Visibility.Collapsed;
        PageSettings.Visibility = Visibility.Collapsed;
        PageProfiles.Visibility = Visibility.Collapsed;
        PageBlocklists.Visibility = Visibility.Collapsed;
        PageActivity.Visibility = Visibility.Collapsed;

        switch (pageName)
        {
            case "Dashboard":
                PageDashboard.Visibility = Visibility.Visible;
                PageTitle.Text = "Dashboard";
                NavDashboard.Tag = "Active";
                break;
            case "Rules":
                PageRules.Visibility = Visibility.Visible;
                PageTitle.Text = "Firewall Rules";
                NavRules.Tag = "Active";
                _vm.Rules.LoadRules();
                break;
            case "Connections":
                PageConnections.Visibility = Visibility.Visible;
                PageTitle.Text = "Live Connections";
                NavConnections.Tag = "Active";
                break;
            case "Settings":
                PageSettings.Visibility = Visibility.Visible;
                PageTitle.Text = "Settings";
                NavSettings.Tag = "Active";
                break;
            case "Profiles":
                PageProfiles.Visibility = Visibility.Visible;
                PageTitle.Text = "Application Profiles";
                NavProfiles.Tag = "Active";
                _vm.Profiles.Refresh();
                break;
            case "Blocklists":
                PageBlocklists.Visibility = Visibility.Visible;
                PageTitle.Text = "Blocklists";
                NavBlocklists.Tag = "Active";
                _vm.Blocklists.Refresh();
                break;
            case "Activity":
                PageActivity.Visibility = Visibility.Visible;
                PageTitle.Text = "Activity Log";
                NavActivity.Tag = "Active";
                _vm.Activity.RefreshStatus();
                break;
        }
    }

    private void NavDashboard_Click(object sender, RoutedEventArgs e) => ShowPage("Dashboard");
    private void NavRules_Click(object sender, RoutedEventArgs e) => ShowPage("Rules");
    private void NavConnections_Click(object sender, RoutedEventArgs e) => ShowPage("Connections");
    private void NavSettings_Click(object sender, RoutedEventArgs e) => ShowPage("Settings");
    private void NavProfiles_Click(object sender, RoutedEventArgs e) => ShowPage("Profiles");
    private void NavBlocklists_Click(object sender, RoutedEventArgs e) => ShowPage("Blocklists");
    private void NavActivity_Click(object sender, RoutedEventArgs e) => ShowPage("Activity");

    // ── Window Controls ──────────────────────────────────────────

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

        // [WFP DISABLED]
        // if (_vm.IsEngineOpen)
        // {
        //     e.Cancel = true;
        //     Dispatcher.InvokeAsync(async () =>
        //     {
        //         await _vm.CloseEngineAsync();
        //         Application.Current.Shutdown();
        //     });
        //     return;
        // }

        base.OnClosing(e);
    }
}
