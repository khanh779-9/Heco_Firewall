using System.Runtime.Versioning;
using System.Security.Principal;
using System.Windows;
using Heco.Common.Services.Notifications;
using Heco_Firewall.Tray;
using Heco_Firewall.ViewModels;

namespace Heco_Firewall;

/// <summary>
///   Application entry point. Manages the MainWindow and system tray.
/// </summary>
[SupportedOSPlatform("windows")]
public partial class App : Application
{
    private TrayService? _trayService;
    private bool _trayInitialized;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // StartupUri has not yet created MainWindow at this point,
        // so we defer tray initialization to the first Activated event.

        if (!IsRunningAsAdmin())
        {
            MessageBox.Show(
                "Heco Firewall is not running as Administrator.\n\n" +
                "Packet filtering (WinDivert) and Self-Defense driver will not work.\n" +
                "Please restart the application with 'Run as administrator'.",
                "Insufficient Privileges",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
    }

    private static bool IsRunningAsAdmin()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>
    ///   Called by MainWindow once it is fully loaded, so we can safely
    ///   access its DataContext and initialize the tray icon.
    /// </summary>
    internal void InitializeTray(MainViewModel mainVm)
    {
        if (_trayInitialized) return;
        _trayInitialized = true;

        _trayService = new TrayService(mainVm);
        _trayService.Initialize();

        // Wire up block notifications from service → tray balloon
        if (mainVm.NotificationService is NotificationService notifSvc)
        {
            notifSvc.BlockNotification += (_, info) =>
            {
                _trayService?.ShowBlockNotification(info.ProcessName, info.RemoteAddress, info.RemotePort);
            };
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _trayService?.Dispose();
        if (MainWindow?.DataContext is MainViewModel vm)
            vm.Cleanup();
        base.OnExit(e);
    }
}
