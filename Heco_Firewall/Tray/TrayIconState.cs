namespace Heco_Firewall.Tray;

/// <summary>
///   Represents the visual state of the system tray icon.
///   Controls the shield icon color displayed in the notification area.
/// </summary>
internal enum TrayIconState
{
    /// <summary>Green shield — firewall engine is active and protecting.</summary>
    Active,

    /// <summary>Gray shield — firewall engine is stopped/disabled.</summary>
    Disabled,

    /// <summary>Red shield — WinDivert driver error or engine failure.</summary>
    Error
}
