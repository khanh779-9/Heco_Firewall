using System;
using System.Collections.Generic;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using Heco.Common.Services.Blocklists;
using Heco.Common.Services.Settings;
using Heco.Common.Models;
using Heco.Common.Enums;
using Heco.Common.Interfaces;

namespace Heco_Firewall.Converters;

/// <summary>True → Visible, False → Collapsed</summary>
internal sealed class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is bool b)
            return b ? Visibility.Visible : Visibility.Collapsed;
        return Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is Visibility v && v == Visibility.Visible;
    }
}

/// <summary>Inverse a boolean value.</summary>
internal sealed class InverseBoolConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is bool b ? !b : false;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is bool b ? !b : false;
    }
}

/// <summary>RuleAction → SolidColorBrush (Permit=green, Block=red)</summary>
internal sealed class RuleActionToColorConverter : IValueConverter
{
    private static readonly SolidColorBrush Green = new(Color.FromRgb(0x2E, 0xA0, 0x43));
    private static readonly SolidColorBrush Red = new(Color.FromRgb(0xF8, 0x51, 0x49));

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is RuleAction action)
            return action == RuleAction.Permit ? Green : Red;
        return Red;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>NetworkProtocol → short display string</summary>
internal sealed class ProtocolToTextConverter : IValueConverter
{
    private static readonly Dictionary<NetworkProtocol, string> DisplayNames = new()
    {
        { NetworkProtocol.Any, "Any" },
        { NetworkProtocol.ARP, "ARP" },
        { NetworkProtocol.TCP, "TCP" },
        { NetworkProtocol.UDP, "UDP" },
        { NetworkProtocol.ICMP, "ICMP" },
        { NetworkProtocol.IGMP, "IGMP" },
        { NetworkProtocol.GRE, "GRE" },
        { NetworkProtocol.ESP, "ESP" },
        { NetworkProtocol.AH, "AH" },
        { NetworkProtocol.IPv6_ICMP, "ICMPv6" },
        { NetworkProtocol.L2TP, "L2TP" },
        { NetworkProtocol.SCTP, "SCTP" },
        { NetworkProtocol.EGP, "EGP" },
        { NetworkProtocol.OSPF, "OSPF" },
        { NetworkProtocol.EIGRP, "EIGRP" },
        { NetworkProtocol.RSVP, "RSVP" },
        { NetworkProtocol.VRRP, "VRRP" },
        { NetworkProtocol.IP_in_IP, "IPIP" },
        { NetworkProtocol.IPv6, "IPv6" },
        { NetworkProtocol.IPv6_Route, "IPv6-Route" },
        { NetworkProtocol.IPv6_Frag, "IPv6-Frag" },
        { NetworkProtocol.IPv6_NoNxt, "IPv6-NoNxt" },
        { NetworkProtocol.IPv6_Opts, "IPv6-Opts" },
        { NetworkProtocol.PIM, "PIM" },
        { NetworkProtocol.UDPLite, "UDPLite" },
        { NetworkProtocol.MPLS_in_IP, "MPLS" },
    };

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is NetworkProtocol proto)
        {
            if (DisplayNames.TryGetValue(proto, out var name))
                return name;
            return $"Proto {(int)proto}";
        }
        return "?";
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>TcpState → short display string</summary>
internal sealed class TcpStateToTextConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is TcpState state)
            return state switch
            {
                TcpState.Unknown => "?",
                TcpState.Closed => "Closed",
                TcpState.Listen => "Listen",
                TcpState.SynSent => "SYN_SENT",
                TcpState.SynReceived => "SYN_RCVD",
                TcpState.Established => "ESTAB",
                TcpState.FinWait1 => "FIN_WAIT1",
                TcpState.FinWait2 => "FIN_WAIT2",
                TcpState.CloseWait => "CLOSE_WAIT",
                TcpState.Closing => "CLOSING",
                TcpState.LastAck => "LAST_ACK",
                TcpState.TimeWait => "TIME_WAIT",
                TcpState.DeleteTcb => "DEL_TCB",
                _ => $"S{(int)state}"
            };
        return "?";
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Bytes → human-readable format (KB, MB, GB)</summary>
internal sealed class ByteFormatConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not long bytes || bytes == 0)
            return "0 B";

        var abs = Math.Abs(bytes);
        var suffix = new[] { "B", "KB", "MB", "GB", "TB" };
        var place = 0;
        double d = abs;

        while (d >= 1024 && place < suffix.Length - 1)
        {
            d /= 1024;
            place++;
        }

        return $"{d:F1} {suffix[place]}";
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>NetworkActionSettings → display string (e.g. "Block outbound, Allow inbound")</summary>
public sealed class NetworkActionSettingsConverter : IValueConverter
{
    public static readonly NetworkActionSettingsConverter Default = new();

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not NetworkActionSettings s)
            return "Inherit";

        var parts = new List<string>();
        if (s.AllowOutbound == true) parts.Add("Allow OUT");
        if (s.AllowInbound == true) parts.Add("Allow IN");
        if (s.BlockOutbound == true) parts.Add("Block OUT");
        if (s.BlockInbound == true) parts.Add("Block IN");

        return parts.Count > 0 ? string.Join(", ", parts) : "Inherit";
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>BlocklistSource enum → display string</summary>
public sealed class BlocklistSourceConverter : IValueConverter
{
    public static readonly BlocklistSourceConverter Default = new();

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is BlocklistSource src)
            return src switch
            {
                BlocklistSource.OfflineFile => "Offline",
                BlocklistSource.OnlineUrl => "Online",
                _ => src.ToString()
            };
        return "?";
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>BlocklistContentType enum → display string</summary>
public sealed class BlocklistContentTypeConverter : IValueConverter
{
    public static readonly BlocklistContentTypeConverter Default = new();

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is BlocklistContentType ct)
            return ct switch
            {
                BlocklistContentType.Domain => "Domain",
                BlocklistContentType.IP => "IP",
                BlocklistContentType.Wildcard => "Wildcard",
                BlocklistContentType.Hosts => "Hosts",
                _ => ct.ToString()
            };
        return "?";
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>int count → Visible if 0, Collapsed otherwise (for empty state messages)</summary>
internal sealed class IsEmptyConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is int count)
            return count == 0 ? Visibility.Visible : Visibility.Collapsed;
        return Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Nullable ushort → string for port bindings</summary>
public sealed class NullablePortConverter : IValueConverter
{
    public static readonly NullablePortConverter Default = new();

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is ushort port)
            return port.ToString();
        return string.Empty;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is string s && ushort.TryParse(s, out var port))
            return port;
        return null!;
    }
}

/// <summary>Bool (files exist) → green/gray Ellipse fill</summary>
internal sealed class BoolToStatusColorConverter : IValueConverter
{
    private static readonly SolidColorBrush Green = new(Color.FromRgb(0x2E, 0xA0, 0x43));
    private static readonly SolidColorBrush Gray = new(Color.FromRgb(0x99, 0x99, 0x99));

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is bool b && b ? Green : Gray;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Bool (files exist) → "Loaded" / "Not installed"</summary>
internal sealed class BoolToGeoIpStatusConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is bool b && b ? "GeoIP databases loaded" : "Not installed — click Download";
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Full file path → filename only (e.g. "C:\Windows\explorer.exe" → "explorer.exe")</summary>
internal sealed class FileNameOnlyConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is string path && !string.IsNullOrEmpty(path))
        {
            try { return System.IO.Path.GetFileName(path); }
            catch { return path; }
        }
        return "*";
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
