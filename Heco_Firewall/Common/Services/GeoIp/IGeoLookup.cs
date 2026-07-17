using System.Net;
using System.Threading.Tasks;

namespace Heco.Common.Services.GeoIp;

/// <summary>
///   GeoIP lookup using MaxMind GeoLite2 databases (.mmdb format).
///   Provides country, ASN, organization, and anycast information for IPv4 and IPv6 addresses.
/// </summary>
public interface IGeoLookup
{
    /// <summary>Whether the GeoIP databases are loaded and ready.</summary>
    bool IsReady { get; }

    /// <summary>Lookup geographic and network information for an IP address.</summary>
    GeoIpResult? Lookup(IPAddress address);

    /// <summary>Lookup by string IP address. Returns null on parse failure.</summary>
    GeoIpResult? Lookup(string ipAddress);

    /// <summary>Load databases from the specified directory.</summary>
    void Load(string databaseDirectory);

    /// <summary>Load databases in the background (fire-and-forget on thread-pool).</summary>
    Task LoadAsync(string databaseDirectory);

    /// <summary>Close database readers and release resources.</summary>
    void Close();
}

/// <summary>
///   Result of a GeoIP lookup.
/// </summary>
public sealed class GeoIpResult
{
    /// <summary>ISO 3166-1 alpha-2 country code (e.g. "US", "VN").</summary>
    public string? CountryCode { get; set; }

    /// <summary>Full country name.</summary>
    public string? CountryName { get; set; }

    /// <summary>Autonomous System Number (e.g. "AS15169").</summary>
    public string? Asn { get; set; }

    /// <summary>Organization name (e.g. "Google LLC").</summary>
    public string? Organization { get; set; }

    /// <summary>Whether the IP is on an anycast network.</summary>
    public bool IsAnycast { get; set; }

    public override string ToString() =>
        $"{CountryCode ?? "??"} | {Asn ?? "AS?"} | {Organization ?? "?"}";
}
