using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using Heco.Common.Services.GeoIp;
using MaxMind.Db;
using Heco.Common.Services.Diagnostics;

namespace Heco.Common.Services.GeoIp;

/// <summary>
///   GeoIP lookup using MaxMind GeoLite2 databases (.mmdb format).
///   Provides country, ASN, organization, and anycast information.
/// </summary>
public sealed class GeoLookup : IGeoLookup, IDisposable
{
    private Reader? _cityReader;
    private Reader? _asnReader;
    private bool _isReady;

    public bool IsReady => _isReady;

    public GeoIpResult? Lookup(IPAddress address)
    {
        if (!_isReady) return null;

        try
        {
            var result = new GeoIpResult();

            if (_cityReader is not null)
            {
                var cityData = _cityReader.Find<CityRecord>(address);
                if (cityData is not null)
                {
                    result.CountryCode = cityData.Country?.ISOCode;
                    result.CountryName = cityData.Country?.Names?.En;
                }
            }

            if (_asnReader is not null)
            {
                var asnData = _asnReader.Find<AsnRecord>(address);
                if (asnData is not null)
                {
                    result.Asn = asnData.AutonomousSystemNumber > 0
                        ? $"AS{asnData.AutonomousSystemNumber}"
                        : null;
                    result.Organization = asnData.AutonomousSystemOrganization;
                    result.IsAnycast = asnData.IsAnycast;
                }
            }

            return result;
        }
        catch (Exception ex)
        {
            Logger.Debug($"GeoIP lookup failed for {address}: {ex.Message}");
            return null;
        }
    }

    public GeoIpResult? Lookup(string ipAddress)
    {
        if (!IPAddress.TryParse(ipAddress, out var addr))
            return null;
        return Lookup(addr);
    }

    public void Load(string databaseDirectory)
    {
        try
        {
            if (!Directory.Exists(databaseDirectory))
            {
                Logger.Warn($"GeoIP database directory not found: {databaseDirectory}");
                return;
            }

            var cityPath = Path.Combine(databaseDirectory, "GeoLite2-City.mmdb");
            var asnPath = Path.Combine(databaseDirectory, "GeoLite2-ASN.mmdb");

            if (File.Exists(cityPath))
                _cityReader = new Reader(cityPath);

            if (File.Exists(asnPath))
                _asnReader = new Reader(asnPath);

            _isReady = _cityReader is not null || _asnReader is not null;

            Logger.Info($"GeoIP loaded: City={_cityReader is not null}, ASN={_asnReader is not null}");
        }
        catch (Exception ex)
        {
            Logger.Error("Failed to load GeoIP databases", ex);
            _isReady = false;
        }
    }

    public Task LoadAsync(string databaseDirectory)
    {
        return Task.Run(() => Load(databaseDirectory));
    }

    public void Close()
    {
        _cityReader?.Dispose();
        _asnReader?.Dispose();
        _cityReader = null;
        _asnReader = null;
        _isReady = false;
    }

    public void Dispose()
    {
        Close();
    }

    // ── MaxMind model records ────────────────────────────────────

    private sealed class CityRecord
    {
        public CityCountry? Country { get; set; }
    }

    private sealed class CityCountry
    {
        public string? ISOCode { get; set; }
        public CityCountryNames? Names { get; set; }
    }

    private sealed class CityCountryNames
    {
        public string? En { get; set; }
    }

    private sealed class AsnRecord
    {
        public long AutonomousSystemNumber { get; set; }
        public string? AutonomousSystemOrganization { get; set; }
        public bool IsAnycast { get; set; }
    }
}
