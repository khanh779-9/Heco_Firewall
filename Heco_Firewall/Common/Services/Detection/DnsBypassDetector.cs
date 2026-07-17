using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Heco.Common.Services.Detection;

namespace Heco.Common.Services.Detection;

/// <summary>
///   Detects DNS bypass attempts — connections using DoT (port 853),
///   known DoH IPs, or non-standard DNS servers.
/// </summary>
public sealed class DnsBypassDetector : IDnsBypassDetector
{
    private readonly List<IPAddress> _knownDohIps = new();
    private readonly HashSet<string> _networkDnsServers = new();
    private readonly object _sync = new();

    // Default known DoH providers
    private static readonly (string Name, IPAddress[] Ips)[] DefaultDohProviders = new[]
    {
        ("CloudFlare", new[] { IPAddress.Parse("1.1.1.1"), IPAddress.Parse("1.0.0.1"),
            IPAddress.Parse("2606:4700:4700::1111"), IPAddress.Parse("2606:4700:4700::1001") }),
        ("Google", new[] { IPAddress.Parse("8.8.8.8"), IPAddress.Parse("8.8.4.4"),
            IPAddress.Parse("2001:4860:4860::8888"), IPAddress.Parse("2001:4860:4860::8844") }),
        ("Quad9", new[] { IPAddress.Parse("9.9.9.9"), IPAddress.Parse("149.112.112.112"),
            IPAddress.Parse("2620:fe::fe"), IPAddress.Parse("2620:fe::9") }),
        ("Mullvad", new[] { IPAddress.Parse("194.242.2.2"), IPAddress.Parse("194.242.2.3"),
            IPAddress.Parse("2a07:e340::2"), IPAddress.Parse("2a07:e340::3") }),
        ("AdGuard", new[] { IPAddress.Parse("94.140.14.14"), IPAddress.Parse("94.140.15.15"),
            IPAddress.Parse("2a10:50c0::ad1:ff"), IPAddress.Parse("2a10:50c0::ad2:ff") }),
        ("NextDNS", new[] { IPAddress.Parse("45.90.28.0"), IPAddress.Parse("45.90.30.0") }),
    };

    public IReadOnlyList<IPAddress> KnownDohIps => _knownDohIps.AsReadOnly();

    public DnsBypassDetector()
    {
        InitializeDefaultDohProviders();
    }

    private void InitializeDefaultDohProviders()
    {
        foreach (var (_, ips) in DefaultDohProviders)
        {
            foreach (var ip in ips)
            {
                if (!_knownDohIps.Contains(ip))
                    _knownDohIps.Add(ip);
            }
        }
    }

    public DnsBypassResult Check(IPAddress remoteAddress, ushort remotePort)
    {
        var result = new DnsBypassResult();

        // Check 1: DoT port 853
        if (remotePort == 853)
        {
            result.IsDnsBypass = true;
            result.BypassType = DnsBypassType.DotPort853;
            result.Description = "DNS-over-TLS (port 853)";
            return result;
        }

        // Check 2: Known DoH provider IPs
        lock (_sync)
        {
            var match = _knownDohIps.FirstOrDefault(ip => ip.Equals(remoteAddress));
            if (match is not null)
            {
                result.IsDnsBypass = true;
                result.BypassType = DnsBypassType.KnownDohIp;
                result.MatchedProvider = GetProviderName(remoteAddress);
                result.Description = $"Known DoH provider: {result.MatchedProvider}";
                return result;
            }
        }

        // Check 3: Non-standard DNS server (connected to a DNS server not configured on this machine)
        lock (_sync)
        {
            if (_networkDnsServers.Count > 0 && remotePort == 53 &&
                !_networkDnsServers.Contains(remoteAddress.ToString()))
            {
                result.IsDnsBypass = true;
                result.BypassType = DnsBypassType.NonStandardDnsServer;
                result.Description = $"Non-standard DNS server: {remoteAddress}";
                return result;
            }
        }

        return result;
    }

    public bool IsDotPort(ushort port) => port == 853;

    public bool IsKnownDohServer(IPAddress address)
    {
        lock (_sync)
        {
            return _knownDohIps.Any(ip => ip.Equals(address));
        }
    }

    public void UpdateNetworkDnsServers(IEnumerable<IPAddress> dnsServers)
    {
        lock (_sync)
        {
            _networkDnsServers.Clear();
            foreach (var dns in dnsServers)
                _networkDnsServers.Add(dns.ToString());
        }
    }

    private string GetProviderName(IPAddress address)
    {
        foreach (var (name, ips) in DefaultDohProviders)
        {
            if (ips.Any(ip => ip.Equals(address)))
                return name;
        }
        return "Unknown";
    }
}
