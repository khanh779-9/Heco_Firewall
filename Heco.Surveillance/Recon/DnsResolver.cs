using System;
using System.Collections.Generic;
using System.Net;

namespace Heco.Surveillance.Recon;

/// <summary>
///   Performs reverse DNS lookups with in-memory caching.
/// </summary>
public static class DnsResolver
{
    private static readonly Dictionary<string, string> Cache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly object CacheLock = new();

    /// <summary>
    ///   Resolve an IP address to a host name. Results are cached for the
    ///   application lifetime; returns <c>null</c> on failure.
    /// </summary>
    public static string? Resolve(IPAddress address)
    {
        if (address == null) return null;
        var key = address.ToString();

        lock (CacheLock)
        {
            if (Cache.TryGetValue(key, out var cached))
                return cached;
        }

        try
        {
            var entry = Dns.GetHostEntry(address);
            var name = entry.HostName;

            lock (CacheLock)
            {
                if (!Cache.ContainsKey(key))
                    Cache[key] = name;
            }

            return name;
        }
        catch
        {
            // Not all IPs have reverse records
            lock (CacheLock)
            {
                if (!Cache.ContainsKey(key))
                    Cache[key] = key;
            }
            return null;
        }
    }

    /// <summary>Clear the DNS cache.</summary>
    public static void ClearCache()
    {
        lock (CacheLock)
        {
            Cache.Clear();
        }
    }
}
