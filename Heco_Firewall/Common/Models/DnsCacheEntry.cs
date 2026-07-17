using System.Net;

namespace Heco.Common.Models;

/// <summary>
///   A single entry from the Windows DNS client cache.
/// </summary>
public sealed class DnsCacheEntry
{
    /// <summary>Domain name (e.g. "google.com").</summary>
    public string? DomainName { get; set; }

    /// <summary>Record type (1=A, 28=AAAA, 5=CNAME).</summary>
    public ushort Type { get; set; }

    /// <summary>Resolved IP address (for A/AAAA records).</summary>
    public IPAddress? Address { get; set; }

    public override string ToString() =>
        $"{DomainName} ({Type switch { 1 => "A", 28 => "AAAA", 5 => "CNAME", _ => $"Type{Type}" }}) → {Address}";
}
