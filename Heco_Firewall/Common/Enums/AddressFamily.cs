namespace Heco.Common.Enums;

/// <summary>
///   Specifies the IP address families a rule matches.
/// </summary>
public enum AddressFamily
{
    /// <summary>Matches both IPv4 and IPv6 traffic.</summary>
    Both,
    /// <summary>Matches IPv4 traffic only.</summary>
    IPv4,
    /// <summary>Matches IPv6 traffic only.</summary>
    IPv6
}
