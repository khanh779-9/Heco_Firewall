using System;
using System.Collections.Generic;
using System.Net;

namespace Heco.Common.Services.Detection;

/// <summary>
///   Detects potential threats from connection patterns using behavioral analysis.
/// </summary>
public interface IThreatDetector : IDisposable
{
    /// <summary>
    ///   Analyze a connection for threat indicators.
    /// </summary>
    ThreatResultV2 Analyze(
        IPAddress localAddress,
        ushort localPort,
        IPAddress remoteAddress,
        ushort remotePort,
        uint processId);

    /// <summary>
    ///   Register a connection for behavioral tracking.
    /// </summary>
    void TrackConnection(uint processId, IPAddress remoteAddress, ushort remotePort);
}

/// <summary>
///   Result of a threat analysis.
/// </summary>
public sealed class ThreatResultV2
{
    /// <summary>Whether any threat indicators were found.</summary>
    public bool IsThreat { get; set; }

    /// <summary>Overall threat level.</summary>
    public ThreatLevelV2 Level { get; set; }

    /// <summary>Individual threat indicators detected.</summary>
    public List<ThreatIndicatorV2> Indicators { get; set; } = new();
}

/// <summary>
///   An individual threat indicator.
/// </summary>
public sealed class ThreatIndicatorV2
{
    /// <summary>Human-readable description of the threat.</summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>Severity level.</summary>
    public ThreatLevelV2 Level { get; set; }
}

/// <summary>
///   Threat severity levels.
/// </summary>
public enum ThreatLevelV2
{
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}