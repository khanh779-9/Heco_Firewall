namespace Heco.Common.Enums;

/// <summary>
///   Represents the state of a TCP connection.
/// </summary>
public enum TcpState
{
    /// <summary>State is unknown.</summary>
    Unknown,
    /// <summary>Connection is closed.</summary>
    Closed,
    /// <summary>Listening for incoming connections.</summary>
    Listen,
    /// <summary>SYN packet sent.</summary>
    SynSent,
    /// <summary>SYN packet received.</summary>
    SynReceived,
    /// <summary>Connection established.</summary>
    Established,
    /// <summary>Fin-Wait 1 state.</summary>
    FinWait1,
    /// <summary>Fin-Wait 2 state.</summary>
    FinWait2,
    /// <summary>Close-Wait state.</summary>
    CloseWait,
    /// <summary>Closing state.</summary>
    Closing,
    /// <summary>Last-Ack state.</summary>
    LastAck,
    /// <summary>Time-Wait state.</summary>
    TimeWait,
    /// <summary>Delete-TCB state.</summary>
    DeleteTcb
}
