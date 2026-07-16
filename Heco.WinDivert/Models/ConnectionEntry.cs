using System;
using System.Net;
using Heco.WinDivert.Structs;

namespace Heco.WinDivert.Models;

public sealed class ConnectionEntry
{
    public long Id { get; set; }
    public Protocol Protocol { get; set; }
    public IPAddress LocalAddress { get; set; } = IPAddress.Any;
    public ushort LocalPort { get; set; }
    public IPAddress RemoteAddress { get; set; } = IPAddress.Any;
    public ushort RemotePort { get; set; }
    public uint ProcessId { get; set; }
    public string? ProcessName { get; set; }
    public string? ProcessPath { get; set; }
    public bool IsInbound { get; set; }
    public DateTime FirstSeen { get; set; } = DateTime.UtcNow;
    public DateTime LastSeen { get; set; } = DateTime.UtcNow;

    public override string ToString() =>
        $"[{Protocol}] {LocalAddress}:{LocalPort} \u2192 {RemoteAddress}:{RemotePort}  PID:{ProcessId} {ProcessName}";
}
