using System;
using System.Collections.Generic;
using Heco.Common.Models;

namespace Heco.Common.Interfaces;

/// <summary>
///   Monitors active TCP and UDP connections via the IP Helper API.
/// </summary>
public interface IConnectionMonitor
{
    /// <summary>Raised each time the connection table is refreshed with new data.</summary>
    event EventHandler<IReadOnlyList<ConnectionEntry>> ConnectionsUpdated;

    /// <summary>Raised when a new connection is first observed.</summary>
    event EventHandler<ConnectionEntry> ConnectionAdded;

    /// <summary>Raised when a previously observed connection is closed (TCP) or disappears (UDP).</summary>
    event EventHandler<ConnectionEntry> ConnectionRemoved;

    /// <summary>Whether the monitor is currently running.</summary>
    bool IsRunning { get; }

    /// <summary>Current snapshot of all active connections.</summary>
    IReadOnlyList<ConnectionEntry> CurrentConnections { get; }

    /// <summary>Start polling at the specified interval (ms).</summary>
    void Start(int intervalMs = 4000);

    /// <summary>Stop polling and release resources.</summary>
    void Stop();
}
