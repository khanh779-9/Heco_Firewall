using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;

namespace Heco.Common.Sniffer;

/// <summary>
///   Captures raw IP packets using a promiscuous-mode raw socket.
///   Requires Administrator privileges.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class PacketSniffer : IDisposable
{
    private Socket? _socket;
    private CancellationTokenSource? _cts;
    private Task? _captureTask;
    private bool _disposed;

    /// <summary>Fired for each captured packet with raw bytes.</summary>
    public event EventHandler<PacketCaptureEventArgs>? PacketCaptured;

    /// <summary>Whether the sniffer is currently running.</summary>
    public bool IsRunning => _captureTask?.IsCompleted == false;

    /// <summary>
    ///   Start capturing on the specified interface (IP address) or <see cref="IPAddress.Loopback"/>.
    /// </summary>
    public void Start(IPAddress? localAddress = null)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(PacketSniffer));
        if (IsRunning) return;

        localAddress = localAddress ?? IPAddress.Loopback;

        _socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP)
        {
            ReceiveBufferSize = 1024 * 256
        };

        _socket.Bind(new IPEndPoint(localAddress, 0));
        _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

        // SIO_RCVALL — enable promiscuous mode
        var rcvAll = new byte[] { 1, 0, 0, 0 };
        _socket.IOControl(IOControlCode.ReceiveAll, rcvAll, null);

        _cts = new CancellationTokenSource();
        var token = _cts.Token;
        var buffer = new byte[65536];

        _captureTask = Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    if (_socket == null) break;
                    var available = await Task<int>.Factory.FromAsync(
                        _socket.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, null, null),
                        _socket.EndReceive)
                        .ConfigureAwait(false);

                    if (token.IsCancellationRequested) break;

                    if (available > 0)
                    {
                        var packet = new byte[available];
                        Array.Copy(buffer, packet, available);
                        var args = new PacketCaptureEventArgs(packet, DateTime.UtcNow);
                        PacketCaptured?.Invoke(this, args);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (ObjectDisposedException) { break; }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine("[PacketSniffer] Error: " + ex.Message);
                }
            }
        }, token);
    }

    /// <summary>Stop capture.</summary>
    public void Stop()
    {
        if (_cts != null)
        {
            _cts.Cancel();
            _cts.Dispose();
            _cts = null;
        }

        try { _socket?.Close(); } catch { }
        try { _socket?.Dispose(); } catch { }
        _socket = null;

        _captureTask = null;
    }

    /// <summary>Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        Stop();
        _disposed = true;
    }
}

/// <summary>Event args for captured packets.</summary>
public sealed class PacketCaptureEventArgs : EventArgs
{
    /// <summary>Raw packet bytes (IP header + payload).</summary>
    public byte[] Data { get; }

    /// <summary>Timestamp of capture.</summary>
    public DateTime Timestamp { get; }

    /// <summary>Initializes a new instance of the PacketCaptureEventArgs class.</summary>
    public PacketCaptureEventArgs(byte[] data, DateTime timestamp)
    {
        Data = data ?? throw new ArgumentNullException(nameof(data));
        Timestamp = timestamp;
    }
}
