using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace Heco.WinDivert.Native;

[DebuggerDisplay("Family = {AddressFamily}, Port = {Port}")]
public unsafe struct SocketAddress
{
    private const int V4_SIZE = 4;
    private const int V6_SIZE = 16;

    private ushort _addressFamily;
    public ushort Port;
    private fixed byte _addressV4[V4_SIZE];
    private fixed byte _addressV6[V6_SIZE];
    private uint _scopeId;
    private fixed byte _reserved[8];

    public readonly AddressFamily AddressFamily => (AddressFamily)_addressFamily;

    public IPAddress GetIPAddress()
    {
        var family = (AddressFamily)_addressFamily;
        if (family == AddressFamily.InterNetwork)
        {
            fixed (byte* ptr = _addressV4)
                return new IPAddress(new Span<byte>(ptr, V4_SIZE));
        }
        if (family == AddressFamily.InterNetworkV6)
        {
            fixed (byte* ptr = _addressV6)
                return new IPAddress(new Span<byte>(ptr, V6_SIZE), _scopeId);
        }
        throw new NotSupportedException($"Unsupported AddressFamily: {family}");
    }

    public void SetIPAddress(IPAddress value)
    {
        _addressFamily = (ushort)value.AddressFamily;
        if (value.AddressFamily == AddressFamily.InterNetwork)
        {
            fixed (byte* ptr = _addressV4)
                value.TryWriteBytes(new Span<byte>(ptr, V4_SIZE), out _);
        }
        else if (value.AddressFamily == AddressFamily.InterNetworkV6)
        {
            fixed (byte* ptr = _addressV6)
            {
                value.TryWriteBytes(new Span<byte>(ptr, V6_SIZE), out _);
                _scopeId = (uint)value.ScopeId;
            }
        }
        else
        {
            throw new NotSupportedException($"Unsupported AddressFamily: {value.AddressFamily}");
        }
    }
}
