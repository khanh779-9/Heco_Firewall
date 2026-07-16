using System;
using System.Net;
using Heco.WinDivert.Structs;

namespace Heco.WinDivert.Packet;

public sealed class PacketInfo
{
    public byte Version { get; set; }
    public Protocol Protocol { get; set; }
    public IPAddress SourceAddress { get; set; } = IPAddress.None;
    public IPAddress DestinationAddress { get; set; } = IPAddress.None;
    public ushort SourcePort { get; set; }
    public ushort DestinationPort { get; set; }
    public bool IsTcpSyn { get; set; }

    public byte IcmpType { get; set; }
    public byte IcmpCode { get; set; }
    public byte TcpFlags { get; set; }
}

public static class PacketParser
{
    private static bool IsIPv6ExtensionHeader(Protocol nextHeader) => nextHeader switch
    {
        Protocol.HOPOPT                 => true,
        Protocol.IPv6_Route             => true,
        Protocol.IPv6_Frag              => true,
        Protocol.ESP                    => true,
        Protocol.AH                     => true,
        Protocol.IPv6_Opts              => true,
        Protocol.Mobility_Header        => true,
        Protocol.HIP                    => true,
        Protocol.Shim6                  => true,
        _ => false
    };

    public static PacketInfo? Parse(byte[] buffer, uint length)
    {
        if (length < 20) return null;

        var version = (byte)(buffer[0] >> 4);
        return version == (byte)IPVersion.V4 ? ParseIPv4(buffer, length)
             : version == (byte)IPVersion.V6 ? ParseIPv6(buffer, length)
             : null;
    }

    private static PacketInfo? ParseIPv4(byte[] buffer, uint length)
    {
        var ipHeaderLen = (buffer[0] & 0x0F) * 4;
        if (length < ipHeaderLen) return null;

        var info = new PacketInfo
        {
            Version = 4,
            Protocol = (Protocol)buffer[9],
            SourceAddress = new IPAddress(buffer.AsSpan(12, 4)),
            DestinationAddress = new IPAddress(buffer.AsSpan(16, 4))
        };

        ParseLayer4(buffer, ipHeaderLen, length, info);
        return info;
    }

    private static PacketInfo? ParseIPv6(byte[] buffer, uint length)
    {
        if (length < 40) return null;

        // Walk extension header chain to find transport protocol
        int offset = 40;
        var transportProtocol = (Protocol)buffer[6];
        int extCount = 0;

        while (IsIPv6ExtensionHeader(transportProtocol) && offset + 2 <= length && extCount < 16)
        {
            var extNext = (Protocol)buffer[offset];
            int extLen = transportProtocol switch
            {
                Protocol.IPv6_Frag => 8,
                Protocol.AH        => (buffer[offset + 1] + 2) * 4,
                _ => (buffer[offset + 1] + 1) * 8
            };
            if (extLen <= 0) break;
            offset += extLen;
            transportProtocol = extNext;
            extCount++;
        }

        var info = new PacketInfo
        {
            Version = 6,
            Protocol = transportProtocol,
            SourceAddress = new IPAddress(buffer.AsSpan(8, 16)),
            DestinationAddress = new IPAddress(buffer.AsSpan(24, 16))
        };

        ParseLayer4(buffer, offset, length, info);
        return info;
    }

    private static void ParseLayer4(byte[] buffer, int offset, uint length, PacketInfo info)
    {
        if (length < offset + 4) return;

        if (info.Protocol is Protocol.ICMP or Protocol.IPv6_ICMP)
        {
            info.IcmpType = buffer[offset];
            info.IcmpCode = buffer[offset + 1];
            return;
        }

        if (info.Protocol == Protocol.IGMP) return;

        info.SourcePort = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
        info.DestinationPort = (ushort)((buffer[offset + 2] << 8) | buffer[offset + 3]);

        if (info.Protocol == Protocol.TCP && length >= offset + 20)
        {
            info.TcpFlags = buffer[offset + 13];
            info.IsTcpSyn = (info.TcpFlags & (byte)TcpFlag.Syn) != 0;
        }
    }
}
