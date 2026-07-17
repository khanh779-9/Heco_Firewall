using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using Heco.WinDivert.Structs;
using Heco.WinDivert.Interop;
using Heco.WinDivert.Models;
using Heco.WinDivert.Packet;


namespace Heco.WinDivert.Filtering;

/// <summary>
/// Packet payload modification utilities for redirect, tamper, and inject operations.
/// All modifications automatically recalculate IP/TCP/UDP checksums via WinDivert helper.
/// </summary>
public static class PacketModifier
{
    /// <summary>
    /// Redirect a TCP connection to a different destination IP/port.
    /// Modifies IP header (dst addr) and TCP header (dst port) in-place.
    /// </summary>
    public static bool RedirectTcpPacket(byte[] packet, uint packetLen,
        IPAddress newDstIp, ushort newDstPort,
        ref WINDIVERT_ADDRESS addr)
    {
        try
        {
            int ipHeaderLen = GetIpHeaderLen(packet, packetLen);
            if (ipHeaderLen <= 0) return false;

            unsafe
            {
                fixed (byte* p = packet)
                {
                    var ipVersion = packet[0] >> 4;

                    if (ipVersion == 4)
                    {
                        var ipv4 = (V4Header*)p;
                        // Update destination IP
                        ipv4->DstAddr = IpToUint(newDstIp);
                        // Update total length will be recalculated by WinDivert
                        ipv4->Length = 0; // Mark for recalculation

                        // Find and update TCP destination port
                        var tcp = (TcpHeader*)(p + ipHeaderLen);
                        tcp->DstPort = Htons(newDstPort);
                        tcp->Checksum = 0;
                    }
                    else if (ipVersion == 6)
                    {
                        var ipv6 = (V6Header*)p;
                        // Update destination IPv6
                        var newAddr = IpV6ToBytes(newDstIp);
                        fixed (byte* src = newAddr)
                        {
                            Buffer.MemoryCopy(src, ipv6->DstAddr, 16, 16);
                        }

                        // Update TCP destination port
                        var tcp = (TcpHeader*)(p + ipHeaderLen);
                        tcp->DstPort = Htons(newDstPort);
                        tcp->Checksum = 0;
                        ipv6->PayloadLength = 0; // Mark for recalc
                    }

                    // Recalculate checksums
                    return WinDivertNative.WinDivertHelperCalcChecksums(packet, packetLen, ref addr, 0);
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[PacketModifier] Redirect error: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Inject a fake HTTP response (e.g., block page, redirect).
    /// Replaces TCP payload with custom HTTP response and recalculates checksums.
    /// </summary>
    public static bool InjectHttpResponse(byte[] packet, uint packetLen,
        string httpResponse,
        ref WINDIVERT_ADDRESS addr,
        out byte[]? newPacket)
    {
        newPacket = null;
        try
        {
            int ipHeaderLen = GetIpHeaderLen(packet, packetLen);
            if (ipHeaderLen <= 0) return false;

            var responseBytes = System.Text.Encoding.ASCII.GetBytes(httpResponse);

            unsafe
            {
                fixed (byte* p = packet)
                {
                    var ipVersion = packet[0] >> 4;
                    int tcpHeaderLen = 0;
                    byte* tcpPtr = null;

                    if (ipVersion == 4)
                    {
                        var ipv4 = (V4Header*)p;
                        tcpPtr = (byte*)(p + ipHeaderLen);
                        var tcp = (TcpHeader*)tcpPtr;
                        tcpHeaderLen = tcp->DataOffsetBytes;
                    }
                    else if (ipVersion == 6)
                    {
                        tcpPtr = (byte*)(p + ipHeaderLen);
                        var tcp = (TcpHeader*)tcpPtr;
                        tcpHeaderLen = tcp->DataOffsetBytes;
                    }

                    if (tcpPtr == null) return false;

                    int payloadOffset = ipHeaderLen + tcpHeaderLen;
                    int oldPayloadLen = (int)packetLen - payloadOffset;

                    // Build new packet
                    int newPacketLen = payloadOffset + responseBytes.Length;
                    newPacket = new byte[newPacketLen];

                    fixed (byte* np = newPacket)
                    {
                        // Copy headers
                        Buffer.MemoryCopy(p, np, newPacketLen, payloadOffset);

                        // Swap SRC/DST for response (inbound to client)
                        if (ipVersion == 4)
                        {
                            var ipv4 = (V4Header*)np;
                            var tmp = ipv4->SrcAddr;
                            ipv4->SrcAddr = ipv4->DstAddr;
                            ipv4->DstAddr = tmp;
                            ipv4->Length = Htons((ushort)newPacketLen);
                        }
                        else if (ipVersion == 6)
                        {
                            var ipv6 = (V6Header*)np;
                            var tmpSrc = stackalloc byte[16];
                            var tmpDst = stackalloc byte[16];
                            Buffer.MemoryCopy(ipv6->SrcAddr, tmpSrc, 16, 16);
                            Buffer.MemoryCopy(ipv6->DstAddr, tmpDst, 16, 16);
                            Buffer.MemoryCopy(tmpDst, ipv6->SrcAddr, 16, 16);
                            Buffer.MemoryCopy(tmpSrc, ipv6->DstAddr, 16, 16);
                            ipv6->PayloadLength = Htons((ushort)(tcpHeaderLen + responseBytes.Length));
                        }

                        // Swap TCP ports
                        var ntcp = (TcpHeader*)(np + ipHeaderLen);
                        var tmpPort = ntcp->SrcPort;
                        ntcp->SrcPort = ntcp->DstPort;
                        ntcp->DstPort = tmpPort;

                        // Clear flags except ACK, set PSH+ACK for response
                        ntcp->DataOffset = (ushort)((ntcp->DataOffset & 0xF000) | (byte)(TcpFlag.Ack | TcpFlag.Psh));
                        ntcp->Checksum = 0;
                        ntcp->Window = Htons(65535);

                        // Set new SEQ/ACK for response
                        // ACK = client's SEQ + client payload len
                        // SEQ = server's initial SEQ (we copy from original)
                        ntcp->SeqNumber = ntcp->AckNumber; // Simplified
                        ntcp->AckNumber = AddToSeq(ntcp->AckNumber, (uint)oldPayloadLen);

                        // Copy HTTP response payload
                        var payloadDest = np + payloadOffset;
                        Buffer.BlockCopy(responseBytes, 0, newPacket, payloadOffset, responseBytes.Length);
                    }

                    // Recalculate checksums on new packet
                    var newAddr = addr;
                    newAddr.Outbound = false; // Send back as inbound
                    WinDivertNative.WinDivertHelperCalcChecksums(newPacket, (uint)newPacket.Length, ref newAddr, 0);
                    return true;
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[PacketModifier] Inject HTTP response error: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Modify HTTP request in-place (e.g., change Host header, URL path, inject headers).
    /// </summary>
    public static bool ModifyHttpRequest(byte[] packet, uint packetLen,
        Func<string, string> modifyRequest,
        ref WINDIVERT_ADDRESS addr,
        out byte[]? newPacket)
    {
        newPacket = null;
        try
        {
            int ipHeaderLen = GetIpHeaderLen(packet, packetLen);
            if (ipHeaderLen <= 0) return false;

            unsafe
            {
                fixed (byte* p = packet)
                {
                    var ipVersion = packet[0] >> 4;
                    byte* tcpPtr = p + ipHeaderLen;
                    var tcp = (TcpHeader*)tcpPtr;
                    int tcpHeaderLen = tcp->DataOffsetBytes;
                    int payloadOffset = ipHeaderLen + tcpHeaderLen;
                    int payloadLen = (int)packetLen - payloadOffset;

                    if (payloadLen <= 0) return false;

                    // Extract and modify HTTP request
                    var payload = new byte[payloadLen];
                    Marshal.Copy(new IntPtr(p + payloadOffset), payload, 0, payloadLen);
                    var requestStr = System.Text.Encoding.ASCII.GetString(payload);
                    var modifiedRequest = modifyRequest(requestStr);
                    var modifiedBytes = System.Text.Encoding.ASCII.GetBytes(modifiedRequest);

                    // Build new packet
                    int newPacketLen = payloadOffset + modifiedBytes.Length;
                    newPacket = new byte[newPacketLen];

                    fixed (byte* np = newPacket)
                    {
                        Buffer.MemoryCopy(p, np, newPacketLen, payloadOffset);

                        // Update IP total length / payload length
                        if (ipVersion == 4)
                        {
                            var ipv4 = (V4Header*)np;
                            ipv4->Length = Htons((ushort)newPacketLen);
                        }
                        else
                        {
                            var ipv6 = (V6Header*)np;
                            ipv6->PayloadLength = Htons((ushort)(tcpHeaderLen + modifiedBytes.Length));
                        }

                        // Update TCP payload
                        var ntcp = (TcpHeader*)(np + ipHeaderLen);
                        var payloadDest = np + payloadOffset;
                        Marshal.Copy(modifiedBytes, 0, new IntPtr(payloadDest), modifiedBytes.Length);
                        ntcp->Checksum = 0;
                    }

                    WinDivertNative.WinDivertHelperCalcChecksums(newPacket, (uint)newPacket.Length, ref addr, 0);
                    return true;
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[PacketModifier] Modify HTTP request error: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Tamper with packet payload - generic byte replacement at offset.
    /// </summary>
    public static bool TamperPayload(byte[] packet, uint packetLen,
        int payloadOffset, byte[] newData,
        ref WINDIVERT_ADDRESS addr)
    {
        try
        {
            if (payloadOffset + newData.Length > packetLen) return false;

            unsafe
            {
                fixed (byte* p = packet)
                {
                    var dst = p + payloadOffset;
                    Buffer.BlockCopy(newData, 0, packet, payloadOffset, newData.Length);

                    return WinDivertNative.WinDivertHelperCalcChecksums(packet, packetLen, ref addr, 0);
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[PacketModifier] Tamper error: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Block a packet by recalculating checksums and letting WinDivert drop it.
    /// Actually we just return false from the filter to drop, but this helper
    /// can be used to inject a RST packet instead.
    /// </summary>
    public static bool InjectTcpReset(byte[] originalPacket, uint packetLen,
        ref WINDIVERT_ADDRESS addr, out byte[] resetPacket)
    {
        resetPacket = Array.Empty<byte>();
        try
        {
            int ipHeaderLen = GetIpHeaderLen(originalPacket, packetLen);
            if (ipHeaderLen <= 0) return false;

            unsafe
            {
                fixed (byte* p = originalPacket)
                {
                    var ipVersion = originalPacket[0] >> 4;
                    int tcpHeaderLen = 20; // Minimal RST header
                    int totalLen = ipHeaderLen + tcpHeaderLen;

                    resetPacket = new byte[totalLen];

                    fixed (byte* rp = resetPacket)
                    {
                        // Copy IP header
                        Buffer.MemoryCopy(p, rp, totalLen, ipHeaderLen);

                        if (ipVersion == 4)
                        {
                            var ipv4 = (V4Header*)rp;
                            var origIpv4 = (V4Header*)p;

                            // Swap src/dst
                            var tmp = ipv4->SrcAddr;
                            ipv4->SrcAddr = ipv4->DstAddr;
                            ipv4->DstAddr = tmp;

                            ipv4->Length = Htons((ushort)totalLen);
                            ipv4->TTL = 64;
                            ipv4->Protocol = Protocol.TCP;
                            ipv4->Checksum = 0;

                            var tcp = (TcpHeader*)(rp + ipHeaderLen);
                            var origTcp = (TcpHeader*)(p + ipHeaderLen);

                            // Swap ports
                            tcp->SrcPort = origTcp->DstPort;
                            tcp->DstPort = origTcp->SrcPort;

                            // RST packet: SEQ = ACK of original, ACK = SEQ + payloadLen
                            tcp->SeqNumber = origTcp->AckNumber;
                            tcp->AckNumber = AddToSeq(origTcp->SeqNumber, (uint)(packetLen - ipHeaderLen - origTcp->DataOffsetBytes));
                            tcp->DataOffset = (ushort)((5 << 12) | (byte)TcpFlag.Ack); // 5 * 4 = 20 bytes, ACK flag
                            tcp->Window = 0;
                            tcp->Checksum = 0;
                            tcp->UrgentPointer = 0;
                        }
                        else if (ipVersion == 6)
                        {
                            var ipv6 = (V6Header*)rp;
                            var origIpv6 = (V6Header*)p;

                            // Swap addresses
                            var tmpSrc = stackalloc byte[16];
                            var tmpDst = stackalloc byte[16];
                            Buffer.MemoryCopy(ipv6->SrcAddr, tmpSrc, 16, 16);
                            Buffer.MemoryCopy(ipv6->DstAddr, tmpDst, 16, 16);
                            Buffer.MemoryCopy(tmpDst, ipv6->SrcAddr, 16, 16);
                            Buffer.MemoryCopy(tmpSrc, ipv6->DstAddr, 16, 16);

                            ipv6->PayloadLength = Htons((ushort)tcpHeaderLen);
                            ipv6->NextHdr = Protocol.TCP;
                            ipv6->HopLimit = 64;

                            var tcp = (TcpHeader*)(rp + ipHeaderLen);
                            var origTcp = (TcpHeader*)(p + ipHeaderLen);

                            tcp->SrcPort = origTcp->DstPort;
                            tcp->DstPort = origTcp->SrcPort;
                            tcp->SeqNumber = origTcp->AckNumber;
                            tcp->AckNumber = AddToSeq(origTcp->SeqNumber, (uint)(packetLen - ipHeaderLen - origTcp->DataOffsetBytes));
                            tcp->DataOffset = (ushort)((5 << 12) | (byte)TcpFlag.Ack);
                            tcp->Window = 0;
                            tcp->Checksum = 0;
                            tcp->UrgentPointer = 0;
                        }

                        var newAddr = addr;
                        newAddr.Outbound = !addr.Outbound; // Reverse direction

                        WinDivertNative.WinDivertHelperCalcChecksums(resetPacket, (uint)resetPacket.Length, ref newAddr, 0);
                        return true;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[PacketModifier] Inject RST error: {ex.Message}");
            return false;
        }
    }

    // --- Helper methods ---

    private static int GetIpHeaderLen(byte[] packet, uint packetLen)
    {
        if (packetLen < 1) return 0;
        var version = packet[0] >> 4;
        return version == 4 ? (packet[0] & 0x0F) * 4 : version == 6 ? 40 : 0;
    }

    private static uint IpToUint(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        if (bytes.Length == 4)
        {
            return (uint)(bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24));
        }
        throw new ArgumentException("IPv4 only");
    }

    private static byte[] IpV6ToBytes(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        if (bytes.Length != 16) throw new ArgumentException("IPv6 only");
        return bytes;
    }

    private static ushort Htons(ushort hostShort)
    {
        return (ushort)(((hostShort & 0xFF) << 8) | ((hostShort >> 8) & 0xFF));
    }

    private static uint AddToSeq(uint seq, uint add)
    {
        return seq + add;
    }
}