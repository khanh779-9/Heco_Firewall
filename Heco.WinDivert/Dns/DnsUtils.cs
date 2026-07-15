using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace Heco.WinDivert.Dns;

public static class DnsUtils
{
    public static string ExtractDomain(byte[] buffer)
    {
        if (buffer == null || buffer.Length <= 12)
            return string.Empty;
        var domain = new System.Text.StringBuilder(buffer.Length);
        int position = 12; // DNS header is 12 bytes
        try
        {
            while (position < buffer.Length && buffer[position] != 0)
            {
                int length = buffer[position];
                if (position + length >= buffer.Length)
                    return string.Empty;

                position++;
                domain.Append(System.Text.Encoding.ASCII.GetString(buffer, position, length));
                position += length;
                domain.Append('.');
            }
            return domain.Length > 0 ? domain.ToString(0, domain.Length - 1) : string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    public static byte[] EncodeDomainName(string domain)
    {
        var result = new List<byte>();
        foreach (var label in domain.Split('.'))
        {
            result.Add((byte)label.Length);
            result.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }
        result.Add(0); // Root label
        return result.ToArray();
    }

    public static string? GetPtrDomainFromIPAddress(IPAddress ipAddress)
    {
        if (ipAddress.AddressFamily == AddressFamily.InterNetwork) // IPv4
        {
            var octets = ipAddress.GetAddressBytes();
            Array.Reverse(octets);
            return string.Join(".", octets) + ".in-addr.arpa";
        }
        else if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6) // IPv6
        {
            var addrBytes = ipAddress.GetAddressBytes();
            var nibbleList = new List<string>();
            foreach (var b in addrBytes.Reverse())
            {
                nibbleList.Add((b & 0x0F).ToString("x"));
                nibbleList.Add((b >> 4).ToString("x"));
            }
            return string.Join(".", nibbleList) + ".ip6.arpa";
        }
        else
        {
            return null;
        }
    }
}
