using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace Heco.WinDivert.Dns;

public static class DnsQueryBuilder
{
    private static int _queryId = 1;

    public static byte[] CreateUDP(string domain, DnsQueryType queryType = DnsQueryType.A)
    {
        var query = new List<byte>();

        var id = (ushort)Interlocked.Increment(ref _queryId);
        query.AddRange(BitConverter.GetBytes(id).Reverse()); // Transaction ID (big endian)
        query.AddRange(new byte[] { 1, 0 }); // Flags: standard query, recursion desired
        query.AddRange(new byte[] { 0, 1 }); // Questions: 1
        query.AddRange(new byte[] { 0, 0 }); // Answer RRs: 0
        query.AddRange(new byte[] { 0, 0 }); // Authority RRs: 0
        query.AddRange(new byte[] { 0, 0 }); // Additional RRs: 0

        foreach (var label in domain.Split('.'))
        {
            query.Add((byte)label.Length);
            query.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }
        query.Add(0); // Root label

        query.AddRange(new byte[] { 0, (byte)queryType, 0, 1 }); // Type and Class (IN)

        return query.ToArray();
    }

    public static byte[] CreateBlockedResponse(byte[] originalQuery, string domain, DnsQueryType queryType)
    {
        var response = new DnsResponse
        {
            Domain = domain,
            TTL = 3600, // 1 hour cache
            Blocked = true,
            IPs = queryType == DnsQueryType.AAAA ? new List<string> { "::" } : new List<string> { "0.0.0.0" }
        };
        return CreateResponse(originalQuery, response);
    }

    public static byte[] CreateResponse(byte[] originalQuery, DnsResponse dnsResponse)
    {
        var responsePacket = new List<byte>();

        // Copy transaction ID and set response flags
        responsePacket.AddRange(originalQuery.Take(2));
        responsePacket.AddRange(new byte[] { 0x81, 0x80 }); // Standard response, recursion available, no error

        // Add counts
        responsePacket.AddRange(new byte[] { 0, 1 }); // Questions: 1
        responsePacket.AddRange(BitConverter.GetBytes((ushort)(dnsResponse.IPs.Count + dnsResponse.CNames.Count)).Reverse());
        responsePacket.AddRange(new byte[] { 0, 0 }); // Authority RRs: 0
        responsePacket.AddRange(new byte[] { 0, 0 }); // Additional RRs: 0

        // Copy original query section (starts at byte 12)
        int queryLen = 0;
        for (int i = 12; i < originalQuery.Length; i++)
        {
            queryLen++;
            if (originalQuery[i] == 0)
            {
                queryLen += 4; // Type (2) + Class (2)
                break;
            }
        }
        responsePacket.AddRange(originalQuery.Skip(12).Take(queryLen));

        // Add CNAME records
        foreach (var cname in dnsResponse.CNames)
        {
            // Name pointer pointing to the original query domain (offset 12)
            responsePacket.AddRange(new byte[] { 0xC0, 12 });
            responsePacket.AddRange(new byte[] { 0, 5 }); // Type: CNAME
            responsePacket.AddRange(new byte[] { 0, 1 }); // Class: IN
            responsePacket.AddRange(BitConverter.GetBytes((uint)dnsResponse.TTL).Reverse());

            var cnameBytes = DnsUtils.EncodeDomainName(cname);
            responsePacket.AddRange(BitConverter.GetBytes((ushort)cnameBytes.Length).Reverse());
            responsePacket.AddRange(cnameBytes);
        }

        // Add A and AAAA records
        foreach (var ip in dnsResponse.IPs)
        {
            // Name pointer pointing to the original query domain (offset 12)
            responsePacket.AddRange(new byte[] { 0xC0, 12 });

            if (ip.Contains(':')) // IPv6 (AAAA)
            {
                responsePacket.AddRange(new byte[] { 0, 28 }); // Type: AAAA
                responsePacket.AddRange(new byte[] { 0, 1 });  // Class: IN
                responsePacket.AddRange(BitConverter.GetBytes((uint)dnsResponse.TTL).Reverse());
                responsePacket.AddRange(new byte[] { 0, 16 }); // Length: 16

                var ipBytes = System.Net.IPAddress.Parse(ip).GetAddressBytes();
                responsePacket.AddRange(ipBytes);
            }
            else // IPv4 (A)
            {
                responsePacket.AddRange(new byte[] { 0, 1 }); // Type: A
                responsePacket.AddRange(new byte[] { 0, 1 }); // Class: IN
                responsePacket.AddRange(BitConverter.GetBytes((uint)dnsResponse.TTL).Reverse());
                responsePacket.AddRange(new byte[] { 0, 4 });  // Length: 4
                responsePacket.AddRange(ip.Split('.').Select(byte.Parse));
            }
        }

        return responsePacket.ToArray();
    }
}
