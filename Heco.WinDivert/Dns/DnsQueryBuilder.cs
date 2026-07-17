using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace Heco.WinDivert.Dns;

public static class DnsQueryBuilder
{
    private static int _queryId = 1;

    private const byte NamePointerHigh = 0xC0;
    private const byte OriginalQueryOffset = 12;

    public static byte[] CreateUDP(string domain, DnsQueryType queryType = DnsQueryType.A)
    {
        var query = new List<byte>();

        var id = (ushort)Interlocked.Increment(ref _queryId);
        AppendUInt16(query, id);
        AppendUInt16(query, 0x0100);
        AppendUInt16(query, 1);
        AppendUInt16(query, 0);
        AppendUInt16(query, 0);
        AppendUInt16(query, 0);

        foreach (var label in domain.Split('.'))
        {
            query.Add((byte)label.Length);
            query.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }
        query.Add(0);

        AppendUInt16(query, (ushort)queryType);
        AppendUInt16(query, 1);

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

        responsePacket.AddRange(originalQuery.Take(2));
        responsePacket.AddRange(new byte[] { 0x81, 0x80 });

        AppendUInt16(responsePacket, 1);
        AppendUInt16(responsePacket, (ushort)(dnsResponse.IPs.Count + dnsResponse.CNames.Count));
        AppendUInt16(responsePacket, 0);
        AppendUInt16(responsePacket, 0);

        AppendQuestionSection(responsePacket, originalQuery);

        foreach (var cname in dnsResponse.CNames)
        {
            AppendNamePointer(responsePacket);
            AppendUInt16(responsePacket, 5);
            AppendUInt16(responsePacket, 1);
            AppendUInt32(responsePacket, (uint)dnsResponse.TTL);

            var cnameBytes = DnsUtils.EncodeDomainName(cname);
            AppendUInt16(responsePacket, (ushort)cnameBytes.Length);
            responsePacket.AddRange(cnameBytes);
        }

        foreach (var ip in dnsResponse.IPs)
        {
            AppendNamePointer(responsePacket);
            if (ip.Contains(':'))
            {
                AppendUInt16(responsePacket, 28);
                AppendUInt16(responsePacket, 1);
                AppendUInt32(responsePacket, (uint)dnsResponse.TTL);
                AppendUInt16(responsePacket, 16);
                responsePacket.AddRange(System.Net.IPAddress.Parse(ip).GetAddressBytes());
                continue;
            }

            AppendUInt16(responsePacket, 1);
            AppendUInt16(responsePacket, 1);
            AppendUInt32(responsePacket, (uint)dnsResponse.TTL);
            AppendUInt16(responsePacket, 4);
            responsePacket.AddRange(ip.Split('.').Select(byte.Parse));
        }

        return responsePacket.ToArray();
    }

    private static void AppendUInt16(List<byte> target, ushort value)
    {
        target.AddRange(BitConverter.GetBytes(value).Reverse());
    }

    private static void AppendUInt32(List<byte> target, uint value)
    {
        target.AddRange(BitConverter.GetBytes(value).Reverse());
    }

    private static void AppendNamePointer(List<byte> target)
    {
        target.Add(NamePointerHigh);
        target.Add(OriginalQueryOffset);
    }

    private static void AppendQuestionSection(List<byte> target, byte[] originalQuery)
    {
        int queryLength = GetQuestionSectionLength(originalQuery);
        target.AddRange(originalQuery.Skip(OriginalQueryOffset).Take(queryLength));
    }

    private static int GetQuestionSectionLength(byte[] query)
    {
        int length = 0;
        for (int i = OriginalQueryOffset; i < query.Length; i++)
        {
            length++;
            if (query[i] != 0)
                continue;

            length += 4;
            break;
        }

        return length;
    }
}
