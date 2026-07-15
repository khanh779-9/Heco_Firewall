using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;

namespace Heco.WinDivert.Dns;

public class DnsQuery
{
    public byte[] RawQuery { get; }
    public IPAddress IpAddress { get; }
    public int Port { get; }
    public DateTime Timestamp { get; }

    public ushort TransactionId { get; set; }
    public bool IsQuery { get; set; }
    public ushort Flags { get; set; }

    public ushort QuestionCount { get; set; }
    public ushort AnswerCount { get; set; }
    public ushort AuthorityCount { get; set; }
    public ushort AdditionalCount { get; set; }

    public string? QueryDomain { get; set; }
    public DnsQueryType QueryType { get; set; }
    public DnsQueryClass QueryClass { get; set; }
    public bool Recurse { get; set; }

    public DnsQuery(byte[] rawQuery, IPEndPoint remoteEndPoint)
    {
        RawQuery = rawQuery;
        IpAddress = remoteEndPoint.Address;
        Port = remoteEndPoint.Port;
        Timestamp = DateTime.UtcNow;
        ParseDnsHeader();
        Recurse = false;
    }

    public DnsQuery(DnsQueryType queryType, string domain, IPAddress ipAddress, int port)
    {
        QueryType = queryType;
        QueryDomain = domain;
        IpAddress = ipAddress;
        Port = port;
        Timestamp = DateTime.UtcNow;
        RawQuery = DnsQueryBuilder.CreateUDP(domain, queryType);
        ParseDnsHeader();
        Recurse = false;
    }

    public override string ToString()
    {
        return $"{QueryDomain} {IpAddress}:{Port} " +
               $"{TransactionId} {Flags} " +
               $"{QuestionCount} {AnswerCount} " +
               $"{AuthorityCount} {AdditionalCount} " +
               $"{QueryType} {QueryClass}";
    }

    public static bool IsValidQuery(DnsQuery query)
    {
        if (query.RawQuery.Length < 12)
        {
            Debug.WriteLine($"DnsValidation: Query too short ({query.RawQuery.Length} bytes)");
            return false;
        }

        var opcode = (query.Flags >> 11) & 0xF;
        if (!query.IsQuery || opcode != 0)
        {
            Debug.WriteLine($"DnsValidation: Invalid query flags - QR:{!query.IsQuery}, OPCODE:{opcode}");
            return false;
        }

        if (query.QuestionCount != 1)
        {
            Debug.WriteLine($"DnsValidation: Invalid question count: {query.QuestionCount}");
            return false;
        }

        if (string.IsNullOrWhiteSpace(query.QueryDomain))
        {
            return false;
        }

        if (!Enum.IsDefined(typeof(DnsQueryType), query.QueryType))
        {
            Debug.WriteLine($"DnsValidation: Non-standard query type: {query.QueryType} for {query.QueryDomain}");
            return true;
        }

        if (query.QueryClass != DnsQueryClass.IN)
        {
            Debug.WriteLine($"DnsValidation: Invalid query class: {query.QueryClass}");
            return false;
        }

        return true;
    }

    private void ParseDnsHeader()
    {
        if (RawQuery.Length < 12) return;

        TransactionId = (ushort)((RawQuery[0] << 8) | RawQuery[1]);
        Flags = (ushort)((RawQuery[2] << 8) | RawQuery[3]);
        IsQuery = (Flags & 0x8000) == 0;
        QuestionCount = (ushort)((RawQuery[4] << 8) | RawQuery[5]);
        AnswerCount = (ushort)((RawQuery[6] << 8) | RawQuery[7]);
        AuthorityCount = (ushort)((RawQuery[8] << 8) | RawQuery[9]);
        AdditionalCount = (ushort)((RawQuery[10] << 8) | RawQuery[11]);

        QueryDomain = DnsUtils.ExtractDomain(RawQuery);

        // Parse the Question section properly: the first question starts at
        // offset 12. After the domain name (terminated by a 0 byte), the next
        // 4 bytes are QueryType (2) and QueryClass (2). This is correct even
        // when EDNS0 OPT records are present in the Additional section, because
        // the Question section always comes first.
        var questionEnd = FindQuestionEnd(RawQuery);
        if (questionEnd >= 0 && questionEnd + 4 <= RawQuery.Length)
        {
            QueryType = (DnsQueryType)((RawQuery[questionEnd] << 8) | RawQuery[questionEnd + 1]);
            QueryClass = (DnsQueryClass)((RawQuery[questionEnd + 2] << 8) | RawQuery[questionEnd + 3]);
        }
    }

    /// <summary>
    ///   Walk the domain-name labels starting at offset 12 and return the
    ///   index of the first byte after the terminating 0 byte (the start of
    ///   the QueryType field).  Returns -1 if the name is malformed.
    /// </summary>
    private static int FindQuestionEnd(byte[] data)
    {
        int pos = 12; // DNS header is 12 bytes
        while (pos < data.Length)
        {
            int labelLen = data[pos];
            if (labelLen == 0)
            {
                // Root label — end of name. The next byte is the start of QTYPE.
                return pos + 1;
            }
            // Compression pointer (0xC0+) not expected in a question, but
            // treat defensively: we can't follow pointers without a full
            // message context, so bail out.
            if ((labelLen & 0xC0) == 0xC0)
                return -1;
            pos += 1 + labelLen;
        }
        return -1;
    }
}

public enum DnsQueryType : ushort
{
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    ANY = 255,
    HTTPS = 65,
    SVCB = 64,
    OPT = 41,
    CAA = 257,
}

public enum DnsQueryClass : ushort
{
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    ANY = 255
}
