using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace Heco.WinDivert.Dns;

public class DnsResponse
{
    public string Domain { get; set; } = string.Empty;
    public List<string> CNames { get; set; } = [];
    public List<string> IPs { get; set; } = [];
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public int TTL { get; set; }
    public string ResolvedBy { get; set; } = string.Empty;
    public int ResolvedIn { get; set; } = 0;
    public bool Blocked { get; set; } = false;
    public string? BlockedBy { get; set; }
    public string? BlockedReason { get; set; }

    public string IPsAsString => string.Join(", ", IPs);
    public string CNamesAsString => string.Join(", ", CNames);
    public bool HasIPAddress => IPs.Count > 0;
    public string? CNAME => CNames.FirstOrDefault();

    public override string ToString()
    {
        var status = Blocked
            ? (BlockedReason != null ? $"BLOCKED ({BlockedReason})" : "BLOCKED")
            : "ALLOWED";
        return $"{ResolvedBy} {ResolvedIn}ms: {Domain} ({TTL}) = {status} | IPs: {IPs.Count} | CNAMEs: {CNames.Count}";
    }

    public static DnsResponse Parse(byte[] buffer, string queryDomain)
    {
        var response = new DnsResponse { Domain = queryDomain };

        if (buffer.Length < 12) return response;

        int position = 12;

        try
        {
            // Skip query section
            while (position < buffer.Length && buffer[position] != 0)
                position += buffer[position] + 1;
            position += 5; // Skip root 0 + Type (2) + Class (2)

            int answers = (buffer[6] << 8) | buffer[7];

            for (int i = 0; i < answers && position < buffer.Length; i++)
            {
                position = SkipNameReference(buffer, position);
                if (position + 10 > buffer.Length) break;

                int type = (buffer[position] << 8) | buffer[position + 1];
                position += 4;

                response.TTL = (buffer[position] << 24) | (buffer[position + 1] << 16) |
                              (buffer[position + 2] << 8) | buffer[position + 3];
                position += 4;

                int dataLength = (buffer[position] << 8) | buffer[position + 1];
                position += 2;
                if (position + dataLength > buffer.Length) break;

                switch (type)
                {
                    case 1:
                        if (dataLength == 4)
                        {
                            var ip = $"{buffer[position]}.{buffer[position + 1]}.{buffer[position + 2]}.{buffer[position + 3]}";
                            response.IPs.Add(ip);
                        }
                        break;
                    case 28:
                        if (dataLength == 16)
                        {
                            var ipBytes = new byte[16];
                            Array.Copy(buffer, position, ipBytes, 0, 16);
                            response.IPs.Add(new IPAddress(ipBytes).ToString());
                        }
                        break;
                    case 5:
                        response.CNames.Add(ReadDomainName(buffer, position));
                        break;
                    case 12:
                        response.CNames.Add(ReadDomainName(buffer, position));
                        break;
                }

                position += dataLength;
            }
        }
        catch { }

        return response;
    }

    public static string ReadDomainName(byte[] buffer, int position)
    {
        var domain = new System.Text.StringBuilder();
        var currentPosition = position;

        while (currentPosition < buffer.Length)
        {
            if (buffer[currentPosition] == 0)
            {
                break;
            }
            else if ((buffer[currentPosition] & 0xC0) == 0xC0)
            {
                var offset = ((buffer[currentPosition] & 0x3F) << 8) | buffer[currentPosition + 1];
                if (domain.Length > 0) domain.Append('.');
                domain.Append(ReadDomainName(buffer, offset));
                break;
            }
            else
            {
                int length = buffer[currentPosition++];
                if (domain.Length > 0) domain.Append('.');
                for (int i = 0; i < length; i++)
                {
                    domain.Append((char)buffer[currentPosition++]);
                }
            }
        }
        return domain.ToString();
    }

    public static int SkipNameReference(byte[] buffer, int position)
    {
        while (position < buffer.Length)
        {
            if (buffer[position] == 0)
            {
                return position + 1;
            }
            else if ((buffer[position] & 0xC0) == 0xC0)
            {
                return position + 2;
            }
            else
            {
                position += buffer[position] + 1;
            }
        }
        return position;
    }
}
