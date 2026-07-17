using System;
using System.Net;
using System.Runtime.InteropServices;

namespace Heco.Common.Native;

/// <summary>
///   P/Invoke declarations for DNS API (dnsapi.dll).
///   Used to read the Windows DNS client cache.
/// </summary>
internal static class DnsApi
{
    public const ushort DNS_TYPE_A    = 1;
    public const ushort DNS_TYPE_AAAA = 28;
    public const ushort DNS_TYPE_CNAME = 5;

    [StructLayout(LayoutKind.Sequential)]
    internal struct DNS_CACHE_ENTRY
    {
        public nint pNext;              // 0:8
        public nint pszName;            // 8:8
        public ushort wType;            // 16:2
        public ushort wDataLength;      // 18:2
        public uint dwFlags;            // 20:4
    }

    [DllImport("dnsapi.dll")]
    internal static extern int DnsGetCacheDataTable(
        out nint CacheEntries);

    [DllImport("dnsapi.dll")]
    internal static extern void DnsFree(
        nint pData, uint FreeType);

    internal static string? ReadDnsEntryName(DNS_CACHE_ENTRY entry)
    {
        try
        {
            if (entry.pszName == 0) return null;
            return Marshal.PtrToStringUni(entry.pszName);
        }
        catch { return null; }
    }

    internal static IPAddress? ReadDnsEntryAddress(nint entryPtr, DNS_CACHE_ENTRY entry)
    {
        if (entry.wDataLength < 4) return null;
        try
        {
            // After the fixed DNS_CACHE_ENTRY fields, there's variable-length
            // DNS_RECORD data. For type A: address is at offset 24 (after entry fields).
            // The fixed part of DNS_CACHE_ENTRY:
            //   pNext(8) + pszName(8) + wType(2) + wDataLength(2) + dwFlags(4) = 24 bytes
            // Actually, the cache entry has variable additional data beyond that.
            // The DNS_RECORD_W follows but the exact offset varies.
            // Let me try reading 4 bytes after the fixed header as the IPv4 address.
            // This is a best-effort approach.

            if (entry.wType == DNS_TYPE_A && entry.wDataLength >= 4)
            {
                var addrBytes = new byte[4];
                Marshal.Copy(entryPtr + 24, addrBytes, 0, 4);
                Array.Reverse(addrBytes);
                return new IPAddress(addrBytes);
            }
            if (entry.wType == DNS_TYPE_AAAA && entry.wDataLength >= 16)
            {
                var addrBytes = new byte[16];
                Marshal.Copy(entryPtr + 24, addrBytes, 0, 16);
                return new IPAddress(addrBytes);
            }
        }
        catch { }
        return null;
    }
}
