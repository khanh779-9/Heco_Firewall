using System;
using System.Net;
using System.Runtime.InteropServices;

namespace Heco.Common.Native;

/// <summary>
///   P/Invoke declarations for IP Helper API (iphlpapi.dll) and related.
///   Used to enumerate TCP, UDP, ARP, IPNET tables, and adapter/DHCP info.
/// </summary>
internal static class IpHlpApi
{
    //  Address families 
    internal const ushort AF_INET  = 2;
    internal const ushort AF_INET6 = 23;

    //  TCP table classes 
    internal const uint TCP_TABLE_BASIC_LISTENER       = 0;
    internal const uint TCP_TABLE_BASIC_CONNECTIONS     = 1;
    internal const uint TCP_TABLE_BASIC_ALL             = 2;
    internal const uint TCP_TABLE_OWNER_PID_LISTENER    = 3;
    internal const uint TCP_TABLE_OWNER_PID_CONNECTIONS  = 4;
    internal const uint TCP_TABLE_OWNER_PID_ALL         = 5;
    internal const uint TCP_TABLE_OWNER_MODULE_LISTENER  = 6;
    internal const uint TCP_TABLE_OWNER_MODULE_CONNECTIONS = 7;
    internal const uint TCP_TABLE_OWNER_MODULE_ALL       = 8;

    internal const uint UDP_TABLE_BASIC       = 0;
    internal const uint UDP_TABLE_OWNER_PID   = 1;
    internal const uint UDP_TABLE_OWNER_MODULE = 2;

    //  TCP states (MIB_TCP_STATE) ─
    internal const uint MIB_TCP_STATE_CLOSED     = 0;
    internal const uint MIB_TCP_STATE_LISTEN     = 1;
    internal const uint MIB_TCP_STATE_SYN_SENT   = 2;
    internal const uint MIB_TCP_STATE_SYN_RCVD   = 3;
    internal const uint MIB_TCP_STATE_ESTAB      = 4;
    internal const uint MIB_TCP_STATE_FIN_WAIT1  = 5;
    internal const uint MIB_TCP_STATE_FIN_WAIT2  = 6;
    internal const uint MIB_TCP_STATE_CLOSE_WAIT = 7;
    internal const uint MIB_TCP_STATE_CLOSING    = 8;
    internal const uint MIB_TCP_STATE_LAST_ACK   = 9;
    internal const uint MIB_TCP_STATE_TIME_WAIT  = 10;
    internal const uint MIB_TCP_STATE_DELETE_TCB = 11;

    //  TCP structures 

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_TCPTABLE_OWNER_PID
    {
        public uint dwNumEntries;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_UDPROW_OWNER_PID
    {
        public uint localAddr;
        public uint localPort;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_UDPTABLE_OWNER_PID
    {
        public uint dwNumEntries;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct MIB_TCP6ROW_OWNER_PID
    {
        public fixed byte localAddr[16];
        public uint localScopeId;
        public uint localPort;
        public fixed byte remoteAddr[16];
        public uint remoteScopeId;
        public uint remotePort;
        public uint state;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct MIB_UDP6ROW_OWNER_PID
    {
        public fixed byte localAddr[16];
        public uint localScopeId;
        public uint localPort;
        public uint owningPid;
    }

    //  ARP / IPNET (v4) structures ─

    internal const int MAXLEN_PHYSADDR = 8;

    internal enum MIB_IPNET_TYPE : int
    {
        Other   = 1,
        Invalid = 2,
        Dynamic = 3,
        Static  = 4
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_IPNETROW
    {
        public int dwIndex;
        public int dwPhysAddrLen;
        public uint dwAddr;
        public MIB_IPNET_TYPE dwType;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = MAXLEN_PHYSADDR)]
        public byte[] bPhysAddr;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_IPNETTABLE
    {
        public uint dwNumEntries;
    }

    //  IPNET (v6) structures (GetIpNetTable2) 

    internal enum NL_NEIGHBOR_STATE
    {
        Unreachable = 0,
        Incomplete = 1,
        Probe = 2,
        Stale = 3,
        Reachable = 4,
        Delay = 5,
        Permanent = 6
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct MIB_IPNET_ROW2
    {
        public ushort si_family;           // 0:2
        public ushort si_port;             // 2:2
        public uint si_scope_id;           // 4:4
        public fixed byte si_address[16];  // 8:16
        public uint InterfaceIndex;        // 24:4
        public fixed byte PhysicalAddress[8]; // 28:8
        public uint PhysicalAddressLength; // 36:4
        public NL_NEIGHBOR_STATE State;    // 40:4
    } // Size: 44

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_IPNET_TABLE2
    {
        public uint NumEntries;
        // Followed by MIB_IPNET_ROW2[NumEntries] inline
    }

    //  ICMP statistics structures 

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_ICMPSTATS
    {
        public uint dwMsgs;
        public uint dwErrors;
        public uint dwDestUnreachs;
        public uint dwTimeExcds;
        public uint dwParmProbs;
        public uint dwSrcQuenchs;
        public uint dwRedirects;
        public uint dwEchos;
        public uint dwEchoReps;
        public uint dwTimestamps;
        public uint dwTimestampReps;
        public uint dwAddrMasks;
        public uint dwAddrMaskReps;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_ICMPINFO
    {
        public MIB_ICMPSTATS icmpInStats;
        public MIB_ICMPSTATS icmpOutStats;
    }

    //  IP statistics structures 

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_IPSTATS
    {
        public uint dwForwarding;
        public uint dwDefaultTTL;
        public uint dwInReceives;
        public uint dwInHdrErrors;
        public uint dwInAddrErrors;
        public uint dwForwDatagrams;
        public uint dwInUnknownProtos;
        public uint dwInDiscards;
        public uint dwInDelivers;
        public uint dwOutRequests;
        public uint dwRoutingDiscards;
        public uint dwOutDiscards;
        public uint dwOutNoRoutes;
        public uint dwReasmTimeout;
        public uint dwReasmReqds;
        public uint dwReasmOks;
        public uint dwReasmFails;
        public uint dwFragOks;
        public uint dwFragFails;
        public uint dwFragCreates;
        public uint dwNumIf;
        public uint dwNumAddr;
        public uint dwNumRoutes;
    }

    //  API: TCP/UDP 

    [DllImport("iphlpapi.dll", SetLastError = true)]
    internal static extern uint GetExtendedTcpTable(
        nint pTcpTable, ref uint pdwSize, bool bOrder,
        uint af, uint tableClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    internal static extern uint GetExtendedUdpTable(
        nint pUdpTable, ref uint pdwSize, bool bOrder,
        uint af, uint tableClass, uint reserved);

    //  API: ARP / IPNET 

    [DllImport("iphlpapi.dll", SetLastError = true)]
    internal static extern int GetIpNetTable(
        nint pIpNetTable, ref int pdwSize, bool bOrder);

    [DllImport("iphlpapi.dll")]
    internal static extern int GetIpNetTable2(
        ushort Family, out nint Table);

    [DllImport("iphlpapi.dll")]
    internal static extern void FreeMibTable(nint Memory);

    //  API: ICMP / IP stats ─

    [DllImport("iphlpapi.dll")]
    internal static extern int GetIcmpStatistics(ref MIB_ICMPINFO pStats);

    [DllImport("iphlpapi.dll")]
    internal static extern int GetIpStatistics(ref MIB_IPSTATS pStats);

    //  API: DHCP / adapter info 

    internal const uint GAA_FLAG_INCLUDE_PREFIX = 0x0010;
    internal const uint GAA_FLAG_SKIP_DNS_SERVER = 0x0002;
    internal const uint GAA_FLAG_SKIP_MULTICAST = 0x0004;

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct IP_ADAPTER_ADDRESSES
    {
        public nint Next;                  // 0:8
        public nint FirstAdapterAddress;   // 8:8  (always null in LH+)
        public uint IfIndex;               // 16:4
        public nint FirstUnicastAddress;   // 20:8
        public nint FirstAnycastAddress;   // 28:8
        public nint FirstMulticastAddress; // 36:8
        public nint FirstDnsServerAddress; // 44:8
        public ushort DdnsEnabled;         // 52:2
        public ushort RegisterAdapterSuffix; // 54:2
        public uint Dhcpv4Enabled;         // 56:4
        public uint ReceiveOnly;           // 60:4
        public uint NoMulticast;           // 64:4
        public nint FirstWinsAddress;      // 68:8
        public nint FirstGatewayAddress;   // 76:8
        public uint Ipv4Metric;            // 84:4
        public uint Ipv6Metric;            // 88:4
        public uint IfType;                // 92:4
        public ushort OperStatus;          // 96:2
        public ushort Reserved1;           // 98:2
        public uint TransmitLinkSpeed;     // 100:4
        public uint ReceiveLinkSpeed;      // 104:4
        public nint FirstPrefix;           // 108:8
        public nint FirstWinsServer;       // 116:8
        public nint FirstGateway;          // 124:8
        public uint Ipv4Metric2;           // 132:4
        public uint Ipv6Metric2;           // 136:4
        public ulong LeaseLifetime;        // 140:8
        public nint Dhcpv4Server;          // 148:8
        public nint Dhcpv6Server;          // 156:8
        public nint FirstDnsSuffix;        // 164:8
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    internal static extern uint GetAdaptersAddresses(
        uint Family, uint Flags, nint Reserved,
        nint AdapterAddresses, ref uint SizePointer);

    //  SOCKADDR helpers 

    internal static unsafe IPAddress? ReadSockAddr(nint addrPtr)
    {
        if (addrPtr == 0) return null;
        var family = Marshal.ReadInt16(addrPtr);
        if (family == AF_INET)
        {
            // SOCKADDR_IN: family(2) + port(2) + addr(4) + zero(8) = 16 bytes
            var bytes = new byte[4];
            Marshal.Copy(addrPtr + 4, bytes, 0, 4);
            Array.Reverse(bytes); // network byte order → host
            return new IPAddress(bytes);
        }
        if (family == AF_INET6)
        {
            // SOCKADDR_IN6: family(2) + port(2) + flowinfo(4) + addr(16) + scope(4) = 28 bytes
            var bytes = new byte[16];
            Marshal.Copy(addrPtr + 8, bytes, 0, 16);
            return new IPAddress(bytes);
        }
        return null;
    }
}
