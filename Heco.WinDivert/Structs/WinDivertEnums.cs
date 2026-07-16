using System;

namespace Heco.WinDivert.Structs;

public enum WinDivertLayer : int
{
    Network = 0, Forward = 1, Flow = 2, Socket = 3, Reflect = 4,
}

public enum WinDivertEvent : int
{
    NetworkPacket = 0, FlowEstablished = 1, FlowDeleted = 2, SocketBind = 3, SocketConnect = 4,
    SocketListen = 5, SocketAccept = 6, SocketClose = 7, ReflectOpen = 8, ReflectClose = 9,
}

[Flags]
public enum WinDivertFlag : ulong
{
    None = 0, Sniff = 0x0001, Drop = 0x0002, RecvOnly = 0x0004, ReadOnly = 0x0004,
    SendOnly = 0x0008, WriteOnly = 0x0008, NoInstall = 0x0010, Fragments = 0x0020,
}

public enum WinDivertShutdown : byte { Recv = 1, Send = 2, Both = 3 }

public enum WinDivertParam : uint
{
    QueueLength = 0, QueueTime = 1, QueueSize = 2, VersionMajor = 3, VersionMinor = 4,
}

[Flags]
public enum ChecksumsFlag : ulong
{
    All = 0, NoIPChecksum = 0x0001, NoIcmpChecksum = 0x0002,
    NoIcmpV6Checksum = 0x0004, NoTcpChecksum = 0x0008, NoUdpChecksum = 0x0010,
}

public static class WinDivertConst
{
    public const short PriorityHighest = 30000;
    public const short PriorityLowest = -30000;
    public const int QueueLengthDefault = 4096;
    public const int QueueLengthMin = 32;
    public const int QueueLengthMax = 16384;
    public const int QueueTimeDefault = 2000;
    public const int QueueTimeMin = 100;
    public const int QueueTimeMax = 16000;
    public const int QueueSizeDefault = 4194304;
    public const int QueueSizeMin = 65535;
    public const int QueueSizeMax = 33554432;
    public const byte BatchMax = 0xFF;
    public const int MtuMax = 40 + 0xFFFF;
    public const int FilterMaxLen = 4096;
    public const int PriorityMin = -30000;
    public const int PriorityMax = 30000;
}

public static class FilterToken
{
    public const string Inbound = "inbound";
    public const string Outbound = "outbound";
    public const string Fragment = "fragment";
    public const string Loopback = "loopback";
    public const string Impostor = "impostor";
    public const string IfIdx = "ifIdx";
    public const string SubIfIdx = "subIfIdx";
    public const string ProcessId = "processId";
    public const string LocalAddr = "localAddr";
    public const string RemoteAddr = "remoteAddr";
    public const string LocalPort = "localPort";
    public const string RemotePort = "remotePort";
    public const string Protocol = "protocol";
    public const string EndpointId = "endpointId";
    public const string ParentEndpointId = "parentEndpointId";
    public const string Layer = "layer";
    public const string Priority = "priority";
    public const string Length = "length";
    public const string Timestamp = "timestamp";
    public const string True = "true";
    public const string False = "false";
    public const string Zero = "zero";
    public const string Random8 = "random8";
    public const string Random16 = "random16";
    public const string Random32 = "random32";
    public const string Event = "event";
    public const string Network = "network";
    public const string NetworkForward = "network_forward";
    public const string Flow = "flow";
    public const string Socket = "socket";
    public const string Reflect = "reflect";
    public const string Packet = "packet";
    public const string Established = "established";
    public const string Deleted = "deleted";
    public const string Bind = "bind";
    public const string Connect = "connect";
    public const string Listen = "listen";
    public const string Accept = "accept";
    public const string Open = "open";
    public const string Close = "close";
    public const string Ip = "ip";
    public const string IpChecksum = "ip.Checksum";
    public const string IpDF = "ip.DF";
    public const string IpDstAddr = "ip.DstAddr";
    public const string IpFragOff = "ip.FragOff";
    public const string IpHdrLength = "ip.HdrLength";
    public const string IpId = "ip.Id";
    public const string IpLength = "ip.Length";
    public const string IpMF = "ip.MF";
    public const string IpProtocol = "ip.Protocol";
    public const string IpSrcAddr = "ip.SrcAddr";
    public const string IpTOS = "ip.TOS";
    public const string IpTTL = "ip.TTL";
    public const string Ipv6 = "ipv6";
    public const string Ipv6DstAddr = "ipv6.DstAddr";
    public const string Ipv6FlowLabel = "ipv6.FlowLabel";
    public const string Ipv6HopLimit = "ipv6.HopLimit";
    public const string Ipv6Length = "ipv6.Length";
    public const string Ipv6NextHdr = "ipv6.NextHdr";
    public const string Ipv6SrcAddr = "ipv6.SrcAddr";
    public const string Ipv6TrafficClass = "ipv6.TrafficClass";
    public const string Icmp = "icmp";
    public const string IcmpType = "icmp.Type";
    public const string IcmpCode = "icmp.Code";
    public const string IcmpChecksum = "icmp.Checksum";
    public const string IcmpBody = "icmp.Body";
    public const string Icmpv6 = "icmpv6";
    public const string Icmpv6Type = "icmpv6.Type";
    public const string Icmpv6Code = "icmpv6.Code";
    public const string Icmpv6Checksum = "icmpv6.Checksum";
    public const string Icmpv6Body = "icmpv6.Body";
    public const string Tcp = "tcp";
    public const string TcpSrcPort = "tcp.SrcPort";
    public const string TcpDstPort = "tcp.DstPort";
    public const string TcpSeqNum = "tcp.SeqNum";
    public const string TcpAckNum = "tcp.AckNum";
    public const string TcpHdrLength = "tcp.HdrLength";
    public const string TcpFin = "tcp.Fin";
    public const string TcpSyn = "tcp.Syn";
    public const string TcpRst = "tcp.Rst";
    public const string TcpPsh = "tcp.Psh";
    public const string TcpAck = "tcp.Ack";
    public const string TcpUrg = "tcp.Urg";
    public const string TcpWindow = "tcp.Window";
    public const string TcpChecksum = "tcp.Checksum";
    public const string TcpUrgPtr = "tcp.UrgPtr";
    public const string TcpPayloadLength = "tcp.PayloadLength";
    public const string TcpPayload = "tcp.Payload";
    public const string TcpPayload16 = "tcp.Payload16";
    public const string TcpPayload32 = "tcp.Payload32";
    public const string Udp = "udp";
    public const string UdpSrcPort = "udp.SrcPort";
    public const string UdpDstPort = "udp.DstPort";
    public const string UdpLength = "udp.Length";
    public const string UdpChecksum = "udp.Checksum";
    public const string UdpPayloadLength = "udp.PayloadLength";
    public const string UdpPayload = "udp.Payload";
    public const string UdpPayload16 = "udp.Payload16";
    public const string UdpPayload32 = "udp.Payload32";
    public const string Packet16 = "packet16";
    public const string Packet32 = "packet32";
    public const string TcpProto = "tcp";
    public const string UdpProto = "udp";
    public const string IcmpProto = "icmp";
    public const string Icmpv6Proto = "icmpv6";
}

public enum TcpFlag : byte
{
    Fin = 0x01, Syn = 0x02, Rst = 0x04, Psh = 0x08, Ack = 0x10, Urg = 0x20,
}

public enum IPVersion : byte { V4 = 4, V6 = 6 }

public enum StateType : int
{
    CLOSED, LISTEN, SYN_SENT, SYN_RECEIVED, ESTABLISHED,
    FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT, CLOSING, LAST_ACK,
    TIME_WAIT, DELETE_TCB, UNKNOWN = -1
}

public enum Protocol : byte
{
    HOPOPT = 0, ICMP = 1, IGMP = 2, GGP = 3, IP_in_IP = 4, ST = 5, TCP = 6, CBT = 7,
    EGP = 8, IGP = 9, BBN_RCC_MON = 10, NVP_II = 11, PUP = 12, ARGUS = 13, EMCON = 14,
    XNET = 15, CHAOS = 16, UDP = 17, MUX = 18, DCN_MEAS = 19, HMP = 20, PRM = 21,
    XNS_IDP = 22, TRUNK_1 = 23, TRUNK_2 = 24, LEAF_1 = 25, LEAF_2 = 26, RDP = 27,
    IRTP = 28, ISO_TP4 = 29, NETBLT = 30, MFE_NSP = 31, MERIT_INP = 32, DCCP = 33,
    _3PC = 34, IDPR = 35, XTP = 36, DDP = 37, IDPR_CMTP = 38, TPPlusPlus = 39,
    IL = 40, IPv6 = 41, SDRP = 42, IPv6_Route = 43, IPv6_Frag = 44, IDRP = 45,
    RSVP = 46, GRE = 47, DSR = 48, BNA = 49, ESP = 50, AH = 51, I_NLSP = 52,
    SWIPE = 53, NARP = 54, MOBILE = 55, TLSP = 56, SKIP = 57, IPv6_ICMP = 58,
    IPv6_NoNxt = 59, IPv6_Opts = 60, AHIP = 61, CFTP = 62, ALN = 63, SAT_EXPAK = 64,
    KRYPTOLAN = 65, RVD = 66, IPPC = 67, ADFS = 68, SAT_MON = 69, VISA = 70,
    IPCU = 71, CPNX = 72, CPHB = 73, WSN = 74, PVP = 75, BR_SAT_MON = 76,
    SUN_ND = 77, WB_MON = 78, WB_EXPAK = 79, ISO_IP = 80, VMTP = 81, SECURE_VMTP = 82,
    VINES = 83, TTP = 84, IPTM = 84, NSFNET_IGP = 85, DGP = 86, TCF = 87,
    EIGRP = 88, OSPF = 89, Sprite_RPC = 90, LARP = 91, MTP = 92, AX_25 = 93,
    OS = 94, MICP = 95, SCC_SP = 96, ETHERIP = 97, ENCAP = 98, APES = 99,
    GMTP = 100, IFMP = 101, PNNI = 102, PIM = 103, ARIS = 104, SCPS = 105,
    QNX = 106, A_N = 107, IPComp = 108, SNP = 109, Compaq_Peer = 110,
    IPX_in_IP = 111, VRRP = 112, PGM = 113, AHOP = 114, L2TP = 115, DDX = 116,
    IATP = 117, STP = 118, SRP = 119, UTI = 120, SMP = 121, SM = 122, PTP = 123,
    IS_IS_Over_IPv4 = 124, FIRE = 125, CRTP = 126, CRUDP = 127, SSCOPMCE = 128,
    IPLT = 129, SPS = 130, PIPE = 131, SCTP = 132, FC = 133, RSVP_E2E_IGNORE = 134,
    Mobility_Header = 135, UDPLite = 136, MPLS_in_IP = 137, MANET = 138, HIP = 139,
    Shim6 = 140, WESP = 141, ROHC = 142
}

[Flags]
public enum FragmentFlag : byte
{
    Reserved = 0, MayFragment = 0, DontFragment = 2, MoreFragments = 4,
}

public enum IcmpV4MessageType : byte
{
    EchoReply = 0, DestinationUnreachable = 3, SourceQuench = 4, Redirect = 5,
    EchoRequest = 8, RouterAdvertisement = 9, RouterSolicitation = 10,
    TimeExceeded = 11, ParameterProblem = 12, TimestampRequest = 13,
    TimestampReply = 14, InformationRequest = 15, InformationReply = 16,
    AddressMaskRequest = 17, AddressMaskReply = 18,
}

public enum IcmpV4UnreachableCode : byte
{
    Net = 0, Host = 1, Protocol = 2, Port = 3, FragNeeded = 4,
    SourceRouteFailed = 5, NetUnknown = 6, HostUnknown = 7,
    SourceHostIsolated = 8, NetProhibited = 9, HostProhibited = 10,
    NetTOS = 11, HostTOS = 12, NetAdmin = 13, HostAdmin = 14,
}

public enum IcmpV6MessageType : byte
{
    DestinationUnreachable = 1, PacketTooBig = 2, TimeExceeded = 3,
    ParameterProblem = 4, EchoRequest = 128, EchoReply = 129,
    RouterSolicitation = 133, RouterAdvertisement = 134,
    NeighborSolicitation = 135, NeighborAdvertisement = 136, Redirect = 137,
}

public enum IcmpV6UnreachableCode : byte
{
    NoRoute = 0, AdminProhibited = 1, BeyondScope = 2,
    AddressUnreachable = 3, PortUnreachable = 4,
    SourceAddressFailed = 5, RejectRoute = 6,
}
