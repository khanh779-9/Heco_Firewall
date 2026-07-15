using System;

namespace Heco.WinDivert.Native;

public enum WinDivertLayer : int
{
    Network = 0,
    Forward = 1,
    Flow = 2,
    Socket = 3,
    Reflect = 4,
}

public enum WinDivertEvent : int
{
    NetworkPacket = 0,
    FlowEstablished = 1,
    FlowDeleted = 2,
    SocketBind = 3,
    SocketConnect = 4,
    SocketListen = 5,
    SocketAccept = 6,
    SocketClose = 7,
    ReflectOpen = 8,
    ReflectClose = 9,
}

[Flags]
public enum WinDivertFlag : ulong
{
    None = 0,
    Sniff = 0x0001,
    Drop = 0x0002,
    RecvOnly = 0x0004,
    ReadOnly = 0x0004,
    SendOnly = 0x0008,
    WriteOnly = 0x0008,
    NoInstall = 0x0010,
    Fragments = 0x0020,
}

public enum WinDivertShutdown : byte
{
    Recv = 1,
    Send = 2,
    Both = 3,
}

public enum WinDivertParam : uint
{
    QueueLength = 0,
    QueueTime   = 1,
    QueueSize   = 2,
    VersionMajor = 3,
    VersionMinor = 4,
}

[Flags]
public enum ChecksumsFlag : ulong
{
    All              = 0,
    NoIPChecksum     = 0x0001,
    NoIcmpChecksum   = 0x0002,
    NoIcmpV6Checksum = 0x0004,
    NoTcpChecksum    = 0x0008,
    NoUdpChecksum    = 0x0010,
}

public static class WinDivertConst
{
    public const short PriorityHighest = 30000;
    public const short PriorityLowest  = -30000;

    public const int QueueLengthDefault = 4096;
    public const int QueueLengthMin     = 32;
    public const int QueueLengthMax     = 16384;
    public const int QueueTimeDefault   = 2000;
    public const int QueueTimeMin       = 100;
    public const int QueueTimeMax       = 16000;
    public const int QueueSizeDefault   = 4194304;
    public const int QueueSizeMin       = 65535;
    public const int QueueSizeMax       = 33554432;

    public const byte BatchMax = 0xFF;
    public const int MtuMax    = 40 + 0xFFFF;
}

public enum TcpFlag : byte
{
    Fin = 0x01,
    Syn = 0x02,
    Rst = 0x04,
    Psh = 0x08,
    Ack = 0x10,
    Urg = 0x20,
}

public enum IPVersion : byte
{
    V4 = 4,
    V6 = 6,
}

/// <summary>
/// Enumeration representing the various states of a TCP connection.
/// </summary>
public enum StateType : int
{
    /// <summary>
    /// The connection is closed.
    /// </summary>
    CLOSED,

    /// <summary>
    /// The connection is listening for incoming connections.
    /// </summary>
    LISTEN,

    /// <summary>
    /// The connection has sent a SYN (synchronize) packet.
    /// </summary>
    SYN_SENT,

    /// <summary>
    /// The connection has received a SYN packet.
    /// </summary>
    SYN_RECEIVED,

    /// <summary>
    /// The connection is established.
    /// </summary>
    ESTABLISHED,

    /// <summary>
    /// The connection is in the first stage of closing (FIN_WAIT_1).
    /// </summary>
    FIN_WAIT_1,

    /// <summary>
    /// The connection is in the second stage of closing (FIN_WAIT_2).
    /// </summary>
    FIN_WAIT_2,

    /// <summary>
    /// The connection is waiting for a closing response (CLOSE_WAIT).
    /// </summary>
    CLOSE_WAIT,

    /// <summary>
    /// The connection is in the process of closing (CLOSING).
    /// </summary>
    CLOSING,

    /// <summary>
    /// The connection has received the last acknowledgment (LAST_ACK).
    /// </summary>
    LAST_ACK,

    /// <summary>
    /// The connection is in the TIME_WAIT state.
    /// </summary>
    TIME_WAIT,

    /// <summary>
    /// The connection is deleted (DELETE_TCB).
    /// </summary>
    DELETE_TCB,

    /// <summary>
    /// The state of the connection is unknown.
    /// </summary>
    UNKNOWN = -1
}


public enum Protocol : byte
{
    HOPOPT = 0,
    ICMP = 1,
    IGMP = 2,
    GGP = 3,
    IP_in_IP = 4,
    ST = 5,
    TCP = 6,
    CBT = 7,
    EGP = 8,
    IGP = 9,
    BBN_RCC_MON = 10,
    NVP_II = 11,
    PUP = 12,
    ARGUS = 13,
    EMCON = 14,
    XNET = 15,
    CHAOS = 16,
    UDP = 17,
    MUX = 18,
    DCN_MEAS = 19,
    HMP = 20,
    PRM = 21,
    XNS_IDP = 22,
    TRUNK_1 = 23,
    TRUNK_2 = 24,
    LEAF_1 = 25,
    LEAF_2 = 26,
    RDP = 27,
    IRTP = 28,
    ISO_TP4 = 29,
    NETBLT = 30,
    MFE_NSP = 31,
    MERIT_INP = 32,
    DCCP = 33,
    _3PC = 34,
    IDPR = 35,
    XTP = 36,
    DDP = 37,
    IDPR_CMTP = 38,
    TPPlusPlus = 39,
    IL = 40,
    IPv6 = 41,
    SDRP = 42,
    IPv6_Route = 43,
    IPv6_Frag = 44,
    IDRP = 45,
    RSVP = 46,
    GRE = 47,
    DSR = 48,
    BNA = 49,
    ESP = 50,
    AH = 51,
    I_NLSP = 52,
    SWIPE = 53,
    NARP = 54,
    MOBILE = 55,
    TLSP = 56,
    SKIP = 57,
    IPv6_ICMP = 58,
    IPv6_NoNxt = 59,
    IPv6_Opts = 60,
    AHIP = 61,
    CFTP = 62,
    ALN = 63,
    SAT_EXPAK = 64,
    KRYPTOLAN = 65,
    RVD = 66,
    IPPC = 67,
    ADFS = 68,
    SAT_MON = 69,
    VISA = 70,
    IPCU = 71,
    CPNX = 72,
    CPHB = 73,
    WSN = 74,
    PVP = 75,
    BR_SAT_MON = 76,
    SUN_ND = 77,
    WB_MON = 78,
    WB_EXPAK = 79,
    ISO_IP = 80,
    VMTP = 81,
    SECURE_VMTP = 82,
    VINES = 83,
    TTP = 84,
    IPTM = 84,
    NSFNET_IGP = 85,
    DGP = 86,
    TCF = 87,
    EIGRP = 88,
    OSPF = 89,
    Sprite_RPC = 90,
    LARP = 91,
    MTP = 92,
    AX_25 = 93,
    OS = 94,
    MICP = 95,
    SCC_SP = 96,
    ETHERIP = 97,
    ENCAP = 98,
    APES = 99,
    GMTP = 100,
    IFMP = 101,
    PNNI = 102,
    PIM = 103,
    ARIS = 104,
    SCPS = 105,
    QNX = 106,
    A_N = 107,
    IPComp = 108,
    SNP = 109,
    Compaq_Peer = 110,
    IPX_in_IP = 111,
    VRRP = 112,
    PGM = 113,
    AHOP = 114,
    L2TP = 115,
    DDX = 116,
    IATP = 117,
    STP = 118,
    SRP = 119,
    UTI = 120,
    SMP = 121,
    SM = 122,
    PTP = 123,
    IS_IS_Over_IPv4 = 124,
    FIRE = 125,
    CRTP = 126,
    CRUDP = 127,
    SSCOPMCE = 128,
    IPLT = 129,
    SPS = 130,
    PIPE = 131,
    SCTP = 132,
    FC = 133,
    RSVP_E2E_IGNORE = 134,
    Mobility_Header = 135,
    UDPLite = 136,
    MPLS_in_IP = 137,
    MANET = 138,
    HIP = 139,
    Shim6 = 140,
    WESP = 141,
    ROHC = 142
}


