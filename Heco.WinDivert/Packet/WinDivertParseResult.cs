using Heco.WinDivert.Structs;

namespace Heco.WinDivert.Packet;

public sealed unsafe class WinDivertParseResult
{
    public Structs.V4Header* V4 { get; }
    public Structs.V6Header* V6 { get; }
    public Protocol Protocol { get; }
    public byte* Icmp4 { get; }
    public byte* Icmp6 { get; }
    public byte* Tcp { get; }
    public byte* Udp { get; }
    public byte* Data { get; }
    public int DataLen { get; }
    public byte* Next { get; }
    public int NextLen { get; }

    internal WinDivertParseResult(
        Structs.V4Header* v4,
        Structs.V6Header* v6,
        Protocol protocol,
        byte* icmp4, byte* icmp6,
        byte* tcp, byte* udp,
        byte* data, int dataLen,
        byte* next, int nextLen)
    {
        V4 = v4;
        V6 = v6;
        Protocol = protocol;
        Icmp4 = icmp4;
        Icmp6 = icmp6;
        Tcp = tcp;
        Udp = udp;
        Data = data;
        DataLen = dataLen;
        Next = next;
        NextLen = nextLen;
    }

    //  Convenience: L4 fields thông qua V4-> hoặc V6-> 
    public ushort SrcPort => V4 != null ? V4->SrcPort : V6 != null ? V6->SrcPort : (ushort)0;
    public ushort DstPort => V4 != null ? V4->DstPort : V6 != null ? V6->DstPort : (ushort)0;
}
