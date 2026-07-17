namespace Heco.WinDivert.Enums;

public enum IcmpV6MessageType : byte
{
    DestinationUnreachable = 1, PacketTooBig = 2, TimeExceeded = 3,
    ParameterProblem = 4, EchoRequest = 128, EchoReply = 129,
    RouterSolicitation = 133, RouterAdvertisement = 134,
    NeighborSolicitation = 135, NeighborAdvertisement = 136, Redirect = 137,
}