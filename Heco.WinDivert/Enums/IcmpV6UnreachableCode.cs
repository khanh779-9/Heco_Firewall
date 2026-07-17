namespace Heco.WinDivert.Enums;

public enum IcmpV6UnreachableCode : byte
{
    NoRoute = 0, AdminProhibited = 1, BeyondScope = 2,
    AddressUnreachable = 3, PortUnreachable = 4,
    SourceAddressFailed = 5, RejectRoute = 6,
}