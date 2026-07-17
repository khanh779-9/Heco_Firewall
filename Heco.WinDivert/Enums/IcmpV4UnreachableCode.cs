namespace Heco.WinDivert.Enums;

public enum IcmpV4UnreachableCode : byte
{
    Net = 0, Host = 1, Protocol = 2, Port = 3, FragNeeded = 4,
    SourceRouteFailed = 5, NetUnknown = 6, HostUnknown = 7,
    SourceHostIsolated = 8, NetProhibited = 9, HostProhibited = 10,
    NetTOS = 11, HostTOS = 12, NetAdmin = 13, HostAdmin = 14,
}