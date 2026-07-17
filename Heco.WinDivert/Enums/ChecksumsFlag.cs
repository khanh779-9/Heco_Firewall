using System;

namespace Heco.WinDivert.Enums;

[Flags]
public enum ChecksumsFlag : ulong
{
    All = 0, NoIPChecksum = 0x0001, NoIcmpChecksum = 0x0002,
    NoIcmpV6Checksum = 0x0004, NoTcpChecksum = 0x0008, NoUdpChecksum = 0x0010,
}