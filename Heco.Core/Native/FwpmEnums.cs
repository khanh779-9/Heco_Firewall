using System;

namespace Heco.Core.Native;

internal enum FWPM_ENGINE_OPTION : uint
{
    CollectNetEvents       = 0x00000001,
    NetEventsMatchAny      = 0x00000002,
    RegisterForAuditEvents = 0x00000003,
    CollectIpsecEvents     = 0x00000004,
    AllowBypass            = 0x00000005,
    CollectAleEndpoints    = 0x00000006,
    PacketQueuing          = 0x00000007,
}

//  Session Flags 
[Flags]
internal enum FWPM_SESSION_FLAG : uint
{
    None    = 0,
    Dynamic = 0x00000001,
}

//  Provider Flags ─
[Flags]
internal enum FWPM_PROVIDER_FLAG : ulong
{
    None = 0,
}

//  SubLayer Flags ─
[Flags]
internal enum FWPM_SUBLAYER_FLAG : ulong
{
    None = 0,
}

//  Filter Flags ─
[Flags]
internal enum FWPM_FILTER_FLAG : uint
{
    None                       = 0,
    Persistent                 = 0x00000001,
    BootTime                   = 0x00000002,
    HasProviderContext         = 0x00000004,
    ClearActionRight           = 0x00000008,
    PermitIfCalloutUnregistered = 0x00000010,
    Disabled                   = 0x00000020,
    Indexed                    = 0x00000040,
}

//  Data Types 
internal enum FWP_DATA_TYPE : uint
{
    Empty                = 0,
    UInt8                = 1,
    UInt16               = 2,
    UInt32               = 3,
    UInt64               = 4,
    Int8                 = 5,
    Int16                = 6,
    Int32                = 7,
    Int64                = 8,
    Float                = 9,
    Double               = 10,
    ByteArray16Type      = 11,
    ByteBlobType         = 12,
    Sid                  = 13,
    SecurityDescriptorType = 14,
    TokenInformationType = 15,
    TokenAccessInformationType = 16,
    UnicodeStringType    = 17,
    ByteArray6Type       = 18,
    V4AddrMask           = 19,
    V6AddrMask           = 20,
}

//  Match Types 
internal enum FWP_MATCH_TYPE : uint
{
    Equal           = 0,
    GreaterThan     = 1,
    LessThan        = 2,
    GreaterOrEqual  = 3,
    LessOrEqual     = 4,
    Range           = 5,
    FlagsAllSet     = 6,
    FlagsAnySet     = 7,
    FlagsNoneSet    = 8,
    EqualCaseInsensitive = 9,
    NotEqual        = 10,
    Prefix          = 11,
    NotPrefix       = 12,
}

//  Action Types ─
internal enum FWP_ACTION_TYPE : uint
{
    Block               = 0x00000001,
    Permit              = 0x00000002,
    CalloutTerminating  = 0x00000003,
    CalloutInspection   = 0x00000004,
    CalloutUnknown      = 0x00000005,
}
