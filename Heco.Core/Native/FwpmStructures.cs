using System;
using System.Runtime.InteropServices;

namespace Heco.Core.Native;

internal static class WfpNativeTypes
{
    //  Session 

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_SESSION0
    {
        public Guid sessionKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public FWPM_SESSION_FLAG flags;
        public uint txnWaitTimeoutInMSec;
        public uint processId;
        public nint sid;
        [MarshalAs(UnmanagedType.LPWStr)] public string? userName;
        public bool kernelMode;
    }

    //  Display Data ─

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_DISPLAY_DATA0
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string? name;
        [MarshalAs(UnmanagedType.LPWStr)] public string? description;
    }

    //  Provider ─

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_PROVIDER0
    {
        public Guid providerKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public FWPM_PROVIDER_FLAG flags;
        public FWP_BYTE_BLOB providerData;
        [MarshalAs(UnmanagedType.LPWStr)] public string? serviceName;
    }

    //  SubLayer ─

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_SUBLAYER0
    {
        public Guid subLayerKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public FWPM_SUBLAYER_FLAG flags;
        public nint providerKey;
        public FWP_BYTE_BLOB providerData;
        public ushort weight;
    }

    //  Filter 

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_FILTER0
    {
        public Guid filterKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public FWPM_FILTER_FLAG flags;
        public nint providerKey;
        public FWP_BYTE_BLOB providerData;
        public Guid layerKey;
        public Guid subLayerKey;
        public FWP_VALUE0 weight;
        public uint numFilterConditions;
        public nint filterCondition;
        public FWPM_ACTION0 action;
        public ulong rawContext;
        public nint reserved;
        public ulong filterId;
        public FWP_VALUE0 effectiveWeight;
    }

    //  Filter Condition 

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_FILTER_CONDITION0
    {
        public Guid fieldKey;
        public FWP_MATCH_TYPE matchType;
        public FWP_CONDITION_VALUE0 conditionValue;
    }

    //  Action 

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_ACTION0
    {
        public FWP_ACTION_TYPE type;
        public Guid calloutKey;
    }

    //  Value ─

    [StructLayout(LayoutKind.Explicit)]
    internal struct FWP_VALUE_UNION
    {
        [FieldOffset(0)] public byte uint8;
        [FieldOffset(0)] public ushort uint16;
        [FieldOffset(0)] public uint uint32;
        [FieldOffset(0)] public nint uint64;
        [FieldOffset(0)] public int int8;
        [FieldOffset(0)] public short int16;
        [FieldOffset(0)] public int int32;
        [FieldOffset(0)] public nint int64;
        [FieldOffset(0)] public float float32;
        [FieldOffset(0)] public nint double64;
        [FieldOffset(0)] public nint byteArray16;
        [FieldOffset(0)] public nint byteBlob;
        [FieldOffset(0)] public nint sid;
        [FieldOffset(0)] public nint sd;
        [FieldOffset(0)] public nint tokenInformation;
        [FieldOffset(0)] public nint tokenAccessInformation;
        [FieldOffset(0)] public nint unicodeString;
        [FieldOffset(0)] public nint byteArray6;
        [FieldOffset(0)] public nint v4AddrMask;
        [FieldOffset(0)] public nint v6AddrMask;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_VALUE0
    {
        public FWP_DATA_TYPE type;
        public FWP_VALUE_UNION value;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_CONDITION_VALUE0
    {
        public FWP_DATA_TYPE type;
        public FWP_VALUE_UNION value;
    }

    //  Byte Blob ─

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_BYTE_BLOB
    {
        public uint size;
        public nint data;
    }

    //  Address / Mask 

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_V4_ADDR_AND_MASK
    {
        public uint addr;
        public uint mask;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_V6_ADDR_AND_MASK
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] addr;
        public byte prefixLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_BYTE_ARRAY16
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] data;
    }

    //  Callout 

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_CALLOUT0
    {
        public Guid calloutKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public Guid applicableLayer;
        public Guid providerKey;
        public FWP_BYTE_BLOB providerData;
        public uint flags;
        public nint classifyFn;
        public nint notifyFn;
        public nint flowDeleteFn;
    }

    //  Provider Context 

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_PROVIDER_CONTEXT0
    {
        public Guid providerContextKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public Guid providerKey;
        public FWP_BYTE_BLOB providerData;
        public uint type;
        public FWP_VALUE0 data;
    }

    //  Layer ─

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_LAYER0
    {
        public Guid layerKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public ushort layerId;
        public ushort defaultSubLayerKey;
        public uint numFields;
    }

    //  Network Event 

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_NET_EVENT_SUBSCRIPTION0
    {
        public uint flags;
        public nint enumTemplate;
    }

    //  System Ports ─

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_SYSTEM_PORTS_BY_TYPE0
    {
        public ushort portType;
        public uint numPorts;
        public nint ports;
    }

    //  Tunnel / IPsec 

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_TUNNEL_POLICY0
    {
        public Guid providerKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public uint numIpsecFilterIds;
        public nint ipsecFilterIds;
        public nint virtualIfTunnelInfo;
    }
}
