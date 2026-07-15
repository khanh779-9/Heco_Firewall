# Implementation Plan: Heco Firewall — WPF-Based Windows Firewall Application

> **Date:** 2026-07-10  
> **Author:** Claude Code (based on research of 3 existing projects + Microsoft WFP documentation)  
> **Tech Stack:** C#, .NET 6/8, WPF, WFP (Windows Filtering Platform), MVVM

---

## Table of Contents
1. [Research Summary](#1-research-summary)
2. [Architecture Overview](#2-architecture-overview)
3. [Project Structure](#3-project-structure)
4. [Phase 1: Foundation — WFP Engine Layer](#4-phase-1-foundation--wfp-engine-layer)
5. [Phase 2: Network Monitor Layer](#5-phase-2-network-monitor-layer)
6. [Phase 3: Rule Engine & Policy Management](#6-phase-3-rule-engine--policy-management)
7. [Phase 4: WPF UI — MVVM Dashboard](#7-phase-4-wpf-ui--mvvm-dashboard)
8. [Phase 5: Advanced Features](#8-phase-5-advanced-features)
9. [Phase 6: Packaging, Deployment & Testing](#9-phase-6-packaging-deployment--testing)
10. [Data Flow Diagrams](#10-data-flow-diagrams)
11. [Appendix: Key WFP API Reference](#11-appendix-key-wfp-api-reference)

---

## 1. Research Summary

### 1.1 Existing Projects Analyzed

| Project | Type | Strengths | Weaknesses | Key Lessons |
|---------|------|-----------|------------|-------------|
| **Albion-master** | .NET 5.0 Console | Clean WFP abstraction, good GUID definitions, P/Invoke to `FWPUCLNT.DLL`, proper `NativePtrs` disposable pattern | No kernel callout, no UI, no process monitoring | How to structure C# WFP P/Invoke layer |
| **WFP_App** (3 sub-projects) | WinForms + Class Library | WFPFilterManager library, PacketInterceptor, FormAddRule structure, rich WFP condition building helpers | FormAddRule has NO event handlers = incomplete, dead code in Helper | How to build WFP filter conditions with all match types |
| **Network_Packet_Analyzer** | WinForms .NET 4.7.2 | Excellent `iphlpapi` polling (TCP/UDP/ARP/ICMP tables), raw socket capture, event-driven `ConnectionsMonitor` | Uses deprecated `Thread.Abort()`, inverted status label bug, no WFP | How to monitor network connections in real-time + sniff packets |
| **Microsoft WFP Docs** | MSDN/WDK | Complete API reference, all layer/condition GUIDs, filter management, ALE layers | C/C++ focused, no C# examples | Exact GUIDs, structure layouts for P/Invoke |

### 1.2 Key Architectural Decisions

Based on the research:

1. **Pure User-Mode WFP** — No kernel callout driver needed. Use `FWPUCLNT.DLL` P/Invoke (same as Albion-master). This avoids driver signing complexity while still allowing full PERMIT/BLOCK filtering on ALE layers.

2. **ALE Layers for Firewall Rules** — Use `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` (outbound) and `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6` (inbound). These layers provide application identity (`ALE_APP_ID`), user identity, ports, addresses, and protocols.

3. **iphlpapi for Connection Monitoring** — Use `GetExtendedTcpTable`/`GetExtendedUdpTable` (same as Network_Packet_Analyzer) for live connection monitoring. Poll every 1-2 seconds.

4. **WPF + MVVM** — Modern WPF UI with `CommunityToolkit.Mvvm` for clean separation.

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Heco Firewall (WPF)                          │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                   Presentation Layer (WPF)                     │  │
│  │  ┌──────────┐  ┌──────────────┐  ┌──────────┐  ┌──────────┐  │  │
│  │  │Dashboard  │  │  Rules View  │  │Monitor   │  │Settings  │  │  │
│  │  │(Real-time)│  │  (Add/Edit/  │  │View      │  │View      │  │  │
│  │  │           │  │   Delete)    │  │(Live Con-│  │(App/Excep-│  │  │
│  │  │           │  │              │  │nections) │  │tions)    │  │  │
│  │  └─────┬─────┘  └──────┬───────┘  └────┬─────┘  └────┬─────┘  │  │
│  │        │               │               │             │         │  │
│  │  ┌─────┴───────────────┴───────────────┴─────────────┴─────┐  │  │
│  │  │              ViewModels (MVVM)                            │  │  │
│  │  │  DashboardVM ~ RuleManagerVM ~ MonitorVM ~ SettingsVM    │  │  │
│  │  └─────────────────────────┬─────────────────────────────────┘  │  │
│  └────────────────────────────┼────────────────────────────────────┘  │
│                               │                                       │
│  ┌────────────────────────────┼────────────────────────────────────┐  │
│  │                 Service Layer (DI)                               │  │
│  │  ┌──────────────┐  ┌──────────────────┐  ┌──────────────────┐  │  │
│  │  │WfpEngine     │  │ConnectionMonitor │  │PacketSniffer     │  │  │
│  │  │(Add/Remove   │  │(iphlpapi polling)│  │(Raw Socket/      │  │  │
│  │  │ Rules via WFP)│  │                  │  │ Event Tracing)   │  │  │
│  │  └──────┬───────┘  └────────┬─────────┘  └────────┬─────────┘  │  │
│  └─────────┼───────────────────┼──────────────────────┼───────────┘  │
└────────────┼───────────────────┼──────────────────────┼──────────────┘
             │                   │                      │
             ▼                   ▼                      ▼
     ┌──────────────┐   ┌──────────────┐   ┌──────────────────┐
     │ FWPUCLNT.DLL │   │ iphlpapi.dll │   │ WinSock / ETW    │
     │ (WFP API)    │   │ (IP Helper)  │   │ (Raw Socket)     │
     └──────┬───────┘   └──────┬───────┘   └────────┬─────────┘
            │                  │                     │
            ▼                  ▼                     ▼
     ┌───────────────────────────────────────────────────────┐
     │              Windows Filtering Platform               │
     │           (Built-in Kernel + User Mode Engine)        │
     └───────────────────────────────────────────────────────┘
```

---

## 3. Project Structure

```
Heco_Firewall/
├── Heco_Firewall.sln
│
├── src/
│   ├── Heco_Firewall/                          # WPF App (Main UI)
│   │   ├── Heco_Firewall.csproj                # .NET 8, WPF, Windows
│   │   ├── App.xaml / App.xaml.cs
│   │   ├── MainWindow.xaml / MainWindow.xaml.cs
│   │   │
│   │   ├── Views/
│   │   │   ├── DashboardView.xaml
│   │   │   ├── RulesView.xaml
│   │   │   ├── MonitorView.xaml
│   │   │   ├── RuleEditorView.xaml
│   │   │   ├── ProcessDetailView.xaml
│   │   │   └── SettingsView.xaml
│   │   │
│   │   ├── ViewModels/
│   │   │   ├── DashboardViewModel.cs
│   │   │   ├── RulesViewModel.cs
│   │   │   ├── MonitorViewModel.cs
│   │   │   ├── RuleEditorViewModel.cs
│   │   │   ├── ProcessDetailViewModel.cs
│   │   │   └── SettingsViewModel.cs
│   │   │
│   │   ├── Converters/
│   │   │   ├── ActionTypeToColorConverter.cs
│   │   │   ├── BooleanToStateStringConverter.cs
│   │   │   └── ProtocolToIconConverter.cs
│   │   │
│   │   ├── Resources/
│   │   │   ├── Styles/
│   │   │   ├── Themes/
│   │   │   └── Icons/
│   │   │
│   │   └── Properties/
│   │
│   ├── Heco_WfpEngine/                         # WFP Engine Library
│   │   ├── Heco_WfpEngine.csproj               # .NET 8 Class Library
│   │   │
│   │   ├── Engine/
│   │   │   ├── WfpEngine.cs                    # Main WFP session manager
│   │   │   ├── WfpEngine.Disposable.cs          # IDisposable pattern
│   │   │   ├── WfpProvider.cs                   # Provider management
│   │   │   └── WfpSubLayer.cs                   # SubLayer management
│   │   │
│   │   ├── Filtering/
│   │   │   ├── WfpFilter.cs                     # High-level filter abstraction
│   │   │   ├── WfpFilterCollection.cs           # Filter CRUD collection
│   │   │   ├── FilterConditionBuilder.cs        # Fluent condition builder
│   │   │   └── FilterFactory.cs                 # Pre-built filter templates
│   │   │
│   │   ├── Rules/
│   │   │   ├── FirewallRule.cs                  # Domain model: rule
│   │   │   ├── RuleAction.cs                    # enum: Permit/Block
│   │   │   ├── RuleDirection.cs                 # enum: Inbound/Outbound
│   │   │   ├── NetworkProtocol.cs               # enum: TCP/UDP/ICMP/Any
│   │   │   ├── AddressFamily.cs                 # enum: IPv4/IPv6
│   │   │   └── RuleProfile.cs                   # enum: Domain/Private/Public
│   │   │
│   │   ├── Native/                              # P/Invoke declarations
│   │   │   ├── FwpmNative.cs                    # [DllImport("FWPUCLNT.DLL")]
│   │   │   ├── FwpmStructures.cs                # All WFP structs [StructLayout]
│   │   │   ├── FwpmConstants.cs                 # GUIDs: layers, conditions, callouts
│   │   │   ├── FwpmEnums.cs                     # Enumerations
│   │   │   └── NativePtrs.cs                    # Marshal.AllocHGlobal RAII tracker
│   │   │
│   │   ├── Eventing/
│   │   │   ├── NetEventSubscriber.cs             # Subscribe to WFP net events
│   │   │   └── FilterChangeMonitor.cs            # Monitor WFP filter changes
│   │   │
│   │   └── Extensions/
│   │       └── WfpExtensions.cs                  # Helper methods
│   │
│   ├── Heco_Monitor/                            # Network Monitor Library
│   │   ├── Heco_Monitor.csproj                  # .NET 8 Class Library
│   │   │
│   │   ├── ConnectionMonitor.cs                  # Polls iphlpapi for TCP/UDP
│   │   ├── ConnectionInfo.cs                     # Domain model: connection
│   │   ├── ConnectionEventArgs.cs                # Events
│   │   │
│   │   ├── Sniffer/
│   │   │   ├── PacketSniffer.cs                  # Raw socket / promiscuous mode
│   │   │   ├── PacketHeader.cs                   # IP/TCP/UDP header parsing
│   │   │   └── PacketEventArgs.cs
│   │   │
│   │   ├── ProcessResolver.cs                    # PID → Process name/path/icon
│   │   ├── PortResolver.cs                       # Port → Service name
│   │   ├── DnsResolver.cs                        # IP → Hostname (async)
│   │   │
│   │   └── Native/                               # iphlpapi P/Invoke
│   │       ├── IpHelperApi.cs
│   │       ├── IpHelperStructures.cs
│   │       └── IpHelperEnums.cs
│   │
│   └── Heco_Common/                              # Shared Domain Library
│       ├── Heco_Common.csproj
│       ├── Models/
│       │   ├── Rule.cs                           # Shared rule model
│       │   ├── Connection.cs
│       │   ├── ProcessInfo.cs
│       │   └── TrafficStats.cs
│       │
│       ├── Enums/
│       │   ├── RuleAction.cs
│       │   ├── Direction.cs
│       │   └── Protocol.cs
│       │
│       └── Interfaces/
│           ├── IWfpEngine.cs
│           ├── IConnectionMonitor.cs
│           └── IFirewallRuleRepository.cs
│
├── tests/
│   ├── Heco_WfpEngine.Tests/
│   │   ├── WfpEngineTests.cs
│   │   └── FilterConditionBuilderTests.cs
│   │
│   ├── Heco_Monitor.Tests/
│   │   ├── ConnectionMonitorTests.cs
│   │   └── ProcessResolverTests.cs
│   │
│   └── Heco_Firewall.Tests/
│       ├── ViewModelTests.cs
│       └── IntegrationTests.cs
│
├── docs/
│   ├── implement_plan.md                         # This document
│   ├── wfp_reference.md
│   └── screenshots/
│
├── scripts/
│   ├── build.ps1
│   └── deploy.ps1
│
├── .gitignore
└── README.md
```

---

## 4. Phase 1: Foundation — WFP Engine Layer

**Duration:** ~5-7 days  
**Core Library:** `Heco_WfpEngine`

### 4.1 Native P/Invoke Layer (`Native/`)

#### 4.1.1 `FwpmNative.cs` — Core P/Invoke Declarations

```csharp
// DllImport("FWPUCLNT.DLL") methods:
internal static class FwpmNative
{
    // --- Engine Management ---
    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmEngineOpen0(
        [In, Optional] string serverName,
        [In] uint authnService,        // RPC_C_AUTHN_WINNT = 10
        [In] IntPtr authIdentity,
        [In] ref FWPM_SESSION0 session,
        [Out] out IntPtr engineHandle
    );

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmEngineClose0(
        [In] IntPtr engineHandle
    );

    // --- Provider Management ---
    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmProviderAdd0(
        [In] IntPtr engineHandle,
        [In] ref FWPM_PROVIDER0 provider,
        [In, Optional] IntPtr sd
    );

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmProviderDeleteByKey0(
        [In] IntPtr engineHandle,
        [In] ref Guid providerKey
    );

    // --- SubLayer Management ---
    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmSubLayerAdd0(
        [In] IntPtr engineHandle,
        [In] ref FWPM_SUBLAYER0 subLayer,
        [In, Optional] IntPtr sd
    );

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmSubLayerDeleteByKey0(
        [In] IntPtr engineHandle,
        [In] ref Guid subLayerKey
    );

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmSubLayerCreateEnumHandle0(
        [In] IntPtr engineHandle,
        [In] IntPtr enumTemplate,
        [Out] out IntPtr enumHandle
    );

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmSubLayerEnum0(
        [In] IntPtr engineHandle,
        [In] IntPtr enumHandle,
        [In] uint numEntriesRequested,
        [Out] out IntPtr entries,
        [Out] out uint numEntriesReturned
    );

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmSubLayerDestroyEnumHandle0(
        [In] IntPtr engineHandle,
        [In] IntPtr enumHandle
    );

    // --- Filter Management ---
    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmFilterAdd0(
        [In] IntPtr engineHandle,
        [In] ref FWPM_FILTER0 filter,
        [In, Optional] IntPtr sd,
        [Out] out ulong filterId
    );

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmFilterDeleteByKey0(
        [In] IntPtr engineHandle,
        [In] ref Guid filterKey
    );

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmFilterCreateEnumHandle0(
        [In] IntPtr engineHandle,
        [In] IntPtr enumTemplate,
        [Out] out IntPtr enumHandle
    );

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmFilterEnum0(
        [In] IntPtr engineHandle,
        [In] IntPtr enumHandle,
        [In] uint numEntriesRequested,
        [Out] out IntPtr entries,
        [Out] out uint numEntriesReturned
    );

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmFilterDestroyEnumHandle0(
        [In] IntPtr engineHandle,
        [In] IntPtr enumHandle
    );

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmFilterGetByKey0(
        [In] IntPtr engineHandle,
        [In] ref Guid filterKey,
        [Out] out IntPtr filter
    );

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmFilterDeleteById0(
        [In] IntPtr engineHandle,
        [In] ulong filterId
    );

    // --- App ID ---
    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmGetAppIdFromFileName0(
        [In, MarshalAs(UnmanagedType.LPWStr)] string fileName,
        [Out] out IntPtr appId
    );

    // --- Memory Management ---
    [DllImport("FWPUCLNT.DLL")]
    internal static extern void FwpmFreeMemory0(
        [In] ref IntPtr pointer
    );

    // --- Transactions ---
    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmTransactionBegin0(
        [In] IntPtr engineHandle,
        [In] uint flags     // 0 = begin
    );

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmTransactionCommit0(
        [In] IntPtr engineHandle
    );

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmTransactionAbort0(
        [In] IntPtr engineHandle
    );

    // --- Net Events ---
    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmNetEventSubscribe0(
        [In] IntPtr engineHandle,
        [In] ref FWPM_NET_EVENT_SUBSCRIPTION0 subscription,
        [In] FWPM_NET_EVENT_CALLBACK0 callback,
        [In] IntPtr context
    );

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmNetEventUnsubscribe0(
        [In] IntPtr engineHandle,
        [In] IntPtr subscriptionHandle
    );
}
```

#### 4.1.2 `FwpmStructures.cs` — Key WFP Structures

```csharp
[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_SESSION0
{
    public Guid sessionKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public FWPM_SESSION_FLAG flags;
    public uint txnWaitTimeoutInMSec;
    public uint processId;
    public IntPtr sid;           // PSID
    [MarshalAs(UnmanagedType.LPWStr)] public string username;
    public bool kernelMode;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_DISPLAY_DATA0
{
    [MarshalAs(UnmanagedType.LPWStr)] public string name;
    [MarshalAs(UnmanagedType.LPWStr)] public string description;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_PROVIDER0
{
    public Guid providerKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public FWPM_PROVIDER_FLAG flags;
    public FWP_BYTE_BLOB providerData;
    [MarshalAs(UnmanagedType.LPWStr)] public string serviceName;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_SUBLAYER0
{
    public Guid subLayerKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public FWPM_SUBLAYER_FLAG flags;
    public IntPtr providerKey;    // GUID*
    public FWP_BYTE_BLOB providerData;
    public ushort weight;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_FILTER0
{
    public Guid filterKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public FWPM_FILTER_FLAG flags;
    public IntPtr providerKey;                    // GUID*
    public FWP_BYTE_BLOB providerData;
    public Guid layerKey;
    public Guid subLayerKey;
    public FWP_VALUE0 weight;
    public uint numFilterConditions;
    public IntPtr filterCondition;                // FWPM_FILTER_CONDITION0*
    public FWPM_ACTION0 action;
    public ulong rawContext;                      // or GUID providerContextKey
    public IntPtr reserved;
    public ulong filterId;
    public FWP_VALUE0 effectiveWeight;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_FILTER_CONDITION0
{
    public Guid fieldKey;
    public FWP_MATCH_TYPE matchType;
    public FWP_CONDITION_VALUE0 conditionValue;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_ACTION0
{
    public FWP_ACTION_TYPE type;
    public Guid filterType;       // union: calloutKey when type is CALLOUT
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWP_VALUE0
{
    public FWP_DATA_TYPE type;
    // Union — use explicit layout in C#:
    public FWP_VALUE_UNION value;
}

[StructLayout(LayoutKind.Explicit)]
internal struct FWP_VALUE_UNION
{
    [FieldOffset(0)] public byte uint8;
    [FieldOffset(0)] public ushort uint16;
    [FieldOffset(0)] public uint uint32;
    [FieldOffset(0)] public IntPtr uint64;      // UInt64*
    [FieldOffset(0)] public IntPtr byteBlob;    // FWP_BYTE_BLOB*
    [FieldOffset(0)] public IntPtr byteArray16; // FWP_BYTE_ARRAY16*
    [FieldOffset(0)] public IntPtr unicodeString;
    [FieldOffset(0)] public IntPtr sd;          // FWP_BYTE_BLOB* (security desc)
    [FieldOffset(0)] public IntPtr v4AddrMask;  // FWP_V4_ADDR_AND_MASK*
    [FieldOffset(0)] public IntPtr v6AddrMask;  // FWP_V6_ADDR_AND_MASK*
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWP_BYTE_BLOB
{
    public uint size;
    public IntPtr data;   // byte*
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWP_V4_ADDR_AND_MASK
{
    public uint addr;    // host order
    public uint mask;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWP_V6_ADDR_AND_MASK
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] addr;
    public byte prefixLength;
}
```

> **Note:** For `FWP_CONDITION_VALUE0`, use the same union layout as `FWP_VALUE0` (same fields), and for `FWPM_NET_EVENT_SUBSCRIPTION0` / `FWPM_NET_EVENT_CALLBACK0`, use delegate marshaling.

#### 4.1.3 `FwpmConstants.cs` — GUID Definitions

Critical GUIDs (from Albion-master + MS Docs):

```csharp
internal static class WfpLayerGuids
{
    // Ale Connect (outbound)
    public static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V4 =
        new("2A5FFBA1-E8B4-4DC7-A27F-2577BA1A6340");
    public static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V6 =
        new("78C2B39A-31AF-44F8-8E9F-A38213F543EC");

    // Ale Receive/Accept (inbound)
    public static readonly Guid FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 =
        new("E1CDD904-C67C-4763-A862-4C47274A80B0");
    public static readonly Guid FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 =
        new("2504C081-C099-4621-B567-13120B2B4223");

    // Transport layers
    public static readonly Guid FWPM_LAYER_INBOUND_TRANSPORT_V4 =
        new("111C5E0C-EB34-46C7-93EC-B0D298A41AAD");
    public static readonly Guid FWPM_LAYER_OUTBOUND_TRANSPORT_V4 =
        new("E53F06D4-1E96-4572-A651-02A65AB31F0B");
    public static readonly Guid FWPM_LAYER_INBOUND_TRANSPORT_V6 =
        new("46951D22-5B6B-4C74-83FC-B9B33CB3C048");
    public static readonly Guid FWPM_LAYER_OUTBOUND_TRANSPORT_V6 =
        new("1E02DFCE-CA2E-4112-8977-47E07DBD0F45");

    // Stream layer
    public static readonly Guid FWPM_LAYER_STREAM_V4 =
        new("7F07FE95-27D6-4281-96BB-D2327C6FDC5D");
    public static readonly Guid FWPM_LAYER_STREAM_V6 =
        new("77C37125-5D57-4697-B8FA-307279A5D8D6");
}

internal static class WfpConditionGuids
{
    public static readonly Guid FWPM_CONDITION_IP_PROTOCOL =
        new("B3F3E81D-EACF-4B4F-8607-083D0854C28A");
    public static readonly Guid FWPM_CONDITION_IP_LOCAL_PORT =
        new("4EA3D3C6-4B30-4C2D-87B1-87A88DB518D1");
    public static readonly Guid FWPM_CONDITION_IP_REMOTE_PORT =
        new("B4BD1275-445B-4B0E-B7E1-12604431D450");
    public static readonly Guid FWPM_CONDITION_IP_LOCAL_ADDRESS =
        new("5A2F608E-79FE-4A77-9473-C5D0F20E4E1D");
    public static readonly Guid FWPM_CONDITION_IP_REMOTE_ADDRESS =
        new("4814D290-A5C0-4D28-B39D-B2D7ACDDCDEE");
    public static readonly Guid FWPM_CONDITION_ALE_APP_ID =
        new("C1C0144B-22F4-4CAA-B4A0-D48138AD7A16");
    public static readonly Guid FWPM_CONDITION_ALE_USER_ID =
        new("2072F20B-2831-4A7B-A48B-63822666967B");
    public static readonly Guid FWPM_CONDITION_FLAGS =
        new("632CEF2B-B6C2-4C5A-B99A-7FD14E4DEF22");
    public static readonly Guid FWPM_CONDITION_DIRECTION =
        new("B4DED1BB-EFB7-40A7-A318-8656053A39B7");
    public static readonly Guid FWPM_CONDITION_IP_LOCAL_INTERFACE =
        new("1C1B4AE4-1261-4428-B5D6-F94B0A66032F");
}
```

### 4.2 Engine Layer (`Engine/`)

#### 4.2.1 `WfpEngine.cs` — Core WFP Manager

```csharp
public sealed class WfpEngine : IDisposable, IWfpEngine
{
    // Provider identity
    private static readonly Guid ProviderKey = new("HEXO-PROV-..."); // Generate once
    private const string ProviderName = "Heco Firewall";
    private const string ProviderDescription = "Heco Firewall — Advanced WFP-based firewall";

    // Engine constants
    private const uint RPC_C_AUTHN_WINNT = 10;
    private const uint SESSION_FLAG_DYNAMIC = 0x00000001;  // Reset on session close

    private IntPtr _engineHandle = IntPtr.Zero;
    private bool _initialized;
    private readonly object _lock = new();
    private readonly List<Guid> _subLayerKeys = new();

    public event EventHandler<NetEventEventArgs>? NetEventReceived;

    public WfpEngine()
    {
        // Generate sublayer GUIDs
        _subLayerKeys.Add(Guid.NewGuid()); // Outbound-V4
        _subLayerKeys.Add(Guid.NewGuid()); // Outbound-V6
        _subLayerKeys.Add(Guid.NewGuid()); // Inbound-V4
        _subLayerKeys.Add(Guid.NewGuid()); // Inbound-V6
    }

    public void Initialize()
    {
        lock (_lock)
        {
            if (_initialized) return;
            OpenEngine();
            AddProvider();
            AddSubLayers();
            _initialized = true;
        }
    }

    private void OpenEngine()
    {
        var session = new FWPM_SESSION0
        {
            displayData = new FWPM_DISPLAY_DATA0
            {
                name = "Heco Firewall Session",
                description = "Firewall management session"
            },
            flags = FWPM_SESSION_FLAG.DYNAMIC, // Auto-clean on close
            txnWaitTimeoutInMSec = 15000
        };

        uint result = FwpmNative.FwpmEngineOpen0(
            null, RPC_C_AUTHN_WINNT, IntPtr.Zero,
            ref session, out _engineHandle);

        if (result != WinError.ERROR_SUCCESS)
            throw new WfpException("FwpmEngineOpen0", result);
    }

    private void AddProvider() { /* FwpmProviderAdd0 with ProviderKey */ }
    private void AddSubLayers() { /* 4 sublayers, one per direction/IP version */ }

    public void Close()
    {
        lock (_lock)
        {
            if (!_initialized) return;
            ClearAllFilters();
            DeleteSubLayers();
            DeleteProvider();
            CloseEngine();
            _initialized = false;
        }
    }

    public FirewallRule AddRule(FirewallRule rule) { /* Implement filter creation */ }
    public bool RemoveRule(Guid ruleKey) { /* FwpmFilterDeleteByKey0 */ }
    public IEnumerable<FirewallRule> GetRules() { /* Enumerate all filters */ }
    public void ClearAllFilters() { /* Enumerate + delete */ }

    public void Dispose() { Close(); }
}
```

#### 4.2.2 `FilterConditionBuilder.cs` — Fluent Builder

```csharp
public class FilterConditionBuilder
{
    private readonly List<FWPM_FILTER_CONDITION0> _conditions = new();
    private readonly NativePtrs _ptrs = new();

    public FilterConditionBuilder AddProtocol(IP_PROTOCOL protocol)
    {
        var cond = new FWPM_FILTER_CONDITION0
        {
            fieldKey = WfpConditionGuids.FWPM_CONDITION_IP_PROTOCOL,
            matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
            conditionValue = new FWP_CONDITION_VALUE0
            {
                type = FWP_DATA_TYPE.FWP_UINT8,
                value = new FWP_VALUE_UNION { uint8 = (byte)protocol }
            }
        };
        _conditions.Add(cond);
        return this;
    }

    public FilterConditionBuilder AddLocalPort(ushort port)
    {
        // Add condition for FWPM_CONDITION_IP_LOCAL_PORT
        return this;
    }

    public FilterConditionBuilder AddRemotePort(ushort port) { /* ... */ return this; }
    public FilterConditionBuilder AddLocalAddress(IPAddress addr, byte maskLength) { /* ... */ return this; }
    public FilterConditionBuilder AddRemoteAddress(IPAddress addr, byte maskLength) { /* ... */ return this; }
    public FilterConditionBuilder AddApplication(string filePath) { /* FwpmGetAppIdFromFileName0 */ return this; }
    public FilterConditionBuilder AddUserId(string userName) { /* Security descriptor */ return this; }

    public (FWPM_FILTER_CONDITION0[] Conditions, NativePtrs Ptrs) Build()
    {
        // Return conditions array + ptrs for unmanaged memory cleanup
        return (_conditions.ToArray(), _ptrs);
    }
}
```

### 4.3 Rule Domain Model (`Rules/`)

```csharp
public class FirewallRule
{
    public Guid Key { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsEnabled { get; set; } = true;
    public RuleAction Action { get; set; } = RuleAction.Block;
    public RuleDirection Direction { get; set; } = RuleDirection.Outbound;
    public AddressFamily AddressFamily { get; set; } = AddressFamily.IPv4;

    // Match conditions
    public NetworkProtocol Protocol { get; set; } = NetworkProtocol.Any;
    public ushort? LocalPort { get; set; }
    public ushort? RemotePort { get; set; }
    public string? LocalAddress { get; set; }  // CIDR notation: "192.168.1.0/24"
    public string? RemoteAddress { get; set; }
    public string? ApplicationPath { get; set; }
    public string? ServiceName { get; set; }
    public string? UserName { get; set; }

    // Metadata
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? ModifiedAt { get; set; }
    public ulong? WfpFilterId { get; set; }  // Assigned by WFP
    public long HitCount { get; set; }       // How many times triggered

    public FWPM_FILTER0 ToWfpFilter(Guid layerKey, Guid subLayerKey, IntPtr providerKey)
    {
        var builder = new FilterConditionBuilder();

        if (Protocol != NetworkProtocol.Any)
            builder.AddProtocol((IP_PROTOCOL)Protocol);
        if (LocalPort.HasValue)
            builder.AddLocalPort(LocalPort.Value);
        if (RemotePort.HasValue)
            builder.AddRemotePort(RemotePort.Value);
        if (LocalAddress != null)
            builder.AddLocalAddress(LocalAddress);
        if (RemoteAddress != null)
            builder.AddRemoteAddress(RemoteAddress);
        if (ApplicationPath != null)
            builder.AddApplication(ApplicationPath);

        var (conditions, ptrs) = builder.Build();

        var filter = new FWPM_FILTER0
        {
            filterKey = Key,
            displayData = new FWPM_DISPLAY_DATA0 { name = Name, description = Description },
            flags = FWPM_FILTER_FLAG.PERSISTENT,
            providerKey = providerKey,
            layerKey = layerKey,
            subLayerKey = subLayerKey,
            weight = new FWP_VALUE0 { type = FWP_DATA_TYPE.FWP_UINT8,
                                      value = new FWP_VALUE_UNION { uint8 = Action == RuleAction.Block ? (byte)0 : (byte)15 } },
            numFilterConditions = (uint)conditions.Length,
            filterCondition = ptrs.MarshalArray(conditions),
            action = new FWPM_ACTION0
            {
                type = Action == RuleAction.Block
                    ? FWP_ACTION_TYPE.FWP_ACTION_BLOCK
                    : FWP_ACTION_TYPE.FWP_ACTION_PERMIT
            }
        };

        return filter;
    }
}
```

---

## 5. Phase 2: Network Monitor Layer

**Duration:** ~3-4 days  
**Core Library:** `Heco_Monitor`

### 5.1 `ConnectionMonitor.cs` — IP Helper API Polling

Based on **Network_Packet_Analyzer**'s `ConnectionsMonitor` but with modernized threading:

```csharp
public sealed class ConnectionMonitor : IConnectionMonitor, IDisposable
{
    private readonly Timer _timer;          // System.Threading.Timer
    private readonly object _lock = new();
    private Dictionary<long, Connection> _snapshot = new();
    private bool _isRunning;

    // Events
    public event EventHandler<ConnectionEventArgs>? ConnectionAdded;
    public event EventHandler<ConnectionEventArgs>? ConnectionRemoved;
    public event EventHandler<ConnectionEventArgs>? ConnectionUpdated;
    public event EventHandler<ConnectionsSnapshotEventArgs>? SnapshotUpdated;

    public ConnectionMonitor()
    {
        // Use Timer instead of deprecated Thread.Suspend/Resume
        _timer = new Timer(TimerCallback, null, Timeout.Infinite, Timeout.Infinite);
    }

    public void Start(int intervalMs = 1000)
    {
        _isRunning = true;
        _timer.Change(0, intervalMs);
    }

    public void Stop()
    {
        _isRunning = false;
        _timer.Change(Timeout.Infinite, Timeout.Infinite);
    }

    private void TimerCallback(object? state)
    {
        try
        {
            var current = GetCurrentConnections();
            var (added, removed, updated) = DiffConnections(_snapshot, current);
            _snapshot = current;

            foreach (var conn in added)   ConnectionAdded?.Invoke(this, new(conn));
            foreach (var conn in removed) ConnectionRemoved?.Invoke(this, new(conn));
            foreach (var conn in updated) ConnectionUpdated?.Invoke(this, new(conn));

            // Marshal to UI thread
            SnapshotUpdated?.Invoke(this, new(current.Values.ToList()));
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Monitor error: {ex.Message}");
        }
    }

    private Dictionary<long, Connection> GetCurrentConnections()
    {
        var connections = new Dictionary<long, Connection>();
        // 1. Get TCP table via GetExtendedTcpTable (iphlpapi)
        // 2. Get UDP table via GetExtendedUdpTable
        // 3. For each entry, create Connection object
        // 4. Resolve PID -> Process name via ProcessResolver
        // 5. Resolve IP -> DNS via DnsResolver (async cache)
        return connections;
    }

    public void Dispose() => _timer.Dispose();
}
```

### 5.2 `ConnectionInfo.cs` — Connection Domain Model

```csharp
public class Connection : INotifyPropertyChanged, IEquatable<Connection>
{
    // Identity
    public long HashKey { get; private set; }  // Tuple hash of 5-tuple

    // Network info
    public ProtocolType Protocol { get; set; }   // TCP/UDP
    public IPAddress LocalAddress { get; set; }  = IPAddress.Any;
    public ushort LocalPort { get; set; }
    public IPAddress RemoteAddress { get; set; } = IPAddress.Any;
    public ushort RemotePort { get; set; }
    public TcpState TcpState { get; set; }       // Established, Listen, etc.

    // Process info
    public uint ProcessId { get; set; }
    public string? ProcessName { get; set; }
    public string? ProcessPath { get; set; }
    public string? ProcessIcon { get; set; }     // Base64 or icon path

    // DNS
    public string? RemoteHostName { get; set; }   // Resolved via reverse DNS

    // Metadata
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public long BytesSent { get; set; }
    public long BytesReceived { get; set; }
    public bool IsInbound { get; set; }

    // Equality by 5-tuple (protocol, local addr:port, remote addr:port)
    public bool Equals(Connection? other) { /* ... */ }
    public override int GetHashCode()
    {
        return HashCode.Combine((int)Protocol, LocalAddress, LocalPort, RemoteAddress, RemotePort);
    }
}
```

### 5.3 `ProcessResolver.cs` — Process Lookup

```csharp
public static class ProcessResolver
{
    private static readonly Dictionary<uint, ProcessCacheEntry> _cache = new();
    private static readonly TimeSpan CacheDuration = TimeSpan.FromSeconds(10);

    public static ProcessInfo? Resolve(uint pid)
    {
        if (_cache.TryGetValue(pid, out var entry) && !entry.IsExpired)
            return entry.Info;

        try
        {
            var process = Process.GetProcessById((int)pid);
            var info = new ProcessInfo
            {
                ProcessId = pid,
                ProcessName = process.ProcessName,
                ProcessPath = GetMainModulePath(process),
                IconBase64 = ExtractIconBase64(process),
                UserName = GetProcessOwner(pid),
                ServiceName = GetServiceName(pid),
                StartTime = process.StartTime,
                MemoryUsage = process.WorkingSet64
            };

            _cache[pid] = new ProcessCacheEntry(info, CacheDuration);
            return info;
        }
        catch (ArgumentException) { return null; } // PID not found
    }

    private static string? GetMainModulePath(Process process)
    {
        try { return process.MainModule?.FileName; }
        catch { return null; }
    }

    private static string? GetProcessOwner(uint pid)
    {
        // Use WMI: "SELECT * FROM Win32_Process WHERE ProcessId = {pid}"
        // Return Domain\User
    }

    private static string? GetServiceName(uint pid)
    {
        // Use ServiceController or sc query
    }
}
```

### 5.4 `PacketSniffer.cs` — Raw Packet Capture

```csharp
public sealed class PacketSniffer : IDisposable
{
    private Socket? _rawSocket;
    private CancellationTokenSource? _cts;
    private Task? _captureTask;

    public event EventHandler<PacketEventArgs>? PacketCaptured;

    public void Start(IPAddress localIp)
    {
        _rawSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
        _rawSocket.Bind(new IPEndPoint(localIp, 0));
        _rawSocket.IOControl(IOControlCode.ReceiveAll, new byte[] { 1, 0, 0, 0 }, null);

        _cts = new CancellationTokenSource();
        _captureTask = Task.Run(() => CaptureLoop(_cts.Token));
    }

    private void CaptureLoop(CancellationToken ct)
    {
        byte[] buffer = new byte[65536];

        while (!ct.IsCancellationRequested)
        {
            try
            {
                int received = _rawSocket.Receive(buffer);
                var packet = ParsePacket(buffer, received);
                PacketCaptured?.Invoke(this, new(packet));
            }
            catch (SocketException) when (ct.IsCancellationRequested) { break; }
            catch (ObjectDisposedException) { break; }
        }
    }

    private PacketInfo ParsePacket(byte[] buffer, int length)
    {
        // IP header parsing:
        // byte 0: Version (4 bits) + HeaderLength (4 bits) = 0x45 for standard IPv4
        // bytes 12-15: Source IP
        // bytes 16-19: Dest IP
        // byte 9: Protocol (6=TCP, 17=UDP, 1=ICMP)
        // If TCP: bytes 20-21 = Source port, 22-23 = Dest port
        // If UDP: bytes 20-21 = Source port, 22-23 = Dest port
    }

    public void Stop() { _cts?.Cancel(); }
    public void Dispose() { Stop(); _rawSocket?.Dispose(); }
}
```

---

## 6. Phase 3: Rule Engine & Policy Management

**Duration:** ~4-5 days  
**Path:** `Heco_WfpEngine/Rules/`

### 6.1 `FirewallRuleManager.cs`

```csharp
public class FirewallRuleManager : IFirewallRuleRepository
{
    private readonly IWfpEngine _engine;
    private readonly List<FirewallRule> _rules = new();
    private readonly string _rulesFile;

    public FirewallRuleManager(IWfpEngine engine, string rulesFile = "rules.json")
    {
        _engine = engine;
        _rulesFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, rulesFile);
    }

    public async Task LoadRulesAsync()
    {
        if (!File.Exists(_rulesFile)) return;
        var json = await File.ReadAllTextAsync(_rulesFile);
        var rules = JsonSerializer.Deserialize<List<FirewallRule>>(json);
        if (rules == null) return;

        _rules.Clear();
        foreach (var rule in rules)
        {
            if (rule.IsEnabled && !string.IsNullOrEmpty(rule.ApplicationPath))
            {
                var fileExists = File.Exists(rule.ApplicationPath);
                if (!fileExists)
                {
                    rule.IsEnabled = false;  // Disable if app no longer exists
                }
            }
            _rules.Add(rule);
        }
    }

    public async Task SaveRulesAsync()
    {
        var json = JsonSerializer.Serialize(_rules, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(_rulesFile, json);
    }

    public async Task<FirewallRule> AddRuleAsync(FirewallRule rule)
    {
        rule.Key = Guid.NewGuid();
        rule.CreatedAt = DateTime.UtcNow;

        if (rule.IsEnabled)
            ApplyRuleToWfp(rule);   // Call _engine.AddRule(rule)

        _rules.Add(rule);
        await SaveRulesAsync();
        return rule;
    }

    public async Task<bool> RemoveRuleAsync(Guid ruleKey)
    {
        var rule = _rules.FirstOrDefault(r => r.Key == ruleKey);
        if (rule == null) return false;

        _engine.RemoveRule(ruleKey);
        _rules.Remove(rule);
        await SaveRulesAsync();
        return true;
    }

    public async Task<FirewallRule> UpdateRuleAsync(FirewallRule rule)
    {
        var existing = _rules.FirstOrDefault(r => r.Key == rule.Key);
        if (existing == null) throw new KeyNotFoundException("Rule not found");

        // Remove old filter, apply new
        _engine.RemoveRule(rule.Key);
        if (rule.IsEnabled)
            ApplyRuleToWfp(rule);

        var index = _rules.IndexOf(existing);
        _rules[index] = rule;
        rule.ModifiedAt = DateTime.UtcNow;
        await SaveRulesAsync();
        return rule;
    }

    public void ApplyRuleToWfp(FirewallRule rule)
    {
        // Determine which layers to apply to based on Direction & AddressFamily
        if (rule.AddressFamily == AddressFamily.IPv4 || rule.AddressFamily == AddressFamily.Both)
        {
            var layerKey = rule.Direction == RuleDirection.Inbound
                ? WfpLayerGuids.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
                : WfpLayerGuids.FWPM_LAYER_ALE_AUTH_CONNECT_V4;

            _engine.AddRule(rule, layerKey, GetSubLayerKey(layerKey));
        }
        // Same for IPv6
    }

    public IEnumerable<FirewallRule> GetAllRules() => _rules.AsReadOnly();
    public IEnumerable<FirewallRule> GetEnabledRules() => _rules.Where(r => r.IsEnabled);
    public FirewallRule? GetRule(Guid key) => _rules.FirstOrDefault(r => r.Key == key);
    public int RuleCount => _rules.Count;
}
```

### 6.2 Rule Persistence (`rules.json`)

```json
{
  "rules": [
    {
      "key": "guid-here",
      "name": "Block Chrome Outbound",
      "description": "Block Google Chrome from accessing the internet",
      "isEnabled": true,
      "action": "Block",
      "direction": "Outbound",
      "addressFamily": "IPv4",
      "protocol": "TCP",
      "applicationPath": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
      "createdAt": "2026-07-10T10:00:00Z"
    },
    {
      "key": "guid-here",
      "name": "Allow SSH Outbound",
      "description": "Allow outbound SSH connections",
      "isEnabled": true,
      "action": "Permit",
      "direction": "Outbound",
      "addressFamily": "IPv4",
      "protocol": "TCP",
      "remotePort": 22,
      "createdAt": "2026-07-10T10:05:00Z"
    }
  ]
}
```

---

## 7. Phase 4: WPF UI — MVVM Dashboard

**Duration:** ~6-8 days  
**UI Library:** `Heco_Firewall`

### 7.1 WPF NuGet Dependencies

```xml
<ItemGroup>
  <PackageReference Include="CommunityToolkit.Mvvm" Version="8.2.2" />
  <PackageReference Include="CommunityToolkit.Wpf.UI.Controls" Version="8.2.2" />
  <PackageReference Include="MaterialDesignThemes" Version="5.0.0" />
  <PackageReference Include="System.Management" Version="8.0.0" />
  <PackageReference Include="Serilog" Version="3.1.1" />
  <PackageReference Include="Serilog.Sinks.File" Version="5.0.0" />
</ItemGroup>
```

### 7.2 UI Layout & Views

```
┌────────────────────────────────────────────────────────────────┐
│ 🔥 Heco Firewall                  [🔴] [🟡] [🟢]      _ □ X │
├────────────────────────────────────────────────────────────────┤
│ ┌───┬──────┬──────┬─────────┬──────────┬─────────┬──────┐    │
│ │ 🏠│📋    │📡    │📊       │⚙️        │         │      │    │
│ │ DS│Rules │Monitor│Traffic  │Settings  │         │      │    │
│ ├───┴──────┴──────┴─────────┴──────────┴─────────┴──────┤    │
│ │                                                        │    │
│ │  [Content Area — changes per tab]                      │    │
│ │                                                        │    │
│ │  Dashboard View:                                       │    │
│ │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │    │
│ │  │Rules     │ │Active    │ │Blocked   │ │Bytes/sec │  │    │
│ │  │ 12       │ │Conns     │ │Today     │ │ 1.2 MB   │  │    │
│ │  │ Active   │ │ 34       │ │ 1,523    │ │          │  │    │
│ │  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │    │
│ │                                                        │    │
│ │  ┌───────────── Latest Blocked Events ──────────────┐  │    │
│ │  │ 🚫 10:23:45  Chrome → 185.199.108.153:443  BLOCK │  │    │
│ │  │ 🚫 10:23:42  Edge → 34.120.8.2:443     BLOCK │  │    │
│ │  └─────────────────────────────────────────────────┘  │    │
│ │                                                        │    │
│ └────────────────────────────────────────────────────────┘    │
│ Status: Running • Rules: 12 active • 34 connections     │
└────────────────────────────────────────────────────────────────┘
```

### 7.3 ViewModels

#### `DashboardViewModel.cs`

```csharp
public partial class DashboardViewModel : ObservableObject
{
    private readonly IWfpEngine _wfpEngine;
    private readonly IConnectionMonitor _monitor;

    [ObservableProperty] private int _activeRuleCount;
    [ObservableProperty] private int _activeConnectionCount;
    [ObservableProperty] private long _blockedTodayCount;
    [ObservableProperty] private long _bandwidthPerSecond;
    [ObservableProperty] private ObservableCollection<BlockedEvent> _recentBlockedEvents = new();
    [ObservableProperty] private string _statusText = "Starting...";
    [ObservableProperty] private bool _isEngineRunning;

    public DashboardViewModel(IWfpEngine wfpEngine, IConnectionMonitor monitor)
    {
        _wfpEngine = wfpEngine;
        _monitor = monitor;

        // Subscribe to events
        _monitor.SnapshotUpdated += OnSnapshotUpdated;
        _monitor.ConnectionAdded += OnConnectionAdded;
    }

    // Commands
    [RelayCommand]
    private async Task ToggleFirewallAsync()
    {
        if (IsEngineRunning)
        {
            _wfpEngine.Close();
            IsEngineRunning = false;
            StatusText = "Firewall Disabled";
        }
        else
        {
            _wfpEngine.Initialize();
            IsEngineRunning = true;
            StatusText = "Firewall Enabled";
        }
    }

    private void OnSnapshotUpdated(object? sender, ConnectionsSnapshotEventArgs e)
    {
        // Marshal to UI thread
        App.Current.Dispatcher.Invoke(() =>
        {
            ActiveConnectionCount = e.Connections.Count;
        });
    }
}
```

#### `RulesViewModel.cs`

```csharp
public partial class RulesViewModel : ObservableObject
{
    private readonly IFirewallRuleRepository _ruleRepo;

    [ObservableProperty] private ObservableCollection<FirewallRule> _rules = new();
    [ObservableProperty] private FirewallRule? _selectedRule;
    [ObservableProperty] private string _searchText = string.Empty;

    // Sorting/filtering
    [ObservableProperty] private bool _showEnabled = true;
    [ObservableProperty] private bool _showDisabled = true;

    partial void OnSearchTextChanged(string value) => FilterRules();

    [RelayCommand]
    private async Task AddRuleAsync()
    {
        // Open RuleEditorView dialog
        var dialog = new RuleEditorView();
        if (dialog.ShowDialog() == true)
        {
            var rule = dialog.ViewModel.GetRule();
            await _ruleRepo.AddRuleAsync(rule);
            Rules.Add(rule);
        }
    }

    [RelayCommand]
    private async Task DeleteRuleAsync()
    {
        if (SelectedRule == null) return;
        if (MessageBox.Show("Delete this rule?", "Confirm",
            MessageBoxButton.YesNo) == MessageBoxResult.Yes)
        {
            await _ruleRepo.RemoveRuleAsync(SelectedRule.Key);
            Rules.Remove(SelectedRule);
        }
    }

    [RelayCommand]
    private async Task ToggleRuleAsync(FirewallRule rule)
    {
        rule.IsEnabled = !rule.IsEnabled;
        await _ruleRepo.UpdateRuleAsync(rule);
    }

    private void FilterRules() { /* Filter by searchText + ShowEnabled/Disabled */ }
}
```

#### `MonitorViewModel.cs`

```csharp
public partial class MonitorViewModel : ObservableObject, IDisposable
{
    private readonly IConnectionMonitor _monitor;

    [ObservableProperty] private ObservableCollection<Connection> _connections = new();
    [ObservableProperty] private string _filterText = string.Empty;
    [ObservableProperty] private ProtocolType _filterProtocol = ProtocolType.All;
    [ObservableProperty] private Connection? _selectedConnection;
    [ObservableProperty] private int _totalConnections;
    [ObservableProperty] private int _establishedCount;
    [ObservableProperty] private int _listeningCount;
    [ObservableProperty] private int _timeWaitCount;

    // Filtering
    partial void OnFilterTextChanged(string value) => ApplyFilters();
    partial void OnFilterProtocolChanged(ProtocolType value) => ApplyFilters();

    private void ApplyFilters()
    {
        var filtered = _monitor.CurrentConnections.AsEnumerable();

        if (!string.IsNullOrEmpty(FilterText))
            filtered = filtered.Where(c =>
                c.ProcessName?.Contains(FilterText, StringComparison.OrdinalIgnoreCase) == true ||
                c.RemoteAddress?.ToString().Contains(FilterText) == true);

        if (FilterProtocol != ProtocolType.All)
            filtered = filtered.Where(c => c.Protocol == (ProtocolType)FilterProtocol);

        TotalConnections = filtered.Count();
        Connections = new ObservableCollection<Connection>(filtered);
    }
}
```

### 7.4 RuleEditorView (Add/Edit Rule Dialog)

A WPF `Window` with:

- **Name** (TextBox)
- **Description** (TextBox)
- **Action** (ComboBox: Block / Permit)
- **Direction** (ComboBox: Inbound / Outbound)
- **Protocol** (ComboBox: Any / TCP / UDP / ICMP)
- **Local Port** (TextBox + Range mode)
- **Remote Port** (TextBox + Range mode)
- **Local Address** (TextBox, CIDR format)
- **Remote Address** (TextBox, CIDR format)
- **Application Path** (TextBox + Browse button → `OpenFileDialog`)
- **Browse running processes** (List of active processes with PIDs)
- **Enabled** (CheckBox)

### 7.5 XAML Styling Approach

Use **MaterialDesignThemes** for modern appearance with custom color theme:
- **Primary:** Deep blue (#1a237e)
- **Secondary:** Cyan (#00bcd4)
- **Error/Block:** Red (#d32f2f)
- **Success/Permit:** Green (#388e3c)
- **Warning:** Amber (#ffa000)

---

## 8. Phase 5: Advanced Features

**Duration:** ~5-7 days

### 8.1 Traffic Statistics & Bandwidth Monitoring

```csharp
public class TrafficStatistics
{
    // Per-connection byte counting using Windows NetStat or WinPCap
    private readonly PerformanceCounter _bytesReceived;
    private readonly PerformanceCounter _bytesSent;

    public TrafficStatistics()
    {
        var category = "Network Interface";
        var instance = GetActiveInterface();
        _bytesReceived = new PerformanceCounter(category, "Bytes Received/sec", instance);
        _bytesSent = new PerformanceCounter(category, "Bytes Sent/sec", instance);
    }

    public (long DownSpeed, long UpSpeed) GetCurrentSpeed()
    {
        return ((long)_bytesReceived.NextValue(), (long)_bytesSent.NextValue());
    }
}
```

### 8.2 Port Scanning Detection

```csharp
public class PortScanDetector
{
    private readonly TimeSpan _window = TimeSpan.FromSeconds(5);
    private readonly int _threshold = 20;  // 20+ unique ports = scan
    private readonly Dictionary<IPAddress, HashSet<ushort>> _connectionAttempts = new();
    private readonly Dictionary<IPAddress, DateTime> _lastCleanup = new();

    public bool IsPortScan(Connection connection)
    {
        CleanupOldEntries();

        if (!_connectionAttempts.ContainsKey(connection.RemoteAddress))
            _connectionAttempts[connection.RemoteAddress] = new HashSet<ushort>();

        _connectionAttempts[connection.RemoteAddress].Add(connection.RemotePort);
        return _connectionAttempts[connection.RemoteAddress].Count >= _threshold;
    }

    private void CleanupOldEntries() { /* Remove entries older than 5 seconds */ }
}
```

### 8.3 Application Profile Learning

```csharp
public class AppProfileLearner
{
    // Observe connections over time and create profiles per application
    // Alert on unusual outbound connections from known apps
    
    private readonly Dictionary<string, AppProfile> _profiles = new();
    
    public void LearnConnection(Connection conn)
    {
        if (conn.ProcessName == null) return;
        
        if (!_profiles.ContainsKey(conn.ProcessName))
            _profiles[conn.ProcessName] = new AppProfile(conn.ProcessName);
        
        _profiles[conn.ProcessName].RecordConnection(conn.RemoteAddress, conn.RemotePort);
    }
    
    public bool IsUnusual(string processName, IPAddress remoteAddr, ushort port)
    {
        return _profiles.TryGetValue(processName, out var profile)
            && !profile.IsKnown(remoteAddr, port);
    }
}
```

### 8.4 Blocked Event Logging (Serilog)

```csharp
// Structured logging using Serilog
ILogger _log = new LoggerConfiguration()
    .WriteTo.File("heco_firewall_.log",
        rollingInterval: RollingInterval.Day,
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss} [{Level}] {Message}{NewLine}{Exception}")
    .WriteTo.Sink(new BlockedEventSink())  // Also notify UI
    .CreateLogger();

// Log blocked connection
_log.Information("BLOCKED {Protocol} {LocalAddress}:{LocalPort} → {RemoteAddress}:{RemotePort} | {Process} (PID: {Pid})",
    conn.Protocol, conn.LocalAddress, conn.LocalPort,
    conn.RemoteAddress, conn.RemotePort,
    conn.ProcessName, conn.ProcessId);
```

### 8.5 Elevation & UAC Handling

```csharp
public static class ElevationHelper
{
    public static bool IsRunningAsAdmin()
    {
        var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static void RestartAsAdmin()
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = Process.GetCurrentProcess().MainModule.FileName,
            Verb = "runas",   // Elevate
            UseShellExecute = true
        };
        Process.Start(startInfo);
        Application.Current.Shutdown();
    }
}
```

---

## 9. Phase 6: Packaging, Deployment & Testing

**Duration:** ~2-3 days

### 9.1 Build Configuration

```xml
<!-- Heco_Firewall.csproj -->
<PropertyGroup>
  <OutputType>WinExe</OutputType>
  <TargetFramework>net8.0-windows</TargetFramework>
  <UseWPF>true</UseWPF>
  <ApplicationManifest>app.manifest</ApplicationManifest>
  <ApplicationIcon>Resources\firewall.ico</ApplicationIcon>
  <RequireAdministrator>true</RequireAdministrator>
  <SelfContained>false</SelfContained>
  <IncludeNativeLibrariesForSelfExtract>true</IncludeNativeLibrariesForSelfExtract>
</PropertyGroup>
```

### 9.2 Windows Service Integration

For persistent firewall that runs even when app is closed:

```csharp
// Optional: WFP filters are PERSISTENT by default -> they survive reboot
// even without the app running. But a Windows Service can:
// 1. Ensure provider is registered at boot
// 2. Log blocked events to Windows Event Log
// 3. Auto-restart on crash
```

### 9.3 App Manifest (`app.manifest`)

Must include:
```xml
<requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
```

**Why:** All WFP operations (`FwpmEngineOpen0`, `FwpmFilterAdd0`, etc.) require Administrator privileges.

### 9.4 Testing Strategy

| Test Type | Focus | Tool |
|-----------|-------|------|
| Unit | ConditionBuilder, FirewallRule model | xUnit + Moq |
| Unit | Rule serialization (JSON roundtrip) | xUnit |
| Integration | WFP filter add/delete via real engine | xUnit (admin) |
| Integration | ConnectionMonitor diff logic | xUnit |
| Integration | ProcessResolver (mock Process) | xUnit |
| UI | All ViewModels with mock services | xUnit |
| E2E | Full firewall: add rule → block Chrome | Manual + Script |
| Security | Verify admin-only access | Test |
| Performance | 1000+ rules, 10000+ connections | Benchmark |

---

## 10. Data Flow Diagrams

### 10.1 Adding a Firewall Rule

```
User (UI)                    ViewModel                     RuleManager                    WfpEngine               Windows
    │                           │                              │                              │                      │
    │  Click "Add Rule"         │                              │                              │                      │
    │ ─────────────────────────►│                              │                              │                      │
    │                           │  Open RuleEditor Dialog      │                              │                      │
    │  ┌──── RuleEditor ──────┐ │                              │                              │                      │
    │  │ Fill fields → OK      │                              │                              │                      │
    │  │───────────────────────│─► ShowDialog()                │                              │                      │
    │  └───────────────────────┘ │                              │                              │                      │
    │                           │  AddRuleAsync(rule)          │                              │                      │
    │                           │ ────────────────────────────►│                              │                      │
    │                           │                              │  AddRule(rule, layerKey)     │                      │
    │                           │                              │ ───────────────────────────►│                      │
    │                           │                              │                              │  FwpmFilterAdd0()    │
    │                           │                              │                              │ ───────────────────►│──► WFP
    │                           │                              │                              │◄──── uint result ───│──► Kernel
    │                           │                              │                              │                      │
    │                           │                              │  SaveRulesAsync() → rules.json                       │
    │                           │                              │◄─────────────────────────────│                      │
    │                           │◄──────── Rule ──────────────│                              │                      │
    │  UI updates rule list     │                              │                              │                      │
    │◄──────────────────────────│                              │                              │                      │
```

### 10.2 Connection Monitoring Flow

```
ConnectionsMonitor              iphlpapi.dll               ProcessResolver              DnsResolver              UI
       │                              │                          │                          │                    │
       │  Timer tick (1s)              │                          │                          │                    │
       │ ─────────────────────────────►│                          │                          │                    │
       │◄──── MIB_TCPROW_OWNER_PID ────│                          │                          │                    │
       │                              │                          │                          │                    │
       │  For each connection entry:   │                          │                          │                    │
       │ ────────────────────────────────────────────────────────►│                          │                    │
       │◄───────── ProcessInfo ──────────────────────────────────│                          │                    │
       │                              │                          │                          │                    │
       │ ──────────────────────────────────────────────────────────────────────────────────►│                    │
       │◄────────── HostName ───────────────────────────────────────────────────────────────│                    │
       │                              │                          │                          │                    │
       │  Diff vs previous snapshot    │                          │                          │                    │
       │  [added, removed, updated]    │                          │                          │                    │
       │                              │                          │                          │                    │
       │  ConnectionAdded event        │                          │                          │                    │
       │ ──────────────────────────────────────────────────────────────────────────────────► │                    │
       │                              │                          │                          │  Dispatcher.Invoke │
       │                              │                          │                          │ ────────────────►  │
       │                              │                          │                          │                    │
```

### 10.3 WFP Classification / Filter Matching

```
Packet arrives (inbound/outbound)
        │
        ▼
Network Stack (TCP/IP)
        │
        ▼
WFP Filter Engine
        │
        ├── Layer ALE_AUTH_CONNECT (outbound) or ALE_AUTH_RECV_ACCEPT (inbound)
        │       │
        │       ├── Check filter 1 (weight=15, Action=Permit, condition="app=chrome")
        │       │       │
        │       │       └── Match? ──► YES ──► PERMIT (allow, skip remaining)
        │       │
        │       ├── Check filter 2 (weight=10, Action=Permit, condition="port=443")
        │       │       │
        │       │       └── Match? ──► YES ──► PERMIT
        │       │
        │       ├── Check filter 3 (weight=5, Action=Block, condition="protocol=TCP")
        │       │       │
        │       │       └── Match? ──► YES ──► BLOCK (connection refused)
        │       │
        │       └── No match → Default (Permit)
        │
        ▼
Result: Permit or Block
```

---

## 11. Appendix: Key WFP API Reference

### 11.1 WFP Function Groups (from `FWPUCLNT.DLL`)

| Category | Functions | Phase |
|----------|-----------|-------|
| **Engine** | `FwpmEngineOpen0`, `FwpmEngineClose0` | 1 |
| **Provider** | `FwpmProviderAdd0`, `FwpmProviderDeleteByKey0` | 1 |
| **SubLayer** | `FwpmSubLayerAdd0`, `FwpmSubLayerDeleteByKey0` | 1 |
| **Filter** | `FwpmFilterAdd0`, `FwpmFilterDeleteByKey0/ById0`, `FwpmFilterEnum0` | 1 |
| **Transaction** | `FwpmTransactionBegin0`, `FwpmTransactionCommit0`, `FwpmTransactionAbort0` | 3 |
| **App ID** | `FwpmGetAppIdFromFileName0` | 1 |
| **Memory** | `FwpmFreeMemory0` | 1 (always) |
| **Net Events** | `FwpmNetEventSubscribe0`, `FwpmNetEventUnsubscribe0` | 4 |

### 11.2 Critical WFP Layers for Firewall

| Layer Name | GUID | Purpose |
|------------|------|---------|
| `FWPM_LAYER_ALE_AUTH_CONNECT_V4` | `2A5FFBA1-...` | Outbound TCP connect / first UDP send (IPv4) |
| `FWPM_LAYER_ALE_AUTH_CONNECT_V6` | `78C2B39A-...` | Outbound TCP connect / first UDP send (IPv6) |
| `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4` | `E1CDD904-...` | Inbound TCP accept / first UDP recv (IPv4) |
| `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6` | `2504C081-...` | Inbound TCP accept / first UDP recv (IPv6) |
| `FWPM_LAYER_STREAM_V4` | `7F07FE95-...` | Full TCP stream inspection (callout only) |

### 11.3 Key Error Codes

```csharp
internal static class WinError
{
    public const uint ERROR_SUCCESS = 0;
    public const uint ERROR_ACCESS_DENIED = 5;           // Not admin
    public const uint ERROR_FILE_NOT_FOUND = 2;          // Bad app path
    public const uint FWP_E_ALREADY_EXISTS = 0x80320002; // Duplicate filter
    public const uint FWP_E_NOT_FOUND = 0x80320001;      // Filter/object not found
    public const uint FWP_E_SESSION_ABORTED = 0x8032000B;
    public const uint FWP_E_IN_USE = 0x8032000A;
    public const uint ERROR_NO_MORE_ITEMS = 259;         // Enumeration complete
}
```

### 11.4 iphlpapi Functions (for Connection Monitor)

```csharp
[DllImport("iphlpapi.dll")]
internal static extern uint GetExtendedTcpTable(
    IntPtr pTcpTable,
    ref int dwOutBufferLen,
    bool sort,
    TCP_TABLE_CLASS tcpTableClass  // TCP_TABLE_OWNER_PID_ALL = 5
);

[DllImport("iphlpapi.dll")]
internal static extern uint GetExtendedUdpTable(
    IntPtr pUdpTable,
    ref int dwOutBufferLen,
    bool sort,
    UDP_TABLE_CLASS udpTableClass  // UDP_TABLE_OWNER_PID = 1
);
```

---

## Implementation Roadmap

```
Week 1  │ Phase 1: WFP Engine Layer
        │   ├── Native P/Invoke declarations
        │   ├── WfpEngine (open/close engine, provider, sublayers)
        │   └── Basic filter add/delete
        │
Week 2  │ Phase 2: Network Monitor Layer
        │   ├── ConnectionMonitor (iphlpapi polling)
        │   ├── ProcessResolver / DnsResolver
        │   └── PacketSniffer (raw socket)
        │
Week 3  │ Phase 3: Rule Engine & Policy Management
        │   ├── FilterConditionBuilder (full fluent API)
        │   ├── FirewallRuleManager (CRUD + persistence)
        │   └── Transaction support + error recovery
        │
Week 4-5│ Phase 4: WPF UI — MVVM Dashboard
        │   ├── Solution setup + MVVM infrastructure
        │   ├── Dashboard, Rules, Monitor, Settings views
        │   ├── RuleEditor dialog (full CRUD)
        │   └── Material Design theming
        │
Week 6  │ Phase 5: Advanced Features
        │   ├── Traffic statistics
        │   ├── Port scan detection
        │   ├── Application profile learning
        │   └── Logging + ETW events
        │
Week 7  │ Phase 6: Testing, Packaging, Deployment
        │   ├── Unit + Integration tests
        │   ├── MSI installer
        │   └── Documentation + README
```

---

> **Note:** This plan assumes you already have `Albion-master`'s WFP P/Invoke patterns, `Network_Packet_Analyzer`'s connection monitoring with iphlpapi, and `WFP_App`'s filter management as reference implementations. All three have been analyzed and their best patterns are incorporated above.
