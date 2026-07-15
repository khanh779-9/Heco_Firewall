using System;
using System.Runtime.InteropServices;

namespace Heco.Core.Native;

internal static class FwpmNative
{
    // ═══════════════════════════════════════════════════════════════
    //  Engine
    // ═══════════════════════════════════════════════════════════════

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmEngineOpen0(
        [MarshalAs(UnmanagedType.LPWStr)] string? serverName,
        uint authnService,
        nint authIdentity,
        in WfpNativeTypes.FWPM_SESSION0 session,
        out nint engineHandle);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmEngineClose0(nint engineHandle);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmEngineGetOption0(
        nint engineHandle,
        uint option,
        out WfpNativeTypes.FWP_VALUE0 value);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmEngineSetOption0(
        nint engineHandle,
        uint option,
        in WfpNativeTypes.FWP_VALUE0 value);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmEngineGetSecurityInfo0(
        nint engineHandle,
        uint securityInfo,
        out nint sidOwner,
        out nint sidGroup,
        out nint dacl,
        out nint sacl,
        out nint securityDescriptor);

    // ═══════════════════════════════════════════════════════════════
    //  Session
    // ═══════════════════════════════════════════════════════════════

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmSessionCreateEnumHandle0(
        nint engineHandle,
        nint enumTemplate,
        out nint enumHandle);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmSessionEnum0(
        nint engineHandle,
        nint enumHandle,
        uint numEntriesRequested,
        out nint entries,
        out uint numEntriesReturned);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmSessionDestroyEnumHandle0(
        nint engineHandle,
        nint enumHandle);

    // ═══════════════════════════════════════════════════════════════
    //  Provider
    // ═══════════════════════════════════════════════════════════════

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmProviderAdd0(
        nint engineHandle,
        in WfpNativeTypes.FWPM_PROVIDER0 provider,
        nint sd);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmProviderDeleteByKey0(
        nint engineHandle,
        in Guid providerKey);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmProviderGetByKey0(
        nint engineHandle,
        in Guid providerKey,
        out nint provider);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmProviderCreateEnumHandle0(
        nint engineHandle,
        nint enumTemplate,
        out nint enumHandle);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmProviderGetSecurityInfoByKey0(
        nint engineHandle,
        in Guid providerKey,
        uint securityInfo,
        out nint sidOwner,
        out nint sidGroup,
        out nint dacl,
        out nint sacl,
        out nint securityDescriptor);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmProviderSetSecurityInfoByKey0(
        nint engineHandle,
        in Guid providerKey,
        uint securityInfo,
        nint sidOwner,
        nint sidGroup,
        nint dacl,
        nint sacl);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmProviderEnum0(
        nint engineHandle,
        nint enumHandle,
        uint numEntriesRequested,
        out nint entries,
        out uint numEntriesReturned);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmProviderDestroyEnumHandle0(
        nint engineHandle,
        nint enumHandle);

    // ═══════════════════════════════════════════════════════════════
    //  Provider Context
    // ═══════════════════════════════════════════════════════════════

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmProviderContextAdd0(
        nint engineHandle,
        in WfpNativeTypes.FWPM_PROVIDER_CONTEXT0 providerContext,
        nint sd,
        out ulong id);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmProviderContextDeleteByKey0(
        nint engineHandle,
        in Guid providerContextKey);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmProviderContextGetByKey0(
        nint engineHandle,
        in Guid providerContextKey,
        out nint providerContext);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmProviderContextCreateEnumHandle0(
        nint engineHandle,
        nint enumTemplate,
        out nint enumHandle);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmProviderContextEnum0(
        nint engineHandle,
        nint enumHandle,
        uint numEntriesRequested,
        out nint entries,
        out uint numEntriesReturned);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmProviderContextDestroyEnumHandle0(
        nint engineHandle,
        nint enumHandle);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmProviderContextGetSecurityInfoByKey0(
        nint engineHandle,
        in Guid providerContextKey,
        uint securityInfo,
        out nint sidOwner,
        out nint sidGroup,
        out nint dacl,
        out nint sacl,
        out nint securityDescriptor);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmProviderContextSetSecurityInfoByKey0(
        nint engineHandle,
        in Guid providerContextKey,
        uint securityInfo,
        nint sidOwner,
        nint sidGroup,
        nint dacl,
        nint sacl);

    // ═══════════════════════════════════════════════════════════════
    //  SubLayer
    // ═══════════════════════════════════════════════════════════════

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmSubLayerAdd0(
        nint engineHandle,
        in WfpNativeTypes.FWPM_SUBLAYER0 subLayer,
        nint sd);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmSubLayerDeleteByKey0(
        nint engineHandle,
        in Guid subLayerKey);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmSubLayerGetByKey0(
        nint engineHandle,
        in Guid subLayerKey,
        out nint subLayer);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmSubLayerCreateEnumHandle0(
        nint engineHandle,
        nint enumTemplate,
        out nint enumHandle);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmSubLayerEnum0(
        nint engineHandle,
        nint enumHandle,
        uint numEntriesRequested,
        out nint entries,
        out uint numEntriesReturned);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmSubLayerDestroyEnumHandle0(
        nint engineHandle,
        nint enumHandle);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmSubLayerGetSecurityInfoByKey0(
        nint engineHandle,
        in Guid subLayerKey,
        uint securityInfo,
        out nint sidOwner,
        out nint sidGroup,
        out nint dacl,
        out nint sacl,
        out nint securityDescriptor);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmSubLayerSetSecurityInfoByKey0(
        nint engineHandle,
        in Guid subLayerKey,
        uint securityInfo,
        nint sidOwner,
        nint sidGroup,
        nint dacl,
        nint sacl);

    // ═══════════════════════════════════════════════════════════════
    //  Layer
    // ═══════════════════════════════════════════════════════════════

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmLayerGetByKey0(
        nint engineHandle,
        in Guid layerKey,
        out nint layer);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmLayerGetById0(
        nint engineHandle,
        ushort layerId,
        out nint layer);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmLayerCreateEnumHandle0(
        nint engineHandle,
        nint enumTemplate,
        out nint enumHandle);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmLayerEnum0(
        nint engineHandle,
        nint enumHandle,
        uint numEntriesRequested,
        out nint entries,
        out uint numEntriesReturned);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmLayerDestroyEnumHandle0(
        nint engineHandle,
        nint enumHandle);

    // ═══════════════════════════════════════════════════════════════
    //  Callout
    // ═══════════════════════════════════════════════════════════════

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmCalloutAdd0(
        nint engineHandle,
        in WfpNativeTypes.FWPM_CALLOUT0 callout,
        nint sd,
        out uint id);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmCalloutDeleteByKey0(
        nint engineHandle,
        in Guid calloutKey);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmCalloutGetByKey0(
        nint engineHandle,
        in Guid calloutKey,
        out nint callout);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmCalloutCreateEnumHandle0(
        nint engineHandle,
        nint enumTemplate,
        out nint enumHandle);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmCalloutEnum0(
        nint engineHandle,
        nint enumHandle,
        uint numEntriesRequested,
        out nint entries,
        out uint numEntriesReturned);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmCalloutDestroyEnumHandle0(
        nint engineHandle,
        nint enumHandle);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmCalloutGetSecurityInfoByKey0(
        nint engineHandle,
        in Guid calloutKey,
        uint securityInfo,
        out nint sidOwner,
        out nint sidGroup,
        out nint dacl,
        out nint sacl,
        out nint securityDescriptor);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmCalloutSetSecurityInfoByKey0(
        nint engineHandle,
        in Guid calloutKey,
        uint securityInfo,
        nint sidOwner,
        nint sidGroup,
        nint dacl,
        nint sacl);

    // ═══════════════════════════════════════════════════════════════
    //  Filter
    // ═══════════════════════════════════════════════════════════════

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmFilterAdd0(
        nint engineHandle,
        in WfpNativeTypes.FWPM_FILTER0 filter,
        nint sd,
        out ulong filterId);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmFilterDeleteByKey0(
        nint engineHandle,
        in Guid filterKey);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmFilterDeleteById0(
        nint engineHandle,
        ulong filterId);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmFilterGetByKey0(
        nint engineHandle,
        in Guid filterKey,
        out nint filter);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmFilterGetById0(
        nint engineHandle,
        ulong filterId,
        out nint filter);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmFilterCreateEnumHandle0(
        nint engineHandle,
        nint enumTemplate,
        out nint enumHandle);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmFilterEnum0(
        nint engineHandle,
        nint enumHandle,
        uint numEntriesRequested,
        out nint entries,
        out uint numEntriesReturned);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmFilterDestroyEnumHandle0(
        nint engineHandle,
        nint enumHandle);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmFilterSetSecurityInfoByKey0(
        nint engineHandle,
        in Guid filterKey,
        uint securityInfo,
        nint sidOwner,
        nint sidGroup,
        nint dacl,
        nint sacl);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmFilterGetSecurityInfoByKey0(
        nint engineHandle,
        in Guid filterKey,
        uint securityInfo,
        out nint sidOwner,
        out nint sidGroup,
        out nint dacl,
        out nint sacl,
        out nint securityDescriptor);

    // ═══════════════════════════════════════════════════════════════
    //  Network Events (audit / blocked-connection logging)
    // ═══════════════════════════════════════════════════════════════

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmNetEventEnum0(
        nint engineHandle,
        nint enumHandle,
        uint numEntriesRequested,
        out nint entries,
        out uint numEntriesReturned);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmNetEventCreateEnumHandle0(
        nint engineHandle,
        nint enumTemplate,
        out nint enumHandle);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmNetEventDestroyEnumHandle0(
        nint engineHandle,
        nint enumHandle);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmNetEventSubscribe0(
        nint engineHandle,
        in WfpNativeTypes.FWPM_NET_EVENT_SUBSCRIPTION0 subscription,
        nint callback,
        out nint subscriptionHandle);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmNetEventUnsubscribe0(
        nint engineHandle,
        nint subscriptionHandle);

    // ═══════════════════════════════════════════════════════════════
    //  System Ports (RPC / reserved ports)
    // ═══════════════════════════════════════════════════════════════

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmSystemPortsGet0(
        nint engineHandle,
        out nint sysPorts);

    // ═══════════════════════════════════════════════════════════════
    //  ALE Endpoint (connection tracking)
    // ═══════════════════════════════════════════════════════════════

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmAleEndpointGetEnum0(
        nint engineHandle,
        nint enumTemplate,
        out nint enumHandle);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmAleEndpointEnum0(
        nint engineHandle,
        nint enumHandle,
        uint numEntriesRequested,
        out nint entries,
        out uint numEntriesReturned);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmAleEndpointDestroyEnumHandle0(
        nint engineHandle,
        nint enumHandle);

    // ═══════════════════════════════════════════════════════════════
    //  App Identity
    // ═══════════════════════════════════════════════════════════════

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmGetAppIdFromFileName0(
        [MarshalAs(UnmanagedType.LPWStr)] string fileName,
        out nint appId);

    // ═══════════════════════════════════════════════════════════════
    //  Memory
    // ═══════════════════════════════════════════════════════════════

    [DllImport("FWPUCLNT.DLL")]
    internal static extern void FwpmFreeMemory0(ref nint pointer);

    // ═══════════════════════════════════════════════════════════════
    //  Transactions
    // ═══════════════════════════════════════════════════════════════

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmTransactionBegin0(nint engineHandle, uint flags);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmTransactionCommit0(nint engineHandle);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmTransactionAbort0(nint engineHandle);

    // ═══════════════════════════════════════════════════════════════
    //  IPsec (VPN / security policy)
    // ═══════════════════════════════════════════════════════════════

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmIPsecTunnelAdd0(
        nint engineHandle,
        uint flags,
        in WfpNativeTypes.FWPM_TUNNEL_POLICY0 tunnelPolicy,
        out uint id);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmIPsecTunnelDeleteByKey0(
        nint engineHandle,
        in Guid tunnelPolicyKey);

    [DllImport("FWPUCLNT.DLL")]
    internal static extern uint FwpmIPsecSaEnum0(
        nint engineHandle,
        nint enumHandle,
        uint numEntriesRequested,
        out nint entries,
        out uint numEntriesReturned);
}
