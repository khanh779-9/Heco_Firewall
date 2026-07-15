using System;
using System.Collections.Generic;
using System.Linq;
using Heco.Common.Models;
using Heco.Common.Interfaces;
using Heco.Common.Diagnostics;
using Heco.Core.Filtering;
using Heco.Core.Native;

namespace Heco.Core.Engine;

/// <summary>
///   Core WFP engine wrapper. Manages engine session, provider, sub-layer,
///   and filter lifecycle. Thread-safe.
/// </summary>
public sealed partial class WfpEngine : IWfpEngine, IDisposable
{
    private readonly object _lock = new();
    private nint _engineHandle;
    private bool _disposed;
    private bool _providerRegistered;
    private bool _subLayerRegistered;

    // Maps FirewallRule.Id -> WFP filterId for each installed filter
    private readonly Dictionary<Guid, ulong> _ruleIdToFilterId = new();

    // Heco's provider and sub-layer are registered once and reused
    private static readonly Guid ProviderKey = FilterConditionBuilder.HecoProviderKey;
    private static readonly Guid SubLayerKey = FilterConditionBuilder.HecoSubLayerKey;

    private const uint RPC_C_AUTHN_WINNT = 10;
    private const uint RPC_C_AUTHN_LEVEL_DEFAULT = 0;
    private const uint RPC_C_AUTHZ_NONE = 0;

    /// <summary>Whether the engine session is open.</summary>
    public bool IsConnected => _engineHandle != nint.Zero;

    /// <summary>Open a session to the WFP engine. Must be called with Administrator privileges.</summary>
    public void Open(string? serverName = null)
    {
        var session = new WfpNativeTypes.FWPM_SESSION0
        {
            displayData = new WfpNativeTypes.FWPM_DISPLAY_DATA0
            {
                name = "Heco Firewall Session",
                description = "Heco Firewall WFP Engine Session"
            },
            flags = FWPM_SESSION_FLAG.Dynamic,
            txnWaitTimeoutInMSec = 1000
        };

        var hr = FwpmNative.FwpmEngineOpen0(
            serverName,
            RPC_C_AUTHN_WINNT,
            nint.Zero,
            in session,
            out _engineHandle);

        if (hr != WfpErrors.Success)
            throw new HecoException((uint)hr, $"FwpmEngineOpen0 failed: 0x{hr:X8}");

        RegisterProvider();
        RegisterSubLayer();
    }

    /// <summary>Close the WFP engine session and release all handles.</summary>
    public void Close()
    {
        lock (_lock)
        {
            if (_engineHandle == nint.Zero)
                return;

            ClearAllRules();

            // Sub-layer and provider are persistent — only clean up handles
            if (_subLayerRegistered)
            {
                FwpmNative.FwpmSubLayerDeleteByKey0(_engineHandle, SubLayerKey);
                _subLayerRegistered = false;
            }

            if (_providerRegistered)
            {
                FwpmNative.FwpmProviderDeleteByKey0(_engineHandle, ProviderKey);
                _providerRegistered = false;
            }

            FwpmNative.FwpmEngineClose0(_engineHandle);
            _engineHandle = nint.Zero;
            _ruleIdToFilterId.Clear();
        }
    }

    /// <summary>Apply all enabled rules to the WFP engine.</summary>
    public void ApplyRules(IEnumerable<FirewallRule> rules)
    {
        if (_engineHandle == nint.Zero)
            return;

        lock (_lock)
        {
            foreach (var rule in rules)
            {
                if (!rule.IsEnabled)
                    continue;

                try
                {
                    var builder = new FilterConditionBuilder(rule);

                    foreach (var layerKey in builder.ResolveLayers())
                    {
                        var filter = builder.Build(layerKey);
                        var hr = FwpmNative.FwpmFilterAdd0(
                            _engineHandle,
                            in filter,
                            nint.Zero,
                            out var filterId);

                        if (hr == WfpErrors.Success)
                        {
                            _ruleIdToFilterId[rule.Id] = filterId;
                        }

                        // Free allocated condition values
                        FreeFilterResources(filter);
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[WfpEngine] ApplyRules error: {ex.Message}");
                }
            }
        }
    }

    /// <summary>Remove a specific rule from the WFP engine by its filter ID.</summary>
    public void RemoveRule(ulong wfpFilterId)
    {
        if (_engineHandle == nint.Zero)
            return;

        lock (_lock)
        {
            var hr = FwpmNative.FwpmFilterDeleteById0(_engineHandle, wfpFilterId);
            if (hr != WfpErrors.Success && hr != WfpErrors.NotFound)
            {
                System.Diagnostics.Debug.WriteLine($"[WfpEngine] RemoveRule (id={wfpFilterId}) failed: 0x{hr:X8}");
            }
        }
    }

    /// <summary>Clear all rules registered by this application from the WFP engine.</summary>
    public void ClearAllRules()
    {
        if (_engineHandle == nint.Zero)
            return;

        lock (_lock)
        {
            foreach (var kvp in _ruleIdToFilterId.ToList())
            {
                var hr = FwpmNative.FwpmFilterDeleteById0(_engineHandle, kvp.Value);
                if (hr != WfpErrors.Success && hr != WfpErrors.NotFound)
                {
                    System.Diagnostics.Debug.WriteLine($"[WfpEngine] ClearAllRules: filter {kvp.Value} delete failed: 0x{hr:X8}");
                }
            }
            _ruleIdToFilterId.Clear();
        }
    }

    private void RegisterProvider()
    {
        if (_providerRegistered)
            return;

        var provider = new WfpNativeTypes.FWPM_PROVIDER0
        {
            providerKey = ProviderKey,
            displayData = new WfpNativeTypes.FWPM_DISPLAY_DATA0
            {
                name = "Heco Firewall Provider",
                description = "Heco Firewall — Windows Filtering Platform Provider"
            },
            flags = FWPM_PROVIDER_FLAG.None
        };

        var hr = FwpmNative.FwpmProviderAdd0(_engineHandle, in provider, nint.Zero);
        if (hr != WfpErrors.Success && hr != WfpErrors.AlreadyExists)
            throw new HecoException((uint)hr, $"FwpmProviderAdd0 failed: 0x{hr:X8}");

        _providerRegistered = true;
    }

    private void RegisterSubLayer()
    {
        if (_subLayerRegistered)
            return;

        var subLayer = new WfpNativeTypes.FWPM_SUBLAYER0
        {
            subLayerKey = SubLayerKey,
            displayData = new WfpNativeTypes.FWPM_DISPLAY_DATA0
            {
                name = "Heco Firewall Sub-Layer",
                description = "Heco Firewall — WFP Sub-Layer"
            },
            flags = FWPM_SUBLAYER_FLAG.None,
            providerKey = MarshalProviderKeyForSubLayer(),
            weight = 0
        };

        var hr = FwpmNative.FwpmSubLayerAdd0(_engineHandle, in subLayer, nint.Zero);
        if (hr != WfpErrors.Success && hr != WfpErrors.AlreadyExists)
            throw new HecoException((uint)hr, $"FwpmSubLayerAdd0 failed: 0x{hr:X8}");

        _subLayerRegistered = true;
        System.Runtime.InteropServices.Marshal.FreeCoTaskMem(subLayer.providerKey);
    }

    private static nint MarshalProviderKeyForSubLayer()
    {
        var ptr = System.Runtime.InteropServices.Marshal.AllocCoTaskMem(16);
        System.Runtime.InteropServices.Marshal.StructureToPtr(ProviderKey, ptr, false);
        return ptr;
    }

    private static void FreeFilterResources(WfpNativeTypes.FWPM_FILTER0 filter)
    {
        if (filter.providerKey != nint.Zero)
            System.Runtime.InteropServices.Marshal.FreeHGlobal(filter.providerKey);

        // Free condition values (allocated by FilterConditionBuilder.MarshalConditions)
        if (filter.filterCondition != nint.Zero)
            System.Runtime.InteropServices.Marshal.FreeHGlobal(filter.filterCondition);
    }

    /// <summary>Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Close();
    }
}
