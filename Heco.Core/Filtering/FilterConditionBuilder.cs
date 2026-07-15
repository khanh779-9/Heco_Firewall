using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Heco.Common.Models;
using Heco.Common.Enums;
using Heco.Core.Native;

namespace Heco.Core.Filtering;

internal sealed class FilterConditionBuilder
{
    private readonly FirewallRule _rule;
    private readonly List<WfpNativeTypes.FWPM_FILTER_CONDITION0> _conditions = new();

    /// <summary>The provider key identifying Heco rules in the WFP store.</summary>
    internal static readonly Guid HecoProviderKey = new("8C7B8A9E-4D3F-4B2E-9A1C-6D5E7F8A9B0C");

    /// <summary>The sub-layer key used for all Heco filters.</summary>
    internal static readonly Guid HecoSubLayerKey = new("9D8C7B6A-5E4F-3D2C-1B0A-9E8F7D6C5B4A");

    internal FilterConditionBuilder(FirewallRule rule)
    {
        _rule = rule ?? throw new ArgumentNullException(nameof(rule));
    }

    /// <summary>Build the native filter structure for the specified layer.</summary>
    /// <param name="layerKey">The WFP layer GUID to attach the filter to.</param>
    internal WfpNativeTypes.FWPM_FILTER0 Build(Guid layerKey)
    {
        BuildConditions();
        return CreateFilter(layerKey);
    }

    /// <summary>
    ///   Resolve the WFP layer GUID(s) for this rule. Returns one GUID for
    ///   IPv4-only or IPv6-only rules, or two GUIDs for <see cref="AddressFamily.Both"/>.
    /// </summary>
    internal IEnumerable<Guid> ResolveLayers()
    {
        switch (_rule.AddressFamily)
        {
            case AddressFamily.IPv6:
                yield return ResolveLayer(isV6: true);
                break;
            case AddressFamily.IPv4:
                yield return ResolveLayer(isV6: false);
                break;
            default: // Both — install on both V4 and V6 layers
                yield return ResolveLayer(isV6: false);
                yield return ResolveLayer(isV6: true);
                break;
        }
    }

    private Guid ResolveLayer(bool isV6)
    {
        if (_rule.Direction == TrafficDirection.Inbound)
            return isV6 ? WfpLayers.AleAuthRecvAcceptV6 : WfpLayers.AleAuthRecvAcceptV4;
        else
            return isV6 ? WfpLayers.AleAuthConnectV6 : WfpLayers.AleAuthConnectV4;
    }

    private void BuildConditions()
    {
        if (_rule.Protocol != NetworkProtocol.Any)
            AddCondition(WfpConditions.IpProtocol, FWP_MATCH_TYPE.Equal, (byte)_rule.Protocol);

        if (_rule.LocalPort.HasValue)
            AddCondition(WfpConditions.IpLocalPort, FWP_MATCH_TYPE.Equal, _rule.LocalPort.Value);

        if (_rule.RemotePort.HasValue)
            AddCondition(WfpConditions.IpRemotePort, FWP_MATCH_TYPE.Equal, _rule.RemotePort.Value);

        if (!string.IsNullOrEmpty(_rule.LocalAddress))
            AddAddressCondition(WfpConditions.IpLocalAddress, _rule.LocalAddress);

        if (!string.IsNullOrEmpty(_rule.RemoteAddress))
            AddAddressCondition(WfpConditions.IpRemoteAddress, _rule.RemoteAddress);

        if (!string.IsNullOrEmpty(_rule.ApplicationPath))
            AddAppIdCondition(_rule.ApplicationPath);
    }

    private void AddCondition(Guid fieldKey, FWP_MATCH_TYPE matchType, byte value)
    {
        _conditions.Add(new WfpNativeTypes.FWPM_FILTER_CONDITION0
        {
            fieldKey = fieldKey,
            matchType = matchType,
            conditionValue = new WfpNativeTypes.FWP_CONDITION_VALUE0
            {
                type = FWP_DATA_TYPE.UInt8,
                value = new WfpNativeTypes.FWP_VALUE_UNION { uint8 = value }
            }
        });
    }

    private void AddCondition(Guid fieldKey, FWP_MATCH_TYPE matchType, ushort value)
    {
        _conditions.Add(new WfpNativeTypes.FWPM_FILTER_CONDITION0
        {
            fieldKey = fieldKey,
            matchType = matchType,
            conditionValue = new WfpNativeTypes.FWP_CONDITION_VALUE0
            {
                type = FWP_DATA_TYPE.UInt16,
                value = new WfpNativeTypes.FWP_VALUE_UNION { uint16 = value }
            }
        });
    }

    private void AddAddressCondition(Guid fieldKey, string cidr)
    {
        var parts = cidr.Split('/');
        if (!System.Net.IPAddress.TryParse(parts[0], out var addr))
            return;

        var isV6 = addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;

        if (isV6)
        {
            var prefixLen = parts.Length > 1 && byte.TryParse(parts[1], out var pl) ? pl : (byte)128;
            var rawAddr = addr.GetAddressBytes();
            _conditions.Add(new WfpNativeTypes.FWPM_FILTER_CONDITION0
            {
                fieldKey = fieldKey,
                matchType = FWP_MATCH_TYPE.Equal,
                conditionValue = new WfpNativeTypes.FWP_CONDITION_VALUE0
                {
                    type = FWP_DATA_TYPE.V6AddrMask,
                    value = new WfpNativeTypes.FWP_VALUE_UNION
                    {
                        v6AddrMask = MarshalAddrMask(rawAddr, prefixLen)
                    }
                }
            });
        }
        else
        {
            var prefixLen = parts.Length > 1 && byte.TryParse(parts[1], out var pm) ? pm : (byte)32;
            var mask = prefixLen >= 32 ? 0xFFFFFFFFu : ~(0xFFFFFFFFu >> prefixLen);
            var packed = (uint)System.Net.IPAddress.HostToNetworkOrder(
                (int)BitConverter.ToUInt32(addr.GetAddressBytes(), 0));

            _conditions.Add(new WfpNativeTypes.FWPM_FILTER_CONDITION0
            {
                fieldKey = fieldKey,
                matchType = FWP_MATCH_TYPE.Equal,
                conditionValue = new WfpNativeTypes.FWP_CONDITION_VALUE0
                {
                    type = FWP_DATA_TYPE.V4AddrMask,
                    value = new WfpNativeTypes.FWP_VALUE_UNION
                    {
                        v4AddrMask = MarshalV4AddrMask(packed, mask)
                    }
                }
            });
        }
    }

    private void AddAppIdCondition(string appPath)
    {
        var hr = Native.FwpmNative.FwpmGetAppIdFromFileName0(appPath, out var appIdPtr);
        if (hr != 0) return;

        _conditions.Add(new WfpNativeTypes.FWPM_FILTER_CONDITION0
        {
            fieldKey = WfpConditions.AleAppId,
            matchType = FWP_MATCH_TYPE.Equal,
            conditionValue = new WfpNativeTypes.FWP_CONDITION_VALUE0
            {
                type = FWP_DATA_TYPE.ByteBlobType,
                value = new WfpNativeTypes.FWP_VALUE_UNION { byteBlob = appIdPtr }
            }
        });

        // NOTE: Do NOT free appIdPtr here — FwpmFilterAdd0 must deep-copy it.
        // The pointer is freed after the add call in WfpEngine.FreeConditionValues.
    }

    private WfpNativeTypes.FWPM_FILTER0 CreateFilter(Guid layerKey)
    {
        var conditionsPtr = MarshalConditions();

        return new WfpNativeTypes.FWPM_FILTER0
        {
            filterKey = Guid.NewGuid(),
            displayData = new WfpNativeTypes.FWPM_DISPLAY_DATA0
            {
                name = _rule.Name,
                description = _rule.Description
            },
            flags = FWPM_FILTER_FLAG.Persistent | FWPM_FILTER_FLAG.Indexed,
            providerKey = MarshalHecoProviderKey(),
            layerKey = layerKey,
            subLayerKey = HecoSubLayerKey,
            weight = new WfpNativeTypes.FWP_VALUE0
            {
                type = FWP_DATA_TYPE.UInt8,
                value = new WfpNativeTypes.FWP_VALUE_UNION { uint8 = 0 }
            },
            numFilterConditions = (uint)_conditions.Count,
            filterCondition = conditionsPtr,
            action = new WfpNativeTypes.FWPM_ACTION0
            {
                type = _rule.Action == RuleAction.Block
                    ? FWP_ACTION_TYPE.Block
                    : FWP_ACTION_TYPE.Permit
            }
        };
    }

    private unsafe nint MarshalConditions()
    {
        if (_conditions.Count == 0)
            return IntPtr.Zero;

        var size = sizeof(WfpNativeTypes.FWPM_FILTER_CONDITION0);
        var ptr = System.Runtime.InteropServices.Marshal.AllocHGlobal(size * _conditions.Count);

        for (var i = 0; i < _conditions.Count; i++)
        {
            System.Runtime.InteropServices.Marshal.StructureToPtr(
                _conditions[i], ptr + i * size, false);
        }

        return ptr;
    }

    private static nint MarshalAddrMask(byte[] addrBytes, byte prefixLength)
    {
        var mask = new WfpNativeTypes.FWP_V6_ADDR_AND_MASK
        {
            addr = addrBytes,
            prefixLength = prefixLength
        };
        var ptr = System.Runtime.InteropServices.Marshal.AllocHGlobal(
            System.Runtime.InteropServices.Marshal.SizeOf(mask));
        System.Runtime.InteropServices.Marshal.StructureToPtr(mask, ptr, false);
        return ptr;
    }

    private static nint MarshalV4AddrMask(uint addr, uint mask)
    {
        var v4 = new WfpNativeTypes.FWP_V4_ADDR_AND_MASK
        {
            addr = addr,
            mask = mask
        };
        var ptr = System.Runtime.InteropServices.Marshal.AllocHGlobal(
            System.Runtime.InteropServices.Marshal.SizeOf(v4));
        System.Runtime.InteropServices.Marshal.StructureToPtr(v4, ptr, false);
        return ptr;
    }

    private Guid ResolveLayer()
    {
        var isV6 = _rule.AddressFamily == AddressFamily.IPv6;

        if (_rule.Direction == TrafficDirection.Inbound)
            return isV6 ? WfpLayers.AleAuthRecvAcceptV6 : WfpLayers.AleAuthRecvAcceptV4;
        else
            return isV6 ? WfpLayers.AleAuthConnectV6 : WfpLayers.AleAuthConnectV4;
    }

    /// <summary>
    ///   Allocate unmanaged memory and write the Heco provider GUID into it.
    ///   The returned pointer is owned by the caller (WfpEngine frees it after
    ///   <c>FwpmFilterAdd0</c>).
    /// </summary>
    private static nint MarshalHecoProviderKey()
    {
        var ptr = System.Runtime.InteropServices.Marshal.AllocHGlobal(16);
        System.Runtime.InteropServices.Marshal.StructureToPtr(HecoProviderKey, ptr, false);
        return ptr;
    }
}
