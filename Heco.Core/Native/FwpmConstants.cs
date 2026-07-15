using System;

namespace Heco.Core.Native;

internal static class WfpLayers
{
    // ── ALE Connect (outbound) ──────────────────────────────────
    public static readonly Guid AleAuthConnectV4     = new("2A5FFBA1-E8B4-4DC7-A27F-2577BA1A6340");
    public static readonly Guid AleAuthConnectV6     = new("78C2B39A-31AF-44F8-8E9F-A38213F543EC");

    // ── ALE Receive/Accept (inbound) ────────────────────────────
    public static readonly Guid AleAuthRecvAcceptV4  = new("E1CDD904-C67C-4763-A862-4C47274A80B0");
    public static readonly Guid AleAuthRecvAcceptV6  = new("2504C081-C099-4621-B567-13120B2B4223");

    // ── Transport (inbound / outbound) ──────────────────────────
    public static readonly Guid InboundTransportV4   = new("111C5E0C-EB34-46C7-93EC-B0D298A41AAD");
    public static readonly Guid OutboundTransportV4  = new("E53F06D4-1E96-4572-A651-02A65AB31F0B");
    public static readonly Guid InboundTransportV6   = new("46951D22-5B6B-4C74-83FC-B9B33CB3C048");
    public static readonly Guid OutboundTransportV6  = new("1E02DFCE-CA2E-4112-8977-47E07DBD0F45");
}

/// <summary>
///   WFP condition field GUIDs — what each filter condition tests.
/// </summary>
internal static class WfpConditions
{
    public static readonly Guid IpProtocol      = new("B3F3E81D-EACF-4B4F-8607-083D0854C28A");
    public static readonly Guid IpLocalPort     = new("4EA3D3C6-4B30-4C2D-87B1-87A88DB518D1");
    public static readonly Guid IpRemotePort    = new("B4BD1275-445B-4B0E-B7E1-12604431D450");
    public static readonly Guid IpLocalAddress  = new("5A2F608E-79FE-4A77-9473-C5D0F20E4E1D");
    public static readonly Guid IpRemoteAddress = new("4814D290-A5C0-4D28-B39D-B2D7ACDDCDEE");
    public static readonly Guid AleAppId        = new("C1C0144B-22F4-4CAA-B4A0-D48138AD7A16");
    public static readonly Guid AleUserId       = new("2072F20B-2831-4A7B-A48B-63822666967B");
    public static readonly Guid AleFlags        = new("632CEF2B-B6C2-4C5A-B99A-7FD14E4DEF22");
    public static readonly Guid Direction       = new("B4DED1BB-EFB7-40A7-A318-8656053A39B7");
    public static readonly Guid IpLocalInterface = new("1C1B4AE4-1261-4428-B5D6-F94B0A66032F");
}

/// <summary>
///   WFP error codes returned by API functions.
/// </summary>
internal static class WfpErrors
{
    public const uint Success        = 0;
    public const uint AccessDenied   = 5;
    public const uint NotFound       = 0x80320001;
    public const uint AlreadyExists  = 0x80320009; // FWP_E_ALREADY_EXISTS
    public const uint InUse          = 0x8032000A;
    public const uint SessionAborted = 0x8032000B;
    public const uint NoMoreItems    = 259;
}
