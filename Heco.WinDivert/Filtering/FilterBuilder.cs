using System;
using System.Collections.Generic;
using System.Text;
using Heco.WinDivert.Structs;

namespace Heco.WinDivert.Filtering;

/// <summary>
/// Fluent builder for constructing WinDivert filter strings programmatically.
/// Provides IntelliSense and compile-time validation for filter fields.
/// </summary>
public sealed class FilterBuilder
{
    private readonly List<string> _conditions = new();
    private readonly List<(string op, FilterBuilder subFilter)> _groups = new();

    private FilterBuilder() { }

    public static FilterBuilder Create() => new();

    // --- Meta conditions ---

    public FilterBuilder Inbound() { _conditions.Add(FilterToken.Inbound); return this; }
    public FilterBuilder Outbound() { _conditions.Add(FilterToken.Outbound); return this; }
    public FilterBuilder Fragment() { _conditions.Add(FilterToken.Fragment); return this; }
    public FilterBuilder Loopback() { _conditions.Add(FilterToken.Loopback); return this; }
    public FilterBuilder Impostor() { _conditions.Add(FilterToken.Impostor); return this; }
    public FilterBuilder IfIdx(uint value) { _conditions.Add($"{FilterToken.IfIdx} == {value}"); return this; }
    public FilterBuilder SubIfIdx(uint value) { _conditions.Add($"{FilterToken.SubIfIdx} == {value}"); return this; }
    public FilterBuilder ProcessId(uint value) { _conditions.Add($"{FilterToken.ProcessId} == {value}"); return this; }
    public FilterBuilder LocalAddr(string addr) { _conditions.Add($"{FilterToken.LocalAddr} == {addr}"); return this; }
    public FilterBuilder RemoteAddr(string addr) { _conditions.Add($"{FilterToken.RemoteAddr} == {addr}"); return this; }
    public FilterBuilder LocalPort(ushort port) { _conditions.Add($"{FilterToken.LocalPort} == {port}"); return this; }
    public FilterBuilder RemotePort(ushort port) { _conditions.Add($"{FilterToken.RemotePort} == {port}"); return this; }
    public FilterBuilder Protocol(byte proto) { _conditions.Add($"{FilterToken.Protocol} == {proto}"); return this; }
    public FilterBuilder Length(int len) { _conditions.Add($"{FilterToken.Length} == {len}"); return this; }
    public FilterBuilder True() { _conditions.Add(FilterToken.True); return this; }
    public FilterBuilder False() { _conditions.Add(FilterToken.False); return this; }

    // --- Layer/Event ---

    public FilterBuilder Layer(WinDivertLayer layer) { _conditions.Add($"{FilterToken.Layer} == {(int)layer}"); return this; }
    public FilterBuilder Event(WinDivertEvent evt) { _conditions.Add($"{FilterToken.Event} == {(int)evt}"); return this; }
    public FilterBuilder Packet() { _conditions.Add(FilterToken.Packet); return this; }
    public FilterBuilder Established() { _conditions.Add(FilterToken.Established); return this; }
    public FilterBuilder Deleted() { _conditions.Add(FilterToken.Deleted); return this; }
    public FilterBuilder Bind() { _conditions.Add(FilterToken.Bind); return this; }
    public FilterBuilder Connect() { _conditions.Add(FilterToken.Connect); return this; }
    public FilterBuilder Listen() { _conditions.Add(FilterToken.Listen); return this; }
    public FilterBuilder Accept() { _conditions.Add(FilterToken.Accept); return this; }
    public FilterBuilder Open() { _conditions.Add(FilterToken.Open); return this; }
    public FilterBuilder Close() { _conditions.Add(FilterToken.Close); return this; }

    // --- IPv4 ---

    public FilterBuilder IpDstAddr(string addr) { _conditions.Add($"{FilterToken.IpDstAddr} == {addr}"); return this; }
    public FilterBuilder IpSrcAddr(string addr) { _conditions.Add($"{FilterToken.IpSrcAddr} == {addr}"); return this; }
    public FilterBuilder IpProtocol(byte proto) { _conditions.Add($"{FilterToken.IpProtocol} == {proto}"); return this; }
    public FilterBuilder IpLength(int len) { _conditions.Add($"{FilterToken.IpLength} == {len}"); return this; }
    public FilterBuilder IpTTL(byte ttl) { _conditions.Add($"{FilterToken.IpTTL} == {ttl}"); return this; }
    public FilterBuilder IpTOS(byte tos) { _conditions.Add($"{FilterToken.IpTOS} == {tos}"); return this; }
    public FilterBuilder IpId(ushort id) { _conditions.Add($"{FilterToken.IpId} == {id}"); return this; }
    public FilterBuilder IpDF(bool value) { _conditions.Add($"{FilterToken.IpDF} == {(value ? 1 : 0)}"); return this; }
    public FilterBuilder IpMF(bool value) { _conditions.Add($"{FilterToken.IpMF} == {(value ? 1 : 0)}"); return this; }
    public FilterBuilder IpFragOff(ushort off) { _conditions.Add($"{FilterToken.IpFragOff} == {off}"); return this; }
    public FilterBuilder IpHdrLength(byte len) { _conditions.Add($"{FilterToken.IpHdrLength} == {len}"); return this; }
    public FilterBuilder IpChecksum(ushort cs) { _conditions.Add($"{FilterToken.IpChecksum} == {cs}"); return this; }

    // --- IPv6 ---

    public FilterBuilder Ipv6DstAddr(string addr) { _conditions.Add($"{FilterToken.Ipv6DstAddr} == {addr}"); return this; }
    public FilterBuilder Ipv6SrcAddr(string addr) { _conditions.Add($"{FilterToken.Ipv6SrcAddr} == {addr}"); return this; }
    public FilterBuilder Ipv6NextHdr(byte proto) { _conditions.Add($"{FilterToken.Ipv6NextHdr} == {proto}"); return this; }
    public FilterBuilder Ipv6HopLimit(byte limit) { _conditions.Add($"{FilterToken.Ipv6HopLimit} == {limit}"); return this; }
    public FilterBuilder Ipv6TrafficClass(byte tc) { _conditions.Add($"{FilterToken.Ipv6TrafficClass} == {tc}"); return this; }
    public FilterBuilder Ipv6FlowLabel(uint label) { _conditions.Add($"{FilterToken.Ipv6FlowLabel} == {label}"); return this; }
    public FilterBuilder Ipv6Length(int len) { _conditions.Add($"{FilterToken.Ipv6Length} == {len}"); return this; }

    // --- ICMP ---

    public FilterBuilder IcmpType(byte type) { _conditions.Add($"{FilterToken.IcmpType} == {type}"); return this; }
    public FilterBuilder IcmpCode(byte code) { _conditions.Add($"{FilterToken.IcmpCode} == {code}"); return this; }
    public FilterBuilder IcmpChecksum(ushort cs) { _conditions.Add($"{FilterToken.IcmpChecksum} == {cs}"); return this; }

    // --- ICMPv6 ---

    public FilterBuilder Icmpv6Type(byte type) { _conditions.Add($"{FilterToken.Icmpv6Type} == {type}"); return this; }
    public FilterBuilder Icmpv6Code(byte code) { _conditions.Add($"{FilterToken.Icmpv6Code} == {code}"); return this; }
    public FilterBuilder Icmpv6Checksum(ushort cs) { _conditions.Add($"{FilterToken.Icmpv6Checksum} == {cs}"); return this; }

    // --- TCP ---

    public FilterBuilder TcpSrcPort(ushort port) { _conditions.Add($"{FilterToken.TcpSrcPort} == {port}"); return this; }
    public FilterBuilder TcpDstPort(ushort port) { _conditions.Add($"{FilterToken.TcpDstPort} == {port}"); return this; }
    public FilterBuilder TcpSeqNum(uint seq) { _conditions.Add($"{FilterToken.TcpSeqNum} == {seq}"); return this; }
    public FilterBuilder TcpAckNum(uint ack) { _conditions.Add($"{FilterToken.TcpAckNum} == {ack}"); return this; }
    public FilterBuilder TcpFlags(TcpFlag flags) { _conditions.Add($"{FilterToken.Tcp} == {FilterToken.TcpProto} and ({BuildTcpFlagCheck(flags)})"); return this; }
    public FilterBuilder TcpSyn() { _conditions.Add($"{FilterToken.TcpSyn} == 1"); return this; }
    public FilterBuilder TcpAck() { _conditions.Add($"{FilterToken.TcpAck} == 1"); return this; }
    public FilterBuilder TcpFin() { _conditions.Add($"{FilterToken.TcpFin} == 1"); return this; }
    public FilterBuilder TcpRst() { _conditions.Add($"{FilterToken.TcpRst} == 1"); return this; }
    public FilterBuilder TcpPsh() { _conditions.Add($"{FilterToken.TcpPsh} == 1"); return this; }
    public FilterBuilder TcpUrg() { _conditions.Add($"{FilterToken.TcpUrg} == 1"); return this; }
    public FilterBuilder TcpWindow(ushort win) { _conditions.Add($"{FilterToken.TcpWindow} == {win}"); return this; }
    public FilterBuilder TcpPayloadLength(int len) { _conditions.Add($"{FilterToken.TcpPayloadLength} == {len}"); return this; }
    public FilterBuilder TcpHdrLength(byte len) { _conditions.Add($"{FilterToken.TcpHdrLength} == {len}"); return this; }
    public FilterBuilder TcpChecksum(ushort cs) { _conditions.Add($"{FilterToken.TcpChecksum} == {cs}"); return this; }
    public FilterBuilder TcpUrgPtr(ushort ptr) { _conditions.Add($"{FilterToken.TcpUrgPtr} == {ptr}"); return this; }

    // --- UDP ---

    public FilterBuilder UdpSrcPort(ushort port) { _conditions.Add($"{FilterToken.UdpSrcPort} == {port}"); return this; }
    public FilterBuilder UdpDstPort(ushort port) { _conditions.Add($"{FilterToken.UdpDstPort} == {port}"); return this; }
    public FilterBuilder UdpLength(ushort len) { _conditions.Add($"{FilterToken.UdpLength} == {len}"); return this; }
    public FilterBuilder UdpChecksum(ushort cs) { _conditions.Add($"{FilterToken.UdpChecksum} == {cs}"); return this; }
    public FilterBuilder UdpPayloadLength(int len) { _conditions.Add($"{FilterToken.UdpPayloadLength} == {len}"); return this; }

    // --- Comparison operators ---

    public FilterBuilder Eq(string field, object value) { _conditions.Add($"{field} == {value}"); return this; }
    public FilterBuilder Neq(string field, object value) { _conditions.Add($"{field} != {value}"); return this; }
    public FilterBuilder Lt(string field, object value) { _conditions.Add($"{field} < {value}"); return this; }
    public FilterBuilder Gt(string field, object value) { _conditions.Add($"{field} > {value}"); return this; }
    public FilterBuilder Le(string field, object value) { _conditions.Add($"{field} <= {value}"); return this; }
    public FilterBuilder Ge(string field, object value) { _conditions.Add($"{field} >= {value}"); return this; }

    // --- Logical grouping ---

    public FilterBuilder And(Action<FilterBuilder> build)
    {
        var sub = new FilterBuilder();
        build(sub);
        _groups.Add(("and", sub));
        return this;
    }

    public FilterBuilder Or(Action<FilterBuilder> build)
    {
        var sub = new FilterBuilder();
        build(sub);
        _groups.Add(("or", sub));
        return this;
    }

    public FilterBuilder Not(Action<FilterBuilder> build)
    {
        var sub = new FilterBuilder();
        build(sub);
        _conditions.Add($"!({sub.Build()})");
        return this;
    }

    // --- Build ---

    public string Build()
    {
        var sb = new StringBuilder();
        bool first = true;

        foreach (var cond in _conditions)
        {
            if (!first) sb.Append(" and ");
            sb.Append(cond);
            first = false;
        }

        foreach (var (op, sub) in _groups)
        {
            if (!first) sb.Append($" {op} ");
            sb.Append($"({sub.Build()})");
            first = false;
        }

        return sb.Length == 0 ? FilterToken.True : sb.ToString();
    }

    public override string ToString() => Build();

    private static string BuildTcpFlagCheck(TcpFlag flags)
    {
        var parts = new List<string>();
        if ((flags & TcpFlag.Fin) != 0) parts.Add($"{FilterToken.TcpFin} == 1");
        if ((flags & TcpFlag.Syn) != 0) parts.Add($"{FilterToken.TcpSyn} == 1");
        if ((flags & TcpFlag.Rst) != 0) parts.Add($"{FilterToken.TcpRst} == 1");
        if ((flags & TcpFlag.Psh) != 0) parts.Add($"{FilterToken.TcpPsh} == 1");
        if ((flags & TcpFlag.Ack) != 0) parts.Add($"{FilterToken.TcpAck} == 1");
        if ((flags & TcpFlag.Urg) != 0) parts.Add($"{FilterToken.TcpUrg} == 1");
        return string.Join(" and ", parts);
    }
}