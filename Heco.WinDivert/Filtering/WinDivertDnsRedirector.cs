using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Heco.WinDivert.Dns;
using Heco.WinDivert.Native;
using static Heco.WinDivert.Native.WinDivertLayer;
using static Heco.WinDivert.Native.WinDivertFlag;
using static Heco.WinDivert.Native.WinDivertStructs;

namespace Heco.WinDivert.Filtering;

public sealed class WinDivertDnsRedirector : IDisposable
{
    private nint _redirectorHandle;
    private readonly object _handleLock = new();
    private CancellationTokenSource? _cts;
    private Task? _redirectorTask;
    private readonly List<Task> _backgroundTasks = new();
    private bool _disposed;

    private static readonly HttpClient _httpClient;

    private readonly Func<string, bool> _blockChecker;
    private readonly Func<bool> _dohEnabledProvider;
    private readonly Func<string> _dohUrlProvider;

    public bool IsRunning => _redirectorTask?.IsCompleted == false;

    static WinDivertDnsRedirector()
    {
        var handler = new HttpClientHandler
        {
            AutomaticDecompression = System.Net.DecompressionMethods.GZip | System.Net.DecompressionMethods.Deflate
        };
        _httpClient = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(3)
        };
        _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("HecoFirewallDNS/1.0");
    }

    public WinDivertDnsRedirector(
        Func<string, bool> blockChecker,
        Func<bool> dohEnabledProvider,
        Func<string> dohUrlProvider)
    {
        _blockChecker = blockChecker ?? throw new ArgumentNullException(nameof(blockChecker));
        _dohEnabledProvider = dohEnabledProvider ?? throw new ArgumentNullException(nameof(dohEnabledProvider));
        _dohUrlProvider = dohUrlProvider ?? throw new ArgumentNullException(nameof(dohUrlProvider));
    }

    public void Start()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(WinDivertDnsRedirector));
        if (IsRunning) return;

        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        try
        {
            _redirectorHandle = WinDivertNative.WinDivertOpen(
                "outbound and udp.DstPort == 53",
                (int)Network,
                priority: 90,
                flags: 0);

            if (_redirectorHandle != 0 && _redirectorHandle != -1)
            {
                _redirectorTask = Task.Run(() => RunRedirectorLoop(token), token);
                Debug.WriteLine("[WinDivertDnsRedirector] DNS interception loop started");
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[WinDivertDnsRedirector] Failed to start: {ex.Message}");
        }
    }

    public void Stop()
    {
        _cts?.Cancel();

        if (_redirectorTask != null)
        {
            try
            {
                if (!_redirectorTask.Wait(TimeSpan.FromSeconds(5)))
                    Debug.WriteLine("[WinDivertDnsRedirector] Loop did not exit within timeout");
            }
            catch (AggregateException ex)
            {
                Debug.WriteLine($"[WinDivertDnsRedirector] Stop exception: {ex.Message}");
            }
            finally
            {
                _redirectorTask = null;
            }
        }

        lock (_backgroundTasks)
        {
            foreach (var task in _backgroundTasks)
            {
                try
                {
                    if (!task.Wait(TimeSpan.FromSeconds(2)))
                        Debug.WriteLine("[WinDivertDnsRedirector] Background task timeout");
                }
                catch (AggregateException ex)
                {
                    Debug.WriteLine($"[WinDivertDnsRedirector] Background exception: {ex.Message}");
                }
            }
            _backgroundTasks.Clear();
        }

        lock (_handleLock)
        {
            var handle = _redirectorHandle;
            if (handle != 0 && handle != -1)
            {
                _redirectorHandle = 0;
                try { WinDivertNative.WinDivertClose(handle); }
                catch { }
            }
        }
        Debug.WriteLine("[WinDivertDnsRedirector] Stopped");
    }

    private void RunRedirectorLoop(CancellationToken token)
    {
        var buffer = new byte[65536];
        var addr = new WINDIVERT_ADDRESS();
        uint recvLen = 0;

        while (!token.IsCancellationRequested)
        {
            nint handle;
            lock (_handleLock) { handle = _redirectorHandle; }
            if (handle == 0 || handle == -1) break;

            try
            {
                if (WinDivertNative.WinDivertRecv(handle, buffer, (uint)buffer.Length, ref recvLen, ref addr))
                {
                    if (token.IsCancellationRequested) break;

                    var ipHeaderLen = GetIpHeaderLen(buffer, recvLen);
                    if (ipHeaderLen <= 0)
                    {
                        Reinject(buffer, recvLen, addr, token);
                        continue;
                    }

                    var payloadOffset = ipHeaderLen + 8;
                    if (recvLen <= payloadOffset)
                    {
                        Reinject(buffer, recvLen, addr, token);
                        continue;
                    }

                    var payloadLen = recvLen - (uint)payloadOffset;
                    var dnsQueryPayload = new byte[payloadLen];
                    Array.Copy(buffer, payloadOffset, dnsQueryPayload, 0, payloadLen);

                    var query = new DnsQuery(dnsQueryPayload, new System.Net.IPEndPoint(System.Net.IPAddress.Any, 0));
                    if (!DnsQuery.IsValidQuery(query) || string.IsNullOrEmpty(query.QueryDomain))
                    {
                        Reinject(buffer, recvLen, addr, token);
                        continue;
                    }

                    var domain = query.QueryDomain!;
                    var queryType = query.QueryType;

                    if (_blockChecker(domain))
                    {
                        Debug.WriteLine($"[DNS] Blocked domain: {domain}");
                        var blockPayload = DnsQueryBuilder.CreateBlockedResponse(dnsQueryPayload, domain, queryType);
                        SendSpoofedResponse(buffer, recvLen, ipHeaderLen, blockPayload, addr, token);
                        continue;
                    }

                    if (_dohEnabledProvider())
                    {
                        var dohUrl = _dohUrlProvider();
                        var pendingQuery = dnsQueryPayload;
                        var originalBuffer = new byte[recvLen];
                        Array.Copy(buffer, originalBuffer, recvLen);
                        var originalAddr = addr;

                        var bgTask = Task.Run(async () =>
                        {
                            var responsePayload = await ResolveViaDoHAsync(pendingQuery, dohUrl);
                            if (responsePayload != null && responsePayload.Length > 0)
                                SendSpoofedResponse(originalBuffer, (uint)originalBuffer.Length, ipHeaderLen, responsePayload, originalAddr, token);
                            else
                                Reinject(originalBuffer, (uint)originalBuffer.Length, originalAddr, token);
                        }, token);

                        lock (_backgroundTasks) { _backgroundTasks.Add(bgTask); }
                        continue;
                    }

                    Reinject(buffer, recvLen, addr, token);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[WinDivertDnsRedirector] Error: {ex.Message}");
                Thread.Sleep(10);
            }
        }
    }

    private async Task<byte[]?> ResolveViaDoHAsync(byte[] dnsQueryPayload, string dohUrl)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, dohUrl);
            request.Headers.Accept.Clear();
            request.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/dns-message"));
            request.Content = new ByteArrayContent(dnsQueryPayload);
            request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/dns-message");

            using var response = await _httpClient.SendAsync(request);
            if (response.IsSuccessStatusCode)
                return await response.Content.ReadAsByteArrayAsync();
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[DoH] Error: {ex.Message}");
        }
        return null;
    }

    private unsafe void SendSpoofedResponse(byte[] originalBuffer, uint recvLen, int ipHeaderLen, byte[] responsePayload, WINDIVERT_ADDRESS addr, CancellationToken token)
    {
        if (_disposed || token.IsCancellationRequested) return;
        nint handle;
        lock (_handleLock) { handle = _redirectorHandle; }
        if (handle == 0 || handle == -1) return;

        try
        {
            var isIpv6 = (originalBuffer[0] >> 4) == (byte)IPVersion.V6;
            var newPacket = new byte[ipHeaderLen + 8 + responsePayload.Length];

            Array.Copy(originalBuffer, 0, newPacket, 0, ipHeaderLen + 8);

            var udpLen = 8 + responsePayload.Length;

            fixed (byte* pkt = newPacket)
            {
                if (isIpv6)
                {
                    var v6 = (V6Header*)pkt;
                    // Swap addresses
                    var tmpAddr = stackalloc byte[16];
                    Buffer.MemoryCopy(v6->SrcAddr, tmpAddr, 16, 16);
                    Buffer.MemoryCopy(v6->DstAddr, v6->SrcAddr, 16, 16);
                    Buffer.MemoryCopy(tmpAddr, v6->DstAddr, 16, 16);
                    // Update payload length
                    v6->PayloadLength = (ushort)udpLen;
                }
                else
                {
                    var v4 = (V4Header*)pkt;
                    // Swap addresses
                    (v4->SrcAddr, v4->DstAddr) = (v4->DstAddr, v4->SrcAddr);
                    // Update total length
                    v4->Length = (ushort)newPacket.Length;
                }

                // Swap UDP ports
                var udp = (ushort*)(pkt + ipHeaderLen);
                (udp[0], udp[1]) = (udp[1], udp[0]);
                // UDP length
                udp[2] = (ushort)udpLen;
                // Reset checksum
                udp[3] = 0;
            }

            // Copy payload after UDP header
            Array.Copy(responsePayload, 0, newPacket, ipHeaderLen + 8, responsePayload.Length);

            // Send as inbound
            var newAddr = addr;
            newAddr.Outbound = false;

            WinDivertNative.WinDivertHelperCalcChecksums(newPacket, (uint)newPacket.Length, ref newAddr, 0);

            uint sendLen = 0;
            WinDivertNative.WinDivertSend(handle, newPacket, (uint)newPacket.Length, ref sendLen, ref newAddr);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[DNS] SendSpoofedResponse error: {ex.Message}");
        }
    }

    private static unsafe int GetIpHeaderLen(byte[] buffer, uint recvLen)
    {
        if (recvLen < 1) return 0;
        fixed (byte* p = buffer)
        {
            var version = p[0] >> 4;
            return version == 4
                ? (p[0] & 0x0F) * 4
                : version == 6 ? 40 : 0;
        }
    }

    private void Reinject(byte[] packet, uint length, WINDIVERT_ADDRESS addr, CancellationToken token)
    {
        if (_disposed || token.IsCancellationRequested) return;
        nint handle;
        lock (_handleLock) { handle = _redirectorHandle; }
        if (handle == 0 || handle == -1) return;

        try
        {
            uint sendLen = 0;
            WinDivertNative.WinDivertSend(handle, packet, length, ref sendLen, ref addr);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[WinDivertDnsRedirector] Reinject error: {ex.Message}");
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        Stop();
        _cts?.Dispose();
        _disposed = true;
    }
}
