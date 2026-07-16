# Heco Firewall

**Heco Firewall** is a modern, WPF-based Windows firewall application that provides real-time network monitoring, packet filtering, GeoIP lookup, blocklist management, and application profiling. Built on .NET 8 with a clean MVVM architecture, it uses **WinDivert** for high-performance packet interception and **MaxMind GeoLite2** databases for IP geolocation.

---

## Features

### Packet Filtering Engine (WinDivert)
- **Active interception** of all network traffic (inbound/outbound, TCP/UDP/ICMP/other protocols)
- **Connection-time verdict evaluation** — decisions made at SYN packet, before connection establishes
- **Per-application rules** — allow/block by executable path, port, protocol, IP address, or CIDR range
- **Dynamic rule caching** — avoids repeated lookups for same application/direction
- **Interactive mode** — prompts user for unknown connections (Allow Once / Block Once / Always Allow / Always Block)
- **True async I/O** with overlapped WinDivertRecvEx/SendEx + `IValueTaskSource<int>` (zero-allocation)
- **Native memory packet** — `SafeHandle`-backed `WinDivertPacket` with `NativeMemory.AllocZeroed`
- **Full protocol headers** — unified `V4Header`/`V6Header` (LayoutKind.Explicit) covering TCP, UDP, ICMPv4, ICMPv6 fields
- **Reverse endpoint, IP length recalculation, route-aware flags** — `ReverseEndPoint()`, `ApplyLengthToHeaders()`, `CalcNetworkIfIdx()`, `CalcOutboundFlag()`, `CalcLoopbackFlag()`

### Multi-Layer Verdict Pipeline
Rules are evaluated in priority order:
1. **Blocklists** (domains/IPs) — HaGeZi, threat feeds, custom lists
2. **Application Profiles** — auto-generated or manual, with action overrides
3. **User Firewall Rules** — explicit allow/block rules
4. **Interactive Prompt** — user decision for unknown connections

### GeoIP Lookup (MaxMind GeoLite2)
- **Country** — ISO code + name
- **ASN** — Autonomous System Number + organization
- **Anycast detection** — identifies anycast IPs (CDNs, cloud providers)
- **MMDB Viewer** — built-in database inspector

### Blocklist Management
- **Online auto-update** from URLs (HaGeZi, OISD, threat intelligence feeds)
- **Offline file import** — hosts files, domain lists, IP lists, wildcard patterns
- **Bloom filter** backed for O(1) lookups with minimal memory
- **Content types**: Domain, IP, Wildcard (`*.example.com`), Hosts file format
- **Parent domain matching** — blocks `sub.example.com` when `example.com` is listed

### Application Profiles
- **Auto-generation** from running processes
- **Fingerprint matching** by: full path, process name, command line, Windows service, Store app
- **Action overrides** — per-profile allow/block inbound/outbound
- **Hit counting** — tracks how many connections matched each profile

### Real-Time Connection Monitor
- **Live TCP/UDP/ARP/ICMP** connection table via `iphlpapi` (polled every 1–2s)
- **Process resolution** — PID → name, path, icon, user, service
- **DNS cache inspection** — view resolved hostnames
- **DHCP lease info** — adapter configuration
- **Bandwidth tracking** — per-connection KB/s sent/received
- **Search/filter** by process, IP, port, country, profile

### Activity Log
- **Block events** — timestamp, process, protocol, addresses, ports, profile source
- **DNS queries** — domain, type, result, blocked status
- **Export** to CSV/JSON

### Modern WPF UI (MVVM)
- **Tabbed dashboard**: Dashboard, Rules, Connections, Profiles, Blocklists, Activity, Settings
- **System tray** integration — minimize to tray, balloon notifications on blocks
- **Toast notifications** — non-intrusive block alerts
- **Dark/light theme** ready (MaterialDesignThemes)
- **Drag-to-move** frameless window
- **Responsive DataGrid** with sorting, filtering, multi-select

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Heco Firewall (WPF App)                     │
├─────────────────────────────────────────────────────────────────┤
│  Views (XAML)          │  ViewModels (CommunityToolkit.Mvvm)    │
│  ┌─────────────────┐   │  ┌─────────────────────────────────┐  │
│  │ DashboardView   │   │  │ MainViewModel                   │  │
│  │ RulesView       │   │  │ RulesViewModel                  │  │
│  │ ConnectionsView │   │  │ ConnectionsViewModel            │  │
│  │ ProfilesView    │◄──┤  │ ProfilesViewModel               │  │
│  │ BlocklistsView  │   │  │ BlocklistsViewModel             │  │
│  │ ActivityView    │   │  │ ActivityViewModel               │  │
│  │ SettingsView    │   │  │ SettingsViewModel               │  │
│  └─────────────────┘   │  └─────────────────────────────────┘  │
├────────────────────────┼────────────────────────────────────────┤
│         Services Layer (Dependency Injection via constructors)  │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌────────┐ │
│  │WinDivertFilter│ │ConnectionMonitor│ │BlocklistManager│ │GeoLookup│ │
│  │(Active filter)│ │(iphlpapi poll) │ │(Bloom filters) │ │(MaxMind)│ │
│  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └────┬───┘ │
├─────────┼────────────────┼────────────────┼──────────────┼─────┤
│         ▼                ▼                ▼              ▼     │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    VerdictEngine                          │  │
│  │  Blocklists → Profiles → User Rules → Interactive Prompt  │  │
│  └──────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│  Native Layer (P/Invoke)                                        │
│  • WinDivert.dll (packet interception via overlapped I/O)       │
│  • iphlpapi.dll (connection tables, DNS cache, DHCP)           │
│  • dnsapi.dll (DNS resolution)                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Project Structure
```
Heco_Firewall/
├── Heco_Firewall/                 # WPF Application (Main UI)
│   ├── Views/                     # XAML Views
│   ├── ViewModels/                # MVVM ViewModels
│   ├── Windows/                   # Dialog/Toast/Prompt windows
│   ├── Tray/                      # System tray service
│   ├── Converters/                # Value converters
│   ├── Helpers/                   # RelayCommand, ObservableObject
│   └── Data/                      # Bundled blocklists, GeoIP DBs
├── Heco.Common/                   # Shared domain library
│   ├── Models/                    # FirewallRule, ConnectionEntry, GeoIpResult, etc.
│   ├── Enums/                     # RuleAction, TrafficDirection, NetworkProtocol, etc.
│   ├── Interfaces/                # IWfpEngine, IConnectionMonitor, IBlocklistManager, etc.
│   ├── Services/                  # Settings, Profiles, Blocklists, GeoIP, Monitoring, etc.
│   ├── Data/                      # FirewallRuleRepository (JSON persistence)
│   └── Diagnostics/               # Logger, HecoException
├── Heco.WinDivert/                # WinDivert wrapper & packet filtering
│   ├── Structs/                   # Protocol headers & WinDivert structs (V4Header, V6Header, TcpHeader, WINDIVERT_ADDRESS, enums)
│   ├── Interop/                   # P/Invoke: WinDivertNative, Kernel32Native, IPHelpApiNative, RouteResolver
│   ├── Device/                    # WinDivertDevice + overlapped async I/O (IValueTaskSource<int>)
│   ├── Packet/                    # Native memory SafeHandle packet, packet parsing
│   ├── Filtering/                 # WinDivertFilter (active interception), WinDivertDnsRedirector
│   ├── StreamReassembly/          # TCP stream reassembly for HTTP inspection
│   ├── Services/                  # Driver management
│   ├── Models/                    # ConnectionEntry, RuleAction
│   ├── Dns/                       # DNS query/response parsing for DoH redirect
│   └── Drivers/                   # WinDivert DLL & driver files
├── Heco.Surveillance/             # Network monitoring (iphlpapi-based)
│   ├── Patrol/                    # ConnectionMonitor (live connection polling)
│   ├── Recon/                     # ProcessResolver, DnsResolver
│   ├── Native/                    # IpHlpApi, DnsApi P/Invoke
│   └── Sniffer/                   # Raw packet capture (PacketSniffer)
├── tools/
│   └── Download-GeoIP.ps1         # PowerShell script to download MaxMind DBs
├── Heco_Firewall.sln
└── README.md
```

---

## Getting Started

### Prerequisites
- **Windows 10/11** (x64)
- **.NET 8 Desktop Runtime** (or SDK for building)
- **Administrator privileges** — required for WinDivert driver
- **WinDivert driver** — installed automatically on first run (or manually via `WinDivert.dll`)

### Installation

#### Option 1: Build from Source
```bash
# Clone repository
git clone https://github.com/your-org/Heco_Firewall.git
cd Heco_Firewall

# Restore packages
dotnet restore

# Build (Release x64 recommended)
dotnet build -c Release -p:Platform=x64

# Run
cd Heco_Firewall/bin/x64/Release/net8.0-windows
./Heco_Firewall.exe
```

#### Option 2: Download GeoIP Databases (Required for GeoIP features)
```powershell
# Register at https://www.maxmind.com/en/geolite2/signup (free)
# Generate license key at https://www.maxmind.com/en/accounts/current/license

# Run download script
.\tools\Download-GeoIP.ps1 -LicenseKey YOUR_LICENSE_KEY

# Extract .mmdb files from .tar.gz into Heco_Firewall/Data/GeoIP/
# Expected files:
#   GeoLite2-City.mmdb
#   GeoLite2-ASN.mmdb
```

> **Note:** The app includes a bundled `Download-GeoIP.ps1` script. You can also download manually from [MaxMind GeoLite2 Free](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).

---

## Usage Guide

### First Launch
1. Run **as Administrator** (right-click → "Run as administrator")
2. The app will show a warning if not elevated — WinDivert requires admin
3. Click **"Start Protection"** on Dashboard or enable **Firewall Active** in Settings

### Dashboard
- **Quick stats**: active rules, live connections, blocked today, bandwidth
- **Recent blocked events** — click to view details
- **Start/Stop** protection toggle

### Firewall Rules
- **Add Rule** — define name, action (Allow/Block), direction, protocol, ports, addresses, application path
- **Edit/Delete/Toggle** — multi-select supported
- **Rule priority**: Blocklists → Profiles → User Rules → Interactive

### Live Connections
- **Real-time table** of all TCP/UDP/ICMP/ARP connections
- **Columns**: Process, PID, Protocol, Local/Remote Address:Port, State, Profile, Country, ASN, Bandwidth
- **Search** by any column
- **Force refresh** button
- **DNS Cache** viewer (via `iphlpapi`)
- **DHCP Info** — adapter leases

### Application Profiles
- **Auto-generate** from running processes
- **Edit fingerprints**: full path, process name, command line, service name, Store app
- **Action overrides**: Allow/Block inbound/outbound per profile
- **Hit count** tracking

### Blocklists
- **Built-in**: HaGeZi (domains), OISD, custom offline lists
- **Add online** — name, URL, content type, update interval
- **Add offline** — select .txt/.hosts file
- **Update all** / update selected
- **View entries** — inspect loaded domains/IPs

### Activity Log
- **Block events** — timestamp, process, protocol, src/dst IP:port, profile source
- **DNS queries** — domain, query type, result, blocked status
- **Clear / Refresh / Export**

### Settings
- **General**: Minimize to tray, start minimized, check for updates
- **Firewall**: Interactive mode, secure DNS (DoH), notifications

- **GeoIP**: Database path, MMDB Viewer
- **Advanced**: Refresh interval, max dynamic filters, log level

---

## Configuration

Settings are stored in `%APPDATA%\Heco\settings.json`:

```json
{
  "AppSettings": {
    "MinimizeToTray": true,
    "StartMinimized": false,
    "FirewallActive": false,
    "InteractiveMode": true,
    "ShowNotifications": true,
    "SecureDnsEnabled": false,
    "DnsOverHttpsProvider": "https://cloudflare-dns.com/dns-query",
    "GeoIpDatabasePath": "Data\\GeoIP",
    "SelfDefenseLevel": 1,
    "EnableSelfDefense": false,
    "ConnectionRefreshIntervalMs": 2000,
    "MaxDynamicFilters": 100
  }
}
```

Blocklists are cached in `%APPDATA%\Heco\Blocklists\`:
```
Blocklists/
├── BuiltIn/          # Bundled lists (copied on first run)
│   ├── DNS_DOMAINS.txt
│   └── DNS_IP.txt
└── Offline/          # User-added offline files
    └── DnsBypassoffline.txt
```

Firewall rules stored in `%APPDATA%\Heco\rules.json`.

---

## Development

### Key NuGet Packages
| Package | Purpose |
|---------|---------|
| `CommunityToolkit.Mvvm` | MVVM source generators |
| `MaterialDesignThemes` | UI theming & controls |
| `MaxMind.Db` | GeoIP MMDB reader |
| `Hardcodet.NotifyIcon.Wpf` | System tray icon |
| `YamlDotNet` | YAML parsing (if used) |

### Debugging Tips
- **WinDivert**: Check `Debug.WriteLine` output in Visual Studio Output window
- **Driver**: Use `DbgView` for kernel debug prints (`KdPrint`)
- **Connection Monitor**: Logs to `Logger` (Serilog → file + debug)
- **Packet capture**: Enable `PacketSniffer` in `Heco.Surveillance` for raw pcap

---

## Acknowledgments & Credits

### MaxMind GeoLite2 Databases
This project uses **GeoLite2 databases** from MaxMind for IP geolocation and ASN lookup.

- **Source**: [https://github.com/P3TERX/GeoLite.mmdb](https://github.com/P3TERX/GeoLite.mmdb)
- **Original**: [MaxMind GeoLite2 Free](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
- **License**: Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)
- **Files used**: `GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb`

> **Special thanks to P3TERX** for maintaining the automated GeoLite2 mirror repository, which makes it easy to obtain updated databases.

### WinDivert
Packet interception powered by **WinDivert** — a user-mode packet capture/divert library for Windows.

- **Author**: Basil (basil00)
- **Repository**: [https://github.com/basil00/Divert](https://github.com/basil00/Divert)
- **License**: LGPL-2.1

### Other Libraries
- **CommunityToolkit.Mvvm** — .NET Foundation (MIT)
- **MaterialDesignThemes** — MaterialDesignInXamlToolkit (MIT)
- **MaxMind.Db** — MaxMind (Apache-2.0)
- **Hardcodet.NotifyIcon.Wpf** — Philipp Sumi (CPOL)
- **YamlDotNet** — Antoine Aubry (MIT)

---

## License

**Heco Firewall** is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

Third-party components retain their original licenses:
- MaxMind GeoLite2 databases: **CC BY-SA 4.0**
- WinDivert: **LGPL-2.1**

---

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style
- Follow existing C# conventions (PascalCase for public, camelCase for private)
- Use `CommunityToolkit.Mvvm` source generators (`[ObservableProperty]`, `[RelayCommand]`)
- Prefer `async/await` over `.Result`/`.Wait()`
- Nullable reference types enabled (`<Nullable>enable</Nullable>`)

---

## Disclaimer

**Heco Firewall is provided "as is" without warranty of any kind.**  
Network filtering operates at kernel level — misconfiguration can block legitimate traffic or cause system instability.  
**Always test in a controlled environment before deploying on production systems.**  
The self-defense driver requires a valid certificate for production use (test-signed driver works with Test Signing mode enabled).

---

## Support

- **Issues**: [GitHub Issues](https://github.com/your-org/Heco_Firewall/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/Heco_Firewall/discussions)

---

*Made for Windows power users who want visibility and control over their network traffic.*