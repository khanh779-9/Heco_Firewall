using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Heco.Common.Services.Blocklists;
using Heco.Common.Services.Diagnostics;

namespace Heco.Common.Services.Blocklists;

/// <summary>
///   Manages domain and IP blocklists with Bloom filter support.
///   Supports online auto-update from URLs (HaGeZi, threat feeds),
///   offline file loading, and multiple input formats.
/// </summary>
public sealed class BlocklistManager : IBlocklistManager, IDisposable
{
    private readonly List<Blocklist> _blocklists = new();
    private readonly Dictionary<string, BloomFilter> _domainFilters = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, BloomFilter> _ipFilters = new(StringComparer.OrdinalIgnoreCase);
    private readonly HttpClient _httpClient;
    private readonly object _sync = new();

    public IReadOnlyList<Blocklist> Blocklists => _blocklists.AsReadOnly();
    public long TotalEntries => _blocklists.Sum(b => b.EntryCount);

    public event EventHandler<BlocklistEventArgs>? BlocklistUpdated;

    public BlocklistManager()
    {
        _httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(30)
        };
        _httpClient.DefaultRequestHeaders.Add("User-Agent", "Heco-Firewall/1.0");
    }

    public void LoadAll()
    {
        lock (_sync)
        {
            SeedFromBundle();

            var appData = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Heco");
            var blocklistsDir = Path.Combine(appData, "Blocklists");

            if (Directory.Exists(blocklistsDir))
            {
                var txtFiles = Directory.GetFiles(blocklistsDir, "*.txt", SearchOption.AllDirectories);
                foreach (var file in txtFiles)
                {
                    var name = Path.GetFileNameWithoutExtension(file);
                    if (_blocklists.Any(b => string.Equals(b.Name, name, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    var contentType = BlocklistContentType.Domain;
                    if (name.IndexOf("ip", StringComparison.OrdinalIgnoreCase) >= 0)
                        contentType = BlocklistContentType.IP;
                    else if (file.IndexOf("hosts", StringComparison.OrdinalIgnoreCase) >= 0)
                        contentType = BlocklistContentType.Hosts;

                    var blocklist = new Blocklist
                    {
                        Name = name,
                        Source = BlocklistSource.OfflineFile,
                        ContentType = contentType,
                        LocalPath = file,
                        IsEnabled = true
                    };
                    _blocklists.Add(blocklist);
                }
            }

            foreach (var blocklist in _blocklists.ToList())
            {
                if (blocklist.Source == BlocklistSource.OfflineFile && blocklist.LocalPath is not null)
                {
                    LoadFileBlocklist(blocklist);
                }
            }
        }
        Logger.Info($"Loaded {_blocklists.Count} blocklists, {TotalEntries} total entries");
    }

    /// <summary>
    ///   Seeds blocklists from the app's bundled Data directory into
    ///   %APPDATA%\Heco\Blocklists\ on first run.
    /// </summary>
    private void SeedFromBundle()
    {
        try
        {
            var appData = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Heco", "Blocklists");
            var builtInDir = Path.Combine(appData, "BuiltIn");
            var offlineDir = Path.Combine(appData, "Offline");

            // Copy from app install directory
            var bundleDir = Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                "Data", "Blocklists");

            if (!Directory.Exists(bundleDir)) return;

            CopyDirectoryContents(Path.Combine(bundleDir, "BuiltIn"), builtInDir);
            CopyDirectoryContents(Path.Combine(bundleDir, "Offline"), offlineDir);

            Logger.Info("Seeded bundled blocklists into APPDATA");
        }
        catch (Exception ex)
        {
            Logger.Warn($"Failed to seed bundled blocklists: {ex.Message}");
        }
    }

    private static void CopyDirectoryContents(string sourceDir, string destDir)
    {
        if (!Directory.Exists(sourceDir)) return;
        Directory.CreateDirectory(destDir);
        foreach (var file in Directory.GetFiles(sourceDir))
        {
            var dest = Path.Combine(destDir, Path.GetFileName(file));
            if (!File.Exists(dest))
                File.Copy(file, dest);
        }
    }

    public bool IsDomainBlocked(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return false;

        domain = domain.Trim().ToLowerInvariant();

        lock (_sync)
        {
            foreach (var kvp in _domainFilters)
            {
                if (kvp.Value.MightContain(domain))
                    return true;

                // Check parent domains (e.g., sub.example.com → example.com)
                var parts = domain.Split('.');
                for (int i = 1; i < parts.Length - 1; i++)
                {
                    var parent = string.Join(".", parts, i, parts.Length - i);
                    if (kvp.Value.MightContain(parent))
                        return true;
                }
            }
        }

        return false;
    }

    public bool IsIpBlocked(string ipAddress)
    {
        if (string.IsNullOrWhiteSpace(ipAddress)) return false;

        ipAddress = ipAddress.Trim();

        // Normalize: strip port if present
        if (ipAddress.Contains(':'))
            ipAddress = ipAddress.Split(':')[0];

        lock (_sync)
        {
            foreach (var kvp in _ipFilters)
            {
                if (kvp.Value.MightContain(ipAddress))
                    return true;
            }
        }

        return false;
    }

    public async Task UpdateOnlineBlocklist(string name)
    {
        Blocklist? blocklist;
        lock (_sync)
        {
            blocklist = _blocklists.FirstOrDefault(b =>
                string.Equals(b.Name, name, StringComparison.OrdinalIgnoreCase) &&
                b.Source == BlocklistSource.OnlineUrl);
        }

        if (blocklist is null || blocklist.Url is null) return;

        try
        {
            Logger.Info($"Updating online blocklist: {name}");
            var response = await _httpClient.GetStringAsync(blocklist.Url);
            var lines = response.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

            var entries = ParseLines(lines, blocklist.ContentType);
            var filter = BuildFilter(entries);

            lock (_sync)
            {
                blocklist.EntryCount = entries.Count;
                blocklist.LastUpdated = DateTime.UtcNow;
                blocklist.ErrorMessage = null;

                if (blocklist.ContentType == BlocklistContentType.Domain)
                    _domainFilters[name] = filter;
                else
                    _ipFilters[name] = filter;

                // Update local cache file
                if (blocklist.LocalPath is not null)
                {
                    var dir = Path.GetDirectoryName(blocklist.LocalPath);
                    if (dir is not null) Directory.CreateDirectory(dir);
                    File.WriteAllText(blocklist.LocalPath, response);
                }
            }

            BlocklistUpdated?.Invoke(this, new BlocklistEventArgs(blocklist, BlocklistChangeType.Updated));
            Logger.Info($"Updated blocklist '{name}': {entries.Count} entries");
        }
        catch (Exception ex)
        {
            blocklist.ErrorMessage = ex.Message;
            BlocklistUpdated?.Invoke(this, new BlocklistEventArgs(blocklist, BlocklistChangeType.Error));
            Logger.Error($"Failed to update blocklist '{name}'", ex);
        }
    }

    public async Task UpdateAllOnlineBlocklists()
    {
        var online = _blocklists
            .Where(b => b.Source == BlocklistSource.OnlineUrl && b.IsEnabled)
            .ToList();

        var tasks = online.Select(b => UpdateOnlineBlocklist(b.Name));
        await Task.WhenAll(tasks);
    }

    public Blocklist AddOnlineBlocklist(string name, string url, BlocklistContentType contentType, int updateIntervalHours = 24)
    {
        var localPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Heco", "Blocklists", $"{name}.txt");

        var blocklist = new Blocklist
        {
            Name = name,
            Source = BlocklistSource.OnlineUrl,
            ContentType = contentType,
            Url = url,
            LocalPath = localPath,
            IsEnabled = true,
            NextUpdate = DateTime.UtcNow.AddHours(updateIntervalHours)
        };

        lock (_sync) _blocklists.Add(blocklist);

        BlocklistUpdated?.Invoke(this, new BlocklistEventArgs(blocklist, BlocklistChangeType.Added));
        Logger.Info($"Added online blocklist '{name}' — {url}");
        return blocklist;
    }

    public Blocklist AddOfflineBlocklist(string filePath, BlocklistContentType contentType)
    {
        var name = Path.GetFileNameWithoutExtension(filePath);

        var blocklist = new Blocklist
        {
            Name = name,
            Source = BlocklistSource.OfflineFile,
            ContentType = contentType,
            LocalPath = filePath,
            IsEnabled = true
        };

        lock (_sync)
        {
            _blocklists.Add(blocklist);
            LoadFileBlocklist(blocklist);
        }

        BlocklistUpdated?.Invoke(this, new BlocklistEventArgs(blocklist, BlocklistChangeType.Added));
        return blocklist;
    }

    /// <summary>
    ///   Update an existing blocklist's configuration (Name, ContentType, Url, IsEnabled).
    ///   If the name changed, the bloom filter key and cache file are also updated.
    /// </summary>
    public void UpdateBlocklistConfig(string originalName, string newName, BlocklistContentType contentType, string? url, bool isEnabled)
    {
        lock (_sync)
        {
            var blocklist = _blocklists.FirstOrDefault(b =>
                string.Equals(b.Name, originalName, StringComparison.OrdinalIgnoreCase));
            if (blocklist is null) return;

            var nameChanged = !string.Equals(originalName, newName, StringComparison.OrdinalIgnoreCase);

            // Transfer bloom filter to new name key
            if (nameChanged)
            {
                if (_domainFilters.TryGetValue(originalName, out var df))
                {
                    _domainFilters.Remove(originalName);
                    _domainFilters[newName] = df;
                }
                if (_ipFilters.TryGetValue(originalName, out var ipf))
                {
                    _ipFilters.Remove(originalName);
                    _ipFilters[newName] = ipf;
                }
            }

            var previousContentType = blocklist.ContentType;
            var previousUrl = blocklist.Url;

            blocklist.Name = newName;
            blocklist.ContentType = contentType;
            blocklist.Url = url;
            blocklist.IsEnabled = isEnabled;

            // Reload offline file if content type changed (re-parsing required)
            if (previousContentType != contentType && blocklist.Source == BlocklistSource.OfflineFile)
            {
                LoadFileBlocklist(blocklist);
            }

            // Reload from URL if content type or URL changed
            if (blocklist.Source == BlocklistSource.OnlineUrl &&
                (previousContentType != contentType || previousUrl != url))
            {
                blocklist.LastUpdated = null;
                blocklist.EntryCount = 0;
                // Clear the existing filter so next update fetches fresh data
                _domainFilters.Remove(newName);
                _ipFilters.Remove(newName);
            }

            // Rename cached file if name changed
            if (nameChanged && blocklist.LocalPath is not null)
            {
                var dir = Path.GetDirectoryName(blocklist.LocalPath);
                if (dir is not null)
                {
                    var newPath = Path.Combine(dir, $"{newName}.txt");
                    if (File.Exists(blocklist.LocalPath) && !string.Equals(blocklist.LocalPath, newPath, StringComparison.OrdinalIgnoreCase))
                    {
                        try { File.Move(blocklist.LocalPath, newPath); }
                        catch { }
                    }
                    blocklist.LocalPath = newPath;
                }
            }
        }

        BlocklistUpdated?.Invoke(this, new BlocklistEventArgs(
            _blocklists.FirstOrDefault(b => string.Equals(b.Name, newName, StringComparison.OrdinalIgnoreCase))!,
            BlocklistChangeType.Updated));
    }

    public bool RemoveBlocklist(string name)
    {
        Blocklist? blocklist;
        lock (_sync)
        {
            blocklist = _blocklists.FirstOrDefault(b =>
                string.Equals(b.Name, name, StringComparison.OrdinalIgnoreCase));

            if (blocklist is null) return false;

            _blocklists.Remove(blocklist);
            _domainFilters.Remove(name);
            _ipFilters.Remove(name);
        }

        BlocklistUpdated?.Invoke(this, new BlocklistEventArgs(blocklist, BlocklistChangeType.Removed));
        return true;
    }

    // ── Internal ─────────────────────────────────────────────────

    private void LoadFileBlocklist(Blocklist blocklist)
    {
        if (blocklist.LocalPath is null || !File.Exists(blocklist.LocalPath)) return;

        try
        {
            var lines = File.ReadAllLines(blocklist.LocalPath);
            var entries = ParseLines(lines, blocklist.ContentType);
            var filter = BuildFilter(entries);

            blocklist.EntryCount = entries.Count;
            blocklist.ErrorMessage = null;

            if (blocklist.ContentType is BlocklistContentType.Domain or BlocklistContentType.Wildcard)
                _domainFilters[blocklist.Name] = filter;
            else
                _ipFilters[blocklist.Name] = filter;
        }
        catch (Exception ex)
        {
            blocklist.ErrorMessage = ex.Message;
            Logger.Error($"Failed to load blocklist '{blocklist.Name}'", ex);
        }
    }

    private static List<string> ParseLines(IEnumerable<string> lines, BlocklistContentType contentType)
    {
        var entries = new List<string>();

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();

            // Skip comments and empty
            if (string.IsNullOrEmpty(line) || line.StartsWith("#") || line.StartsWith("!"))
                continue;

            switch (contentType)
            {
                case BlocklistContentType.Domain:
                    entries.Add(line.ToLowerInvariant());
                    break;

                case BlocklistContentType.IP:
                    if (IPAddress.TryParse(line, out _))
                        entries.Add(line);
                    break;

                case BlocklistContentType.Wildcard:
                    // Format: "*.example.com" → store as wildcard pattern
                    entries.Add(line.ToLowerInvariant());
                    break;

                case BlocklistContentType.Hosts:
                    // Format: "0.0.0.0 example.com" or "127.0.0.1 example.com"
                    var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1"))
                    {
                        var host = parts[1].Trim().ToLowerInvariant();
                        if (!string.IsNullOrEmpty(host) && host != "localhost")
                            entries.Add(host);
                    }
                    break;
            }
        }

        return entries;
    }

    private static BloomFilter BuildFilter(List<string> entries)
    {
        var filter = new BloomFilter(Math.Max(entries.Count * 2, 10000));
        foreach (var entry in entries)
            filter.Add(entry);
        return filter;
    }

    /// <summary>Get raw entries from a blocklist's local file.</summary>
    public string[] GetEntries(string name)
    {
        lock (_sync)
        {
            var blocklist = _blocklists.FirstOrDefault(b =>
                string.Equals(b.Name, name, StringComparison.OrdinalIgnoreCase));
            if (blocklist?.LocalPath is null || !File.Exists(blocklist.LocalPath))
                return [];

            return File.ReadAllLines(blocklist.LocalPath)
                .Where(l => !string.IsNullOrWhiteSpace(l))
                .ToArray();
        }
    }

    /// <summary>Overwrite a blocklist's entries and reload the bloom filter.</summary>
    public void SetEntries(string name, string[] entries)
    {
        lock (_sync)
        {
            var blocklist = _blocklists.FirstOrDefault(b =>
                string.Equals(b.Name, name, StringComparison.OrdinalIgnoreCase));
            if (blocklist?.LocalPath is null) return;

            var dir = Path.GetDirectoryName(blocklist.LocalPath);
            if (dir is not null) Directory.CreateDirectory(dir);
            File.WriteAllLines(blocklist.LocalPath, entries);

            LoadFileBlocklist(blocklist);
        }

        BlocklistUpdated?.Invoke(this, new BlocklistEventArgs(
            _blocklists.FirstOrDefault(b => string.Equals(b.Name, name, StringComparison.OrdinalIgnoreCase))!,
            BlocklistChangeType.Updated));
    }

    public void Dispose()
    {
        _httpClient?.Dispose();
    }
}
