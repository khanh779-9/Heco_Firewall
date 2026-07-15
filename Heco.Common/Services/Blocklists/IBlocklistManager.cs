using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Heco.Common.Services.Blocklists;

/// <summary>
///   Manages domain and IP blocklists with Bloom filter support.
///   Supports online auto-update, offline file loading, and multiple input formats.
/// </summary>
public interface IBlocklistManager
{
    /// <summary>All loaded blocklists.</summary>
    IReadOnlyList<Blocklist> Blocklists { get; }

    /// <summary>Total entries across all loaded blocklists.</summary>
    long TotalEntries { get; }

    /// <summary>Event raised when a blocklist is updated.</summary>
    event EventHandler<BlocklistEventArgs> BlocklistUpdated;

    /// <summary>Load all blocklists from disk (both offline and cached online).</summary>
    void LoadAll();

    /// <summary>Check if a domain is blocked.</summary>
    bool IsDomainBlocked(string domain);

    /// <summary>Check if an IP address is blocked.</summary>
    bool IsIpBlocked(string ipAddress);

    /// <summary>Update an online blocklist asynchronously.</summary>
    Task UpdateOnlineBlocklist(string name);

    /// <summary>Update all online blocklists.</summary>
    Task UpdateAllOnlineBlocklists();

    /// <summary>Add an offline blocklist from a file path.</summary>
    Blocklist AddOfflineBlocklist(string filePath, BlocklistContentType contentType);

    /// <summary>Add an online blocklist from a URL.</summary>
    Blocklist AddOnlineBlocklist(string name, string url, BlocklistContentType contentType, int updateIntervalHours = 24);

    /// <summary>Remove a blocklist.</summary>
    bool RemoveBlocklist(string name);

    /// <summary>Update an existing blocklist's configuration.</summary>
    void UpdateBlocklistConfig(string originalName, string newName, BlocklistContentType contentType, string? url, bool isEnabled);

    /// <summary>Get raw entries from a blocklist's local file.</summary>
    string[] GetEntries(string name);

    /// <summary>Overwrite a blocklist's entries and reload the bloom filter.</summary>
    void SetEntries(string name, string[] entries);
}

/// <summary>
///   EventArgs for blocklist update events.
/// </summary>
public sealed class BlocklistEventArgs : EventArgs
{
    public Blocklist Blocklist { get; }
    public BlocklistChangeType ChangeType { get; }

    public BlocklistEventArgs(Blocklist blocklist, BlocklistChangeType changeType)
    {
        Blocklist = blocklist;
        ChangeType = changeType;
    }
}

public enum BlocklistChangeType
{
    Added,
    Updated,
    Removed,
    Error
}

/// <summary>
///   Represents a single blocklist (offline file or online source).
/// </summary>
public sealed class Blocklist
{
    public string Name { get; set; } = string.Empty;
    public BlocklistSource Source { get; set; }
    public BlocklistContentType ContentType { get; set; } = BlocklistContentType.Domain;
    public string? Url { get; set; }
    public string? LocalPath { get; set; }
    public bool IsEnabled { get; set; } = true;
    public long EntryCount { get; set; }
    public DateTime? LastUpdated { get; set; }
    public DateTime? NextUpdate { get; set; }
    public long FalsePositives { get; set; }
    public string? ErrorMessage { get; set; }
}

public enum BlocklistSource
{
    OfflineFile,
    OnlineUrl
}

public enum BlocklistContentType
{
    Domain,
    IP,
    Wildcard,
    Hosts
}

/// <summary>
///   Bloom filter for memory-efficient set membership testing.
///   Uses combined SHA-256 + SHA-512 hashing with false-positive cache.
/// </summary>
public sealed class BloomFilter
{
    private readonly System.Collections.BitArray _bits;
    private readonly int _hashCount;
    private readonly int _bitSize;
    private readonly System.Collections.Concurrent.ConcurrentQueue<string> _fpCache = new();
    private const int FpCacheMax = 1000;

    public BloomFilter(int capacity, double falsePositiveRate = 0.01)
    {
        _bitSize = (int)Math.Ceiling(capacity * Math.Log(falsePositiveRate) / Math.Log(1.0 / Math.Pow(2, Math.Log(2))));
        _hashCount = (int)Math.Round(_bitSize / (double)capacity * Math.Log(2));
        _bits = new System.Collections.BitArray(Math.Max(_bitSize, 1));
    }

    /// <summary>Add an item to the filter.</summary>
    public void Add(string item)
    {
        if (string.IsNullOrEmpty(item)) return;
        item = item.Trim().ToLowerInvariant();
        foreach (var hash in GetHashes(item))
            _bits[Math.Abs((int)(hash % _bitSize))] = true;
    }

    /// <summary>Check if an item might be in the set. False positives are possible.</summary>
    public bool MightContain(string item)
    {
        if (string.IsNullOrEmpty(item)) return false;
        item = item.Trim().ToLowerInvariant();

        // Check false-positive cache (linear scan)
        if (IsInQueue(_fpCache, item))
            return false;

        foreach (var hash in GetHashes(item))
        {
            if (!_bits[Math.Abs((int)(hash % _bitSize))])
                return false;
        }
        return true;
    }

    /// <summary>Record a false positive for tracking.</summary>
    public void RecordFalsePositive(string item)
    {
        _fpCache.Enqueue(item);
        while (_fpCache.Count > FpCacheMax)
            _fpCache.TryDequeue(out _);
    }

    private static bool IsInQueue(System.Collections.Concurrent.ConcurrentQueue<string> queue, string item)
    {
        foreach (var existing in queue)
        {
            if (existing == item)
                return true;
        }
        return false;
    }

    private long[] GetHashes(string item)
    {
        // Combined SHA-256 + SHA-512 to produce multiple hash values
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        using var sha512 = System.Security.Cryptography.SHA512.Create();

        var bytes = System.Text.Encoding.UTF8.GetBytes(item);
        var hash256 = sha256.ComputeHash(bytes);
        var hash512 = sha512.ComputeHash(bytes);

        var hashes = new long[_hashCount];
        for (int i = 0; i < _hashCount; i++)
        {
            // Combine bytes from both hash functions
            long h = BitConverter.ToInt64(hash256, i % (hash256.Length - 7)) ^
                     BitConverter.ToInt64(hash512, i % (hash512.Length - 7));
            hashes[i] = Math.Abs(h);
        }
        return hashes;
    }
}
