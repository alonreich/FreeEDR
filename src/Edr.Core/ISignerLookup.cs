namespace Edr.Core;

/// <summary>Publisher of a validly signed file (e.g. "Google LLC"), or null.</summary>
public interface ISignerLookup
{
    string? SignerOf(string path);
}

/// <summary>For tests and fixtures without signed files: every lookup is "not signed".</summary>
public sealed class NoSigners : ISignerLookup
{
    public static readonly NoSigners Instance = new();
    public string? SignerOf(string path) => null;
}

/// <summary>Caches lookups per path and last-write time, like Get-TraySigner (signatures are checked again by the
/// engine). Thread-safe (the tray builds its model on a worker) and bounded; stamped = false keys on the path only
/// (the per-build cache of <see cref="ModelBuilder"/>).</summary>
public sealed class CachedSigners(ISignerLookup inner, int max = 5000, bool stamped = true) : ISignerLookup
{
    private readonly Dictionary<string, string?> _cache = new(StringComparer.OrdinalIgnoreCase);

    public string? SignerOf(string path)
    {
        if (string.IsNullOrEmpty(path)) return null;
        DateTime stamp;
        try { stamp = stamped ? File.GetLastWriteTimeUtc(path) : DateTime.MinValue; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { stamp = DateTime.MinValue; }
        var key = $"{path}|{stamp.Ticks}";
        lock (_cache)
            if (_cache.TryGetValue(key, out var hit)) return hit;
        var s = inner.SignerOf(path);   // slow (WinVerifyTrust): outside the lock
        lock (_cache)
        {
            if (_cache.Count >= max) _cache.Clear();
            _cache[key] = s;
        }
        return s;
    }
}
