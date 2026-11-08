namespace Edr.Core;

public interface ISignerLookup
{
    string? SignerOf(string path);
}

public sealed class NoSigners : ISignerLookup
{
    public static readonly NoSigners Instance = new();
    public string? SignerOf(string path) => null;
}

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
        var s = inner.SignerOf(path);
        lock (_cache)
        {
            if (_cache.Count >= max) _cache.Clear();
            _cache[key] = s;
        }
        return s;
    }
}
