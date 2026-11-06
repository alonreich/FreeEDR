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

/// <summary>Caches lookups per path, like Get-TraySigner (signatures are checked again by the engine).</summary>
public sealed class CachedSigners(ISignerLookup inner) : ISignerLookup
{
    private readonly Dictionary<string, string?> _cache = new(StringComparer.OrdinalIgnoreCase);

    public string? SignerOf(string path)
    {
        if (string.IsNullOrEmpty(path)) return null;
        if (!_cache.TryGetValue(path, out var s)) _cache[path] = s = inner.SignerOf(path);
        return s;
    }
}
