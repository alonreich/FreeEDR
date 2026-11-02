using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Edr.Core;

/// <summary>
/// The PowerShell 5.1 semantics EDR-Tray.ps1 relies on, so the port decides exactly the same:
/// [string] casts, truthiness, case-insensitive -eq / -like / -match, and Sort-Object string order.
/// </summary>
public static class Ps
{
    /// <summary>String order of Sort-Object and -gt/-lt: current culture, case-insensitive.</summary>
    public static readonly StringComparer Order = StringComparer.Create(CultureInfo.CurrentCulture, ignoreCase: true);

    /// <summary>[string]$value for values read by ConvertFrom-Json.</summary>
    public static string Str(JsonNode? node) => node switch
    {
        null => "",
        JsonValue v when v.TryGetValue(out string? s) => s ?? "",
        JsonValue v when v.TryGetValue(out bool b) => b ? "True" : "False",
        JsonValue v => v.ToJsonString(),   // numbers: their JSON text, as JavaScriptSerializer keeps them
        JsonArray a => string.Join(" ", a.Select(Str)),   // $OFS
        _ => "",
    };

    /// <summary>PowerShell truthiness: $null, "", 0, $false and empty arrays are false; a 1-item array is its item.</summary>
    public static bool Truthy(JsonNode? node) => node switch
    {
        null => false,
        JsonValue v when v.TryGetValue(out string? s) => !string.IsNullOrEmpty(s),
        JsonValue v when v.TryGetValue(out bool b) => b,
        JsonValue v when v.TryGetValue(out double d) => d != 0,
        JsonValue => true,
        JsonArray a => a.Count > 1 || (a.Count == 1 && Truthy(a[0])),
        _ => true,
    };

    public static bool Eq(string? a, string? b) => string.Equals(a ?? "", b ?? "", StringComparison.OrdinalIgnoreCase);

    /// <summary>$Text -like $Pattern: wildcards * ? [set], backtick escapes, case-insensitive, whole string.</summary>
    public static bool Like(string? text, string? pattern) => LikeRegex(pattern ?? "").IsMatch(text ?? "");

    /// <summary>$Text -match $Pattern (case-insensitive .NET regex).</summary>
    public static bool Match(string? text, string pattern) => Rx(pattern).IsMatch(text ?? "");

    public static Regex Rx(string pattern) => RegexCache.GetOrAdd(pattern, p => new Regex(p, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));

    /// <summary>[WildcardPattern]::Escape: the inverse of <see cref="Like"/> for literal paths.</summary>
    public static string WildcardEscape(string path)
    {
        var sb = new StringBuilder(path.Length);
        foreach (var c in path)
        {
            if (c is '*' or '?' or '[' or ']' or '`') sb.Append('`');
            sb.Append(c);
        }
        return sb.ToString();
    }

    /// <summary>[datetime]$Text (invariant culture), or null.</summary>
    public static DateTime? ToDate(string? text) =>
        !string.IsNullOrWhiteSpace(text) && DateTime.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.None, out var d) ? d : null;

    /// <summary>[int]$value: banker's rounding of numbers, parse of strings, 0 for nothing.</summary>
    public static int ToInt(JsonNode? node)
    {
        var s = Str(node);
        return double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? (int)Math.Round(d, MidpointRounding.ToEven) : 0;
    }

    /// <summary>Split-Path -Leaf of a path-like string ("" for nothing).</summary>
    public static string Leaf(string? path)
    {
        if (string.IsNullOrEmpty(path)) return "";
        var p = path.TrimEnd('\\', '/');
        var i = p.LastIndexOfAny(['\\', '/']);
        return i < 0 ? p : p[(i + 1)..];
    }

    private static readonly ConcurrentDictionary<string, Regex> RegexCache = new();
    private static readonly ConcurrentDictionary<string, Regex> LikeCache = new();

    private static Regex LikeRegex(string pattern) => LikeCache.GetOrAdd(pattern, p =>
    {
        var sb = new StringBuilder("^");
        for (var i = 0; i < p.Length; i++)
        {
            var c = p[i];
            switch (c)
            {
                case '`' when i + 1 < p.Length: sb.Append(Regex.Escape(p[++i].ToString())); break;
                case '*': sb.Append("(?s:.*)"); break;
                case '?': sb.Append("(?s:.)"); break;
                case '[':
                    var end = p.IndexOf(']', i + 1);
                    if (end < 0) { sb.Append(@"\["); break; }
                    var set = p[(i + 1)..end];
                    sb.Append('[').Append(set.Replace(@"\", @"\\").Replace("^", @"\^").Replace("[", @"\[")).Append(']');
                    i = end;
                    break;
                default: sb.Append(Regex.Escape(c.ToString())); break;
            }
        }
        return new Regex(sb.Append('$').ToString(), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    });
}
