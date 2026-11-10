using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Edr.Core;

public sealed class Wail2BanConfig
{
    public bool Block { get; set; } = true;
    public bool BlockRdpIpv6 { get; set; }
    public int WindowSeconds { get; set; } = 1800;
    public int FailCount { get; set; } = 5;
    public int MaxBanPublicSec { get; set; } = 7_776_000;
    public int MaxBanPrivateSec { get; set; } = 604_800;
    public int MaxTrackedIps { get; set; } = 50_000;
}

public sealed partial class EdrConfig
{
    public const string DefaultFeed = "https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/hash-iocs.txt";

    public List<string> ScanTimes { get; set; } = ["06:00", "18:00"];
    public List<string> QuietProcesses { get; set; } = ["FortniteClient*", "FortniteLauncher*"];
    public string IocFeedUrl { get; set; } = DefaultFeed;
    public string SigmaLookback { get; set; } = "2d";
    public string DefenderMode { get; set; } = "audit";
    public bool AllowProfilesInitialized { get; set; }
    public string InstalledAt { get; set; } = "";
    public Wail2BanConfig Wail2Ban { get; set; } = new();

    public static EdrConfig Load(string path, bool strict = false)
    {
        var node = strict ? JsonFile.ReadStrict(path) : JsonFile.Read(path);
        return node is JsonObject o ? FromJson(o) : new EdrConfig();
    }

    public static EdrConfig FromJson(JsonObject o)
    {
        var c = new EdrConfig();
        if (o["scanTimes"] is JsonArray st) { var v = st.Select(Ps.Str).Where(IsTime).ToList(); if (v.Count > 0) c.ScanTimes = v; }
        if (o["quietProcesses"] is JsonArray qp) c.QuietProcesses = qp.Select(Ps.Str).Where(s => s.Length > 0).ToList();
        if (IsValidFeed(o.Str("iocFeedUrl"))) c.IocFeedUrl = o.Str("iocFeedUrl");
        if (LookbackRx().IsMatch(o.Str("sigmaLookback"))) c.SigmaLookback = o.Str("sigmaLookback");
        if (o.Str("defenderMode") is "audit" or "untouched") c.DefenderMode = o.Str("defenderMode");
        c.AllowProfilesInitialized = o.Truthy("allowProfilesInitialized");
        c.InstalledAt = o.Str("installedAt");
        if (o["wail2ban"] is JsonObject w)
        {
            if (w.ContainsKey("block")) c.Wail2Ban.Block = w.Truthy("block");
            c.Wail2Ban.BlockRdpIpv6 = w.Truthy("blockRdpIpv6");
            c.Wail2Ban.WindowSeconds = Limits.WindowSeconds.Clamp(w.Int("windowSeconds"), c.Wail2Ban.WindowSeconds);
            c.Wail2Ban.FailCount = Limits.FailCount.Clamp(w.Int("failCount"), c.Wail2Ban.FailCount);
            c.Wail2Ban.MaxBanPublicSec = Limits.MaxBanSeconds.Clamp(w.Int("maxBanPublicSec"), c.Wail2Ban.MaxBanPublicSec);
            c.Wail2Ban.MaxBanPrivateSec = Limits.MaxBanSeconds.Clamp(w.Int("maxBanPrivateSec"), c.Wail2Ban.MaxBanPrivateSec);
            c.Wail2Ban.MaxTrackedIps = Positive(w.Int("maxTrackedIps"), c.Wail2Ban.MaxTrackedIps);
        }
        return c;
    }

    public JsonObject ToJson() => new()
    {
        ["scanTimes"] = ScanTimes.ToJsonArray(),
        ["quietProcesses"] = QuietProcesses.ToJsonArray(),
        ["iocFeedUrl"] = IocFeedUrl,
        ["sigmaLookback"] = SigmaLookback,
        ["defenderMode"] = DefenderMode,
        ["allowProfilesInitialized"] = AllowProfilesInitialized,
        ["installedAt"] = InstalledAt,
        ["wail2ban"] = new JsonObject
        {
            ["block"] = Wail2Ban.Block,
            ["blockRdpIpv6"] = Wail2Ban.BlockRdpIpv6,
            ["windowSeconds"] = Wail2Ban.WindowSeconds,
            ["failCount"] = Wail2Ban.FailCount,
            ["maxBanPublicSec"] = Wail2Ban.MaxBanPublicSec,
            ["maxBanPrivateSec"] = Wail2Ban.MaxBanPrivateSec,
            ["maxTrackedIps"] = Wail2Ban.MaxTrackedIps,
        },
    };

    public void Save(string path) => JsonFile.WriteAtomic(path, ToJson());

    public bool Apply(JsonObject req)
    {
        var defenderBefore = DefenderMode;
        if (req["scanTimes"] is JsonArray st) { var v = st.Select(Ps.Str).Where(IsTime).Distinct().ToList(); if (v.Count > 0) ScanTimes = v; }
        if (req["quietProcesses"] is JsonArray qp) QuietProcesses = qp.Select(Ps.Str).Where(IsQuietName).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (LookbackRx().IsMatch(req.Str("sigmaLookback"))) SigmaLookback = req.Str("sigmaLookback");
        if (IsValidFeed(req.Str("iocFeedUrl"))) IocFeedUrl = req.Str("iocFeedUrl");
        if (req.Str("defenderMode") is "audit" or "untouched") DefenderMode = req.Str("defenderMode");
        if (req["wail2ban"] is JsonObject w)
        {
            if (w.ContainsKey("block")) Wail2Ban.Block = w.Truthy("block");
            if (w.ContainsKey("blockRdpIpv6")) Wail2Ban.BlockRdpIpv6 = w.Truthy("blockRdpIpv6");
            Wail2Ban.WindowSeconds = Limits.WindowSeconds.Clamp(w.Int("windowSeconds"), Wail2Ban.WindowSeconds);
            Wail2Ban.FailCount = Limits.FailCount.Clamp(w.Int("failCount"), Wail2Ban.FailCount);
            Wail2Ban.MaxBanPublicSec = Limits.MaxBanSeconds.Clamp(w.Int("maxBanPublicSec"), Wail2Ban.MaxBanPublicSec);
            Wail2Ban.MaxBanPrivateSec = Limits.MaxBanSeconds.Clamp(w.Int("maxBanPrivateSec"), Wail2Ban.MaxBanPrivateSec);
        }
        return DefenderMode != defenderBefore;
    }

    public static string FeedProblem(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return "Enter an address.";
        if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) return "The address must start with https://";
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || u.Host.Length == 0 || url.Any(char.IsWhiteSpace)) return "This is not a valid web address.";
        if (u.Host.Contains("bazaar.abuse.ch", StringComparison.OrdinalIgnoreCase)) return "MalwareBazaar needs an account key; FreeEDR cannot use it.";
        return "";
    }

    public static bool IsValidFeed(string? url) => FeedProblem(url).Length == 0;

    public static bool FeedHasSecret(string? url)
    {
        if (string.IsNullOrEmpty(url) || !Uri.TryCreate(url, UriKind.Absolute, out var u)) return false;
        if (u.Query.Length > 1 || u.UserInfo.Length > 0 || u.Fragment.Length > 1) return true;
        var p = u.AbsolutePath;
        return p.Contains("/token/", StringComparison.OrdinalIgnoreCase) ||
               p.Contains("/key/", StringComparison.OrdinalIgnoreCase) ||
               p.Contains("/auth/", StringComparison.OrdinalIgnoreCase) ||
               p.Split('/').Any(seg => seg.Length >= 24 && seg.All(c => char.IsAsciiLetterOrDigit(c) || c == '_' || c == '-'));
    }

    public static string RedactUrl(string? url)
    {
        if (string.IsNullOrEmpty(url) || !Uri.TryCreate(url, UriKind.Absolute, out var u)) return url ?? "";
        if (!FeedHasSecret(url)) return url;
        var host = u.IsDefaultPort ? u.Host : $"{u.Host}:{u.Port}";
        var segments = u.AbsolutePath.Split('/');
        for (var i = 0; i < segments.Length; i++)
        {
            var seg = segments[i];
            if (seg.Length >= 24 && seg.All(c => char.IsAsciiLetterOrDigit(c) || c == '_' || c == '-'))
                segments[i] = "(hidden)";
            else if (i > 0 && (segments[i - 1].Equals("token", StringComparison.OrdinalIgnoreCase) ||
                               segments[i - 1].Equals("key", StringComparison.OrdinalIgnoreCase) ||
                               segments[i - 1].Equals("auth", StringComparison.OrdinalIgnoreCase)))
                segments[i] = "(hidden)";
        }
        var safePath = string.Join('/', segments);
        return $"{u.Scheme}://{(u.UserInfo.Length > 0 ? "(hidden)@" : "")}{host}{safePath}{(u.Query.Length > 1 || u.Fragment.Length > 1 ? "?(hidden)" : "")}";
    }

    public static JsonObject Redacted(JsonObject req)
    {
        var c = (JsonObject)req.DeepClone();
        if (c.Str("iocFeedUrl") is { Length: > 0 } f) c["iocFeedUrl"] = RedactUrl(f);
        return c;
    }

    public JsonObject UserJson()
    {
        var o = ToJson();
        var user = UserDefaults();
        foreach (var k in o.Select(kv => kv.Key).ToList()) if (!user.ContainsKey(k)) o.Remove(k);
        if (o["wail2ban"] is JsonObject w) w.Remove("maxTrackedIps");
        return o;
    }

    public static JsonObject UserDefaults()
    {
        var d = new EdrConfig().ToJson();
        d.Remove("installedAt");
        d.Remove("allowProfilesInitialized");
        d.Remove("quietProcesses");
        ((JsonObject)d["wail2ban"]!).Remove("maxTrackedIps");
        return d;
    }

    public static JsonObject Changes(JsonObject before, JsonObject now)
    {
        var d = new JsonObject();
        foreach (var (k, v) in now)
        {
            var old = before[k];
            if (v is JsonObject vo && old is JsonObject oo)
            {
                var inner = Changes(oo, vo);
                if (inner.Count > 0) d[k] = inner;
            }
            else if (JsonFile.ToText(v, false) != JsonFile.ToText(old, false)) d[k] = v?.DeepClone();
        }
        return d;
    }

    public static bool IsQuietName(string s)
    {
        var clean = CleanQuietName(s);
        return clean.Length is > 0 and < 128 && clean != "*" && !clean.Contains('\\') && !clean.Contains('/');
    }

    public static string CleanQuietName(string s)
    {
        var t = (s ?? "").Trim();
        if (t.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) t = t[..^4].Trim();
        return t;
    }

    public static bool IsTime(string s) => TimeRx().IsMatch(s) && TimeSpan.TryParse(s, System.Globalization.CultureInfo.InvariantCulture, out var t) && t < TimeSpan.FromDays(1);

    private static int Positive(int v, int fallback) => v > 0 ? v : fallback;

    public readonly record struct Range(int Min, int Max)
    {
        public int Clamp(int v, int fallback) => v <= 0 ? fallback : Math.Clamp(v, Min, Max);
    }

    public static class Limits
    {
        public static readonly Range FailCount = new(2, 1000);
        public static readonly Range WindowSeconds = new(60, 86_400);
        public static readonly Range MaxBanSeconds = new(300, 31_536_000);
    }

    public static (DateTime Prev, DateTime Next) ScanSlots(IEnumerable<string> times, DateTime now)
    {
        var spans = times.Select(t => TimeSpan.TryParse(t, System.Globalization.CultureInfo.InvariantCulture, out var s) ? s : (TimeSpan?)null)
                         .Where(s => s is not null).Select(s => s!.Value).ToList();
        if (spans.Count == 0) spans = [TimeSpan.FromHours(6), TimeSpan.FromHours(18)];
        var all = new[] { -1, 0, 1 }.SelectMany(d => spans.Select(t => now.Date.AddDays(d).Add(t))).Order().ToList();
        return (all.Last(x => x <= now), all.First(x => x > now));
    }

    [GeneratedRegex(@"^\d{1,2}:\d{2}$")]
    private static partial Regex TimeRx();

    [GeneratedRegex(@"^\d{1,3}[dh]$")]
    private static partial Regex LookbackRx();
}
