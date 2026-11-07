using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Edr.Core;

/// <summary>Wail2Ban settings: the only part of FreeEDR that really blocks (inbound firewall rules).</summary>
public sealed class Wail2BanConfig
{
    /// <summary>true = ban attackers in Windows Firewall; false = report only.</summary>
    public bool Block { get; set; } = true;
    /// <summary>Block inbound Remote Desktop from every IPv6 address (failures there are not counted). Off by default.</summary>
    public bool BlockRdpIpv6 { get; set; }
    public int WindowSeconds { get; set; } = 1800;
    public int FailCount { get; set; } = 5;
    public int MaxBanPublicSec { get; set; } = 7_776_000;   // 90 days
    public int MaxBanPrivateSec { get; set; } = 604_800;    // 7 days (W7)
    public int MaxTrackedIps { get; set; } = 50_000;
}

/// <summary>
/// config\edr-config.json. FreeEDR only detects and logs; Wail2Ban is the single part that enforces (it can be set to
/// report only). Unknown or obsolete keys (enforce, scanTime, userProfile) are dropped when the file is rewritten.
/// </summary>
public sealed partial class EdrConfig
{
    public const string DefaultFeed = "https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/hash-iocs.txt";

    public List<string> ScanTimes { get; set; } = ["06:00", "18:00"];
    public List<string> QuietProcesses { get; set; } = ["FortniteClient*", "FortniteLauncher*"];
    public string IocFeedUrl { get; set; } = DefaultFeed;
    public string SigmaLookback { get; set; } = "2d";
    /// <summary>"audit" = Defender ASR rules + Controlled folder access in audit mode (reported, never blocked);
    /// "untouched" = FreeEDR does not change Defender's settings and only reads its log.</summary>
    public string DefenderMode { get; set; } = "audit";
    public bool AllowProfilesInitialized { get; set; }
    /// <summary>First install time (ISO 8601): the tray's 7-day learning period starts here.</summary>
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
            // The same ranges as a save (Apply): a value set by hand or imported is used exactly as the dashboard shows it
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

    /// <summary>
    /// Applies a validated "set-config" request (from the elevated helper). Only known keys with valid values change.
    /// Returns true when Defender's mode changed (the caller re-applies the Defender settings).
    /// </summary>
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

    /// <summary>Why a malware hash feed address is refused ("" = usable). One rule for the dashboard, the helper and every
    /// read of the file, so an address that is saved is never dropped later: an absolute https:// URL with a host, not
    /// MalwareBazaar (its list needs an account key and is refused).</summary>
    public static string FeedProblem(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return "Enter an address.";
        if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) return "The address must start with https://";
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || u.Host.Length == 0 || url.Any(char.IsWhiteSpace)) return "This is not a valid web address.";
        if (u.Host.Contains("bazaar.abuse.ch", StringComparison.OrdinalIgnoreCase)) return "MalwareBazaar needs an account key; FreeEDR cannot use it.";
        return "";
    }

    public static bool IsValidFeed(string? url) => FeedProblem(url).Length == 0;

    /// <summary>The feed address carries something private (a key in the query, a user name or password): it is masked in
    /// the dashboard and left out of logs.</summary>
    public static bool FeedHasSecret(string? url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var u) && (u.Query.Length > 1 || u.UserInfo.Length > 0 || u.Fragment.Length > 1);

    /// <summary>The address for logs and messages: user name / password, query and fragment replaced by "(hidden)".</summary>
    public static string RedactUrl(string? url)
    {
        if (string.IsNullOrEmpty(url) || !Uri.TryCreate(url, UriKind.Absolute, out var u)) return url ?? "";
        if (!FeedHasSecret(url)) return url;
        var host = u.IsDefaultPort ? u.Host : $"{u.Host}:{u.Port}";
        return $"{u.Scheme}://{(u.UserInfo.Length > 0 ? "(hidden)@" : "")}{host}{u.AbsolutePath}{(u.Query.Length > 1 || u.Fragment.Length > 1 ? "?(hidden)" : "")}";
    }

    /// <summary>A copy of a settings request with the feed address redacted (for the audit log line).</summary>
    public static JsonObject Redacted(JsonObject req)
    {
        var c = (JsonObject)req.DeepClone();
        if (c.Str("iocFeedUrl") is { Length: > 0 } f) c["iocFeedUrl"] = RedactUrl(f);
        return c;
    }

    /// <summary>The PC settings the Settings page edits, as stored now (the keys of <see cref="UserDefaults"/>): the
    /// baseline a save is compared against, so a value is never changed just because it was shown.</summary>
    public JsonObject UserJson()
    {
        var o = ToJson();
        var user = UserDefaults();
        foreach (var k in o.Select(kv => kv.Key).ToList()) if (!user.ContainsKey(k)) o.Remove(k);
        if (o["wail2ban"] is JsonObject w) w.Remove("maxTrackedIps");
        return o;
    }

    /// <summary>The settings a user can change on the Settings page, at their out-of-the-box values.</summary>
    public static JsonObject UserDefaults()
    {
        var d = new EdrConfig().ToJson();
        d.Remove("installedAt");
        d.Remove("allowProfilesInitialized");
        // Quiet mode only holds back the tray's pop-ups: it is a per-account preference (the PC value is the starting list)
        d.Remove("quietProcesses");
        ((JsonObject)d["wail2ban"]!).Remove("maxTrackedIps");
        return d;
    }

    /// <summary>The values in <paramref name="now"/> that differ from <paramref name="before"/> (nested objects compared per
    /// key, arrays as a whole): what a settings save must send, so it never overwrites a value it did not change.</summary>
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

    /// <summary>A quiet-mode entry: a program name with wildcards, never a folder (1-127 characters, no \ or /).</summary>
    public static bool IsQuietName(string s) => s.Length is > 0 and < 128 && !s.Contains('\\') && !s.Contains('/');

    public static bool IsTime(string s) => TimeRx().IsMatch(s) && TimeSpan.TryParse(s, System.Globalization.CultureInfo.InvariantCulture, out var t) && t < TimeSpan.FromDays(1);

    private static int Positive(int v, int fallback) => v > 0 ? v : fallback;

    /// <summary>One numeric range for every reader and writer of the file (the dashboard, the helper, the engine).</summary>
    public readonly record struct Range(int Min, int Max)
    {
        /// <summary>0 or missing = <paramref name="fallback"/>; anything else into the range.</summary>
        public int Clamp(int v, int fallback) => v <= 0 ? fallback : Math.Clamp(v, Min, Max);
    }

    public static class Limits
    {
        public static readonly Range FailCount = new(2, 1000);
        public static readonly Range WindowSeconds = new(60, 86_400);
        public static readonly Range MaxBanSeconds = new(300, 31_536_000);
    }

    /// <summary>The scheduled scan slot before and after <paramref name="now"/> (Get-ScanSlots).</summary>
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
