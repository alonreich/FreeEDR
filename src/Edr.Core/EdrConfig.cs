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
        var feed = o.Str("iocFeedUrl");
        if (feed.StartsWith("https://", StringComparison.OrdinalIgnoreCase) && !feed.Contains("bazaar.abuse.ch", StringComparison.OrdinalIgnoreCase)) c.IocFeedUrl = feed;
        if (LookbackRx().IsMatch(o.Str("sigmaLookback"))) c.SigmaLookback = o.Str("sigmaLookback");
        if (o.Str("defenderMode") is "audit" or "untouched") c.DefenderMode = o.Str("defenderMode");
        c.AllowProfilesInitialized = o.Truthy("allowProfilesInitialized");
        c.InstalledAt = o.Str("installedAt");
        if (o["wail2ban"] is JsonObject w)
        {
            if (w.ContainsKey("block")) c.Wail2Ban.Block = w.Truthy("block");
            c.Wail2Ban.BlockRdpIpv6 = w.Truthy("blockRdpIpv6");
            c.Wail2Ban.WindowSeconds = Positive(w.Int("windowSeconds"), c.Wail2Ban.WindowSeconds);
            c.Wail2Ban.FailCount = Positive(w.Int("failCount"), c.Wail2Ban.FailCount);
            c.Wail2Ban.MaxBanPublicSec = Positive(w.Int("maxBanPublicSec"), c.Wail2Ban.MaxBanPublicSec);
            c.Wail2Ban.MaxBanPrivateSec = Positive(w.Int("maxBanPrivateSec"), c.Wail2Ban.MaxBanPrivateSec);
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
        if (req["quietProcesses"] is JsonArray qp) QuietProcesses = qp.Select(Ps.Str).Where(s => s.Length is > 0 and < 128 && !s.Contains('\\')).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (LookbackRx().IsMatch(req.Str("sigmaLookback"))) SigmaLookback = req.Str("sigmaLookback");
        var feed = req.Str("iocFeedUrl");
        if (feed.StartsWith("https://", StringComparison.OrdinalIgnoreCase) && Uri.TryCreate(feed, UriKind.Absolute, out _)) IocFeedUrl = feed;
        if (req.Str("defenderMode") is "audit" or "untouched") DefenderMode = req.Str("defenderMode");
        if (req["wail2ban"] is JsonObject w)
        {
            if (w.ContainsKey("block")) Wail2Ban.Block = w.Truthy("block");
            if (w.ContainsKey("blockRdpIpv6")) Wail2Ban.BlockRdpIpv6 = w.Truthy("blockRdpIpv6");
            Wail2Ban.WindowSeconds = Clamp(w.Int("windowSeconds"), 60, 86_400, Wail2Ban.WindowSeconds);
            Wail2Ban.FailCount = Clamp(w.Int("failCount"), 2, 1000, Wail2Ban.FailCount);
            Wail2Ban.MaxBanPublicSec = Clamp(w.Int("maxBanPublicSec"), 300, 31_536_000, Wail2Ban.MaxBanPublicSec);
            Wail2Ban.MaxBanPrivateSec = Clamp(w.Int("maxBanPrivateSec"), 300, 31_536_000, Wail2Ban.MaxBanPrivateSec);
        }
        return DefenderMode != defenderBefore;
    }

    public static bool IsTime(string s) => TimeRx().IsMatch(s) && TimeSpan.TryParse(s, System.Globalization.CultureInfo.InvariantCulture, out var t) && t < TimeSpan.FromDays(1);

    private static int Positive(int v, int fallback) => v > 0 ? v : fallback;
    private static int Clamp(int v, int min, int max, int fallback) => v <= 0 ? fallback : Math.Clamp(v, min, max);

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
