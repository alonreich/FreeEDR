using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Xunit;

namespace Edr.Core.Tests;

public class SettingsTests
{

    [Fact]
    public void Changes_hold_only_the_values_that_differ()
    {
        var before = new EdrConfig().ToJson();
        var now = new EdrConfig().ToJson();
        ((JsonObject)now["wail2ban"]!)["failCount"] = 7;
        now["scanTimes"] = new JsonArray("07:00");
        var d = EdrConfig.Changes(before, now);
        Assert.Equal(2, d.Count);
        Assert.Equal(7, ((JsonObject)d["wail2ban"]!).Int("failCount"));
        Assert.Single((JsonObject)d["wail2ban"]!);
        Assert.Empty(EdrConfig.Changes(before, new EdrConfig().ToJson()));
    }

    [Fact]
    public void A_partial_save_keeps_a_value_changed_elsewhere()
    {
        var cfg = new EdrConfig();
        cfg.Apply(new JsonObject { ["wail2ban"] = new JsonObject { ["block"] = false } });
        cfg.Apply(new JsonObject { ["wail2ban"] = new JsonObject { ["failCount"] = 9 } });
        Assert.False(cfg.Wail2Ban.Block);
        Assert.Equal(9, cfg.Wail2Ban.FailCount);
        Assert.Equal(1800, cfg.Wail2Ban.WindowSeconds);
    }

    [Theory]
    [InlineData("https://example.org/hashes.txt", true)]
    [InlineData("http://example.org/hashes.txt", false)]
    [InlineData("https://bazaar.abuse.ch/export/txt/sha256/recent/", false)]
    [InlineData("https://exa mple.org/x", false)]
    [InlineData("", false)]
    public void Feed_rule_is_the_same_for_saving_and_reading(string url, bool ok)
    {
        Assert.Equal(ok, EdrConfig.IsValidFeed(url));
        var cfg = new EdrConfig();
        cfg.Apply(new JsonObject { ["iocFeedUrl"] = url });
        var reread = EdrConfig.FromJson(cfg.ToJson());
        Assert.Equal(cfg.IocFeedUrl, reread.IocFeedUrl);
        Assert.Equal(ok ? url : EdrConfig.DefaultFeed, reread.IocFeedUrl);
    }

    [Fact]
    public void Quiet_names_with_spaces_are_kept()
    {
        var cfg = new EdrConfig();
        cfg.Apply(new JsonObject { ["quietProcesses"] = new JsonArray("My Game*", "obs64*") });
        Assert.Equal(["My Game*", "obs64*"], cfg.QuietProcesses);
    }

    [Fact]
    public void A_security_log_sigma_hit_is_covered_by_the_trusted_app_allow()
    {
        const string details = "Cmdline: \u00A6 Proc: C:\\Windows\\System32\\wpbbin.exe \u00A6 PID: 1836 \u00A6 User: - \u00A6 ParentProcessName: C:\\Windows\\System32\\smss.exe \u00A6 ProcessId: 1336";
        var sp = SigmaProcess.FromDetails(details);
        Assert.Equal(@"C:\Windows\System32\wpbbin.exe", sp.Image);
        Assert.Equal(@"C:\Windows\System32\smss.exe", sp.Parent);
        var allow = new JsonObject { ["title"] = "UEFI Persistence Via Wpbbin - ProcessCreation", ["parent"] = @"*\smss.exe", ["parentSigner"] = "" };
        Assert.NotNull(Detection.SigmaExcluded([allow], "UEFI Persistence Via Wpbbin - ProcessCreation", sp.Parent, new NoSigners()));
    }

    private sealed class NoSigners : ISignerLookup { public string? SignerOf(string path) => null; }

    private static JsonObject Exclusions(params (string List, JsonObject Entry)[] items)
    {
        var o = new JsonObject();
        foreach (var l in SettingsBackup.Lists) o[l] = new JsonArray();
        foreach (var (l, e) in items) ((JsonArray)o[l]!).Add((JsonNode)e.DeepClone());
        return o;
    }

    [Fact]
    public void A_backup_imports_its_settings_and_missing_allows_as_valid_requests()
    {
        var source = new EdrConfig { SigmaLookback = "3d" };
        source.Wail2Ban.FailCount = 8;
        var allow = new JsonObject { ["id"] = "a1", ["added"] = "2026-11-01 10:00", ["rule"] = "*", ["image"] = @"C:\Tools\mytool.exe" };
        var broad = new JsonObject { ["id"] = "a2", ["rule"] = "*", ["image"] = "*" };
        var backup = SettingsBackup.Create(source, Exclusions(("realtime", allow), ("realtime", broad)));
        Assert.Equal(SettingsBackup.Format, backup.Str("format"));
        Assert.DoesNotContain("installedAt", ((JsonObject)backup["settings"]!).Select(kv => kv.Key));

        var plan = SettingsBackup.PlanImport(backup, new EdrConfig(), Exclusions());
        Assert.Equal("", plan.Problem);
        Assert.Equal("3d", plan.ConfigChanges.Str("sigmaLookback"));
        Assert.Equal(8, ((JsonObject)plan.ConfigChanges["wail2ban"]!).Int("failCount"));
        var op = Assert.Single(plan.Ops);
        Assert.True(PatternRules.IsValidOp(op));
        Assert.False(op.ContainsKey("id"));
        Assert.Equal(1, plan.Refused);

        var again = SettingsBackup.PlanImport(backup, source, Exclusions(("realtime", allow)));
        Assert.True(again.Empty);
        Assert.Equal(1, again.AlreadyThere);
    }

    [Fact]
    public void A_foreign_file_is_not_imported()
    {
        Assert.NotEqual("", SettingsBackup.PlanImport(new JsonObject { ["action"] = "pause" }, new EdrConfig(), null).Problem);
        Assert.NotEqual("", SettingsBackup.PlanImport(new JsonObject { ["format"] = SettingsBackup.Format, ["version"] = 99 }, new EdrConfig(), null).Problem);
    }

    [Fact]
    public void Imported_allows_are_split_into_requests_each_shown_in_full()
    {
        var ops = Enumerable.Range(0, 45).Select(i => new JsonObject { ["action"] = "exclude", ["blade"] = "yara", ["image"] = $@"C:\Tools\tool{i}.exe" }).ToList();
        var batches = SettingsBackup.Batches(ops);
        Assert.Equal(3, batches.Count);
        Assert.All(batches, b => Assert.True(RequestSummary.Build(b).Complete));
        Assert.All(batches, b => Assert.True(PatternRules.IsValidCommand(b, out _)));
        Assert.Equal(45, batches.Sum(b => b.Str("action") == "batch" ? ((JsonArray)b["ops"]!).Count : 1));
    }

    private static string Repo()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
            if (File.Exists(Path.Combine(d.FullName, "project_structure.txt"))) return d.FullName;
        throw new DirectoryNotFoundException("repository root");
    }

    private static Dictionary<string, string> ThemeColors(string variant)
    {
        var x = XDocument.Load(Path.Combine(Repo(), "src", "Edr.Tray", "Theme.axaml"));
        XNamespace xk = "http://schemas.microsoft.com/winfx/2006/xaml";
        var dict = x.Descendants().First(e => e.Name.LocalName == "ResourceDictionary" && (string?)e.Attribute(xk + "Key") == variant);
        var map = new Dictionary<string, string>();
        foreach (var e in dict.Elements())
        {
            var key = (string?)e.Attribute(xk + "Key");
            if (key is null) continue;
            if (e.Name.LocalName == "Color") map[key] = e.Value.Trim();
            else if (e.Name.LocalName == "SolidColorBrush") map[key] = (string)e.Attribute("Color")!;
            else map[key] = "gradient";
        }
        return map;
    }

    [Fact]
    public void Dark_and_light_themes_define_the_same_colors()
    {
        var dark = ThemeColors("Dark");
        var light = ThemeColors("Light");
        Assert.Equal(dark.Keys.Order(), light.Keys.Order());
        var styles = File.ReadAllText(Path.Combine(Repo(), "src", "Edr.Tray", "Theme.axaml"));
        Assert.DoesNotContain("{StaticResource", styles[styles.IndexOf("</Styles.Resources>", StringComparison.Ordinal)..]);
        Assert.DoesNotMatch(new Regex(@"Value=""#[0-9A-Fa-f]{6}"""), styles);
    }

    [Fact]
    public void Code_palette_matches_both_themes()
    {
        var ui = File.ReadAllText(Path.Combine(Repo(), "src", "Edr.Tray", "Views", "Ui.cs"));
        var dark = ThemeColors("Dark");
        var light = ThemeColors("Light");
        var n = 0;
        foreach (Match m in Regex.Matches(ui, @"SolidColorBrush (\w+) = Themed\(""(#\w{6})"", ""(#\w{6})""\)"))
        {
            var key = m.Groups[1].Value + "Brush";
            if (!dark.ContainsKey(key)) continue;
            Assert.Equal(dark[key], m.Groups[2].Value, ignoreCase: true);
            Assert.Equal(light[key], m.Groups[3].Value, ignoreCase: true);
            n++;
        }
        Assert.True(n >= 10, $"only {n} palette colors matched a theme brush");
    }

    [Theory]
    [InlineData("Dark")]
    [InlineData("Light")]
    public void Text_colors_reach_readable_contrast(string variant)
    {
        var c = ThemeColors(variant);
        foreach (var (fg, bg, min) in new[]
                 {
                     ("TextBrush", "BgBrush", 7.0), ("TextBrush", "SurfaceBrush", 7.0), ("Text2Brush", "SurfaceBrush", 4.5),
                     ("MutedBrush", "SurfaceBrush", 4.5), ("MutedBrush", "SurfaceHiBrush", 4.5), ("ErrorTextBrush", "SurfaceBrush", 4.5), ("DangerBrush", "SurfaceBrush", 3.0),
                     ("WarnBrush", "SurfaceBrush", 4.5), ("AccentBrush", "SurfaceBrush", 3.0), ("PrimaryFg", "PrimaryBg", 4.5),
                     ("OkBtnFg", "OkBtnBg", 4.5), ("DangerBtnFg", "DangerBtnBg", 4.5), ("NavActiveFg", "NavActiveBg", 4.5),
                 })
            Assert.True(Contrast(c[fg], c[bg]) >= min, $"{variant}: {fg} on {bg} = {Contrast(c[fg], c[bg]):0.00}:1 (needs {min})");
    }

    private static double Contrast(string a, string b)
    {
        static double L(string hex)
        {
            double Ch(int i) { var v = int.Parse(hex.Substring(1 + i * 2, 2), NumberStyles.HexNumber) / 255.0; return v <= 0.03928 ? v / 12.92 : Math.Pow((v + 0.055) / 1.055, 2.4); }
            return 0.2126 * Ch(0) + 0.7152 * Ch(1) + 0.0722 * Ch(2);
        }
        var (x, y) = (L(a), L(b));
        return (Math.Max(x, y) + 0.05) / (Math.Min(x, y) + 0.05);
    }

    [Fact]
    public void Numbers_in_the_file_are_used_in_the_ranges_a_save_allows()
    {
        var o = new EdrConfig().ToJson();
        var w = (JsonObject)o["wail2ban"]!;
        w["failCount"] = 1; w["windowSeconds"] = 10; w["maxBanPublicSec"] = 60; w["maxBanPrivateSec"] = 999_999_999;
        var c = EdrConfig.FromJson(o);
        Assert.Equal(EdrConfig.Limits.FailCount.Min, c.Wail2Ban.FailCount);
        Assert.Equal(EdrConfig.Limits.WindowSeconds.Min, c.Wail2Ban.WindowSeconds);
        Assert.Equal(EdrConfig.Limits.MaxBanSeconds.Min, c.Wail2Ban.MaxBanPublicSec);
        Assert.Equal(EdrConfig.Limits.MaxBanSeconds.Max, c.Wail2Ban.MaxBanPrivateSec);
        var saved = new EdrConfig();
        saved.Apply(new JsonObject { ["wail2ban"] = new JsonObject { ["failCount"] = 500, ["windowSeconds"] = 90, ["maxBanPublicSec"] = 3600 } });
        var reread = EdrConfig.FromJson(saved.ToJson());
        Assert.Equal((500, 90, 3600), (reread.Wail2Ban.FailCount, reread.Wail2Ban.WindowSeconds, reread.Wail2Ban.MaxBanPublicSec));
    }

    [Fact]
    public void The_settings_page_baseline_is_the_file_without_internal_or_account_keys()
    {
        var cfg = new EdrConfig { InstalledAt = "2026-11-01T10:00:00", AllowProfilesInitialized = true };
        cfg.Wail2Ban.WindowSeconds = 90;
        var u = cfg.UserJson();
        Assert.Equal(EdrConfig.UserDefaults().Select(kv => kv.Key).Order(), u.Select(kv => kv.Key).Order());
        Assert.DoesNotContain("quietProcesses", u.Select(kv => kv.Key));
        Assert.False(((JsonObject)u["wail2ban"]!).ContainsKey("maxTrackedIps"));
        Assert.Equal(90, ((JsonObject)u["wail2ban"]!).Int("windowSeconds"));
        Assert.Empty(EdrConfig.Changes(u, cfg.UserJson()));
    }

    [Theory]
    [InlineData("https://example.org/hashes.txt", false, "https://example.org/hashes.txt")]
    [InlineData("https://example.org/list.txt?key=dummy_token", true, "https://example.org/list.txt?(hidden)")]
    [InlineData("https://dummy_token@example.org:8443/l.txt", true, "https://(hidden)@example.org:8443/l.txt")]
    public void A_private_feed_address_is_masked_and_redacted(string url, bool secret, string shown)
    {
        Assert.Equal(secret, EdrConfig.FeedHasSecret(url));
        Assert.Equal(shown, EdrConfig.RedactUrl(url));
        Assert.DoesNotContain("dummy_token", EdrConfig.RedactUrl(url));
        Assert.DoesNotContain("dummy_token", EdrConfig.RedactUrl(url));
        var req = new JsonObject { ["iocFeedUrl"] = url, ["sigmaLookback"] = "2d" };
        Assert.Equal(shown, EdrConfig.Redacted(req).Str("iocFeedUrl"));
        Assert.Equal(url, req.Str("iocFeedUrl"));
    }

    [Fact]
    public void A_backup_carries_the_quiet_list_for_the_account_not_for_the_pc()
    {
        var backup = SettingsBackup.Create(new EdrConfig(), Exclusions());
        var settings = (JsonObject)backup["settings"]!;
        Assert.False(settings.ContainsKey("quietProcesses"));
        settings["quietProcesses"] = new JsonArray("obs64*", @"C:\Games\x.exe", "My Game*");
        Assert.Equal(["obs64*", "My Game*"], SettingsBackup.QuietOf(backup));
        var plan = SettingsBackup.PlanImport(backup, new EdrConfig(), Exclusions());
        Assert.False(plan.ConfigChanges.ContainsKey("quietProcesses"));
        Assert.Null(SettingsBackup.QuietOf(new JsonObject { ["format"] = SettingsBackup.Format }));
        Assert.Null(SettingsBackup.QuietOf(new JsonObject { ["settings"] = new JsonObject { ["quietProcesses"] = new JsonArray("x*") } }));
    }

    [Theory]
    [InlineData("obs64*", true)]
    [InlineData("My Game*", true)]
    [InlineData(@"C:\Games\x.exe", false)]
    [InlineData("games/x", false)]
    [InlineData("", false)]
    public void Quiet_names_follow_one_rule(string name, bool ok) => Assert.Equal(ok, EdrConfig.IsQuietName(name));

    [Fact]
    public void Settings_page_uses_the_shared_ranges()
    {
        var page = File.ReadAllText(Path.Combine(Repo(), "src", "Edr.Tray", "Views", "SettingsPage.cs"));
        Assert.Contains("EdrConfig.Limits.FailCount", page);
        Assert.Contains("EdrConfig.Limits.WindowSeconds", page);
        Assert.DoesNotContain("Thickness(240, -6", page);
    }
}
