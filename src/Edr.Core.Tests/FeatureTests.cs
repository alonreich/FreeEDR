using System.Globalization;
using System.Text.Json.Nodes;
using Edr.Core;
using Edr.Engine;
using Xunit;

namespace Edr.Core.Tests;

public class ProfileTests
{
    [Fact]
    public void Every_profile_entry_passes_the_engine_validation()
    {
        foreach (var p in Profiles.All)
            foreach (var op in Profiles.Ops(p))
                Assert.True(PatternRules.IsValidOp(op), $"{p.Id}: {op.ToJsonString()}");
    }

    [Fact]
    public void Profiles_never_name_a_user_account()
    {
        var me = Environment.UserName;
        foreach (var p in Profiles.All)
            foreach (var e in p.Entries.Concat(p.Detect.Select(d => new ProfileEntry("detect", Image: d))))
                Assert.DoesNotContain($@"\{me}\", e.Image + e.Parent + e.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_matching_profile_that_is_off_is_offered()
    {
        var ev = new Rec((JsonObject)JsonNode.Parse("""{"blade":"realtime","rule":"PowerShell download or in-memory execution","process":"C:\\Program Files\\PowerShell\\7\\pwsh.exe","detail":"pwsh x vcpkg-init.cmd y"}""")!);
        var p = Profiles.FindFor(ev, _ => false, NoSigners.Instance);
        Assert.Equal("vcpkg", p?.Id);
        Assert.Null(Profiles.FindFor(ev, id => id == "vcpkg", NoSigners.Instance));
    }
}

public class ActionTests
{
    private static Rec R(string json) => new((JsonObject)JsonNode.Parse(json)!);

    [Fact]
    public void Flag_needs_a_concrete_program_or_address()
    {
        Assert.Null(ActionBuilder.FlagOp(R("""{"blade":"realtime","process":"relative.exe"}""")));
        Assert.Equal("block", ActionBuilder.FlagOp(R("""{"blade":"ioc","process":"C:\\x\\m.exe","sha256":"aa"}"""))!.Str("action"));
        Assert.Equal("1.2.3.4", ActionBuilder.FlagOp(R("""{"blade":"wail2ban","ip":"1.2.3.4"}"""))!.Str("ip"));
    }

    [Fact]
    public void Allow_variants_build_valid_engine_requests()
    {
        var e = R("""{"blade":"realtime","rule":"Encoded PowerShell command","process":"C:\\Tools\\x[1].exe","parent":"C:\\Apps\\app\\2.1.0\\app.exe"}""");
        string? NoSigner(string _) => null;
        var basic = ActionBuilder.AllowOp(e, "default", NoSigner)!;
        Assert.Equal(@"C:\Tools\x`[1`].exe", basic.Str("image"));
        Assert.True(PatternRules.IsValidOp(basic));
        var rule = ActionBuilder.AllowOp(e, "rule", NoSigner)!;
        Assert.Equal("Encoded PowerShell command", rule.Str("rule"));
        var parent = ActionBuilder.AllowOp(e, "parent", NoSigner)!;
        Assert.Equal(@"C:\Apps\app\*\app.exe", parent.Str("parent"));
        Assert.True(PatternRules.IsValidOp(parent));
        Assert.Null(ActionBuilder.AllowOp(e, "signer", _ => "Microsoft Windows"));
        var net = ActionBuilder.AllowOp(R("""{"blade":"wail2ban","ip":"203.0.113.9"}"""), "net", NoSigner)!;
        Assert.Equal("203.0.113.0/24", net.Str("cidr"));
    }

    [Fact]
    public void Cve_updates_use_argument_vectors_and_refuse_injection()
    {
        var sid = "S-1-5-21-1-2-3-1001";
        var items = new[]
        {
            R("""{"package":"requests","version":"2.0","fixed":"2.32.0","python":"python3.11","owner":"S-1-5-21-1-2-3-1001"}"""),
            R("""{"package":"requests","version":"2.0","fixed":"2.31.0","python":"python3.11","owner":"S-1-5-21-1-2-3-1001"}"""),
            R("""{"package":"evil; calc","version":"1","fixed":"2 & calc","python":"C:\\x\\python.exe\"; calc","owner":"S-1-5-21-1-2-3-1001"}"""),
            R("""{"package":"other","version":"1","fixed":"2","python":"python3.11","owner":"S-1-5-21-9-9-9-500"}"""),
        };
        var cmds = ActionBuilder.CveCommands(items, sid, @"C:\Users\me");
        Assert.Equal(2, cmds.Count);
        Assert.Equal(["-m", "pip", "install", "--upgrade", "requests>=2.32.0"], cmds[0].Arguments);
        Assert.Equal("py", cmds[1].FilePath);
        Assert.DoesNotContain(cmds[1].Arguments, a => a.Contains(';') || a.Contains('&') || a.Contains(' '));
    }

    [Fact]
    public void Advisory_links_point_to_nvd_or_osv()
    {
        Assert.Equal("https://nvd.nist.gov/vuln/detail/CVE-2024-1234", ActionBuilder.AdvisoryUrl(R("""{"cve":"CVE-2024-1234"}""")));
        Assert.Equal("https://osv.dev/vulnerability/GHSA-abcd", ActionBuilder.AdvisoryUrl(R("""{"cve":"GHSA-abcd","id":"GHSA-abcd"}""")));
    }

    [Fact]
    public void Pinned_alerts_offer_yes_and_no_first()
    {
        var ev = R("""{"id":"1","blade":"wail2ban","kind":"login","ip":"203.0.113.9","title":"Successful login as a from 203.0.113.9 (public internet)","severity":"High"}""");
        var row = new Row { Kind = "event", Sec = "wail2ban", Cols = [], Ev = ev, Group = [ev], Pinned = true };
        var acts = ActionBuilder.For([row], _ => null, _ => null, _ => false, _ => true, _ => false);
        Assert.Equal(ActionKind.ItWasMe, acts[0].Kind);
        Assert.Equal(ActionKind.Flag, acts[1].Kind);
        Assert.Contains(acts, a => a.Kind == ActionKind.AllowSubnet);
        Assert.Contains(acts, a => a.Kind == ActionKind.ExplainForDummies);
    }

    [Fact]
    public void ExplainPrompt_builds_full_context_and_instructions()
    {
        var ev = R("""{"id":"test-1","blade":"realtime","rule":"Encoded PowerShell command","title":"Encoded PowerShell command","severity":"High","process":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","parent":"C:\\tools\\launcher.exe","detail":"powershell -EncodedCommand SQBF...","time":"2026-11-10 10:00:00"}""");
        var now = new DateTimeOffset(2026, 11, 10, 10, 0, 0, TimeSpan.FromHours(2));
        var related = new[] { R("""{"blade":"realtime","title":"Process Created","process":"C:\\tools\\launcher.exe","detail":"launcher started","time":"2026-11-10 09:59:50"}""") };
        var prompt = ExplainPrompt.Build(ev, now, related);

        Assert.Contains("=== SYSTEM & FREEEDR CONTEXT ===", prompt);
        Assert.Contains("FreeEDR", prompt);
        Assert.Contains("2026-11-10 10:00:00 +02:00", prompt);
        Assert.Contains("UTC offset: +02:00", prompt);
        Assert.Contains("=== DETECTED INCIDENT TELEMETRY ===", prompt);
        Assert.Contains("Encoded PowerShell command", prompt);
        Assert.Contains("=== RECENT SURROUNDING / RELATED LOGS ===", prompt);
        Assert.Contains("Process Created", prompt);
        Assert.Contains("=== USER QUESTION & INSTRUCTIONS ===", prompt);
        Assert.Contains(ExplainPrompt.UserInstruction, prompt);
    }
}

public class SummaryTests
{
    [Fact]
    public void Weekly_summary_counts_alerts_bans_and_scans()
    {
        var now = new DateTime(2026, 11, 6, 12, 0, 0);
        string T(int daysAgo) => now.AddDays(-daysAgo).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
        var events = new[]
        {
            new Rec(new JsonObject { ["time"] = T(1), ["blade"] = "realtime", ["severity"] = "High", ["title"] = "A" }),
            new Rec(new JsonObject { ["time"] = T(2), ["blade"] = "realtime", ["severity"] = "High", ["title"] = "A" }),
            new Rec(new JsonObject { ["time"] = T(2), ["blade"] = "ioc", ["severity"] = "Critical", ["title"] = "B" }),
            new Rec(new JsonObject { ["time"] = T(3), ["blade"] = "wail2ban", ["kind"] = "fail", ["severity"] = "Low", ["title"] = "f" }),
            new Rec(new JsonObject { ["time"] = T(3), ["blade"] = "wail2ban", ["expires"] = "x", ["severity"] = "Medium", ["title"] = "ban" }),
            new Rec(new JsonObject { ["time"] = T(4), ["blade"] = "system", ["kind"] = "scan", ["ok"] = true, ["severity"] = "Info", ["title"] = "s" }),
            new Rec(new JsonObject { ["time"] = T(9), ["blade"] = "realtime", ["severity"] = "High", ["title"] = "old" }),
        };
        var s = PeriodSummary.Compute(events, now.AddDays(-7), now);
        Assert.Equal(3, s.Alerts);
        Assert.Equal(1, s.Critical);
        Assert.Equal(1, s.Bans);
        Assert.Equal(1, s.SignInFailures);
        Assert.Equal(1, s.ScansOk);
        Assert.Equal(("A", 2), s.Noisiest[0]);
    }
}

public class EngineInternalsTests
{
    [Fact]
    public void Osv_rows_only_for_released_fixes_and_pip_vendored_libraries()
    {
        var osv = (JsonObject)JsonNode.Parse("""
        {"results":[{"source":{"path":"C:\\Py\\Lib\\site-packages\\pip\\_vendor\\urllib3"},"packages":[{"package":{"name":"urllib3","version":"1.26.0"},
          "vulnerabilities":[{"id":"GHSA-1","aliases":["CVE-2024-1"],"summary":"bad","affected":[{"package":{"name":"urllib3"},"ranges":[{"events":[{"introduced":"0"},{"fixed":"1.26.18"}]}]}]},
                             {"id":"GHSA-2","summary":"no fix","affected":[{"package":{"name":"urllib3"},"ranges":[{"events":[{"introduced":"0"}]}]}]}],
          "groups":[{"ids":["GHSA-1"],"max_severity":"7.5"},{"ids":["GHSA-2"],"max_severity":""}]}]}]}
        """)!;
        var noFix = 0;
        var rows = OsvParser.Rows(osv, "S-1-5-21-1", ref noFix).ToList();
        Assert.Single(rows);
        Assert.Equal(1, noFix);
        Assert.Equal("CVE-2024-1", rows[0].Str("cve"));
        Assert.Equal("1.26.18", rows[0].Str("fixed"));
        Assert.Equal("High", rows[0].Str("severity"));
        Assert.Equal("pip", rows[0].Str("fixPackage"));
    }

    [Fact]
    public void Csv_handles_quotes_commas_and_newlines()
    {
        var f = Path.Combine(AppContext.BaseDirectory, $"t-{Guid.NewGuid():N}.csv");
        File.WriteAllText(f, "A,B\r\n\"x, y\",\"line1\nline2 \"\"q\"\"\"\r\n");
        try
        {
            var rows = Csv.Read(f).ToList();
            Assert.Equal(["x, y", "line1\nline2 \"q\""], rows[1]);
        }
        finally { File.Delete(f); }
    }

    [Fact]
    public void Wail2Ban_in_report_only_mode_reports_guessing_without_a_firewall_rule()
    {
        var d = Path.Combine(AppContext.BaseDirectory, "w2b-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(d, "data"));
        try
        {
            var ctx = new Context(new EdrPaths(d, Path.Combine(d, "local")));
            ctx.Cfg = new EdrConfig { Wail2Ban = { Block = false, FailCount = 3 } };
            var w = new Wail2Ban(ctx);
            var t = DateTime.Now;
            w.AddFailure("203.0.113.50", "Security", t, replay: false);
            w.AddFailure("203.0.113.50", "RdpCoreTS", t.AddSeconds(1), replay: false);
            w.AddFailure("203.0.113.50", "Security", t.AddSeconds(10), replay: false);
            w.AddFailure("203.0.113.50", "Security", t.AddSeconds(20), replay: false);
            var events = File.ReadAllLines(ctx.Paths.EventsFile).Select(l => (JsonObject)JsonNode.Parse(l)!).ToList();
            Assert.Equal(2, events.Count(e => e.Str("kind") == "fail"));
            Assert.Single(events, e => e.Str("kind") == "guess" && e.Truthy("threshold"));
            Assert.DoesNotContain(events, e => e.ContainsKey("expires"));
        }
        finally { Directory.Delete(d, true); }
    }

    [Fact]
    public void Ban_length_escalates_and_is_capped_for_private_addresses()
    {
        var d = Path.Combine(AppContext.BaseDirectory, "w2b-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(d, "data"));
        try
        {
            var ctx = new Context(new EdrPaths(d, Path.Combine(d, "local"))) { Cfg = new EdrConfig() };
            var w = new Wail2Ban(ctx);
            Assert.Equal((300, 1), w.BanDuration("203.0.113.7"));
            Assert.Equal((1500, 2), w.BanDuration("203.0.113.7"));
            for (var i = 0; i < 8; i++) w.BanDuration("10.0.0.9");
            Assert.Equal(604_800, w.BanDuration("10.0.0.9").Seconds);
        }
        finally { Directory.Delete(d, true); }
    }
}
