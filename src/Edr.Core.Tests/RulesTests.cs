using System.Text.Json.Nodes;
using Edr.Core;
using Xunit;

namespace Edr.Core.Tests;

/// <summary>The single validation gate for allows and commands (elevated helper + engine).</summary>
public class PatternRulesTests
{
    [Theory]
    [InlineData("*", "image", false)]
    [InlineData("*.*", "image", false)]
    [InlineData(@"C:\", "image", false)]
    [InlineData(@"C:\*", "image", false)]
    [InlineData(@"*\pwsh.exe", "image", true)]
    [InlineData(@"C:\Program Files\Razer\*", "image", true)]
    [InlineData(@"*\a.exe", "image", false)]
    [InlineData("ab", "detail", false)]
    [InlineData("*vcpkg-init.cmd*", "detail", true)]
    [InlineData("123456", "threat", true)]
    [InlineData("12a", "threat", false)]
    [InlineData(@"C:\Games\game.exe", "cfa", true)]
    [InlineData(@"C:\Games\*.exe", "cfa", false)]
    [InlineData(@"D:\", "asr", false)]
    public void Specificity(string pattern, string kind, bool ok) => Assert.Equal(ok, PatternRules.IsSpecific(pattern, kind));

    [Fact]
    public void A_match_all_parent_needs_a_safe_signer()
    {
        Assert.False(PatternRules.IsSpecific("*", "parent"));
        Assert.False(PatternRules.IsSpecific("*", "parent", "Microsoft Corporation"));
        Assert.True(PatternRules.IsSpecific("*", "parent", "Anthropic, PBC"));
    }

    private static JsonObject Op(string json) => (JsonObject)JsonNode.Parse(json)!;

    [Fact]
    public void Realtime_allows_must_be_narrow()
    {
        Assert.False(PatternRules.IsValidOp(Op("""{"action":"exclude","blade":"realtime","rule":"*"}""")));
        Assert.False(PatternRules.IsValidOp(Op("""{"action":"exclude","blade":"realtime","image":"*"}""")));
        Assert.False(PatternRules.IsValidOp(Op("""{"action":"exclude","blade":"realtime","signer":"Microsoft Windows"}""")));
        Assert.False(PatternRules.IsValidOp(Op("""{"action":"exclude","blade":"realtime","parent":"*","parentSigner":"Microsoft Corporation"}""")));
        Assert.False(PatternRules.IsValidOp(Op("""{"action":"exclude","blade":"realtime","image":"*\\x.exe","match":"regex"}""")));
        Assert.True(PatternRules.IsValidOp(Op("""{"action":"exclude","blade":"realtime","image":"C:\\Tools\\tool.exe"}""")));
        Assert.True(PatternRules.IsValidOp(Op("""{"action":"exclude","blade":"realtime","image":"C:\\Program Files\\Microsoft OneDrive\\*","signer":"Microsoft Corporation"}""")));
    }

    [Fact]
    public void Other_lists_validate_their_fields()
    {
        Assert.True(PatternRules.IsValidOp(Op("""{"action":"exclude","blade":"wail2ban","cidr":"192.168.1.0/24"}""")));
        Assert.False(PatternRules.IsValidOp(Op("""{"action":"exclude","blade":"wail2ban","cidr":"192.168.1.0/99"}""")));
        Assert.False(PatternRules.IsValidOp(Op("""{"action":"exclude","blade":"wail2ban","cidr":"not-an-ip"}""")));
        Assert.True(PatternRules.IsValidOp(Op("""{"action":"exclude","blade":"ioc","sha256":"411CE8749115C85B359ADE15B9824B38650B06274DC816D1D4B9035859C8C573"}""")));
        Assert.False(PatternRules.IsValidOp(Op("""{"action":"exclude","blade":"ioc","sha256":"abc"}""")));
        Assert.False(PatternRules.IsValidOp(Op("""{"action":"exclude","blade":"sigma","title":"*"}""")));
        Assert.True(PatternRules.IsValidOp(Op("""{"action":"exclude","blade":"sigma","title":"Some rule"}""")));
        Assert.False(PatternRules.IsValidOp(Op("""{"action":"exclude","blade":"defender","kind":"cfa","path":"C:\\*"}""")));
        Assert.False(PatternRules.IsValidOp(Op("""{"action":"pause","blade":"defender"}""")));
        Assert.True(PatternRules.IsValidOp(Op("""{"action":"pause","blade":"wail2ban","minutes":15}""")));
        Assert.False(PatternRules.IsValidOp(Op("""{"action":"block","blade":"realtime","image":"relative.exe"}""")));
        Assert.False(PatternRules.IsValidOp(Op("""{"action":"unexclude","id":"../../x"}""")));
        Assert.True(PatternRules.IsValidOp(Op("""{"action":"update-tool","name":"YARA"}""")));
        Assert.False(PatternRules.IsValidOp(Op("""{"action":"update-tool","name":"evil"}""")));
    }

    [Fact]
    public void Batches_are_capped_and_only_hold_batchable_steps()
    {
        var ops = new JsonArray();
        for (var i = 0; i < 101; i++) ops.Add((JsonNode)new JsonObject { ["action"] = "unban", ["ip"] = "10.0.0.1" });
        Assert.False(PatternRules.IsValidCommand(new JsonObject { ["action"] = "batch", ["ops"] = ops }, out _));
        Assert.False(PatternRules.IsValidCommand(Op("""{"action":"batch","ops":[{"action":"restore-defaults"}]}"""), out _));
        Assert.False(PatternRules.IsValidCommand(Op("""{"action":"batch","ops":[]}"""), out _));
        Assert.True(PatternRules.IsValidCommand(Op("""{"action":"batch","ops":[{"action":"unban","ip":"10.0.0.1"},{"action":"exclude","blade":"wail2ban","cidr":"10.0.0.1"}]}"""), out _));
        Assert.False(PatternRules.IsValidCommand(Op("""{"action":"kill-everything"}"""), out _));
    }

    [Fact]
    public void Versionless_and_escaped_patterns()
    {
        Assert.Equal(@"C:\x\claude-code\*\*\claude.exe", PatternRules.VersionlessPattern(@"C:\x\claude-code\2.1.309\9078b9c1d466\claude.exe"));
        Assert.Equal(@"C:\a`[1`]\b.exe", PatternRules.EscapeWildcards(@"C:\a[1]\b.exe"));
        Assert.True(Ps.Like(@"C:\a[1]\b.exe", PatternRules.EscapeWildcards(@"C:\a[1]\b.exe")));
        Assert.False(PatternRules.HasWildcards(PatternRules.EscapeWildcards(@"C:\a*b?.exe")));
    }
}

public class IpTests
{
    [Theory]
    [InlineData("::ffff:1.2.3.4", "1.2.3.4")]
    [InlineData("[fe80::1%12]", "fe80::1")]
    [InlineData(" 10.0.0.5 ", "10.0.0.5")]
    [InlineData("999.1.1.1", null)]
    [InlineData("-", null)]
    public void Normalize(string input, string? expected) => Assert.Equal(expected, Ip.Normalize(input));

    [Fact]
    public void Cidr_and_private_ranges()
    {
        Assert.True(Ip.InCidr("10.0.0.15", "10.0.0.0/24"));
        Assert.False(Ip.InCidr("10.0.0.15", "10.0.0.1"));   // W1: exact, not a prefix match
        Assert.True(Ip.IsPrivate("192.168.1.1"));
        Assert.True(Ip.IsPrivate("100.64.0.1"));
        Assert.False(Ip.IsPrivate("8.8.8.8"));
        Assert.True(Ip.IsValidCidr("2001:db8::/32"));
        Assert.False(Ip.IsValidCidr("10.0.0.0/33"));
    }
}

public class ConfigTests
{
    [Fact]
    public void Defaults_are_detect_only_with_wail2ban_blocking()
    {
        var c = new EdrConfig();
        Assert.True(c.Wail2Ban.Block);
        Assert.False(c.Wail2Ban.BlockRdpIpv6);
        Assert.Equal("audit", c.DefenderMode);
        Assert.DoesNotContain("enforce", c.ToJson().ToJsonString());
    }

    [Fact]
    public void Obsolete_and_invalid_values_are_dropped()
    {
        var c = EdrConfig.FromJson((JsonObject)JsonNode.Parse("""{"enforce":true,"scanTimes":["25:00","07:30"],"iocFeedUrl":"https://bazaar.abuse.ch/x","sigmaLookback":"forever","defenderMode":"block","wail2ban":{"block":false,"failCount":0}}""")!);
        Assert.Equal(["07:30"], c.ScanTimes);
        Assert.Equal(EdrConfig.DefaultFeed, c.IocFeedUrl);
        Assert.Equal("2d", c.SigmaLookback);
        Assert.Equal("audit", c.DefenderMode);
        Assert.False(c.Wail2Ban.Block);
        Assert.Equal(5, c.Wail2Ban.FailCount);
        Assert.DoesNotContain("enforce", c.ToJson().ToJsonString());
    }

    [Fact]
    public void Apply_clamps_and_reports_a_defender_change()
    {
        var c = new EdrConfig();
        var changed = c.Apply((JsonObject)JsonNode.Parse("""{"defenderMode":"untouched","iocFeedUrl":"http://insecure","wail2ban":{"failCount":1,"windowSeconds":10,"block":false},"quietProcesses":["obs64*","C:\\bad\\path"]}""")!);
        Assert.True(changed);
        Assert.Equal(EdrConfig.DefaultFeed, c.IocFeedUrl);
        Assert.Equal(2, c.Wail2Ban.FailCount);
        Assert.Equal(60, c.Wail2Ban.WindowSeconds);
        Assert.False(c.Wail2Ban.Block);
        Assert.Equal(["obs64*"], c.QuietProcesses);
    }

    [Fact]
    public void Scan_slots_wrap_around_midnight()
    {
        var (prev, next) = EdrConfig.ScanSlots(["06:00", "18:00"], new DateTime(2026, 11, 6, 3, 0, 0));
        Assert.Equal(new DateTime(2026, 11, 5, 18, 0, 0), prev);
        Assert.Equal(new DateTime(2026, 11, 6, 6, 0, 0), next);
    }
}

public class JsonFileTests
{
    private static string TempDir()
    {
        var d = Path.Combine(AppContext.BaseDirectory, "tmp-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(d);
        return d;
    }

    [Fact]
    public void Atomic_write_keeps_a_backup_and_strict_read_recovers_from_it()
    {
        var d = TempDir();
        try
        {
            var f = Path.Combine(d, "x.json");
            JsonFile.WriteAtomic(f, new JsonObject { ["v"] = 1 });
            JsonFile.WriteAtomic(f, new JsonObject { ["v"] = 2 });
            Assert.True(File.Exists(f + ".bak"));
            File.WriteAllText(f, "{ damaged");
            string? recovered = null;
            JsonFile.Recovered = (p, _) => recovered = p;
            var n = JsonFile.ReadStrict(f) as JsonObject;
            JsonFile.Recovered = null;
            Assert.Equal(1, n!.Int("v"));
            Assert.Equal(f, recovered);
            Assert.Single(Directory.GetFiles(d, "x.json.corrupt-*"));
            Assert.Equal(1, (JsonFile.ReadStrict(f) as JsonObject)!.Int("v"));
        }
        finally { Directory.Delete(d, true); }
    }

    [Fact]
    public void Strict_read_without_backup_fails_closed()
    {
        var d = TempDir();
        try
        {
            var f = Path.Combine(d, "y.json");
            File.WriteAllText(f, "");
            Assert.Throws<InvalidDataException>(() => JsonFile.ReadStrict(f));
            Assert.Null(JsonFile.ReadStrict(Path.Combine(d, "missing.json")));
            Assert.Null(JsonFile.Read(f));
        }
        finally { Directory.Delete(d, true); }
    }

    [Fact]
    public void Event_writer_rotates_and_writes_one_line_per_event()
    {
        var d = TempDir();
        try
        {
            var p = new EdrPaths(d, Path.Combine(d, "local"));
            var w = new EventWriter(p);
            var e = w.Write("system", "Info", "hello", extra: new JsonObject { ["kind"] = "status" });
            var lines = File.ReadAllLines(p.EventsFile);
            Assert.Single(lines);
            Assert.Contains("\"kind\":\"status\"", lines[0]);
            Assert.Equal(32, e.Str("id").Length);
        }
        finally { Directory.Delete(d, true); }
    }

    [Fact]
    public void Command_drop_writes_json_never_tmp()
    {
        var d = TempDir();
        try
        {
            var f = CommandDrop.Write(d, new JsonObject { ["action"] = "scan-now" });
            Assert.EndsWith(".json", f);
            Assert.Empty(Directory.GetFiles(d, "*.tmp"));
        }
        finally { Directory.Delete(d, true); }
    }
}
