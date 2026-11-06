using System.Text;
using System.Text.Json.Nodes;
using System.Xml;
using Edr.Core;
using Xunit;

namespace Edr.Core.Tests;

/// <summary>The Sysmon process rules against everyday (must stay quiet) and attack (must alert) command lines.</summary>
public class SysmonRuleTests
{
    private static readonly XmlDocument Config = Load();

    private static XmlDocument Load()
    {
        var d = new XmlDocument();
        d.LoadXml(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Repo", "sysmonconfig.template.xml")).Replace("{ROOT}", @"C:\Program Files\FreeEDR"));
        return d;
    }

    /// <summary>Sysmon's conditions (case-insensitive) as used by the template.</summary>
    public static bool Cond(string value, string cond, string pattern)
    {
        var v = value.ToLowerInvariant();
        var items = cond.EndsWith(" any") || cond.EndsWith(" all") ? pattern.Split(';').Where(x => x.Length > 0).Select(x => x.ToLowerInvariant()).ToList() : [pattern.ToLowerInvariant()];
        return cond switch
        {
            "is" or "is any" => items.Any(i => v == i),
            "contains" or "contains any" => items.Any(v.Contains),
            "contains all" => items.All(v.Contains),
            "begin with" => items.Any(v.StartsWith),
            "end with" or "end with any" => items.Any(v.EndsWith),
            "excludes" or "excludes all" => !items.Any(v.Contains),
            "excludes any" => items.Any(i => !v.Contains(i)),
            _ => throw new NotSupportedException($"condition '{cond}' is not supported by this test - add it"),
        };
    }

    private static bool Field(XmlElement n, IReadOnlyDictionary<string, string> ev) =>
        Cond(ev.TryGetValue(n.LocalName, out var v) ? v : "", n.GetAttribute("condition"), n.InnerText);

    public static List<string> Hits(IReadOnlyDictionary<string, string> ev)
    {
        foreach (XmlElement ex in Config.SelectNodes("//ProcessCreate[@onmatch='exclude']/*")!) if (Field(ex, ev)) return ["EXCLUDED"];
        var hits = new List<string>();
        foreach (XmlElement n in Config.SelectNodes("//ProcessCreate[@onmatch='include']/*")!)
        {
            if (n.LocalName == "Rule")
            {
                var res = n.ChildNodes.OfType<XmlElement>().Select(c => Field(c, ev)).ToList();
                if (n.GetAttribute("groupRelation") == "and" ? res.All(x => x) : res.Any(x => x)) hits.Add(n.GetAttribute("name"));
            }
            else if (Field(n, ev)) hits.Add(n.GetAttribute("name"));
        }
        return hits;
    }

    private static Dictionary<string, string> Ev(string image, string cmd, string parent) =>
        new() { ["Image"] = image, ["CommandLine"] = cmd, ["ParentImage"] = parent, ["OriginalFileName"] = Path.GetFileName(image) };

    private static JsonObject Corpus() => (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Repo", "process-corpus.json")))!;

    public static TheoryData<int> Malicious() { var d = new TheoryData<int>(); for (var i = 0; i < Corpus().Objects("malicious").Count(); i++) d.Add(i); return d; }
    public static TheoryData<int> Benign() { var d = new TheoryData<int>(); for (var i = 0; i < Corpus().Objects("benign").Count(); i++) d.Add(i); return d; }

    [Theory]
    [MemberData(nameof(Malicious))]
    public void Attack_command_lines_alert(int i)
    {
        var s = Corpus().Objects("malicious").ElementAt(i);
        var cmd = Encoding.UTF8.GetString(Convert.FromBase64String(s.Str("cmd")));
        var h = Hits(Ev(s.Str("image"), cmd, s.Str("parent")));
        Assert.True(h.Contains(s.Str("expect")), $"missed (false negative): '{cmd[..Math.Min(60, cmd.Length)]}' matched [{string.Join("; ", h)}], expected '{s.Str("expect")}'");
    }

    [Theory]
    [MemberData(nameof(Benign))]
    public void Everyday_command_lines_stay_quiet(int i)
    {
        var s = Corpus().Objects("benign").ElementAt(i);
        var h = Hits(Ev(s.Str("image"), s.Str("cmd"), s.Str("parent"))).Where(x => x != "EXCLUDED").ToList();
        Assert.True(h.Count == 0, $"false positive: '{s.Str("name")}' raises [{string.Join("; ", h)}]");
    }

    [Fact]
    public void T2_new_user_with_password_is_detected() =>
        Assert.Contains("New user or admin group change", Hits(Ev(@"C:\Windows\System32\net.exe", "net user hacker Passw0rd! /add", @"C:\Windows\System32\cmd.exe")));

    [Fact]
    public void T4_listing_administrators_is_quiet() =>
        Assert.DoesNotContain("New user or admin group change", Hits(Ev(@"C:\Windows\System32\net.exe", "net localgroup administrators", @"C:\Windows\System32\cmd.exe")));

    [Fact]
    public void T4_adding_an_administrator_is_detected() =>
        Assert.Contains("New user or admin group change", Hits(Ev(@"C:\Windows\System32\net.exe", "net localgroup administrators eve /add", @"C:\Windows\System32\cmd.exe")));

    [Theory]
    [InlineData("pwsh.exe -NoProfile -Command \"rg -e TODO src\"")]
    [InlineData(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Command ""git commit -m 'support -e flag'""")]
    public void T3_dash_e_inside_a_command_is_quiet(string cmd) =>
        Assert.DoesNotContain("Encoded PowerShell command", Hits(Ev(@"C:\Program Files\PowerShell\7\pwsh.exe", cmd, @"C:\Windows\explorer.exe")));

    [Fact]
    public void Every_rule_has_a_severity_and_an_explanation()
    {
        foreach (XmlElement n in Config.SelectNodes("//EventFiltering//*[@name]")!)
        {
            if (n.LocalName == "RuleGroup") continue;
            var name = n.GetAttribute("name");
            Assert.True(Catalog.RuleSeverity.ContainsKey(name), $"rule '{name}' has no severity in Catalog.RuleSeverity");
            Assert.True(Hints.Rules.ContainsKey(name), $"rule '{name}' has no explanation in Hints.Rules");
        }
    }

    [Fact]
    public void Template_never_uses_end_with_any() => Assert.Empty(Config.SelectNodes("//*[@condition='end with any']")!.OfType<XmlElement>());
}

/// <summary>The engine's allow decisions and its own-process trust.</summary>
public class EngineDecisionTests
{
    private sealed class FakeSigners(Dictionary<string, string> map) : ISignerLookup
    {
        public string? SignerOf(string path) => map.TryGetValue(path, out var s) ? s : null;
    }

    private static JsonObject X(string json) => (JsonObject)JsonNode.Parse(json)!;

    [Fact]
    public void A_signed_parent_up_the_chain_allows_only_its_rules()
    {
        var claude = @"C:\Users\x\AppData\Local\Claude\claude.exe";
        var signers = new FakeSigners(new() { [claude] = "Anthropic, PBC" });
        var allow = X("""{"rule":"Encoded PowerShell command","image":"","parent":"*\\claude.exe","parentSigner":"Anthropic, PBC","ancestors":3}""");
        IReadOnlyList<string> Chain(int n) => new[] { @"C:\Windows\System32\cmd.exe", claude }.Take(n).ToList();
        Assert.NotNull(Detection.RealtimeExcluded([], [allow], "Encoded PowerShell command", @"C:\Program Files\PowerShell\7\pwsh.exe", @"C:\Windows\System32\cmd.exe", "x", Chain, signers));
        Assert.Null(Detection.RealtimeExcluded([], [allow], "LSASS memory dump", @"C:\Program Files\PowerShell\7\pwsh.exe", @"C:\Windows\System32\cmd.exe", "x", Chain, signers));
        var unsigned = new FakeSigners([]);
        Assert.Null(Detection.RealtimeExcluded([], [allow], "Encoded PowerShell command", @"C:\Program Files\PowerShell\7\pwsh.exe", @"C:\Windows\System32\cmd.exe", "x", Chain, unsigned));
    }

    [Fact]
    public void Exact_detail_allows_do_not_match_imitations()
    {
        var allow = X("""{"rule":"PowerShell download or in-memory execution","image":"*\\pwsh.exe","match":"exact","detail":"pwsh.exe -Command \"Invoke-Expression $x\""}""");
        var s = new FakeSigners([]);
        Assert.NotNull(Detection.RealtimeExcluded([], [allow], "PowerShell download or in-memory execution", @"C:\p\pwsh.exe", "", "pwsh.exe -Command \"Invoke-Expression $x\"", null, s));
        Assert.Null(Detection.RealtimeExcluded([], [allow], "PowerShell download or in-memory execution", @"C:\p\pwsh.exe", "", "pwsh.exe -Command \"Invoke-Expression $x\"; IEX(New-Object Net.WebClient)", null, s));
    }

    [Fact]
    public void Blanket_allows_are_never_honoured()
    {
        var s = new FakeSigners([]);
        Assert.Null(Detection.RealtimeExcluded([], [X("""{"rule":"*","image":"*"}""")], "x", @"C:\a.exe", "", "", null, s));
        Assert.Null(Detection.SigmaExcluded([X("""{"title":"*","parent":""}""")], "Some rule", @"C:\a.exe", s));
        Assert.NotNull(Detection.SigmaExcluded([X("""{"title":"Some rule"}""")], "Some rule", "", s));
    }

    [Fact]
    public void Defender_allows_by_threat_id_or_program()
    {
        Assert.True(Detection.DefenderExcluded([X("""{"kind":"threat","path":"2147"}""")], [], "2147", ""));
        Assert.True(Detection.DefenderExcluded([], [X("""{"image":"*\\FreeEDR-Setup*.exe"}""")], "", @"file:_C:\x\FreeEDR-Setup.exe"));
        Assert.False(Detection.DefenderExcluded([], [], "1", @"C:\x\a.exe"));
    }

    private const string Root = @"C:\Program Files\FreeEDR";

    [Fact]
    public void FreeEDRs_own_programs_and_their_elevated_children_are_trusted()
    {
        Assert.Equal(OwnProcess.Verdict.Own, OwnProcess.Check(new Dictionary<string, string> { ["Image"] = $@"{Root}\bin\FreeEDR-Engine.exe" }, Root));
        Assert.Equal(OwnProcess.Verdict.Own, OwnProcess.Check(new Dictionary<string, string>
        {
            ["Image"] = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", ["ParentImage"] = $@"{Root}\bin\FreeEDR-Engine.exe", ["IntegrityLevel"] = "System",
            ["CommandLine"] = "powershell -NoProfile -Command Get-MpComputerStatus",
        }, Root));
        Assert.Equal(OwnProcess.Verdict.Own, OwnProcess.Check(new Dictionary<string, string>
        {
            ["Image"] = @"C:\Windows\explorer.exe", ["ParentImage"] = $@"{Root}\bin\tray\FreeEDR-Tray.exe", ["IntegrityLevel"] = "Medium",
        }, Root));
    }

    [Fact]
    public void Unelevated_children_and_copies_elsewhere_are_not_trusted()
    {
        // A medium-integrity child of the engine's path cannot be the engine's own work
        Assert.NotEqual(OwnProcess.Verdict.Own, OwnProcess.Check(new Dictionary<string, string>
        {
            ["Image"] = @"C:\Windows\System32\cmd.exe", ["ParentImage"] = $@"{Root}\bin\FreeEDR-Engine.exe", ["IntegrityLevel"] = "Medium",
        }, Root));
        // The tray may start Explorer, never PowerShell directly
        Assert.NotEqual(OwnProcess.Verdict.Own, OwnProcess.Check(new Dictionary<string, string>
        {
            ["Image"] = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", ["ParentImage"] = $@"{Root}\bin\tray\FreeEDR-Tray.exe",
        }, Root));
        // A copy of the engine in a user folder is somebody else
        Assert.Equal(OwnProcess.Verdict.NearMiss, OwnProcess.Check(new Dictionary<string, string>
        {
            ["Image"] = @"C:\Users\x\Downloads\FreeEDR-Engine.exe", ["CommandLine"] = @"C:\Users\x\Downloads\FreeEDR-Engine.exe --console",
        }, Root));
        Assert.Equal(OwnProcess.Verdict.NearMiss, OwnProcess.Check(new Dictionary<string, string>
        {
            ["Image"] = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", ["CommandLine"] = $@"powershell -File ""{Root}\EDR-Engine.ps1"" ; iex $x",
        }, Root));
        Assert.Equal(OwnProcess.Verdict.NotOwn, OwnProcess.Check(new Dictionary<string, string> { ["Image"] = @"C:\x\a.exe", ["CommandLine"] = "a.exe" }, Root));
    }
}
