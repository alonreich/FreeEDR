using System.Globalization;
using System.Text.Json.Nodes;
using Edr.Core;
using Xunit;

namespace Edr.Core.Tests;

public class GoldenModelTests(ITestOutputHelper output)
{
    public static TheoryData<string> Fixtures()
    {
        var data = new TheoryData<string>();
        var dir = Path.Combine(AppContext.BaseDirectory, "Fixtures");
        if (Directory.Exists(dir))
            foreach (var f in Directory.GetDirectories(dir).Where(d => File.Exists(Path.Combine(d, "model.json")))) data.Add(Path.GetFileName(f));
        return data;
    }

    [Theory]
    [MemberData(nameof(Fixtures))]
    public void Model_matches_the_golden_file(string fixture)
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "Fixtures", fixture);
        var expected = JsonNode.Parse(File.ReadAllText(Path.Combine(dir, "model.json")))!;
        var now = DateTime.ParseExact(expected["now"]!.GetValue<string>(), "yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture);
        var inputs = EdrInputs.Load(new EdrPaths(Path.Combine(dir, "inputs"), Path.Combine(dir, "inputs", "local")));
        var record = Environment.GetEnvironmentVariable("FREEEDR_RECORD_SIGNERS") == "1";
        var signers = new FixtureSigners(dir, record);
        var model = new ModelBuilder(inputs, signers).Build();
        if (record)
        {
            var src = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "Fixtures", fixture));
            if (Directory.Exists(src)) signers.Save(src);
        }
        var overall = ModelBuilder.GetOverall(model, inputs.Status, now);
        var actual = ModelDump.ToJson(model, overall, now);
        foreach (var line in ModelDump.Summary(model, overall)) output.WriteLine(line);

        if (Environment.GetEnvironmentVariable("FREEEDR_UPDATE_GOLDEN") == "1")
        {
            var src = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "Fixtures", fixture, "model.json"));
            if (File.Exists(src)) File.WriteAllText(src, ModelDump.Write(actual));
            return;
        }
        var diffs = ParityCheck.Compare(expected, actual);
        foreach (var d in diffs) output.WriteLine(d);
        Assert.True(diffs.Count == 0, $"{diffs.Count} difference(s):\n" + string.Join("\n", diffs.Take(15)));
    }

    [Fact]
    public void Overall_says_detect_only_actions()
    {
        var o = ModelBuilder.GetOverall(null, null, DateTime.Now);
        Assert.Equal("down", o.Key);
        Assert.DoesNotContain("tray shield", o.Sub);
    }

    [Fact]
    public void Overall_review_count_matches_the_open_items_of_Activity()
    {
        var now = DateTime.Now;
        var st = Rec.Parse("{\"heartbeat\":\"" + now.ToString("yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture) + "\",\"sysmon\":{\"ok\":true}}");
        var m = new TrayModel();
        m.Sec["edr"].Count = 4; m.Sec["edr"].Attention = 3;
        m.Sec["malware"].Count = 2; m.Sec["malware"].Attention = 2;
        m.Sec["sigma"].Count = 2; m.Sec["sigma"].Attention = 2;
        m.Attention = 7;
        var o = ModelBuilder.GetOverall(m, st, now);
        Assert.Equal("attention", o.Key);
        Assert.StartsWith("8 items need your review", o.Text);
        Assert.Contains(": 4", o.Sub);
    }
}
