using System.Globalization;
using System.Text.Json.Nodes;
using Edr.Core;
using Xunit;

namespace Edr.Core.Tests;

/// <summary>
/// Golden tests: each Fixtures\* folder holds the inputs EDR-Tray.ps1 -SelfTest read (inputs\) and the model it
/// built (model.json, written with EDR_SELFTEST_DUMP). The C# model built from the same inputs must match.
/// Refresh a fixture: $env:EDR_SELFTEST_DUMP='<folder>'; powershell -STA -File EDR-Tray.ps1 -SelfTest
/// </summary>
public class ParityTests(ITestOutputHelper output)
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
    public void Model_matches_the_PowerShell_tray(string fixture)
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "Fixtures", fixture);
        var expected = JsonNode.Parse(File.ReadAllText(Path.Combine(dir, "model.json")))!;
        var now = DateTime.ParseExact(expected["now"]!.GetValue<string>(), "yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture);

        var inputs = EdrInputs.Load(new EdrPaths(Path.Combine(dir, "inputs"), Path.Combine(dir, "inputs", "local")));
        // Real signature checks, as the PowerShell tray did when it wrote the fixture (signer allows depend on them)
        var model = new ModelBuilder(inputs, new Native.AuthenticodeSigners()).Build();
        var actual = ModelDump.ToJson(model, ModelBuilder.GetOverall(model, inputs.Status, now), now);

        foreach (var line in ModelDump.Summary(model, ModelBuilder.GetOverall(model, inputs.Status, now))) output.WriteLine(line);
        var diffs = ParityCheck.Compare(expected, actual);
        foreach (var d in diffs) output.WriteLine(d);
        Assert.True(diffs.Count == 0, $"{diffs.Count} difference(s):\n" + string.Join("\n", diffs.Take(15)));
    }
}
