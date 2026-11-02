using System.Globalization;
using System.Text.Json.Nodes;
using Edr.Core;
using Edr.Core.Native;

namespace Edr.Tray;

/// <summary>
/// --selftest: the model from the live data, without UI (the C# side of EDR-Tray.ps1 -SelfTest).
/// --dump &lt;folder&gt; also writes model.json. --compare &lt;folder&gt; instead reads a PowerShell dump folder
/// (inputs\ + model.json from EDR_SELFTEST_DUMP), builds the model from the same inputs and lists the differences.
/// </summary>
internal static class SelfTest
{
    public static int Run(EdrPaths paths, string? dumpDir, string? compareDir)
    {
        try
        {
            var now = DateTime.Now;
            JsonNode? expected = null;
            if (compareDir is not null)
            {
                expected = JsonNode.Parse(File.ReadAllText(Path.Combine(compareDir, "model.json")))!;
                now = DateTime.ParseExact(expected["now"]!.GetValue<string>(), "yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture);
                paths = new EdrPaths(Path.Combine(compareDir, "inputs"), Path.Combine(compareDir, "inputs", "local"));
            }
            var inputs = EdrInputs.Load(paths);
            var model = new ModelBuilder(inputs, new AuthenticodeSigners()).Build();
            var overall = ModelBuilder.GetOverall(model, inputs.Status, now);
            foreach (var line in ModelDump.Summary(model, overall)) Console.Out.WriteLine(line);
            var json = ModelDump.ToJson(model, overall, now);
            if (dumpDir is not null)
            {
                Directory.CreateDirectory(dumpDir);
                File.WriteAllText(Path.Combine(dumpDir, "model.json"), ModelDump.Write(json));
                Console.Out.WriteLine($"Dump  : {dumpDir}");
            }
            var rc = 0;
            if (expected is not null)
            {
                var diffs = ParityCheck.Compare(expected, json);
                Console.Out.WriteLine(diffs.Count == 0 ? "Parity: OK (same model as the PowerShell tray)" : $"Parity: {diffs.Count} difference(s)");
                foreach (var d in diffs) Console.Out.WriteLine("  " + d);
                rc = diffs.Count == 0 ? 0 : 2;
            }
            Console.Out.Flush();
            return rc;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"Self-test failed: {e}");
            return 1;
        }
    }
}
