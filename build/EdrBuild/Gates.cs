using System.Text;
using System.Text.RegularExpressions;

namespace EdrBuild;

/// <summary>Checks a build must pass before anything is packed (Installation_Process.md §2 and §8).</summary>
internal static partial class Gates
{
    /// <summary>The files Install-EDR.ps1 copies ($ProjectFiles) - the installer packs exactly these.</summary>
    public static List<string>? ProjectFiles(string root, BuildLog log)
    {
        var installer = Path.Combine(root, "Install-EDR.ps1");
        var m = ProjectFilesRx().Match(File.ReadAllText(installer));
        if (!m.Success) { log.Error("Install-EDR.ps1: the $ProjectFiles list was not found"); return null; }
        var files = QuotedRx().Matches(m.Groups[1].Value).Select(x => x.Groups[1].Value).ToList();
        var missing = files.Where(f => !File.Exists(Path.Combine(root, f))).ToList();
        foreach (var f in missing) log.Error($"project file missing: {f}");
        if (missing.Count > 0 || files.Count == 0) return null;
        log.Success($"[Files] {files.Count} project files (from Install-EDR.ps1 $ProjectFiles)");
        return files;
    }

    /// <summary>*.ps1 UTF-8 with BOM (PowerShell 5.1 reads BOM-less files as ANSI); *.yar plain ASCII, no BOM (YARA rejects it).</summary>
    public static bool Encodings(string root, IEnumerable<string> files, BuildLog log)
    {
        var ok = true;
        foreach (var f in files)
        {
            var bytes = File.ReadAllBytes(Path.Combine(root, f));
            var bom = bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF;
            if (f.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase) && !bom) { log.Error($"{f}: must be UTF-8 with BOM"); ok = false; }
            if (f.EndsWith(".yar", StringComparison.OrdinalIgnoreCase) && (bom || bytes.Any(b => b > 0x7F))) { log.Error($"{f}: must be ASCII without BOM"); ok = false; }
            if (f.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".md", StringComparison.OrdinalIgnoreCase))
            {
                try { _ = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(bytes); }
                catch (DecoderFallbackException) { log.Error($"{f}: not valid UTF-8"); ok = false; }
            }
        }
        if (ok) log.Success("[Encoding] .ps1 UTF-8 with BOM, .yar ASCII without BOM");
        return ok;
    }

    /// <summary>Every script parses in Windows PowerShell 5.1 (the engine and tray target 5.1, not PowerShell 7).</summary>
    public static bool PowerShellParse(string root, IEnumerable<string> files, string workDir, BuildLog log)
    {
        var scripts = files.Where(f => f.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase)).Select(f => Path.Combine(root, f)).ToList();
        Directory.CreateDirectory(workDir);
        var check = Path.Combine(workDir, "parse-check.ps1");
        File.WriteAllText(check, """
            $bad = 0
            foreach ($f in $args) {
                $e = $null
                [void][Management.Automation.Language.Parser]::ParseFile($f, [ref]$null, [ref]$e)
                foreach ($x in $e) { "{0}:{1}: {2}" -f (Split-Path $f -Leaf), $x.Extent.StartLineNumber, $x.Message; $bad++ }
            }
            exit $bad
            """, new UTF8Encoding(true));
        var rc = Cli.Run(Cli.WindowsPowerShell, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", check, .. scripts], log);
        if (rc != 0) { log.Error($"PowerShell 5.1 parse: {rc} error(s)"); return false; }
        log.Success($"[PowerShell] {scripts.Count} scripts parse in Windows PowerShell 5.1");
        return true;
    }

    /// <summary>C# tests (tray core, parity with the PowerShell tray on the fixtures, signatures).</summary>
    public static bool DotnetTests(string root, BuildLog log)
    {
        var rc = Cli.Run("dotnet", ["test", "--project", Path.Combine(root, "src", "Edr.Core.Tests"), "-c", "Release"], log, Path.Combine(root, "src"));
        if (rc != 0) { log.Error($"C# tests failed (exit {rc})"); return false; }
        log.Success("[Tests] C# tests passed (incl. parity with the PowerShell tray)");
        return true;
    }

    /// <summary>The C# tray still publishes as NativeAOT with no warnings (it is packed from phase 5 of the tray rewrite).</summary>
    public static bool TrayPublish(string root, string outDir, BuildLog log)
    {
        Cli.EnsureVswhereOnPath();
        var rc = Cli.Run("dotnet", ["publish", Path.Combine(root, "src", "Edr.Tray"), "-c", "Release", "-o", outDir], log, Path.Combine(root, "src"), quiet: true);
        var exe = Path.Combine(outDir, "FreeEDR-Tray.exe");
        if (rc != 0 || !File.Exists(exe)) { log.Error($"NativeAOT publish of the C# tray failed (exit {rc})"); return false; }
        log.Success($"[Tray] NativeAOT publish OK ({new FileInfo(exe).Length / (1024 * 1024)} MB; not packed yet)");
        return true;
    }

    /// <summary>
    /// Smoke test on this PC's live data, read-only: the PowerShell tray's -SelfTest runs to the end, and the C# tray
    /// builds the same model from the inputs it read. Skipped when FreeEDR is not installed here (C:\Program Files\FreeEDR).
    /// </summary>
    public static bool LiveSelfTest(string root, string trayExe, string workDir, BuildLog log)
    {
        var installed = Path.Combine(Environment.GetEnvironmentVariable("ProgramW6432") ?? Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "FreeEDR");
        if (!File.Exists(Path.Combine(installed, "data", "status.json"))) { log.Info($"[Self-test] skipped: FreeEDR is not installed on this PC ({installed})"); return true; }
        var dump = Path.Combine(workDir, "parity");
        if (Directory.Exists(dump)) Directory.Delete(dump, true);
        Environment.SetEnvironmentVariable("EDR_SELFTEST_DUMP", dump);
        int rc;
        try { rc = Cli.Run(Cli.WindowsPowerShell, ["-NoProfile", "-ExecutionPolicy", "Bypass", "-STA", "-File", Path.Combine(root, "EDR-Tray.ps1"), "-SelfTest"], log, quiet: true); }
        finally { Environment.SetEnvironmentVariable("EDR_SELFTEST_DUMP", null); }
        try
        {
            if (rc != 0 || !File.Exists(Path.Combine(dump, "model.json"))) { log.Error($"EDR-Tray.ps1 -SelfTest failed (exit {rc})"); return false; }
            rc = Cli.Run(trayExe, ["--selftest", "--compare", dump], log);
            if (rc != 0) { log.Error("the C# tray's model differs from the PowerShell tray on the live data"); return false; }
        }
        finally
        {
            // The dump is a copy of this PC's live data (events, command lines, user names): never left behind
            try { if (Directory.Exists(dump)) Directory.Delete(dump, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
        log.Success("[Self-test] both trays build the same model from this PC's live data");
        return true;
    }

    [GeneratedRegex(@"\$ProjectFiles\s*=\s*@\((.*?)\)", RegexOptions.Singleline)]
    private static partial Regex ProjectFilesRx();

    [GeneratedRegex(@"'([^']+)'")]
    private static partial Regex QuotedRx();
}
