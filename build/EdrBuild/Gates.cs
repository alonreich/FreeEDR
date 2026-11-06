using System.Text;

namespace EdrBuild;

/// <summary>Checks a build must pass before anything is packed (docs/agents/AGENT_WORKFLOW.md §3).</summary>
internal static class Gates
{
    /// <summary>Data files installed next to the programs (the programs themselves come from the NativeAOT publish).</summary>
    public static readonly string[] DataFiles =
    [
        @"config\sysmonconfig.template.xml", @"rules\custom_edr.yar", @"rules\ransomware.yar",
        "README.md", @"docs\user\USER_GUIDE.md", @"docs\install\INSTALLATION.md", @"docs\install\UNINSTALL.md",
    ];

    /// <summary>The NativeAOT programs: project folder under src\, output folder in bin\ of the install, exe name.</summary>
    public static readonly (string Project, string BinSub, string Exe)[] Programs =
    [
        ("Edr.Engine", "", "FreeEDR-Engine.exe"),
        ("Edr.Control", "", "FreeEDR-Control.exe"),
        ("Edr.Setup", "", "FreeEDR-Installer.exe"),
        ("Edr.Tray", "tray", "FreeEDR-Tray.exe"),
    ];

    public static bool ProjectFiles(string root, BuildLog log)
    {
        var missing = DataFiles.Where(f => !File.Exists(Path.Combine(root, f))).ToList();
        foreach (var f in missing) log.Error($"project file missing: {f}");
        foreach (var (p, _, _) in Programs)
            if (!File.Exists(Path.Combine(root, "src", p, p + ".csproj"))) { log.Error($"project missing: src\\{p}\\{p}.csproj"); missing.Add(p); }
        if (missing.Count > 0) return false;
        log.Success($"[Files] {DataFiles.Length} data files and {Programs.Length} programs");
        return true;
    }

    /// <summary>*.yar plain ASCII without BOM (YARA rejects a BOM); *.md and *.xml valid UTF-8.</summary>
    public static bool Encodings(string root, BuildLog log)
    {
        var ok = true;
        foreach (var f in DataFiles)
        {
            var bytes = File.ReadAllBytes(Path.Combine(root, f));
            var bom = bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF;
            if (f.EndsWith(".yar", StringComparison.OrdinalIgnoreCase) && (bom || bytes.Any(b => b > 0x7F))) { log.Error($"{f}: must be ASCII without BOM"); ok = false; }
            if (f.EndsWith(".md", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
            {
                try { _ = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(bytes); }
                catch (DecoderFallbackException) { log.Error($"{f}: not valid UTF-8"); ok = false; }
            }
        }
        if (ok) log.Success("[Encoding] .yar ASCII without BOM, docs and config valid UTF-8");
        return ok;
    }

    /// <summary>C# tests: rules, detection decisions, Sysmon corpus, golden dashboard models, engine internals.</summary>
    public static bool DotnetTests(string root, BuildLog log)
    {
        var rc = Cli.Run("dotnet", ["test", "--project", Path.Combine(root, "src", "Edr.Core.Tests"), "-c", "Release"], log, Path.Combine(root, "src"));
        if (rc != 0) { log.Error($"C# tests failed (exit {rc})"); return false; }
        log.Success("[Tests] C# tests passed");
        return true;
    }

    /// <summary>Every program publishes as NativeAOT with no warnings (warnings are errors).</summary>
    public static bool Publish(string root, string outDir, string version, BuildLog log)
    {
        Cli.EnsureVswhereOnPath();
        foreach (var (project, _, exe) in Programs)
        {
            var dir = Path.Combine(outDir, project);
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
            var rc = Cli.Run("dotnet", ["publish", Path.Combine(root, "src", project), "-c", "Release", "-o", dir, $"-p:Version={version}", $"-p:FileVersion={version}", $"-p:InformationalVersion={version}"],
                             log, Path.Combine(root, "src"), quiet: true);
            var path = Path.Combine(dir, exe);
            if (rc != 0 || !File.Exists(path)) { log.Error($"NativeAOT publish of {project} failed (exit {rc})"); return false; }
            log.Success($"[NativeAOT] {exe}  {new FileInfo(path).Length / 1024.0 / 1024.0:0.0} MB");
        }
        return true;
    }

    /// <summary>
    /// Optional code signing (signtool). Configure one of:
    ///   EDR_SIGN_THUMBPRINT  = SHA1 thumbprint of a code-signing certificate in the current user's or machine's store
    ///   EDR_SIGN_DLIB + EDR_SIGN_METADATA = Azure Trusted Signing (Azure.CodeSigning.Dlib.dll and its metadata.json)
    /// Without either, the build stays unsigned (WARN). A configured signing that fails fails the build.
    /// </summary>
    public static bool Sign(IEnumerable<string> files, BuildLog log)
    {
        var thumb = Environment.GetEnvironmentVariable("EDR_SIGN_THUMBPRINT");
        var dlib = Environment.GetEnvironmentVariable("EDR_SIGN_DLIB");
        var meta = Environment.GetEnvironmentVariable("EDR_SIGN_METADATA");
        var list = files.Where(File.Exists).ToList();
        if (string.IsNullOrWhiteSpace(thumb) && (string.IsNullOrWhiteSpace(dlib) || string.IsNullOrWhiteSpace(meta)))
        {
            log.Warn($"[Signing] not configured: {list.Count} file(s) left unsigned (SmartScreen may warn). See docs\\agents\\AGENT_WORKFLOW.md §3 (code signing).");
            return true;
        }
        var signtool = Cli.FindSigntool();
        if (signtool is null) { log.Error("[Signing] configured, but signtool.exe (Windows SDK) was not found. Set EDR_SIGNTOOL."); return false; }
        var args = new List<string> { "sign", "/fd", "SHA256", "/tr", Environment.GetEnvironmentVariable("EDR_SIGN_TIMESTAMP") ?? "http://timestamp.acs.microsoft.com", "/td", "SHA256" };
        if (!string.IsNullOrWhiteSpace(thumb)) args.AddRange(["/sha1", thumb.Trim()]);
        else args.AddRange(["/dlib", dlib!, "/dmdf", meta!]);
        args.AddRange(list);
        var rc = Cli.Run(signtool, args, log, quiet: true);
        if (rc != 0) { log.Error($"[Signing] signtool failed (exit {rc})"); return false; }
        log.Success($"[Signing] {list.Count} file(s) signed");
        return true;
    }

    /// <summary>Read-only smoke test on this PC's live data: the published tray builds the model from the installed FreeEDR.</summary>
    public static bool LiveSelfTest(string trayExe, BuildLog log)
    {
        var installed = Path.Combine(Environment.GetEnvironmentVariable("ProgramW6432") ?? Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "FreeEDR");
        if (!File.Exists(Path.Combine(installed, "data", "status.json"))) { log.Info($"[Self-test] skipped: FreeEDR is not installed on this PC ({installed})"); return true; }
        var rc = Cli.Run(trayExe, ["--selftest"], log, quiet: true);
        if (rc != 0) { log.Error($"the tray could not build its model from this PC's live data (exit {rc})"); return false; }
        log.Success("[Self-test] the tray builds its model from this PC's live data");
        return true;
    }
}
