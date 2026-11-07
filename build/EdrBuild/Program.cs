using System.Security.Cryptography;
using Edr.Core;

namespace EdrBuild;

/// <summary>
/// EdrBuild - builds .\compiled\FreeEDR-Setup.exe, the single-file installer of FreeEDR.
/// Pipeline: data files -> encodings -> C# tests -> NativeAOT publish of the engine, control helper, installer and
/// tray -> live self-test of the tray -> staging (+ optional code signing) -> Inno Setup -> exactly one file in .\compiled.
/// Release (build.cmd) wipes .\compiled first; dev (dev_build.cmd, --dev) only replaces the installer and marks the
/// version as a dev build. Nothing is installed and nothing leaves this PC.
/// Exit codes: 0 = OK, 1 = BUILD FAILED.
/// </summary>
internal static class Program
{
    private const string SetupName = "FreeEDR-Setup.exe";

    private static int Main(string[] args)
    {
        if (args.Any(a => a is "--help" or "-h" or "/?"))
        {
            Console.WriteLine("Usage: build.cmd | dev_build.cmd [--skip-live]");
            Console.WriteLine("  build.cmd      release build: .\\compiled is wiped first, then holds only FreeEDR-Setup.exe");
            Console.WriteLine("  dev_build.cmd  local dev build (--dev): .\\compiled is not wiped, the version says \"dev\"");
            Console.WriteLine("  --skip-live    skip the self-test of the tray on this PC's live FreeEDR data");
            Console.WriteLine("  Code signing (optional): EDR_SIGN_THUMBPRINT, or EDR_SIGN_DLIB + EDR_SIGN_METADATA (Azure Trusted Signing)");
            return 0;
        }
        var dev = args.Contains("--dev", StringComparer.OrdinalIgnoreCase);
        var skipLive = args.Contains("--skip-live", StringComparer.OrdinalIgnoreCase);
        var root = FindRoot();
        Environment.CurrentDirectory = root;
        try { Console.OutputEncoding = System.Text.Encoding.UTF8; } catch (IOException) { }

        var started = DateTime.Now;
        using var log = new BuildLog(Path.Combine(root, "build.log"));
        var ok = false;
        try { ok = Run(root, dev, skipLive, log); }
        catch (Exception e) { log.Error($"unhandled build failure: {e}"); }

        log.Banner("###########################################################");
        if (ok)
        {
            log.Success(dev ? "SUCCESS: local dev build completed." : "SUCCESS: release build completed.");
            log.Info($"Installer: {Path.Combine(root, "compiled", SetupName)}");
        }
        else
        {
            log.Error("BUILD FAILED - scroll up for the first ERROR line, or read .\\build.log");
        }
        log.Info("Log file:  .\\build.log  (first line: OK / WARN / FAIL)");
        log.Banner("###########################################################");
        log.Close(ok, DateTime.Now - started);
        return ok ? 0 : 1;
    }

    private static bool Run(string root, bool dev, bool skipLive, BuildLog log)
    {
        // Numeric for the file version resource (each part <= 65535): 2026.11.1.2315
        var now = DateTime.Now;
        var version = $"{now:yyyy}.{now.Month}.{now.Day}.{now:HHmm}";
        var versionText = dev ? $"{version} (dev build)" : version;
        var obj = Path.Combine(root, "obj", "EdrBuild");
        var publish = Path.Combine(obj, "publish");
        var staging = Path.Combine(obj, "Staging");
        var compiled = Path.Combine(root, "compiled");

        log.Banner("###########################################################");
        log.Banner($"BUILDING FreeEDR {versionText}");
        log.Banner("###########################################################");

        log.Banner("1. Checking the project files...");
        if (!Gates.ProjectFiles(root, log)) return false;
        if (!Gates.Encodings(root, log)) return false;

        log.Banner("2. C# tests...");
        if (!Gates.DotnetTests(root, log)) return false;

        log.Banner("3. NativeAOT publish (engine, control helper, installer, tray)...");
        if (!Gates.Publish(root, publish, version, log)) return false;
        var trayExe = Path.Combine(publish, "Edr.Tray", "FreeEDR-Tray.exe");
        if (skipLive) log.Warn("[Self-test] skipped on request (--skip-live)");
        else if (!Gates.LiveSelfTest(trayExe, log)) return false;

        log.Banner("4. Staging...");
        if (Directory.Exists(staging)) Directory.Delete(staging, true);
        var n = 0;
        foreach (var (project, sub, _) in Gates.Programs)
        {
            var to = Path.Combine(staging, "bin", sub);
            Directory.CreateDirectory(to);
            foreach (var f in Directory.GetFiles(Path.Combine(publish, project)).Where(f => !f.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase)))
            {
                File.Copy(f, Path.Combine(to, Path.GetFileName(f)), true);
                n++;
            }
        }
        foreach (var f in Gates.DataFiles)
        {
            var to = Path.Combine(staging, f);
            Directory.CreateDirectory(Path.GetDirectoryName(to)!);
            File.Copy(Path.Combine(root, f), to);
            n++;
        }
        if (!Gates.Sign(Directory.GetFiles(Path.Combine(staging, "bin"), "FreeEDR-*.exe", SearchOption.AllDirectories), log)) return false;
        if (!EmbedTools(root, staging, log)) return false;
        log.Success($"[Staging] {n} files -> {staging}");

        log.Banner("5. Building the installer (Inno Setup)...");
        var iscc = Cli.FindIscc();
        if (iscc is null)
        {
            log.Error("Inno Setup was not found. It is free: winget install JRSoftware.InnoSetup (6.3 or newer), or set EDR_ISCC to ISCC.exe.");
            return false;
        }
        if (dev) log.Info("[Compiled] dev build: .\\compiled is not wiped, only the installer is replaced");
        else if (Directory.Exists(compiled)) { Directory.Delete(compiled, true); log.Info("[Compiled] .\\compiled wiped (release build)"); }
        Directory.CreateDirectory(compiled);
        var output = Path.Combine(compiled, SetupName);
        if (File.Exists(output)) File.Delete(output);
        var rc = Cli.Run(iscc,
        [
            "/Qp", "/DAppVersion=" + version, "/DAppVersionText=" + versionText,
            "/DStagingDir=" + staging, "/DOutputDir=" + compiled,
            Path.Combine(root, "build", "installer", "FreeEDR-Setup.iss"),
        ], log);
        if (rc != 0 || !File.Exists(output)) { log.Error($"Inno Setup failed (exit {rc}); the installer was not produced"); return false; }
        if (!Gates.Sign([output], log)) return false;

        log.Banner("6. Validating .\\compiled...");
        if (!ValidateCompiled(compiled, output, log)) return false;
        using (var fs = File.OpenRead(output))
            log.Success($"[Installer] {SetupName}  {new FileInfo(output).Length / 1024.0 / 1024.0:0.0} MB  SHA256 {Convert.ToHexString(SHA256.HashData(fs))}");
        Directory.Delete(staging, true);
        return true;
    }

    /// <summary>
    /// The baseline ships inside Setup: the pinned tools (Hayabusa with its rules, YARA, OSV-Scanner, Velociraptor), each
    /// checked against its pinned SHA256, plus a seed of the malware hash list. The installer then copies them instead of
    /// downloading; afterwards only updates are downloaded (dashboard "Update tool", the scan's rule and IOC updates).
    /// Downloads are cached in obj\tools-cache, so only the first build (or a new pin) needs the network.
    /// Sysmon is not embedded: Microsoft's Sysinternals license does not allow redistributing it, so the installer still
    /// downloads it from Microsoft (signature checked) when it is not installed yet.
    /// </summary>
    private static bool EmbedTools(string root, string staging, BuildLog log)
    {
        var cache = Path.Combine(root, "obj", "tools-cache");
        var cachePaths = new EdrPaths(cache, Path.Combine(cache, "user"));
        var tools = new Tools(cachePaths, s => log.Info("[Tools] " + s));
        var bin = Path.Combine(staging, "bin");
        var notices = new List<string>
        {
            "Third-party tools shipped with FreeEDR (unchanged release binaries, SHA256-checked against the pinned values):", "",
        };
        foreach (var t in Tools.Pinned)
        {
            try { tools.EnsurePinned(t).GetAwaiter().GetResult(); }
            catch (Exception e) when (e is IOException or InvalidDataException or HttpRequestException)
            {
                log.Error($"[Tools] {t.Name} {t.Tag}: {e.Message} (needed once to fill obj\tools-cache)");
                return false;
            }
            var exe = tools.ExePath(t);
            if (!File.Exists(exe) || !string.Equals(Tools.Sha256Of(exe), t.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                log.Error($"[Tools] {t.Name}: {exe} does not match the pinned SHA256 - delete obj\tools-cache and build again");
                return false;
            }
            if (t.Name == "Hayabusa") CopyTree(cachePaths.HayabusaDir, Path.Combine(bin, "hayabusa"));
            else File.Copy(exe, Path.Combine(bin, Path.GetFileName(exe)), true);
            if (t.Name == "YARA" && File.Exists(cachePaths.YaracExe)) File.Copy(cachePaths.YaracExe, Path.Combine(bin, "yarac64.exe"), true);
            notices.Add($"{t.Name} {t.Tag}  https://github.com/{t.Repo}  ({License(t.Name)})");
            log.Success($"[Tools] {t.Name} {t.Tag} embedded (SHA256 {t.Sha256[..12]}...)");
        }
        notices.AddRange(["", "Source code and license texts: the project pages above (each release includes its LICENSE).",
                          "Microsoft Sysinternals Sysmon is not included; Setup downloads it from Microsoft."]);
        File.WriteAllLines(Path.Combine(staging, "docs", "THIRD_PARTY_NOTICES.txt"), notices);

        // Seed of the malware hash list (abuse.ch MalwareBazaar, CC0): used only when the PC has none yet
        var seed = Path.Combine(cache, "ioc_sha256.txt");
        try
        {
            if (!File.Exists(seed) || File.GetLastWriteTimeUtc(seed) < DateTime.UtcNow.AddDays(-1))
                tools.Download(new EdrConfig().IocFeedUrl, seed).GetAwaiter().GetResult();
        }
        catch (Exception e) when (e is IOException or HttpRequestException or TaskCanceledException) { log.Warn($"[Tools] malware hash seed not refreshed: {e.Message}"); }
        if (File.Exists(seed) && new FileInfo(seed).Length >= 1000)
        {
            Directory.CreateDirectory(Path.Combine(staging, "seed"));
            File.Copy(seed, Path.Combine(staging, "seed", "ioc_sha256.txt"), true);
            log.Success($"[Tools] malware hash seed embedded ({new FileInfo(seed).Length / 1024} KB, {File.GetLastWriteTime(seed):yyyy-MM-dd})");
        }
        else log.Warn("[Tools] no malware hash seed: the installer downloads it, the first scan retries");
        return true;
    }

    private static string License(string tool) => tool switch
    {
        "Hayabusa" => "AGPL-3.0; detection rules: DRL 1.1 / Sigma", "YARA" => "BSD-3-Clause", "OSV-Scanner" => "Apache-2.0", "Velociraptor" => "AGPL-3.0", _ => "see project",
    };

    private static void CopyTree(string from, string to)
    {
        Directory.CreateDirectory(to);
        foreach (var d in Directory.GetDirectories(from, "*", SearchOption.AllDirectories)) Directory.CreateDirectory(Path.Combine(to, Path.GetRelativePath(from, d)));
        foreach (var f in Directory.GetFiles(from, "*", SearchOption.AllDirectories)) File.Copy(f, Path.Combine(to, Path.GetRelativePath(from, f)), true);
    }

    /// <summary>.\compiled holds exactly one file: the installer. Anything else is removed and fails the build.</summary>
    private static bool ValidateCompiled(string compiled, string output, BuildLog log)
    {
        var ok = File.Exists(output);
        foreach (var entry in Directory.EnumerateFileSystemEntries(compiled))
        {
            if (string.Equals(entry, output, StringComparison.OrdinalIgnoreCase)) continue;
            log.Error($"removing a disallowed artifact from .\\compiled: {Path.GetFileName(entry)}");
            if (Directory.Exists(entry)) Directory.Delete(entry, true); else File.Delete(entry);
            ok = false;
        }
        if (ok) log.Success("[Compiled] exactly one file: " + Path.GetFileName(output));
        return ok;
    }

    private static string FindRoot()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
            if (File.Exists(Path.Combine(d.FullName, "project_structure.txt")) && Directory.Exists(Path.Combine(d.FullName, "build", "EdrBuild")))
                return d.FullName;
        return Environment.CurrentDirectory;
    }
}
