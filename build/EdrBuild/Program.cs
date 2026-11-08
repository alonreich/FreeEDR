using System.Security.Cryptography;
using Edr.Core;

namespace EdrBuild;

internal static class Program
{
    private const string SetupName = "FreeEDR-Setup.exe";

    private static int Main(string[] args)
    {
        if (args.Any(a => a is "--help" or "-h" or "/?"))
        {
            Console.WriteLine("Usage: build.cmd | dev_build.cmd [--skip-live]");
            Console.WriteLine("  build.cmd      release build: .\\compiled is wiped first, then holds FreeEDR-Setup.exe and FreeEDR-Update.exe (set EDR_BUILD_UPDATE=1 to build the update package in a dev build)");
            Console.WriteLine("  dev_build.cmd  local dev build (--dev): .\\compiled is not wiped, the version says \"dev\"");
            Console.WriteLine("  --skip-live    skip the self-test of the tray on this PC's live FreeEDR data");
            Console.WriteLine("  --promote-changelog <version> [--notes <file>]   move docs\\CHANGELOG.md's Unreleased entries under <version> (release workflow)");
            Console.WriteLine("  Release version: EDR_VERSION, else the v<version> tag on HEAD, else a local build 0.yyMM.ddHH.mm that ranks below every release (WARN)");
            Console.WriteLine("  Code signing: EDR_SIGN_THUMBPRINT, or EDR_SIGN_DLIB + EDR_SIGN_METADATA (Azure Trusted Signing).");
            Console.WriteLine("  Release builds must be signed; EDR_ALLOW_UNSIGNED=1 allows an unsigned release build (WARN).");
            return 0;
        }
        var promote = Array.FindIndex(args, a => a.Equals("--promote-changelog", StringComparison.OrdinalIgnoreCase));
        if (promote >= 0)
        {
            if (promote + 1 >= args.Length) { Console.Error.WriteLine("ERROR: --promote-changelog needs a version"); return 2; }
            var n = Array.FindIndex(args, a => a.Equals("--notes", StringComparison.OrdinalIgnoreCase));
            var r = FindRoot();
            return Release.Promote(r, args[promote + 1].TrimStart('v'), n >= 0 && n + 1 < args.Length ? args[n + 1] : Path.Combine(r, "obj", "release-notes.md"));
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
        BuildVersion bv;
        try { bv = Release.Compute(root, dev, DateTime.UtcNow, log); }
        catch (InvalidDataException e) { log.Error(e.Message); return false; }
        var version = bv.Numeric;
        var versionText = bv.Text;
        var requireSigning = !dev && Environment.GetEnvironmentVariable("EDR_ALLOW_UNSIGNED") != "1";
        var obj = Path.Combine(root, "obj", "EdrBuild");
        var publish = Path.Combine(obj, "publish");
        var staging = Path.Combine(obj, "Staging");
        var compiled = Path.Combine(root, "compiled");

        log.Banner("###########################################################");
        log.Banner($"BUILDING FreeEDR {versionText}");
        log.Banner("###########################################################");
        log.Info($"[Version] {version}  informational {bv.Informational}  commit {bv.Commit}");

        log.Banner("1. Checking the project files...");
        if (!Gates.ProjectFiles(root, log)) return false;
        if (!Gates.Encodings(root, log)) return false;
        if (!Release.ChangelogGate(root, bv, dev, log)) return false;

        log.Banner("2. C# tests...");
        if (!Gates.DotnetTests(root, log)) return false;

        log.Banner("3. NativeAOT publish (engine, control helper, installer, tray)...");
        if (!Gates.Publish(root, publish, version, bv.Informational, log)) return false;
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
        if (!Gates.Sign(Directory.GetFiles(Path.Combine(staging, "bin"), "FreeEDR-*.exe", SearchOption.AllDirectories), requireSigning, log)) return false;
        if (!EmbedTools(root, staging, dev, log)) return false;
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
        var update = Path.Combine(compiled, UpdateName);
        foreach (var f in new[] { output, output + ".sha256", update, update + ".sha256" }) if (File.Exists(f)) File.Delete(f);
        if (!Compile(root, iscc, "FreeEDR-Setup", staging, compiled, version, versionText, requireSigning, log)) return false;

        var slim = !dev || Environment.GetEnvironmentVariable("EDR_BUILD_UPDATE") == "1";
        var slimStaging = Path.Combine(obj, "StagingUpdate");
        if (slim)
        {
            log.Banner("5b. Building the update package (same programs, without the bundled third-party tools)...");
            if (Directory.Exists(slimStaging)) Directory.Delete(slimStaging, true);
            var kept = 0;
            foreach (var f in Directory.GetFiles(staging, "*", SearchOption.AllDirectories))
            {
                var rel = Path.GetRelativePath(staging, f);
                if (Tools.IsPackagedToolFile(rel)) continue;
                var to = Path.Combine(slimStaging, rel);
                Directory.CreateDirectory(Path.GetDirectoryName(to)!);
                File.Copy(f, to);
                kept++;
            }
            log.Info($"[Update] {kept} files; tools are kept from the installed copy, or downloaded and SHA256-checked against their pins when a pin changed");
            if (!Compile(root, iscc, "FreeEDR-Update", slimStaging, compiled, version, versionText, requireSigning, log)) return false;
        }
        else log.Info("[Update] dev build: the update package is not built (set EDR_BUILD_UPDATE=1 to build it)");

        log.Banner("6. Validating .\\compiled...");
        if (!ValidateCompiled(compiled, slim ? [output, update] : [output], log)) return false;
        foreach (var f in slim ? new[] { output, update } : [output])
            log.Success($"[Installer] {Path.GetFileName(f)}  {versionText}  {new FileInfo(f).Length / 1024.0 / 1024.0:0.0} MB  SHA256 {File.ReadAllText(f + ".sha256").Split(' ')[0]}  (also in {Path.GetFileName(f)}.sha256)");
        Directory.Delete(staging, true);
        if (Directory.Exists(slimStaging)) Directory.Delete(slimStaging, true);
        return true;
    }

    private const string UpdateName = "FreeEDR-Update.exe";

    private static bool Compile(string root, string iscc, string name, string staging, string compiled, string version, string versionText, bool requireSigning, BuildLog log)
    {
        var output = Path.Combine(compiled, name + ".exe");
        var rc = Cli.Run(iscc,
        [
            "/Qp", "/DAppVersion=" + version, "/DAppVersionText=" + versionText,
            "/DStagingDir=" + staging, "/DOutputDir=" + compiled, "/DOutputName=" + name,
            Path.Combine(root, "build", "installer", "FreeEDR-Setup.iss"),
        ], log);
        if (rc != 0 || !File.Exists(output)) { log.Error($"Inno Setup failed for {name}.exe (exit {rc}); it was not produced"); return false; }
        if (!Gates.Sign([output], requireSigning, log)) return false;
        string hash;
        using (var fs = File.OpenRead(output)) hash = Convert.ToHexString(SHA256.HashData(fs));
        File.WriteAllText(output + ".sha256", $"{hash}  {name}.exe\n");
        return true;
    }

    private static bool EmbedTools(string root, string staging, bool dev, BuildLog log)
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

        var seed = Path.Combine(cache, "ioc_sha256.txt");
        try
        {
            if (!File.Exists(seed) || File.GetLastWriteTimeUtc(seed) < DateTime.UtcNow.AddDays(-1))
                tools.Download(new EdrConfig().IocFeedUrl, seed).GetAwaiter().GetResult();
        }
        catch (Exception e) when (e is IOException or HttpRequestException or TaskCanceledException) { log.Warn($"[Tools] malware hash seed not refreshed: {e.Message}"); }
        if (File.Exists(seed) && new FileInfo(seed).Length >= SeedMinBytes)
        {
            Directory.CreateDirectory(Path.Combine(staging, "seed"));
            File.Copy(seed, Path.Combine(staging, "seed", "ioc_sha256.txt"), true);
            var seedHash = Tools.Sha256Of(seed);
            var stamp = File.GetLastWriteTimeUtc(seed).ToString("yyyy-MM-dd HH:mm 'UTC'");
            notices.AddRange(["", $"Malware hash seed (seed\\ioc_sha256.txt): {new EdrConfig().IocFeedUrl}, fetched {stamp}, SHA256 {seedHash}"]);
            log.Success($"[Tools] malware hash seed embedded ({new FileInfo(seed).Length / 1024} KB, fetched {stamp}, SHA256 {seedHash})");
        }
        else if (!dev)
        {
            log.Error($"[Tools] the malware hash seed is missing or smaller than {SeedMinBytes / 1024} KB: a release build must ship it (feed down? build again later)");
            return false;
        }
        else log.Warn("[Tools] no malware hash seed: the installer downloads it, the first scan retries");
        File.WriteAllLines(Path.Combine(staging, "docs", "THIRD_PARTY_NOTICES.txt"), notices);
        return true;
    }

    private const long SeedMinBytes = 64 * 1024;

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

    private static bool ValidateCompiled(string compiled, string[] outputs, BuildLog log)
    {
        var ok = outputs.All(o => File.Exists(o) && File.Exists(o + ".sha256"));
        var allowed = outputs.SelectMany(o => new[] { o, o + ".sha256" }).ToList();
        foreach (var entry in Directory.EnumerateFileSystemEntries(compiled))
        {
            if (allowed.Any(a => string.Equals(entry, a, StringComparison.OrdinalIgnoreCase))) continue;
            log.Error($"removing a disallowed artifact from .\\compiled: {Path.GetFileName(entry)}");
            if (Directory.Exists(entry)) Directory.Delete(entry, true); else File.Delete(entry);
            ok = false;
        }
        if (ok) log.Success($"[Compiled] only {string.Join(" and ", outputs.Select(Path.GetFileName))} with their .sha256");
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
