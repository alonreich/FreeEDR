using System.Security.Cryptography;

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
        if (!Gates.Sign(Directory.GetFiles(Path.Combine(staging, "bin"), "*.exe", SearchOption.AllDirectories), log)) return false;
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
