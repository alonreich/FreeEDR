using Edr.Core;

namespace Edr.Setup;

internal sealed record SetupOptions(bool Silent, bool NoDesktopIcon, bool ReplaceSysmonConfig, string Version, bool FromSetup, bool NoPause);

/// <summary>
/// FreeEDR-Installer.exe install [--source &lt;folder&gt;] [--silent] [--no-desktop-icon] [--replace-sysmon-config] [--version &lt;text&gt;] [--no-pause]
/// FreeEDR-Installer.exe uninstall [--from-setup] [--no-pause]
/// FreeEDR-Setup.exe (Inno Setup) unpacks the files to C:\Program Files\FreeEDR\setup-src and runs "install";
/// Settings > Apps > FreeEDR > Uninstall runs "uninstall --from-setup". Exit codes: install 0/3/1 = success/rolled back/failed.
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        bool Has(string n) => args.Any(a => a.Equals(n, StringComparison.OrdinalIgnoreCase));
        string? Value(string n) { var i = Array.FindIndex(args, a => a.Equals(n, StringComparison.OrdinalIgnoreCase)); return i >= 0 && i + 1 < args.Length ? args[i + 1] : null; }
        var verb = args.FirstOrDefault()?.ToLowerInvariant() ?? "";
        var opt = new SetupOptions(Has("--silent"), Has("--no-desktop-icon"), Has("--replace-sysmon-config"), Value("--version") ?? "", Has("--from-setup"), Has("--no-pause"));
        var paths = new EdrPaths(Value("--root"));
        int rc;
        switch (verb)
        {
            case "install":
            {
                var exeDir = Path.GetDirectoryName(Environment.ProcessPath) ?? ".";
                var source = Value("--source") ?? Path.GetFullPath(Path.Combine(exeDir, ".."));
                Directory.CreateDirectory(paths.Root);
                using var log = new SetupLog(paths.InstallLog);
                rc = new Installer(paths, source, opt, log).Run();
                try { File.Copy(paths.InstallLog, Path.Combine(Path.GetTempPath(), "FreeEDR-install.log"), true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
                break;
            }
            case "uninstall":
            {
                using var log = new SetupLog(Path.Combine(Path.GetTempPath(), "FreeEDR-uninstall.log"));
                rc = new Uninstaller(paths, opt, log).Run();
                break;
            }
            default:
                Console.WriteLine("Usage: FreeEDR-Installer.exe install [--source <folder>] [--silent] [--no-desktop-icon] [--replace-sysmon-config] [--version <text>]");
                Console.WriteLine("       FreeEDR-Installer.exe uninstall [--from-setup]");
                return 2;
        }
        if (!opt.NoPause && !opt.Silent && !opt.FromSetup && Environment.UserInteractive && !Console.IsInputRedirected)
        {
            Console.Write("\nPress Enter to close");
            Console.ReadLine();
        }
        return rc;
    }
}
