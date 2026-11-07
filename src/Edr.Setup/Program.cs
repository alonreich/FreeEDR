using Avalonia;
using Edr.Core;

namespace Edr.Setup;

internal sealed record SetupOptions(bool Silent, bool NoDesktopIcon, bool ReplaceSysmonConfig, string Version, bool FromSetup, bool NoPause, bool Clean = false);

internal enum SetupMode { Install, Uninstall }

/// <summary>What the setup window runs: the mode, the folders and the options from the command line.</summary>
internal sealed record SetupContext(SetupMode Mode, EdrPaths Paths, string Source, SetupOptions Options, string? Screenshot = null);

/// <summary>
/// FreeEDR-Installer.exe install [--source &lt;folder&gt;] [--silent] [--no-desktop-icon] [--replace-sysmon-config] [--clean] [--version &lt;text&gt;]
/// FreeEDR-Installer.exe uninstall [--from-setup] [--silent]
/// FreeEDR-Setup.exe (Inno Setup) unpacks the files to C:\Program Files\FreeEDR\setup-src and runs "install";
/// Settings > Apps > FreeEDR > Uninstall runs "uninstall --from-setup". Without --silent the work runs in the setup
/// window (Avalonia, the dashboard's theme; no console); with --silent it runs headless and writes the log only.
/// Exit codes: install 0/3/1 = success/rolled back/failed (4 = cancelled in the window); uninstall 0/1 = done/WARNs.
/// </summary>
internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        bool Has(string n) => args.Any(a => a.Equals(n, StringComparison.OrdinalIgnoreCase));
        string? Value(string n) { var i = Array.FindIndex(args, a => a.Equals(n, StringComparison.OrdinalIgnoreCase)); return i >= 0 && i + 1 < args.Length ? args[i + 1] : null; }
        var verb = args.FirstOrDefault()?.ToLowerInvariant() ?? "";
        var opt = new SetupOptions(Has("--silent"), Has("--no-desktop-icon"), Has("--replace-sysmon-config"), Value("--version") ?? "", Has("--from-setup"), Has("--no-pause"), Has("--clean"));
        // Always the real install folder: an elevated program must not take its settings/baseline folder from the caller
        var paths = new EdrPaths();
        var exeDir = Path.GetDirectoryName(Environment.ProcessPath) ?? ".";
        var source = Value("--source") ?? Path.GetFullPath(Path.Combine(exeDir, ".."));
        var mode = verb switch { "install" => SetupMode.Install, "uninstall" => SetupMode.Uninstall, _ => (SetupMode?)null };
        var shots = Value("--screenshot");   // development: render the window's pages to PNG and exit (installs nothing)
        if (shots is not null) mode = SetupMode.Install;
        if (mode is null) return 2;   // usage: see the summary above
        if (opt.Silent) return RunHeadless(new SetupContext(mode.Value, paths, source, opt), null);

        SetupApp.Context = new SetupContext(mode.Value, paths, source, opt, shots);
        return AppBuilder.Configure<SetupApp>().UsePlatformDetect().LogToTrace().StartWithClassicDesktopLifetime(args);
    }

    /// <summary>The work itself (also run by the window on a worker thread). <paramref name="onLine"/> receives every log line.</summary>
    public static int RunHeadless(SetupContext c, Action<char, string>? onLine)
    {
        if (c.Mode == SetupMode.Install)
        {
            Directory.CreateDirectory(c.Paths.Root);
            int rc;
            using (var log = new SetupLog(c.Paths.InstallLog))
            {
                if (onLine is not null) log.Line += onLine;
                rc = new Installer(c.Paths, c.Source, c.Options, log).Run();
            }
            try { File.Copy(c.Paths.InstallLog, Path.Combine(Path.GetTempPath(), "FreeEDR-install.log"), true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            return rc;
        }
        using var ulog = new SetupLog(Path.Combine(Path.GetTempPath(), "FreeEDR-uninstall.log"));
        if (onLine is not null) ulog.Line += onLine;
        return new Uninstaller(c.Paths, c.Options, ulog).Run();
    }
}
