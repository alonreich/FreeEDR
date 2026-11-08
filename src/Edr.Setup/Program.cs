using Avalonia;
using Edr.Core;

namespace Edr.Setup;

internal sealed record SetupOptions(bool Silent, bool NoDesktopIcon, bool ReplaceSysmonConfig, string Version, bool FromSetup, bool NoPause, bool Clean = false, bool AllowDowngrade = false);

internal enum SetupMode { Install, Uninstall }

internal sealed record SetupContext(SetupMode Mode, EdrPaths Paths, string Source, SetupOptions Options, string? Screenshot = null);

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        bool Has(string n) => args.Any(a => a.Equals(n, StringComparison.OrdinalIgnoreCase));
        string? Value(string n) { var i = Array.FindIndex(args, a => a.Equals(n, StringComparison.OrdinalIgnoreCase)); return i >= 0 && i + 1 < args.Length ? args[i + 1] : null; }
        var verb = args.FirstOrDefault()?.ToLowerInvariant() ?? "";
        var opt = new SetupOptions(Has("--silent"), Has("--no-desktop-icon"), Has("--replace-sysmon-config"), Value("--version") ?? "", Has("--from-setup"), Has("--no-pause"), Has("--clean"), Has("--allow-downgrade"));
        var paths = new EdrPaths();
        var exeDir = Path.GetDirectoryName(Environment.ProcessPath) ?? ".";
        var source = Value("--source") ?? Path.GetFullPath(Path.Combine(exeDir, ".."));
        var mode = verb switch { "install" => SetupMode.Install, "uninstall" => SetupMode.Uninstall, _ => (SetupMode?)null };
        var shots = Value("--screenshot");
        if (shots is not null) mode = SetupMode.Install;
        if (mode is null) return 2;
        if (opt.Silent) return RunHeadless(new SetupContext(mode.Value, paths, source, opt), null);

        SetupApp.Context = new SetupContext(mode.Value, paths, source, opt, shots);
        return AppBuilder.Configure<SetupApp>().UsePlatformDetect().LogToTrace().StartWithClassicDesktopLifetime(args);
    }

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
