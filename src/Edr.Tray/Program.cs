using Avalonia;
using Edr.Core;

namespace Edr.Tray;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        var options = TrayOptions.Parse(args);
        var paths = new EdrPaths(options.Root, options.Local);
        if (options.SelfTest) return SelfTest.Run(paths, options.Dump, options.Compare);
        var log = new TrayLog(paths.TrayLog);

        using var instance = SingleInstance.Acquire(InstanceNames.For(options.Dev));
        if (instance is null) return 0;

        AppDomain.CurrentDomain.UnhandledException += (_, e) => log.Write($"Unhandled: {e.ExceptionObject}");
        if (!options.Dev && options.Screenshot is null && !Edr.Core.Native.Win32.RegisterRestart("--restarted")) log.Write("Could not register for restart after a crash");
        log.Write($"Tray started (PID {Environment.ProcessId}{(options.Dev ? ", dev" : "")})");
        try
        {
            return BuildAvaloniaApp(new TrayContext(options, paths, log, instance)).StartWithClassicDesktopLifetime(args);
        }
        finally { log.Write("Tray stopped"); }
    }

    public static AppBuilder BuildAvaloniaApp() => BuildAvaloniaApp(null);

    private static AppBuilder BuildAvaloniaApp(TrayContext? context) =>
        AppBuilder.Configure(() => new App(context)).UsePlatformDetect().LogToTrace();
}

internal sealed record TrayOptions(bool Show, bool Dev, bool SelfTest, string? Dump, string? Compare, string? Root = null, string? ToastTitle = null, string? ToastText = null, string? Screenshot = null, string? Local = null)
{
    public static TrayOptions Parse(string[] args)
    {
        bool Is(string a, string name) => a.Equals(name, StringComparison.OrdinalIgnoreCase) || a.Equals("-" + name.TrimStart('-'), StringComparison.OrdinalIgnoreCase);
        bool Has(string name) => args.Any(a => Is(a, name));
        string? Value(string name) { var i = Array.FindIndex(args, a => Is(a, name)); return i >= 0 && i + 1 < args.Length ? args[i + 1] : null; }
        return new TrayOptions(Has("--show"), Has("--dev"), Has("--selftest"), Value("--dump"), Value("--compare"), Value("--root"), Value("--toast-title"), Value("--toast-text"), Value("--screenshot"), Value("--local"));
    }
}

internal sealed record TrayContext(TrayOptions Options, EdrPaths Paths, TrayLog Log, SingleInstance Instance);
