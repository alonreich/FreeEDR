using Edr.Core;
using Edr.Core.Native;

namespace Edr.Engine;

internal static class Program
{
    // FreeEDR-Engine.exe            started by the service manager (service "FreeEDR", LocalSystem)
    // FreeEDR-Engine.exe --console  runs in the console until Ctrl+C (diagnostics; needs an elevated prompt)
    // FreeEDR-Engine.exe --root <d> uses another install folder (tests)
    private static int Main(string[] args)
    {
        var root = Value(args, "--root");
        var paths = new EdrPaths(root);
        if (args.Any(a => a.Equals("--console", StringComparison.OrdinalIgnoreCase)))
        {
            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
            Console.WriteLine($"FreeEDR engine (console). Install folder: {paths.Root}. Ctrl+C stops.");
            using var engine = new Engine(paths);
            return engine.Run(cts.Token);
        }
        var ran = ServiceHost.TryRun(EdrPaths.ServiceName, token =>
        {
            using var engine = new Engine(paths);
            engine.Run(token);
        });
        if (!ran)
        {
            Console.Error.WriteLine("FreeEDR-Engine.exe runs as the Windows service \"FreeEDR\". For diagnostics: FreeEDR-Engine.exe --console (elevated).");
            return 2;
        }
        return 0;
    }

    private static string? Value(string[] args, string name)
    {
        var i = Array.FindIndex(args, a => a.Equals(name, StringComparison.OrdinalIgnoreCase));
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }
}
