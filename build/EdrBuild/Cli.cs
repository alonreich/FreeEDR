using System.Diagnostics;

namespace EdrBuild;

internal static class Cli
{
    /// <summary>Runs a program, streams its output into the log, returns the exit code (-1 if it could not start).</summary>
    public static int Run(string exe, IEnumerable<string> args, BuildLog log, string? workDir = null, bool quiet = false)
    {
        var psi = new ProcessStartInfo(exe)
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true,
            WorkingDirectory = workDir ?? Environment.CurrentDirectory,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        // A build started from PowerShell 7 passes on its PSModulePath; Windows PowerShell 5.1 then fails to load
        // Microsoft.PowerShell.Security (Get-AuthenticodeSignature), so every signature-tied allow silently stops matching.
        // Without the variable, 5.1 uses its own default module path.
        if (string.Equals(exe, WindowsPowerShell, StringComparison.OrdinalIgnoreCase)) psi.Environment.Remove("PSModulePath");
        try
        {
            using var p = Process.Start(psi)!;
            p.OutputDataReceived += (_, e) => { if (!quiet && !string.IsNullOrWhiteSpace(e.Data)) log.Child(e.Data); };
            p.ErrorDataReceived += (_, e) => { if (!string.IsNullOrWhiteSpace(e.Data)) log.Child(e.Data); };
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();
            p.WaitForExit();
            return p.ExitCode;
        }
        catch (System.ComponentModel.Win32Exception e)
        {
            log.Error($"cannot start {exe}: {e.Message}");
            return -1;
        }
    }

    public static string? FindOnPath(string exe) =>
        (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator)
            .Select(d => Path.Combine(d.Trim('"'), exe)).FirstOrDefault(File.Exists);

    /// <summary>Inno Setup's compiler: EDR_ISCC, PATH, then the default install folders.</summary>
    public static string? FindIscc()
    {
        var configured = Environment.GetEnvironmentVariable("EDR_ISCC");
        if (!string.IsNullOrWhiteSpace(configured) && File.Exists(configured)) return configured;
        if (FindOnPath("ISCC.exe") is { } onPath) return onPath;
        foreach (var root in new[] { Environment.SpecialFolder.ProgramFilesX86, Environment.SpecialFolder.ProgramFiles })
        {
            var c = Path.Combine(Environment.GetFolderPath(root), "Inno Setup 6", "ISCC.exe");
            if (File.Exists(c)) return c;
        }
        var perUser = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Inno Setup 6", "ISCC.exe");
        return File.Exists(perUser) ? perUser : null;
    }

    /// <summary>signtool.exe: EDR_SIGNTOOL, PATH, then the newest Windows 10/11 SDK.</summary>
    public static string? FindSigntool()
    {
        var configured = Environment.GetEnvironmentVariable("EDR_SIGNTOOL");
        if (!string.IsNullOrWhiteSpace(configured) && File.Exists(configured)) return configured;
        if (FindOnPath("signtool.exe") is { } onPath) return onPath;
        var kits = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Windows Kits", "10", "bin");
        if (!Directory.Exists(kits)) return null;
        return Directory.GetDirectories(kits, "10.*").OrderByDescending(d => d, StringComparer.Ordinal)
                        .Select(d => Path.Combine(d, "x64", "signtool.exe")).FirstOrDefault(File.Exists);
    }

    /// <summary>The NativeAOT linker finds the C++ tools through vswhere.exe, which the VS installer does not put on PATH.</summary>
    public static void EnsureVswhereOnPath()
    {
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Microsoft Visual Studio", "Installer");
        var path = Environment.GetEnvironmentVariable("PATH") ?? "";
        if (File.Exists(Path.Combine(dir, "vswhere.exe")) && !path.Contains(dir, StringComparison.OrdinalIgnoreCase))
            Environment.SetEnvironmentVariable("PATH", path + Path.PathSeparator + dir);
    }

    public static string WindowsPowerShell => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
}
