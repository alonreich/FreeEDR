using System.Diagnostics;
using Edr.Core;
using Edr.Core.Native;
using Microsoft.Win32;

namespace Edr.Setup;

internal sealed class SetupLog : IDisposable
{
    private readonly StreamWriter? _file;
    private readonly Lock _gate = new();
    public int Warnings { get; private set; }
    public event Action<char, string>? Line;

    public SetupLog(string? path)
    {
        if (path is null) return;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            _file = new StreamWriter(path, append: false, JsonFile.Utf8NoBom) { AutoFlush = true };
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }

    private void Write(char kind, string text, string raw)
    {
        lock (_gate) _file?.WriteLine($"{DateTime.Now:HH:mm:ss} {text}");
        Line?.Invoke(kind, raw);
    }

    public void Step(string t) => Write('S', $"\n== {t}", t);
    public void Ok(string t) => Write('O', $"   OK   {t}", t);
    public void Warn(string t) { Warnings++; Write('W', $"   WARN {t}", t); }
    public void Info(string t) => Write('I', $"   {t}", t);
    public void Error(string t) => Write('E', $"\nERROR: {t}", t);
    public void Result(string label, string result, bool good) => Write('R', $"\n{label}: {result}", result);

    public void Note(string n)
    {
        if (n.StartsWith("WARN ", StringComparison.Ordinal)) Warn(n[5..]);
        else Ok(n.StartsWith("OK ", StringComparison.Ordinal) ? n[3..] : n);
    }

    public void Dispose() => _file?.Dispose();
}

internal static class Sys
{
    public static (int Exit, string Output) Run(string exe, params string[] args) => Tools.RunCapture(exe, args, EdrPaths.System32, 300);

    public static string Sys32(string exe) => Path.Combine(EdrPaths.System32, exe);

    public static void StopFreeEdrProcesses(EdrPaths paths, bool includeTools)
    {
        foreach (var ev in new[] { @"Local\FreeEDR-Tray-Exit", @"Local\EDR-Tray-Exit" })
            try { using var h = EventWaitHandle.OpenExisting(ev); h.Set(); } catch (WaitHandleCannotBeOpenedException) { } catch (UnauthorizedAccessException) { }
        Thread.Sleep(1500);
        var me = Environment.ProcessId;
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                if (p.Id == me || p.Id <= 4) continue;
                var (path, _) = Win32.ImageAndStart(p.Id);
                var name = Path.GetFileName(path);
                var ours = path.StartsWith(paths.Root + "\\", StringComparison.OrdinalIgnoreCase) &&
                           (includeTools || name.StartsWith("FreeEDR-", StringComparison.OrdinalIgnoreCase)) &&
                           !path.Contains(@"\setup-src\", StringComparison.OrdinalIgnoreCase) && !IsUpdateDownload(paths, path);
                if (!ours && (Ps.Eq(name, "powershell.exe") || Ps.Eq(name, "pwsh.exe")))
                    ours = Ps.Rx(@"EDR-(Engine|Tray|Scan|Control)\.ps1").IsMatch(Win32.CommandLineOf(p.Id));
                if (ours) Win32.Kill(p.Id);
            }
        }
    }

    public static bool IsUpdateDownload(EdrPaths paths, string path) =>
        path.StartsWith(paths.UserDir + "\\", StringComparison.OrdinalIgnoreCase) &&
        (path.Contains(@"\update\", StringComparison.OrdinalIgnoreCase) || Path.GetFileName(path).StartsWith("FreeEDR-Setup", StringComparison.OrdinalIgnoreCase) ||
         Path.GetFileName(path).StartsWith("FreeEDR-Update", StringComparison.OrdinalIgnoreCase));

    public static bool TaskExists(string name) => Run(Sys32("schtasks.exe"), "/Query", "/TN", name).Exit == 0;

    public static void TaskEnd(string name) { if (TaskExists(name)) Run(Sys32("schtasks.exe"), "/End", "/TN", name); }

    public static void TaskDisable(string name) { if (TaskExists(name)) { TaskEnd(name); Run(Sys32("schtasks.exe"), "/Change", "/TN", name, "/DISABLE"); } }

    public static void TaskEnable(string name) { if (TaskExists(name)) { Run(Sys32("schtasks.exe"), "/Change", "/TN", name, "/ENABLE"); Run(Sys32("schtasks.exe"), "/Run", "/TN", name); } }

    public static bool TaskDelete(string name) => !TaskExists(name) || Run(Sys32("schtasks.exe"), "/Delete", "/TN", name, "/F").Exit == 0;

    public static List<(string Name, string Image)> SysmonServices()
    {
        var list = new List<(string, string)>();
        using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        if (k is null) return list;
        foreach (var n in k.GetSubKeyNames())
        {
            using var s = k.OpenSubKey(n);
            var img = s?.GetValue("ImagePath") as string ?? "";
            var desc = s?.GetValue("Description") as string ?? "";
            var type = s?.GetValue("Type") is int t ? t : 0;
            if (type is 0x10 or 0x20 && (Ps.Match(img, @"\\sysmon(64a?)?\.exe") || desc.StartsWith("System Monitor service", StringComparison.OrdinalIgnoreCase)))
                list.Add((n, img));
        }
        return list;
    }

    public static bool EventSourceExists(string source)
    {
        using var k = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\EventLog\Application\{source}");
        return k is not null;
    }

    public static void CreateEventSource(string source)
    {
        using var k = Registry.LocalMachine.CreateSubKey($@"SYSTEM\CurrentControlSet\Services\EventLog\Application\{source}");
        k.SetValue("EventMessageFile", @"%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll", RegistryValueKind.ExpandString);
        k.SetValue("TypesSupported", 7, RegistryValueKind.DWord);
    }

    public static void DeleteEventSource(string source) =>
        Registry.LocalMachine.DeleteSubKeyTree($@"SYSTEM\CurrentControlSet\Services\EventLog\Application\{source}", throwOnMissingSubKey: false);

    public static void ForEachUserHive(Action<RegistryKey> action)
    {
        using var list = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
        if (list is null) return;
        foreach (var sid in list.GetSubKeyNames().Where(s => Ps.Rx(@"^S-1-(5-21|12-1)-[\d-]+$").IsMatch(s)))
        {
            using (var loaded = Registry.Users.OpenSubKey(sid, writable: true))
            {
                if (loaded is not null) { try { action(loaded); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { } continue; }
            }
            using var pk = list.OpenSubKey(sid);
            var profile = Environment.ExpandEnvironmentVariables(pk?.GetValue("ProfileImagePath") as string ?? "");
            var dat = Path.Combine(profile, "NTUSER.DAT");
            if (!File.Exists(dat)) continue;
            var tmp = $"FreeEDR-{sid}";
            if (Run(Sys32("reg.exe"), "load", $@"HKU\{tmp}", dat).Exit != 0) continue;
            try
            {
                using var h = Registry.Users.OpenSubKey(tmp, writable: true);
                if (h is not null) action(h);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
            finally
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
                Run(Sys32("reg.exe"), "unload", $@"HKU\{tmp}");
            }
        }
    }

    public static string CommonPrograms => Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms);
    public static string CommonDesktop => Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory);
}
