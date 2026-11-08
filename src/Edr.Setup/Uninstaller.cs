using System.Text.Json.Nodes;
using Edr.Core;
using Edr.Core.Native;
using Microsoft.Win32;

namespace Edr.Setup;

internal sealed class Uninstaller(EdrPaths paths, SetupOptions opt, SetupLog log)
{
    public int Run()
    {
        Directory.SetCurrentDirectory(EdrPaths.SystemRoot);
        if (!File.Exists(paths.BaselineFile) && !File.Exists(paths.ManagedFile) && !File.Exists(paths.EnginePath) && !File.Exists(Path.Combine(paths.Root, "EDR-Engine.ps1")))
        {
            log.Ok("FreeEDR was never set up on this PC (Setup was cancelled): no Windows setting to put back");
            return 0;
        }
        var baseline = JsonFile.ReadObject(paths.BaselineFile);
        var managed = JsonFile.ReadObject(paths.ManagedFile);
        var known = baseline?.Truthy("known") == true;
        log.Info(known ? $"FreeEDR uninstall (restoring the settings recorded {baseline!.Str("recorded")})" : "FreeEDR uninstall (no settings on record from before FreeEDR: removing what FreeEDR added, Windows defaults otherwise)");

        log.Step("Stopping FreeEDR");
        Services.Stop(EdrPaths.ServiceName, 30);
        if (Services.Exists(EdrPaths.ServiceName)) { if (Services.Delete(EdrPaths.ServiceName)) log.Ok("Removed the service 'FreeEDR'"); else log.Warn("Could not remove the service 'FreeEDR'"); }
        foreach (var t in new[] { "FreeEDR", "EDR", "FreeEDR tray start" }.Concat((managed?["tasks"] as JsonArray)?.Select(Ps.Str) ?? []).Distinct())
        {
            if (!Sys.TaskExists(t)) continue;
            Sys.TaskEnd(t);
            if (Sys.TaskDelete(t)) log.Ok($"Removed the scheduled task '{t}'"); else log.Warn($"Could not remove the scheduled task '{t}'");
        }
        Sys.StopFreeEdrProcesses(paths, includeTools: true);
        log.Ok("Engine, scans, tools and trays stopped");

        log.Step("Tray start and shortcuts");
        try { using var run = Registry.LocalMachine.OpenSubKey(EdrPaths.RunKey, writable: true); run?.DeleteValue(EdrPaths.RunValue, false); }
        catch (Exception e) when (e is UnauthorizedAccessException or IOException) { log.Warn($"Tray start: {e.Message}"); }
        Sys.ForEachUserHive(h => { using var k = h.OpenSubKey(EdrPaths.RunKey, writable: true); k?.DeleteValue(EdrPaths.RunValue, false); k?.DeleteValue("EDR Tray", false); });
        var lnks = new List<string> { Path.Combine(Sys.CommonPrograms, "FreeEDR.lnk"), Path.Combine(Sys.CommonDesktop, "FreeEDR.lnk") };
        lnks.AddRange((managed?["shortcuts"] as JsonArray)?.Select(Ps.Str) ?? []);
        foreach (var l in lnks.Where(l => l.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            JsonFile.TryDelete(l);
            if (File.Exists(l)) log.Warn($"Could not delete {l}");
        }
        log.Ok("Tray start (all accounts) and Start menu / desktop shortcuts removed");

        log.Step("Firewall");
        try { log.Ok($"{Firewall.RemoveAllBans()} Wail2Ban block rules removed"); Firewall.RemoveRdpIpv6Blocks(); }
        catch (Exception e) when (e is IOException or System.ComponentModel.Win32Exception) { log.Warn($"Wail2Ban firewall rules: {e.Message}"); }
        if (known && baseline!["rdpShadowEnabled"] is JsonValue v && v.TryGetValue(out bool shadow) && shadow)
        {
            var r = PowerShellRunner.Run("Get-NetFirewallRule -Name 'RemoteDesktop-Shadow-In-TCP' | Enable-NetFirewallRule");
            if (r.ExitCode == 0) log.Ok("Remote Desktop Shadow rule enabled again (it was on before FreeEDR)"); else log.Warn($"Remote Desktop Shadow rule: {r.Error.Trim()}");
        }
        else log.Ok("Remote Desktop Shadow rule left disabled (it was off before FreeEDR, or that is not on record)");

        log.Step("Microsoft Defender");
        var allows = (JsonFile.ReadObject(paths.ExclusionsFile)?["defender"] as JsonArray)?.OfType<JsonObject>().Where(e => e.Str("path").Length > 0).ToList() ?? [];
        foreach (var n in Defender.Restore(baseline, managed, allows)) log.Note(n);

        log.Step("Sysmon");
        var sysmonExe = Path.Combine(EdrPaths.SystemRoot, "Sysmon64.exe");
        if (!Services.Exists("Sysmon64")) log.Ok("Sysmon is not installed");
        else if (baseline?.Truthy("sysmonPreexisting") == true)
        {
            var reg = baseline.Str("sysmonConfigBackup");
            if (reg.Length > 0 && File.Exists(reg) && Sys.Run(Sys.Sys32("reg.exe"), "import", reg).Exit == 0)
            {
                Services.Stop("Sysmon64"); Services.Start("Sysmon64");
                log.Ok("Sysmon kept (it was installed before FreeEDR); its earlier configuration is back");
            }
            else log.Warn("Sysmon kept (it was installed before FreeEDR), but its earlier configuration could not be restored - apply it again with Sysmon64 -c <your config>");
        }
        else
        {
            var (_, output) = Tools.RunCapture(sysmonExe, ["-u", "force"], timeoutSeconds: 180);
            if (Services.Exists("Sysmon64")) log.Warn($"Sysmon could not be removed: {string.Join(" ", output.Trim().Split('\n').TakeLast(2))}");
            else
            {
                log.Ok("Sysmon (service, driver and program) removed");
                var evtx = Path.Combine(EdrPaths.System32, "winevt", "Logs", "Microsoft-Windows-Sysmon%4Operational.evtx");
                if (File.Exists(evtx)) { JsonFile.TryDelete(evtx); if (File.Exists(evtx)) log.Warn($"The Sysmon event log file is still in use: delete {evtx} after a restart"); else log.Ok("Sysmon event log file removed"); }
            }
        }

        log.Step("Event log source");
        if (baseline?.Truthy("eventSourcePreexisting") == true) log.Ok("Event source \"wail2ban\" kept (it existed before FreeEDR)");
        else if (Sys.EventSourceExists(EdrPaths.EventSource)) { Sys.DeleteEventSource(EdrPaths.EventSource); log.Ok("Event source \"wail2ban\" removed (entries already written stay in the Application log)"); }
        else log.Ok("No event source to remove");

        var restoreFailed = log.Warnings > 0;
        var keep = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (restoreFailed)
        {
            foreach (var f in new[] { paths.BaselineFile, paths.ManagedFile, baseline?.Str("sysmonConfigBackup") ?? "" }.Where(f => f.Length > 0 && File.Exists(f))) keep.Add(Path.GetFullPath(f));
            if (Directory.Exists(paths.BinDir)) foreach (var f in Directory.GetFiles(paths.BinDir)) keep.Add(Path.GetFullPath(f));
        }

        log.Step($"Files ({paths.Root})");
        if (!opt.FromSetup && !restoreFailed) Registry.LocalMachine.DeleteSubKeyTree(EdrPaths.SetupUninstallKey, throwOnMissingSubKey: false);
        if (!restoreFailed) Registry.LocalMachine.DeleteSubKeyTree(EdrPaths.FinishRemovalKey, throwOnMissingSubKey: false);
        foreach (var old in new[] { @"C:\EDR", @"C:\Wail2Ban", @"C:\LocalEDR" }.Where(Directory.Exists))
            try { Directory.Delete(old, true); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        var self = Environment.ProcessPath ?? "";
        if (self.Length > 0) keep.Add(Path.GetFullPath(self));
        if (Directory.Exists(paths.Root))
        {
            foreach (var entry in new DirectoryInfo(paths.Root).GetFileSystemInfos())
            {
                if (opt.FromSetup && entry.Name.StartsWith("unins", StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    if (entry is DirectoryInfo d)
                    {
                        if (keep.Any(k => k.StartsWith(d.FullName + "\\", StringComparison.OrdinalIgnoreCase))) DeleteTreeExcept(d, keep);
                        else d.Delete(true);
                    }
                    else if (!keep.Contains(entry.FullName)) entry.Delete();
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
            }
            var left = Directory.GetFiles(paths.Root, "*", SearchOption.AllDirectories)
                .Where(f => !keep.Contains(f) && !(opt.FromSetup && Path.GetFileName(f).StartsWith("unins", StringComparison.OrdinalIgnoreCase))).ToList();
            if (left.Count > 0) log.Warn($"{left.Count} files are still in use (first: {left[0]}) - delete {paths.Root} after a restart");
            else if (restoreFailed) log.Ok($"Removed {paths.Root} except the record of the Windows settings to put back and the uninstaller ({paths.InstallerPath})");
            else log.Ok($"Deleted {paths.Root} (events, settings, allow/block lists, tools){(opt.FromSetup ? "; Setup removes the rest" : "")}");
        }
        if (restoreFailed)
        {
            log.Warn("Not every Windows setting could be put back. The record of the original settings was kept: fix what is listed above (or restart the PC), " +
                     $"then run the removal again: Settings > Apps > \"FreeEDR (finish removal)\", or as administrator: \"{paths.InstallerPath}\" uninstall");
            log.Result("UNINSTALL RESULT", "INCOMPLETE - the Windows settings record was kept, run the removal again", false);
            return RestoreIncomplete;
        }
        log.Result("UNINSTALL RESULT", log.Warnings > 0 ? $"DONE WITH {log.Warnings} WARNING(S) - see above" : "SUCCESS", log.Warnings == 0);
        return log.Warnings > 0 ? 1 : 0;
    }

    public const int RestoreIncomplete = 5;

    private static void DeleteTreeExcept(DirectoryInfo dir, HashSet<string> keep)
    {
        foreach (var f in dir.GetFiles()) if (!keep.Contains(f.FullName)) try { f.Delete(); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        foreach (var d in dir.GetDirectories())
        {
            if (keep.Any(k => k.StartsWith(d.FullName + "\\", StringComparison.OrdinalIgnoreCase))) DeleteTreeExcept(d, keep);
            else try { d.Delete(true); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }
    }
}
