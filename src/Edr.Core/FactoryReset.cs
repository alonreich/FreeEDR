using System.Globalization;
using System.Text.Json.Nodes;
using Edr.Core.Native;

namespace Edr.Core;

/// <summary>
/// Back to a fresh install's state, with the service stopped by the caller. Used by Settings ▸ Restore defaults
/// (FreeEDR-Control.exe) and by Setup's "Clean install". Never touches data\preinstall.json / managed.json (the record of
/// Windows settings before FreeEDR, which the uninstaller needs) or a legacy quarantine\ folder (users' files).
/// Microsoft Defender allows added from the dashboard are removed from Defender in both cases; one Defender refuses to
/// remove stays in the allow list, so it is never active without FreeEDR knowing about it.
/// </summary>
public static class FactoryReset
{
    /// <param name="everything">Clean install: also the logs, scan results, event archive, backups and the install date
    /// (the learning week starts again). Restore defaults keeps those and the install date.</param>
    public static List<string> Apply(EdrPaths paths, bool everything)
    {
        var notes = new List<string>();
        var old = EdrConfig.Load(paths.ConfigFile);

        // Defender allows that were added from the dashboard go with the allow list (Restore defaults and Clean install
        // alike). One that Defender would not remove stays listed, so the dashboard and the uninstaller can still remove it.
        var keptDefender = RemoveDefenderAllows(JsonFile.ReadObject(paths.ExclusionsFile), Defender.RemoveAllow, notes);

        var cfg = new EdrConfig { AllowProfilesInitialized = true, DefenderMode = old.DefenderMode, InstalledAt = everything ? DateTime.Now.ToString("s", CultureInfo.InvariantCulture) : old.InstalledAt };
        cfg.Save(paths.ConfigFile);

        var excl = new JsonObject();
        foreach (var l in new[] { "realtimePath", "realtime", "ioc", "yara", "sigma", "wail2ban", "cve", "defender" }) excl[l] = new JsonArray();
        foreach (var p in Profiles.All.Where(p => p.Default && Profiles.IsInstalled(p)))
            foreach (var op in Profiles.Ops(p))
            {
                var entry = new JsonObject { ["id"] = Guid.NewGuid().ToString("N"), ["added"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) };
                foreach (var (k, v) in op) if (k is not ("action" or "blade")) entry[k] = v?.DeepClone();
                ((JsonArray)excl[op.Str("blade")]!).Add((JsonNode)entry);
            }
        foreach (var k in keptDefender) ((JsonArray)excl["defender"]!).Add((JsonNode)k);   // still active in Defender: still listed
        JsonFile.WriteAtomic(paths.ExclusionsFile, excl);
        JsonFile.WriteAtomic(paths.BlocklistFile, new JsonObject { ["items"] = new JsonArray() });
        notes.Add("OK Settings and allow lists set to the defaults (recommended trusted apps), verdicts cleared");

        Firewall.RemoveAllBans();
        notes.Add("OK Every Wail2Ban firewall block removed");

        var files = new List<string> { paths.StrikesFile, paths.StateFile, paths.BookmarksFile, paths.EventsFile };
        if (everything) files.AddRange([paths.EngineLog, paths.ScanLog, paths.ScanResultFile, paths.CveFile, Path.Combine(paths.DataDir, "hayabusa_last_scan.csv")]);
        foreach (var f in files) { JsonFile.TryDelete(f); JsonFile.TryDelete(f + ".bak"); }
        if (Directory.Exists(paths.DataDir))
            foreach (var f in Directory.GetFiles(paths.DataDir, "events-*.jsonl").Concat(Directory.GetFiles(paths.DataDir, "*.corrupt-*"))) JsonFile.TryDelete(f);
        if (everything && Directory.Exists(paths.ConfigDir))
            foreach (var f in Directory.GetFiles(paths.ConfigDir, "*.corrupt-*")) JsonFile.TryDelete(f);

        if (everything)
            foreach (var d in new[] { Path.Combine(paths.DataDir, "archive"), Path.Combine(paths.DataDir, "legacy") }
                         .Concat(Directory.Exists(paths.DataDir) ? Directory.GetDirectories(paths.DataDir, "backup-*") : []))
                try { if (Directory.Exists(d)) Directory.Delete(d, true); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { notes.Add($"WARN Could not remove {d}: {e.Message}"); }

        foreach (var d in new[] { paths.ControlDir, paths.InboxDir }.Where(Directory.Exists))
            foreach (var f in Directory.GetFiles(d)) DropFile.TryDelete(f);   // inbox\ is user-writable: never follow a link or wait on a lock
        if (Directory.Exists(paths.UserDir))
            foreach (var u in Directory.GetDirectories(paths.UserDir))
            {
                var files2 = everything ? Directory.GetFiles(u) : new[] { "reviewed.txt", "history.json", "ignored-apps.txt", "insights.json" }.Select(n => Path.Combine(u, n)).ToArray();
                foreach (var f in files2) DropFile.TryDelete(f);   // user\<SID>\ belongs to that account: same rule
            }
        notes.Add(everything ? "OK Events, logs, scan results, event archive, backups and every account's dashboard state deleted"
                             : "OK Events, Wail2Ban strikes, engine state and every account's reviewed / history / hidden lists deleted");
        return notes;
    }

    /// <summary>Removes every Defender allow of <paramref name="exclusions"/>' "defender" list with <paramref name="remove"/>
    /// (kind, path) → (ok, error); returns the ones Defender kept, which must stay listed.</summary>
    public static List<JsonObject> RemoveDefenderAllows(JsonObject? exclusions, Func<string, string, (bool Ok, string Error)> remove, List<string> notes)
    {
        var kept = new List<JsonObject>();
        if (exclusions?["defender"] is not JsonArray da) return kept;
        var all = da.OfType<JsonObject>().Where(e => e.Str("path").Length > 0).ToList();
        foreach (var e in all)
        {
            var (ok, err) = remove(e.Str("kind").Length > 0 ? e.Str("kind") : "asr", e.Str("path"));
            if (ok) continue;
            kept.Add((JsonObject)e.DeepClone());
            notes.Add($"WARN Microsoft Defender allow '{e.Str("path")}' could not be removed ({err}); it stays listed under Allowed & trusted");
        }
        if (all.Count > 0) notes.Add($"OK {all.Count - kept.Count} of {all.Count} Microsoft Defender allows added from FreeEDR removed");
        return kept;
    }
}
