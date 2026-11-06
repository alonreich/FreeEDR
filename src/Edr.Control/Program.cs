using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using Edr.Core;
using Edr.Core.Native;

namespace Edr.Control;

/// <summary>
/// FreeEDR-Control.exe --payload &lt;base64 JSON&gt;: the elevated helper the tray starts through UAC (manifest:
/// requireAdministrator). It validates the request with the same rules as the engine, then either drops it into the
/// admin-only control\ folder or (restart-engine, set-config, restore-defaults, update-tool) carries it out itself.
/// Exit codes: 0 done, 2 refused (invalid request), 3 failed, 5 not elevated.
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        if (!Win32.IsAdministrator()) return 5;
        var i = Array.FindIndex(args, a => a.Equals("--payload", StringComparison.OrdinalIgnoreCase) || a.Equals("-Payload", StringComparison.OrdinalIgnoreCase));
        if (i < 0 || i + 1 >= args.Length) return 2;
        var payload = args[i + 1];
        if (payload.Length == 0 || payload.Length > PatternRules.MaxPayload * 2) return 2;
        JsonObject? cmd;
        try
        {
            var raw = Encoding.UTF8.GetString(Convert.FromBase64String(payload));
            if (raw.Length > PatternRules.MaxPayload) return 2;
            cmd = JsonFile.Parse(raw) as JsonObject;
        }
        catch (FormatException) { return 2; }
        if (cmd is null || !PatternRules.IsValidCommand(cmd, out _)) return 2;
        var paths = new EdrPaths(Value(args, "--root"));
        try
        {
            return cmd.Str("action") switch
            {
                "restart-engine" => RestartEngine() ? 0 : 3,
                "set-config" => SetConfig(paths, (JsonObject)cmd["config"]!, cmd.Truthy("restart")),
                "restore-defaults" => RestoreDefaults(paths),
                "update-tool" => UpdateTool(paths, cmd.Str("name")),
                _ => Drop(paths, cmd),
            };
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            new TextLog(paths.EngineLog).Error($"Control helper failed ({cmd!.Str("action")}): {e.Message}");
            return 3;
        }
    }

    private static string? Value(string[] args, string name)
    {
        var i = Array.FindIndex(args, a => a.Equals(name, StringComparison.OrdinalIgnoreCase));
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    private static int Drop(EdrPaths paths, JsonObject cmd)
    {
        if (cmd.Str("user").Length == 0) cmd["user"] = Environment.UserName;
        CommandDrop.Write(paths.ControlDir, cmd);
        return 0;
    }

    private static bool RestartEngine()
    {
        Services.Stop(EdrPaths.ServiceName, 30);
        return Services.Start(EdrPaths.ServiceName, 30);
    }

    private static int SetConfig(EdrPaths paths, JsonObject req, bool restart)
    {
        var cfg = EdrConfig.Load(paths.ConfigFile, strict: true);
        var defenderChanged = cfg.Apply(req);
        cfg.Save(paths.ConfigFile);
        var log = new TextLog(paths.EngineLog);
        log.Audit($"[FORENSIC-AUDIT] [{DateTime.UtcNow:yyyy-MM-ddTHH:mm:ssZ}] [USER: {Environment.UserName}] [RUBRIC: settings] [ACTION: SET-CONFIG] {JsonFile.ToText(req, false)}");
        Win32.WriteAppEvent(EdrPaths.EventSource, $"Forensic Audit: settings changed by '{Environment.UserName}'", 3000);
        if (defenderChanged)
        {
            var baseline = JsonFile.ReadObject(paths.BaselineFile);
            var notes = cfg.DefenderMode == "audit"
                ? Defender.ApplyAudit(baseline, Defender.GameExes())
                : Defender.Restore(baseline, JsonFile.ReadObject(paths.ManagedFile), []);
            foreach (var n in notes) log.Info($"Defender ({cfg.DefenderMode}): {n}");
            new EventWriter(paths).Write("system", "Info", cfg.DefenderMode == "audit" ? "Microsoft Defender: audit mode applied" : "Microsoft Defender: FreeEDR's settings removed",
                detail: string.Join("\n", notes), extra: new() { ["kind"] = "status" });
        }
        if (restart) RestartEngine();
        return 0;
    }

    /// <summary>Factory reset: settings, allows (the recommended trusted apps again), verdicts, bans, strikes, state, events and every account's tray state.</summary>
    private static int RestoreDefaults(EdrPaths paths)
    {
        Services.Stop(EdrPaths.ServiceName, 30);
        var old = EdrConfig.Load(paths.ConfigFile);
        var cfg = new EdrConfig { AllowProfilesInitialized = true, InstalledAt = old.InstalledAt, DefenderMode = old.DefenderMode };
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
        JsonFile.WriteAtomic(paths.ExclusionsFile, excl);
        JsonFile.WriteAtomic(paths.BlocklistFile, new JsonObject { ["items"] = new JsonArray() });
        Firewall.RemoveAllBans();
        foreach (var f in new[] { paths.StrikesFile, paths.StateFile, paths.BookmarksFile, paths.EventsFile })
        {
            JsonFile.TryDelete(f);
            JsonFile.TryDelete(f + ".bak");
        }
        if (Directory.Exists(paths.UserDir))
            foreach (var u in Directory.GetDirectories(paths.UserDir))
                foreach (var f in new[] { "reviewed.txt", "history.json", "ignored-apps.txt", "insights.json" }) JsonFile.TryDelete(Path.Combine(u, f));
        new TextLog(paths.EngineLog).Audit($"[FORENSIC-AUDIT] [{DateTime.UtcNow:yyyy-MM-ddTHH:mm:ssZ}] [USER: {Environment.UserName}] [RUBRIC: all] [ACTION: RESTORE-DEFAULTS]");
        Win32.WriteAppEvent(EdrPaths.EventSource, $"Forensic Audit: factory reset by '{Environment.UserName}'", 3000);
        return Services.Start(EdrPaths.ServiceName, 30) ? 0 : 3;
    }

    private static int UpdateTool(EdrPaths paths, string name)
    {
        var spec = Tools.Spec(name)!;
        var log = new TextLog(paths.EngineLog);
        var (ok, msg) = new Tools(paths, log.Info).UpdateToLatest(spec).GetAwaiter().GetResult();
        log.Audit($"Tool update by {Environment.UserName}: {msg}");
        new EventWriter(paths).Write("system", ok ? "Info" : "Medium", ok ? $"Tool updated: {spec.Name}" : $"Tool update failed: {spec.Name}", spec.Name, msg,
            new() { ["kind"] = "tool-update", ["tool"] = spec.Name, ["ok"] = ok });
        if (ok && spec.Name == "YARA") RestartEngine();   // recompiles the rules with the new version
        return ok ? 0 : 3;
    }
}
