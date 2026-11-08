using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using Edr.Core;
using Edr.Core.Native;

namespace Edr.Control;

internal static partial class Program
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
        var paths = new EdrPaths();
        var summary = RequestSummary.Build(cmd, RequestSummary.LookupFor(paths));
        if (!summary.Complete)
        {
            new TextLog(paths.EngineLog).Warn($"Control helper: '{cmd.Str("action")}' refused: {summary.Lines} changes or {summary.Text.Length} characters cannot be confirmed in one window");
            return 6;
        }
        if (!Confirmed(summary.Text, RequestSummary.Weakens(cmd))) return 4;
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

    private static bool Confirmed(string summary, bool weakens) =>
        ConfirmWindow.Ask("FreeEDR - confirm administrator change", "FreeEDR is about to make this change as administrator:", summary,
                          "Continue only if you started it from the FreeEDR dashboard just now.", weakens);

    private static int Drop(EdrPaths paths, JsonObject cmd)
    {
        cmd["user"] = Environment.UserName;
        var r = EnginePipe.SendAsync(cmd, 30_000).GetAwaiter().GetResult();
        var log = new TextLog(paths.EngineLog);
        if (r.Answered)
        {
            if (r.Ok) return 0;
            log.Warn($"Control helper: the engine {(r.Failed ? "could not carry out" : "refused")} '{cmd.Str("action")}': {r.Message}");
            return r.Failed ? 8 : 2;
        }
        if (r.Unanswered)
        {
            log.Warn($"Control helper: '{cmd.Str("action")}' was sent but the engine did not answer in time ({r.Message}); it may still be carried out");
            return 7;
        }
        if (r.Busy) log.Info($"Control helper: the engine was busy; '{cmd.Str("action")}' is queued in control\\");
        CommandDrop.Write(paths.ControlDir, cmd);
        return 0;
    }

    private static bool StopEngine() => Services.Stop(EdrPaths.ServiceName, 90);

    private static bool StartEngine()
    {
        if (Services.Start(EdrPaths.ServiceName, 30)) return true;
        Services.WaitFor(EdrPaths.ServiceName, Services.State.Stopped, 60);
        return Services.Start(EdrPaths.ServiceName, 30);
    }

    private static bool RestartEngine()
    {
        var stopped = StopEngine();
        if (!stopped) new TextLog(new EdrPaths().EngineLog).Error("Control helper: the engine did not stop within 90 seconds");
        var started = StartEngine();
        if (!started) new TextLog(new EdrPaths().EngineLog).Error("Control helper: the engine did not start again");
        return stopped && started;
    }

    private static int SetConfig(EdrPaths paths, JsonObject req, bool restart)
    {
        var cfg = EdrConfig.Load(paths.ConfigFile, strict: true);
        var defenderChanged = cfg.Apply(req);
        cfg.Save(paths.ConfigFile);
        var log = new TextLog(paths.EngineLog);
        log.Audit($"[FORENSIC-AUDIT] [{DateTime.UtcNow:yyyy-MM-ddTHH:mm:ssZ}] [USER: {Environment.UserName}] [RUBRIC: settings] [ACTION: SET-CONFIG] {JsonFile.ToText(EdrConfig.Redacted(req), false)}");
        Win32.WriteAppEvent(EdrPaths.EventSource, $"Forensic Audit: settings changed by '{Environment.UserName}'", 3000);
        if (defenderChanged)
        {
            var baseline = JsonFile.ReadObject(paths.BaselineFile);
            var notes = cfg.DefenderMode == "audit"
                ? Defender.ApplyAudit(baseline, Defender.GameExes())
                : Defender.Restore(baseline, JsonFile.ReadObject(paths.ManagedFile), []);
            foreach (var n in notes) log.Info($"Defender ({cfg.DefenderMode}): {n}");
            EngineNote.Send(paths, "Info", cfg.DefenderMode == "audit" ? "Microsoft Defender: audit mode applied" : "Microsoft Defender: FreeEDR's settings removed",
                detail: string.Join("\n", notes));
        }
        if (restart) RestartEngine();
        return 0;
    }

    private static int RestoreDefaults(EdrPaths paths)
    {
        var log = new TextLog(paths.EngineLog);
        if (!StopEngine())
        {
            log.Error("Restore defaults: the engine did not stop within 90 seconds - nothing was reset");
            StartEngine();
            return 3;
        }
        var started = false;
        try
        {
            foreach (var n in FactoryReset.Apply(paths, everything: false)) log.Info($"Restore defaults: {n}");
            log.Audit($"[FORENSIC-AUDIT] [{DateTime.UtcNow:yyyy-MM-ddTHH:mm:ssZ}] [USER: {Environment.UserName}] [RUBRIC: all] [ACTION: RESTORE-DEFAULTS]");
            Win32.WriteAppEvent(EdrPaths.EventSource, $"Forensic Audit: factory reset by '{Environment.UserName}'", 3000);
        }
        catch (Exception e)
        {
            log.Error($"Restore defaults stopped part-way: {e.GetType().Name}: {e.Message}");
            started = StartEngine();
            if (started) EngineNote.Send(paths, "High", "Reset to defaults did not finish", detail: $"{e.Message}. Some settings, allows or files may still be as before. Try the reset again.");
            return 3;
        }
        finally
        {
            if (!started) started = StartEngine();
            if (!started) log.Error("Restore defaults: the engine did not start again");
        }
        return started ? 0 : 3;
    }

    private static int UpdateTool(EdrPaths paths, string name)
    {
        var spec = Tools.Spec(name)!;
        var log = new TextLog(paths.EngineLog);
        var (ok, msg) = new Tools(paths, log.Info).UpdateToLatest(spec).GetAwaiter().GetResult();
        log.Audit($"Tool update by {Environment.UserName}: {msg}");
        EngineNote.Send(paths, ok ? "Info" : "Medium", ok ? $"Tool updated: {spec.Name}" : $"Tool update failed: {spec.Name}", spec.Name, msg, "tool-update", spec.Name, ok);
        if (ok && spec.Name == "YARA") RestartEngine();
        return ok ? 0 : 3;
    }
}
