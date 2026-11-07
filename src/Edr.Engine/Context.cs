using System.Globalization;
using System.Text.Json.Nodes;
using Edr.Core;
using Edr.Core.Native;

namespace Edr.Engine;

/// <summary>Everything the engine's parts share: paths, logs, settings and the persistent stores.</summary>
internal sealed class Context
{
    public Context(EdrPaths paths)
    {
        Paths = paths;
        Log = new TextLog(paths.EngineLog);
        Events = new EventWriter(paths);
        State = new EngineState(this);
        Excl = new ExclusionStore(this);
        Blocks = new Blocklist(this);
    }

    public EdrPaths Paths { get; }
    public TextLog Log { get; }
    public EventWriter Events { get; }
    public EdrConfig Cfg { get; set; } = new();
    public DateTime CfgStamp { get; set; }
    public EngineState State { get; }
    public ExclusionStore Excl { get; }
    public Blocklist Blocks { get; }
    public DateTime Started { get; } = DateTime.Now;

    /// <summary>Something the dashboards show changed (an event was written): set by the engine to notify them over the pipe.</summary>
    public Action? Changed { get; set; }

    public JsonObject Event(string blade, string severity, string title, string process = "", string detail = "", JsonObject? extra = null)
    {
        var e = Events.Write(blade, severity, title, process, detail, extra);
        Changed?.Invoke();
        return e;
    }

    public void AppEvent(string text, int id, ushort type = 4) => Win32.WriteAppEvent(EdrPaths.EventSource, text, id, type);

    /// <summary>[FORENSIC-AUDIT] line in engine.log + Event ID 3000 in the Application log.</summary>
    public void Audit(string action, string rubric, string user, string tail, string appText)
    {
        var now = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
        Log.Audit($"[FORENSIC-AUDIT] [{now}] [USER: {user}] [RUBRIC: {rubric}] [ACTION: {action}] {tail}");
        AppEvent(appText, 3000);
    }

    public void LoadConfig(bool strict)
    {
        try { Cfg = EdrConfig.Load(Paths.ConfigFile, strict); }
        catch (InvalidDataException e)
        {
            Log.Error($"Config load failed: {e.Message}");
            try { File.Move(Paths.ConfigFile, $"{Paths.ConfigFile}.corrupt-{DateTime.Now:yyyyMMdd-HHmmss}", true); } catch (IOException) { }
            Cfg = new EdrConfig();
            Event("system", "High", "Settings file damaged - config unrecoverable", detail: $"Config file was damaged and could not be recovered: {e.Message}", extra: new() { ["kind"] = "status" });
        }
        CfgStamp = File.Exists(Paths.ConfigFile) ? File.GetLastWriteTimeUtc(Paths.ConfigFile) : DateTime.MinValue;
    }

    /// <summary>Picks up settings saved by the elevated helper (Settings window) without a restart.</summary>
    public bool ReloadConfigIfChanged()
    {
        var t = File.Exists(Paths.ConfigFile) ? File.GetLastWriteTimeUtc(Paths.ConfigFile) : DateTime.MinValue;
        if (t == CfgStamp) return false;
        try { Cfg = EdrConfig.Load(Paths.ConfigFile); Log.Info("Settings reloaded"); }
        catch (InvalidDataException e) { Log.Warn($"Settings reload failed: {e.Message}"); }
        CfgStamp = t;
        return true;
    }
}
