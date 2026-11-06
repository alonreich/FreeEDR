using System.Text.Json.Nodes;
using Edr.Core;
using Edr.Core.Native;

namespace Edr.Tray.Services;

/// <summary>
/// Everything the dashboard shows: the engine's files and this account's own tray files, read incrementally every
/// 2 seconds (events.jsonl is tailed; other files are re-read when their timestamp changes) and turned into the model.
/// Unelevated and read-only on the install folder.
/// </summary>
public sealed class TrayState
{
    public EdrPaths Paths { get; }
    public EdrInputs Inputs { get; private set; } = new();
    public TrayModel? Model { get; private set; }
    public Overall Overall { get; private set; } = new("down", "Starting...", "");
    public EdrConfig Config { get; private set; } = new();
    public ISignerLookup Signers { get; } = new CachedSigners(new AuthenticodeSigners());
    public string CurrentSid { get; } = EdrPaths.CurrentUserSid;
    public bool Dirty { get; set; } = true;

    /// <summary>Events read since the last tick (for notifications); empty on the first read.</summary>
    public List<Rec> NewEvents { get; } = [];

    private EventTail? _tail;
    private readonly Dictionary<string, DateTime> _stamps = new(StringComparer.OrdinalIgnoreCase);
    private bool _first = true;

    public TrayState(EdrPaths paths) => Paths = paths;

    private bool Changed(string path)
    {
        var t = File.Exists(path) ? File.GetLastWriteTimeUtc(path) : DateTime.MinValue;
        if (_stamps.TryGetValue(path, out var old) && old == t) return false;
        _stamps[path] = t;
        return true;
    }

    /// <summary>One tick: re-read what changed. Returns true when the model was rebuilt.</summary>
    public bool Refresh()
    {
        NewEvents.Clear();
        if (_first)
        {
            Inputs = new EdrInputs();
            ReadSysmonConfig();
            _tail = new EventTail(Paths.EventsFile);
        }
        if (Changed(Paths.StatusFile)) { Inputs.Status = EdrInputs.ReadJson(Paths.StatusFile); Dirty = true; }
        if (Changed(Paths.CveFile)) { Inputs.Cve = EdrInputs.ReadJson(Paths.CveFile); Dirty = true; }
        if (Changed(Paths.ScanResultFile)) { Inputs.ScanResult = EdrInputs.ReadJson(Paths.ScanResultFile); Dirty = true; }
        if (Changed(Paths.ExclusionsFile)) { Inputs.Exclusions = EdrInputs.ReadExclusions(Paths.ExclusionsFile); Dirty = true; }
        if (Changed(Paths.BlocklistFile)) { Inputs.Blocks = EdrInputs.ReadJson(Paths.BlocklistFile)?.Recs("items").ToList() ?? []; Dirty = true; }
        if (Changed(Paths.HistoryFile)) { Inputs.History = EdrInputs.ReadJson(Paths.HistoryFile)?.Recs("items").ToList() ?? []; Dirty = true; }
        if (Changed(Paths.ConfigFile)) { Config = EdrConfig.Load(Paths.ConfigFile); Dirty = true; }
        if (Changed(Paths.ReviewedFile))
        {
            Inputs.Reviewed.Clear();
            foreach (var l in ReadLines(Paths.ReviewedFile)) Inputs.Reviewed.Add(l);
            Dirty = true;
        }
        if (Changed(Paths.IgnoredAppsFile))
        {
            Inputs.Ignored.Clear();
            Inputs.Ignored.AddRange(ReadLines(Paths.IgnoredAppsFile).Distinct(StringComparer.OrdinalIgnoreCase));
            Dirty = true;
        }
        if (_tail is not null)
        {
            var added = _tail.ReadNew(Inputs.Events, Inputs, drainAll: _first);
            if (added.Count > 0) { Dirty = true; if (!_first) NewEvents.AddRange(added); }
        }
        _first = false;
        Overall = ModelBuilder.GetOverall(Model, Inputs.Status, DateTime.Now);
        if (!Dirty) return false;
        Model = new ModelBuilder(Inputs, Signers).Build();
        Overall = ModelBuilder.GetOverall(Model, Inputs.Status, DateTime.Now);
        Dirty = false;
        return true;
    }

    private void ReadSysmonConfig()
    {
        // Built-in exclusions and rule names (retired rules) come from the applied Sysmon config
        try
        {
            var doc = new System.Xml.XmlDocument();
            if (!File.Exists(Paths.SysmonConfig)) return;
            doc.Load(Paths.SysmonConfig);
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (System.Xml.XmlElement g in doc.SelectNodes("/Sysmon/EventFiltering/RuleGroup[@name='BuiltInExclusions']/ProcessCreate/Image")!)
                if (g.InnerText.Length > 0 && seen.Add(g.InnerText)) Inputs.BuiltIn.Add(g.InnerText);
            foreach (System.Xml.XmlElement n in doc.SelectNodes("//EventFiltering//*[@name]")!)
                if (n.LocalName != "RuleGroup") Inputs.RuleNames.Add(n.GetAttribute("name"));
        }
        catch (Exception e) when (e is System.Xml.XmlException or IOException or UnauthorizedAccessException) { }
    }

    private static List<string> ReadLines(string path)
    {
        try { return File.Exists(path) ? File.ReadAllLines(path).Select(l => l.Trim()).Where(l => l.Length > 0).ToList() : []; }
        catch (IOException) { return []; }
    }

    public bool EngineAlive => ModelBuilder.EngineAlive(Inputs.Status, DateTime.Now);

    public Rec? Status => Inputs.Status;

    public string PauseState(string blade) => ModelBuilder.PauseState(Inputs.Status, blade)?.S("state") ?? "unknown";

    public bool IsProfileOn(string id) => new[] { "realtime", "sigma" }.Any(l => Inputs.Exclusions[l].Any(x => x.S("profile") == id));

    public bool ParentAllowed(string parent)
    {
        var pat = PatternRules.VersionlessPattern(parent);
        return Inputs.Exclusions["realtime"].Any(x => x.S("parent") == pat) && Inputs.Exclusions["sigma"].Any(x => x.S("parent") == pat);
    }

    public bool IsReviewed(Rec e) => new ModelBuilder(Inputs, Signers).IsReviewed(e);

    // ---- per-account files (user\<SID>\) ----------------------------------------------------------------

    public void SetReviewed(IEnumerable<Rec> events, bool reviewed)
    {
        var ids = events.Select(e => e.S("id")).Where(i => i.Length > 0).ToList();
        if (ids.Count == 0) return;
        if (reviewed) { foreach (var i in ids) Inputs.Reviewed.Add(i); }
        else foreach (var i in ids) Inputs.Reviewed.Remove(i);
        try { File.WriteAllLines(Paths.ReviewedFile, Inputs.Reviewed); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        Dirty = true;
    }

    public void AddHistory(string sec, string key, Rec entry)
    {
        var o = (JsonObject)entry.Obj.DeepClone();
        o["id"] = Guid.NewGuid().ToString("N");
        o["sec"] = sec;
        o["key"] = key;
        o["time"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        Inputs.History.Add(new Rec(o));
        SaveHistory();
    }

    public void RemoveHistory(string id)
    {
        Inputs.History.RemoveAll(h => h.S("id") == id);
        SaveHistory();
    }

    private void SaveHistory()
    {
        try { JsonFile.WriteAtomic(Paths.HistoryFile, new JsonObject { ["items"] = new JsonArray(Inputs.History.Select(h => (JsonNode)h.Obj.DeepClone()).ToArray()) }); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        Dirty = true;
    }

    public void SetAppHidden(string id, bool hidden)
    {
        if (hidden) { if (!Inputs.Ignored.Contains(id, StringComparer.OrdinalIgnoreCase)) Inputs.Ignored.Add(id); }
        else Inputs.Ignored.RemoveAll(i => Ps.Eq(i, id));
        try { File.WriteAllLines(Paths.IgnoredAppsFile, Inputs.Ignored); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        Dirty = true;
    }

    public void SetPatchResults(List<Rec> apps)
    {
        Inputs.PatchEvents.Clear();
        Inputs.PatchEvents.AddRange(apps);
        Inputs.PatchChecked = DateTime.Now;
        Dirty = true;
    }
}
