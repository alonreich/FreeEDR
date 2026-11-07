using System.Text.Json.Nodes;
using Edr.Core;
using Edr.Core.Native;

namespace Edr.Tray.Services;

/// <summary>
/// Everything the dashboard shows: the engine's files and this account's own tray files, read incrementally every
/// 2 seconds (events.jsonl is tailed; other files are re-read when their timestamp changes) and turned into the model.
/// Unelevated and read-only on the install folder.
/// Threading: <see cref="Refresh"/> runs on a background worker (<see cref="RefreshAsync"/>), never on the UI thread.
/// The worker owns the working inputs; the UI reads only what was published (<see cref="Inputs"/>, a snapshot, and
/// <see cref="Model"/>). The few UI edits (reviewed, history, hidden apps, winget results) change the working inputs
/// under <c>_gate</c>, which the worker holds only while it reads files, never while it builds the model.
/// </summary>
public sealed class TrayState
{
    public EdrPaths Paths { get; }

    /// <summary>The inputs of the last published model (a read-only snapshot; safe on the UI thread).</summary>
    public EdrInputs Inputs => _published;
    public TrayModel? Model => _model;
    public Overall Overall => _overall;
    public EdrConfig Config => _config;
    /// <summary>Write time (UTC) of the settings file the dashboard read.</summary>
    public DateTime ConfigStamp { get; private set; }

    /// <summary>The engine runs with the settings file as it is now (status.json "settingsLoaded" is not older than the
    /// file): a saved change is active.</summary>
    public bool SettingsActive => Status?.S("settingsLoaded") is { Length: > 0 } s
        && DateTime.TryParse(s, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind, out var t)
        && t.ToUniversalTime() >= ConfigStamp;
    public ISignerLookup Signers { get; } = new CachedSigners(new AuthenticodeSigners());
    public string CurrentSid { get; } = EdrPaths.CurrentUserSid;
    public bool Dirty { get => _dirty; set => _dirty = value; }

    /// <summary>Events read by the last refresh (for notifications); empty on the first read.</summary>
    public IReadOnlyList<Rec> NewEvents => _newEvents;

    private readonly Lock _gate = new();          // the working inputs (_work), _stamps, _tail
    private readonly Lock _refreshGate = new();   // one refresh at a time
    private readonly EdrInputs _work = new();
    private volatile EdrInputs _published = new();
    private volatile TrayModel? _model;
    private volatile Overall _overall = new("down", "Starting...", "");
    private volatile EdrConfig _config = new();
    private volatile bool _dirty = true;
    private volatile IReadOnlyList<Rec> _newEvents = [];
    private Task<bool>? _running;

    private EventTail? _tail;
    private readonly Dictionary<string, DateTime> _stamps = new(StringComparer.OrdinalIgnoreCase);
    private bool _first = true;

    public TrayState(EdrPaths paths) => Paths = paths;

    /// <summary>Starts a refresh on the thread pool, or returns the one already running (call from the UI thread).</summary>
    public Task<bool> RefreshAsync()
    {
        if (_running is { IsCompleted: false } r) return r;
        return _running = Task.Run(Refresh);
    }

    private bool Changed(string path)
    {
        var t = File.Exists(path) ? File.GetLastWriteTimeUtc(path) : DateTime.MinValue;
        if (_stamps.TryGetValue(path, out var old) && old == t) return false;
        _stamps[path] = t;
        return true;
    }

    /// <summary>One tick: re-read what changed; returns true when the model was rebuilt. Blocking (file I/O and the
    /// model build): the tray calls it through <see cref="RefreshAsync"/>.</summary>
    public bool Refresh()
    {
        lock (_refreshGate) return RefreshCore();
    }

    private bool RefreshCore()
    {
        EdrInputs snapshot;
        var fresh = new List<Rec>();
        lock (_gate)
        {
            ReadChanged(fresh);
            if (!_dirty)
            {
                _newEvents = fresh;
                _overall = ModelBuilder.GetOverall(_model, _published.Status, DateTime.Now);
                return false;
            }
            _dirty = false;
            snapshot = _work.Snapshot();
        }
        var model = new ModelBuilder(snapshot, Signers).Build();   // the slow part, outside the lock
        _published = snapshot;
        _model = model;
        _overall = ModelBuilder.GetOverall(model, snapshot.Status, DateTime.Now);
        _newEvents = fresh;
        return true;
    }

    private void ReadChanged(List<Rec> fresh)
    {
        var w = _work;
        if (_first)
        {
            ReadSysmonConfig();
            _tail = new EventTail(Paths.EventsFile);
        }
        if (Changed(Paths.StatusFile)) { w.Status = EdrInputs.ReadJson(Paths.StatusFile); Dirty = true; }
        if (Changed(Paths.CveFile)) { w.Cve = EdrInputs.ReadJson(Paths.CveFile); Dirty = true; }
        if (Changed(Paths.ScanResultFile)) { w.ScanResult = EdrInputs.ReadJson(Paths.ScanResultFile); Dirty = true; }
        if (Changed(Paths.ExclusionsFile)) { w.Exclusions = EdrInputs.ReadExclusions(Paths.ExclusionsFile); Dirty = true; }
        if (Changed(Paths.BlocklistFile)) { w.Blocks = EdrInputs.ReadJson(Paths.BlocklistFile)?.Recs("items").ToList() ?? []; Dirty = true; }
        if (Changed(Paths.HistoryFile)) { w.History = EdrInputs.ReadJson(Paths.HistoryFile)?.Recs("items").ToList() ?? []; Dirty = true; }
        if (Changed(Paths.ConfigFile)) { _config = EdrConfig.Load(Paths.ConfigFile); ConfigStamp = _stamps[Paths.ConfigFile]; Dirty = true; }
        if (Changed(Paths.ReviewedFile))
        {
            w.Reviewed.Clear();
            foreach (var l in ReadLines(Paths.ReviewedFile)) w.Reviewed.Add(l);
            Dirty = true;
        }
        if (Changed(Paths.IgnoredAppsFile))
        {
            w.Ignored.Clear();
            w.Ignored.AddRange(ReadLines(Paths.IgnoredAppsFile).Distinct(StringComparer.OrdinalIgnoreCase));
            Dirty = true;
        }
        if (_tail is not null)
        {
            var added = _tail.ReadNew(w.Events, w, drainAll: _first);
            if (added.Count > 0) { Dirty = true; if (!_first) fresh.AddRange(added); }
        }
        _first = false;
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
                if (g.InnerText.Length > 0 && seen.Add(g.InnerText)) _work.BuiltIn.Add(g.InnerText);
            foreach (System.Xml.XmlElement n in doc.SelectNodes("//EventFiltering//*[@name]")!)
                if (n.LocalName != "RuleGroup") _work.RuleNames.Add(n.GetAttribute("name"));
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
        lock (_gate)
        {
            if (reviewed) { foreach (var i in ids) _work.Reviewed.Add(i); }
            else foreach (var i in ids) _work.Reviewed.Remove(i);
            try { File.WriteAllLines(Paths.ReviewedFile, _work.Reviewed); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            Dirty = true;
        }
    }

    public void AddHistory(string sec, string key, Rec entry)
    {
        var o = (JsonObject)entry.Obj.DeepClone();
        o["id"] = Guid.NewGuid().ToString("N");
        o["sec"] = sec;
        o["key"] = key;
        o["time"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        lock (_gate)
        {
            _work.History.Add(new Rec(o));
            SaveHistory();
        }
    }

    public void RemoveHistory(string id)
    {
        lock (_gate)
        {
            _work.History.RemoveAll(h => h.S("id") == id);
            SaveHistory();
        }
    }

    private void SaveHistory()
    {
        try { JsonFile.WriteAtomic(Paths.HistoryFile, new JsonObject { ["items"] = new JsonArray(_work.History.Select(h => (JsonNode)h.Obj.DeepClone()).ToArray()) }); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        Dirty = true;
    }

    public void SetAppHidden(string id, bool hidden)
    {
        lock (_gate)
        {
            if (hidden) { if (!_work.Ignored.Contains(id, StringComparer.OrdinalIgnoreCase)) _work.Ignored.Add(id); }
            else _work.Ignored.RemoveAll(i => Ps.Eq(i, id));
            try { File.WriteAllLines(Paths.IgnoredAppsFile, _work.Ignored); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            Dirty = true;
        }
    }

    public void SetPatchResults(List<Rec> apps)
    {
        lock (_gate)
        {
            _work.PatchEvents.Clear();
            _work.PatchEvents.AddRange(apps);
            _work.PatchChecked = DateTime.Now;
            Dirty = true;
        }
    }
}
