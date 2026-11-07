using System.Globalization;
using System.Text.Json.Nodes;
using Edr.Core;

namespace Edr.Engine;

/// <summary>data\state.json: pauses, scan bookkeeping and the "already reported" sets. Fail-closed: a state that could
/// not be read is never written back empty over the damaged file. Thread-safe: the engine loop and the background
/// scan both read pauses (an expired pause is cleared and saved on read), so every access holds one lock.</summary>
internal sealed class EngineState(Context ctx)
{
    private readonly Lock _gate = new();   // re-entrant: IsPaused -> Active -> Save
    private JsonObject _s = new();
    private bool _corrupted;

    public static readonly string[] PauseKeys = ["edr", "realtime", "malware", "sigma", "cve", "wail2ban"];
    private static readonly string[] EdrChildren = ["realtime", "malware", "ioc", "yara", "sigma", "cve"];

    public void Load()
    {
        lock (_gate) LoadLocked();
    }

    private void LoadLocked()
    {
        try { _s = JsonFile.ReadStrict(ctx.Paths.StateFile) as JsonObject ?? new JsonObject(); }
        catch (InvalidDataException e)
        {
            ctx.Log.Error($"State file load failed: {e.Message}");
            try { File.Move(ctx.Paths.StateFile, $"{ctx.Paths.StateFile}.corrupt-{DateTime.Now:yyyyMMdd-HHmmss}", true); } catch (IOException) { }
            _corrupted = true;
            _s = new JsonObject();
            ctx.Event("system", "High", "Settings file damaged - state unrecoverable", detail: $"State file was damaged and could not be recovered: {e.Message}", extra: new() { ["kind"] = "status" });
        }
    }

    public void Save()
    {
        lock (_gate) SaveLocked();
    }

    private void SaveLocked()
    {
        if (_corrupted)
        {
            var hasData = PauseKeys.Any(k => _s.Str(k + "PausedUntil").Length > 0) || new[] { "sigmaSeen", "cveSeen", "toolSeen", "defSeen" }.Any(k => _s.Objects(k).Any() || (_s[k] as JsonArray)?.Count > 0);
            if (!hasData) { ctx.Log.Error("Save-State skipped: state is uninitialized from a corrupt file"); return; }
            _corrupted = false;
        }
        try { JsonFile.WriteAtomic(ctx.Paths.StateFile, _s); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { ctx.Log.Error($"State save failed: {e.Message}"); }
    }

    public string Get(string key) { lock (_gate) return _s.Str(key); }
    public void Set(string key, JsonNode? value) { lock (_gate) _s[key] = value; }
    public bool? GetBool(string key) { lock (_gate) return _s[key] is JsonValue v && v.TryGetValue(out bool b) ? b : null; }

    public HashSet<string> Seen(string key)
    {
        lock (_gate) return _s[key] is JsonArray a ? a.Select(Ps.Str).Where(s => s.Length > 0).ToHashSet(StringComparer.Ordinal) : new HashSet<string>(StringComparer.Ordinal);
    }

    public void SetSeen(string key, IEnumerable<string> items, int keep)
    {
        var arr = items.TakeLast(keep).ToJsonArray();
        lock (_gate) _s[key] = arr;
    }

    public string PausedUntil(string blade) { lock (_gate) return _s.Str(blade + "PausedUntil"); }

    /// <summary>Is this part paused? An expired pause is cleared here and reported as "resumed automatically".</summary>
    public bool IsPaused(string blade)
    {
        lock (_gate)
        {
            if (EdrChildren.Contains(blade) && Active("edr")) return true;
            return Active(blade);
        }
    }

    private bool Active(string blade)
    {
        var u = PausedUntil(blade);
        if (u.Length == 0) return false;
        if (Ps.ToDate(u) is { } until && until > DateTime.Now) return true;
        _s[blade + "PausedUntil"] = null;
        Save();
        var name = Catalog.PauseNames.GetValueOrDefault(blade) ?? blade;
        ctx.Log.Audit($"{blade} pause expired - resumed automatically");
        ctx.Event("system", "Info", $"{name} resumed automatically", detail: "The timed pause ended.", extra: new() { ["kind"] = "status" });
        return false;
    }

    public string State(string blade) => IsPaused(blade) ? "paused" : "on";
}

/// <summary>config\exclusions.json: the allow lists (realtimePath, realtime, ioc, yara, sigma, wail2ban, cve, defender).</summary>
internal sealed class ExclusionStore(Context ctx)
{
    public static readonly string[] Lists = ["realtimePath", "realtime", "ioc", "yara", "sigma", "wail2ban", "cve", "defender"];
    private Dictionary<string, List<JsonObject>> _x = Empty();
    private DateTime _stamp = DateTime.MinValue;
    private bool _corrupted;

    public List<JsonObject> this[string list] => _x.TryGetValue(list, out var l) ? l : [];

    public static Dictionary<string, List<JsonObject>> Empty() => Lists.ToDictionary(l => l, _ => new List<JsonObject>());

    public void Load()
    {
        try { _x = Parse(JsonFile.ReadStrict(ctx.Paths.ExclusionsFile) as JsonObject); }
        catch (InvalidDataException e)
        {
            ctx.Log.Error($"Exclusions load failed: {e.Message}");
            try { File.Move(ctx.Paths.ExclusionsFile, $"{ctx.Paths.ExclusionsFile}.corrupt-{DateTime.Now:yyyyMMdd-HHmmss}", true); } catch (IOException) { }
            _corrupted = true;
            _x = Empty();
            ctx.Event("system", "High", "Settings file damaged - exclusions unrecoverable", detail: $"Exclusions file was damaged and could not be recovered: {e.Message}", extra: new() { ["kind"] = "status" });
        }
        _stamp = Stamp();
    }

    private DateTime Stamp() => File.Exists(ctx.Paths.ExclusionsFile) ? File.GetLastWriteTimeUtc(ctx.Paths.ExclusionsFile) : DateTime.MinValue;

    public static Dictionary<string, List<JsonObject>> Parse(JsonObject? o)
    {
        var x = Empty();
        if (o is null) return x;
        foreach (var l in Lists) if (o[l] is JsonArray a) x[l] = a.OfType<JsonObject>().Select(n => (JsonObject)n.DeepClone()).ToList();
        return x;
    }

    public JsonObject ToJson()
    {
        var o = new JsonObject();
        foreach (var l in Lists) o[l] = new JsonArray(this[l].Select(n => (JsonNode)n.DeepClone()).ToArray());
        return o;
    }

    public void Save()
    {
        if (_corrupted)
        {
            if (!_x.Values.Any(v => v.Count > 0)) { ctx.Log.Error("Save-Exclusions skipped: in-memory exclusions are empty from an unrecoverable corrupt file"); return; }
            _corrupted = false;
        }
        JsonFile.WriteAtomic(ctx.Paths.ExclusionsFile, ToJson());
        _stamp = Stamp();
    }

    public void ReloadIfChanged()
    {
        if (!File.Exists(ctx.Paths.ExclusionsFile))
        {
            if (_stamp != DateTime.MinValue) { _x = Empty(); _stamp = DateTime.MinValue; _corrupted = false; ctx.Log.Info("Exclusions file removed - reset in-memory exclusions to empty"); }
            return;
        }
        var t = Stamp();
        if (t == _stamp) return;
        try
        {
            var fresh = Parse(JsonFile.ReadStrict(ctx.Paths.ExclusionsFile) as JsonObject);
            if (_x.Values.Any(v => v.Count > 0) && !fresh.Values.Any(v => v.Count > 0))
                ctx.Log.Warn("Exclusions reload returned empty while in-memory exclusions exist; keeping in-memory exclusions");
            else { _x = fresh; _corrupted = false; }
        }
        catch (InvalidDataException e) { ctx.Log.Warn($"Exclusions reload failed: {e.Message}"); }
        _stamp = t;
    }

    /// <summary>Same entry already allowed (e.g. a profile switched on twice)? Tags an untagged twin with the profile.</summary>
    public bool Exists(string list, JsonObject f, string[] keys)
    {
        foreach (var x in this[list])
        {
            if (!keys.All(k => x.Str(k) == f.Str(k))) continue;
            if (f.Str("profile").Length > 0 && x.Str("profile").Length == 0) { x["profile"] = f.Str("profile"); Save(); }
            return true;
        }
        return false;
    }

    public JsonObject Add(string list, JsonObject fields, string user)
    {
        var entry = new JsonObject { ["id"] = Guid.NewGuid().ToString("N"), ["added"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) };
        foreach (var (k, v) in fields) entry[k] = v?.DeepClone();
        if (!_x.ContainsKey(list)) _x[list] = [];
        _x[list].Add(entry);
        Save();
        var summary = Summary(entry, ["image", "parent", "rule", "title", "path", "cidr", "sha256", "cve", "signer", "detail"]);
        ctx.Audit("EXCLUDE", list, user, $"[ENTRY: {summary}]", $"Forensic Audit: Rubric '{list}' allow added by '{user}': {summary}");
        var extra = new JsonObject { ["kind"] = "audit", ["action"] = "exclude", ["rubric"] = list, ["user"] = user, ["id"] = entry.Str("id") };
        foreach (var (k, v) in fields) if (Ps.Truthy(v) && !extra.ContainsKey(k)) extra[k] = Ps.Str(v);
        ctx.Event("system", "Medium", $"Allow added: {list} - {summary}", detail: $"Forensic Audit: Allow added to {list} by {user} ({summary})", extra: extra);
        return entry;
    }

    public (string List, JsonObject Entry)? Find(string id)
    {
        foreach (var l in Lists) if (this[l].FirstOrDefault(x => x.Str("id") == id) is { } e) return (l, e);
        return null;
    }

    public void Remove(string list, JsonObject entry, string user)
    {
        this[list].Remove(entry);
        Save();
        var summary = string.Join(", ", entry.Where(kv => kv.Key is not ("id" or "added") && Ps.Truthy(kv.Value)).Select(kv => $"{kv.Key}={Ps.Str(kv.Value)}"));
        ctx.Audit("UNEXCLUDE", list, user, $"[ID: {entry.Str("id")}] [ENTRY: {summary}]", $"Forensic Audit: Rubric '{list}' allow removed by '{user}': {summary}");
        var extra = new JsonObject { ["kind"] = "audit", ["action"] = "unexclude", ["rubric"] = list, ["user"] = user };
        foreach (var (k, v) in entry) if (Ps.Truthy(v)) extra[k] = Ps.Str(v);
        ctx.Event("system", "Medium", $"Allow removed: {list} - {summary}", detail: $"Forensic Audit: Allow removed from {list} by {user} ({summary})", extra: extra);
    }

    private static string Summary(JsonObject f, string[] keys)
    {
        var parts = keys.Where(k => f.Str(k).Length > 0).Select(k => $"{k}={f.Str(k)}").ToList();
        return parts.Count > 0 ? string.Join(", ", parts) : string.Join(" | ", f.Where(kv => kv.Key is not ("id" or "added") && Ps.Truthy(kv.Value)).Select(kv => Ps.Str(kv.Value)));
    }
}

/// <summary>config\blocklist.json: what the user flagged as a threat, and permanent IP bans. Nothing here stops a
/// program: FreeEDR only detects. A legacy quarantined file is restored when its entry is removed.</summary>
internal sealed class Blocklist(Context ctx)
{
    public List<JsonObject> Items { get; private set; } = [];
    private bool _corrupted;

    public void Load()
    {
        try { Items = (JsonFile.ReadStrict(ctx.Paths.BlocklistFile) as JsonObject)?.Objects("items").Select(o => (JsonObject)o.DeepClone()).ToList() ?? []; }
        catch (InvalidDataException e)
        {
            ctx.Log.Error($"Blocklist load failed: {e.Message}");
            try { File.Move(ctx.Paths.BlocklistFile, $"{ctx.Paths.BlocklistFile}.corrupt-{DateTime.Now:yyyyMMdd-HHmmss}", true); } catch (IOException) { }
            _corrupted = true;
            Items = [];
            ctx.Event("system", "High", "Settings file damaged - blocklist unrecoverable", detail: $"Blocklist file was damaged and could not be recovered: {e.Message}", extra: new() { ["kind"] = "status" });
        }
    }

    public void Save()
    {
        if (_corrupted)
        {
            if (Items.Count == 0) { ctx.Log.Error("Save-Blocks skipped: in-memory blocks are empty from an unrecoverable corrupt file"); return; }
            _corrupted = false;
        }
        JsonFile.WriteAtomic(ctx.Paths.BlocklistFile, new JsonObject { ["items"] = new JsonArray(Items.Select(i => (JsonNode)i.DeepClone()).ToArray()) });
    }
}
