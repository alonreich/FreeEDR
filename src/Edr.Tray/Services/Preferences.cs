using System.Text.Json.Nodes;
using Edr.Core;

namespace Edr.Tray.Services;

public sealed class Preferences
{
    private readonly string _path;
    private JsonObject _o;

    public Preferences(string path)
    {
        _path = path;
        _o = JsonFile.ReadObject(path) ?? new JsonObject();
        if (_o["quietProcesses"] is JsonArray q) _quiet = q.Select(Ps.Str).Where(x => x.Length > 0).ToList().AsReadOnly();
    }

    public string NotifyLevel { get => _o.Str("notifyLevel") is "critical" or "important" or "all" ? _o.Str("notifyLevel") : "important"; set { _o["notifyLevel"] = value; Save(); } }
    public bool WelcomeDone { get => _o.Truthy("welcomeDone"); set { _o["welcomeDone"] = value; Save(); } }
    public bool LearningSummaryShown { get => _o.Truthy("learningSummaryShown"); set { _o["learningSummaryShown"] = value; Save(); } }
    public string LastWeeklySummary { get => _o.Str("lastWeeklySummary"); set { _o["lastWeeklySummary"] = value; Save(); } }
    public string LastPage { get => _o.Str("lastPage"); set { _o["lastPage"] = value; Save(); } }
    public bool UpdateCheck { get => _o["updateCheck"] is not JsonValue v || !v.TryGetValue<bool>(out var b) || b; set { _o["updateCheck"] = value; Save(); } }
    public string SkippedVersion { get => _o.Str("skippedVersion"); set { _o["skippedVersion"] = value; Save(); } }
    public string NotifiedVersion { get => _o.Str("notifiedVersion"); set { _o["notifiedVersion"] = value; Save(); } }
    public string LastSeenVersion { get => _o.Str("lastSeenVersion"); set { _o["lastSeenVersion"] = value; Save(); } }
    public string LastUpdateCheck { get => _o.Str("lastUpdateCheck"); set { _o["lastUpdateCheck"] = value; Save(); } }
    public string Theme { get => _o.Str("theme") is "dark" or "light" or "system" ? _o.Str("theme") : "system"; set { _o["theme"] = value; Save(); } }

    private IReadOnlyList<string>? _quiet;

    public IReadOnlyList<string>? QuietProcesses
    {
        get => _quiet;
        set
        {
            _quiet = value is null ? null : value.ToList().AsReadOnly();
            if (value is null) _o.Remove("quietProcesses"); else _o["quietProcesses"] = value.ToJsonArray();
            Save();
        }
    }

    public double SettingsScroll { get => _o["settingsScroll"] is JsonValue v && v.TryGetValue<double>(out var d) && d >= 0 ? d : 0; set { _o["settingsScroll"] = Math.Round(value); Save(); } }

    public bool AdvancedOpen(string key) => _o["advancedOpen"] is JsonObject a && a.Truthy(key);

    public void SetAdvancedOpen(string key, bool open)
    {
        var a = _o["advancedOpen"] as JsonObject ?? (JsonObject)(_o["advancedOpen"] = new JsonObject());
        if (a.Truthy(key) == open) return;
        a[key] = open;
        Save();
    }

    public string SaveError { get; private set; } = "";

    public (double W, double H, int X, int Y, bool Max)? Window
    {
        get => _o["window"] is JsonObject w && w.Int("w") > 400 ? (w.Int("w"), w.Int("h"), w.Int("x"), w.Int("y"), w.Truthy("max")) : null;
        set
        {
            if (value is not { } v) return;
            _o["window"] = new JsonObject { ["w"] = (int)v.W, ["h"] = (int)v.H, ["x"] = v.X, ["y"] = v.Y, ["max"] = v.Max };
            Save();
        }
    }

    private void Save()
    {
        try { JsonFile.WriteAtomic(_path, _o); SaveError = ""; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { SaveError = e.Message; }
    }
}

public sealed class Insights
{
    public const int SuggestAfter = 3;
    private readonly string _path;
    private readonly JsonObject _o;

    public Insights(string path)
    {
        _path = path;
        _o = JsonFile.ReadObject(path) ?? new JsonObject();
    }

    private JsonObject Counts => _o["reviewCounts"] as JsonObject ?? (JsonObject)(_o["reviewCounts"] = new JsonObject());
    private JsonObject Dismissed => _o["dismissed"] as JsonObject ?? (JsonObject)(_o["dismissed"] = new JsonObject());

    public static string KeyOf(Rec e) => Ps.Eq(e.S("blade"), "sigma")
        ? $"sigma|{e.S("title")}|{SigmaProcess.Of(e).Parent}"
        : $"{e.S("blade")}|{e.S("title")}|{e.S("process")}|{e.S("parent")}";

    public void CountReview(Rec e)
    {
        var k = KeyOf(e);
        Counts[k] = Counts.Int(k) + 1;
        Save();
    }

    public void UncountReview(Rec e)
    {
        var k = KeyOf(e);
        var n = Counts.Int(k) - 1;
        if (n > 0) Counts[k] = n; else Counts.Remove(k);
        Save();
    }

    public int ReviewCount(Rec e) => Counts.Int(KeyOf(e));

    public bool ShouldSuggest(Rec e) => ReviewCount(e) >= SuggestAfter && !Dismissed.Truthy(KeyOf(e));

    public void Dismiss(Rec e)
    {
        Dismissed[KeyOf(e)] = true;
        Save();
    }

    private void Save()
    {
        try { JsonFile.WriteAtomic(_path, _o); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }
}
