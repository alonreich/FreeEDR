using System.Text.Json.Nodes;
using Edr.Core;

namespace Edr.Tray.Services;

/// <summary>This account's tray preferences (user\&lt;SID&gt;\preferences.json): notifications, window, first run.</summary>
public sealed class Preferences
{
    private readonly string _path;
    private JsonObject _o;

    public Preferences(string path)
    {
        _path = path;
        _o = JsonFile.ReadObject(path) ?? new JsonObject();
    }

    /// <summary>"critical" (only critical alerts), "important" (default), "all".</summary>
    public string NotifyLevel { get => _o.Str("notifyLevel") is "critical" or "important" or "all" ? _o.Str("notifyLevel") : "important"; set { _o["notifyLevel"] = value; Save(); } }
    public bool WelcomeDone { get => _o.Truthy("welcomeDone"); set { _o["welcomeDone"] = value; Save(); } }
    public bool LearningSummaryShown { get => _o.Truthy("learningSummaryShown"); set { _o["learningSummaryShown"] = value; Save(); } }
    public string LastWeeklySummary { get => _o.Str("lastWeeklySummary"); set { _o["lastWeeklySummary"] = value; Save(); } }
    public string LastPage { get => _o.Str("lastPage"); set { _o["lastPage"] = value; Save(); } }

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
        try { JsonFile.WriteAtomic(_path, _o); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }
}

/// <summary>
/// Learns from what the user does (user\&lt;SID&gt;\insights.json): how often the same alert was marked reviewed (after the
/// third time FreeEDR suggests allowing it), and which suggestions were dismissed.
/// </summary>
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
