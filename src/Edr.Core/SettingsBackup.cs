using System.Globalization;
using System.Text.Json.Nodes;

namespace Edr.Core;

public static class SettingsBackup
{
    public const string Format = "FreeEDR settings backup";
    public const int Version = 1;
    public const int MaxBytes = 2 * 1024 * 1024;

    public static readonly string[] Lists = ["realtime", "sigma", "ioc", "yara", "cve", "wail2ban", "defender"];

    private static readonly HashSet<string> NotCopied = new(StringComparer.Ordinal) { "id", "added", "user", "hits", "action", "blade" };

    public sealed record Plan(JsonObject ConfigChanges, List<JsonObject> Ops, int AlreadyThere, int Refused, string Problem)
    {
        public bool Empty => ConfigChanges.Count == 0 && Ops.Count == 0;
    }

    public static JsonObject Create(EdrConfig cfg, JsonObject? exclusions, JsonObject? preferences = null)
    {
        var settings = cfg.UserJson();
        var allows = new JsonObject();
        foreach (var l in Lists)
            allows[l] = new JsonArray((exclusions?[l] as JsonArray ?? []).OfType<JsonObject>().Select(e => (JsonNode)Fields(e)).ToArray());
        var res = new JsonObject
        {
            ["format"] = Format, ["version"] = Version, ["created"] = DateTime.Now.ToString("s", CultureInfo.InvariantCulture),
            ["settings"] = settings, ["allows"] = allows,
        };
        if (preferences is not null) res["preferences"] = preferences.DeepClone();
        return res;
    }

    public static JsonObject? PrefsOf(JsonObject? backup) =>
        backup is not null && backup.Str("format") == Format && backup["preferences"] is JsonObject p ? (JsonObject)p.DeepClone() : null;

    public static List<string>? QuietOf(JsonObject? backup) =>
        backup is not null && backup.Str("format") == Format && backup["settings"] is JsonObject s && s["quietProcesses"] is JsonArray q
            ? q.Select(Ps.Str).Select(x => x.Trim()).Where(EdrConfig.IsQuietName).Distinct(StringComparer.OrdinalIgnoreCase).ToList()
            : null;

    public static Plan PlanImport(JsonObject? backup, EdrConfig current, JsonObject? exclusions)
    {
        if (backup is null || backup.Str("format") != Format) return new([], [], 0, 0, "This is not a FreeEDR settings backup.");
        if (backup.Int("version") > Version) return new([], [], 0, 0, "This backup was made by a newer FreeEDR. Update FreeEDR first.");

        var changes = new JsonObject();
        if (backup["settings"] is JsonObject wanted)
        {
            var before = UserView(current);
            var after = EdrConfig.FromJson(current.ToJson());
            after.Apply(wanted);
            changes = EdrConfig.Changes(before, UserView(after));
        }

        var ops = new List<JsonObject>();
        int there = 0, refused = 0;
        var have = new HashSet<string>(StringComparer.Ordinal);
        foreach (var l in Lists)
            foreach (var e in (exclusions?[l] as JsonArray ?? []).OfType<JsonObject>()) have.Add(l + "|" + Canonical(Fields(e)));
        foreach (var l in Lists)
            foreach (var e in (backup["allows"]?[l] as JsonArray ?? []).OfType<JsonObject>())
            {
                var f = Fields(e);
                if (!have.Add(l + "|" + Canonical(f))) { there++; continue; }
                var op = new JsonObject { ["action"] = "exclude", ["blade"] = l };
                foreach (var (k, v) in f) op[k] = v?.DeepClone();
                if (PatternRules.IsValidOp(op)) ops.Add(op); else refused++;
            }
        return new(changes, ops, there, refused, "");
    }

    public static List<JsonObject> Batches(List<JsonObject> ops, Func<JsonObject, bool>? fits = null)
    {
        fits ??= cmd => RequestSummary.Build(cmd).Complete;
        var result = new List<JsonObject>();
        var current = new List<JsonObject>();
        JsonObject Wrap(List<JsonObject> l) => l.Count == 1 ? (JsonObject)l[0].DeepClone() : new JsonObject { ["action"] = "batch", ["ops"] = new JsonArray(l.Select(o => (JsonNode)o.DeepClone()).ToArray()) };
        foreach (var op in ops)
        {
            current.Add(op);
            if (current.Count <= PatternRules.MaxBatch && fits(Wrap(current))) continue;
            current.RemoveAt(current.Count - 1);
            if (current.Count > 0) result.Add(Wrap(current));
            current = [op];
        }
        if (current.Count > 0) result.Add(Wrap(current));
        return result;
    }

    private static JsonObject UserView(EdrConfig c) => c.UserJson();

    private static JsonObject Fields(JsonObject e)
    {
        var f = new JsonObject();
        foreach (var (k, v) in e) if (!NotCopied.Contains(k) && Ps.Truthy(v)) f[k] = v?.DeepClone();
        return f;
    }

    private static string Canonical(JsonObject f) =>
        string.Join(";", f.OrderBy(kv => kv.Key, StringComparer.Ordinal).Select(kv => $"{kv.Key}={Ps.Str(kv.Value)}"));
}
