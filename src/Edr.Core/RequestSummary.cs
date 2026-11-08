using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;

namespace Edr.Core;

public static class RequestSummary
{
    public const int MaxLines = 20;
    public const int MaxChars = 6000;

    public sealed record Lookup(EdrConfig? Config, Func<string, JsonObject?>? FindAllow, Func<string, JsonObject?>? FindVerdict);

    public sealed record Summary(string Text, bool Complete, int Lines);

    public static Lookup LookupFor(EdrPaths paths)
    {
        var excl = JsonFile.ReadObject(paths.ExclusionsFile);
        var blocks = JsonFile.ReadObject(paths.BlocklistFile);
        return new Lookup(
            EdrConfig.Load(paths.ConfigFile),
            id => FindIn(excl, id),
            id => blocks?.Objects("items").FirstOrDefault(e => e.Str("id") == id));
    }

    private static JsonObject? FindIn(JsonObject? excl, string id)
    {
        if (excl is null || id.Length == 0) return null;
        foreach (var (list, v) in excl)
            if (v is JsonArray a && a.OfType<JsonObject>().FirstOrDefault(e => e.Str("id") == id) is { } hit)
            {
                var copy = (JsonObject)hit.DeepClone();
                copy["blade"] = list;
                return copy;
            }
        return null;
    }

    public static string Describe(JsonObject cmd, Lookup? lookup = null) => Build(cmd, lookup).Text;

    public static Summary Build(JsonObject cmd, Lookup? lookup = null)
    {
        var lines = cmd.Str("action") == "batch" ? BatchLines(cmd.Objects("ops").ToList(), lookup) : OneLines(cmd, lookup);
        var sb = new StringBuilder();
        foreach (var l in lines.Take(MaxLines)) sb.Append("• ").AppendLine(l);
        if (lines.Count > MaxLines) sb.AppendLine($"... and {lines.Count - MaxLines} more changes");
        var text = sb.ToString().TrimEnd();
        return new Summary(text, lines.Count <= MaxLines && text.Length <= MaxChars, lines.Count);
    }

    public static bool Weakens(JsonObject cmd) => cmd.Str("action") switch
    {
        "batch" => cmd.Objects("ops").Any(Weakens),
        "pause" or "exclude" or "unblock" or "unban" or "set-config" or "restore-defaults" or "update-tool" => true,
        _ => false,
    };

    private static List<string> OneLines(JsonObject c, Lookup? lookup) =>
        c.Str("action") == "set-config" ? ConfigLines(c, lookup?.Config) : [Line(c, lookup)];

    private static List<string> BatchLines(List<JsonObject> ops, Lookup? lookup)
    {
        var lines = new List<string>();
        var done = new HashSet<JsonObject>(ReferenceEqualityComparer.Instance);

        foreach (var g in ops.Where(o => o.Str("action") == "exclude" && o.Str("profile").Length > 0).GroupBy(o => o.Str("profile")))
        {
            if (Profiles.Get(g.Key) is not { } p) continue;
            var want = Profiles.Ops(p).Select(Canonical).ToHashSet(StringComparer.Ordinal);
            var have = g.Select(Canonical).ToHashSet(StringComparer.Ordinal);
            if (!want.SetEquals(have)) continue;
            lines.Add($"Trust the app \"{Clean(p.Name)}\" ({want.Count} allows built into FreeEDR)");
            foreach (var o in g) done.Add(o);
        }
        if (lookup?.FindAllow is { } find)
            foreach (var g in ops.Where(o => o.Str("action") == "unexclude").Select(o => (Op: o, Entry: find(o.Str("id"))))
                                 .Where(x => x.Entry is not null && x.Entry.Str("profile").Length > 0).GroupBy(x => x.Entry!.Str("profile")))
            {
                var name = Profiles.Get(g.Key)?.Name ?? g.Key;
                lines.Add($"Stop trusting \"{Clean(name)}\" (remove its {g.Count()} allows)");
                foreach (var x in g) done.Add(x.Op);
            }
        foreach (var o in ops) if (!done.Contains(o)) lines.Add(Line(o, lookup));
        return lines;
    }

    private static string Line(JsonObject c, Lookup? lookup)
    {
        var a = c.Str("action");
        var blade = c.Str("blade");
        var part = Catalog.PauseNames.GetValueOrDefault(blade, blade);
        return a switch
        {
            "pause" => c.Int("minutes") > 0 ? $"Pause {Clean(part)} for {c.Int("minutes")} minutes" : $"Pause {Clean(part)} until it is resumed",
            "resume" => $"Resume {Clean(part)}",
            "scan-now" => "Start a scan now",
            "restart-engine" => "Restart the FreeEDR service",
            "restore-defaults" => "FACTORY RESET: default settings, allows, verdicts, bans and events are deleted",
            "update-tool" => $"Download and install a newer {Clean(c.Str("name"))} (only a release signed by its publisher is installed)",
            "exclude" => $"Allow ({Clean(blade)}): {Fields(c)}",
            "unexclude" => lookup?.FindAllow?.Invoke(c.Str("id")) is { } e ? $"Remove the allow ({Clean(e.Str("blade"))}): {Fields(e)}" : $"Remove the allow {Clean(c.Str("id"))} (not found)",
            "block" => $"Flag as threat ({Clean(blade)}): {Fields(c)}",
            "unblock" => lookup?.FindVerdict?.Invoke(c.Str("id")) is { } v ? $"Remove the verdict ({Clean(v.Str("blade"))}): {Fields(v)}" : $"Remove the verdict {Clean(c.Str("id"))} (not found)",
            "unban" => $"Unblock the address {Clean(c.Str("ip"))}",
            _ => $"{Clean(a)}: {Fields(c)}",
        };
    }

    private static List<string> ConfigLines(JsonObject c, EdrConfig? current)
    {
        var restart = c.Truthy("restart") ? " (then restart the service)" : "";
        if (c["config"] is not JsonObject req) return ["Change settings: (nothing)"];
        var before = (current ?? new EdrConfig()).ToJson();
        var after = EdrConfig.FromJson((JsonObject)before.DeepClone());
        after.Apply(req);
        var lines = new List<string>();
        Diff("", before, after.ToJson(), lines);
        if (lines.Count == 0) return [$"Change settings: no value changes{restart}"];
        if (restart.Length > 0) lines[^1] += restart;
        return lines;
    }

    private static void Diff(string prefix, JsonObject a, JsonObject b, List<string> lines)
    {
        foreach (var (k, vb) in b)
        {
            var va = a[k];
            if (va is JsonObject oa && vb is JsonObject ob) { Diff(prefix + k + ".", oa, ob, lines); continue; }
            var sa = JsonFile.ToText(va, indented: false);
            var sb = JsonFile.ToText(vb, indented: false);
            if (sa != sb) lines.Add($"Setting {Clean(prefix + k)}: {Clean(sa)} → {Clean(sb)}");
        }
    }

    private static readonly string[] Decisive =
        ["image", "parent", "parentSigner", "signer", "ancestors", "rule", "match", "detail", "raw", "title", "path", "kind", "sha256", "cidr", "ip", "cve", "package", "profile", "note"];

    private static readonly HashSet<string> Hidden = new(StringComparer.Ordinal) { "action", "blade", "user", "id", "added", "hits", "enforce", "quarantine" };

    private static string Fields(JsonObject c)
    {
        var keys = Decisive.Where(c.ContainsKey).Concat(c.Select(kv => kv.Key).Where(k => !Decisive.Contains(k)).Order(StringComparer.Ordinal));
        var parts = keys.Where(k => !Hidden.Contains(k) && Ps.Truthy(c[k])).Select(k => $"{Clean(k)}={Clean(Ps.Str(c[k]))}").ToList();
        return parts.Count > 0 ? string.Join(", ", parts) : "(no details)";
    }

    private static string Clean(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var ch in s)
            sb.Append(char.IsControl(ch) ? ' ' : CharUnicodeInfo.GetUnicodeCategory(ch) is UnicodeCategory.Format or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator ? '?' : ch);
        return sb.ToString();
    }

    private static string Canonical(JsonObject o) =>
        string.Join(";", o.Where(kv => kv.Key != "user").OrderBy(kv => kv.Key, StringComparer.Ordinal).Select(kv => $"{kv.Key}={Ps.Str(kv.Value)}"));
}
