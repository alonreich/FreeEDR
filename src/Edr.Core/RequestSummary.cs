using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;

namespace Edr.Core;

/// <summary>
/// Plain-text description of an elevated request, shown by FreeEDR-Control.exe in its own elevated confirmation
/// window. The UAC prompt only names the program, so this is where the administrator sees what will actually change
/// (an unelevated process could have started the helper with its own payload). The rule: the window shows the whole
/// request or the helper refuses it. Nothing is cut: no value is shortened, no step is left out ("... and N more" makes
/// the summary <see cref="Summary.Complete"/> = false, and the helper then refuses). The fields that decide what an
/// allow covers come first, in a fixed order the payload cannot change; control and Unicode formatting characters
/// (line breaks, right-to-left overrides) are replaced, so no text can disguise another.
/// Compact forms only where the content is FreeEDR's own: a trusted-app profile whose allows are exactly the built-in
/// ones is one line, settings are shown as the values that change, allows and verdicts to remove are shown as what
/// they are (looked up by id), not as ids.
/// </summary>
public static class RequestSummary
{
    public const int MaxLines = 20;
    public const int MaxChars = 6000;

    /// <summary>What the helper knows about the installed state, to describe a request in its own terms.</summary>
    public sealed record Lookup(EdrConfig? Config, Func<string, JsonObject?>? FindAllow, Func<string, JsonObject?>? FindVerdict);

    /// <summary>Complete = the text shows every change in full (otherwise the helper must refuse the request).</summary>
    public sealed record Summary(string Text, bool Complete, int Lines);

    /// <summary>The installed config, allow list and verdicts (read leniently: a damaged file just means less detail).</summary>
    public static Lookup LookupFor(EdrPaths paths)
    {
        var excl = JsonFile.ReadObject(paths.ExclusionsFile);
        var blocks = JsonFile.ReadObject(paths.BlocklistFile);
        return new Lookup(
            EdrConfig.Load(paths.ConfigFile),
            id => FindIn(excl, id),
            id => blocks?.Objects("items").FirstOrDefault(e => e.Str("id") == id));
    }

    /// <summary>The allow with this id, as a copy with the list it is in as "blade".</summary>
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

    /// <summary>Weakens protection (pause, allow, settings, reset, new tool code): the confirmation is shown with a warning icon.</summary>
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

        // A trusted-app profile switched on: one line when the request holds exactly FreeEDR's built-in allows for it
        foreach (var g in ops.Where(o => o.Str("action") == "exclude" && o.Str("profile").Length > 0).GroupBy(o => o.Str("profile")))
        {
            if (Profiles.Get(g.Key) is not { } p) continue;
            var want = Profiles.Ops(p).Select(Canonical).ToHashSet(StringComparer.Ordinal);
            var have = g.Select(Canonical).ToHashSet(StringComparer.Ordinal);
            if (!want.SetEquals(have)) continue;   // anything else in it: every allow is listed on its own
            lines.Add($"Trust the app \"{Clean(p.Name)}\" ({want.Count} allows built into FreeEDR)");
            foreach (var o in g) done.Add(o);
        }
        // A trusted-app profile switched off: removing allows only strengthens protection, so they are counted per profile
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

    /// <summary>Settings: only what changes, as old → new, every changed value (the request applied to the installed settings).</summary>
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

    /// <summary>The fields that decide what an allow or verdict covers first (fixed order), then every other one; nothing is cut.</summary>
    private static readonly string[] Decisive =
        ["image", "parent", "parentSigner", "signer", "ancestors", "rule", "match", "detail", "raw", "title", "path", "kind", "sha256", "cidr", "ip", "cve", "package", "profile", "note"];

    private static readonly HashSet<string> Hidden = new(StringComparer.Ordinal) { "action", "blade", "user", "id", "added", "hits", "enforce", "quarantine" };

    private static string Fields(JsonObject c)
    {
        var keys = Decisive.Where(c.ContainsKey).Concat(c.Select(kv => kv.Key).Where(k => !Decisive.Contains(k)).Order(StringComparer.Ordinal));
        var parts = keys.Where(k => !Hidden.Contains(k) && Ps.Truthy(c[k])).Select(k => $"{Clean(k)}={Clean(Ps.Str(c[k]))}").ToList();
        return parts.Count > 0 ? string.Join(", ", parts) : "(no details)";
    }

    /// <summary>Control characters become spaces and Unicode formatting characters (bidi overrides, zero-width) '?'.</summary>
    private static string Clean(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var ch in s)
            sb.Append(char.IsControl(ch) ? ' ' : CharUnicodeInfo.GetUnicodeCategory(ch) is UnicodeCategory.Format or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator ? '?' : ch);
        return sb.ToString();
    }

    /// <summary>One operation as sorted key=value pairs (without the caller's name), to compare it with a built-in profile.</summary>
    private static string Canonical(JsonObject o) =>
        string.Join(";", o.Where(kv => kv.Key != "user").OrderBy(kv => kv.Key, StringComparer.Ordinal).Select(kv => $"{kv.Key}={Ps.Str(kv.Value)}"));
}
