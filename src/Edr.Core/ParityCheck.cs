using System.Text.Json.Nodes;

namespace Edr.Core;

/// <summary>
/// Compares two model dumps (PowerShell tray vs C# tray). Sort-Object in Windows PowerShell 5.1 is not stable,
/// so rows that tie on their sort keys may come in any order: lists are compared as the same rows (by key, all
/// fields) plus the same sequence of sort keys. Returns the differences (empty = parity).
/// </summary>
public static class ParityCheck
{
    public static List<string> Compare(JsonNode expected, JsonNode actual)
    {
        var diffs = new List<string>();
        void Eq(string what, JsonNode? a, JsonNode? b)
        {
            var x = a?.ToJsonString() ?? "null";
            var y = b?.ToJsonString() ?? "null";
            if (x != y) diffs.Add($"{what}: expected {x}, got {y}");
        }
        foreach (var k in new[] { "key", "text", "sub" }) Eq($"overall.{k}", expected["overall"]?[k], actual["overall"]?[k]);
        foreach (var k in new[] { "attention", "pinned", "claude" }) Eq(k, expected[k], actual[k]);
        foreach (var s in Catalog.Sections)
        {
            var e = expected["sections"]?[s.Key];
            var a = actual["sections"]?[s.Key];
            foreach (var k in new[] { "count", "alert", "attention" }) Eq($"{s.Key}.{k}", e?[k], a?[k]);
            for (var i = 0; i < 3; i++)
                CompareList($"{s.Key}|{i}", e?["lists"]?[i] as JsonArray, a?["lists"]?[i] as JsonArray, s.Key == "cve" && i == 0, diffs);
        }
        CompareList("messages", expected["messages"] as JsonArray, actual["messages"] as JsonArray, false, diffs);
        return diffs;
    }

    private static void CompareList(string name, JsonArray? exp, JsonArray? act, bool cveOrder, List<string> diffs)
    {
        var e = exp?.OfType<JsonObject>().ToList() ?? [];
        var a = act?.OfType<JsonObject>().ToList() ?? [];
        if (e.Count != a.Count) diffs.Add($"{name}: expected {e.Count} rows, got {a.Count}");

        string SortKey(JsonObject r) => cveOrder
            ? $"{r["sev"]}|{r["cols"]?[2]}"
            : $"{(r["pinned"]?.GetValue<bool>() == true && r["muted"]?.GetValue<bool>() != true ? 1 : 0)}|{r["time"]}";
        var ek = e.Select(SortKey).ToList();
        var ak = a.Select(SortKey).ToList();
        for (var i = 0; i < Math.Min(ek.Count, ak.Count); i++)
            if (ek[i] != ak[i]) { diffs.Add($"{name}: order differs at row {i}: expected [{ek[i]}], got [{ak[i]}]"); break; }

        // Same rows: grouped by sort key (ties may be in any order), then matched by content.
        // A grouped row "(xN)" shows its newest member; when several members share that time, PowerShell picks
        // any of them, so the id (key) and the member's own detail (last column) may differ - nothing else.
        static string Content(JsonObject r) => r.ToJsonString();
        static string Loose(JsonObject r)
        {
            var c = (JsonObject)r.DeepClone();
            c.Remove("key");
            if (c["cols"] is JsonArray cols && cols.Count > 0) cols.RemoveAt(cols.Count - 1);
            return c.ToJsonString();
        }
        static bool Grouped(JsonObject r) => (r["group"]?.GetValue<int>() ?? 0) > 1;
        foreach (var g in e.GroupBy(SortKey))
        {
            var pool = a.Where(r => SortKey(r) == g.Key).ToList();
            var mine = pool.Select(Content).ToList();
            var loose = pool.Where(Grouped).Select(Loose).ToList();
            foreach (var r in g)
            {
                var c = Content(r);
                if (mine.Remove(c)) { if (Grouped(r)) loose.Remove(Loose(r)); continue; }
                if (Grouped(r) && loose.Remove(Loose(r))) continue;
                {
                    var key = r["key"]?.ToString();
                    var other = a.FirstOrDefault(x => x["key"]?.ToString() == key);
                    diffs.Add(other is null ? $"{name}: missing row {c}" : $"{name}: row {key} differs:\n  expected {c}\n  got      {Content(other)}");
                    if (diffs.Count > 40) return;
                }
            }
        }
    }
}
