using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Edr.Core;

public static class ModelDump
{
    public static JsonObject ToJson(TrayModel m, Overall overall, DateTime now)
    {
        var secs = new JsonObject();
        foreach (var s in m.Sec.Values)
        {
            secs[s.Info.Key] = new JsonObject
            {
                ["count"] = s.Count, ["alert"] = s.Alert, ["attention"] = s.Attention,
                ["lists"] = new JsonArray(s.Rows.Select(l => (JsonNode)new JsonArray(l.Select(RowJson).ToArray())).ToArray()),
            };
        }
        return new JsonObject
        {
            ["now"] = now.ToString("yyyy-MM-ddTHH:mm:ss"),
            ["overall"] = new JsonObject { ["key"] = overall.Key, ["text"] = overall.Text, ["sub"] = overall.Sub },
            ["attention"] = m.Attention, ["pinned"] = m.Pinned, ["claude"] = m.Claude,
            ["sections"] = secs,
            ["messages"] = new JsonArray(m.Messages.Select(RowJson).ToArray()),
        };
    }

    private static JsonNode RowJson(Row r) => new JsonObject
    {
        ["kind"] = r.Kind, ["key"] = r.Key, ["time"] = r.Time, ["sev"] = r.Sev,
        ["cols"] = new JsonArray(r.Cols.Select(c => (JsonNode?)JsonValue.Create(c)).ToArray()),
        ["muted"] = r.Muted, ["pinned"] = r.Pinned, ["group"] = r.Group.Count,
    };

    public static string Write(JsonNode node)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
            node.WriteTo(w);
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    public static IEnumerable<string> Summary(TrayModel m, Overall overall)
    {
        yield return $"Overall : {overall.Text} - {overall.Sub}";
        foreach (var s in m.Sec.Values)
        {
            var i = s.Info;
            yield return string.Format("{0,-9} open={1,-3} alert={2,-5} | {3}={4}  {5}={6}  {7}={8}", i.Key, s.Count, s.Alert ? "True" : "False",
                                       i.Subs[0], s.Rows[0].Count, i.Subs[1], s.Rows[1].Count, i.Subs[2], s.Rows[2].Count);
        }
        yield return $"Messages: {m.Messages.Count}";
    }
}
