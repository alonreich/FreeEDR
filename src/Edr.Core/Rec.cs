using System.Text.Json;
using System.Text.Json.Nodes;

namespace Edr.Core;

public sealed class Rec(JsonObject obj)
{
    public static readonly JsonNodeOptions NodeOptions = new() { PropertyNameCaseInsensitive = true };
    private static readonly JsonDocumentOptions DocOptions = new() { AllowTrailingCommas = true };

    public JsonObject Obj { get; } = obj;

    internal SigmaProcess? SigmaCache { get; set; }

    public JsonNode? this[string name] => Obj.TryGetPropertyValue(name, out var v) ? v : null;

    public string S(string name) => Ps.Str(this[name]);

    public bool T(string name) => Ps.Truthy(this[name]);

    public int I(string name) => Ps.ToInt(this[name]);

    public Rec? Child(string name) => this[name] is JsonObject o ? new Rec(o) : null;

    public IReadOnlyList<string> Strings(string name) => this[name] switch
    {
        null => [],
        JsonArray a => a.Where(x => x is not null).Select(Ps.Str).ToList(),
        var v => [Ps.Str(v)],
    };

    public IReadOnlyList<Rec> Recs(string name) => this[name] switch
    {
        JsonArray a => a.OfType<JsonObject>().Select(o => new Rec(o)).ToList(),
        JsonObject o => [new Rec(o)],
        _ => [],
    };

    public static Rec? Parse(string json)
    {
        try { return JsonNode.Parse(json, NodeOptions, DocOptions) is JsonObject o ? new Rec(Materialize(o)) : null; }
        catch (JsonException) { return null; }
    }

    private static T Materialize<T>(T node) where T : JsonNode
    {
        switch (node)
        {
            case JsonObject o: foreach (var (_, v) in o) if (v is not null) Materialize(v); break;
            case JsonArray a: foreach (var v in a) if (v is not null) Materialize(v); break;
        }
        return node;
    }

    public override string ToString() => Obj.ToJsonString();
}
