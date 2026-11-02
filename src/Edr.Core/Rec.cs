using System.Text.Json;
using System.Text.Json.Nodes;

namespace Edr.Core;

/// <summary>
/// One JSON record (event, exclusion, block, CVE item, ...) read the way ConvertFrom-Json exposes it to the
/// PowerShell tray: case-insensitive property names, [string] casts and truthiness. Unknown fields are kept,
/// so newer engine versions can add fields freely.
/// </summary>
public sealed class Rec(JsonObject obj)
{
    public static readonly JsonNodeOptions NodeOptions = new() { PropertyNameCaseInsensitive = true };
    private static readonly JsonDocumentOptions DocOptions = new() { AllowTrailingCommas = true };

    public JsonObject Obj { get; } = obj;

    /// <summary>Per-record cache for derived values (e.g. the parsed Sigma program and parent).</summary>
    internal SigmaProcess? SigmaCache { get; set; }

    public JsonNode? this[string name] => Obj.TryGetPropertyValue(name, out var v) ? v : null;

    /// <summary>[string]$rec.name</summary>
    public string S(string name) => Ps.Str(this[name]);

    /// <summary>[bool]$rec.name (PowerShell truthiness)</summary>
    public bool T(string name) => Ps.Truthy(this[name]);

    public int I(string name) => Ps.ToInt(this[name]);

    /// <summary>A nested object, e.g. $status.wail2ban</summary>
    public Rec? Child(string name) => this[name] is JsonObject o ? new Rec(o) : null;

    /// <summary>@($rec.name) as strings, nulls dropped (e.g. ancestors, aliases)</summary>
    public IReadOnlyList<string> Strings(string name) => this[name] switch
    {
        null => [],
        JsonArray a => a.Where(x => x is not null).Select(Ps.Str).ToList(),
        var v => [Ps.Str(v)],
    };

    /// <summary>@($rec.name) as records, non-objects dropped</summary>
    public IReadOnlyList<Rec> Recs(string name) => this[name] switch
    {
        JsonArray a => a.OfType<JsonObject>().Select(o => new Rec(o)).ToList(),
        JsonObject o => [new Rec(o)],
        _ => [],
    };

    public static Rec? Parse(string json)
    {
        try { return JsonNode.Parse(json, NodeOptions, DocOptions) is JsonObject o ? new Rec(o) : null; }
        catch (JsonException) { return null; }
    }

    public override string ToString() => Obj.ToJsonString();
}
