using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Edr.Core;

/// <summary>
/// Durable JSON persistence shared by every FreeEDR process: shared reads (another process may be writing), atomic
/// writes (temp file, flush to disk, File.Replace keeping a .bak) and fail-closed strict reads that recover from the
/// .bak and keep the damaged file as .corrupt-&lt;time&gt;. AOT-safe: JsonNode only, no reflection.
/// </summary>
public static class JsonFile
{
    public static readonly UTF8Encoding Utf8NoBom = new(false);
    private static readonly JsonDocumentOptions DocOptions = new() { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip };

    /// <summary>A damaged file was restored from its .bak (path, reason). Set by the engine to raise an alert.</summary>
    public static Action<string, string>? Recovered { get; set; }

    public static JsonNode? Parse(string text)
    {
        try { return JsonNode.Parse(text, Rec.NodeOptions, DocOptions); }
        catch (JsonException) { return null; }
    }

    /// <summary>Null when missing, empty or invalid (lenient read).</summary>
    public static JsonNode? Read(string path)
    {
        var text = ReadText(path);
        return string.IsNullOrWhiteSpace(text) ? null : Parse(text);
    }

    public static JsonObject? ReadObject(string path) => Read(path) as JsonObject;

    /// <summary>
    /// Strict read: missing file = null; an unreadable/invalid file is recovered from .bak (the damaged copy is kept
    /// as .corrupt-&lt;time&gt;), otherwise throws <see cref="InvalidDataException"/> so the caller never overwrites real
    /// data with defaults.
    /// </summary>
    public static JsonNode? ReadStrict(string path)
    {
        if (!File.Exists(path)) return null;
        string? error;
        try
        {
            var text = ReadText(path, throwOnError: true);
            if (string.IsNullOrWhiteSpace(text)) error = "file is empty";
            else if (Parse(text) is { } n) return n;
            else error = "invalid JSON";
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { error = e.Message; }

        var bak = path + ".bak";
        if (File.Exists(bak))
        {
            var t = ReadText(bak);
            if (!string.IsNullOrWhiteSpace(t) && Parse(t) is { } restored)
            {
                try
                {
                    File.Move(path, $"{path}.corrupt-{DateTime.Now:yyyyMMdd-HHmmss}", true);
                    File.Copy(bak, path, true);
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
                Recovered?.Invoke(path, error ?? "damaged");
                return restored;
            }
        }
        throw new InvalidDataException($"JSON read failed for '{path}' and its backup is unavailable or damaged: {error}");
    }

    public static string? ReadText(string path, bool throwOnError = false)
    {
        for (var i = 0; i < 5; i++)
        {
            try
            {
                if (!File.Exists(path)) return null;
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var sr = new StreamReader(fs, Encoding.UTF8);
                return sr.ReadToEnd();
            }
            catch (IOException) when (i < 4) { Thread.Sleep(150); }
            catch (Exception) when (!throwOnError) { return null; }
        }
        return null;
    }

    /// <summary>Indented JSON text (relaxed escaping keeps paths and quotes readable).</summary>
    public static string ToText(JsonNode? node, bool indented = true)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = indented, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
        {
            if (node is null) w.WriteNullValue(); else node.WriteTo(w);
        }
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    /// <summary>Durable atomic write: temp file + Flush(true) + File.Replace (keeps .bak) or Move.</summary>
    public static void WriteAtomic(string path, JsonNode? node) => WriteTextAtomic(path, ToText(node));

    public static void WriteTextAtomic(string path, string text)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = $"{path}.{Environment.ProcessId}.{Guid.NewGuid():N}.tmp";
        var bytes = Utf8NoBom.GetBytes(text);
        try
        {
            using var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            fs.Write(bytes);
            fs.Flush(true);
        }
        catch
        {
            TryDelete(tmp);
            throw;
        }
        Exception? last = null;
        for (var i = 0; i < 5; i++)
        {
            try
            {
                if (File.Exists(path)) File.Replace(tmp, path, path + ".bak", ignoreMetadataErrors: true);
                else File.Move(tmp, path);
                return;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                last = e;
                Thread.Sleep(150);
            }
        }
        TryDelete(tmp);
        throw last!;
    }

    public static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>Appends one line (LF), retrying while another process holds the file.</summary>
    public static bool AppendLine(string path, string line)
    {
        for (var i = 0; i < 10; i++)
        {
            try
            {
                using var fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                var b = Utf8NoBom.GetBytes(line + "\n");
                fs.Write(b);
                return true;
            }
            catch (IOException) { Thread.Sleep(100); }
            catch (UnauthorizedAccessException) { return false; }
        }
        return false;
    }

    // ---- JsonObject helpers (PowerShell-like accessors used by the engine) ---------------------------------

    public static string Str(this JsonObject o, string name) => Ps.Str(o.TryGetPropertyValue(name, out var v) ? v : null);

    public static bool Truthy(this JsonObject o, string name) => Ps.Truthy(o.TryGetPropertyValue(name, out var v) ? v : null);

    public static int Int(this JsonObject o, string name, int fallback = 0)
    {
        var s = o.Str(name);
        return double.TryParse(s, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var d) ? (int)d : fallback;
    }

    public static JsonArray Arr(this JsonObject o, string name)
    {
        if (o.TryGetPropertyValue(name, out var v) && v is JsonArray a) return a;
        var n = new JsonArray();
        o[name] = n;
        return n;
    }

    public static IEnumerable<JsonObject> Objects(this JsonObject o, string name) =>
        o.TryGetPropertyValue(name, out var v) && v is JsonArray a ? a.OfType<JsonObject>() : [];

    public static JsonArray ToJsonArray(this IEnumerable<string> items) => new(items.Select(s => (JsonNode?)JsonValue.Create(s)).ToArray());
}
