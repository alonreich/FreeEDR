using System.Globalization;
using System.Text.Json.Nodes;

namespace Edr.Core;

/// <summary>
/// Appends alerts and status messages to data\events.jsonl (one JSON object per line), the file the tray reads.
/// Thread-safe; rotates at 20 MB and keeps 5 archives (events-yyyyMMdd-HHmmss.jsonl).
/// Every record has id, time, blade, severity, title, process, detail plus optional fields.
/// </summary>
public sealed class EventWriter(EdrPaths paths)
{
    private const long RotateBytes = 20L * 1024 * 1024;
    private readonly Lock _gate = new();

    public JsonObject Write(string blade, string severity, string title, string process = "", string detail = "", JsonObject? extra = null)
    {
        var e = new JsonObject
        {
            ["id"] = Guid.NewGuid().ToString("N"),
            ["time"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
            ["blade"] = blade,
            ["severity"] = severity,
            ["title"] = title,
            ["process"] = process,
            ["detail"] = detail,
        };
        if (extra is not null)
            foreach (var (k, v) in extra.ToList())
            {
                extra.Remove(k);
                e[k] = v;
            }
        Append(e);
        return e;
    }

    private long _failures;
    private string _lastError = "";

    /// <summary>Events that could not be written since this writer was created (never silent: the engine reports them).</summary>
    public long Failures => Interlocked.Read(ref _failures);

    public string LastError { get { lock (_gate) return _lastError; } }

    /// <summary>False when the event could not be written (counted in <see cref="Failures"/>). A failed rotation does
    /// not lose the event: it is still appended to the current file.</summary>
    public bool Append(JsonObject e)
    {
        lock (_gate)
        {
            try
            {
                Directory.CreateDirectory(paths.DataDir);
                Rotate();
                if (JsonFile.AppendLine(paths.EventsFile, JsonFile.ToText(e, indented: false))) return true;
                return Failed("the events file stayed locked or is not writable");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return Failed(ex.Message); }
        }
    }

    private void Rotate()
    {
        try
        {
            var fi = new FileInfo(paths.EventsFile);
            if (!fi.Exists || fi.Length <= RotateBytes) return;
            File.Move(paths.EventsFile, Path.Combine(paths.DataDir, $"events-{DateTime.Now:yyyyMMdd-HHmmss}.jsonl"), true);
            var archives = new DirectoryInfo(paths.DataDir).GetFiles("events-*.jsonl").OrderBy(f => f.LastWriteTimeUtc).ToList();
            foreach (var old in archives.Take(Math.Max(0, archives.Count - 5))) JsonFile.TryDelete(old.FullName);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { _lastError = $"rotation failed: {ex.Message}"; }
    }

    private bool Failed(string why)
    {
        _lastError = why;
        Interlocked.Increment(ref _failures);
        return false;
    }
}

/// <summary>"yyyy-MM-dd HH:mm:ss [L] text" lines; trimmed to the newest 10,000 lines above 5 MB. Never throws.</summary>
public sealed class TextLog(string path, long maxBytes = 5L * 1024 * 1024)
{
    private readonly Lock _gate = new();

    public void Write(char level, string text)
    {
        lock (_gate)
        {
            try
            {
                var fi = new FileInfo(path);
                if (fi.Exists && fi.Length > maxBytes)
                {
                    var keep = File.ReadAllLines(path).TakeLast(10_000).ToArray();
                    File.WriteAllLines(path, keep, JsonFile.Utf8NoBom);
                }
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                JsonFile.AppendLine(path, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{level}] {text}");
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }
    }

    public void Info(string t) => Write('I', t);
    public void Warn(string t) => Write('W', t);
    public void Error(string t) => Write('E', t);
    public void Audit(string t) => Write('A', t);
}
