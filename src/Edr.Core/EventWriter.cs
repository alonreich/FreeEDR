using System.Globalization;
using System.Text.Json.Nodes;

namespace Edr.Core;

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

    public long Failures => Interlocked.Read(ref _failures);

    public string LastError { get { lock (_gate) return _lastError; } }

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
