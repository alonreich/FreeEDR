using System.Text.Json.Nodes;

namespace Edr.Core;

/// <summary>
/// The two command drop folders: control\ (admin-only, written by the elevated FreeEDR-Control.exe) and inbox\
/// (any account; the engine accepts only resume and scan-now from it). A request is written as .tmp and renamed to
/// .json, so the engine never reads half a file.
/// </summary>
public static class CommandDrop
{
    public static string Write(string dir, JsonObject cmd)
    {
        Directory.CreateDirectory(dir);
        var name = $"{DateTime.Now:yyyyMMddHHmmssfff}-{Guid.NewGuid().ToString("N")[..6]}";
        var tmp = Path.Combine(dir, name + ".tmp");
        var final = Path.Combine(dir, name + ".json");
        try
        {
            File.WriteAllText(tmp, JsonFile.ToText(cmd, indented: false), JsonFile.Utf8NoBom);
            File.Move(tmp, final);
            return final;
        }
        catch
        {
            JsonFile.TryDelete(tmp);
            throw;
        }
    }
}

/// <summary>
/// An event from one of FreeEDR's elevated programs (the helper, the installer). The engine is the only writer of
/// data\events.jsonl (one process, one lock: no rotation race, no silent loss), so these are sent to it as a "note"
/// request: over the pipe (it answers at once), or into the admin-only control\ when it is not running (written at its
/// next start).
/// </summary>
public static class EngineNote
{
    public static void Send(EdrPaths paths, string severity, string title, string process = "", string detail = "", string kind = "status", string tool = "", bool? ok = null)
    {
        var cmd = new JsonObject
        {
            ["action"] = "note", ["blade"] = "system", ["severity"] = severity, ["title"] = Fit(title, 200), ["process"] = Fit(process, 260),
            ["detail"] = Fit(detail, 4000), ["kind"] = kind, ["user"] = Environment.UserName,
        };
        if (tool.Length > 0) cmd["tool"] = Fit(tool, 64);
        if (ok is { } b) cmd["ok"] = b;
        var (reached, accepted, message) = EnginePipe.SendAsync(cmd, 10_000).GetAwaiter().GetResult();
        if (reached && accepted) return;
        if (reached) new TextLog(paths.EngineLog).Warn($"Engine refused an event ({title}): {message}");
        else CommandDrop.Write(paths.ControlDir, cmd);
    }

    private static string Fit(string s, int max) => s.Length <= max ? s : s[..(max - 3)] + "...";
}
