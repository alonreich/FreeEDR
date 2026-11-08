using System.Text.Json.Nodes;

namespace Edr.Core;

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
        var r = EnginePipe.SendAsync(cmd, 10_000).GetAwaiter().GetResult();
        if (r.Answered)
        {
            if (!r.Ok) new TextLog(paths.EngineLog).Warn($"Engine refused an event ({title}): {r.Message}");
            return;
        }
        if (r.Unanswered) { new TextLog(paths.EngineLog).Warn($"Engine did not confirm an event in time ({title}): {r.Message}"); return; }
        CommandDrop.Write(paths.ControlDir, cmd);
    }

    private static string Fit(string s, int max) => s.Length <= max ? s : s[..(max - 3)] + "...";
}
