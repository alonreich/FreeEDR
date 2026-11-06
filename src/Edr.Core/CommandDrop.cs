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
