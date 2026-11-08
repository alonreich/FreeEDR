using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using System.Text.Json.Nodes;
using Edr.Core;

namespace Edr.Tray.Services;

public enum CommandResult { Done, Cancelled, Refused, Failed, TooLarge, Busy, Unconfirmed, Incomplete }

public sealed class Commands(TrayState state)
{
    private bool _busy;

    public bool Busy => _busy;

    public string LastMessage { get; private set; } = "";

    public Action? Slow { get; set; }

    public static readonly TimeSpan SlowAfter = TimeSpan.FromMinutes(2);
    public static readonly TimeSpan GiveUpAfter = TimeSpan.FromMinutes(30);

    public static CommandResult FromExitCode(int code) => code switch
    {
        0 => CommandResult.Done, 2 => CommandResult.Refused, 4 => CommandResult.Cancelled, 6 => CommandResult.TooLarge,
        7 => CommandResult.Unconfirmed, 8 => CommandResult.Incomplete, _ => CommandResult.Failed,
    };

    public async Task<CommandResult> Admin(JsonObject cmd)
    {
        if (_busy) return CommandResult.Busy;
        if (cmd.Str("user").Length == 0) cmd["user"] = Environment.UserName;
        var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonFile.ToText(cmd, indented: false)));
        if (b64.Length > 30_000) return CommandResult.TooLarge;
        var exe = Path.Combine(state.Paths.BinDir, EdrPaths.ControlExe);
        if (!File.Exists(exe)) return CommandResult.Failed;
        _busy = true;
        try
        {
            var psi = new ProcessStartInfo(exe) { UseShellExecute = true, Verb = "runas" };
            psi.ArgumentList.Add("--payload");
            psi.ArgumentList.Add(b64);
            using var p = Process.Start(psi);
            if (p is null) return CommandResult.Failed;
            var exit = p.WaitForExitAsync();
            if (await Task.WhenAny(exit, Task.Delay(SlowAfter)) != exit)
            {
                Slow?.Invoke();
                if (await Task.WhenAny(exit, Task.Delay(GiveUpAfter - SlowAfter)) != exit) { state.Dirty = true; return CommandResult.Unconfirmed; }
            }
            state.Dirty = true;
            return FromExitCode(p.ExitCode);
        }
        catch (Win32Exception e) when (e.NativeErrorCode == 1223) { return CommandResult.Cancelled; }
        catch (Win32Exception) { return CommandResult.Failed; }
        finally { _busy = false; }
    }

    public async Task<CommandResult> Ops(IEnumerable<JsonObject?> ops)
    {
        var list = new List<JsonObject>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var o in ops)
            if (o is not null && seen.Add(string.Join(";", o.OrderBy(kv => kv.Key, StringComparer.Ordinal).Select(kv => $"{kv.Key}={Ps.Str(kv.Value)}")))) list.Add(o);
        if (list.Count == 0) return CommandResult.Refused;
        var cmd = list.Count == 1 ? list[0] : new JsonObject { ["action"] = "batch", ["ops"] = new JsonArray(list.Select(o => (JsonNode)o).ToArray()) };
        var paths = state.Paths;
        var summary = await Task.Run(() => RequestSummary.Build(cmd, RequestSummary.LookupFor(paths)));
        if (!summary.Complete) return CommandResult.TooLarge;
        return await Admin(cmd);
    }

    public async Task<CommandResult> User(JsonObject cmd)
    {
        LastMessage = "";
        if (cmd.Str("user").Length == 0) cmd["user"] = Environment.UserName;
        var r = await EnginePipe.SendAsync(cmd, 5_000);
        if (r.Answered)
        {
            state.Dirty = true;
            LastMessage = r.Ok && r.Message == "done" ? "" : r.Message;
            return r.Ok ? CommandResult.Done : r.Failed ? CommandResult.Incomplete : CommandResult.Refused;
        }
        if (r.Unanswered) return CommandResult.Unconfirmed;
        try
        {
            CommandDrop.Write(state.Paths.InboxDir, cmd);
            return CommandResult.Done;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return await Admin(cmd); }
    }

    public static string Explain(CommandResult r) => r switch
    {
        CommandResult.Done => "Done. The lists update within a few seconds.",
        CommandResult.Cancelled => "Cancelled - Windows administrator approval was not given. Nothing was changed.",
        CommandResult.Refused => "FreeEDR refused this change (it would be too broad or is not valid). Nothing was changed.",
        CommandResult.TooLarge => $"Too many changes for one administrator approval (at most {RequestSummary.MaxLines}; a trusted app counts as one). Select fewer items and try again.",
        CommandResult.Busy => "Another administrator action is still in progress. Please wait for it to finish.",
        CommandResult.Unconfirmed => "The request was sent, but FreeEDR did not confirm it in time. It may still be carried out: check the lists in a minute before you try again.",
        CommandResult.Incomplete => "FreeEDR could not carry out all of this change. The reason is in Activity > Messages.",
        _ => "The change could not be completed. The engine log has the details (Settings > Open logs).",
    };
}

public static class Shell
{

    public static bool OpenUrl(string url)
    {
        if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) return false;
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); return true; } catch (Win32Exception) { return false; }
    }

    public static bool OpenDocument(string path)
    {
        if (!File.Exists(path)) return false;
        try { Process.Start(new ProcessStartInfo(path) { UseShellExecute = true }); return true; }
        catch (Win32Exception) { return Notepad(path); }
    }

    public static bool ShowInExplorer(string path)
    {
        if (!File.Exists(path)) return false;
        var psi = new ProcessStartInfo(Path.Combine(EdrPaths.SystemRoot, "explorer.exe"));
        psi.ArgumentList.Add("/select,");
        psi.ArgumentList.Add(path);
        try { Process.Start(psi); return true; } catch (Win32Exception) { return false; }
    }

    public static bool Notepad(string path)
    {
        if (!File.Exists(path)) return false;
        var psi = new ProcessStartInfo(Path.Combine(EdrPaths.System32, "notepad.exe"));
        psi.ArgumentList.Add(path);
        try { Process.Start(psi); return true; } catch (Win32Exception) { return false; }
    }

    public static bool Run(string file, IEnumerable<string> args)
    {
        var psi = new ProcessStartInfo(file) { UseShellExecute = false, CreateNoWindow = false };
        foreach (var a in args) psi.ArgumentList.Add(a);
        try { Process.Start(psi); return true; } catch (Win32Exception) { return false; }
    }

    public static bool DefenderScan(string file)
    {
        var mp = Path.Combine(EdrPaths.ProgramFiles, "Windows Defender", "MpCmdRun.exe");
        if (!File.Exists(mp) || !File.Exists(file)) return false;
        var psi = new ProcessStartInfo(Path.Combine(EdrPaths.System32, "cmd.exe")) { UseShellExecute = false };
        foreach (var a in new[] { "/k", mp, "-Scan", "-ScanType", "3", "-File", file }) psi.ArgumentList.Add(a);
        try { Process.Start(psi); return true; } catch (Win32Exception) { return false; }
    }

    public static bool VirusTotal(string file, string? knownSha256)
    {
        var sha = knownSha256 is { Length: 64 } ? knownSha256 : File.Exists(file) ? Tools.Sha256Of(file) : null;
        return sha is not null && OpenUrl($"https://www.virustotal.com/gui/file/{sha.ToLowerInvariant()}");
    }

    public static bool Elevated(string file, IEnumerable<string> args, bool minimized = false)
    {
        var psi = new ProcessStartInfo(file) { UseShellExecute = true, Verb = "runas", WindowStyle = minimized ? ProcessWindowStyle.Minimized : ProcessWindowStyle.Normal };
        foreach (var a in args) psi.ArgumentList.Add(a);
        try { Process.Start(psi); return true; } catch (Win32Exception) { return false; }
    }
}
