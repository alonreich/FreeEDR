using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using System.Text.Json.Nodes;
using Edr.Core;

namespace Edr.Tray.Services;

/// <summary>Result of a request to the engine.</summary>
public enum CommandResult { Done, Cancelled, Refused, Failed, TooLarge, Busy }

/// <summary>
/// Requests to the engine. Weakening changes (allow, verdicts, pause, settings) go through Windows' UAC prompt to the
/// elevated FreeEDR-Control.exe, which validates them; resume and scan-now go to inbox\ without a prompt. Never blocks
/// the UI thread.
/// </summary>
public sealed class Commands(TrayState state)
{
    private bool _busy;

    public bool Busy => _busy;

    public async Task<CommandResult> Admin(JsonObject cmd)
    {
        if (_busy) return CommandResult.Busy;
        if (cmd.Str("user").Length == 0) cmd["user"] = Environment.UserName;
        var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonFile.ToText(cmd, indented: false)));
        if (b64.Length > 30_000) return CommandResult.TooLarge;   // travels on the command line (~32,000 characters)
        var exe = Path.Combine(state.Paths.BinDir, EdrPaths.ControlExe);
        if (!File.Exists(exe)) return CommandResult.Failed;
        _busy = true;
        try
        {
            var psi = new ProcessStartInfo(exe) { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden };
            psi.ArgumentList.Add("--payload");
            psi.ArgumentList.Add(b64);
            using var p = Process.Start(psi);
            if (p is null) return CommandResult.Failed;
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(2));
            try { await p.WaitForExitAsync(cts.Token); }
            catch (OperationCanceledException) { try { p.Kill(); } catch (InvalidOperationException) { } return CommandResult.Failed; }
            state.Dirty = true;
            return p.ExitCode switch { 0 => CommandResult.Done, 2 => CommandResult.Refused, _ => CommandResult.Failed };
        }
        catch (Win32Exception e) when (e.NativeErrorCode == 1223) { return CommandResult.Cancelled; }   // UAC declined
        catch (Win32Exception) { return CommandResult.Failed; }
        finally { _busy = false; }
    }

    /// <summary>Several steps behind one prompt (duplicates removed); a single step is sent as itself.</summary>
    public Task<CommandResult> Ops(IEnumerable<JsonObject?> ops)
    {
        var list = new List<JsonObject>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var o in ops)
            if (o is not null && seen.Add(string.Join(";", o.OrderBy(kv => kv.Key, StringComparer.Ordinal).Select(kv => $"{kv.Key}={Ps.Str(kv.Value)}")))) list.Add(o);
        if (list.Count == 0) return Task.FromResult(CommandResult.Refused);
        var cmd = list.Count == 1 ? list[0] : new JsonObject { ["action"] = "batch", ["ops"] = new JsonArray(list.Select(o => (JsonNode)o).ToArray()) };
        return Admin(cmd);
    }

    /// <summary>resume / scan-now through inbox\ (no prompt); falls back to the elevated helper when the drop fails.</summary>
    public async Task<CommandResult> User(JsonObject cmd)
    {
        if (cmd.Str("user").Length == 0) cmd["user"] = Environment.UserName;
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
        CommandResult.TooLarge => "Too many items selected for one change. Select fewer items (for example 50) and try again.",
        CommandResult.Busy => "Another administrator action is still in progress. Please wait for it to finish.",
        _ => "The change could not be completed. Nothing was changed.",
    };
}

/// <summary>Things the tray starts for the user: browser pages, Explorer, terminals (argument vectors, never shell strings).</summary>
public static class Shell
{
    public static void OpenUrl(string url)
    {
        if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) return;
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); } catch (Win32Exception) { }
    }

    public static void OpenFile(string path)
    {
        try { if (File.Exists(path) || Directory.Exists(path)) Process.Start(new ProcessStartInfo(path) { UseShellExecute = true }); } catch (Win32Exception) { }
    }

    public static void ShowInExplorer(string path)
    {
        if (!File.Exists(path)) return;
        var psi = new ProcessStartInfo(Path.Combine(EdrPaths.SystemRoot, "explorer.exe"));
        psi.ArgumentList.Add("/select,");
        psi.ArgumentList.Add(path);
        try { Process.Start(psi); } catch (Win32Exception) { }
    }

    public static void Notepad(string path)
    {
        if (!File.Exists(path)) return;
        var psi = new ProcessStartInfo(Path.Combine(EdrPaths.System32, "notepad.exe"));
        psi.ArgumentList.Add(path);
        try { Process.Start(psi); } catch (Win32Exception) { }
    }

    /// <summary>Starts a program with an argument vector in its own console window.</summary>
    public static bool Run(string file, IEnumerable<string> args)
    {
        var psi = new ProcessStartInfo(file) { UseShellExecute = false, CreateNoWindow = false };
        foreach (var a in args) psi.ArgumentList.Add(a);
        try { Process.Start(psi); return true; } catch (Win32Exception) { return false; }
    }

    /// <summary>Microsoft Defender custom scan of one file, in a console window the user can watch.</summary>
    public static bool DefenderScan(string file)
    {
        var mp = Path.Combine(EdrPaths.ProgramFiles, "Windows Defender", "MpCmdRun.exe");
        if (!File.Exists(mp) || !File.Exists(file)) return false;
        var psi = new ProcessStartInfo(Path.Combine(EdrPaths.System32, "cmd.exe")) { UseShellExecute = false };
        foreach (var a in new[] { "/k", mp, "-Scan", "-ScanType", "3", "-File", file }) psi.ArgumentList.Add(a);
        try { Process.Start(psi); return true; } catch (Win32Exception) { return false; }
    }

    /// <summary>VirusTotal page for the file's SHA256 (only the hash leaves the PC).</summary>
    public static void VirusTotal(string file, string? knownSha256)
    {
        var sha = knownSha256 is { Length: 64 } ? knownSha256 : File.Exists(file) ? Tools.Sha256Of(file) : null;
        if (sha is not null) OpenUrl($"https://www.virustotal.com/gui/file/{sha.ToLowerInvariant()}");
    }

    public static void Elevated(string file, IEnumerable<string> args)
    {
        var psi = new ProcessStartInfo(file) { UseShellExecute = true, Verb = "runas" };
        foreach (var a in args) psi.ArgumentList.Add(a);
        try { Process.Start(psi); } catch (Win32Exception) { }
    }
}
