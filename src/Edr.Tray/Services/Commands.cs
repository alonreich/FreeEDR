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
            var psi = new ProcessStartInfo(exe) { UseShellExecute = true, Verb = "runas" };   // not Hidden: the helper shows its confirmation window
            psi.ArgumentList.Add("--payload");
            psi.ArgumentList.Add(b64);
            using var p = Process.Start(psi);
            if (p is null) return CommandResult.Failed;
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(2));
            try { await p.WaitForExitAsync(cts.Token); }
            catch (OperationCanceledException) { try { p.Kill(); } catch (InvalidOperationException) { } return CommandResult.Failed; }
            state.Dirty = true;
            // 4: declined in the helper's own confirmation; 6: more than its window can show in full
            return p.ExitCode switch { 0 => CommandResult.Done, 2 => CommandResult.Refused, 4 => CommandResult.Cancelled, 6 => CommandResult.TooLarge, _ => CommandResult.Failed };
        }
        catch (Win32Exception e) when (e.NativeErrorCode == 1223) { return CommandResult.Cancelled; }   // UAC declined
        catch (Win32Exception) { return CommandResult.Failed; }
        finally { _busy = false; }
    }

    /// <summary>Several steps behind one prompt (duplicates removed); a single step is sent as itself. A request the
    /// helper's confirmation could not show in full is not sent (the helper would refuse it after the UAC prompt).</summary>
    public async Task<CommandResult> Ops(IEnumerable<JsonObject?> ops)
    {
        var list = new List<JsonObject>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var o in ops)
            if (o is not null && seen.Add(string.Join(";", o.OrderBy(kv => kv.Key, StringComparer.Ordinal).Select(kv => $"{kv.Key}={Ps.Str(kv.Value)}")))) list.Add(o);
        if (list.Count == 0) return CommandResult.Refused;
        var cmd = list.Count == 1 ? list[0] : new JsonObject { ["action"] = "batch", ["ops"] = new JsonArray(list.Select(o => (JsonNode)o).ToArray()) };
        var paths = state.Paths;
        var summary = await Task.Run(() => RequestSummary.Build(cmd, RequestSummary.LookupFor(paths)));   // reads files: off the UI thread
        if (!summary.Complete) return CommandResult.TooLarge;
        return await Admin(cmd);
    }

    /// <summary>resume / scan-now without a prompt: over the engine's pipe (answered at once); when the engine is not
    /// reachable through inbox\ (read at its next start); when even that fails, through the elevated helper.</summary>
    public async Task<CommandResult> User(JsonObject cmd)
    {
        if (cmd.Str("user").Length == 0) cmd["user"] = Environment.UserName;
        var (reached, ok, _) = await EnginePipe.SendAsync(cmd, 5_000);
        if (reached)
        {
            state.Dirty = true;
            return ok ? CommandResult.Done : CommandResult.Refused;
        }
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
        _ => "The change could not be completed. Nothing was changed.",
    };
}

/// <summary>Things the tray starts for the user: browser pages, Explorer, terminals (argument vectors, never shell strings).</summary>
public static class Shell
{
    // Each returns false when nothing was opened, so the caller can tell the user why

    public static bool OpenUrl(string url)
    {
        if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) return false;
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); return true; } catch (Win32Exception) { return false; }
    }

    /// <summary>Opens a document with its associated app; without one (e.g. .md on a fresh Windows) in Notepad.</summary>
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
    public static bool VirusTotal(string file, string? knownSha256)
    {
        var sha = knownSha256 is { Length: 64 } ? knownSha256 : File.Exists(file) ? Tools.Sha256Of(file) : null;
        return sha is not null && OpenUrl($"https://www.virustotal.com/gui/file/{sha.ToLowerInvariant()}");
    }

    /// <summary>Starts a program elevated; false when the UAC prompt was declined or it could not start.</summary>
    public static bool Elevated(string file, IEnumerable<string> args, bool minimized = false)
    {
        var psi = new ProcessStartInfo(file) { UseShellExecute = true, Verb = "runas", WindowStyle = minimized ? ProcessWindowStyle.Minimized : ProcessWindowStyle.Normal };
        foreach (var a in args) psi.ArgumentList.Add(a);
        try { Process.Start(psi); return true; } catch (Win32Exception) { return false; }
    }
}
