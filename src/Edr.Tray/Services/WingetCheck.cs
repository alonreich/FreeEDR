using System.Diagnostics;
using System.Text.Json.Nodes;
using Edr.Core;

namespace Edr.Tray.Services;

/// <summary>Installed apps with updates (winget upgrade), checked in the user's context at the scan times.</summary>
public sealed class WingetCheck(TrayState state)
{
    private Task<string?>? _task;
    private DateTime _next = DateTime.Now.AddMinutes(2);

    public bool Running => _task is { IsCompleted: false };

    public void CheckSoon(TimeSpan delay) => _next = DateTime.Now + delay;

    public void Tick()
    {
        if (_task is not null)
        {
            if (!_task.IsCompleted) return;
            var output = _task.IsCompletedSuccessfully ? _task.Result : null;
            _task = null;
            if (output is null) return;
            try { File.WriteAllText(state.Paths.WingetFile, output); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
            var stamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            state.SetPatchResults(Parse(output.Split('\n')).Select(a => new Rec(new JsonObject
            {
                ["id"] = $"app-{a.Id}", ["time"] = stamp, ["blade"] = "patch", ["kind"] = "app", ["severity"] = "Info",
                ["title"] = $"{a.Name}: {a.Version} -> {a.Latest}", ["process"] = a.Name, ["appId"] = a.Id, ["version"] = a.Version, ["latest"] = a.Latest,
                ["detail"] = $"winget id: {a.Id}",
            })).ToList());
            return;
        }
        if (DateTime.Now < _next) return;
        _next = EdrConfig.ScanSlots(state.Config.ScanTimes, DateTime.Now).Next;
        _task = Task.Run(Run);
    }

    private static string? Run()
    {
        try
        {
            var psi = new ProcessStartInfo("winget.exe") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, StandardOutputEncoding = System.Text.Encoding.UTF8 };
            foreach (var a in new[] { "upgrade", "--accept-source-agreements", "--disable-interactivity" }) psi.ArgumentList.Add(a);
            using var p = Process.Start(psi);
            if (p is null) return null;
            var o = p.StandardOutput.ReadToEndAsync();
            if (!p.WaitForExit(300_000)) { try { p.Kill(); } catch (InvalidOperationException) { } return null; }
            return o.Result;
        }
        catch (System.ComponentModel.Win32Exception) { return null; }
    }

    public sealed record App(string Name, string Id, string Version, string Latest);

    /// <summary>winget's fixed-width table (column positions from the header line).</summary>
    public static List<App> Parse(IEnumerable<string> lines)
    {
        var clean = lines.Select(l => l.Split('\r').Last()).ToList();
        var h = clean.FindIndex(l => Ps.Rx(@"^Name\s+Id\s+Version\s+Available").IsMatch(l));
        var apps = new List<App>();
        if (h < 0) return apps;
        var hdr = clean[h];
        int cId = hdr.IndexOf("Id", StringComparison.Ordinal), cVer = hdr.IndexOf("Version", StringComparison.Ordinal),
            cAv = hdr.IndexOf("Available", StringComparison.Ordinal), cSrc = hdr.IndexOf("Source", StringComparison.Ordinal);
        for (var i = h + 2; i < clean.Count; i++)
        {
            var l = clean[i];
            if (l.Trim().Length == 0 || Ps.Rx(@"^\d+ upgrades? available").IsMatch(l) || l.Length <= cAv) break;
            string Get(int a, int b) { if (b < 0 || b > l.Length) b = l.Length; return a >= l.Length ? "" : l[a..b].Trim(); }
            var app = new App(Get(0, cId), Get(cId, cVer), Get(cVer, cAv), Get(cAv, cSrc));
            if (app.Id.Length > 0 && app.Latest.Length > 0) apps.Add(app);
        }
        return apps;
    }
}
