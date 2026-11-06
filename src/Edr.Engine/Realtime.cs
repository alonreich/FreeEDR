using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using System.Xml;
using Edr.Core;
using Edr.Core.Native;

namespace Edr.Engine;

/// <summary>
/// Real-time detection from Sysmon (process starts, risky tools, LSASS access, persistence, drivers, WMI), enriched
/// with the IOC hash list and a background YARA scan of the program behind the alert. Detect-only: nothing is stopped.
/// </summary>
internal sealed class Realtime : IDisposable
{
    private readonly Context _ctx;
    private readonly SignerCache _signers = new();
    private readonly Dictionary<string, string> _ioc = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _iocStamp = DateTime.MinValue;
    private readonly HashSet<string> _ruleNames = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _nearMiss = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<int, Win32.ProcInfo> _snapshot = [];
    private DateTime _snapshotTime = DateTime.MinValue;
    private readonly BlockingCollection<YaraJob> _yaraQueue = new(200);
    private readonly ConcurrentDictionary<string, string?> _yaraCache = new(StringComparer.OrdinalIgnoreCase);
    private Thread? _yaraThread;
    private readonly CancellationTokenSource _stop = new();
    private List<string> _yaraRuleFiles = [];

    public string? StaleRule { get; private set; }
    public DateTime StaleRuleTime { get; private set; } = DateTime.MinValue;
    public int Dropped { get; private set; }
    public int YaraBacklog => _yaraQueue.Count;
    public int IocCount => _ioc.Count;
    public IReadOnlyList<string> YaraRuleNames => _yaraRuleFiles.Select(Path.GetFileName).Select(s => s ?? "").ToList();

    private sealed record YaraJob(string Blade, string Severity, string Title, string Image, string Detail, JsonObject Extra);

    public Realtime(Context ctx) => _ctx = ctx;

    // ---- rule sets -------------------------------------------------------------------------------------

    /// <summary>Accepts "sha256" or "sha256;comment" lines (signature-base format); md5/sha1 lines are skipped.</summary>
    public void UpdateIocSet()
    {
        var f = _ctx.Paths.IocFile;
        if (!File.Exists(f)) return;
        var t = File.GetLastWriteTimeUtc(f);
        if (t == _iocStamp) return;
        _iocStamp = t;
        _ioc.Clear();
        foreach (var l in File.ReadLines(f))
        {
            var m = Ps.Rx(@"^\s*([0-9a-fA-F]{64})\s*(?:;(.*))?$").Match(l);
            if (m.Success) _ioc[m.Groups[1].Value] = m.Groups[2].Value;
        }
        _ctx.Log.Info($"IOC hash list loaded: {_ioc.Count} SHA256 hashes");
    }

    /// <summary>Rule names of the applied Sysmon config: an alert with any other name means the driver still runs an older rule set.</summary>
    public void UpdateRuleNames()
    {
        _ruleNames.Clear();
        try
        {
            var doc = new XmlDocument();
            doc.Load(_ctx.Paths.SysmonConfig);
            foreach (XmlElement n in doc.SelectNodes("//EventFiltering//*[@name]")!)
                if (n.LocalName != "RuleGroup") _ruleNames.Add(n.GetAttribute("name"));
        }
        catch (Exception e) when (e is XmlException or IOException or UnauthorizedAccessException) { _ctx.Log.Warn($"Could not read the Sysmon rule names: {e.Message}"); }
    }

    public void UpdateYaraRules()
    {
        _yaraRuleFiles = [];
        var yara = _ctx.Paths.YaraExe;
        if (!File.Exists(yara)) return;
        var probe = Path.Combine(EdrPaths.System32, "notepad.exe");
        foreach (var r in Directory.Exists(_ctx.Paths.RulesDir) ? Directory.GetFiles(_ctx.Paths.RulesDir, "*.yar") : [])
        {
            var (exit, _) = Tools.RunCapture(yara, [r, probe], timeoutSeconds: 60);
            if (exit == 0) _yaraRuleFiles.Add(r); else _ctx.Log.Warn($"YARA rule file skipped (does not compile): {Path.GetFileName(r)}");
        }
        _ctx.Log.Info($"YARA rule files loaded: {string.Join(", ", YaraRuleNames)}");
        if (File.Exists(_ctx.Paths.YaracExe) && _yaraRuleFiles.Count > 0)
        {
            var tmp = _ctx.Paths.CompiledYara + ".tmp";
            var (exit, _) = Tools.RunCapture(_ctx.Paths.YaracExe, [.. _yaraRuleFiles, tmp], timeoutSeconds: 120);
            if (exit == 0 && File.Exists(tmp)) { File.Move(tmp, _ctx.Paths.CompiledYara, true); _ctx.Log.Info("YARA rules precompiled"); }
            else _ctx.Log.Warn($"Failed to precompile YARA rules with yarac64 (exit code {exit})");
        }
    }

    public void StartYaraWorker()
    {
        _yaraThread = new Thread(YaraLoop) { IsBackground = true, Name = "YARA worker" };
        _yaraThread.Start();
        _ctx.Log.Info("YARA background worker started");
    }

    private void YaraLoop()
    {
        foreach (var job in _yaraQueue.GetConsumingEnumerable(_stop.Token).AsEnumerableSafe())
        {
            var blade = job.Blade; var sev = job.Severity; var title = job.Title;
            try
            {
                var hit = ScanFile(job.Image);
                if (hit is not null) { blade = "yara"; sev = "Critical"; title = $"YARA match: {hit}"; job.Extra["yaraRule"] = hit; }
            }
            catch (Exception e) { _ctx.Log.Warn($"YARA scan failed: {e.Message}"); }
            _ctx.Event(blade, sev, title, job.Image, job.Detail, job.Extra);
        }
    }

    private string? ScanFile(string image)
    {
        var fi = new FileInfo(image);
        if (!fi.Exists || fi.Length > 50L * 1024 * 1024) return null;
        var key = $"{image}|{fi.LastWriteTimeUtc.Ticks}";
        if (_yaraCache.TryGetValue(key, out var cached)) return cached;
        string[] args = File.Exists(_ctx.Paths.CompiledYara) ? ["-C", _ctx.Paths.CompiledYara, image] : [.. _yaraRuleFiles, image];
        string? hit = null;
        if (File.Exists(_ctx.Paths.YaraExe) && args.Length > 1)
        {
            var (_, output) = Tools.RunCapture(_ctx.Paths.YaraExe, args, timeoutSeconds: 60);
            var first = output.Split('\n').FirstOrDefault(l => l.Trim().Length > 0 && !l.StartsWith("error", StringComparison.OrdinalIgnoreCase) && !l.StartsWith("warning", StringComparison.OrdinalIgnoreCase));
            hit = first?.Split(' ')[0].Trim();
            if (string.IsNullOrEmpty(hit)) hit = null;
        }
        if (_yaraCache.Count > 1000) _yaraCache.Clear();
        _yaraCache[key] = hit;
        return hit;
    }

    // ---- process chain ---------------------------------------------------------------------------------

    private Dictionary<int, Win32.ProcInfo> Snapshot()
    {
        if ((DateTime.Now - _snapshotTime).TotalSeconds >= 2) { _snapshot = Win32.ProcessSnapshot(); _snapshotTime = DateTime.Now; }
        return _snapshot;
    }

    /// <summary>Parent, grandparent, ... (up to 3): each step checks it really is the logged process (same path, started earlier).</summary>
    private List<string> Ancestors(EventRecord r)
    {
        var list = new List<string>();
        var par = r["ParentImage"];
        if (par.Length > 0) list.Add(par);
        if (!int.TryParse(r["ParentProcessId"], out var pid) || pid <= 4) return list;
        var snap = Snapshot();
        if (!snap.TryGetValue(pid, out var p) || !Ps.Eq(p.Path, par)) return list;
        while (list.Count < Catalog.MaxAncestors && p.ParentPid > 4 && snap.TryGetValue(p.ParentPid, out var q))
        {
            if (q.Path.Length == 0 || q.Created > p.Created) break;
            list.Add(q.Path);
            p = q;
        }
        return list;
    }

    // ---- the pipeline ----------------------------------------------------------------------------------

    public void Handle(EventRecord r)
    {
        if (_ctx.State.IsPaused("realtime")) return;
        var rule = r["RuleName"].Trim();
        if (rule == "-") rule = "";
        if (rule.Length == 0 && r.Id is 19 or 20 or 21) rule = "WMI persistence";   // WMI is logged without a rule name
        if (rule.Length == 0) return;

        switch (OwnProcess.Check(r.Data, _ctx.Paths.Root))
        {
            case OwnProcess.Verdict.Own: return;
            case OwnProcess.Verdict.NearMiss:
                var nm = Ps.Rx("FreeEDR-|EDR-(Engine|Scan|Tray|Control)").IsMatch(r["CommandLine"]) ? r["CommandLine"] : r["ParentCommandLine"];
                if (_nearMiss.Add(nm))
                {
                    var img0 = r["Image"].Length > 0 ? r["Image"] : r["ParentImage"];
                    _ctx.Log.Warn($"Command line imitates FreeEDR's own programs: {nm}");
                    _ctx.Event("realtime", "High", "Command line imitates FreeEDR's own scripts", img0, nm,
                               new() { ["rule"] = "Command line imitates FreeEDR's own scripts", ["user"] = r["User"], ["parent"] = r["ParentImage"], ["sysmonId"] = r.Id });
                }
                break;
        }

        var oldRule = _ruleNames.Count > 0 && rule != "WMI persistence" && !_ruleNames.Contains(rule);
        if (oldRule) { StaleRule = rule; StaleRuleTime = DateTime.Now; }
        var image = r["Image"].Length > 0 ? r["Image"] : r["SourceImage"].Length > 0 ? r["SourceImage"] : r["ImageLoaded"];
        var parent = r["ParentImage"];
        var detail = r.Id switch
        {
            3 => $"Connected to {r["DestinationIp"]}:{r["DestinationPort"]} {r["DestinationHostname"]}".Trim(),
            6 => $"Driver: {r["ImageLoaded"]}  Signature: {r["Signature"]} ({r["SignatureStatus"]})",
            8 => $"Injected into: {r["TargetImage"]}",
            10 => $"Opened {r["TargetImage"]} with access {r["GrantedAccess"]}",
            11 => $"Created: {r["TargetFilename"]}",
            12 or 13 or 14 => r["TargetObject"] + (r["Details"].Length > 0 ? " = " + r["Details"] : ""),
            19 or 20 or 21 => $"WMI {r["Operation"]} {r["EventType"]}: {r["Name"]} {r["Query"]} {r["Destination"]}".Trim(),
            _ => r["CommandLine"],
        };

        List<string>? anc = null;
        IReadOnlyList<string> AncestorsOf(int n) => (anc ??= Ancestors(r)).Take(Math.Max(1, n)).ToList();
        if (Detection.RealtimeExcluded(_ctx.Excl["realtimePath"], _ctx.Excl["realtime"], rule, image, parent, detail, AncestorsOf, _signers) is not null) return;

        var hash = r["Hashes"].Length > 0 ? Ps.Rx(",.*$").Replace(Ps.Rx("^.*SHA256=").Replace(r["Hashes"], ""), "") : "";
        var blade = "realtime";
        var sev = Catalog.RuleSeverity.TryGetValue(rule, out var s) ? s : r.Id is 19 or 20 or 21 ? "High" : "Medium";
        var title = rule;
        var extra = new JsonObject { ["rule"] = rule, ["sha256"] = hash, ["parent"] = parent, ["user"] = r["User"], ["sysmonId"] = r.Id };
        if (oldRule) extra["oldRule"] = true;
        if (r.Id == 1)
        {
            var a = AncestorsOf(Catalog.MaxAncestors).Skip(1).ToList();   // grandparent and up, for "allowed by" in the tray
            if (a.Count > 0) extra["ancestors"] = a.ToJsonArray();
        }

        if (!_ctx.State.IsPaused("malware"))
        {
            if (hash.Length > 0 && _ioc.TryGetValue(hash, out var name) && !_ctx.Excl["ioc"].Any(x => Ps.Eq(x.Str("sha256"), hash)))
            {
                blade = "ioc"; sev = "Critical";
                title = name.Length > 0 ? $"Known malware: {name}" : $"Known malware hash ({rule})";
                extra["threat"] = name;
            }
            if (image.Length > 0 && !image.StartsWith(EdrPaths.SystemRoot + "\\", StringComparison.OrdinalIgnoreCase) && File.Exists(image) &&
                !_ctx.Excl["yara"].Any(x => Ps.Like(image, x.Str("image"))))
            {
                if (_yaraQueue.TryAdd(new YaraJob(blade, sev, title, image, detail, extra))) return;
                extra["yaraSkipped"] = true;   // queue overflow under a flood: report without YARA rather than block intake
                Dropped++;
            }
        }
        _ctx.Event(blade, sev, title, image, detail, extra);
    }

    public void Dispose()
    {
        _stop.Cancel();
        _yaraQueue.CompleteAdding();
        _yaraThread?.Join(3000);
    }
}

/// <summary>Publisher lookups are slow, so they are cached per file identity; files in user-writable folders are always
/// verified live (a user process could swap the file between lookups).</summary>
internal sealed class SignerCache : ISignerLookup
{
    private readonly Edr.Core.Native.AuthenticodeSigners _inner = new();
    private readonly Dictionary<string, string?> _cache = new(StringComparer.Ordinal);

    public string? SignerOf(string path)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
        if (IsUserWritable(path)) return _inner.SignerOf(path);
        var k = Win32.FileIdentity(path);
        if (k is null) return _inner.SignerOf(path);
        lock (_cache)
        {
            if (_cache.TryGetValue(k, out var s)) return s;
            if (_cache.Count > 2000) _cache.Clear();
        }
        var v = _inner.SignerOf(path);
        lock (_cache) _cache[k] = v;
        return v;
    }

    public static bool IsUserWritable(string path)
    {
        var pr = EdrPaths.ProfilesRoot;
        if (pr.Length > 0 && path.StartsWith(pr + "\\", StringComparison.OrdinalIgnoreCase)) return true;
        if (path.StartsWith(EdrPaths.SystemRoot + @"\Temp\", StringComparison.OrdinalIgnoreCase)) return true;
        return path.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase);
    }
}

internal static class EnumerableExtensions
{
    /// <summary>Ends the enumeration quietly when the consuming enumerable is cancelled.</summary>
    public static IEnumerable<T> AsEnumerableSafe<T>(this IEnumerable<T> source)
    {
        using var e = source.GetEnumerator();
        while (true)
        {
            try { if (!e.MoveNext()) yield break; }
            catch (OperationCanceledException) { yield break; }
            yield return e.Current;
        }
    }
}
