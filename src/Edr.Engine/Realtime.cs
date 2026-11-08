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

    /// <summary><paramref name="OnlyIfHit"/>: the behaviour alert was allowed, so only a YARA match is reported (no "not
    /// scanned" alert for an allowed program).</summary>
    private sealed record YaraJob(string Blade, string Severity, string Title, string Image, string Detail, JsonObject Extra, bool OnlyIfHit = false);

    /// <summary>YARA jobs for allowed programs never take more than half the queue: the alerts that were not allowed
    /// keep their YARA scan under load.</summary>
    public const int AllowedYaraShare = 100;

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
            var blade = job.Blade; var sev = job.Severity; var title = job.Title; var detail = job.Detail;
            var hit = false;
            try
            {
                var r = ScanFile(job.Image);
                if (r.Hit is not null) { hit = true; blade = "yara"; sev = "Critical"; title = $"YARA match: {r.Hit}"; job.Extra["yaraRule"] = r.Hit; }
                else if (r.NotScanned is not null && !job.OnlyIfHit) NotScanned(job, r.NotScanned, ref detail);
            }
            catch (Exception e)
            {
                _ctx.Log.Warn($"YARA scan failed: {e.Message}");
                if (!job.OnlyIfHit) NotScanned(job, $"the scan failed ({e.GetType().Name})", ref detail);
            }
            if (job.OnlyIfHit && !hit) continue;   // allowed behaviour, no match: nothing to report
            _ctx.Event(blade, sev, title, job.Image, detail, job.Extra);
        }
    }

    private long _yaraNotScanned, _yaraNotScannedReported;
    private DateTime _yaraNotScannedAlert = DateTime.MinValue;

    /// <summary>Files YARA could not check (unreadable, too large, timed out, sandbox down) since the engine started.</summary>
    public long YaraNotScanned => Interlocked.Read(ref _yaraNotScanned);

    /// <summary>A file YARA could not check is never reported or cached as clean: the alert says so, and it is counted.</summary>
    private void NotScanned(YaraJob job, string why, ref string detail)
    {
        job.Extra["yaraNotScanned"] = why;
        detail = (detail.Length > 0 ? detail + "\n" : "") + $"YARA could not check this file: {why}.";
        Interlocked.Increment(ref _yaraNotScanned);
    }

    /// <summary>Every minute (main loop): at most once an hour, one health alert for the files YARA could not check.</summary>
    public void ReportYaraNotScanned()
    {
        var n = YaraNotScanned;
        if (n == _yaraNotScannedReported || DateTime.Now - _yaraNotScannedAlert < TimeSpan.FromHours(1)) return;
        var count = n - _yaraNotScannedReported;
        _yaraNotScannedReported = n;
        _yaraNotScannedAlert = DateTime.Now;
        _ctx.Event("system", "Medium", $"YARA could not check {count} file{(count == 1 ? "" : "s")}",
                   detail: "The program behind these alerts was not scanned by YARA (unreadable, larger than 50 MB, a scan that timed out, or the sandbox could not start). " +
                           "Each alert says why. Scan such a file with Microsoft Defender.",
                   extra: new() { ["kind"] = "health", ["count"] = count });
    }

    private bool _sandboxWarned;
    public const long YaraMaxBytes = 50L * 1024 * 1024;

    internal readonly record struct YaraResult(string? Hit, string? NotScanned);

    /// <summary>
    /// One file: Hit = the first matching rule; NotScanned = why it could not be checked (never treated as clean).
    /// Results are cached by <see cref="Win32.FileChangeStamp"/> (volume + file index + change-journal number), which the
    /// file's owner cannot set back the way they can a timestamp; without a stamp the file is scanned every time.
    /// </summary>
    internal YaraResult ScanFile(string image)
    {
        var fi = new FileInfo(image);
        if (!fi.Exists) return new(null, "the file no longer exists");
        if (fi.Length > YaraMaxBytes) return new(null, "larger than 50 MB");
        var key = Win32.FileChangeStamp(image);
        if (key is not null && _yaraCache.TryGetValue(key, out var cached)) return new(cached, null);
        string[] args = File.Exists(_ctx.Paths.CompiledYara) ? ["-C", _ctx.Paths.CompiledYara, image] : [.. _yaraRuleFiles, image];
        if (!File.Exists(_ctx.Paths.YaraExe) || args.Length <= 1) return new(null, "YARA or its rules are not installed");
        // YARA parses files any user can drop: it runs at low integrity with no privileges, in a one-process job
        var run = Sandbox.RunCapture(_ctx.Paths.YaraExe, args, timeoutSeconds: 60, memoryMb: 1024);
        if (!run.Started)
        {
            if (!_sandboxWarned) { _ctx.Log.Error($"YARA sandbox could not start, file not scanned: {run.Error}"); _sandboxWarned = true; }
            return new(null, "the YARA sandbox could not start");   // never fall back to running the parser with the engine's SYSTEM rights
        }
        var r = ParseYaraOutput(run.Exit, run.Output, run.Error);
        if (r.NotScanned is null && key is not null)
        {
            if (_yaraCache.Count > 1000) _yaraCache.Clear();
            _yaraCache[key] = r.Hit;
        }
        return r;
    }

    /// <summary>yara64 output: "RuleName path" per match, "error ..." when it could not scan; a timeout or a non-zero exit
    /// without a match is a failed scan, never a clean one.</summary>
    internal static YaraResult ParseYaraOutput(int exit, string output, string error)
    {
        if (error.Length > 0) return new(null, error == "timeout" ? "the scan timed out" : error);
        var lines = output.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).ToList();
        var err = lines.FirstOrDefault(l => l.StartsWith("error", StringComparison.OrdinalIgnoreCase));
        var hit = lines.FirstOrDefault(l => !l.StartsWith("error", StringComparison.OrdinalIgnoreCase) && !l.StartsWith("warning", StringComparison.OrdinalIgnoreCase))?.Split(' ')[0].Trim();
        if (!string.IsNullOrEmpty(hit)) return new(hit, null);
        if (err is not null) return new(null, err.Length > 200 ? err[..200] : err);
        if (exit != 0) return new(null, $"YARA ended with exit code {exit}");
        return new(null, null);
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
        var hash = r["Hashes"].Length > 0 ? Ps.Rx(",.*$").Replace(Ps.Rx("^.*SHA256=").Replace(r["Hashes"], ""), "") : "";
        if (Detection.RealtimeExcluded(_ctx.Excl["realtimePath"], _ctx.Excl["realtime"], rule, image, parent, detail, AncestorsOf, _signers) is { } allow)
        {
            // A real-time allow hides the behaviour alert only: a known-malware hash or a YARA match of the program is
            // still reported (what "Allow everything it starts" promises), unless an IOC / YARA allow covers it
            AllowedMalwareCheck(r, rule, image, parent, detail, hash, allow);
            return;
        }

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
            if (KnownMalware(hash) is { } name)
            {
                blade = "ioc"; sev = "Critical";
                title = name.Length > 0 ? $"Known malware: {name}" : $"Known malware hash ({rule})";
                extra["threat"] = name;
            }
            if (YaraCandidate(image))
            {
                if (_yaraQueue.TryAdd(new YaraJob(blade, sev, title, image, detail, extra))) return;
                extra["yaraSkipped"] = true;   // queue overflow under a flood: report without YARA rather than block intake
                Dropped++;
            }
        }
        _ctx.Event(blade, sev, title, image, detail, extra);
    }

    /// <summary>The IOC name (may be empty) when the hash is known malware and no IOC allow covers it; else null.</summary>
    private string? KnownMalware(string hash) =>
        hash.Length > 0 && _ioc.TryGetValue(hash, out var name) && !_ctx.Excl["ioc"].Any(x => Ps.Eq(x.Str("sha256"), hash)) ? name : null;

    /// <summary>A program YARA checks: outside %SystemRoot%, still there, no YARA allow for it.</summary>
    private bool YaraCandidate(string image) =>
        image.Length > 0 && !image.StartsWith(EdrPaths.SystemRoot + "\\", StringComparison.OrdinalIgnoreCase) && File.Exists(image) &&
        !_ctx.Excl["yara"].Any(x => Ps.Like(image, x.Str("image")));

    /// <summary>
    /// The behaviour alert was allowed: the program is still checked against the malware hashes (at once) and YARA (in
    /// the background, at most <see cref="AllowedYaraShare"/> queued, results cached per file version), and only a hit is
    /// reported, as an "ioc" / "yara" alert that names the allow. Not while Anti-Malware is paused.
    /// </summary>
    private void AllowedMalwareCheck(EventRecord r, string rule, string image, string parent, string detail, string hash, JsonObject allow)
    {
        if (_ctx.State.IsPaused("malware")) return;
        var extra = new JsonObject
        {
            ["rule"] = rule, ["sha256"] = hash, ["parent"] = parent, ["user"] = r["User"], ["sysmonId"] = r.Id,
            ["allowedBehaviour"] = allow.Str("id").Length > 0 ? allow.Str("id") : "built-in",
        };
        var note = "The program's behaviour is allowed in FreeEDR, but the program itself matched a malware check.";
        if (KnownMalware(hash) is { } name)
        {
            extra["threat"] = name;
            _ctx.Event("ioc", "Critical", name.Length > 0 ? $"Known malware: {name}" : $"Known malware hash ({rule})", image, $"{detail}\n{note}", extra);
            return;
        }
        if (YaraCandidate(image) && _yaraQueue.Count < AllowedYaraShare)
            _yaraQueue.TryAdd(new YaraJob("realtime", "Medium", rule, image, $"{detail}\n{note}", extra, OnlyIfHit: true));
    }

    public void Dispose()
    {
        _stop.Cancel();
        _yaraQueue.CompleteAdding();
        _yaraThread?.Join(3000);
    }
}

/// <summary>Publisher lookups are slow, so they are cached per file change stamp (volume + file index + NTFS change-journal
/// number, <see cref="Win32.FileChangeStamp"/>): any rewrite of the file gives a new key, even when its size and
/// timestamps are put back. Files without a stamp (no change journal) and files in the usual user-writable folders are
/// always verified live.</summary>
internal sealed class SignerCache : ISignerLookup
{
    private readonly Edr.Core.Native.AuthenticodeSigners _inner = new();
    private readonly Dictionary<string, string?> _cache = new(StringComparer.Ordinal);

    public string? SignerOf(string path)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
        if (IsUserWritable(path)) return _inner.SignerOf(path);
        var k = Win32.FileChangeStamp(path);
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
