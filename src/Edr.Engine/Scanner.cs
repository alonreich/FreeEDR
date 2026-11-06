using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using Edr.Core;

namespace Edr.Engine;

/// <summary>
/// The scheduled scan (scanTimes, catch-up after the PC was off; "Scan now" at most every 2 minutes):
/// A. IOC feed (kept on failure) B. Sigma rules update + Hayabusa over recent event logs C. OSV scan of every account's
/// Python (only vulnerabilities with a released fix) D. tool version check. Runs on a background task; a run over 2 hours
/// is stopped. The result (data\scan-result.json) is turned into alerts on the engine thread by <see cref="Complete"/>.
/// </summary>
internal sealed class Scanner(Context ctx)
{
    private Task<JsonObject>? _task;
    private CancellationTokenSource? _cts;
    private DateTime _started;
    private string _trigger = "schedule";
    private DateTime _lastManual = DateTime.MinValue;

    public bool Running => _task is { IsCompleted: false };

    public DateTime NextDue()
    {
        var (prev, next) = EdrConfig.ScanSlots(ctx.Cfg.ScanTimes, DateTime.Now);
        var last = Ps.ToDate(ctx.State.Get("lastScanStart")) ?? DateTime.MinValue;
        if (last < prev) return prev < ctx.Started ? ctx.Started.AddMinutes(5) : prev;   // missed while the PC was off
        return next;
    }

    public bool Start(string trigger)
    {
        if (Running || ctx.State.IsPaused("edr")) return false;
        _trigger = trigger;
        _started = DateTime.Now;
        ctx.State.Set("lastScanStart", _started.ToString("s", CultureInfo.InvariantCulture));
        ctx.State.Save();
        _cts = new CancellationTokenSource(TimeSpan.FromHours(2));
        var token = _cts.Token;
        _task = Task.Run(() => Run(token), token);
        ctx.Log.Audit($"Scan started ({trigger})");
        return true;
    }

    public bool StartManual()
    {
        if ((DateTime.Now - _lastManual).TotalMinutes < 2) return false;
        _lastManual = DateTime.Now;
        if (ctx.State.IsPaused("edr")) { ctx.Event("system", "Info", "Scan not started: EDR is paused", extra: new() { ["kind"] = "status" }); return false; }
        if (!Start("manual")) ctx.Event("system", "Info", "A scan is already running", extra: new() { ["kind"] = "status" });
        return true;
    }

    public void Stop(string why)
    {
        if (!Running) return;
        _cts?.Cancel();
        ctx.Log.Audit($"Scan stopped: {why}");
    }

    /// <summary>Every minute: start a due scan, or finish a completed one.</summary>
    public void Watch()
    {
        if (_task is not null)
        {
            if (!_task.IsCompleted) return;
            JsonObject? result = null;
            try { if (_task.IsCompletedSuccessfully) result = _task.Result; }
            catch (AggregateException e) { ctx.Log.Error($"Scan failed: {e.InnerException?.Message}"); }
            _task = null;
            if (result is null && _cts?.IsCancellationRequested == true && (DateTime.Now - _started).TotalHours >= 2) ctx.Log.Audit("Scan stopped: exceeded 2 hours");
            Complete(result);
            return;
        }
        if (!ctx.State.IsPaused("edr") && DateTime.Now >= NextDue()) Start("schedule");
    }

    // ---- the scan itself (background) ------------------------------------------------------------------

    private JsonObject Run(CancellationToken ct)
    {
        var result = new JsonObject
        {
            ["started"] = _started.ToString("s", CultureInfo.InvariantCulture), ["finished"] = null,
            ["steps"] = new JsonArray(), ["sigma"] = new JsonArray(), ["vulns"] = new JsonArray(), ["tools"] = new JsonArray(), ["toolCheck"] = null,
        };
        var log = new TextLog(ctx.Paths.ScanLog, 2L * 1024 * 1024);
        void Step(string name, bool ok, string message)
        {
            result.Arr("steps").Add((JsonNode)new JsonObject { ["name"] = name, ["ok"] = ok, ["message"] = message, ["time"] = DateTime.Now.ToString("s", CultureInfo.InvariantCulture) });
            log.Write(ok ? 'I' : 'E', $"{name}: {message}");
        }
        log.Info("=== Scan started");
        try
        {
            IocFeed(Step, ct);
            Sigma(result, Step, log, ct);
            Osv(result, Step, log, ct);
            ToolVersions(result, Step, ct);
        }
        catch (OperationCanceledException) { Step("Scan", false, "stopped (paused, or running over 2 hours)"); }
        result["finished"] = DateTime.Now.ToString("s", CultureInfo.InvariantCulture);
        try { JsonFile.WriteAtomic(ctx.Paths.ScanResultFile, result); } catch (IOException e) { log.Error($"Could not write scan-result.json: {e.Message}"); }
        log.Info("=== Scan finished");
        return result;
    }

    private void IocFeed(Action<string, bool, string> step, CancellationToken ct)
    {
        const string name = "IOC hash feed update";
        if (ctx.State.IsPaused("malware")) { step(name, true, "Skipped: Anti-Malware is paused"); return; }
        var f = ctx.Paths.IocFile;
        var tmp = f + ".download";
        var code = 0;
        var valid = 0;
        try
        {
            using var resp = Tools.Http.GetAsync(ctx.Cfg.IocFeedUrl, ct).GetAwaiter().GetResult();
            code = (int)resp.StatusCode;
            if (resp.IsSuccessStatusCode)
            {
                var text = resp.Content.ReadAsStringAsync(ct).GetAwaiter().GetResult();
                valid = text.Split('\n').Count(l => Ps.Rx(@"^\s*[0-9a-fA-F]{64}\s*(;|$)").IsMatch(l.TrimEnd('\r')));
                if (valid >= 100) { File.WriteAllText(tmp, text, JsonFile.Utf8NoBom); File.Move(tmp, f, true); }
            }
        }
        catch (Exception e) when (e is HttpRequestException or IOException or TaskCanceledException) { if (ct.IsCancellationRequested) throw new OperationCanceledException(); }
        finally { JsonFile.TryDelete(tmp); }
        if (valid >= 100) step(name, true, $"{valid} SHA256 malware hashes from {ctx.Cfg.IocFeedUrl}");
        else
        {
            var have = File.Exists(f) ? File.ReadLines(f).Count(l => Ps.Rx(@"^\s*[0-9a-fA-F]{64}").IsMatch(l)) : 0;
            step(name, false, $"HTTP {code}, {valid} usable hashes - kept the previous list ({have} hashes)");
        }
    }

    private void Sigma(JsonObject result, Action<string, bool, string> step, TextLog log, CancellationToken ct)
    {
        if (ctx.State.IsPaused("sigma")) { step("Sigma rules update", true, "Skipped: Sigma scanning is paused"); step("Sigma event-log scan", true, "Skipped: Sigma scanning is paused"); return; }
        var haya = ctx.Paths.HayabusaExe;
        if (!File.Exists(haya)) { step("Sigma event-log scan", false, $"hayabusa.exe not found in {ctx.Paths.HayabusaDir}"); return; }
        // Hayabusa 4.x resolves rules\ and config\ relative to its working directory
        var (exit, output) = Tools.RunCapture(haya, ["update-rules", "-q"], ctx.Paths.HayabusaDir, 600, ct);
        log.Info(output.Trim());
        step("Sigma rules update", exit == 0, $"exit code {exit}");
        ct.ThrowIfCancellationRequested();

        var csv = Path.Combine(ctx.Paths.DataDir, "hayabusa_last_scan.csv");
        JsonFile.TryDelete(csv);
        (exit, output) = Tools.RunCapture(haya, ["dfir-timeline", "-l", "-w", "-q", "-Q", "-K", "-C", "-m", "high", "--time-offset", ctx.Cfg.SigmaLookback, "-o", csv], ctx.Paths.HayabusaDir, 3600, ct);
        ct.ThrowIfCancellationRequested();
        if (!File.Exists(csv)) { log.Info(output.Trim()); step("Sigma event-log scan", false, $"no output (exit code {exit}) - see data\\scan.log"); return; }
        const int maxRows = 2000;   // newest hits kept (bounded memory); more is reported as a problem
        var queue = new Queue<Dictionary<string, string>>();
        var total = 0;
        string[]? header = null;
        foreach (var row in Csv.Read(csv))
        {
            if (header is null) { header = row; continue; }
            if (row.Length == 1 && row[0].Length == 0) continue;
            total++;
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (var i = 0; i < header.Length && i < row.Length; i++) d[header[i]] = row[i];
            if (queue.Count >= maxRows) queue.Dequeue();
            queue.Enqueue(d);
        }
        foreach (var h in queue)
        {
            string G(string k) => h.TryGetValue(k, out var v) ? v : "";
            var details = G("ExtraFieldInfo").Length > 0 ? $"{G("Details")} ¦ {G("ExtraFieldInfo")}" : G("Details");
            result.Arr("sigma").Add((JsonNode)new JsonObject
            {
                ["title"] = G("RuleTitle"), ["level"] = G("Level"), ["details"] = details, ["timestamp"] = G("Timestamp"), ["computer"] = G("Computer"),
                ["channel"] = G("Channel"), ["eventId"] = G("EventID"), ["recordId"] = G("RecordID"), ["ruleId"] = G("RuleID"),
            });
        }
        step("Sigma event-log scan", total <= maxRows, total > maxRows
            ? $"{total} high/critical hits in the last {ctx.Cfg.SigmaLookback}; only the newest {maxRows} were checked - see data\\hayabusa_last_scan.csv for the rest"
            : $"{total} high/critical hits in the last {ctx.Cfg.SigmaLookback}");
    }

    private void Osv(JsonObject result, Action<string, bool, string> step, TextLog log, CancellationToken ct)
    {
        const string name = "Python vulnerability scan (OSV)";
        if (ctx.State.IsPaused("cve")) { step(name, true, "Skipped: CVE vulnerability scanning is paused"); return; }
        var osv = ctx.Paths.OsvExe;
        if (!File.Exists(osv)) { step(name, false, "osv-scanner.exe not found"); return; }
        var targets = new List<(string Dir, string Owner)>();
        foreach (var (sid, profile) in Accounts.All())
        {
            var py = Path.Combine(profile, "AppData", "Local", "Programs", "Python");
            if (Directory.Exists(py)) targets.Add((py, sid));
            var pkgs = Path.Combine(profile, "AppData", "Local", "Packages");
            if (Directory.Exists(pkgs))
                try { foreach (var d in Directory.GetDirectories(pkgs, "PythonSoftwareFoundation.Python*")) targets.Add((d, sid)); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }
        var failed = new List<string>();
        var noFix = 0;
        foreach (var (dir, owner) in targets)
        {
            ct.ThrowIfCancellationRequested();
            var (exit, output) = Tools.RunCapture(osv, ["scan", "source", "-r", dir, "--format", "json"], ctx.Paths.BinDir, 1200, ct);
            var jsonStart = output.IndexOf('{');
            var jsonEnd = output.LastIndexOf('}');
            var o = jsonStart >= 0 && jsonEnd > jsonStart ? JsonFile.Parse(output[jsonStart..(jsonEnd + 1)]) as JsonObject : null;
            if (o is null)
            {
                if (exit is 0 || output.Trim().Length == 0) continue;   // nothing found
                failed.Add(dir); log.Error($"OSV scan of {dir} failed (exit {exit})"); continue;
            }
            foreach (var v in OsvParser.Rows(o, owner, ref noFix)) result.Arr("vulns").Add((JsonNode)v);
        }
        if (failed.Count > 0) step(name, false, $"no result for {string.Join(", ", failed)} - kept the previous list (see data\\scan.log)");
        else step(name, true, $"{result.Arr("vulns").Count} vulnerabilities with an available update in {targets.Count} folders ({noFix} without a fix yet are not shown)");
    }

    private void ToolVersions(JsonObject result, Action<string, bool, string> step, CancellationToken ct)
    {
        var tools = new Tools(ctx.Paths);
        var ok = 0;
        var parts = new List<string>();
        foreach (var t in Tools.Pinned)
        {
            ct.ThrowIfCancellationRequested();
            var current = tools.InstalledVersion(t);
            var rel = tools.LatestRelease(t.Repo, null, ct).GetAwaiter().GetResult();
            var latest = rel is { } r ? Tools.VersionOf(r.Tag) : null;
            var outdated = latest is not null && current is not null && Version.TryParse(latest, out var lv) && Version.TryParse(current, out var cv) && lv > cv;
            if (latest is not null && current is not null) ok++;
            result.Arr("tools").Add((JsonNode)new JsonObject { ["name"] = t.Name, ["current"] = current, ["latest"] = latest, ["outdated"] = outdated, ["url"] = rel?.Url ?? $"https://github.com/{t.Repo}/releases" });
            parts.Add($"{t.Name} {current}{(outdated ? $" -> {latest} available" : "")}");
        }
        if (ok > 0) result["toolCheck"] = DateTime.Now.ToString("s", CultureInfo.InvariantCulture);
        step("EDR tool version check", ok > 0, string.Join(", ", parts));
    }

    // ---- results -> alerts (engine thread) -------------------------------------------------------------

    private void Complete(JsonObject? res)
    {
        res ??= JsonFile.ReadObject(ctx.Paths.ScanResultFile);
        if (res is not null && (Ps.ToDate(res.Str("started")) is not { } st || st < _started.AddSeconds(-5))) res = null;   // left over from an earlier scan
        ctx.State.Set("lastScanEnd", DateTime.Now.ToString("s", CultureInfo.InvariantCulture));
        int newSigma = 0, newCve = 0;
        var problems = new List<string>();
        var signers = new SignerCache();
        if (res is null) problems.Add("scan produced no result file");
        else
        {
            foreach (var s in res.Objects("steps")) if (!s.Truthy("ok")) problems.Add($"{s.Str("name")}: {s.Str("message")}");
            var seen = ctx.State.Seen("sigmaSeen");
            var defSeen = ctx.State.Seen("defSeen");
            foreach (var hit in res.Objects("sigma"))
            {
                var title = hit.Str("title");
                if (title.Length == 0 || Ps.Match(title, @"\(Sysmon Alert\)$")) continue;   // Hayabusa repeating our own Sysmon rules
                if (!seen.Add($"{title}|{hit.Str("computer")}|{hit.Str("channel")}|{hit.Str("recordId")}")) continue;
                var sp = SigmaProcess.FromDetails(hit.Str("details"));
                var sev = Ps.Match(hit.Str("level"), "^crit") || Ps.Match(title, "Severe") ? "Critical" : "High";
                if (Ps.Match(title, Catalog.DefenderSigmaTitles))
                {
                    var tm = Ps.Rx("Threat: ([^¦]+)").Match(hit.Str("details"));
                    var threat = tm.Success ? tm.Groups[1].Value.Trim() : title;
                    var ts = hit.Str("timestamp");
                    if (!defSeen.Add($"{threat}|{ts[..Math.Min(16, ts.Length)]}")) continue;
                    if (Detection.DefenderExcluded(ctx.Excl["defender"], ctx.Excl["realtime"], "", sp.Image)) continue;
                    ctx.Event("defender", sev, $"Defender detected malware: {threat}", sp.Image, hit.Str("details"),
                              new() { ["kind"] = "malware", ["threat"] = threat, ["eventTime"] = ts, ["source"] = "Sigma scan of the Defender log" });
                    continue;
                }
                if (Detection.SigmaExcluded(ctx.Excl["sigma"], title, sp.Parent, signers) is not null) continue;
                newSigma++;
                ctx.Event("sigma", sev, title, sp.Image.Length > 0 ? sp.Image : hit.Str("computer"), hit.Str("details"), new()
                {
                    ["level"] = hit.Str("level"), ["eventTime"] = hit.Str("timestamp"), ["channel"] = hit.Str("channel"), ["eventId"] = hit.Str("eventId"),
                    ["recordId"] = hit.Str("recordId"), ["ruleId"] = hit.Str("ruleId"), ["parent"] = sp.Parent, ["computer"] = hit.Str("computer"),
                });
            }
            ctx.State.SetSeen("sigmaSeen", seen, 20000);
            ctx.State.SetSeen("defSeen", defSeen, 2000);
            // The CVE list shows the latest scan only (patched packages disappear); events are just for history
            if (res.Objects("steps").Any(s => s.Str("name").Contains("OSV", StringComparison.Ordinal) && s.Truthy("ok")))
                JsonFile.WriteAtomic(ctx.Paths.CveFile, new JsonObject { ["scanned"] = DateTime.Now.ToString("s", CultureInfo.InvariantCulture), ["items"] = res["vulns"]?.DeepClone() ?? new JsonArray() });
            var cveSeen = ctx.State.Seen("cveSeen");
            foreach (var v in res.Objects("vulns"))
            {
                if (v.Str("id").Length == 0 || !cveSeen.Add(v.Str("id"))) continue;
                if (ctx.Excl["cve"].Any(x => x.Str("cve") == v.Str("id") || x.Str("cve") == v.Str("cve"))) continue;
                newCve++;
                ctx.Event("cve", v.Str("severity").Length > 0 ? v.Str("severity") : "Medium", $"{v.Str("cve")} in {v.Str("package")} {v.Str("version")} (fixed in {v.Str("fixed")})", v.Str("package"), v.Str("summary"),
                          new() { ["cve"] = v.Str("cve"), ["vulnId"] = v.Str("id"), ["package"] = v.Str("package"), ["version"] = v.Str("version"), ["fixed"] = v.Str("fixed"), ["path"] = v.Str("path") });
            }
            ctx.State.SetSeen("cveSeen", cveSeen, 50000);
            var toolSeen = ctx.State.Seen("toolSeen");
            foreach (var t in res.Objects("tools"))
            {
                if (t.Str("latest").Length == 0 || !t.Truthy("outdated") || !toolSeen.Add($"{t.Str("name")}|{t.Str("latest")}")) continue;
                ctx.Event("patch", "Info", $"EDR tool update: {t.Str("name")} {t.Str("current")} -> {t.Str("latest")}", t.Str("name"), $"Download: {t.Str("url")}",
                          new() { ["kind"] = "tool", ["tool"] = t.Str("name"), ["url"] = t.Str("url"), ["version"] = t.Str("current"), ["latest"] = t.Str("latest") });
            }
            ctx.State.SetSeen("toolSeen", toolSeen, 500);
            if (res.Str("toolCheck").Length > 0) ctx.State.Set("lastToolCheck", res.Str("toolCheck"));
        }
        ctx.State.Set("lastScanOk", problems.Count == 0);
        var summary = $"{newSigma} new Sigma alerts, {newCve} new vulnerabilities to patch" + (problems.Count > 0 ? "; problems: " + string.Join("; ", problems) : "");
        ctx.State.Set("lastScanSummary", summary);
        ctx.State.Save();
        ctx.Event("system", problems.Count > 0 ? "Medium" : "Info", $"Scan finished: {newSigma} new Sigma alerts, {newCve} new vulnerabilities",
                  detail: problems.Count > 0 ? "Problems: " + string.Join("\n", problems) : "All scan steps completed.",
                  extra: new() { ["kind"] = "scan", ["trigger"] = _trigger, ["newSigma"] = newSigma, ["newCve"] = newCve, ["ok"] = problems.Count == 0 });
        ctx.Log.Audit($"Scan finished: {summary}");
    }
}

/// <summary>Every real user account with a profile (SID + folder), read from Windows each time; works as SYSTEM.</summary>
internal static class Accounts
{
    public static List<(string Sid, string Profile)> All()
    {
        var list = new List<(string, string)>();
        try
        {
            using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
            if (k is null) return list;
            foreach (var sid in k.GetSubKeyNames())
            {
                if (!Ps.Rx(@"^S-1-(5-21|12-1)-[\d-]+$").IsMatch(sid)) continue;   // local, domain and Entra ID accounts
                using var s = k.OpenSubKey(sid);
                var p = Environment.ExpandEnvironmentVariables(s?.GetValue("ProfileImagePath") as string ?? "");
                if (p.Length > 0 && Directory.Exists(p)) list.Add((sid, p));
            }
        }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException) { }
        return list;
    }
}

/// <summary>RFC 4180 CSV reader (quoted fields, doubled quotes, newlines inside quotes), streamed.</summary>
internal static class Csv
{
    public static IEnumerable<string[]> Read(string path)
    {
        using var sr = new StreamReader(path, Encoding.UTF8);
        var fields = new List<string>();
        var sb = new StringBuilder();
        var inQuotes = false;
        int c;
        while ((c = sr.Read()) >= 0)
        {
            var ch = (char)c;
            if (inQuotes)
            {
                if (ch == '"') { if (sr.Peek() == '"') { sb.Append('"'); sr.Read(); } else inQuotes = false; }
                else sb.Append(ch);
                continue;
            }
            switch (ch)
            {
                case '"': inQuotes = true; break;
                case ',': fields.Add(sb.ToString()); sb.Clear(); break;
                case '\r': break;
                case '\n':
                    fields.Add(sb.ToString()); sb.Clear();
                    yield return fields.ToArray();
                    fields.Clear();
                    break;
                default: sb.Append(ch); break;
            }
        }
        if (sb.Length > 0 || fields.Count > 0) { fields.Add(sb.ToString()); yield return fields.ToArray(); }
    }
}

/// <summary>OSV-Scanner JSON -> one row per vulnerability group with a released fix newer than the installed version.</summary>
internal static class OsvParser
{
    public static IEnumerable<JsonObject> Rows(JsonObject o, string? owner, ref int noFix)
    {
        var rows = new List<JsonObject>();
        foreach (var res in o.Objects("results"))
        {
            var srcPath = (res["source"] as JsonObject)?.Str("path") ?? "";
            foreach (var pkg in res.Objects("packages"))
            {
                var p = pkg["package"] as JsonObject;
                var name = p?.Str("name") ?? ""; var ver = p?.Str("version") ?? "";
                var byId = pkg.Objects("vulnerabilities").ToDictionary(v => v.Str("id"), v => v, StringComparer.Ordinal);
                var groups = pkg.Objects("groups").ToList();
                if (groups.Count == 0) groups = byId.Values.Select(v => new JsonObject { ["ids"] = new JsonArray(v.Str("id")), ["aliases"] = v["aliases"]?.DeepClone(), ["max_severity"] = "" }).ToList();
                foreach (var g in groups)
                {
                    var ids = (g["ids"] as JsonArray)?.Select(Ps.Str).ToList() ?? [];
                    var vs = ids.Where(byId.ContainsKey).Select(i => byId[i]).ToList();
                    if (vs.Count == 0) continue;
                    string? fix = null;
                    foreach (var v in vs) if (FixVersion(v, name, ver) is { } f && (fix is null || PyVersion.Compare(f, fix) > 0)) fix = f;
                    if (fix is null) { noFix++; continue; }   // no fixed release yet: nothing to update to
                    var all = ids.Concat((g["aliases"] as JsonArray)?.Select(Ps.Str) ?? []).Concat(vs.SelectMany(v => (v["aliases"] as JsonArray)?.Select(Ps.Str) ?? []))
                                 .Where(s => s.Length > 0).Distinct().ToList();
                    var cve = all.FirstOrDefault(s => s.StartsWith("CVE-", StringComparison.Ordinal)) ?? vs[0].Str("id");
                    var (python, fixPkg) = PipTarget(srcPath, name);
                    var row = new JsonObject
                    {
                        ["id"] = vs[0].Str("id"), ["cve"] = cve, ["aliases"] = all.ToJsonArray(), ["package"] = name, ["version"] = ver, ["fixed"] = fix,
                        ["score"] = g.Str("max_severity"), ["severity"] = SeverityName(g.Str("max_severity")),
                        ["summary"] = vs.Select(v => v.Str("summary")).FirstOrDefault(s => s.Length > 0) ?? "",
                        ["path"] = srcPath, ["python"] = python, ["fixPackage"] = fixPkg,
                    };
                    if (owner is not null) row["owner"] = owner;
                    rows.Add(row);
                }
            }
        }
        return rows;
    }

    /// <summary>Lowest released version above the installed one that fixes the vulnerability (commit hashes skipped).</summary>
    public static string? FixVersion(JsonObject v, string package, string installed)
    {
        var norm = Ps.Rx("[-_.]+").Replace(package, "-").ToLowerInvariant();
        string? best = null;
        foreach (var a in v.Objects("affected"))
        {
            var pn = (a["package"] as JsonObject)?.Str("name") ?? "";
            if (pn.Length > 0 && Ps.Rx("[-_.]+").Replace(pn, "-").ToLowerInvariant() != norm) continue;
            foreach (var r in a.Objects("ranges"))
                foreach (var ev in r.Objects("events"))
                {
                    var f = ev.Str("fixed");
                    if (f.Length == 0 || !Ps.Rx(@"^\d+(\.\d+)*([a-z]+\d*)?(\.post\d+)?$").IsMatch(f)) continue;
                    if (PyVersion.Compare(f, installed) <= 0) continue;
                    if (best is null || PyVersion.Compare(f, best) < 0) best = f;
                }
        }
        return best;
    }

    public static string SeverityName(string score) =>
        !double.TryParse(score, NumberStyles.Float, CultureInfo.InvariantCulture, out var s) ? "Medium" : s >= 9 ? "Critical" : s >= 7 ? "High" : s >= 4 ? "Medium" : "Low";

    /// <summary>Which python.exe owns the package, and which package to upgrade (a library bundled inside pip: pip itself).</summary>
    public static (string? Python, string Package) PipTarget(string path, string package)
    {
        var p = path.Replace('/', '\\');
        string? python = null;
        var m = Ps.Rx(@"^(.*?)\\Lib\\site-packages\\").Match(p);
        if (m.Success) { var exe = Path.Combine(m.Groups[1].Value, "python.exe"); if (File.Exists(exe)) python = exe; }
        else if (Ps.Rx(@"\\Packages\\PythonSoftwareFoundation\.Python\.(\d+\.\d+)_").Match(p) is { Success: true } s) python = "python" + s.Groups[1].Value;
        var v = Ps.Rx(@"\\site-packages\\([^\\]+)\\_vendor\\").Match(p);
        return (python, v.Success ? v.Groups[1].Value : package);
    }
}
