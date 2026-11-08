using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Security.AccessControl;
using System.Text.Json.Nodes;
using Edr.Core;
using Edr.Core.Native;

namespace Edr.Engine;

internal sealed class Engine : IDisposable
{
    private sealed record Watch(string Sid, string Channel, string XPath);
    private sealed record Item(string Sid, string? Xml, string? Bookmark, int Error);

    private static readonly Watch[] Watches =
    [
        new("w2b-4625", "Security", "*[System[(EventID=4625)]]"),
        new("w2b-rdp140", "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", "*[System[(EventID=140)]]"),
        new("rt-sysmon", "Microsoft-Windows-Sysmon/Operational", "*[System[(EventID=1 or EventID=3 or EventID=6 or EventID=8 or EventID=10 or EventID=11 or EventID=12 or EventID=13 or EventID=14 or EventID=19 or EventID=20 or EventID=21)]]"),
        new("def", "Microsoft-Windows-Windows Defender/Operational", "*[System[(EventID=1116 or EventID=1121 or EventID=1122 or EventID=1123 or EventID=1124)]]"),
        new("logon-ok", "Security", "*[System[(EventID=4624)] and EventData[Data[@Name='LogonType']='3' or Data[@Name='LogonType']='10']]"),
        new("clear-sec", "Security", "*[System[(EventID=1102)]]"),
        new("clear-sys", "System", "*[System[(EventID=104)]]"),
    ];

    private readonly Context _ctx;
    private readonly Wail2Ban _w2b;
    private readonly Realtime _rt;
    private readonly DefenderEvents _def;
    private readonly Scanner _scanner;
    private readonly Commands _commands;
    private readonly EventArchive _archive;
    private readonly PipeServer _pipe;
    private readonly CommandIntake _intake;
    private const int QueueCapacity = 10_000;
    private readonly BlockingCollection<Item> _queue = new(QueueCapacity);
    private CancellationToken _stop;
    private volatile string? _closingSid;
    private long _intakeDropped;
    private long _intakeDroppedReported;
    private readonly Dictionary<string, EventSubscription> _subs = [];
    private readonly Dictionary<string, string> _watchErrors = [];
    private readonly Dictionary<string, string> _bookmarks = [];
    private bool _bookmarksDirty;
    private DateTime _bookmarksSaved = DateTime.Now;
    private int _lagSeconds;
    private Mutex? _mutex;

    private bool _sysmonOk = true;
    private string _sysmonMsg = "";
    private string _sysmonSvc = "";
    private string _sysmonDrv = "";
    private DateTime _lastSysmonRestart = DateTime.MinValue;

    public Engine(EdrPaths paths)
    {
        _ctx = new Context(paths);
        _w2b = new Wail2Ban(_ctx);
        _rt = new Realtime(_ctx);
        _def = new DefenderEvents(_ctx);
        _scanner = new Scanner(_ctx);
        _commands = new Commands(_ctx, _w2b, _scanner);
        _archive = new EventArchive(_ctx);
        _pipe = new PipeServer(_ctx);
        _intake = new CommandIntake(_ctx);
        _ctx.Changed = _pipe.Changed;
    }

    private void Safely(string name, Action a)
    {
        try { a(); }
        catch (Exception e) { _ctx.Log.Error($"{name} failed: {e.GetType().Name}: {e.Message}"); }
    }

    private bool AcquireMutex()
    {
        try
        {
            var sec = new MutexSecurity();
            sec.AddAccessRule(new MutexAccessRule(new System.Security.Principal.SecurityIdentifier(EdrPaths.SystemSid), MutexRights.FullControl, AccessControlType.Allow));
            sec.AddAccessRule(new MutexAccessRule(new System.Security.Principal.SecurityIdentifier(EdrPaths.AdminsSid), MutexRights.FullControl, AccessControlType.Allow));
            _mutex = MutexAcl.Create(true, EdrPaths.EngineMutex, out var created, sec);
            if (created) return true;
            var others = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(EdrPaths.EngineExe)).Where(p => p.Id != Environment.ProcessId).ToList();
            if (others.Count > 0) return false;
            _ctx.Log.Warn($"Mutex '{EdrPaths.EngineMutex}' existed without a running engine; continuing.");
            return true;
        }
        catch (Exception e) when (e is UnauthorizedAccessException or IOException or WaitHandleCannotBeOpenedException)
        {
            _ctx.Log.Error($"Failed to acquire the engine mutex: {e.Message}");
            return true;
        }
    }

    public int Run(CancellationToken stop)
    {
        _stop = stop;
        foreach (var d in new[] { _ctx.Paths.DataDir, _ctx.Paths.ControlDir, _ctx.Paths.InboxDir }) Directory.CreateDirectory(d);
        if (!AcquireMutex()) { _ctx.Log.Warn("Another engine is running - exiting"); return 0; }
        JsonFile.Recovered = (path, why) =>
        {
            _ctx.Log.Warn($"Settings file '{path}' damaged ({why}) - restored from backup");
            _ctx.Event("system", "High", "Settings file damaged - restored from backup", detail: $"File '{path}' was damaged and restored from backup.", extra: new() { ["kind"] = "status" });
        };
        _ctx.Log.Audit($"Engine started (PID {Environment.ProcessId}, {Version()})");
        _ctx.LoadConfig(strict: true);
        _ctx.State.Load();
        _ctx.Excl.Load();
        _ctx.Blocks.Load();
        _sysmonOk = _ctx.State.GetBool("sysmonOk") != false;

        Safely("User folders", () => UserFolders.Ensure(_ctx.Paths));
        Safely("Local IPs", _w2b.UpdateSelfIps);
        Safely("Strikes", _w2b.ReadStrikes);
        Safely("Bookmarks", LoadBookmarks);
        Safely("IOC list", _rt.UpdateIocSet);
        Safely("YARA rules", _rt.UpdateYaraRules);
        Safely("YARA worker", _rt.StartYaraWorker);
        Safely("Sysmon rules", _rt.UpdateRuleNames);
        Safely("IPv6 RDP rules", _w2b.ApplyRdpIpv6Setting);
        Safely("Startup sync", _w2b.SyncRecentFailures);
        foreach (var w in Watches) Safely($"Watcher {w.Sid}", () => StartWatch(w));
        Safely("Event archive", _archive.Start);
        Safely("Pipe", _pipe.Start);
        Safely("Command intake", _intake.Start);
        Safely("Sysmon health", SysmonHealth);
        Safely("Defender", _def.UpdateStatus);
        Safely("Bans", _w2b.RemoveExpiredBans);
        Safely("Status", WriteStatus);

        var now = DateTime.Now;
        DateTime nextStatus = now, nextMinute = now.AddSeconds(60), nextFive = now.AddMinutes(5), nextTen = now.AddMinutes(10);
        var nextSettings = now.AddSeconds(5);
        var cadence = Stopwatch.StartNew();
        var sinceCadence = 0;
        try
        {
            while (!stop.IsCancellationRequested)
            {
                var batch = 0;
                while (batch < 50)
                {
                    Item? it;
                    try { if (!_queue.TryTake(out it, batch == 0 ? 1000 : 0, stop)) break; }
                    catch (OperationCanceledException) { break; }
                    batch++; sinceCadence++;
                    Safely("Event handling", () => Handle(it));
                    if (sinceCadence >= 50 || cadence.ElapsedMilliseconds >= 2000)
                    {
                        Safely("Exclusions reload", _ctx.Excl.ReloadIfChanged);
                        Safely("Commands", () => _commands.RunQueued(_intake));
                        Safely("Pipe requests", () => _pipe.Drain(RunPipeRequest));
                        if (DateTime.Now >= nextStatus) { nextStatus = DateTime.Now.AddSeconds(15); Safely("Status", WriteStatus); }
                        SaveBookmarks();
                        sinceCadence = 0;
                        cadence.Restart();
                    }
                }
                now = DateTime.Now;
                if (now >= nextSettings)
                {
                    nextSettings = now.AddSeconds(5);
                    Safely("Settings reload", () => { if (_ctx.ReloadConfigIfChanged()) { _w2b.ApplyRdpIpv6Setting(); nextStatus = now; } });
                }
                Safely("Exclusions reload", _ctx.Excl.ReloadIfChanged);
                Safely("Commands", () => _commands.RunQueued(_intake));
                Safely("Pipe requests", () => _pipe.Drain(RunPipeRequest));
                if (now >= nextMinute)
                {
                    nextMinute = now.AddSeconds(60);
                    Safely("Attempts cleanup", _w2b.Housekeeping);
                    Safely("Permanent bans", _w2b.RepairPermanentBans);
                    Safely("Ban expiry", _w2b.RemoveExpiredBans);
                    Safely("Sysmon health", SysmonHealth);
                    Safely("Scan", _scanner.Watch);
                    Safely("Intake drops", ReportIntakeDrops);
                    Safely("Command intake health", _intake.CheckStalls);
                    Safely("YARA coverage", _rt.ReportYaraNotScanned);
                    Safely("Event writes", ReportEventWriteFailures);
                    Safely("User folders", () => UserFolders.Ensure(_ctx.Paths));
                }
                if (now >= nextFive)
                {
                    nextFive = now.AddMinutes(5);
                    Safely("Local IPs", _w2b.UpdateSelfIps);
                    Safely("IOC list", _rt.UpdateIocSet);
                    foreach (var w in Watches.Where(w => _watchErrors.ContainsKey(w.Sid))) Safely($"Watcher {w.Sid}", () => StartWatch(w));
                    Safely("Event archive", _archive.RetryMissing);
                }
                if (now >= nextTen) { nextTen = now.AddMinutes(10); Safely("Defender", _def.UpdateStatus); }
                if (now >= nextStatus) { nextStatus = now.AddSeconds(15); Safely("Status", WriteStatus); }
                SaveBookmarks();
            }
        }
        finally
        {
            Safely("Scan stop", () => _scanner.Stop("engine stopping"));
            Safely("Shutdown strikes save", () => _w2b.SaveStrikes(force: true));
            _bookmarksDirty = true;
            Safely("Shutdown bookmarks save", () => SaveBookmarks(force: true));
            Safely("Shutdown state save", _ctx.State.Save);
            _ctx.Log.Audit("Engine stopped");
        }
        return 0;
    }

    private PipeServer.Outcome RunPipeRequest(JsonObject cmd, bool admin)
    {
        var ok = _commands.Execute(cmd, admin);
        return new PipeServer.Outcome(ok, _commands.LastNote, _commands.LastFailed);
    }

    private void Handle(Item it)
    {
        if (it.Xml is null)
        {
            _ctx.Log.Error($"Watcher {it.Sid} error {it.Error} - restarting it");
            if (Watches.FirstOrDefault(w => w.Sid == it.Sid) is { } w) StartWatch(w);
            return;
        }
        if (it.Bookmark is not null) { _bookmarks[it.Sid] = it.Bookmark; _bookmarksDirty = true; }
        var r = EventRecord.FromXml(it.Xml);
        if (r is null) return;
        _lagSeconds = Math.Max(0, (int)(DateTime.Now - r.Time).TotalSeconds);
        var replay = r.Time < _ctx.Started;
        switch (it.Sid)
        {
            case "w2b-4625": if (Wail2Ban.IpFrom(r, fallback: false) is { } ip) _w2b.AddFailure(ip, "Security", r.Time, replay); break;
            case "w2b-rdp140": if (Wail2Ban.IpFrom(r) is { } ip2) _w2b.AddFailure(ip2, "RdpCoreTS", r.Time, replay); break;
            case "rt-sysmon": _rt.Handle(r); break;
            case "def": _def.Handle(r); break;
            case "logon-ok": _w2b.LogonSuccess(r); break;
            case "clear-sec" or "clear-sys": LogCleared(r); break;
        }
    }

    private void LogCleared(EventRecord r)
    {
        var log = r.Id == 1102 ? "Security" : r["Channel"].Length > 0 ? r["Channel"] : "a Windows log";
        var who = r["SubjectUserName"].Length > 0 ? (r["SubjectDomainName"].Length > 0 ? $"{r["SubjectDomainName"]}\\{r["SubjectUserName"]}" : r["SubjectUserName"]) : "unknown";
        _ctx.Event("realtime", "High", "Event log cleared", "", $"The {log} log was cleared by {who} at {r.Time:yyyy-MM-dd HH:mm:ss}. FreeEDR's copy in data\\archive\\ still has what was archived before.",
                   new() { ["rule"] = "Event log cleared", ["user"] = who, ["channel"] = log, ["kind"] = "log-cleared", ["eventId"] = r.Id });
        _ctx.Log.Audit($"Windows log '{log}' was cleared by {who}");
    }

    private void StartWatch(Watch w)
    {
        if (_subs.Remove(w.Sid, out var old))
        {
            _closingSid = w.Sid;
            try { old.Dispose(); } finally { _closingSid = null; }
        }
        var bm = _bookmarks.GetValueOrDefault(w.Sid);
        void OnEvent(string xml, string? bookmark) => Enqueue(new Item(w.Sid, xml, bookmark, 0));
        void OnError(int code) => Enqueue(new Item(w.Sid, null, null, code));
        try
        {
            try { _subs[w.Sid] = EventSubscription.Start(w.Channel, w.XPath, bm, OnEvent, OnError); }
            catch (InvalidDataException e)
            {
                _ctx.Log.Warn($"Corrupt bookmark for {w.Sid}, falling back to now: {e.Message}");
                _bookmarks.Remove(w.Sid);
                _bookmarksDirty = true;
                _ctx.Event("system", "Medium", "Events may have been missed", detail: $"Watcher {w.Sid} bookmark was corrupt, falling back to current time: {e.Message}", extra: new() { ["kind"] = "status", ["sid"] = w.Sid });
                _subs[w.Sid] = EventSubscription.Start(w.Channel, w.XPath, null, OnEvent, OnError);
            }
            _watchErrors.Remove(w.Sid);
            _ctx.Log.Info($"Watching {w.Channel}{(bm is not null ? " from bookmark" : "")}");
        }
        catch (IOException e)
        {
            _watchErrors[w.Sid] = e.Message;
            _ctx.Log.Error($"Cannot watch {w.Channel}: {e.Message}");
        }
    }

    private void Enqueue(Item it)
    {
        if (_queue.TryAdd(it)) return;
        try
        {
            while (!_stop.IsCancellationRequested && _closingSid != it.Sid)
                if (_queue.TryAdd(it, 250, _stop)) return;
        }
        catch (Exception e) when (e is OperationCanceledException or InvalidOperationException or ObjectDisposedException) { }
        Interlocked.Increment(ref _intakeDropped);
    }

    private void ReportIntakeDrops()
    {
        var n = Interlocked.Read(ref _intakeDropped);
        if (n == _intakeDroppedReported) return;
        var lost = n - _intakeDroppedReported;
        _intakeDroppedReported = n;
        _ctx.Log.Error($"{lost} event log records were dropped by the intake queue");
        _ctx.Event("system", "High", "Events may have been missed", detail: $"{lost} Windows event log records could not be queued for analysis (engine stopping or a watcher restarting during a flood).",
                   extra: new() { ["kind"] = "health", ["dropped"] = lost });
    }

    private long _eventFailuresReported;
    private DateTime _eventFailuresAt = DateTime.MinValue;

    private void ReportEventWriteFailures()
    {
        var n = _ctx.Events.Failures;
        if (n == _eventFailuresReported || DateTime.Now - _eventFailuresAt < TimeSpan.FromMinutes(10)) return;
        _eventFailuresAt = DateTime.Now;
        var lost = n - _eventFailuresReported;
        _eventFailuresReported = n;
        var why = _ctx.Events.LastError;
        _ctx.Log.Error($"{lost} events could not be written to events.jsonl: {why}");
        _ctx.AppEvent($"FreeEDR could not record {lost} alerts or messages in its events file ({why}). Check free disk space and the FreeEDR data folder.", 4000, 2);
        _ctx.Event("system", "High", "Alerts could not be recorded", detail: $"{lost} alerts or messages could not be written to the events file ({why}). This is also recorded in the engine log and in the Windows Application log (source wail2ban, event 4000).",
                   extra: new() { ["kind"] = "health", ["lost"] = lost });
    }

    private void LoadBookmarks()
    {
        if (JsonFile.ReadObject(_ctx.Paths.BookmarksFile) is { } o)
            foreach (var (k, v) in o) if (Ps.Str(v).Length > 0) _bookmarks[k] = Ps.Str(v);
        _ctx.Log.Info($"Loaded {_bookmarks.Count} watcher bookmarks");
    }

    private void SaveBookmarks(bool force = false)
    {
        if (!_bookmarksDirty || (!force && (DateTime.Now - _bookmarksSaved).TotalSeconds < 15)) return;
        var o = new JsonObject();
        foreach (var (k, v) in _bookmarks) o[k] = v;
        try { JsonFile.WriteAtomic(_ctx.Paths.BookmarksFile, o); _bookmarksDirty = false; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { _ctx.Log.Warn($"Failed to save bookmarks: {e.Message}"); }
        _bookmarksSaved = DateTime.Now;
    }

    private void SysmonHealth()
    {
        var svc = Services.Query("Sysmon64");
        var drv = Services.Query("SysmonDrv");
        var msg = "";
        if (svc == Services.State.Missing) msg = "Sysmon is not installed";
        else if (svc != Services.State.Running)
        {
            if (DateTime.Now - _lastSysmonRestart > TimeSpan.FromMinutes(5))
            {
                _lastSysmonRestart = DateTime.Now;
                if (Services.Start("Sysmon64", 15)) _ctx.Log.Audit("Sysmon service was stopped - restarted it");
                svc = Services.Query("Sysmon64");
            }
            if (svc != Services.State.Running) msg = $"Sysmon service is {svc}";
        }
        if (msg.Length == 0 && drv != Services.State.Missing && drv != Services.State.Running) msg = $"Sysmon driver is {drv} - restart the PC";
        if (msg.Length == 0 && _watchErrors.ContainsKey("rt-sysmon")) msg = "Sysmon event log not readable";
        if (msg.Length == 0 && _rt.StaleRule is { } sr && (DateTime.Now - _rt.StaleRuleTime).TotalMinutes < 60)
            msg = $"Sysmon still runs an old rule set (alert \"{sr}\" is not in config\\sysmonconfig.xml) - restart the PC";
        var ok = msg.Length == 0;
        if (ok != _sysmonOk)
        {
            if (ok) _ctx.Event("system", "Info", "Sysmon sensor is healthy again", extra: new() { ["kind"] = "health" });
            else _ctx.Event("system", "High", "Sysmon sensor is not working", detail: $"{msg}. Real-time detection is blind until this is fixed.", extra: new() { ["kind"] = "health" });
        }
        if (_ctx.State.GetBool("sysmonOk") != ok) { _ctx.State.Set("sysmonOk", ok); _ctx.State.Save(); }
        _sysmonOk = ok;
        _sysmonMsg = ok ? "Running" : msg;
        _sysmonSvc = svc.ToString();
        _sysmonDrv = drv.ToString();
    }

    private JsonObject PauseInfo(string blade, string state)
    {
        var own = _ctx.State.PausedUntil(blade);
        return new JsonObject { ["state"] = state, ["pausedUntil"] = own.Length > 0 ? own : state == "paused" ? _ctx.State.PausedUntil("edr") : null };
    }

    private void WriteStatus()
    {
        var edrState = _watchErrors.ContainsKey("rt-sysmon") ? "error" : _ctx.State.State("edr");
        var w2State = _watchErrors.ContainsKey("w2b-4625") ? "error" : _ctx.State.State("wail2ban");
        var backlog = _queue.Count + _rt.YaraBacklog;
        if (backlog == 0) _lagSeconds = 0;
        var status = new JsonObject
        {
            ["heartbeat"] = DateTime.Now.ToString("s", CultureInfo.InvariantCulture),
            ["engineStarted"] = _ctx.Started.ToString("s", CultureInfo.InvariantCulture),
            ["version"] = Version(),
            ["mode"] = "detect-only",
            ["backlog"] = backlog,
            ["dropped"] = _rt.Dropped,
            ["intakeDropped"] = Interlocked.Read(ref _intakeDropped),
            ["eventWriteFailures"] = _ctx.Events.Failures,
            ["lagSeconds"] = _lagSeconds,
            ["edr"] = new JsonObject
            {
                ["state"] = edrState, ["pausedUntil"] = NullIfEmpty(_ctx.State.PausedUntil("edr")), ["error"] = _watchErrors.GetValueOrDefault("rt-sysmon"),
                ["iocHashes"] = _rt.IocCount, ["yaraRules"] = _rt.YaraRuleNames.ToJsonArray(), ["yaraNotScanned"] = _rt.YaraNotScanned,
            },
            ["realtime"] = PauseInfo("realtime", _ctx.State.State("realtime")),
            ["malware"] = PauseInfo("malware", _ctx.State.State("malware")),
            ["sigma"] = PauseInfo("sigma", _ctx.State.State("sigma")),
            ["cve"] = PauseInfo("cve", _ctx.State.State("cve")),
            ["wail2ban"] = new JsonObject
            {
                ["state"] = w2State, ["pausedUntil"] = NullIfEmpty(_ctx.State.PausedUntil("wail2ban")), ["error"] = _watchErrors.GetValueOrDefault("w2b-4625"),
                ["banned"] = _w2b.Banned.DeepClone(), ["rdp140"] = !_watchErrors.ContainsKey("w2b-rdp140"), ["block"] = _ctx.Cfg.Wail2Ban.Block,
                ["tracked"] = _w2b.TrackedIps,
            },
            ["sysmon"] = new JsonObject { ["ok"] = _sysmonOk, ["message"] = _sysmonMsg, ["service"] = _sysmonSvc, ["driver"] = _sysmonDrv },
            ["defender"] = _def.Status?.DeepClone(),
            ["defenderMode"] = _ctx.Cfg.DefenderMode,
            ["scan"] = new JsonObject
            {
                ["running"] = _scanner.Running, ["lastStart"] = NullIfEmpty(_ctx.State.Get("lastScanStart")), ["lastEnd"] = NullIfEmpty(_ctx.State.Get("lastScanEnd")),
                ["ok"] = _ctx.State.GetBool("lastScanOk") is { } ok ? ok : null, ["summary"] = _ctx.State.Get("lastScanSummary"),
                ["nextDue"] = _scanner.NextDue().ToString("s", CultureInfo.InvariantCulture), ["times"] = _ctx.Cfg.ScanTimes.ToJsonArray(),
            },
            ["blocks"] = _ctx.Blocks.Items.Count,
            ["archive"] = _archive.Status(),
            ["pipe"] = _pipe.Status(),
            ["commandIntake"] = _intake.Status(),
            ["installedAt"] = _ctx.Cfg.InstalledAt,
            ["settingsLoaded"] = _ctx.CfgStamp == DateTime.MinValue ? null : _ctx.CfgStamp.ToString("o", CultureInfo.InvariantCulture),
        };
        JsonFile.WriteAtomic(_ctx.Paths.StatusFile, status);
        _pipe.Changed();
    }

    private static JsonNode? NullIfEmpty(string s) => s.Length > 0 ? s : null;

    public static string Version() => typeof(Engine).Assembly.GetName().Version?.ToString() ?? "";

    public void Dispose()
    {
        _pipe.Dispose();
        _intake.Dispose();
        _archive.Dispose();
        foreach (var s in _subs.Values) s.Dispose();
        _subs.Clear();
        _rt.Dispose();
        try { _mutex?.ReleaseMutex(); } catch (ApplicationException) { }
        _mutex?.Dispose();
    }
}

internal static class UserFolders
{
    public static void Ensure(EdrPaths paths, bool repair = false)
    {
        foreach (var (sid, _) in Accounts.All())
        {
            var d = paths.UserStateDir(sid);
            var exists = Directory.Exists(d);
            if (exists && !repair) continue;
            if (!exists) Directory.CreateDirectory(d);
            Tools.RunCapture(Path.Combine(EdrPaths.System32, "icacls.exe"), [d, "/grant", $"*{sid}:(OI)(CI)M"], timeoutSeconds: 30);
        }
    }
}
