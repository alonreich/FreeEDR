using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using Edr.Core;
using Edr.Core.Native;

namespace Edr.Engine;

internal sealed class CommandIntake : IDisposable
{
    public sealed record Request(JsonObject Cmd, bool Trusted, string File);

    private sealed class Worker(string dir, bool trusted)
    {
        public readonly string Dir = dir;
        public readonly bool Trusted = trusted;
        public Thread? Thread;
        public long BusySince;
        public string BusyFile = "";
        public bool StallReported;
        public readonly Dictionary<string, (DateTime First, DateTime Retry, bool Logged)> Waiting = new(StringComparer.OrdinalIgnoreCase);
        public long Taken, Rejected;
        public volatile int WaitingCount;
    }

    public const int PerSweep = 25;
    public const int MaxQueued = 200;
    private static readonly TimeSpan Sweep = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan Cooldown = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan StallAfter = TimeSpan.FromMinutes(1);

    private readonly Context _ctx;
    private readonly Worker[] _workers;
    private readonly ConcurrentQueue<Request> _ready = new();
    private readonly CancellationTokenSource _stop = new();

    public CommandIntake(Context ctx)
    {
        _ctx = ctx;
        _workers = [new Worker(ctx.Paths.ControlDir, true), new Worker(ctx.Paths.InboxDir, false)];
    }

    public int Queued => _ready.Count;

    public void Start()
    {
        foreach (var w in _workers)
        {
            w.Thread = new Thread(() => Loop(w)) { IsBackground = true, Name = $"Command intake ({Path.GetFileName(w.Dir)})" };
            w.Thread.Start();
        }
    }

    public bool TryDequeue(out Request r) => _ready.TryDequeue(out r!);

    internal void SweepOnce(int folder) => SweepOnce(_workers[folder]);

    private void Loop(Worker w)
    {
        while (!_stop.IsCancellationRequested)
        {
            try { SweepOnce(w); }
            catch (Exception e) { _ctx.Log.Error($"Command intake ({Path.GetFileName(w.Dir)}) failed: {e.GetType().Name}: {e.Message}"); }
            if (_stop.Token.WaitHandle.WaitOne(Sweep)) break;
        }
    }

    private void SweepOnce(Worker w)
    {
        if (!Directory.Exists(w.Dir) || _ready.Count >= MaxQueued) return;
        var now = DateTime.Now;
        var batch = new List<string>(PerSweep);
        foreach (var f in Directory.EnumerateFiles(w.Dir, "*.json"))
        {
            if (w.Waiting.TryGetValue(f, out var wait) && now < wait.Retry) continue;
            batch.Add(f);
            if (batch.Count >= PerSweep) break;
        }
        foreach (var f in batch)
        {
            if (_stop.IsCancellationRequested || _ready.Count >= MaxQueued) return;
            var r = Guarded(w, f, () => DropFile.Take(f, PatternRules.MaxPayload));
            switch (r.Outcome)
            {
                case DropFile.Outcome.Taken:
                    w.Waiting.Remove(f);
                    Interlocked.Increment(ref w.Taken);
                    if (r.Command is { } cmd) _ready.Enqueue(new Request(cmd, w.Trusted, f));
                    else _ctx.Log.Warn($"Command file '{Path.GetFileName(f)}' is not a JSON object; discarded");
                    break;
                case DropFile.Outcome.Gone:
                    w.Waiting.Remove(f);
                    break;
                case DropFile.Outcome.Rejected:
                    w.Waiting.Remove(f);
                    Interlocked.Increment(ref w.Rejected);
                    _ctx.Log.Warn($"Command file '{Path.GetFileName(f)}' in {Path.GetFileName(w.Dir)}\\ refused: {r.Reason}");
                    break;
                default:
                {
                    var first = w.Waiting.TryGetValue(f, out var old) ? old.First : now;
                    var logged = old.Logged;
                    if (!logged && now - first > TimeSpan.FromMinutes(5))
                    {
                        _ctx.Log.Warn($"Command file '{Path.GetFileName(f)}' in {Path.GetFileName(w.Dir)}\\ could not be read for 5 minutes: {r.Reason}");
                        logged = true;
                    }
                    w.Waiting[f] = (first, now + Cooldown, logged);
                    break;
                }
            }
        }
        if (w.Waiting.Count > 0)
            foreach (var f in w.Waiting.Keys.Where(k => !File.Exists(k)).ToList()) w.Waiting.Remove(f);
        if (w.Waiting.Count > 10_000) w.Waiting.Clear();
        w.WaitingCount = w.Waiting.Count;

        if (!w.Trusted)
            foreach (var t in new DirectoryInfo(w.Dir).EnumerateFiles("*.tmp").Take(100).ToList())
                if (t.LastWriteTime < now.AddMinutes(-2)) Guarded(w, t.FullName, () => DropFile.TryDelete(t.FullName));
    }

    private static T Guarded<T>(Worker w, string file, Func<T> op)
    {
        w.BusyFile = file;
        Interlocked.Exchange(ref w.BusySince, DateTime.Now.Ticks);
        try { return op(); }
        finally { Interlocked.Exchange(ref w.BusySince, 0); }
    }

    public void CheckStalls()
    {
        foreach (var w in _workers)
        {
            var since = Interlocked.Read(ref w.BusySince);
            var stuck = since != 0 && DateTime.Now - new DateTime(since) > StallAfter;
            if (stuck && !w.StallReported)
            {
                w.StallReported = true;
                var folder = Path.GetFileName(w.Dir);
                _ctx.Log.Error($"Command intake for {folder}\\ is stuck on '{w.BusyFile}'");
                _ctx.Event("system", "High", $"FreeEDR's {folder} folder is blocked",
                           detail: $"Reading '{Path.GetFileName(w.BusyFile)}' in {folder}\\ has not finished for over a minute. Detection is not affected; " +
                                   $"requests through this folder wait. Another program may be holding the file.",
                           extra: new() { ["kind"] = "health", ["folder"] = folder });
            }
            else if (!stuck && w.StallReported)
            {
                w.StallReported = false;
                _ctx.Event("system", "Info", $"FreeEDR's {Path.GetFileName(w.Dir)} folder works again", extra: new() { ["kind"] = "health" });
            }
        }
    }

    public JsonObject Status()
    {
        var o = new JsonObject { ["queued"] = _ready.Count };
        foreach (var w in _workers)
        {
            var since = Interlocked.Read(ref w.BusySince);
            o[Path.GetFileName(w.Dir)] = new JsonObject
            {
                ["taken"] = Interlocked.Read(ref w.Taken), ["refused"] = Interlocked.Read(ref w.Rejected), ["waiting"] = w.WaitingCount,
                ["stuck"] = since != 0 && DateTime.Now - new DateTime(since) > StallAfter,
            };
        }
        return o;
    }

    public void Dispose()
    {
        _stop.Cancel();
        foreach (var w in _workers) w.Thread?.Join(2000);
    }
}
