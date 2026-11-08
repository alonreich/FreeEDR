using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json.Nodes;
using Edr.Core;
using Edr.Core.Native;

namespace Edr.Engine;

/// <summary>
/// Engine side of <see cref="EnginePipe"/>. A request is identified by the caller's Windows token (impersonation): an
/// elevated administrator may send every engine verb (like control\), anyone else only resume and scan-now (like
/// inbox\); the user name comes from the token, not from the request. Requests are queued and run on the engine's main
/// loop (<see cref="Drain"/>), so command handling stays single-threaded; the caller gets the result. Subscribers get
/// {"type":"changed"} at most every 300 ms after <see cref="Changed"/>.
/// No account can take the pipe from the others: at most <see cref="MaxClients"/> connections, of which
/// <see cref="ReservedForCommands"/> never go to subscriptions; per account (SID, elevated or not, from the client
/// process's token) at most <see cref="PerCaller"/> connections and <see cref="SubscriptionsPerCaller"/> subscriptions;
/// the first line must arrive within <see cref="FirstLineTimeout"/>; a subscriber that sends anything is dropped.
/// </summary>
internal sealed class PipeServer(Context ctx) : IDisposable
{
    /// <summary>The engine's answer to a request it ran: Ok, a note for the caller ("" = none), Failed = valid but not carried out.</summary>
    public readonly record struct Outcome(bool Ok, string Note, bool Failed);

    private sealed class Request(JsonObject cmd, bool admin, string user)
    {
        public readonly JsonObject Cmd = cmd;
        public readonly bool Admin = admin;
        public readonly string User = user;
        public readonly TaskCompletionSource<Outcome> Done = new(TaskCreationOptions.RunContinuationsAsynchronously);
        /// <summary>0 queued, 1 taken by the main loop, 2 abandoned (the caller's deadline passed first: never runs).</summary>
        public int State;
    }

    /// <summary>A request waits at most this long for the main loop (less when the caller's deadline is earlier).</summary>
    public static readonly TimeSpan MaxQueueWait = TimeSpan.FromSeconds(25);

    public const int MaxClients = 16;
    public const int ReservedForCommands = 4;
    public const int PerCaller = 4;
    public const int SubscriptionsPerCaller = 3;
    public static readonly TimeSpan FirstLineTimeout = TimeSpan.FromSeconds(5);
    private readonly ConcurrentDictionary<string, int> _perCaller = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, int> _subsPerCaller = new(StringComparer.Ordinal);
    private long _refused;
    private readonly ConcurrentQueue<Request> _requests = new();
    private readonly ConcurrentDictionary<NamedPipeServerStream, byte> _subscribers = new();
    private readonly CancellationTokenSource _stop = new();
    private int _clients, _changed;
    private bool _first = true;

    public int Subscribers => _subscribers.Count;
    public string Error { get; private set; } = "";

    public void Start()
    {
        _ = Task.Run(AcceptLoop);
        _ = Task.Run(NotifyLoop);
    }

    /// <summary>Status or events changed (any thread).</summary>
    public void Changed() => Interlocked.Exchange(ref _changed, 1);

    /// <summary>Runs the queued requests on the engine's main loop (tests: an executor without notes).</summary>
    public void Drain(Func<JsonObject, bool, bool> execute) => Drain((c, a) => new Outcome(execute(c, a), "", false));

    /// <summary>Runs the queued requests on the engine's main loop. A request whose caller already got "busy" is skipped.</summary>
    public void Drain(Func<JsonObject, bool, Outcome> execute)
    {
        while (_requests.TryDequeue(out var r))
        {
            if (Interlocked.CompareExchange(ref r.State, 1, 0) != 0) continue;   // abandoned: the caller was told it did not run
            try
            {
                r.Cmd["user"] = r.User;   // the verified caller, never what the request claims
                var o = execute(r.Cmd, r.Admin);
                var note = o.Note.Length > 0 ? o.Note : o.Ok ? "done" : r.Admin ? "refused: not a valid request" : "refused: needs administrator approval";
                r.Done.TrySetResult(o with { Note = note });
            }
            catch (Exception e) { r.Done.TrySetResult(new Outcome(false, e.Message, true)); }
        }
    }

    private async Task AcceptLoop()
    {
        while (!_stop.IsCancellationRequested)
        {
            NamedPipeServerStream? s = null;
            try
            {
                if (Volatile.Read(ref _clients) >= MaxClients) { await Task.Delay(500, _stop.Token); continue; }
                var opts = PipeOptions.Asynchronous | (_first ? PipeOptions.FirstPipeInstance : PipeOptions.None);
                s = NamedPipeServerStreamAcl.Create(EnginePipe.Name, PipeDirection.InOut, MaxClients, PipeTransmissionMode.Byte, opts, 0, 0, EnginePipe.ServerSecurity());
                _first = false;
                Error = "";
                await s.WaitForConnectionAsync(_stop.Token);
                Interlocked.Increment(ref _clients);
                var client = s;
                s = null;
                _ = Task.Run(() => Serve(client));
            }
            catch (OperationCanceledException) { s?.Dispose(); break; }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                s?.Dispose();
                if (_first && Error.Length == 0)
                {
                    Error = $"pipe {EnginePipe.Name} could not be created ({e.Message}) - another program may hold the name";
                    ctx.Log.Error(Error);
                    ctx.Event("system", "High", "FreeEDR's command channel is blocked", detail: $"{Error}. Dashboard requests use the drop folders until it works.", extra: new() { ["kind"] = "health" });
                }
                try { await Task.Delay(5000, _stop.Token); } catch (OperationCanceledException) { break; }
            }
        }
    }

    private async Task Serve(NamedPipeServerStream s)
    {
        var key = Win32.PipeClientKey(s.SafePipeHandle) ?? "unknown";
        var subscribed = false;
        try
        {
            if (_perCaller.AddOrUpdate(key, 1, (_, n) => n + 1) > PerCaller) { Interlocked.Increment(ref _refused); return; }
            var reader = new EnginePipe.LineReader(s);
            JsonObject? msg;
            using (var first = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token))
            {
                first.CancelAfter(FirstLineTimeout);
                msg = await reader.ReadAsync(first.Token);
            }
            if (msg is null) return;
            switch (msg.Str("op"))
            {
                case "subscribe":
                    if (_subscribers.Count >= MaxClients - ReservedForCommands) { Interlocked.Increment(ref _refused); return; }
                    subscribed = true;
                    if (_subsPerCaller.AddOrUpdate(key, 1, (_, n) => n + 1) > SubscriptionsPerCaller) { Interlocked.Increment(ref _refused); return; }
                    _subscribers[s] = 1;
                    // A dashboard only listens: anything it sends (or closing) ends the subscription
                    await reader.ReadAsync(_stop.Token);
                    break;
                case "command" when msg["cmd"] is JsonObject cmd:
                {
                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
                    timeout.CancelAfter(TimeSpan.FromSeconds(60));
                    var (admin, user) = Caller(s);
                    var req = new Request((JsonObject)cmd.DeepClone(), admin, user);
                    _requests.Enqueue(req);
                    // Answer before the caller's own deadline ("wait"); a request still queued then is abandoned, so it
                    // never runs after the caller was told "busy" (and queued it elsewhere, or gave up)
                    var waitMs = msg.Int("wait") is > 0 and var w ? Math.Min(w, (int)MaxQueueWait.TotalMilliseconds) : (int)MaxQueueWait.TotalMilliseconds;
                    var finished = await Task.WhenAny(req.Done.Task, Task.Delay(waitMs, timeout.Token));   // a stopping engine ends the wait
                    if (finished != req.Done.Task) Interlocked.CompareExchange(ref req.State, 2, 0);
                    JsonObject reply;
                    if (Volatile.Read(ref req.State) == 2)   // abandoned (deadline, or the engine is stopping): it never runs
                        reply = new JsonObject { ["ok"] = false, ["busy"] = true, ["message"] = _stop.IsCancellationRequested ? "the engine is stopping and did not run the request" : "the engine was busy and did not run the request" };
                    else
                    {
                        var o = await req.Done.Task.WaitAsync(timeout.Token);   // taken by the main loop: its answer follows
                        reply = new JsonObject { ["ok"] = o.Ok, ["message"] = o.Note };
                        if (o.Failed) reply["failed"] = true;
                    }
                    using (var write = new CancellationTokenSource(TimeSpan.FromSeconds(5)))   // also while the engine stops
                        await EnginePipe.WriteLineAsync(s, reply, write.Token);
                    break;
                }
            }
        }
        catch (Exception e) when (e is IOException or OperationCanceledException or ObjectDisposedException or UnauthorizedAccessException) { }
        finally
        {
            _subscribers.TryRemove(s, out _);
            if (subscribed) Release(_subsPerCaller, key);
            Release(_perCaller, key);   // counted on entry, also when it was refused
            Interlocked.Decrement(ref _clients);
            await s.DisposeAsync();
        }
    }

    private static void Release(ConcurrentDictionary<string, int> map, string key)
    {
        while (map.TryGetValue(key, out var n))
        {
            if (n <= 1 ? map.TryRemove(new KeyValuePair<string, int>(key, n)) : map.TryUpdate(key, n - 1, n)) return;
        }
    }

    /// <summary>Who is calling, from the pipe itself: elevated administrator (Administrators enabled in the token) and name.</summary>
    private static (bool Admin, string User) Caller(NamedPipeServerStream s)
    {
        var admin = false;
        var user = "unknown";
        try
        {
            s.RunAsClient(() =>
            {
                using var id = WindowsIdentity.GetCurrent(System.Security.Principal.TokenAccessLevels.Query);
                admin = new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
                user = id.Name;
            });
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException) { }
        return (admin, user);
    }

    private async Task NotifyLoop()
    {
        var line = System.Text.Encoding.UTF8.GetBytes("{\"type\":\"changed\"}\n");
        while (!_stop.IsCancellationRequested)
        {
            try { await Task.Delay(300, _stop.Token); } catch (OperationCanceledException) { break; }
            if (Interlocked.Exchange(ref _changed, 0) == 0) continue;
            foreach (var s in _subscribers.Keys)
            {
                try
                {
                    using var t = new CancellationTokenSource(2000);   // a dashboard that does not read is dropped
                    await s.WriteAsync(line, t.Token);
                    await s.FlushAsync(t.Token);
                }
                catch (Exception e) when (e is IOException or OperationCanceledException or ObjectDisposedException)
                {
                    _subscribers.TryRemove(s, out _);
                    try { s.Disconnect(); } catch (Exception d) when (d is IOException or InvalidOperationException or ObjectDisposedException) { }
                }
            }
        }
    }

    public JsonObject Status() => new()
    {
        ["name"] = EnginePipe.Name, ["clients"] = Volatile.Read(ref _clients), ["subscribers"] = _subscribers.Count,
        ["refused"] = Interlocked.Read(ref _refused), ["error"] = Error.Length > 0 ? Error : null,
    };

    /// <summary>Connections refused by the per-account caps since the engine started.</summary>
    public long Refused => Interlocked.Read(ref _refused);

    public void Dispose()
    {
        _stop.Cancel();
        while (_requests.TryDequeue(out var r)) Interlocked.CompareExchange(ref r.State, 2, 0);   // never run; their callers hear "busy"
    }
}
