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
    private sealed record Request(JsonObject Cmd, bool Admin, string User, TaskCompletionSource<(bool Ok, string Message)> Done);

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

    /// <summary>Runs the queued requests on the engine's main loop.</summary>
    public void Drain(Func<JsonObject, bool, bool> execute)
    {
        while (_requests.TryDequeue(out var r))
        {
            try
            {
                r.Cmd["user"] = r.User;   // the verified caller, never what the request claims
                var ok = execute(r.Cmd, r.Admin);
                r.Done.TrySetResult((ok, ok ? "done" : r.Admin ? "refused: not a valid request" : "refused: needs administrator approval"));
            }
            catch (Exception e) { r.Done.TrySetResult((false, e.Message)); }
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
                    timeout.CancelAfter(TimeSpan.FromSeconds(30));
                    var (admin, user) = Caller(s);
                    var done = new TaskCompletionSource<(bool, string)>(TaskCreationOptions.RunContinuationsAsynchronously);
                    _requests.Enqueue(new Request((JsonObject)cmd.DeepClone(), admin, user, done));
                    var finished = await Task.WhenAny(done.Task, Task.Delay(TimeSpan.FromSeconds(25), timeout.Token));
                    var (ok, text) = finished == done.Task ? done.Task.Result : (false, "the engine is busy; try again");
                    await EnginePipe.WriteLineAsync(s, new JsonObject { ["ok"] = ok, ["message"] = text }, timeout.Token);
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
        while (_requests.TryDequeue(out var r)) r.Done.TrySetResult((false, "the engine is stopping"));
    }
}
