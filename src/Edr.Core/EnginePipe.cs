using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Nodes;

namespace Edr.Core;

/// <summary>
/// The engine's named pipe (\\.\pipe\FreeEDR-Engine): requests to the engine with a real answer, and "something
/// changed" notices to the dashboards. One JSON object per line (UTF-8, at most 64 KB).
///   client → engine  {"op":"command","cmd":{...}}   → {"ok":true|false,"message":"..."}
///   client → engine  {"op":"subscribe"}              → {"type":"changed"} whenever status or events change
/// Security: the engine (SYSTEM) creates it, so it is owned by SYSTEM or Administrators, reachable by local signed-in accounts only (NETWORK denied), as the
/// first instance (a squatter makes the engine log an error). Clients check that the pipe is owned by SYSTEM or
/// Administrators before they send anything, so a pipe created by a normal user is never trusted. The engine identifies
/// the caller from the pipe (its Windows token: elevated administrator or not, and its name), never from the request.
/// When the engine is not running, callers fall back to the drop folders (control\ / inbox\), read at its next start.
/// </summary>
public static class EnginePipe
{
    public static string Name { get; internal set; } = "FreeEDR-Engine";   // settable for tests only

    /// <summary>Owners a client accepts: SYSTEM or Administrators (the engine's default owner). Replaced only by tests.</summary>
    internal static Func<SecurityIdentifier, bool> AcceptOwner { get; set; } =
        o => o.IsWellKnown(WellKnownSidType.LocalSystemSid) || o.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid);
    public const int MaxLine = PatternRules.MaxPayload;

    public static PipeSecurity ServerSecurity()
    {
        var s = new PipeSecurity();
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        s.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        s.AddAccessRule(new PipeAccessRule(system, PipeAccessRights.FullControl, AccessControlType.Allow));
        // The creating account (SYSTEM for the installed engine) may add instances; nobody else can (no CreateNewInstance)
        using (var me = WindowsIdentity.GetCurrent()) if (me.User is { } u) s.AddAccessRule(new PipeAccessRule(u, PipeAccessRights.FullControl, AccessControlType.Allow));
        s.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        s.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, AccessControlType.Allow));
        return s;
    }

    /// <summary>The pipe really is the engine's: owned by SYSTEM or Administrators (a normal user cannot create that).</summary>
    public static bool TrustedServer(NamedPipeClientStream c)
    {
        try
        {
            var owner = c.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            return owner is not null && AcceptOwner(owner);
        }
        catch (Exception e) when (e is UnauthorizedAccessException or IOException or InvalidOperationException or SystemException) { return false; }
    }

    /// <summary>
    /// The engine's answer to one request.
    /// Reached = false: no (trusted) engine took the request; the caller uses its fallback (drop folder).
    /// Busy: the engine was too busy to start it before the caller's deadline and has dropped it (it never runs), so the
    /// caller may queue it in a drop folder. Unanswered: the request was sent but no answer came in time; it may still
    /// run, so it must not be sent again. Failed: valid, but the engine could not carry it out (Message says why).
    /// </summary>
    public readonly record struct Reply(bool Reached, bool Ok, string Message, bool Busy = false, bool Unanswered = false, bool Failed = false)
    {
        public void Deconstruct(out bool reached, out bool ok, out string message) { reached = Reached; ok = Ok; message = Message; }

        /// <summary>The engine decided (done, refused or failed): nothing else may be sent for this request.</summary>
        public bool Answered => Reached && !Busy && !Unanswered;
    }

    /// <summary>The engine answers "busy" this long before the caller's deadline at the latest, so the answer arrives in time.</summary>
    public const int AnswerMarginMs = 1000;

    /// <summary>Sends one request and waits at most <paramref name="timeoutMs"/>. The engine is told the caller's deadline
    /// ("wait"): a request it cannot start by then is dropped and answered "busy", never run after the caller gave up.</summary>
    public static async Task<Reply> SendAsync(JsonObject cmd, int timeoutMs = 10_000)
    {
        using var cts = new CancellationTokenSource(timeoutMs);
        var clock = System.Diagnostics.Stopwatch.StartNew();
        var sent = false;
        try
        {
            await using var c = new NamedPipeClientStream(".", Name, PipeDirection.InOut, PipeOptions.Asynchronous);
            await c.ConnectAsync(Math.Min(2000, timeoutMs), cts.Token);
            if (!TrustedServer(c)) return new(false, false, "the pipe is not owned by the engine");
            var wait = (int)Math.Max(250, timeoutMs - clock.ElapsedMilliseconds - AnswerMarginMs);
            await WriteLineAsync(c, new JsonObject { ["op"] = "command", ["cmd"] = cmd.DeepClone(), ["wait"] = wait }, cts.Token);
            sent = true;
            var reply = await ReadLineAsync(c, cts.Token);
            if (reply is null) return new(true, false, "no answer from the engine", Unanswered: true);
            return new(true, reply.Truthy("ok"), reply.Str("message"), Busy: reply.Truthy("busy"), Failed: reply.Truthy("failed"));
        }
        catch (Exception e) when (e is TimeoutException or OperationCanceledException or IOException or UnauthorizedAccessException)
        {
            return sent ? new(true, false, $"the engine did not answer in time ({e.Message})", Unanswered: true) : new(false, false, e.Message);
        }
    }

    /// <summary>Keeps a subscription open (reconnecting every 5 s) and calls <paramref name="changed"/> on each notice.</summary>
    public static async Task SubscribeAsync(Action changed, Action<bool>? connected, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await using var c = new NamedPipeClientStream(".", Name, PipeDirection.InOut, PipeOptions.Asynchronous);
                await c.ConnectAsync(2000, ct);
                if (TrustedServer(c))
                {
                    await WriteLineAsync(c, new JsonObject { ["op"] = "subscribe" }, ct);
                    connected?.Invoke(true);
                    var reader = new LineReader(c);
                    while (await reader.ReadAsync(ct) is { } msg) if (msg.Str("type") == "changed") changed();
                }
            }
            catch (Exception e) when (e is TimeoutException or IOException or UnauthorizedAccessException) { }
            catch (OperationCanceledException) { break; }
            connected?.Invoke(false);
            try { await Task.Delay(5000, ct); } catch (OperationCanceledException) { break; }
        }
    }

    public static async Task WriteLineAsync(PipeStream s, JsonObject o, CancellationToken ct)
    {
        var b = Encoding.UTF8.GetBytes(JsonFile.ToText(o, indented: false) + "\n");
        await s.WriteAsync(b, ct);
        await s.FlushAsync(ct);
    }

    /// <summary>One line from a fresh reader (for a stream that carries a single line, such as a reply).</summary>
    public static Task<JsonObject?> ReadLineAsync(PipeStream s, CancellationToken ct) => new LineReader(s).ReadAsync(ct);

    /// <summary>
    /// Buffered line reader for one connection (reads in 4 KB blocks, keeps what follows a line for the next call).
    /// A line longer than <see cref="MaxLine"/> bytes ends the stream (null); so does the end of the stream.
    /// </summary>
    public sealed class LineReader(PipeStream s)
    {
        private readonly byte[] _block = new byte[4096];
        private byte[] _buf = new byte[4096];
        private int _len;

        public async Task<JsonObject?> ReadAsync(CancellationToken ct)
        {
            var scanned = 0;
            while (true)
            {
                var nl = Array.IndexOf(_buf, (byte)'\n', scanned, _len - scanned);
                if (nl >= 0)
                {
                    var text = Encoding.UTF8.GetString(_buf, 0, nl);
                    Buffer.BlockCopy(_buf, nl + 1, _buf, 0, _len - nl - 1);
                    _len -= nl + 1;
                    return JsonFile.Parse(text) as JsonObject ?? new JsonObject();
                }
                scanned = _len;
                if (_len > MaxLine) return null;
                var n = await s.ReadAsync(_block, ct);
                if (n == 0) return null;
                if (_len + n > _buf.Length) Array.Resize(ref _buf, Math.Min(Math.Max(_buf.Length * 2, _len + n), MaxLine + _block.Length + 1));
                if (_len + n > _buf.Length) return null;
                Buffer.BlockCopy(_block, 0, _buf, _len, n);
                _len += n;
            }
        }
    }
}
