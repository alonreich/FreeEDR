using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Nodes;

namespace Edr.Core;

public static class EnginePipe
{
    public static string Name { get; internal set; } = "FreeEDR-Engine";

    internal static Func<SecurityIdentifier, bool> AcceptOwner { get; set; } =
        o => o.IsWellKnown(WellKnownSidType.LocalSystemSid) || o.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid);
    public const int MaxLine = PatternRules.MaxPayload;

    public static PipeSecurity ServerSecurity()
    {
        var s = new PipeSecurity();
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        s.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        s.AddAccessRule(new PipeAccessRule(system, PipeAccessRights.FullControl, AccessControlType.Allow));
        using (var me = WindowsIdentity.GetCurrent()) if (me.User is { } u) s.AddAccessRule(new PipeAccessRule(u, PipeAccessRights.FullControl, AccessControlType.Allow));
        s.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        s.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, AccessControlType.Allow));
        return s;
    }

    public static bool TrustedServer(NamedPipeClientStream c)
    {
        try
        {
            var owner = c.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            return owner is not null && AcceptOwner(owner);
        }
        catch (Exception e) when (e is UnauthorizedAccessException or IOException or InvalidOperationException or SystemException) { return false; }
    }

    public readonly record struct Reply(bool Reached, bool Ok, string Message, bool Busy = false, bool Unanswered = false, bool Failed = false)
    {
        public void Deconstruct(out bool reached, out bool ok, out string message) { reached = Reached; ok = Ok; message = Message; }

        public bool Answered => Reached && !Busy && !Unanswered;
    }

    public const int AnswerMarginMs = 1000;

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

    public static Task<JsonObject?> ReadLineAsync(PipeStream s, CancellationToken ct) => new LineReader(s).ReadAsync(ct);

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
