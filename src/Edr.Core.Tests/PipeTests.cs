using System.Security.Principal;
using System.Text.Json.Nodes;
using Edr.Core.Native;
using Edr.Engine;
using Xunit;

namespace Edr.Core.Tests;

/// <summary>The engine's named pipe (EnginePipe / PipeServer) and the sandboxed scanner tools. One class: the pipe hooks
/// are static, and tests in one class run one after another.</summary>
public class PipeTests
{
    private static (PipeServer Server, Context Ctx, string Root) NewServer()
    {
        EnginePipe.Name = "FreeEDR-Test-" + Guid.NewGuid().ToString("N");
        var root = Path.Combine(AppContext.BaseDirectory, "pipe", Guid.NewGuid().ToString("N"));
        var ctx = new Context(new EdrPaths(root, Path.Combine(root, "user", "x")));
        var s = new PipeServer(ctx);
        s.Start();
        return (s, ctx, root);
    }

    /// <summary>Runs the server's queue like the engine's main loop does, until <paramref name="until"/> completes.</summary>
    private static async Task<T> Pump<T>(PipeServer s, Task<T> until, Func<JsonObject, bool, bool> execute)
    {
        while (!until.IsCompleted) { s.Drain(execute); await Task.Delay(20); }
        return await until;
    }

    [Fact]
    public async Task A_pipe_created_by_a_normal_account_is_not_trusted()
    {
        var (s, _, _) = NewServer();
        try
        {
            // This test process is not SYSTEM: its pipe is owned by the user, exactly like a squatter's would be
            var r = await Pump(s, EnginePipe.SendAsync(new JsonObject { ["action"] = "scan-now" }, 5000), (_, _) => throw new InvalidOperationException("must not run"));
            Assert.False(r.Reached);
        }
        finally { s.Dispose(); EnginePipe.Name = "FreeEDR-Engine"; }
    }

    [Fact]
    public async Task Requests_carry_the_verified_caller_and_get_an_answer()
    {
        var me = WindowsIdentity.GetCurrent();
        var accept = EnginePipe.AcceptOwner;
        EnginePipe.AcceptOwner = o => o == me.User;
        var (s, _, _) = NewServer();
        try
        {
            JsonObject? seen = null;
            bool? seenAdmin = null;
            bool Execute(JsonObject cmd, bool admin)
            {
                seen = cmd; seenAdmin = admin;
                return admin || PatternRules.InboxActions.Contains(cmd.Str("action"));   // the engine's rule
            }
            var ok = await Pump(s, EnginePipe.SendAsync(new JsonObject { ["action"] = "scan-now", ["user"] = "somebody-else" }, 10_000), Execute);
            Assert.True(ok.Reached, ok.Message);
            Assert.True(ok.Ok, ok.Message);
            Assert.Equal(me.Name, seen!.Str("user"));   // not the name the request claimed
            Assert.Equal(new WindowsPrincipal(me).IsInRole(WindowsBuiltInRole.Administrator), seenAdmin);

            var pause = await Pump(s, EnginePipe.SendAsync(new JsonObject { ["action"] = "pause", ["blade"] = "edr", ["minutes"] = 0 }, 10_000), Execute);
            Assert.True(pause.Reached, pause.Message);
            if (seenAdmin == false) { Assert.False(pause.Ok); Assert.Contains("administrator", pause.Message); }
        }
        finally { s.Dispose(); EnginePipe.AcceptOwner = accept; EnginePipe.Name = "FreeEDR-Engine"; }
    }

    [Fact]
    public async Task Subscribers_hear_about_changes()
    {
        var me = WindowsIdentity.GetCurrent();
        var accept = EnginePipe.AcceptOwner;
        EnginePipe.AcceptOwner = o => o == me.User;
        var (s, ctx, _) = NewServer();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        try
        {
            var heard = new TaskCompletionSource();
            var connected = new TaskCompletionSource();
            var sub = EnginePipe.SubscribeAsync(() => heard.TrySetResult(), c => { if (c) connected.TrySetResult(); }, stop.Token);
            await connected.Task.WaitAsync(stop.Token);
            await Task.Delay(200, stop.Token);
            ctx.Changed = s.Changed;
            ctx.Event("system", "Info", "test event");
            await heard.Task.WaitAsync(stop.Token);
            stop.Cancel();
            await sub;
        }
        finally { s.Dispose(); EnginePipe.AcceptOwner = accept; EnginePipe.Name = "FreeEDR-Engine"; }
    }

    // ---- QA round 3: a request the engine was too busy for never runs after the caller heard "busy" -----------

    [Fact]
    public async Task A_request_the_engine_was_too_busy_for_is_dropped_never_run_later()
    {
        var me = WindowsIdentity.GetCurrent();
        var accept = EnginePipe.AcceptOwner;
        EnginePipe.AcceptOwner = o => o == me.User;
        var (s, _, _) = NewServer();
        try
        {
            // The main loop does not drain (busy): the caller's 3 s deadline is passed to the engine
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var r = await EnginePipe.SendAsync(new JsonObject { ["action"] = "scan-now" }, 3000);
            Assert.True(r.Reached, r.Message);
            Assert.True(r.Busy, r.Message);
            Assert.False(r.Answered);
            Assert.False(r.Unanswered);   // answered "busy" before the deadline, so the caller may queue it elsewhere
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(3), $"answered after {sw.Elapsed}");
            var ran = false;
            s.Drain((_, _) => ran = true);   // the main loop is free again
            Assert.False(ran);
        }
        finally { s.Dispose(); EnginePipe.AcceptOwner = accept; EnginePipe.Name = "FreeEDR-Engine"; }
    }

    [Fact]
    public async Task A_request_that_could_not_be_carried_out_says_why()
    {
        var me = WindowsIdentity.GetCurrent();
        var accept = EnginePipe.AcceptOwner;
        EnginePipe.AcceptOwner = o => o == me.User;
        var (s, _, _) = NewServer();
        try
        {
            var send = EnginePipe.SendAsync(new JsonObject { ["action"] = "scan-now" }, 10_000);
            while (!send.IsCompleted) { s.Drain((_, _) => new PipeServer.Outcome(false, "A scan was started less than 2 minutes ago.", true)); await Task.Delay(20, TestContext.Current.CancellationToken); }
            var r = await send;
            Assert.True(r.Answered, r.Message);
            Assert.False(r.Ok);
            Assert.True(r.Failed);
            Assert.Equal("A scan was started less than 2 minutes ago.", r.Message);
        }
        finally { s.Dispose(); EnginePipe.AcceptOwner = accept; EnginePipe.Name = "FreeEDR-Engine"; }
    }

    // ---- fairness: no account can take the pipe from the others (audit round 2, finding 5) -------------------

    [Fact]
    public async Task Line_reader_splits_buffered_lines_and_refuses_an_endless_one()
    {
        using var server = new System.IO.Pipes.AnonymousPipeServerStream(System.IO.Pipes.PipeDirection.Out);
        using var client = new System.IO.Pipes.AnonymousPipeClientStream(System.IO.Pipes.PipeDirection.In, server.ClientSafePipeHandle);
        var ct = TestContext.Current.CancellationToken;
        var reader = new EnginePipe.LineReader(client);
        await server.WriteAsync("{\"a\":1}\n{\"b\":"u8.ToArray(), ct);
        await server.FlushAsync(ct);
        Assert.Equal(1, (await reader.ReadAsync(ct))!.Int("a"));
        await server.WriteAsync("2}\n"u8.ToArray(), ct);
        Assert.Equal(2, (await reader.ReadAsync(ct))!.Int("b"));
        var big = new byte[EnginePipe.MaxLine + 10];
        Array.Fill(big, (byte)'x');
        var write = server.WriteAsync(big, ct).AsTask();
        Assert.Null(await reader.ReadAsync(ct));   // over 64 KB without a line end: the connection ends
        client.Dispose();
        try { await write; } catch (IOException) { }
    }

    [Fact]
    public async Task One_account_cannot_hold_every_connection()
    {
        var me = WindowsIdentity.GetCurrent();
        var accept = EnginePipe.AcceptOwner;
        EnginePipe.AcceptOwner = o => o == me.User;
        var (s, _, _) = NewServer();
        var ct = TestContext.Current.CancellationToken;
        var held = new List<System.IO.Pipes.NamedPipeClientStream>();
        try
        {
            // Its subscriptions are capped ...
            for (var i = 0; i < PipeServer.SubscriptionsPerCaller + 1; i++)
            {
                var c = new System.IO.Pipes.NamedPipeClientStream(".", EnginePipe.Name, System.IO.Pipes.PipeDirection.InOut, System.IO.Pipes.PipeOptions.Asynchronous);
                await c.ConnectAsync(5000, ct);
                await EnginePipe.WriteLineAsync(c, new JsonObject { ["op"] = "subscribe" }, ct);
                held.Add(c);
            }
            // The subscriptions are served in parallel, so any one of them may be the one over the cap: it is closed
            using (var t = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                t.CancelAfter(5000);
                var reads = held.Select(c => c.ReadAsync(new byte[16], t.Token).AsTask()).ToList();
                var closed = await Task.WhenAny(reads);
                Assert.Equal(0, await closed);
                t.Cancel();
                foreach (var r0 in reads.Where(r0 => r0 != closed)) try { await r0; } catch (OperationCanceledException) { } catch (IOException) { }
            }
            Assert.Equal(PipeServer.SubscriptionsPerCaller, s.Subscribers);
            Assert.Equal(1, s.Refused);
            // ... and a request still gets through
            var r = await Pump(s, EnginePipe.SendAsync(new JsonObject { ["action"] = "scan-now" }, 10_000), (_, _) => true);
            Assert.True(r.Reached, r.Message);
            Assert.True(r.Ok, r.Message);
            Assert.True(s.Refused >= 1);
        }
        finally
        {
            foreach (var c in held) c.Dispose();
            s.Dispose(); EnginePipe.AcceptOwner = accept; EnginePipe.Name = "FreeEDR-Engine";
        }
    }

    [Fact]
    public async Task A_client_that_sends_nothing_is_dropped()
    {
        var (s, _, _) = NewServer();
        var ct = TestContext.Current.CancellationToken;
        try
        {
            await using var c = new System.IO.Pipes.NamedPipeClientStream(".", EnginePipe.Name, System.IO.Pipes.PipeDirection.InOut, System.IO.Pipes.PipeOptions.Asynchronous);
            await c.ConnectAsync(5000, ct);
            var sw = System.Diagnostics.Stopwatch.StartNew();
            using var t = CancellationTokenSource.CreateLinkedTokenSource(ct);
            t.CancelAfter(PipeServer.FirstLineTimeout + TimeSpan.FromSeconds(5));
            Assert.Equal(0, await c.ReadAsync(new byte[16], t.Token));
            Assert.True(sw.Elapsed < PipeServer.FirstLineTimeout + TimeSpan.FromSeconds(3), $"held for {sw.Elapsed}");
        }
        finally { s.Dispose(); EnginePipe.Name = "FreeEDR-Engine"; }
    }

    // ---- sandboxed scanner tools -----------------------------------------------------------------------

    private static string? ToolsCache()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
            if (File.Exists(Path.Combine(d.FullName, "project_structure.txt"))) return Path.Combine(d.FullName, "obj", "tools-cache", "bin");
        return null;
    }

    [Fact]
    public void A_low_integrity_folder_is_writable_from_the_sandbox()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "sandbox-work", Guid.NewGuid().ToString("N"));
        // Labelling needs WRITE_OWNER on the folder: the engine has it as SYSTEM, an unelevated test run may not
        Assert.SkipUnless(Sandbox.LowIntegrityFolder(dir), "cannot label a folder low integrity without WRITE_OWNER (checked live: the engine runs as SYSTEM)");
        var target = Path.Combine(dir, "out.txt");
        var r = Sandbox.RunCapture(Path.Combine(EdrPaths.System32, "cmd.exe"), ["/c", "type", "nul", ">", target], 30, workDir: dir, env: new Dictionary<string, string> { ["TEMP"] = dir }, ct: TestContext.Current.CancellationToken);
        Assert.True(r.Started, r.Error);
        Assert.True(File.Exists(target), "the sandbox could not write its own work folder");
        Directory.Delete(dir, true);
    }

    [Fact]
    public void Hayabusa_and_osv_scanner_start_in_the_sandbox()
    {
        var bin = ToolsCache();
        Assert.SkipUnless(bin is not null && File.Exists(Path.Combine(bin, "hayabusa", "hayabusa.exe")) && File.Exists(Path.Combine(bin, "osv-scanner.exe")),
                          "obj\\tools-cache not filled yet (dev_build.cmd fills it)");
        var haya = Sandbox.RunCapture(Path.Combine(bin!, "hayabusa", "hayabusa.exe"), ["help"], 60, 1024, Path.Combine(bin!, "hayabusa"), ct: TestContext.Current.CancellationToken);
        Assert.True(haya.Started, haya.Error);
        Assert.Contains("dfir-timeline", haya.Output);
        var osv = Sandbox.RunCapture(Path.Combine(bin!, "osv-scanner.exe"), ["--version"], 60, 1024, ct: TestContext.Current.CancellationToken);
        Assert.True(osv.Started, osv.Error);
        Assert.Contains("osv-scanner", osv.Output, StringComparison.OrdinalIgnoreCase);
    }
}
