using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using Edr.Core.Native;
using Edr.Engine;
using Xunit;

namespace Edr.Core.Tests;

public class AuditFixTests
{
    private static string DevFolder(string name)
    {
        var d = Path.Combine(AppContext.BaseDirectory, "audit2", $"{name}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(d);
        return d;
    }

    private static Context NewContext(string root) => new(new EdrPaths(root, Path.Combine(root, "user", "x")));

    [Fact]
    public void A_request_file_is_read_and_removed()
    {
        var d = DevFolder("drop");
        var f = Path.Combine(d, "a.json");
        File.WriteAllText(f, """{"action":"scan-now"}""");
        var r = DropFile.Take(f, PatternRules.MaxPayload);
        Assert.Equal(DropFile.Outcome.Taken, r.Outcome);
        Assert.Equal("scan-now", r.Command!.Str("action"));
        Assert.False(File.Exists(f));
        Directory.Delete(d, true);
    }

    [Fact]
    public void An_oversized_request_file_is_removed_unread()
    {
        var d = DevFolder("drop");
        var f = Path.Combine(d, "big.json");
        File.WriteAllText(f, "{\"action\":\"scan-now\",\"pad\":\"" + new string('x', PatternRules.MaxPayload) + "\"}");
        var r = DropFile.Take(f, PatternRules.MaxPayload);
        Assert.Equal(DropFile.Outcome.Rejected, r.Outcome);
        Assert.Null(r.Command);
        Assert.False(File.Exists(f));
        Directory.Delete(d, true);
    }

    [Fact]
    public void A_file_another_program_writes_to_is_busy_not_read_while_it_grows()
    {
        var d = DevFolder("drop");
        var f = Path.Combine(d, "growing.json");
        using (var w = new FileStream(f, FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
        {
            w.Write("{\"action\":\"scan-now\"}"u8);
            w.Flush();
            var r = DropFile.Take(f, PatternRules.MaxPayload);
            Assert.Equal(DropFile.Outcome.Busy, r.Outcome);
            Assert.True(File.Exists(f));
        }
        Assert.Equal(DropFile.Outcome.Taken, DropFile.Take(f, PatternRules.MaxPayload).Outcome);
        Directory.Delete(d, true);
    }

    [Fact]
    public void A_hard_link_is_never_read_and_its_target_survives()
    {
        var d = DevFolder("drop");
        var target = Path.Combine(d, "secret.txt");
        File.WriteAllText(target, """{"action":"scan-now","secret":"do not read"}""");
        var link = Path.Combine(d, "inbox-link.json");
        Assert.SkipUnless(CreateHardLinkW(link, target, 0), "cannot create a hard link here");
        var r = DropFile.Take(link, PatternRules.MaxPayload);
        Assert.Equal(DropFile.Outcome.Rejected, r.Outcome);
        Assert.Null(r.Command);
        Assert.False(File.Exists(link));
        Assert.Contains("do not read", File.ReadAllText(target));
        Directory.Delete(d, true);
    }

    [Fact]
    public void A_folder_named_like_a_request_is_refused()
    {
        var d = DevFolder("drop");
        var f = Path.Combine(d, "x.json");
        Directory.CreateDirectory(f);
        Assert.Equal(DropFile.Outcome.Rejected, DropFile.Take(f, PatternRules.MaxPayload).Outcome);
        Directory.Delete(d, true);
    }

    [Fact]
    public async Task An_oplock_on_a_request_file_does_not_make_the_reader_wait()
    {
        var d = DevFolder("oplock");
        var f = Path.Combine(d, "held.json");
        File.WriteAllText(f, """{"action":"scan-now"}""");
        var ov = Marshal.AllocHGlobal(Marshal.SizeOf<NativeOverlapped>());
        Marshal.StructureToPtr(new NativeOverlapped(), ov, false);
        using var holder = CreateFileW(f, 0x80000000, 0x7, 0, 3, 0x40000000, 0);
        Assert.False(holder.IsInvalid);
        var granted = false;
        try
        {
            granted = !DeviceIoControl(holder, 0x00090008, 0, 0, 0, 0, out _, ov) && Marshal.GetLastPInvokeError() == 997;
            Assert.SkipUnless(granted, "this volume grants no batch oplock");
            var take = Task.Run(() => DropFile.Take(f, PatternRules.MaxPayload), TestContext.Current.CancellationToken);
            var first = await Task.WhenAny(take, Task.Delay(5000, TestContext.Current.CancellationToken));
            Assert.True(first == take, "the reader waited on another process's oplock");
            Assert.Equal(DropFile.Outcome.Busy, (await take).Outcome);
            Assert.True(File.Exists(f));
        }
        finally
        {
            if (granted) { CancelIoEx(holder, ov); GetOverlappedResult(holder, ov, out _, true); }
            holder.Dispose();
            Marshal.FreeHGlobal(ov);
        }
        Directory.Delete(d, true);
    }

    [Fact]
    public void Intake_queues_inbox_requests_and_keeps_busy_files_from_blocking_new_ones()
    {
        var root = DevFolder("intake");
        var ctx = NewContext(root);
        Directory.CreateDirectory(ctx.Paths.InboxDir);
        using var intake = new CommandIntake(ctx);
        var held = new List<FileStream>();
        for (var i = 0; i < 30; i++)
        {
            var f = Path.Combine(ctx.Paths.InboxDir, $"0-held-{i:D2}.json");
            var fs = new FileStream(f, FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            fs.Write("{\"action\":\"resume\",\"blade\":\"edr\"}"u8);
            fs.Flush();
            held.Add(fs);
        }
        try
        {
            File.WriteAllText(Path.Combine(ctx.Paths.InboxDir, "9-real.json"), """{"action":"scan-now"}""");
            var sw = System.Diagnostics.Stopwatch.StartNew();
            intake.SweepOnce(1);
            intake.SweepOnce(1);
            Assert.True(sw.ElapsedMilliseconds < 3000, $"two sweeps took {sw.ElapsedMilliseconds} ms");
            Assert.True(intake.TryDequeue(out var r));
            Assert.Equal("scan-now", r.Cmd.Str("action"));
            Assert.False(r.Trusted);
            Assert.False(File.Exists(Path.Combine(ctx.Paths.InboxDir, "9-real.json")));
        }
        finally { foreach (var fs in held) fs.Dispose(); }
        Directory.Delete(root, true);
    }

    [Fact]
    public void Inbox_requests_are_recorded_under_no_claimed_name_and_cannot_pause()
    {
        var root = DevFolder("intake");
        var ctx = NewContext(root);
        Directory.CreateDirectory(ctx.Paths.InboxDir);
        using var intake = new CommandIntake(ctx);
        File.WriteAllText(Path.Combine(ctx.Paths.InboxDir, "a.json"), """{"action":"pause","blade":"edr","minutes":0,"user":"Administrator"}""");
        intake.SweepOnce(1);
        var cmds = new Commands(ctx, new Wail2Ban(ctx), new Scanner(ctx));
        cmds.RunQueued(intake);
        Assert.Equal("", ctx.State.PausedUntil("edr"));
        Directory.Delete(root, true);
    }

    [Fact]
    public void Confirmation_never_cuts_a_value_and_puts_the_deciding_fields_first()
    {
        var image = @"C:\Users\victim\AppData\Roaming\evil\payload.exe";
        var op = new JsonObject { ["action"] = "exclude", ["blade"] = "realtime", ["note"] = new string('a', 400), ["detail"] = "harmless looking text", ["image"] = image };
        var s = RequestSummary.Build(op);
        Assert.True(s.Complete);
        Assert.Contains(image, s.Text);
        Assert.True(s.Text.IndexOf("image=", StringComparison.Ordinal) < s.Text.IndexOf("note=", StringComparison.Ordinal));
        Assert.Contains(new string('a', 400), s.Text);
    }

    [Fact]
    public void Confirmation_replaces_text_direction_tricks()
    {
        var op = new JsonObject { ["action"] = "exclude", ["blade"] = "yara", ["image"] = "C:\\x\\\u202Eexe.txt\u200B.exe" };
        var text = RequestSummary.Describe(op);
        Assert.DoesNotContain('\u202E', text);
        Assert.DoesNotContain('\u200B', text);
    }

    [Fact]
    public void A_batch_over_the_window_size_is_incomplete()
    {
        var ops = new JsonArray();
        for (var i = 0; i < RequestSummary.MaxLines + 1; i++) ops.Add((JsonNode)new JsonObject { ["action"] = "unban", ["ip"] = $"203.0.113.{i}" });
        Assert.False(RequestSummary.Build(new JsonObject { ["action"] = "batch", ["ops"] = ops }).Complete);
        var fewer = (JsonArray)ops.DeepClone();
        fewer.RemoveAt(0);
        Assert.True(RequestSummary.Build(new JsonObject { ["action"] = "batch", ["ops"] = fewer }).Complete);
    }

    [Fact]
    public void Settings_are_shown_as_the_values_that_change()
    {
        var cfg = new JsonObject { ["action"] = "set-config", ["config"] = new JsonObject { ["sigmaLookback"] = "2d", ["wail2ban"] = new JsonObject { ["block"] = false } } };
        var s = RequestSummary.Build(cfg, new RequestSummary.Lookup(new EdrConfig(), null, null));
        Assert.Contains("wail2ban.block: true → false", s.Text);
        Assert.DoesNotContain("sigmaLookback", s.Text);
        Assert.Equal(1, s.Lines);
    }

    [Fact]
    public void A_built_in_trusted_app_is_one_line_but_a_tampered_one_is_listed_in_full()
    {
        var p = Profiles.Get("claude-code")!;
        var ops = new JsonArray(Profiles.Ops(p).Select(o => (JsonNode)o).ToArray());
        var s = RequestSummary.Build(new JsonObject { ["action"] = "batch", ["ops"] = ops });
        Assert.Equal(1, s.Lines);
        Assert.Contains(p.Name, s.Text);

        var tampered = new JsonArray(Profiles.Ops(p).Select(o => (JsonNode)o).ToArray());
        tampered.Add((JsonNode)new JsonObject { ["action"] = "exclude", ["blade"] = "realtime", ["profile"] = p.Id, ["image"] = @"C:\Users\x\evil.exe" });
        var t = RequestSummary.Build(new JsonObject { ["action"] = "batch", ["ops"] = tampered });
        Assert.Equal(tampered.Count, t.Lines);
        Assert.Contains(@"C:\Users\x\evil.exe", t.Text);
    }

    [Fact]
    public void Removing_an_allow_shows_what_it_allows_not_its_id()
    {
        var entry = new JsonObject { ["id"] = "abc123", ["image"] = @"C:\Tools\thing.exe", ["rule"] = "*", ["blade"] = "realtime" };
        var lookup = new RequestSummary.Lookup(null, id => id == "abc123" ? entry : null, null);
        var text = RequestSummary.Describe(new JsonObject { ["action"] = "unexclude", ["id"] = "abc123" }, lookup);
        Assert.Contains(@"C:\Tools\thing.exe", text);
    }

    [Fact]
    public void Yara_errors_timeouts_and_failed_exits_are_not_clean()
    {
        Assert.NotNull(Realtime.ParseYaraOutput(1, "error scanning C:\\x.exe: could not open file\n", "").NotScanned);
        Assert.NotNull(Realtime.ParseYaraOutput(-1, "", "timeout").NotScanned);
        Assert.NotNull(Realtime.ParseYaraOutput(3, "", "").NotScanned);
        Assert.Equal("Ransom_Note C:\\x.exe".Split(' ')[0], Realtime.ParseYaraOutput(0, "warning: slow rule\nRansom_Note C:\\x.exe\n", "").Hit);
        var clean = Realtime.ParseYaraOutput(0, "", "");
        Assert.Null(clean.Hit);
        Assert.Null(clean.NotScanned);
    }

    [Fact]
    public void A_file_too_large_for_yara_is_reported_as_not_scanned()
    {
        var root = DevFolder("yara");
        var f = Path.Combine(root, "padded.exe");
        using (var fs = new FileStream(f, FileMode.CreateNew)) fs.SetLength(Realtime.YaraMaxBytes + 1);
        using var rt = new Realtime(NewContext(root));
        var r = rt.ScanFile(f);
        Assert.Null(r.Hit);
        Assert.Contains("50 MB", r.NotScanned);
        Directory.Delete(root, true);
    }

    [Fact]
    public async Task An_unsigned_tool_is_never_installed_from_github()
    {
        var root = DevFolder("tools");
        foreach (var t in Tools.Pinned.Where(t => !t.Updatable))
        {
            var (ok, msg) = await new Tools(new EdrPaths(root)).UpdateToLatest(t, TestContext.Current.CancellationToken);
            Assert.False(ok);
            Assert.Contains("not digitally signed", msg);
        }
        Assert.Contains(Tools.Pinned, t => t.Updatable && t.Publisher.Length > 0);
        Directory.Delete(root, true);
    }

    [Fact]
    public void Tool_version_queries_run_in_the_sandbox()
    {
        string? bin = null;
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
            if (File.Exists(Path.Combine(d.FullName, "project_structure.txt"))) { bin = Path.Combine(d.FullName, "obj", "tools-cache"); break; }
        Assert.SkipUnless(bin is not null && File.Exists(Path.Combine(bin, "bin", "yara64.exe")), "obj\\tools-cache not filled yet (dev_build.cmd fills it)");
        var tools = new Tools(new EdrPaths(bin));
        foreach (var t in Tools.Pinned)
            if (File.Exists(tools.ExePath(t)))
                Assert.Equal(Tools.VersionOf(t.Tag), tools.InstalledVersion(t));
    }

    [Fact]
    public void Sigma_lookback_and_hayabusa_errors_are_read_right()
    {
        Assert.Equal(TimeSpan.FromDays(2), Scanner.Lookback("2d"));
        Assert.Equal(TimeSpan.FromHours(12), Scanner.Lookback("12h"));
        Assert.Equal(TimeSpan.FromDays(2), Scanner.Lookback("junk"));
        Assert.True(Scanner.HayabusaFailed(0, "[ERROR] -l, --live-analysis needs to be run as Administrator on Windows."));
        Assert.True(Scanner.HayabusaFailed(2, ""));
        Assert.False(Scanner.HayabusaFailed(0, "Total | Unique detections: 0 | 0"));
    }

    [Fact]
    public void Recent_records_of_the_logs_are_copied_for_the_sandbox()
    {
        var root = DevFolder("logs");
        var r = LogExport.Recent(TimeSpan.FromDays(7), Path.Combine(root, "evtx"), 1L << 30, TestContext.Current.CancellationToken);
        Assert.SkipWhen(r.Logs == 0 && r.Failed == 0, "no readable log has records in the last 7 days");
        Assert.True(r.Logs > 0, r.FirstError);
        Assert.NotEmpty(Directory.GetFiles(Path.Combine(root, "evtx"), "*.evtx"));
        Tools.DeleteTree(root);
    }

    [Fact]
    public void An_event_that_cannot_be_written_is_counted()
    {
        var root = DevFolder("events");
        var p = new EdrPaths(root, Path.Combine(root, "user", "x"));
        var w = new EventWriter(p);
        Assert.True(w.Append(new JsonObject { ["title"] = "first" }));
        using (new FileStream(p.EventsFile, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            Assert.False(w.Append(new JsonObject { ["title"] = "lost" }));
        Assert.Equal(1, w.Failures);
        Assert.NotEqual("", w.LastError);
        Directory.Delete(root, true);
    }

    [Fact]
    public void Notes_are_accepted_only_from_elevated_freeedr_programs()
    {
        var note = new JsonObject { ["action"] = "note", ["blade"] = "system", ["severity"] = "Info", ["title"] = "Tool updated: YARA", ["kind"] = "tool-update", ["tool"] = "YARA", ["ok"] = true };
        Assert.True(PatternRules.IsValidOp(note));
        Assert.False(PatternRules.IsValidCommand(note, out _));
        Assert.False(PatternRules.IsValidOp(new JsonObject { ["action"] = "note", ["blade"] = "realtime", ["severity"] = "Critical", ["title"] = "fake alert", ["kind"] = "status" }));
        Assert.False(PatternRules.IsValidOp(new JsonObject { ["action"] = "note", ["blade"] = "system", ["severity"] = "Info", ["title"] = "x", ["kind"] = "status", ["yaraRule"] = "spoof" }));

        var root = DevFolder("note");
        var ctx = NewContext(root);
        var cmds = new Commands(ctx, new Wail2Ban(ctx), new Scanner(ctx));
        Assert.False(cmds.Execute((JsonObject)note.DeepClone(), trusted: false));
        Assert.True(cmds.Execute((JsonObject)note.DeepClone(), trusted: true));
        Assert.Contains("Tool updated: YARA", File.ReadAllText(ctx.Paths.EventsFile));
        Directory.Delete(root, true);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateHardLinkW(string link, string target, nint security);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(string name, uint access, uint share, nint security, uint disposition, uint flags, nint template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CancelIoEx(Microsoft.Win32.SafeHandles.SafeFileHandle h, nint overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetOverlappedResult(Microsoft.Win32.SafeHandles.SafeFileHandle h, nint overlapped, out uint transferred, bool wait);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(Microsoft.Win32.SafeHandles.SafeFileHandle h, uint code, nint inBuf, uint inSize, nint outBuf, uint outSize, out uint returned, nint overlapped);
}
