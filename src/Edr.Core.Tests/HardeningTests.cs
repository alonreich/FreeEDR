using System.Text.Json.Nodes;
using Edr.Core.Native;
using Edr.Engine;
using Xunit;

namespace Edr.Core.Tests;

/// <summary>Pre-ship audit fixes (2026-11-06): elevated-request summary, scanner sandbox, signer cache key,
/// engine state locking, tray input snapshots.</summary>
public class HardeningTests
{
    private static string DevFolder(string name)   // inside the dev folder, not %TEMP%
    {
        var d = Path.Combine(AppContext.BaseDirectory, "hardening", $"{name}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(d);
        return d;
    }

    // ---- 1: the elevated helper shows what it is about to do ---------------------------------------------

    [Fact]
    public void Request_summary_names_the_change()
    {
        var pause = new JsonObject { ["action"] = "pause", ["blade"] = "edr", ["minutes"] = 0 };
        Assert.Contains("until it is resumed", RequestSummary.Describe(pause));
        Assert.True(RequestSummary.Weakens(pause));

        var cfg = new JsonObject { ["action"] = "set-config", ["config"] = new JsonObject { ["defenderMode"] = "untouched" } };
        Assert.Contains("defenderMode", RequestSummary.Describe(cfg));
        Assert.True(RequestSummary.Weakens(cfg));

        Assert.False(RequestSummary.Weakens(new JsonObject { ["action"] = "scan-now" }));
        Assert.Contains("FACTORY RESET", RequestSummary.Describe(new JsonObject { ["action"] = "restore-defaults" }));
    }

    [Fact]
    public void Request_summary_of_a_large_batch_is_capped_and_has_no_control_characters()
    {
        var ops = new JsonArray();
        for (var i = 0; i < 30; i++) ops.Add((JsonNode)new JsonObject { ["action"] = "exclude", ["blade"] = "realtime", ["image"] = $"C:\\x\\a{i}.exe\r\nfake line" });
        var s = RequestSummary.Build(new JsonObject { ["action"] = "batch", ["ops"] = ops });
        Assert.Contains("and 10 more changes", s.Text);
        Assert.DoesNotContain("\r\nfake", s.Text);
        Assert.Equal(RequestSummary.MaxLines + 1, s.Text.Split('\n').Length);
        Assert.False(s.Complete);   // the helper refuses what its window cannot show in full (exit code 6)
    }

    // ---- 6: untrusted-input parsers run sandboxed ------------------------------------------------------

    [Fact]
    public void Sandbox_runs_at_low_integrity()
    {
        var whoami = Path.Combine(EdrPaths.System32, "whoami.exe");
        var r = Sandbox.RunCapture(whoami, ["/groups"], timeoutSeconds: 30, ct: TestContext.Current.CancellationToken);
        Assert.True(r.Started, r.Error);
        Assert.Contains("S-1-16-4096", r.Output);   // Mandatory Label\Low Mandatory Level
    }

    [Fact]
    public void Sandbox_cannot_write_files()
    {
        var dir = DevFolder("sandbox");
        var target = Path.Combine(dir, "written.txt");
        var cmd = Path.Combine(EdrPaths.System32, "cmd.exe");
        var r = Sandbox.RunCapture(cmd, ["/c", "type", "nul", ">", target], timeoutSeconds: 30, workDir: dir, ct: TestContext.Current.CancellationToken);
        Assert.True(r.Started, r.Error);
        Assert.False(File.Exists(target), "a low-integrity process wrote into a medium-integrity folder");
        Directory.Delete(dir, true);
    }

    [Fact]
    public void Sandbox_quotes_arguments_like_windows_splits_them()
    {
        string[] args = ["plain", "with space", "quote\"inside", @"trail\", @"C:\Program Files\x\"];
        var line = Sandbox.CommandLine(@"C:\a b\t.exe", args);
        Assert.Equal([@"C:\a b\t.exe", .. args], Win32.SplitCommandLine(line));
    }

    // ---- 5: the signer cache key survives no in-place rewrite --------------------------------------------

    [Fact]
    public void Change_stamp_differs_after_a_same_size_rewrite_with_restored_timestamps()
    {
        var dir = DevFolder("stamp");
        var f = Path.Combine(dir, "tool.exe");
        File.WriteAllBytes(f, [1, 2, 3, 4, 5, 6, 7, 8]);
        var before = Win32.FileChangeStamp(f);
        Assert.SkipWhen(before is null, "no NTFS change journal on this volume");
        var created = File.GetCreationTimeUtc(f);
        var written = File.GetLastWriteTimeUtc(f);
        var identity = Win32.FileIdentity(f);
        using (var fs = new FileStream(f, FileMode.Open, FileAccess.Write)) fs.Write([9, 9, 9, 9, 9, 9, 9, 9]);
        File.SetCreationTimeUtc(f, created);
        File.SetLastWriteTimeUtc(f, written);
        Assert.Equal(identity, Win32.FileIdentity(f));          // the old key is fooled ...
        Assert.NotEqual(before, Win32.FileChangeStamp(f));       // ... the change journal is not
        Directory.Delete(dir, true);
    }

    // ---- 3: engine state is safe to use from the scan thread ---------------------------------------------

    [Fact]
    public void Engine_state_survives_concurrent_pause_checks_and_saves()
    {
        var root = DevFolder("state");
        var ctx = new Context(new EdrPaths(root, Path.Combine(root, "user", "x")));
        var past = DateTime.Now.AddMinutes(-1).ToString("s", System.Globalization.CultureInfo.InvariantCulture);
        var errors = 0;
        void Writer() { for (var i = 0; i < 300; i++) { ctx.State.Set($"k{i % 7}", i); ctx.State.Set("sigmaPausedUntil", past); ctx.State.Save(); } }
        void Reader() { for (var i = 0; i < 300; i++) { _ = ctx.State.IsPaused("sigma"); _ = ctx.State.Seen("sigmaSeen"); ctx.State.SetSeen("sigmaSeen", [$"a{i}"], 10); } }
        Parallel.Invoke(() => Guard(Writer), () => Guard(Reader), () => Guard(Reader));
        Assert.Equal(0, errors);
        Assert.NotNull(JsonFile.ReadObject(ctx.Paths.StateFile));
        Directory.Delete(root, true);

        void Guard(Action a) { try { a(); } catch (Exception) { Interlocked.Increment(ref errors); } }
    }

    // ---- 4: the tray builds its model from a snapshot ----------------------------------------------------

    [Fact]
    public void Inputs_snapshot_is_independent_of_later_edits()
    {
        var x = new EdrInputs();
        x.Reviewed.Add("a");
        x.Events.Add(Rec.Parse("""{"id":"1","blade":"realtime"}""")!);
        x.Exclusions["realtime"].Add(Rec.Parse("""{"id":"e1"}""")!);
        var snap = x.Snapshot();
        x.Reviewed.Add("b");
        x.Events.Clear();
        x.Exclusions["realtime"].Clear();
        Assert.Single(snap.Reviewed);
        Assert.Single(snap.Events);
        Assert.Single(snap.Exclusions["realtime"]);
    }

    [Fact]
    public void Parsed_records_can_be_read_from_several_threads()
    {
        var recs = Enumerable.Range(0, 200).Select(i => Rec.Parse("{\"id\":\"" + i + "\",\"ancestors\":[\"a\",\"b\"],\"x\":{\"y\":" + i + "}}")!).ToList();
        Parallel.For(0, 8, n => { foreach (var r in recs) { _ = r.S("id"); _ = r.Strings("ancestors"); _ = r.Child("x")?.I("y"); } });
    }
}
