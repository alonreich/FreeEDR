using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using Edr.Core.Native;
using Edr.Engine;
using Xunit;

namespace Edr.Core.Tests;

public class QaRound3Tests
{
    private static string DevFolder(string name)
    {
        var d = Path.Combine(AppContext.BaseDirectory, "qa3", $"{name}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(d);
        return d;
    }

    private static Context NewContext(string root) => new(new EdrPaths(root, Path.Combine(root, "user", "x")));

    private static List<JsonObject> Events(Context ctx) =>
        File.Exists(ctx.Paths.EventsFile)
            ? File.ReadAllLines(ctx.Paths.EventsFile).Select(l => JsonFile.Parse(l) as JsonObject).OfType<JsonObject>().ToList()
            : [];

    private const string Hash = "AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12";

    private static EventRecord ProcessStart(string hash) => EventRecord.FromXml($"""
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><EventID>1</EventID><TimeCreated SystemTime="2026-11-07T10:00:00.0000000Z"/><Channel>Microsoft-Windows-Sysmon/Operational</Channel></System>
          <EventData>
            <Data Name="RuleName">Encoded PowerShell command</Data><Data Name="Image">C:\NoSuchFolder\payload.exe</Data>
            <Data Name="ParentImage">C:\Tools\Builder\builder.exe</Data><Data Name="CommandLine">payload.exe -run</Data>
            <Data Name="Hashes">MD5=00,SHA256={hash},IMPHASH=00</Data><Data Name="User">PC\someone</Data>
          </EventData>
        </Event>
        """)!;

    [Fact]
    public void A_program_started_by_an_allowed_parent_is_still_checked_against_the_malware_hashes()
    {
        var root = DevFolder("allowed-ioc");
        var ctx = NewContext(root);
        Directory.CreateDirectory(ctx.Paths.RulesDir);
        Directory.CreateDirectory(ctx.Paths.ConfigDir);
        File.WriteAllText(ctx.Paths.IocFile, $"{Hash};Test.Trojan\n");
        File.WriteAllText(ctx.Paths.ExclusionsFile, """{"realtime":[{"id":"allow1","rule":"*","image":"","parent":"C:\\Tools\\Builder\\builder.exe","parentSigner":""}]}""");
        ctx.Excl.Load();
        using var rt = new Realtime(ctx);
        rt.UpdateIocSet();

        rt.Handle(ProcessStart(new string('0', 64)));
        Assert.Empty(Events(ctx));

        rt.Handle(ProcessStart(Hash));
        var e = Assert.Single(Events(ctx));
        Assert.Equal("ioc", e.Str("blade"));
        Assert.Equal("Critical", e.Str("severity"));
        Assert.Contains("Test.Trojan", e.Str("title"));
        Assert.Equal("allow1", e.Str("allowedBehaviour"));
        Directory.Delete(root, true);
    }

    [Fact]
    public void An_ioc_allow_still_silences_that_hash_for_an_allowed_parent()
    {
        var root = DevFolder("allowed-ioc2");
        var ctx = NewContext(root);
        Directory.CreateDirectory(ctx.Paths.RulesDir);
        Directory.CreateDirectory(ctx.Paths.ConfigDir);
        File.WriteAllText(ctx.Paths.IocFile, $"{Hash};Test.Trojan\n");
        File.WriteAllText(ctx.Paths.ExclusionsFile, $$"""{"realtime":[{"id":"a","rule":"*","parent":"C:\\Tools\\Builder\\builder.exe"}],"ioc":[{"id":"b","sha256":"{{Hash}}"}]}""");
        ctx.Excl.Load();
        using var rt = new Realtime(ctx);
        rt.UpdateIocSet();
        rt.Handle(ProcessStart(Hash));
        Assert.Empty(Events(ctx));
        Directory.Delete(root, true);
    }

    [Fact]
    public void Reset_removes_the_defender_allows_and_keeps_listing_one_defender_refused()
    {
        var excl = JsonFile.Parse("""
            {"defender":[{"id":"1","kind":"asr","path":"C:\\Tools\\a.exe"},{"id":"2","kind":"threat","path":"2147735503"},{"id":"3","kind":"cfa","path":"C:\\Tools\\b.exe"}]}
            """) as JsonObject;
        var removed = new List<string>();
        var notes = new List<string>();
        var kept = FactoryReset.RemoveDefenderAllows(excl, (kind, path) =>
        {
            if (kind == "threat") return (false, "0x800106ba");
            removed.Add($"{kind}:{path}");
            return (true, "");
        }, notes);
        Assert.Equal(new[] { @"asr:C:\Tools\a.exe", @"cfa:C:\Tools\b.exe" }, removed);
        Assert.Equal("2", Assert.Single(kept).Str("id"));
        Assert.Contains(notes, n => n.StartsWith("WARN", StringComparison.Ordinal) && n.Contains("2147735503"));
        Assert.Contains("OK 2 of 3", string.Join("\n", notes));
    }

    [Fact]
    public void Removing_a_defender_allow_that_defender_keeps_leaves_it_listed()
    {
        var root = DevFolder("unexclude");
        var ctx = NewContext(root);
        Directory.CreateDirectory(ctx.Paths.ConfigDir);
        File.WriteAllText(ctx.Paths.ExclusionsFile, """{"defender":[{"id":"d1","kind":"asr","path":"C:\\Tools\\a.exe"}]}""");
        ctx.Excl.Load();
        var cmds = new Commands(ctx, new Wail2Ban(ctx), new Scanner(ctx)) { RemoveDefenderAllow = (_, _) => (false, "access denied") };
        Assert.False(cmds.Execute(new JsonObject { ["action"] = "unexclude", ["id"] = "d1" }, trusted: true));
        Assert.True(cmds.LastFailed);
        Assert.Single(ctx.Excl["defender"]);
        Assert.Contains(Events(ctx), e => e.Str("title").Contains("Could not remove a Microsoft Defender allow"));

        cmds.RemoveDefenderAllow = (_, _) => (true, "");
        Assert.True(cmds.Execute(new JsonObject { ["action"] = "unexclude", ["id"] = "d1" }, trusted: true));
        Assert.False(cmds.LastFailed);
        Assert.Empty(ctx.Excl["defender"]);
        Directory.Delete(root, true);
    }

    [Fact]
    public void A_skipped_or_failed_osv_step_keeps_the_vulnerability_list()
    {
        static JsonObject Result(JsonObject step) => new() { ["steps"] = new JsonArray(step) };
        const string name = "Python vulnerability scan (OSV)";
        Assert.True(Scanner.OsvListReplaced(Result(new() { ["name"] = name, ["ok"] = true })));
        Assert.False(Scanner.OsvListReplaced(Result(new() { ["name"] = name, ["ok"] = true, ["skipped"] = true })));
        Assert.False(Scanner.OsvListReplaced(Result(new() { ["name"] = name, ["ok"] = false })));
    }

    [Fact]
    public void Only_a_clean_exit_without_a_report_means_nothing_found()
    {
        var clean = OsvParser.Outcome(new Sandbox.Result(true, 0, "", ""));
        Assert.Null(clean.Report);
        Assert.Null(clean.Problem);
        Assert.NotNull(OsvParser.Outcome(new Sandbox.Result(true, -1, "", "timeout")).Problem);
        Assert.NotNull(OsvParser.Outcome(new Sandbox.Result(true, -1, "", "cancelled")).Problem);
        Assert.NotNull(OsvParser.Outcome(new Sandbox.Result(true, unchecked((int)0xC0000005), "", "")).Problem);
        Assert.NotNull(OsvParser.Outcome(new Sandbox.Result(true, 128, "", "")).Problem);
        Assert.NotNull(OsvParser.Outcome(new Sandbox.Result(false, 0, "", "CreateProcessAsUser")).Problem);
        var found = OsvParser.Outcome(new Sandbox.Result(true, 1, "scanning...\n{\"results\":[]}\n", ""));
        Assert.Null(found.Problem);
        Assert.NotNull(found.Report);
    }

    [Fact]
    public void Scan_now_that_cannot_start_says_why()
    {
        var root = DevFolder("scan-now");
        var ctx = NewContext(root);
        ctx.State.Set("edrPausedUntil", Catalog.UntilResumed);
        var cmds = new Commands(ctx, new Wail2Ban(ctx), new Scanner(ctx));
        Assert.False(cmds.Execute(new JsonObject { ["action"] = "scan-now" }, trusted: false));
        Assert.True(cmds.LastFailed);
        Assert.Contains("paused", cmds.LastNote);
        Assert.Contains(Events(ctx), e => e.Str("title") == "Scan not started");
        Directory.Delete(root, true);
    }

    private static void WriteEvents(string file, int n, string tag) =>
        File.WriteAllLines(file, Enumerable.Range(0, n).Select(i => $$"""{"id":"{{tag}}{{i}}","blade":"realtime","title":"{{tag}} {{i}} {{new string('x', 40)}}"}"""));

    [Fact]
    public void A_deleted_event_history_empties_the_dashboards_list()
    {
        var d = DevFolder("tail-reset");
        var file = Path.Combine(d, "events.jsonl");
        WriteEvents(file, 3, "old");
        var events = new List<Rec>();
        var tail = new EventTail(file);
        Assert.Equal(3, tail.ReadNew(events).Count);

        File.Delete(file);
        WriteEvents(file, 10, "new");
        var added = tail.ReadNew(events);
        Assert.True(tail.WasReset);
        Assert.Equal(10, added.Count);
        Assert.All(events, e => Assert.StartsWith("new", e.S("id")));

        File.Delete(file);
        Assert.Empty(tail.ReadNew(events));
        Assert.True(tail.WasReset);
        Assert.Empty(events);
        Directory.Delete(d, true);
    }

    [Fact]
    public void A_rotated_event_file_keeps_the_alerts_read_before()
    {
        var d = DevFolder("tail-rotate");
        var file = Path.Combine(d, "events.jsonl");
        WriteEvents(file, 3, "old");
        var events = new List<Rec>();
        var tail = new EventTail(file);
        tail.ReadNew(events);
        File.Move(file, Path.Combine(d, "events-20261107-120000.jsonl"));
        WriteEvents(file, 10, "new");
        tail.ReadNew(events);
        Assert.False(tail.WasReset);
        Assert.Equal(13, events.Count);
        Directory.Delete(d, true);
    }

    [Fact]
    public void A_hung_or_chatty_netsh_style_program_never_blocks_its_caller()
    {
        var sw = Stopwatch.StartNew();
        Assert.Equal(-1, Firewall.RunBounded(Path.Combine(EdrPaths.System32, "ping.exe"), "-n 30 127.0.0.1", 1000));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), $"waited {sw.Elapsed}");
        sw.Restart();
        var rc = Firewall.RunBounded(Path.Combine(EdrPaths.System32, "cmd.exe"), "/d /c \"for /L %i in (1,1,4000) do @echo %i-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 1>&2\"", 60_000);
        Assert.Equal(0, rc);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(50), $"took {sw.Elapsed}");
    }

    private static (bool Answer, string Text, RECT Window, RECT Work) AskAndAnswer(string request, Func<nint, bool> answer)
    {
        var title = "FreeEDR test confirm " + Guid.NewGuid().ToString("N");
        var result = false;
        var t = new Thread(() => result = ConfirmWindow.Ask(title, "FreeEDR is about to make this change as administrator:", request, "Continue only if ...", true));
        t.Start();
        nint hwnd = 0;
        for (var i = 0; i < 200 && hwnd == 0; i++) { Thread.Sleep(50); hwnd = FindWindowW(ConfirmWindow.ClassName, title); }
        Assert.NotEqual(0, hwnd);
        var edit = GetDlgItem(hwnd, ConfirmWindow.IdText);
        var len = (int)SendMessageW(edit, 0x0E, 0, 0);
        var buf = new System.Text.StringBuilder(len + 1);
        SendMessageW(edit, 0x0D, len + 1, buf);
        GetWindowRect(hwnd, out var win);
        var work = new RECT();
        SystemParametersInfoW(0x30, 0, ref work, 0);
        Assert.True(answer(hwnd));
        Assert.True(t.Join(10_000), "the window did not close");
        return (result, buf.ToString(), win, work);
    }

    [Fact]
    public void The_confirmation_shows_every_line_of_a_long_request_inside_the_screen()
    {
        var lines = Enumerable.Range(1, 20).Select(i => $"• Allow (realtime): image=C:\\Users\\someone\\AppData\\Local\\{new string('p', 280)}\\tool{i}.exe").ToList();
        var request = string.Join("\n", lines);
        var (answer, text, win, work) = AskAndAnswer(request, h => PostMessageW(h, 0x111, ConfirmWindow.IdNo, GetDlgItem(h, ConfirmWindow.IdNo)));
        Assert.False(answer);
        foreach (var l in lines) Assert.Contains(l, text);
        Assert.True(win.Top >= work.Top && win.Bottom <= work.Bottom && win.Left >= work.Left && win.Right <= work.Right,
                    $"window {win.Left},{win.Top}-{win.Right},{win.Bottom} outside the work area {work.Left},{work.Top}-{work.Right},{work.Bottom}");
    }

    [Fact]
    public void The_confirmation_answers_yes_only_for_the_yes_button()
    {
        Assert.True(AskAndAnswer("• Resume Real-time detection", h => PostMessageW(h, 0x111, ConfirmWindow.IdYes, GetDlgItem(h, ConfirmWindow.IdYes))).Answer);
        Assert.False(AskAndAnswer("• Resume Real-time detection", h => PostMessageW(h, 0x10, 0, 0)).Answer);
        Assert.False(AskAndAnswer("• Resume Real-time detection", h => PostMessageW(h, 0x111, 2, 0)).Answer);
        Assert.False(AskAndAnswer("• Resume Real-time detection", h => PostMessageW(h, 0x111, 1, 0)).Answer);
    }

    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }

    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern nint FindWindowW(string cls, string title);
    [DllImport("user32.dll")] private static extern nint GetDlgItem(nint h, int id);
    [DllImport("user32.dll")] private static extern nint SendMessageW(nint h, uint m, nint w, nint l);
    [DllImport("user32.dll")] private static extern bool PostMessageW(nint h, uint m, nint w, nint l);
    [DllImport("user32.dll")] private static extern bool GetWindowRect(nint h, out RECT r);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern nint SendMessageW(nint h, uint m, nint w, System.Text.StringBuilder l);
    [DllImport("user32.dll")] private static extern bool SystemParametersInfoW(uint action, uint param, ref RECT value, uint ini);
}
