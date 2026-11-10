using System.Diagnostics;
using System.Text;
using System.Text.Json.Nodes;
using Avalonia.Input.Platform;
using Edr.Core;
using Edr.Tray.Services;
using Edr.Tray.Views;

namespace Edr.Tray;

public sealed class Controller
{
    public TrayState State { get; }
    public Commands Commands { get; }
    public Preferences Prefs { get; }
    public Insights Insights { get; }
    public WingetCheck Winget { get; }
    public AppUpdater Updater { get; }
    public Notifier? Notifier { get; set; }

    public Action<string, bool, string?, Action?>? Snack { get; set; }
    public Action? Changed { get; set; }

    public Action? RefreshRequested { get; set; }
    public Func<IClipboard?>? Clipboard { get; set; }

    public Controller(TrayState state)
    {
        State = state;
        Commands = new Commands(state);
        Prefs = new Preferences(state.Paths.PreferencesFile);
        Insights = new Insights(Path.Combine(state.Paths.LocalDir, "insights.json"));
        Winget = new WingetCheck(state);
        Updater = new AppUpdater(state.Paths, Prefs);
        Commands.Slow = () => Say("Still waiting for the administrator step: its confirmation window may still be open, or a download is still running. " +
                                  "FreeEDR tells you the result when it finishes.");
    }

    public string UserProfile => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    private void Refresh()
    {
        State.Dirty = true;
        if (RefreshRequested is { } r) r();
        else Changed?.Invoke();
    }

    public void Say(string msg, bool error = false, string? actionLabel = null, Action? action = null)
    {
        if (Snack is not null) Snack(msg, error, actionLabel, action);
        else Notifier?.Show(error ? "FreeEDR: not done" : "FreeEDR", msg, "page|home", []);
    }

    private async Task<bool> Send(IEnumerable<JsonObject?> ops, string title, string question, string yes, bool danger = false)
    {
        var list = ops.Where(o => o is not null).ToList();
        if (list.Count == 0) { await Dialogs.Info(title, "There is nothing to change for this item."); return false; }
        if (!await Dialogs.Confirm(title, question, yes, danger: danger, note: "Windows asks for administrator approval.")) return false;
        var r = await Commands.Ops(list);
        Say(Commands.Explain(r), r != CommandResult.Done);
        if (r is CommandResult.Done or CommandResult.Incomplete or CommandResult.Unconfirmed) { await Task.Delay(1500); Refresh(); }
        return r == CommandResult.Done;
    }

    public static List<Rec> EventsOf(IEnumerable<Row> rows) =>
        rows.SelectMany(r => r.Group.Count > 0 ? r.Group : r.Ev is { } e && e.T("id") ? [e] : []).ToList();

    public static string NameOf(Row r)
    {
        switch (r.Kind)
        {
            case "excl" or "builtin": return r.Note;
            case "block": return r.Entry!.T("image") ? r.Entry.S("image") : r.Entry.T("ip") ? r.Entry.S("ip") : r.Entry.S("title");
            case "cve": return $"{r.Entry!.S("cve")} in {r.Entry.S("package")} {r.Entry.S("version")}";
            case "hist": return r.Entry!.T("cve") ? $"{r.Entry.S("cve")} in {r.Entry.S("package")}" : r.Entry.S("name");
            case "hidden": return r.EntryId ?? "";
            case "app": return r.Entry!.S("process");
        }
        var e = r.Ev;
        if (e is null) return "";
        if (e.T("ip")) return e.S("ip");
        if (e.T("process") && !Ps.Eq(e.S("blade"), "sigma")) return $"{e.S("process")}  ({e.S("title")})";
        return e.S("title");
    }

    public List<TrayAction> ActionsFor(IReadOnlyList<Row> rows) => ActionBuilder.For(rows, State.Signers.SignerOf,
        e => Profiles.FindFor(e, State.IsProfileOn, State.Signers), State.ParentAllowed,
        r => r.Entry is { } v && ActionBuilder.OwnsCve(v, State.CurrentSid, UserProfile), State.IsReviewed);

    public async Task Run(TrayAction a, IReadOnlyList<Row> rows)
    {
        if (rows.Count == 0 && a.Kind is not (ActionKind.UpdateTool or ActionKind.OpenUrl)) return;
        var same = rows.Where(x => x.Kind == rows[0].Kind).ToList();
        var sec = rows.Count > 0 ? rows[0].Sec : "";
        var names = Dialogs.Names(same.Select(NameOf));
        switch (a.Kind)
        {
            case ActionKind.ItWasMe:
            case ActionKind.MarkReviewed:
            {
                var evs = EventsOf(same);
                foreach (var e in evs) Insights.CountReview(e);
                State.SetReviewed(evs, true);
                Say(a.Kind == ActionKind.ItWasMe ? "Thanks - marked as yours. Future ones are still reported." : "Marked reviewed.", false, "Undo", () =>
                {
                    foreach (var e in evs) Insights.UncountReview(e);
                    State.SetReviewed(evs, false);
                    Say("Undone - it is back in the list.");
                    Refresh();
                });
                Refresh();
                break;
            }
            case ActionKind.MarkUnreviewed:
                State.SetReviewed(EventsOf(same), false);
                Refresh();
                break;
            case ActionKind.Flag:
            case ActionKind.BanIp:
                await Flag(same, sec, names);
                break;
            case ActionKind.Allow: await Allow(same, sec, "default", names); break;
            case ActionKind.AllowRule: await Allow(same, sec, "rule", names); break;
            case ActionKind.AllowParent: await Allow(same, sec, "parent", names); break;
            case ActionKind.AllowSigner: await Allow(same, sec, "signer", names); break;
            case ActionKind.AllowSubnet: await Allow(same, sec, "net", names); break;
            case ActionKind.AllowInDefender: await Allow(same, sec, "default", names); break;
            case ActionKind.IgnoreCve: await Allow(same, sec, "default", names); break;
            case ActionKind.MoveToAllowed: await Allow(same, sec, "default", names); break;
            case ActionKind.AllowParentEverywhere:
            {
                var par = a.Arg!;
                await Send(ActionBuilder.ParentEverywhereOps(par, State.Signers.SignerOf), "Allow everything it starts",
                    $"Allow everything started by {Ps.Leaf(par)}, in real-time detection and the event-log scan?\n\n{PatternRules.VersionlessPattern(par)}\n(* = any version, so it keeps working after updates)\n\nMalware hashes, YARA and Microsoft Defender still check what it starts.", "Allow all");
                break;
            }
            case ActionKind.TrustApp: await SetProfiles(new() { [a.Arg!] = true }); break;
            case ActionKind.BackToDetected: await Back(same, sec, names); break;
            case ActionKind.RemoveAllow: await Back(same, sec, names); break;
            case ActionKind.OpenWindowsSecurity:
                try { Process.Start(new ProcessStartInfo("windowsdefender://threat") { UseShellExecute = true }); }
                catch (System.ComponentModel.Win32Exception) { Say("Windows Security could not be opened. Open it from the Start menu: Windows Security > Virus & threat protection.", true); }
                break;
            case ActionKind.UpdateCve:
            case ActionKind.UpdateAgain when sec == "cve":
                await UpdateCve(same);
                break;
            case ActionKind.UpdateAgain:
            case ActionKind.UpdateApp:
                await UpdateApps(same);
                break;
            case ActionKind.UpdateAllApps: await UpdateApps(State.Model?.Sec["apps"].Rows[0] ?? []); break;
            case ActionKind.HideApp:
                foreach (var r in same)
                {
                    var id = r.Kind == "hist" ? r.Entry!.S("key") : r.Entry!.S("appId");
                    if (r.Kind == "hist") State.RemoveHistory(r.Entry!.S("id"));
                    State.SetAppHidden(id, true);
                }
                Refresh();
                break;
            case ActionKind.ShowApp:
                foreach (var r in same.Where(r => r.EntryId is not null)) State.SetAppHidden(r.EntryId!, false);
                Refresh();
                break;
            case ActionKind.ReadAdvisory: case ActionKind.OpenUrl:
                if (!Shell.OpenUrl(a.Arg ?? "")) Say("The web page could not be opened (no browser, or not an https:// address).", true);
                break;
            case ActionKind.UpdateTool: await UpdateTool(a.Arg ?? ""); break;
            case ActionKind.ScanWithDefender:
                if (Shell.DefenderScan(a.Arg!)) Say("Microsoft Defender is scanning the file in a new window. If it finds something, Defender removes it.");
                else Say("Microsoft Defender's scanner (MpCmdRun.exe) was not found.", true);
                break;
            case ActionKind.VirusTotal:
                if (!Shell.VirusTotal(a.Arg!, rows[0].Ev?.S("sha256")))
                    Say("VirusTotal cannot be opened: the file no longer exists and the alert has no SHA256 fingerprint.", true);
                break;
            case ActionKind.OpenLocation:
                if (!Shell.ShowInExplorer(a.Arg!)) Say($"The file no longer exists: {a.Arg}", true);
                break;
            case ActionKind.CopyDetails: await CopyDetails(rows[0]); break;
            case ActionKind.ExplainForDummies: await ExplainForDummies(rows[0]); break;
        }
    }

    private async Task Flag(List<Row> rows, string sec, string names)
    {
        var ops = new List<JsonObject?>();
        foreach (var r in rows)
        {
            if (r.Kind == "ban" && r.Entry is not null) continue;
            ops.Add(ActionBuilder.FlagOp(r.Ev));
        }
        var blocks = State.Config.Wail2Ban.Block;
        var q = sec switch
        {
            "sigma" => $"Confirm as a threat:\n{names}\n\nThe finding moves to Confirmed. Event-log findings describe the past, so there is nothing to stop.",
            "wail2ban" => blocks ? $"Ban permanently:\n{names}\n\nWail2Ban blocks all inbound traffic from it in Windows Firewall until you unban it."
                                 : $"Ban:\n{names}\n\nWail2Ban is set to report only, so it is recorded but not blocked.",
            _ => $"Flag as a threat:\n{names}\n\nIt moves to Flagged. FreeEDR only detects: the program is not stopped or moved. Use \"Scan with Microsoft Defender\" to have it removed.",
        };
        var verb = sec == "wail2ban" ? "Ban IP" : sec == "sigma" ? "Confirm as threat" : "Flag as threat";
        if (await Send(ops, verb, q, verb, danger: sec == "wail2ban"))
            State.SetReviewed(EventsOf(rows), true);
    }

    private async Task Allow(List<Row> rows, string sec, string variant, string names)
    {
        if (sec == "apps") return;
        var ops = new List<JsonObject?>();
        var hist = new List<Rec>();
        foreach (var r in rows)
        {
            JsonObject? op = null;
            switch (r.Kind)
            {
                case "block":
                    ops.Add(new() { ["action"] = "unblock", ["id"] = r.Entry!.S("id") });
                    op = ActionBuilder.AllowOpFromBlock(r.Entry);
                    break;
                case "ban" or "banhist":
                {
                    if (r.Entry is not null) ops.Add(new() { ["action"] = "unblock", ["id"] = r.Entry.S("id") });
                    var ip = r.Ban?.S("ip") is { Length: > 0 } b ? b : r.Entry?.S("ip") is { Length: > 0 } en ? en : r.Ev?.S("ip") ?? "";
                    if (ip.Length > 0) ops.Add(new() { ["action"] = "unban", ["ip"] = ip });
                    op = ActionBuilder.AllowOp(r.Ev, variant, State.Signers.SignerOf);
                    break;
                }
                case "cve": op = new() { ["action"] = "exclude", ["blade"] = "cve", ["cve"] = r.Entry!.S("id"), ["package"] = r.Entry.S("package") }; break;
                case "hist": op = new() { ["action"] = "exclude", ["blade"] = "cve", ["cve"] = r.Entry!.S("key"), ["package"] = r.Entry.S("package") }; hist.Add(r.Entry); break;
                default: op = ActionBuilder.AllowOp(r.Ev, variant, State.Signers.SignerOf); break;
            }
            if (op is not null) ops.Add(op);
        }
        if (!ops.Any(o => o?.Str("action") == "exclude")) { await Dialogs.Info("Allow", "This item cannot be allowed from here (for a Defender detection without a threat ID, use Windows Security)."); return; }
        var signer = rows[0].Ev is { } ev ? State.Signers.SignerOf(ev.S("process")) : null;
        var q = sec switch
        {
            "malware" => $"Allow:\n{names}\n\nIt is no longer reported. Defender allows are applied in Microsoft Defender.",
            "edr" => $"Allow:\n{names}\n\n" + variant switch
            {
                "rule" => "Only this rule is ignored for the program.",
                "parent" => "Everything started by this program (any version) is ignored.",
                "signer" => $"Every program signed by {signer} is ignored by real-time detection (checked against the digital signature, so it survives updates).",
                _ => "All real-time alerts for the program are ignored.",
            },
            "sigma" => variant == "parent" ? $"Ignore every event-log rule for programs started by:\n{names}" : $"Ignore this event-log rule:\n{names}\n\nIts findings are no longer reported.",
            "cve" => $"Ignore:\n{names}\n\nIt is no longer listed as needing an update.",
            "wail2ban" => $"Trust:\n{names}\n\nWail2Ban never blocks it; any current ban is removed.",
            _ => $"Allow:\n{names}",
        };
        var yes = sec switch { "wail2ban" => "Trust", "cve" => "Ignore", _ => "Allow" };
        if (await Send(ops, yes, q, yes)) foreach (var h in hist) State.RemoveHistory(h.S("id"));
    }

    private async Task Back(List<Row> rows, string sec, string names)
    {
        var info = Catalog.Section(sec is "overview" or "" ? "edr" : sec);
        var ops = new List<JsonObject?>();
        var local = new List<Row>();
        foreach (var r in rows)
        {
            switch (r.Kind)
            {
                case "block": ops.Add(new() { ["action"] = "unblock", ["id"] = r.Entry!.S("id") }); break;
                case "ban" or "banhist":
                {
                    var ip = r.Ban?.S("ip") is { Length: > 0 } b ? b : r.Entry?.S("ip") is { Length: > 0 } en ? en : r.Ev?.S("ip") ?? "";
                    if (r.Entry is not null) ops.Add(new() { ["action"] = "unblock", ["id"] = r.Entry.S("id") });
                    if (ip.Length > 0)
                    {
                        ops.Add(new() { ["action"] = "unban", ["ip"] = ip });
                        foreach (var x in State.Inputs.Exclusions["wail2ban"].Where(x => x.S("cidr") == ip)) ops.Add(new() { ["action"] = "unexclude", ["id"] = x.S("id") });
                    }
                    break;
                }
                case "excl":
                    ops.Add(new() { ["action"] = "unexclude", ["id"] = r.Entry!.S("id") });
                    break;
                case "hist" or "hidden": local.Add(r); break;
            }
        }
        if (ops.Count > 0)
        {
            var what = rows[0].Kind == "excl" ? "Remove the allow" : sec == "wail2ban" ? "Unban and watch again" : $"Move back to {info.Subs[0]}";
            var yes = rows[0].Kind == "excl" ? "Remove allow" : sec == "wail2ban" ? "Unban" : "Move back";
            if (!await Send(ops, what, $"{what}:\n{names}\n\nIt is detected and reported again.", yes)) return;
        }
        foreach (var r in local) { if (r.Kind == "hist") State.RemoveHistory(r.Entry!.S("id")); else if (r.EntryId is not null) State.SetAppHidden(r.EntryId, false); }
        State.SetReviewed(EventsOf(rows), false);
        Refresh();
    }

    public async Task<bool> SetProfiles(Dictionary<string, bool> want)
    {
        var ops = new List<JsonObject?>();
        var on = new List<string>();
        var off = new List<string>();
        foreach (var (id, enable) in want)
        {
            if (Profiles.Get(id) is not { } p) continue;
            var isOn = State.IsProfileOn(id);
            if (enable && !isOn) { ops.AddRange(Profiles.Ops(p)); on.Add(p.Name); }
            else if (!enable && isOn)
            {
                foreach (var l in new[] { "realtime", "sigma" })
                    foreach (var x in State.Inputs.Exclusions[l].Where(x => x.S("profile") == id)) ops.Add(new() { ["action"] = "unexclude", ["id"] = x.S("id") });
                off.Add(p.Name);
            }
        }
        if (ops.Count == 0) return true;
        var q = new StringBuilder();
        if (on.Count > 0) q.Append($"Trust (no more alerts from their normal work):\n{Dialogs.Names(on)}\n\n");
        if (off.Count > 0) q.Append($"Stop trusting (alerts are shown again):\n{Dialogs.Names(off)}\n\n");
        q.Append("You can change this again at any time under Allowed & trusted.");
        return await Send(ops, "Trusted apps", q.ToString(), on.Count > 0 && off.Count > 0 ? "Apply changes" : on.Count > 0 ? "Trust" : "Stop trusting");
    }

    private async Task UpdateCve(List<Row> rows)
    {
        var cmds = ActionBuilder.CveCommands(rows.Where(r => r.Entry is not null).Select(r => r.Entry!), State.CurrentSid, UserProfile);
        if (cmds.Count == 0) return;
        var pip = rows.Any(r => r.Entry is { } v && v.T("fixPackage") && !Ps.Eq(v.S("fixPackage"), v.S("package"))) ? "\n\nSome libraries are bundled inside pip, so pip itself is updated." : "";
        if (!await Dialogs.Confirm("Install the fixed versions", $"{string.Join("\n", cmds.Select(c => c.Display))}{pip}\n\nA window opens and runs this. The list refreshes after the next scan.", "Update now")) return;
        foreach (var c in cmds) Shell.Run(c.FilePath, c.Arguments);
        foreach (var r in rows) { if (r.Kind == "cve") State.AddHistory("cve", r.Entry!.S("id"), r.Entry); else if (r.Kind == "hist") State.AddHistory("cve", r.Entry!.S("key"), r.Entry); }
        Refresh();
    }

    private async Task UpdateApps(IEnumerable<Row> rows)
    {
        var list = rows.ToList();
        var ids = list.Select(r => r.Kind == "hidden" ? r.EntryId ?? "" : r.Kind == "hist" ? r.Entry!.S("key") : r.Entry?.S("appId") ?? "")
                      .Where(ActionBuilder.IsValidWingetId).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (ids.Count == 0) { Say("There is no app with a winget ID to update.", true); return; }
        if (!await Dialogs.Confirm(ids.Count == 1 ? "Update app" : $"Update {ids.Count} apps",
                $"Update with winget:\n{Dialogs.Names(list.Select(NameOf).Where(n => n.Length > 0).DefaultIfEmpty(string.Join(", ", ids)))}\n\n" +
                $"{(ids.Count == 1 ? "A winget window opens" : $"{ids.Count} winget windows open, one per app")}. Some installers ask for administrator approval or close the app while it updates. " +
                "The list is checked again 10 minutes later; an update that failed comes back.", "Update now")) return;
        var started = ids.Count(id => Shell.Run("winget.exe", ["upgrade", "--id", id, "-e", "--accept-source-agreements", "--accept-package-agreements"]));
        if (started == 0) { Say("winget could not be started (is App Installer installed?). Nothing was updated.", true); return; }
        foreach (var r in list)
        {
            if (r.Kind == "hidden" && r.EntryId is not null) State.SetAppHidden(r.EntryId, false);
            else if (r.Kind == "app") State.AddHistory("apps", r.Entry!.S("appId"), r.Entry);
            else if (r.Kind == "hist") State.AddHistory("apps", r.Entry!.S("key"), r.Entry);
        }
        Winget.CheckSoon(TimeSpan.FromMinutes(10));
        Say(started == 1 ? "Update started in a winget window. It is listed under Updates > Started here." : $"{started} updates started in winget windows. They are listed under Updates > Started here.");
        Refresh();
    }

    public async Task InstallUpdate()
    {
        if (Updater.Info is not { } info || Updater.Busy) return;
        var notes = info.Notes.Length > 0 ? info.Notes : "The release page lists the changes.";
        var ready = Updater.Phase == UpdatePhase.Ready;
        if (!await Dialogs.Confirm($"Install FreeEDR {info.Latest}",
                $"What's new:\n{notes}\n\n" +
                (ready ? "The update is downloaded and checked. " : $"Download: {AppRelease.Describe(info.Size)} from FreeEDR's GitHub releases. It is installed only if it matches the SHA256 fingerprint GitHub publishes and is signed like your FreeEDR. ") +
                "Setup keeps all your settings, allow lists and history. Detection pauses for about a minute while the programs are replaced; if the new version does not pass its checks, the previous one comes back by itself. Nothing restarts the PC.",
                ready ? "Install now" : "Download and install", "Later", note: "Windows asks for administrator approval when Setup starts.")) return;
        await Updater.DownloadAndInstall();
    }

    public async Task ShowWhatsNew(AppUpdateInfo? info = null)
    {
        if (info is not null)
        {
            if (await Dialogs.Choose(Changelog.IsCombined(info.Notes) ? $"What's new since your version (up to {info.Latest})" : $"What's new in FreeEDR {info.Latest}", info.Notes.Length > 0 ? info.Notes : "This release has no notes.", ["Install", "Close"]) == 0) await InstallUpdate();
            return;
        }
        var notes = Updater.InstalledNotes();
        await Dialogs.Info($"What's new in FreeEDR {Updater.Installed}", string.IsNullOrWhiteSpace(notes) ? "This version has no release notes (a developer build, or an older release)." : notes);
    }

    public async Task UpdateTool(string name)
    {
        if (Tools.Spec(name) is not { } spec) return;
        if (!spec.Updatable) { await Dialogs.Info($"Update {name}", $"{name}'s releases are not digitally signed by their publisher, so FreeEDR does not install them from GitHub. A checked version comes with the next FreeEDR update."); return; }
        if (!await Dialogs.Confirm($"Update {name}", $"Download the latest {name} release from GitHub. It is installed only if it is digitally signed by {spec.Publisher} and matches the SHA256 fingerprint GitHub publishes; the current version is kept if the new one does not start.", "Update", note: "Windows asks for administrator approval.")) return;
        Say($"Updating {name}... this can take a minute.");
        var r = await Commands.Admin(new() { ["action"] = "update-tool", ["name"] = name });
        Say(r == CommandResult.Done ? $"{name} updated." : r == CommandResult.Failed ? $"{name} was not updated - the reason is in Activity > Messages." : Commands.Explain(r), r != CommandResult.Done);
        Refresh();
    }

    private async Task CopyDetails(Row r)
    {
        var o = r.Ev is not null && r.Kind is not ("block" or "excl" or "cve" or "hist") ? r.Ev.Obj : r.Entry?.Obj ?? r.Ev?.Obj;
        if (o is null) return;
        var text = string.Join("\r\n", o.Where(kv => Ps.Truthy(kv.Value) && !kv.Key.StartsWith('_')).Select(kv => $"{kv.Key}: {Ps.Str(kv.Value)}"));
        try
        {
            if (Clipboard?.Invoke() is { } cb) { await cb.SetTextAsync(text); Say("Details copied."); }
        }
        catch (Exception) { Say("Could not copy to the clipboard (another program holds it). Try again.", true); }
    }

    public async Task ExplainForDummies(Row r)
    {
        var e = r.Ev ?? r.Entry;
        if (e is null) return;
        var related = State.Inputs.Events
            .Where(x => x != e && (x.S("process") == e.S("process") || x.S("blade") == e.S("blade")))
            .Take(10)
            .ToList();
        var prompt = ExplainPrompt.Build(e, DateTimeOffset.Now, related);
        var copied = false;
        try
        {
            if (Clipboard?.Invoke() is { } cb)
            {
                await cb.SetTextAsync(prompt);
                copied = true;
            }
        }
        catch (Exception) { }

        Shell.OpenUrl("https://gemini.google.com/app");
        Say(copied
            ? "Prompt copied to clipboard! Opening Gemini in your browser - paste it in."
            : "Opening Gemini in your browser. Could not copy prompt to clipboard.", !copied);
    }

    public async Task Pause(string blade, int minutes)
    {
        var name = Catalog.PauseNames.GetValueOrDefault(blade, blade);
        var how = minutes > 0 ? $"for {(minutes >= 60 ? Ui.Plural(minutes / 60, "hour") : $"{minutes} minutes")}" : "until you resume it";
        if (!await Dialogs.Confirm($"Pause {name}", $"Pause {name} {how}?\n\n{Catalog.PauseScope.GetValueOrDefault(blade)}\n\nMicrosoft Defender keeps protecting you either way.", "Pause", note: "Windows asks for administrator approval. The pause is recorded in the audit log.")) return;
        var r = await Commands.Admin(new() { ["action"] = "pause", ["blade"] = blade, ["minutes"] = minutes });
        Say(r == CommandResult.Done ? $"{name} paused {how}." : Commands.Explain(r), r != CommandResult.Done);
        await Task.Delay(1200);
        Refresh();
    }

    public async Task Resume(string blade)
    {
        var st = State.Status;
        if (blade is "realtime" or "malware" or "sigma" or "cve" && State.PauseState("edr") == "paused" && st?.Child(blade)?.S("pausedUntil") is { } own &&
            (own.Length == 0 || own == st.Child("edr")?.S("pausedUntil")))
        {
            if (!await Dialogs.Confirm("Resume all detection", $"{Catalog.PauseNames[blade]} is paused by the master switch (all detection).\n\nResume all detection now?", "Resume all")) return;
            blade = "edr";
        }
        var r = await Commands.User(new() { ["action"] = "resume", ["blade"] = blade });
        Say(r == CommandResult.Done ? $"{Catalog.PauseNames.GetValueOrDefault(blade, blade)} is active again within a few seconds." : UserReply(r), r != CommandResult.Done);
        await Task.Delay(2500);
        Refresh();
    }

    public async Task ScanNow()
    {
        if (State.Status?.Child("scan")?.T("running") == true) { Say("A scan is already running. You will be told when it finishes."); return; }
        if (State.PauseState("edr") == "paused") { Say("Detection is paused - resume it first.", true); return; }
        var r = await Commands.User(new() { ["action"] = "scan-now" });
        Say(r == CommandResult.Done
                ? Commands.LastMessage.Length > 0 ? Commands.LastMessage : "Scan started: malware hashes, event logs and the vulnerability check run in the background."
                : UserReply(r), r != CommandResult.Done);
    }

    private string UserReply(CommandResult r) =>
        r is CommandResult.Incomplete or CommandResult.Refused && Commands.LastMessage.Length > 0 ? $"Not done: {Commands.LastMessage}" : Commands.Explain(r);

    public async Task RestartEngine()
    {
        if (!await Dialogs.Confirm("Restart the engine", "Restart the FreeEDR engine service? Detection pauses for a few seconds.", "Restart", note: "Windows asks for administrator approval.")) return;
        var r = await Commands.Admin(new() { ["action"] = "restart-engine" });
        Say(r == CommandResult.Done ? "Engine restarted." : Commands.Explain(r), r != CommandResult.Done);
    }

    public async Task<bool> SaveSettings(JsonObject config)
    {
        if (config.Count == 0) return true;
        var r = await Commands.Admin(new() { ["action"] = "set-config", ["config"] = config, ["restart"] = false });
        var defender = config.ContainsKey("defenderMode") ? " Microsoft Defender was changed right away." : "";
        Say(r == CommandResult.Done ? $"Settings saved. The engine uses them within a few seconds.{defender}" : Commands.Explain(r), r != CommandResult.Done);
        if (r == CommandResult.Done) { await Task.Delay(800); Refresh(); }
        return r == CommandResult.Done;
    }

    public async Task FactoryReset()
    {
        if (!await Dialogs.Confirm("Reset FreeEDR", "Put FreeEDR's PC settings back to the defaults?\n\nThis removes all your allows (also the Microsoft Defender allows added from FreeEDR), verdicts and Wail2Ban bans, clears the alert history and the reviewed marks of every account, and turns the recommended trusted apps back on.\n\nKept as they are: the Microsoft Defender choice (Audit or Off), each account's \"Just for you\" choices, the logs, scan results and the event-log archive.", "Reset everything", danger: true, note: "Windows asks for administrator approval. This cannot be undone.")) return;
        var r = await Commands.Admin(new() { ["action"] = "restore-defaults" });
        Say(r == CommandResult.Done ? "FreeEDR was reset to its defaults." : r == CommandResult.Failed
            ? "The reset did not finish (the engine was started again). The engine log has the details (Settings > Open logs); try the reset again." : Commands.Explain(r), r != CommandResult.Done);
        Refresh();
    }

    public void TestDetection()
    {
        var cmd = Path.Combine(EdrPaths.System32, "cmd.exe");
        Shell.Run(cmd, ["/c", "start", "", "/min", "powershell.exe", "-NoProfile", "-Command", "Invoke-Expression 'Write-Output EDR-test-detection'"]);
        Say("A harmless test alert was triggered. It appears in Activity within a few seconds.");
    }

    public const string ForensicsUrl = "https://127.0.0.1:8889/";

    public async Task OpenForensics()
    {
        var v = State.Paths.VelociraptorExe;
        if (!File.Exists(v)) { Say("Velociraptor is not installed.", true); return; }
        var running = await Task.Run(() => Edr.Core.Native.Win32.ProcessSnapshot().Values.Any(p => Ps.Eq(p.Path, v)));
        if (running)
        {
            Shell.OpenUrl(ForensicsUrl);
            Say("Velociraptor is already running: its page was opened again. Close the Velociraptor window to stop it.");
            return;
        }
        if (Shell.Elevated(v, ["gui", "--datastore", Path.Combine(State.Paths.DataDir, "velociraptor")], minimized: true))
            Say("Velociraptor is starting and opens its page in your browser. It keeps running in a minimized window: close that window to stop it.");
        else Say("Velociraptor was not started: Windows administrator approval was not given.", true);
    }

    public static async Task<(bool Ok, string Text)> TestFeed(string url)
    {
        if (EdrConfig.FeedProblem(url) is { Length: > 0 } bad) return (false, bad);
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            using var resp = await Tools.Http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cts.Token);
            if (!resp.IsSuccessStatusCode) return (false, $"The address answered HTTP {(int)resp.StatusCode}.");
            await using var stream = await resp.Content.ReadAsStreamAsync(cts.Token);
            using var reader = new StreamReader(stream);
            var rx = Ps.Rx(@"^\s*[0-9a-fA-F]{64}\s*(;|$)");
            long read = 0;
            var count = 0;
            while (await reader.ReadLineAsync(cts.Token) is { } line)
            {
                read += line.Length + 1;
                if (read > 64L * 1024 * 1024) break;
                if (rx.IsMatch(line.TrimEnd('\r'))) count++;
            }
            return count >= 100 ? (true, $"Works: {count:N0} malware hashes.") : (false, $"Only {count} SHA256 hash lines found - FreeEDR needs at least 100 (signature-base format: one hash per line).");
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException) { return (false, $"Could not download it: {e.Message}"); }
    }

    public Task<JsonObject> CreateBackup() => Task.Run(() => SettingsBackup.Create(EdrConfig.Load(State.Paths.ConfigFile), JsonFile.ReadObject(State.Paths.ExclusionsFile)));

    public async Task ImportBackup(JsonObject? backup)
    {
        var paths = State.Paths;
        var plan = await Task.Run(() => SettingsBackup.PlanImport(backup, EdrConfig.Load(paths.ConfigFile), JsonFile.ReadObject(paths.ExclusionsFile)));
        if (plan.Problem.Length > 0) { await Dialogs.Info("Import settings", plan.Problem, true); return; }
        var notes = new List<string>();
        if (plan.AlreadyThere > 0) notes.Add($"{plan.AlreadyThere} allows are already here.");
        if (plan.Refused > 0) notes.Add($"{plan.Refused} allows in the file are too broad for FreeEDR's rules and are skipped.");
        var quiet = SettingsBackup.QuietOf(backup) is { } q && !q.SequenceEqual(QuietList, StringComparer.Ordinal) ? q : null;
        if (plan.Empty && quiet is null) { await Dialogs.Info("Import settings", "Nothing to change: this PC already has these settings and allows. " + string.Join(" ", notes)); return; }
        var batches = SettingsBackup.Batches(plan.Ops);
        var approvals = batches.Count + (plan.ConfigChanges.Count > 0 ? 1 : 0);
        var what = new List<string>();
        if (plan.ConfigChanges.Count > 0) what.Add($"{CountLeaves(plan.ConfigChanges)} PC settings");
        if (plan.Ops.Count > 0) what.Add($"{plan.Ops.Count} allows");
        if (quiet is not null) what.Add("your quiet-mode list");
        if (!await Dialogs.Confirm("Import settings", $"This backup changes {string.Join(" and ", what)}. {string.Join(" ", notes)}\n\nEach step shows exactly what it changes before you approve it.",
                                   "Import", note: approvals == 0 ? null : approvals == 1 ? "Windows asks for administrator approval." : $"Windows asks for administrator approval {approvals} times (at most {RequestSummary.MaxLines} changes each).")) return;
        if (quiet is not null) Prefs.QuietProcesses = quiet;
        if (plan.ConfigChanges.Count > 0 && !await SaveSettings(plan.ConfigChanges)) return;
        var done = 0;
        foreach (var b in batches)
        {
            var r = await Commands.Admin(b);
            if (r != CommandResult.Done) { Say($"Import stopped after {done} of {batches.Count} allow steps: {Commands.Explain(r)}", true); Refresh(); return; }
            done++;
        }
        Say($"Imported: {string.Join(" and ", what)}.");
        Refresh();
    }

    public IReadOnlyList<string> QuietList => Prefs.QuietProcesses ?? State.Config.QuietProcesses;

    private static int CountLeaves(JsonObject o) => o.Sum(kv => kv.Value is JsonObject inner ? CountLeaves(inner) : 1);

    public void OpenEngineLog()
    {
        if (!Shell.Notepad(State.Paths.EngineLog))
            Say(File.Exists(State.Paths.EngineLog) ? "Notepad could not be started." : "The engine log does not exist yet: the engine writes it once it has started.", true);
    }

    public void OpenScanLog()
    {
        if (!Shell.Notepad(State.Paths.ScanLog))
            Say(File.Exists(State.Paths.ScanLog) ? "Notepad could not be started." : "The scan log does not exist yet: it is written by the first scan (Home > Scan now).", true);
    }

    public void OpenUserGuide()
    {
        var guide = Path.Combine(State.Paths.DocsDir, "user", "USER_GUIDE.md");
        if (!Shell.OpenDocument(guide)) Say($"The user guide was not found: {guide}", true);
    }

    public string AuditCsv()
    {
        var sb = new StringBuilder("\"Time\",\"Severity\",\"Kind\",\"Title\",\"Detail\",\"User\"\r\n");
        static string Q(string s) => "\"" + s.Replace("\"", "\"\"") + "\"";
        foreach (var e in State.Inputs.Events.Where(e => Ps.Eq(e.S("blade"), "system") && e.S("kind") is "audit" or "verdict" or "tool-update"))
            sb.Append(string.Join(",", Q(e.S("time")), Q(e.S("severity")), Q(e.S("kind")), Q(e.S("title")), Q(e.S("detail")), Q(e.S("user")))).Append("\r\n");
        foreach (var b in State.Inputs.Blocks)
            sb.Append(string.Join(",", Q(b.S("added")), Q("High"), Q("verdict"), Q(b.T("image") ? b.S("image") : b.T("ip") ? b.S("ip") : b.S("title")), Q(b.S("note")), Q(""))).Append("\r\n");
        return sb.ToString();
    }

    public async Task Activated(string args, Action<string, string?> navigate)
    {
        var parts = args.Split('|', 2);
        var verb = parts[0];
        var arg = parts.Length > 1 ? parts[1] : "";
        var ev = State.Inputs.Events.LastOrDefault(e => e.S("id") == arg);
        switch (verb)
        {
            case "explain" when ev is not null:
                await ExplainForDummies(new Row { Kind = "event", Cols = [], Ev = ev });
                break;
            case "review" when ev is not null:
                Insights.CountReview(ev);
                State.SetReviewed([ev], true);
                Refresh();
                break;
            case "me" when ev is not null:
                State.SetReviewed([ev], true);
                Refresh();
                navigate("home", null);
                break;
            case "open":
                navigate(ev is not null && Ps.Eq(ev.S("blade"), "wail2ban") ? "network" : "activity", arg);
                break;
            case "page":
                navigate(arg, null);
                break;
            case "whatsnew":
                await ShowWhatsNew();
                return;
            case "update":
                navigate("settings", null);
                if (Updater.Info is { } info) await ShowWhatsNew(info);
                return;
        }
        await Task.CompletedTask;
    }
}
