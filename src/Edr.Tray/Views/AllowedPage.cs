using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Edr.Core;

namespace Edr.Tray.Views;

public sealed class AllowedPage : UserControl
{
    private readonly Controller _c;
    private readonly ListPage _list;
    private readonly Dictionary<string, bool> _want = [];

    public AllowedPage(Controller c)
    {
        _c = c;
        _list = new ListPage(c, "Allowed & trusted", "Apps you trust and everything you allowed. Removing an allow makes FreeEDR report it again.",
        [
            new("Trusted apps", () => [], "", TrustedApps),
            new("Your allows", () => Sections(2, "malware", "edr", "sigma"), "Nothing allowed yet. Use \"Allow\" on an alert to stop it from coming back."),
            new("Flagged", () => Sections(1, "malware", "edr", "sigma"), "Nothing flagged. \"Flag as threat\" keeps an alert on record as a confirmed threat."),
            new("Ignored updates", () => Sections(2, "cve").Concat(Sections(2, "apps")), "No ignored vulnerabilities or hidden apps."),
        ]);
        Content = _list;
    }

    private IEnumerable<Row> Sections(int list, params string[] keys) =>
        _c.State.Model is { } m ? keys.SelectMany(k => m.Sec[k].Rows[list]).OrderByDescending(r => r.Time, Ps.Order) : [];

    private Control TrustedApps()
    {
        foreach (var id in _want.Keys.ToList()) if (_want[id] == _c.State.IsProfileOn(id)) _want.Remove(id);
        var pendingNote = Ui.T(PendingText(), "", 12, Palette.Warn);
        var apply = Ui.Btn("Apply changes", "primary big", () => _ = Apply(), icon: "");
        ToolTip.SetShowOnDisabled(apply, true);
        void SyncApply()
        {
            apply.IsEnabled = _want.Count > 0;
            ToolTip.SetTip(apply, _want.Count > 0 ? $"Apply {Ui.Plural(_want.Count, "change")} (Windows asks for administrator approval)" : "Flip a switch first: nothing to apply");
        }
        SyncApply();
        var apps = new StackPanel { Spacing = 8 };
        foreach (var group in Profiles.All.GroupBy(p => p.Category))
        {
            apps.Children.Add(Ui.T(group.Key switch { "app" => "APPS", "dev" => "DEVELOPER TOOLS", _ => "SYSTEM" }, "label").Also(t => t.Margin = new Thickness(4, 10, 0, 2)));
            foreach (var p in group)
            {
                var on = _c.State.IsProfileOn(p.Id);
                var sw = new ToggleSwitch { IsChecked = _want.TryGetValue(p.Id, out var w) ? w : on, OnContent = "", OffContent = "", VerticalAlignment = VerticalAlignment.Center };
                Avalonia.Automation.AutomationProperties.SetName(sw, $"Trust {p.Name}");
                var id = p.Id;
                sw.IsCheckedChanged += (_, _) =>
                {
                    if ((sw.IsChecked == true) == _c.State.IsProfileOn(id)) _want.Remove(id); else _want[id] = sw.IsChecked == true;
                    pendingNote.Text = PendingText();
                    SyncApply();
                };
                var installed = Profiles.IsInstalled(p);
                var title = Ui.Row(8, Ui.T(p.Name, "h3"));
                if (!installed) title.Children.Add(Ui.Pill("Not found on this PC", Palette.Muted));
                if (!p.Default) title.Children.Add(Ui.Pill("Off by default", Palette.Warn));
                var d = new DockPanel();
                DockPanel.SetDock(sw, Dock.Right);
                d.Children.Add(sw);
                d.Children.Add(Ui.Stack(4, title, Ui.T(p.What, "muted")).Also(x => x.Margin = new Thickness(0, 0, 16, 0)));
                apps.Children.Add(Ui.Card(d, "tile"));
            }
        }
        var head = new DockPanel();
        DockPanel.SetDock(apply, Dock.Right);
        head.Children.Add(apply);
        head.Children.Add(Ui.Stack(4, Ui.T("Trusted apps run without alerts for their normal work", "h3"),
            Ui.T("Each one allows only what that app does (for AI coding assistants: only their PowerShell launcher, only when the parent is validly signed). Malware fingerprints, YARA and Defender keep checking.", "sub"),
            pendingNote).Also(x => x.Margin = new Thickness(0, 0, 16, 0)));
        return new ScrollViewer { Content = Ui.Stack(14, Ui.Card(head), apps).Also(s => { s.MaxWidth = 1000; s.HorizontalAlignment = HorizontalAlignment.Left; }) };
    }

    private string PendingText() => _want.Count == 0 ? "" : $"{Ui.Plural(_want.Count, "change")} not applied yet - click Apply changes.";

    private async Task Apply()
    {
        if (_want.Count == 0) { _c.Say("Nothing to apply: no switch was changed."); return; }
        if (await _c.SetProfiles(new Dictionary<string, bool>(_want))) _want.Clear();
        _list.Refresh();
    }

    public void Refresh() => _list.Refresh();
}

public static class ToolPanel
{
    public static Control Build(Controller c)
    {
        var res = c.State.Inputs.ScanResult;
        var tools = res?.Recs("tools") ?? [];
        var stack = Ui.Stack(12, Ui.Card(Ui.Stack(4, Ui.T("FreeEDR's detection tools", "h3"),
            Ui.T("Checked for new versions at every scan. A tool whose releases are digitally signed by its publisher can be updated here: FreeEDR installs a new release only when its signature and GitHub's SHA256 fingerprint both check out, and keeps the current version if the new one does not start. Unsigned tools are updated with FreeEDR itself.", "sub"))));
        foreach (var t in Tools.Pinned)
        {
            var info = tools.FirstOrDefault(x => Ps.Eq(x.S("name"), t.Name));
            var current = info?.S("current") is { Length: > 0 } cur ? cur : "?";
            var latest = info?.S("latest") ?? "";
            var outdated = info?.T("outdated") == true;
            var status = outdated ? Ui.Pill($"{latest} available", Palette.Warn) : latest.Length > 0 ? Ui.Pill("Up to date", Palette.Ok) : Ui.Pill("Not checked yet", Palette.Muted);
            var update = Ui.Btn(outdated ? $"Update to {latest}" : "Check & update", outdated ? "primary" : "", () => _ = c.UpdateTool(t.Name), icon: "");
            if (!t.Updatable)
            {
                update.IsEnabled = false;
                Avalonia.Controls.ToolTip.SetTip(update, "Not signed by its publisher: updated with the next FreeEDR release");
            }
            var page = Ui.Btn("Release notes", "ghost", () => Services.Shell.OpenUrl(info?.S("url") is { Length: > 0 } u ? u : $"https://github.com/{t.Repo}/releases"));
            var d = new DockPanel();
            var btns = Ui.Row(8, page, update);
            DockPanel.SetDock(btns, Dock.Right);
            d.Children.Add(btns);
            d.Children.Add(Ui.Stack(4, Ui.Row(10, Ui.T(t.Name, "h3"), status), Ui.T($"Installed: {current}   -   github.com/{t.Repo}", "muted")));
            stack.Children.Add(Ui.Card(d, "tile"));
        }
        var when = c.State.Status?.Child("scan")?.S("lastEnd");
        stack.Children.Add(Ui.T($"Last check: {ModelBuilder.FormatWhen(when, "ddd dd/MM HH:mm")}", "muted"));
        return new ScrollViewer { Content = stack.Also(s => { s.MaxWidth = 1000; s.HorizontalAlignment = HorizontalAlignment.Left; }) };
    }
}
