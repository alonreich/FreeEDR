using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using Edr.Core;

namespace Edr.Tray.Views;

public sealed class DetailView : Border
{
    private readonly Controller _c;
    private readonly ScrollViewer _scroll = new() { HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled };
    private IReadOnlyList<Row> _rows = [];
    private string _shownKey = "";
    private string _shownFp = "";
    private bool _techOpen;

    protected override Type StyleKeyOverride => typeof(Border);

    public DetailView(Controller c)
    {
        _c = c;
        Classes.Add("card");
        Padding = new Thickness(0);
        Child = _scroll;
        _scroll.Content = EmptyView();
        _shownKey = "";
    }

    private void ShowEmpty()
    {
        if (_shownKey == "") return;
        _shownKey = "";
        _shownFp = "";
        _scroll.Content = EmptyView();
    }

    private static StackPanel EmptyView() => new()
    {
        Margin = new Thickness(28), VerticalAlignment = VerticalAlignment.Center, HorizontalAlignment = HorizontalAlignment.Center, Spacing = 10,
        Children = { Ui.Icon("", 40, Palette.Line).Also(i => i.HorizontalAlignment = HorizontalAlignment.Center), Ui.T("Select an item to see what it means and what you can do.", "muted").Also(t => t.TextAlignment = TextAlignment.Center) },
    };

    public void Show(IReadOnlyList<Row> rows)
    {
        _rows = rows;
        if (rows.Count == 0) { ShowEmpty(); return; }
        var r = rows[0];
        var e = r.Ev;
        var item = new RowItem(r);
        var root = new StackPanel { Spacing = 12, Margin = new Thickness(16, 14) };

        var pills = new WrapPanel();
        var sev = item.Severity;
        if (r.Pinned && !r.Muted) pills.Children.Add(Ui.Pill("Was this you?", Palette.Warn).Also(p => p.Margin = new Thickness(0, 0, 6, 4)));
        if (sev.Length > 0) pills.Children.Add(Ui.Pill(sev, Palette.ForSeverity(sev)).Also(p => p.Margin = new Thickness(0, 0, 6, 4)));
        if (r.Muted && r.Kind is "event" or "fail") pills.Children.Add(Ui.Pill("Reviewed", Palette.Muted).Also(p => p.Margin = new Thickness(0, 0, 6, 4)));
        var header = Ui.Stack(4, pills, Ui.T(rows.Count > 1 ? $"{rows.Count} items selected" : item.Title, "h2"),
            Ui.T(rows.Count > 1 ? "Actions apply to every selected item." : Ui.When(item.Time) + (r.Group.Count > 1 ? $"  ·  seen {r.Group.Count} times" : ""), "muted"));
        if (e is not null)
        {
            var mod = Catalog.Module(e.S("blade"));
            var how = mod.Method + (e.T("rule") && e.S("rule") != e.S("title") ? $": {e.S("rule")}" : "");
            header.Children.Add(Ui.Row(8, Ui.T("Caught by", "muted"), Ui.ModuleTag(e.S("blade")), Ui.T(how, "muted")).Also(x => x.Margin = new Thickness(0, 2, 0, 0)));
        }
        root.Children.Add(header);

        if (rows.Count == 1 && e is not null && r.Kind == "event" && _c.Insights.ShouldSuggest(e))
        {
            var allow = Ui.Btn("Allow it from now on", "primary small", () => _ = _c.Run(new TrayAction(ActionKind.Allow, "Allow"), _rows));
            var dismiss = Ui.Btn("Keep showing it", "ghost small", () => { _c.Insights.Dismiss(e); Show(_rows); });
            root.Children.Add(new Border
            {
                Classes = { "banner" }, Background = Palette.Tint(Palette.Accent, 0x22), BorderBrush = Palette.Tint(Palette.Accent, 0x70),
                Child = Ui.Stack(10, Ui.Row(10, Ui.Icon("", 18, Palette.Accent), Ui.T($"You marked this reviewed {_c.Insights.ReviewCount(e)} times.", "h3")),
                    Ui.T("If it is normal on this PC, allow it so it stops coming back. FreeEDR still checks the program for malware.", "sub"), Ui.Row(8, allow, dismiss)),
            });
        }

        var acts = _c.ActionsFor(rows);
        var wrap = new WrapPanel();
        foreach (var a in acts.Where(a => a.Kind != ActionKind.CopyDetails))
        {
            var cls = a.Style.Length > 0 ? a.Style : a.Primary ? "primary" : "";
            var b = Ui.Btn(a.Label, cls + " small", () => _ = _c.Run(a, _rows), icon: IconFor(a.Kind));
            b.IsEnabled = a.Enabled && !_c.Commands.Busy;
            b.Margin = new Thickness(0, 0, 6, 6);
            wrap.Children.Add(b);
        }
        root.Children.Add(wrap);

        if (rows.Count == 1 && e is not null)
        {
            var (what, todo) = Hints.For(e);
            if (what.Length > 0) root.Children.Add(Section("", "What happened", Ui.T(what, "sub")));
            if (todo.Length > 0) root.Children.Add(Section("", "What to do", Ui.T(todo, "sub")));
        }

        var facts = Facts(r);
        var key = facts.Where(f => !f.Technical).ToList();
        var tech = facts.Where(f => f.Technical).ToList();
        if (key.Count > 0) root.Children.Add(Section("\uE946", "Details", FactGrid(key)));
        if (tech.Count > 0)
        {
            var exp = new Expander
            {
                Header = Ui.T("TECHNICAL DETAILS", "label"), IsExpanded = _techOpen, HorizontalAlignment = HorizontalAlignment.Stretch,
                Padding = new Thickness(10, 6), Content = FactGrid(tech),
            };
            exp.PropertyChanged += (_, ev) => { if (ev.Property == Expander.IsExpandedProperty) _techOpen = exp.IsExpanded; };
            root.Children.Add(exp);
        }
        root.Children.Add(Ui.Btn("Copy details", "ghost small", () => _ = _c.Run(new TrayAction(ActionKind.CopyDetails, ""), _rows), icon: "").Also(b => b.HorizontalAlignment = HorizontalAlignment.Left));
        var selKey = string.Join("\n", rows.Select(x => x.Key));
        var fp = Ui.Fingerprint(root);
        if (selKey == _shownKey && fp == _shownFp) return;
        var sameSelection = selKey == _shownKey;
        var offset = _scroll.Offset;
        _shownKey = selKey;
        _shownFp = fp;
        _scroll.Content = root;
        if (sameSelection) Dispatcher.UIThread.Post(() => _scroll.Offset = offset, DispatcherPriority.Background);
    }

    private static Control Section(string icon, string title, Control body) =>
        Ui.Stack(6, Ui.Row(6, Ui.Icon(icon, 12, Palette.Muted), Ui.T(title.ToUpperInvariant(), "label")), body);

    private static Grid FactGrid(List<(string Key, string Value, bool Technical)> facts)
    {
        var g = new Grid { ColumnDefinitions = new ColumnDefinitions("110,*") };
        var i = 0;
        foreach (var (k, v, _) in facts)
        {
            g.RowDefinitions.Add(new RowDefinition(GridLength.Auto));
            var kt = Ui.T(k, "label"); kt.Margin = new Thickness(0, 3, 8, 3);
            var vt = new SelectableTextBlock { Text = v, FontSize = 12, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 2, 0, 2), Foreground = Palette.Text };
            Grid.SetRow(kt, i); Grid.SetRow(vt, i); Grid.SetColumn(vt, 1);
            g.Children.Add(kt); g.Children.Add(vt);
            i++;
        }
        return g;
    }

    private static string? IconFor(ActionKind k) => k switch
    {
        ActionKind.ItWasMe => "", ActionKind.Flag => "", ActionKind.BanIp => "", ActionKind.Allow or ActionKind.AllowRule or ActionKind.AllowParent or ActionKind.AllowSigner or ActionKind.AllowSubnet or ActionKind.AllowParentEverywhere or ActionKind.MoveToAllowed => "",
        ActionKind.TrustApp => "", ActionKind.MarkReviewed => "", ActionKind.MarkUnreviewed => "", ActionKind.ScanWithDefender => "",
        ActionKind.VirusTotal => "", ActionKind.OpenLocation => "", ActionKind.UpdateCve or ActionKind.UpdateApp or ActionKind.UpdateAllApps or ActionKind.UpdateAgain or ActionKind.UpdateTool => "",
        ActionKind.ReadAdvisory or ActionKind.OpenUrl or ActionKind.OpenWindowsSecurity => "", ActionKind.RemoveAllow or ActionKind.BackToDetected => "",
        ActionKind.IgnoreCve or ActionKind.HideApp => "", ActionKind.ShowApp => "", ActionKind.AllowInDefender => "", _ => null,
    };

    private static List<(string Key, string Value, bool Technical)> Facts(Row r)
    {
        var l = new List<(string, string, bool)>();
        void Add(string k, string? v) { if (!string.IsNullOrWhiteSpace(v)) l.Add((k, v, false)); }
        void Tech(string k, string? v) { if (!string.IsNullOrWhiteSpace(v)) l.Add((k, v, true)); }
        var e = r.Ev;
        switch (r.Kind)
        {
            case "excl":
                Add("Allow", r.Note); Add("Type", ModelBuilder.ExclType(r.ExclList, r.Entry!)); Add("Added", r.Entry!.S("added"));
                Add("Matches", r.Group.Count > 0 ? $"{r.Group.Count} alert(s) hidden by it" : null);
                return l;
            case "block":
                Add("Verdict", r.Entry!.S("note")); Add("Program", r.Entry.S("image")); Add("Address", r.Entry.S("ip")); Add("Rule", r.Entry.S("title")); Add("Added", r.Entry.S("added"));
                return l;
            case "cve" or "hist":
            {
                var v = r.Entry!;
                Add("Vulnerability", v.S("cve")); Add("Package", $"{v.S("package")} {v.S("version")}"); Add("Fixed in", v.S("fixed")); Add("Severity", v.S("severity"));
                Add("Score", v.S("score")); Add("Summary", v.S("summary")); Add("Location", v.S("path")); Add("Python", v.S("python"));
                if (v.T("fixPackage") && !Ps.Eq(v.S("fixPackage"), v.S("package"))) Add("Fix by updating", v.S("fixPackage"));
                return l;
            }
            case "app": Add("App", r.Entry!.S("process")); Add("Installed", r.Entry.S("version")); Add("Available", r.Entry.S("latest")); Add("winget id", r.Entry.S("appId")); return l;
            case "ban" or "banhist":
                Add("Address", r.Cols.ElementAtOrDefault(1)); Add("Network", r.Cols.ElementAtOrDefault(4)); Add("Blocked until", r.Cols.ElementAtOrDefault(2));
                Add("Strikes", r.Cols.ElementAtOrDefault(3)); Add("How", r.Cols.ElementAtOrDefault(5));
                break;
        }
        if (e is null) return l;
        var sigma = Ps.Eq(e.S("blade"), "sigma");
        var prog = sigma ? SigmaProcess.Of(e).Image : e.S("process");
        Add("Program", prog.Length > 0 ? Ps.Leaf(prog) : null);
        Add("Started by", ActionBuilder.ParentOf(e) is { Length: > 0 } par ? Ps.Leaf(par) : null);
        Add("Address", e.S("ip"));
        if (e.T("ip")) Add("Network", Ip.NetLabel(e.S("ip")));
        Add("User", e.S("user"));
        Add("Threat", e.S("threat"));
        Tech("Program path", prog);
        Tech("Parent path", ActionBuilder.ParentOf(e));
        var anc = e.Strings("ancestors");
        if (anc.Count > 0) Tech("And above", string.Join("  ›  ", anc.Select(Ps.Leaf)));
        Tech(Ps.Eq(e.S("blade"), "realtime") ? "Command / detail" : "Detail", ModelBuilder.Short(e.S("detail"), 1200));
        Tech("SHA256", e.S("sha256"));
        Tech("Event time", e.S("eventTime"));
        Tech("Sigma rule ID", e.S("ruleId"));
        return l;
    }
}
