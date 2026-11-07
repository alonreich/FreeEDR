using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls.Primitives;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Edr.Core;

namespace Edr.Tray.Views;

/// <summary>
/// Home: one sentence about what matters now, "Was this you?" questions, one tile per protection part (with pause /
/// resume), the learning week, suggestions and the weekly summary.
/// </summary>
public sealed class HomePage : UserControl
{
    private readonly Controller _c;
    private readonly Action<string, string?> _navigate;
    private readonly StackPanel _root = new() { Spacing = 12, Margin = new Thickness(20, 16, 20, 20), MaxWidth = 1180 };
    private string _shown = "";

    public HomePage(Controller c, Action<string, string?> navigate)
    {
        _c = c;
        _navigate = navigate;
        Content = new ScrollViewer { Content = _root };
    }

    /// <summary>Rebuilds the page, but swaps it in only when something visible changed (the engine refreshes every
    /// 15 s): an unchanged page keeps keyboard focus, the scroll position and an open Pause menu.</summary>
    public void Refresh()
    {
        var items = new List<Control>();
        var s = _c.State;
        var m = s.Model;
        var ov = s.Overall;
        items.Add(Hero(ov));
        if (!s.EngineAlive)
        {
            // The dashboard cannot reach the engine: say what that means and offer the fix in one click
            var hb = s.Status?.S("heartbeat");
            var since = Ps.ToDate(hb) is { } t ? $"Its last sign of life was {Ui.When(hb!)}." : "It has not reported since this dashboard started.";
            var fix = Ui.Row(6, Ui.Btn("Restart engine", "primary small", () => _ = _c.RestartEngine()),
                                Ui.Btn("Open engine log", "small", _c.OpenEngineLog));
            items.Add(Banner("\uE7BA", Palette.Danger, "The FreeEDR engine is not responding",
                $"{since} Until it runs again nothing is detected and Wail2Ban does not block. Restart it (Windows asks for administrator approval); Windows also restarts it by itself after a failure.", fix));
        }
        if (_c.Notifier?.InLearningWeek == true && Ps.ToDate(s.Config.InstalledAt) is { } inst)
        {
            var left = Math.Max(1, 7 - (int)(DateTime.Now - inst).TotalDays);
            items.Add(Banner("", Palette.Info, $"Learning week - {Ui.Plural(left, "day")} left",
                "FreeEDR is learning what is normal on this PC. Until then it only notifies you about critical alerts. Everything is still detected and listed in Activity."));
        }
        if (m is not null)
        {
            // Same question asked several times (e.g. four "Event log cleared") = one card that answers all of them
            var groups = new[] { "malware", "edr", "sigma", "wail2ban" }.SelectMany(k => m.Sec[k].Rows[0]).Where(r => r.Pinned && !r.Muted && r.Ev is not null)
                .GroupBy(r => $"{r.Sec}|{r.Ev!.S("blade")}|{r.Ev.S("title")}").Select(g => g.ToList()).ToList();
            if (groups.Count > 0)
            {
                items.Add(Ui.T("Was this you?", "h2"));
                var list = new StackPanel { Spacing = 0 };
                for (var i = 0; i < Math.Min(groups.Count, 6); i++) list.Children.Add(Question(groups[i], first: i == 0));
                if (groups.Count > 6) list.Children.Add(Ui.Btn($"{groups.Count - 6} more in Activity", "link", () => _navigate("activity", null)).Also(b => b.Margin = new Thickness(14, 8)));
                items.Add(Ui.Card(list, "card").Also(c => c.Padding = new Thickness(0)));
            }
        }
        items.Add(Ui.T("Protection", "h2"));
        items.Add(Tiles());
        var suggestions = Suggestions();
        if (suggestions is not null) items.Add(suggestions);
        items.Add(Weekly());
        var fp = string.Join("\n", items.Select(Ui.Fingerprint));
        if (fp == _shown && _root.Children.Count > 0) return;
        _shown = fp;
        _root.Children.Clear();
        foreach (var i in items) _root.Children.Add(i);
    }

    private Control Hero(Overall ov)
    {
        var state = ShieldIcon.From(ov.Key);
        var color = Palette.ForState(ov.Key);
        var img = new Image { Source = ShieldIcon.Bitmap(state, 128), Width = 56, Height = 56, VerticalAlignment = VerticalAlignment.Center };
        var glow = new Border { Width = 72, Height = 72, CornerRadius = new CornerRadius(36), Background = Palette.Tint(color, 0x26), Child = img, VerticalAlignment = VerticalAlignment.Center };
        var scanning = _c.State.Status?.Child("scan")?.T("running") == true;
        var scan = Ui.Btn(scanning ? "Scanning..." : "Scan now", "primary", () => _ = _c.ScanNow(), icon: "");
        scan.IsEnabled = !scanning && _c.State.EngineAlive;
        var review = Ui.Btn("Review alerts", "", () => _navigate("activity", null), icon: "");
        review.IsVisible = (_c.State.Model?.Attention ?? 0) > 0;
        var buttons = Ui.Row(10, scan, review);
        if (ov.Key == "down" && !_c.State.EngineAlive) buttons.Children.Add(Ui.Btn("Restart engine", "danger", () => _ = _c.RestartEngine(), icon: ""));
        var mode = Ui.Row(8, Ui.Pill("Detect-only", Palette.Accent), Ui.Pill(_c.State.Config.Wail2Ban.Block ? "Wail2Ban blocks attackers" : "Wail2Ban reports only", _c.State.Config.Wail2Ban.Block ? Palette.Ok : Palette.Warn));
        var text = Ui.Stack(6, mode, Ui.T(ov.Text, "h1"), Ui.T(ov.Sub, "sub"), buttons);
        text.VerticalAlignment = VerticalAlignment.Center;
        var g = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*") };
        g.Children.Add(glow);
        text.Margin = new Thickness(18, 0, 0, 0);
        Grid.SetColumn(text, 1);
        g.Children.Add(text);
        return Ui.Card(g, "hero");
    }

    private static Control Banner(string icon, IBrush color, string title, string text, Control? action = null)
    {
        var body = Ui.Stack(4, Ui.T(title, "h3"), Ui.T(text, "sub"));
        var d = new DockPanel();
        var ic = Ui.Icon(icon, 22, color);
        ic.Margin = new Thickness(0, 2, 14, 0); ic.VerticalAlignment = VerticalAlignment.Top;
        DockPanel.SetDock(ic, Dock.Left);
        d.Children.Add(ic);
        if (action is not null) { DockPanel.SetDock(action, Dock.Right); action.VerticalAlignment = VerticalAlignment.Center; d.Children.Add(action); }
        d.Children.Add(body);
        return new Border { Classes = { "banner" }, Background = Palette.Tint(color, 0x1E), BorderBrush = Palette.Tint(color, 0x60), Child = d };
    }

    private Control Question(List<Row> rows, bool first)
    {
        var r = rows[0];
        var e = r.Ev!;
        var times = rows.Sum(x => Math.Max(1, x.Group.Count));
        // The same answer labels as the details pane and the notification (ActionBuilder): "Yes, it was me" / "No, it wasn't me"
        var me = Ui.Btn("Yes, it was me", "ok small", () => _ = _c.Run(new TrayAction(ActionKind.ItWasMe, ""), rows));
        var notMe = Ui.Btn(r.Sec == "wail2ban" ? "No - ban this IP" : "No, it wasn't me", "danger small", () => _ = _c.Run(new TrayAction(ActionKind.Flag, ""), rows));
        var more = Ui.Btn("Details", "ghost small", () => _navigate(r.Sec == "wail2ban" ? "network" : "activity", e.S("id")));
        var what = Hints.For(e).What;
        var who = new RowItem(r).Subtitle;
        AutomationProperties.SetName(me, $"Yes, it was me: {e.S("title")}");
        AutomationProperties.SetName(notMe, $"{(r.Sec == "wail2ban" ? "No, ban this IP" : "No, it wasn't me")}: {e.S("title")}");
        AutomationProperties.SetName(more, $"Details: {e.S("title")}");
        var title = Ui.Row(8, Ui.ModuleTag(e.S("blade")), Ui.T(e.S("title") + (times > 1 ? $"  ×{times}" : ""), "h3"), Ui.T(Ui.When(e.S("time")), "muted"));
        var body = Ui.Stack(3, title, Ui.T(what.Length > 0 ? what : ModelBuilder.Short(e.S("detail"), 160), "muted"));
        if (who.Length > 0) body.Children.Add(Ui.T(who, "muted"));
        var line = new DockPanel { Margin = new Thickness(14, 10) };
        var btns = Ui.Row(6, me, notMe, more);
        btns.VerticalAlignment = VerticalAlignment.Center;
        DockPanel.SetDock(btns, Dock.Right);
        line.Children.Add(btns);
        body.Margin = new Thickness(0, 0, 12, 0);
        line.Children.Add(body);
        return new Border { BorderBrush = Palette.Line, BorderThickness = new Thickness(0, first ? 0 : 1, 0, 0), Child = line };
    }

    private Control Tiles()
    {
        var s = _c.State;
        var m = s.Model;
        var grid = new UniformGrid { Columns = 3 };
        void Add(Control c) { c.Margin = new Thickness(0, 0, 10, 10); grid.Children.Add(c); }
        Add(Tile("", "Real-time", "realtime", "activity:edr", m?.Sec["edr"], "Sysmon watches process starts, risky tools, credential theft and persistence."));
        Add(Tile("", "Anti-Malware", "malware", "activity:malware", m?.Sec["malware"], "Malware fingerprints, YARA rules and Microsoft Defender's findings."));
        Add(Tile("", "Event logs", "sigma", "activity:sigma", m?.Sec["sigma"], "Thousands of Sigma rules over the Windows event logs, twice a day."));
        Add(Tile("", "Wail2Ban", "wail2ban", "network", m?.Sec["wail2ban"], s.Config.Wail2Ban.Block ? "Blocks computers that keep failing to sign in." : "Reports password guessing (report-only)."));
        Add(Tile("", "Updates", "cve", "updates", m?.Sec["cve"], "Python vulnerabilities with a fix, and app updates."));
        Add(SensorTile());
        return grid;
    }

    private Control Tile(string icon, string name, string blade, string page, SectionModel? sec, string what)
    {
        var st = _c.State.PauseState(blade == "cve" ? "cve" : blade);
        var engine = _c.State.EngineAlive;
        var attention = sec?.Attention ?? 0;
        var open = sec?.Count ?? 0;
        IBrush color; string status;
        if (!engine || st == "error") { color = Palette.Danger; status = st == "error" ? "Not working" : "Engine stopped"; }
        else if (st == "paused") { color = Palette.Paused; status = "Paused " + Until(blade); }
        else if (attention > 0) { color = Palette.Danger; status = $"{open} to review"; }   // same number as the page's tab and badge
        else if (open > 0) { color = Palette.Warn; status = blade == "cve" ? $"{open} update{(open == 1 ? "" : "s")} waiting" : $"{open} to look at"; }
        else { color = Palette.Ok; status = "All clear"; }
        var action = st == "paused"
            ? Ui.Btn("Resume", "ok small", () => _ = _c.Resume(blade))
            : PauseButton(blade);
        action.IsEnabled = engine;
        AutomationProperties.SetName(action, $"{(st == "paused" ? "Resume" : "Pause")} {name}");
        var head = new DockPanel();
        var ic = new Border { Width = 30, Height = 30, CornerRadius = new CornerRadius(8), Background = Palette.Tint(color, 0x26), Child = Ui.Icon(icon, 15, color).Also(i => i.HorizontalAlignment = HorizontalAlignment.Center) };
        DockPanel.SetDock(ic, Dock.Left);
        head.Children.Add(ic);
        DockPanel.SetDock(action, Dock.Right);
        head.Children.Add(action);
        head.Children.Add(Ui.Stack(1, Ui.T(name, "h3"), Ui.Row(6, Ui.Dot(color, 7), Ui.T(status, "", 11.5, color))).Also(x => x.Margin = new Thickness(10, 0, 8, 0)));
        var tile = new LinkTile(Ui.Stack(6, head, Ui.T(what, "muted")), () => _navigate(page, null));
        AutomationProperties.SetName(tile, $"{name}: {status}. Press Enter to open.");
        ToolTip.SetTip(tile, $"Open {name}");
        return tile;
    }

    private string Until(string blade)
    {
        var st = ModelBuilder.PauseState(_c.State.Status, blade);
        return st is null ? "" : ModelBuilder.FormatUntil(st);
    }

    private Button PauseButton(string blade)
    {
        var b = Ui.Btn("Pause", "ghost small", () => { });
        var menu = new ContextMenu();
        var items = new List<MenuItem>();
        foreach (var (label, minutes) in new[] { ("For 15 minutes", 15), ("For 1 hour", 60), ("Until I resume it", 0) })
        {
            var mi = new MenuItem { Header = label };
            mi.Click += (_, _) => _ = _c.Pause(blade, minutes);
            items.Add(mi);
        }
        menu.ItemsSource = items;
        b.ContextMenu = menu;
        b.Click += (_, _) => menu.Open(b);
        return b;
    }

    private Control SensorTile()
    {
        var st = _c.State.Status;
        var sysmon = st?.Child("sysmon");
        var def = st?.Child("defender");
        var ok = _c.State.EngineAlive && sysmon?.T("ok") == true;
        var color = ok ? Palette.Ok : Palette.Danger;
        var lines = Ui.Stack(4,
            Ui.T($"Engine: {(_c.State.EngineAlive ? "running" : "not running")}{(st?.I("lagSeconds") >= 5 ? $" (lag {st.I("lagSeconds")}s)" : "")}", "muted"),
            Ui.T($"Sysmon: {sysmon?.S("message") ?? "unknown"}", "muted"),
            Ui.T(def is null ? "Defender: status unknown" : $"Defender: real-time {(def.T("realtime") ? "on" : "OFF")}, ASR {def.S("asrAuditRules")} audit / {def.S("asrBlockRules")} block", "muted"),
            Ui.T($"Last scan: {ModelBuilder.FormatWhen(st?.Child("scan")?.S("lastEnd"), "ddd HH:mm")}  -  next {ModelBuilder.FormatWhen(st?.Child("scan")?.S("nextDue"), "ddd HH:mm")}", "muted"));
        var head = Ui.Row(12, new Border { Width = 30, Height = 30, CornerRadius = new CornerRadius(8), Background = Palette.Tint(color, 0x26), Child = Ui.Icon("", 18, color).Also(i => i.HorizontalAlignment = HorizontalAlignment.Center) },
            Ui.Stack(1, Ui.T("Sensors & scans", "h3"), Ui.Row(6, Ui.Dot(color, 8), Ui.T(ok ? "Healthy" : "Needs attention", "", 12.5, color))));
        return Ui.Card(Ui.Stack(10, head, lines), "tile");
    }

    private Control? Suggestions()
    {
        var m = _c.State.Model;
        if (m is null) return null;
        var rows = new[] { "malware", "edr", "sigma" }.SelectMany(k => m.Sec[k].Rows[0]).Where(r => r.Kind == "event" && r.Ev is not null && _c.Insights.ShouldSuggest(r.Ev)).Take(3).ToList();
        if (rows.Count == 0) return null;
        var list = Ui.Stack(10, Ui.Row(10, Ui.Icon("", 18, Palette.Accent), Ui.T("Suggestions", "h3")),
            Ui.T("You keep marking these as reviewed. If they are normal on this PC, allow them so they stop coming back.", "sub"));
        foreach (var r in rows)
        {
            var allow = Ui.Btn("Allow", "primary small", () => _ = _c.Run(new TrayAction(ActionKind.Allow, ""), [r]));
            var keep = Ui.Btn("Keep showing", "ghost small", () => { _c.Insights.Dismiss(r.Ev!); Refresh(); });
            var line = new DockPanel();
            var btns = Ui.Row(6, allow, keep);
            DockPanel.SetDock(btns, Dock.Right);
            line.Children.Add(btns);
            line.Children.Add(Ui.Stack(1, Ui.T(new RowItem(r).Title, "h3"), Ui.T(new RowItem(r).Subtitle, "muted")));
            list.Children.Add(line);
        }
        return Ui.Card(list);
    }

    private Control Weekly()
    {
        var now = DateTime.Now;
        var sum = PeriodSummary.Compute(_c.State.Inputs.Events, now.AddDays(-7), now);
        var stats = new UniformGrid { Columns = 4 };
        void Stat(string value, string label, IBrush color) => stats.Children.Add(Ui.Stack(1, Ui.T(value, "", 20, color, FontWeight.SemiBold), Ui.T(label, "muted")));
        Stat(sum.Alerts.ToString(), "alerts", sum.Critical > 0 ? Palette.Danger : Palette.Text);
        Stat(sum.Bans.ToString(), "Wail2Ban bans", Palette.Text);
        Stat(sum.SignInFailures.ToString(), "failed sign-ins", Palette.Text);
        Stat($"{sum.ScansOk}/{sum.ScansOk + sum.ScansFailed}", "scans OK", sum.ScansFailed > 0 ? Palette.Warn : Palette.Text);
        var body = Ui.Stack(14, Ui.Row(10, Ui.Icon("", 18, Palette.Accent), Ui.T("Your week", "h3"), Ui.T(sum.OneLine, "muted")), stats);
        if (sum.Noisiest.Count > 0)
            body.Children.Add(Ui.Stack(4, Ui.T("MOST FREQUENT", "label"), Ui.Stack(2, sum.Noisiest.Select(n => (Control)Ui.T($"{n.Count}×  {n.Title}", "sub")).ToArray())));
        return Ui.Card(body);
    }
}

/// <summary>
/// A Home tile that opens its page: click anywhere but its own button, or Tab to it and press Enter or Space.
/// Screen readers see it as a button (name set by the caller) that can be invoked.
/// </summary>
internal sealed class LinkTile : Border
{
    private readonly Action _open;

    protected override Type StyleKeyOverride => typeof(Border);   // themed as "Border.tile"

    public LinkTile(Control child, Action open)
    {
        _open = open;
        Child = child;
        Classes.Add("tile");
        Focusable = true;
        Cursor = new Avalonia.Input.Cursor(Avalonia.Input.StandardCursorType.Hand);
    }

    protected override void OnPointerPressed(Avalonia.Input.PointerPressedEventArgs e)
    {
        base.OnPointerPressed(e);
        if (e.Source is not Button && e.Source is Visual v && v.FindAncestorOfType<Button>() is null) _open();
    }

    protected override void OnKeyDown(Avalonia.Input.KeyEventArgs e)
    {
        if (ReferenceEquals(e.Source, this) && e.Key is Avalonia.Input.Key.Enter or Avalonia.Input.Key.Space) { _open(); e.Handled = true; }
        base.OnKeyDown(e);
    }

    protected override Avalonia.Automation.Peers.AutomationPeer OnCreateAutomationPeer() => new Peer(this);

    private sealed class Peer(LinkTile owner) : Avalonia.Automation.Peers.ControlAutomationPeer(owner), Avalonia.Automation.Provider.IInvokeProvider
    {
        protected override Avalonia.Automation.Peers.AutomationControlType GetAutomationControlTypeCore() => Avalonia.Automation.Peers.AutomationControlType.Button;
        protected override bool IsControlElementCore() => true;
        protected override bool IsContentElementCore() => true;
        public void Invoke() => owner._open();
    }
}

internal static class VisualExtensions
{
    public static T? FindAncestorOfType<T>(this Visual v) where T : class
    {
        for (var p = v.GetVisualParent(); p is not null; p = p.GetVisualParent()) if (p is T t) return t;
        return null;
    }

    private static Visual? GetVisualParent(this Visual v) => Avalonia.VisualTree.VisualExtensions.GetVisualParent(v);
}
