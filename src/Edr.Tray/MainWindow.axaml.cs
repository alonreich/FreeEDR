using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using Edr.Core;
using Edr.Tray.Views;

namespace Edr.Tray;

/// <summary>The dashboard: sidebar navigation (Home, Activity, Network, Updates, Allowed &amp; trusted, Settings) and pages.</summary>
public partial class MainWindow : Window
{
    private readonly Controller _c;
    private readonly Dictionary<string, Button> _nav = [];
    private readonly Dictionary<string, TextBlock> _badges = [];
    private readonly ContentControl _host = new();
    private readonly Border _snack;
    private readonly TextBlock _snackText = new() { Foreground = Brushes.White, VerticalAlignment = VerticalAlignment.Center, MaxWidth = 720 };
    private readonly Image _logo = new() { Width = 34, Height = 34 };
    private readonly TextBlock _engine = new() { FontSize = 12, Foreground = Palette.Muted };
    private readonly DispatcherTimer _snackTimer = new() { Interval = TimeSpan.FromSeconds(5) };

    private readonly HomePage _home;
    private readonly ListPage _activity;
    private readonly ListPage _network;
    private readonly ListPage _updates;
    private readonly AllowedPage _allowed;
    private readonly SettingsPage _settings;
    private string _page = "home";

    public MainWindow() : this(null!) { }   // XAML loader

    public MainWindow(Controller c)
    {
        InitializeComponent();
        _c = c;
        Icon = ShieldIcon.Create(ShieldState.Protected);
        _home = new HomePage(c, Navigate);
        _activity = new ListPage(c, "Activity", "Everything FreeEDR detected, newest first. Pick an item to see what it means and what you can do.",
        [
            new("To review", () => Merge(0, "malware", "edr", "sigma"), "Nothing to review. FreeEDR keeps watching."),
            new("Flagged", () => Merge(1, "malware", "edr", "sigma"), "Nothing flagged as a threat."),
            new("Messages", () => c.State.Model?.Messages ?? [], "No messages from FreeEDR yet."),
        ], [("malware", "Anti-Malware"), ("edr", "Real-time"), ("sigma", "Event logs")], reviewToggle: true);
        _network = new ListPage(c, "Network (Wail2Ban)", "Failed and successful sign-ins over the network (Remote Desktop, file sharing) and the addresses Wail2Ban blocked.",
        [
            new("Sign-in attempts", () => Merge(0, "wail2ban"), "No failed or internet sign-ins. Wail2Ban keeps watching."),
            new("Banned", () => Merge(1, "wail2ban"), "No address is banned."),
            new("Trusted", () => Merge(2, "wail2ban"), "No trusted addresses. Trust your own devices so Wail2Ban never blocks them."),
        ], reviewToggle: true);
        _updates = new ListPage(c, "Updates", "Fixable security holes in Python packages, app updates, and FreeEDR's own detection tools.",
        [
            new("Vulnerabilities", () => Merge(0, "cve"), "No fixable vulnerability found in Python packages."),
            new("App updates", () => Merge(0, "apps"), "All apps are up to date (winget)."),
            new("Updated", () => Merge(1, "cve").Concat(Merge(1, "apps")), "Nothing updated from FreeEDR yet."),
            new("FreeEDR tools", () => [], "", () => ToolPanel.Build(c)),
        ]);
        _allowed = new AllowedPage(c);
        _settings = new SettingsPage(c);
        _snackTimer.Tick += (_, _) => { _snack!.IsVisible = false; _snackTimer.Stop(); };
        _snack = new Border
        {
            CornerRadius = new CornerRadius(12), Padding = new Thickness(18, 12), Margin = new Thickness(0, 0, 0, 24), IsVisible = false,
            HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Bottom, BoxShadow = BoxShadows.Parse("0 8 24 0 #66000000"),
            Child = Ui.Row(12, Ui.Icon("", 16, Brushes.White), _snackText),
        };
        Content = BuildLayout();
        c.Clipboard = () => Clipboard;
        if (c.Prefs.Window is { } w)
        {
            Width = w.W; Height = w.H;
            if (w.X > -10000) { Position = new PixelPoint(w.X, w.Y); WindowStartupLocation = WindowStartupLocation.Manual; }
            if (w.Max) WindowState = WindowState.Maximized;
        }
        Closing += (_, _) => c.Prefs.Window = (Bounds.Width, Bounds.Height, Position.X, Position.Y, WindowState == WindowState.Maximized);
        Navigate(c.Prefs.LastPage is { Length: > 0 } lp && lp != "settings" ? lp : "home", null);
    }

    private IEnumerable<Row> Merge(int list, params string[] keys) =>
        _c.State.Model is { } m
            ? keys.SelectMany(k => m.Sec[k].Rows[list]).OrderByDescending(r => r.Pinned && !r.Muted).ThenByDescending(r => r.Time, Ps.Order)
            : [];

    private Control BuildLayout()
    {
        var side = new DockPanel { Width = 236, Background = Palette.Brush("#121B2E") };
        var brand = Ui.Row(10, _logo, Ui.Stack(0, Ui.T("FreeEDR", "", 18, null, FontWeight.Bold), Ui.T("Endpoint protection", "muted")));
        brand.Margin = new Thickness(20, 22, 16, 22);
        DockPanel.SetDock(brand, Dock.Top);
        side.Children.Add(brand);
        var foot = Ui.Stack(6, _engine);
        foot.Margin = new Thickness(20, 12, 16, 18);
        DockPanel.SetDock(foot, Dock.Bottom);
        side.Children.Add(foot);
        var nav = new StackPanel { Spacing = 4, Margin = new Thickness(12, 0) };
        foreach (var (key, icon, label) in new[]
                 {
                     ("home", "", "Home"), ("activity", "", "Activity"), ("network", "", "Network"),
                     ("updates", "", "Updates"), ("allowed", "", "Allowed & trusted"), ("settings", "", "Settings"),
                 })
        {
            var badge = new TextBlock { FontSize = 11.5, FontWeight = FontWeight.Bold, Foreground = Brushes.White, VerticalAlignment = VerticalAlignment.Center };
            var badgeBox = new Border { CornerRadius = new CornerRadius(999), Padding = new Thickness(7, 1), Background = Palette.Danger, Child = badge, IsVisible = false, VerticalAlignment = VerticalAlignment.Center };
            _badges[key] = badge;
            var content = new DockPanel { LastChildFill = true };
            DockPanel.SetDock(badgeBox, Dock.Right);
            content.Children.Add(badgeBox);
            content.Children.Add(Ui.Row(12, Ui.Icon(icon, 17), Ui.T(label, "", 13.5).Also(t => t.TextWrapping = TextWrapping.NoWrap)));
            var b = new Button { Content = content, Classes = { "nav" } };
            b.Click += (_, _) => Navigate(key, null);
            _nav[key] = b;
            nav.Children.Add(b);
        }
        side.Children.Add(nav);
        var main = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*") };
        main.Children.Add(side);
        var right = new Panel { Children = { _host, _snack } };
        Grid.SetColumn(right, 1);
        main.Children.Add(right);
        return main;
    }

    public void Navigate(string page, string? selectId)
    {
        if (!_nav.ContainsKey(page)) page = "home";
        _page = page;
        _c.Prefs.LastPage = page;
        foreach (var (k, b) in _nav) { if (k == page) b.Classes.Add("active"); else b.Classes.Remove("active"); }
        Control view = page switch
        {
            "activity" => _activity, "network" => _network, "updates" => _updates, "allowed" => _allowed, "settings" => _settings, _ => _home,
        };
        _host.Content = view;
        RefreshPage();
        if (selectId is not null)
        {
            if (page == "activity") _activity.Select(selectId, 0);
            else if (page == "network") _network.Select(selectId, 0);
        }
    }

    /// <summary>--screenshot: open every page and every tab twice, refreshing each, so a view that reuses a control
    /// (a control can have only one parent) fails here instead of in the user's tray.</summary>
    public void ExerciseAllViews()
    {
        foreach (var page in _nav.Keys.ToList())
        {
            for (var pass = 0; pass < 2; pass++)
            {
                Navigate(page, null);
                if ((Control?)_host.Content is ListPage lp)
                    for (var t = 0; t < lp.TabCount; t++) { lp.Select(null, t); RefreshPage(); lp.Select(null, t); }
                RefreshPage();
            }
        }
        Navigate("home", null);
    }

    /// <summary>The model changed: redraw the visible page, the badges and the logo.</summary>
    public void RefreshAll()
    {
        var m = _c.State.Model;
        var ov = _c.State.Overall;
        _logo.Source = ShieldIcon.Bitmap(ShieldIcon.From(ov.Key), 64);
        Icon = ShieldIcon.Create(ShieldIcon.From(ov.Key));
        Title = $"FreeEDR - {ov.Text}";
        void Badge(string k, int n, IBrush color)
        {
            _badges[k].Text = n > 99 ? "99+" : n.ToString();
            ((Border)_badges[k].Parent!).IsVisible = n > 0;
            ((Border)_badges[k].Parent!).Background = color;
        }
        if (m is not null)
        {
            var att = m.Sec["malware"].Attention + m.Sec["edr"].Attention + m.Sec["sigma"].Attention;
            Badge("activity", att > 0 ? att : m.Sec["malware"].Count + m.Sec["edr"].Count + m.Sec["sigma"].Count, att > 0 ? Palette.Danger : Palette.Brush("#3B5487"));
            Badge("network", m.Sec["wail2ban"].Attention, Palette.Danger);
            Badge("updates", m.Sec["cve"].Count + m.Sec["apps"].Count, Palette.Brush("#3B5487"));
        }
        _engine.Text = _c.State.EngineAlive ? $"Engine running  ·  {ModelBuilder.FormatWhen(_c.State.Status?.S("heartbeat"), "HH:mm:ss")}" : "Engine not running";
        _engine.Foreground = _c.State.EngineAlive ? Palette.Muted : Palette.Danger;
        RefreshPage();
    }

    private void RefreshPage()
    {
        switch (_page)
        {
            case "activity": _activity.Refresh(); break;
            case "network": _network.SetHeaderExtra(Wail2BanMode()); _network.Refresh(); break;
            case "updates": _updates.Refresh(); break;
            case "allowed": _allowed.Refresh(); break;
            case "settings": _settings.Refresh(); break;
            default: _home.Refresh(); break;
        }
    }

    private Control Wail2BanMode()
    {
        var blocks = _c.State.Config.Wail2Ban.Block;
        var st = _c.State.PauseState("wail2ban");
        var label = st == "paused" ? Ui.Pill("Paused", Palette.Paused) : blocks ? Ui.Pill("Blocking attackers", Palette.Ok) : Ui.Pill("Report only", Palette.Warn);
        var toggle = Ui.Btn(blocks ? "Switch to report only" : "Turn blocking on", blocks ? "" : "primary", () => _ = ToggleWail2Ban(!blocks));
        return Ui.Row(10, label, toggle);
    }

    private async Task ToggleWail2Ban(bool block)
    {
        if (!await Dialogs.Confirm(block ? "Turn Wail2Ban blocking on" : "Wail2Ban: report only",
                block ? "Computers that keep failing to sign in are blocked in Windows Firewall for a while (5 minutes at first, longer for repeat offenders)."
                      : "Password guessing is still detected and reported, but addresses are no longer blocked. Existing bans stay until they expire.", block ? "Turn on" : "Report only")) return;
        await _c.SaveSettings(new System.Text.Json.Nodes.JsonObject { ["wail2ban"] = new System.Text.Json.Nodes.JsonObject { ["block"] = block } });
    }

    public void Snack(string text, bool error)
    {
        Dispatcher.UIThread.Post(() =>
        {
            _snackText.Text = text;
            _snack.Background = error ? Palette.Brush("#B8323F") : Palette.Brush("#2B467A");
            _snack.IsVisible = true;
            _snackTimer.Stop();
            _snackTimer.Start();
        });
    }
}
