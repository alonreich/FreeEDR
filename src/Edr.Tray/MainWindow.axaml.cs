using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using Edr.Core;
using Edr.Tray.Views;

namespace Edr.Tray;

public partial class MainWindow : Window
{
    private readonly Controller _c;
    private readonly Dictionary<string, Button> _nav = [];
    private readonly Dictionary<string, TextBlock> _badges = [];
    private readonly ContentControl _host = new();
    private readonly Border _snack;
    private readonly TextBlock _snackText = new() { Foreground = Brushes.White, VerticalAlignment = VerticalAlignment.Center, MaxWidth = 640 };
    private readonly Button _snackAction = new() { Classes = { "small" }, IsVisible = false, VerticalAlignment = VerticalAlignment.Center };
    private readonly Button _snackClose = new() { Content = "✕", Classes = { "ghost", "small" }, VerticalAlignment = VerticalAlignment.Center, Foreground = Brushes.White };
    private Action? _snackDo;
    private readonly Image _logo = new() { Width = 28, Height = 28 };
    private readonly TextBlock _engine = new() { FontSize = 12, Foreground = Palette.Muted };
    private readonly DispatcherTimer _snackTimer = new() { Interval = TimeSpan.FromSeconds(5) };

    private readonly HomePage _home;
    private readonly ListPage _activity;
    private readonly ListPage _network;
    private readonly ListPage _updates;
    private readonly AllowedPage _allowed;
    private readonly SettingsPage _settings;
    private string _page = "home";
    private PixelPoint? _normalPos;
    private Size? _normalSize;

    private bool OnAScreen(PixelPoint p)
    {
        try { return Screens.All.Any(sc => sc.WorkingArea.Intersects(new PixelRect(p.X, p.Y, 40, 40))); }
        catch (Exception e) when (e is InvalidOperationException or NullReferenceException) { return false; }
    }

    public bool SettingsUnsaved => _settings.HasUnsaved;

    public string CurrentPage => _page;

    public void RenderSettings(string file) => _settings.RenderFull(file);

    public Task<bool> SaveSettingsNow() => _settings.SaveFromOutside();

    public MainWindow() : this(null!) { }

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
            new("Started here", () => Merge(1, "cve").Concat(Merge(1, "apps")), "No update was started from FreeEDR yet."),
            new("FreeEDR tools", () => [], "", () => ToolPanel.Build(c)),
        ]);
        _allowed = new AllowedPage(c);
        _settings = new SettingsPage(c);
        _snackTimer.Tick += (_, _) => { if (SnackHeld) _snackTimer.Stop(); else HideSnack(); };
        _snack = new Border
        {
            CornerRadius = new CornerRadius(12), Padding = new Thickness(18, 12), Margin = new Thickness(0, 0, 0, 24), IsVisible = false,
            HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Bottom, BoxShadow = BoxShadows.Parse("0 8 24 0 #66000000"),
            Child = Ui.Row(12, Ui.Icon("", 16, Brushes.White), _snackText),
        };
        ((StackPanel)_snack.Child!).Children.Add(_snackAction);
        ((StackPanel)_snack.Child!).Children.Add(_snackClose);
        AutomationProperties.SetLiveSetting(_snack, AutomationLiveSetting.Assertive);
        AutomationProperties.SetName(_snackClose, "Dismiss message");
        ToolTip.SetTip(_snackClose, "Dismiss");
        _snackClose.Click += (_, _) => HideSnack();
        _snack.PointerEntered += (_, _) => _snackTimer.Stop();
        _snack.PointerExited += (_, _) => RestartSnackTimer();
        _snack.GotFocus += (_, _) => _snackTimer.Stop();
        _snack.LostFocus += (_, _) => Dispatcher.UIThread.Post(RestartSnackTimer);
        _snackAction.Click += (_, _) => { var a = _snackDo; HideSnack(); a?.Invoke(); };
        _settings.UnsavedChanged += RefreshSettingsBadge;
        Content = BuildLayout();
        c.Clipboard = () => Clipboard;
        if (c.Prefs.Window is { } w)
        {
            Width = Math.Max(MinWidth, w.W); Height = Math.Max(MinHeight, w.H);
            _normalSize = new Size(Width, Height);
            if (w.X > -10000 && OnAScreen(new PixelPoint(w.X, w.Y)))
            {
                Position = new PixelPoint(w.X, w.Y);
                _normalPos = Position;
                WindowStartupLocation = WindowStartupLocation.Manual;
            }
            if (w.Max) WindowState = WindowState.Maximized;
        }
        PositionChanged += (_, e) => { if (WindowState == WindowState.Normal) _normalPos = e.Point; };
        SizeChanged += (_, e) => { if (WindowState == WindowState.Normal) _normalSize = e.NewSize; };
        Closing += (_, _) =>
        {
            var size = WindowState == WindowState.Normal ? Bounds.Size : _normalSize ?? Bounds.Size;
            var pos = WindowState == WindowState.Normal ? Position : _normalPos ?? Position;
            c.Prefs.Window = (size.Width, size.Height, pos.X, pos.Y, WindowState == WindowState.Maximized);
            if (_page == "settings") _settings.RememberScroll();
        };
        Navigate(c.Prefs.LastPage is { Length: > 0 } lp ? lp : "home", null);
    }

    private IEnumerable<Row> Merge(int list, params string[] keys) =>
        _c.State.Model is { } m
            ? keys.SelectMany(k => m.Sec[k].Rows[list]).OrderByDescending(r => r.Pinned && !r.Muted).ThenByDescending(r => r.Time, Ps.Order)
            : [];

    private Control BuildLayout()
    {
        var side = new DockPanel { Width = 210, Background = Palette.Sidebar };
        var brand = Ui.Row(10, _logo, Ui.Stack(0, Ui.T("FreeEDR", "", 15, null, FontWeight.Bold), Ui.T("Endpoint protection", "muted")));
        brand.Margin = new Thickness(16, 16, 12, 16);
        DockPanel.SetDock(brand, Dock.Top);
        side.Children.Add(brand);
        var foot = Ui.Stack(6, _engine);
        foot.Margin = new Thickness(20, 12, 16, 18);
        DockPanel.SetDock(foot, Dock.Bottom);
        side.Children.Add(foot);
        var nav = new StackPanel { Spacing = 2, Margin = new Thickness(10, 0) };
        foreach (var (key, icon, label) in new[]
                 {
                     ("home", "", "Home"), ("activity", "", "Activity"), ("network", "", "Network"),
                     ("updates", "", "Updates"), ("allowed", "", "Allowed & trusted"), ("settings", "", "Settings"),
                 })
        {
            var badge = new TextBlock { FontSize = 10.5, FontWeight = FontWeight.Bold, Foreground = Brushes.White, VerticalAlignment = VerticalAlignment.Center };
            var badgeBox = new Border { CornerRadius = new CornerRadius(999), Padding = new Thickness(7, 1), Background = Palette.Danger, Child = badge, IsVisible = false, VerticalAlignment = VerticalAlignment.Center };
            _badges[key] = badge;
            var content = new DockPanel { LastChildFill = true };
            DockPanel.SetDock(badgeBox, Dock.Right);
            content.Children.Add(badgeBox);
            content.Children.Add(Ui.Row(10, Ui.Icon(icon, 15), Ui.T(label, "", 12.5).Also(t => t.TextWrapping = TextWrapping.NoWrap)));
            var b = new Button { Content = content, Classes = { "nav" } };
            AutomationProperties.SetName(b, label);
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
        string? part = null;
        if (page.IndexOf(':') is var colon and > 0) { part = page[(colon + 1)..]; page = page[..colon]; }
        if (!_nav.ContainsKey(page)) page = "home";
        if (page == "activity" && part is not null) _activity.ShowPart(part);
        if (_page == "settings" && page != "settings") _settings.RememberScroll();
        if (_page == "settings" && page != "settings" && _settings.HasUnsaved)
            Snack("Your settings changes are not saved yet. They wait in Settings until you save or discard them.", false, "Back to Settings", () => Navigate("settings", null));
        _page = page;
        _c.Prefs.LastPage = page;
        foreach (var (k, b) in _nav) { if (k == page) b.Classes.Add("active"); else b.Classes.Remove("active"); }
        Control view = page switch
        {
            "activity" => _activity, "network" => _network, "updates" => _updates, "allowed" => _allowed, "settings" => _settings, _ => _home,
        };
        _host.Content = view;
        _snack.Margin = new Thickness(0, 0, 0, page == "settings" ? 84 : 24);
        RefreshPage();
        if (selectId is not null)
        {
            if (page == "activity") _activity.Select(selectId, 0);
            else if (page == "network") _network.Select(selectId, 0);
        }
    }

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

    public void RefreshAll()
    {
        var m = _c.State.Model;
        var ov = _c.State.Overall;
        _logo.Source = ShieldIcon.Bitmap(ShieldIcon.From(ov.Key), 64);
        Icon = ShieldIcon.Create(ShieldIcon.From(ov.Key));
        Title = $"FreeEDR - {ov.Text}";
        void Badge(string k, int n, IBrush color, string what)
        {
            _badges[k].Text = n > 99 ? "99+" : n.ToString();
            ((Border)_badges[k].Parent!).IsVisible = n > 0;
            ((Border)_badges[k].Parent!).Background = color;
            AutomationProperties.SetName(_nav[k], n > 0 ? $"{NavLabel(k)}, {n} {what}" : NavLabel(k));
        }
        if (m is not null)
        {
            var att = m.Sec["malware"].Attention + m.Sec["edr"].Attention + m.Sec["sigma"].Attention;
            Badge("activity", m.Sec["malware"].Count + m.Sec["edr"].Count + m.Sec["sigma"].Count, att > 0 ? Palette.Danger : Palette.BadgeNeutral, att > 0 ? "to review" : "open");
            var w2b = m.Sec["wail2ban"];
            Badge("network", w2b.Count, w2b.Attention > 0 ? Palette.Danger : Palette.BadgeNeutral, w2b.Attention > 0 ? "to review" : "open");
            Badge("updates", m.Sec["cve"].Count + m.Sec["apps"].Count, Palette.BadgeNeutral, "waiting");
        }
        _engine.Text = _c.State.EngineAlive ? $"Engine running  ·  {ModelBuilder.FormatWhen(_c.State.Status?.S("heartbeat"), "HH:mm:ss")}" : "Engine not running";
        _engine.Foreground = _c.State.EngineAlive ? Palette.Muted : Palette.Danger;
        RefreshPage();
        RefreshSettingsBadge();
    }

    private static string NavLabel(string k) => k switch
    {
        "home" => "Home", "activity" => "Activity", "network" => "Network", "updates" => "Updates", "allowed" => "Allowed & trusted", _ => "Settings",
    };

    private void RefreshSettingsBadge()
    {
        var unsaved = _settings.HasUnsaved;
        _badges["settings"].Text = unsaved ? "Unsaved" : "";
        var box = (Border)_badges["settings"].Parent!;
        box.IsVisible = unsaved;
        box.Background = Palette.BadgeWarn;
        AutomationProperties.SetName(_nav["settings"], unsaved ? "Settings, unsaved changes" : "Settings");
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

    public void Snack(string text, bool error, string? actionLabel = null, Action? action = null)
    {
        Dispatcher.UIThread.Post(() =>
        {
            _snackText.Text = text;
            AutomationProperties.SetName(_snack, text);
            _snack.Background = error ? Palette.Brush("#B8323F") : Palette.Brush("#2B467A");
            _snackDo = action;
            _snackAction.Content = actionLabel;
            _snackAction.IsVisible = actionLabel is not null && action is not null;
            _snack.IsVisible = true;
            _snackTimer.Stop();
            _snackTimed = !error;
            if (!error)
            {
                _snackTimer.Interval = TimeSpan.FromSeconds(_snackAction.IsVisible ? 10 : 6);
                if (!SnackHeld) _snackTimer.Start();
            }
        });
    }

    private bool _snackTimed;

    private bool SnackHeld => _snack.IsPointerOver || _snack.IsKeyboardFocusWithin;

    private void RestartSnackTimer()
    {
        if (!_snack.IsVisible || !_snackTimed || SnackHeld) return;
        _snackTimer.Stop();
        _snackTimer.Start();
    }

    private void HideSnack()
    {
        _snackTimer.Stop();
        _snackTimed = false;
        _snack.IsVisible = false;
        _snackDo = null;
    }
}
