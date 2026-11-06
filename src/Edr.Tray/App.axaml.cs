using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using Edr.Core;
using Edr.Tray.Services;
using Edr.Tray.Views;

namespace Edr.Tray;

/// <summary>
/// The tray app: the shield in the notification area with a short menu, the 2-second refresh, notifications, the
/// first-run welcome and the dashboard window (closing it only hides it).
/// </summary>
public partial class App : Application
{
    private readonly TrayContext? _context;
    private TrayIcon? _tray;
    private MainWindow? _window;
    private Controller? _c;
    private DispatcherTimer? _timer;
    private bool _exiting;
    private bool _inTick;
    private string _menuKey = "";

    public static App? Instance { get; private set; }

    public App() : this(null) { }   // XAML previewer

    internal App(TrayContext? context)
    {
        _context = context;
        Instance = this;
    }

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop && _context is not null)
        {
            desktop.ShutdownMode = ShutdownMode.OnExplicitShutdown;   // the tray lives on with the dashboard closed
            var state = new TrayState(_context.Paths);
            _c = new Controller(state);
            var icon = Path.Combine(_context.Paths.LocalDir, "freeedr.png");
            ShieldIcon.SavePng(ShieldState.Protected, 128, icon);
            _c.Notifier = new Notifier(state, _c.Prefs, args => Dispatcher.UIThread.Post(() => _ = _c.Activated(args, ShowDashboard)));
            _c.Notifier.Register(icon);
            _c.Changed = () => _window?.RefreshAll();
            _tray = new TrayIcon { Icon = ShieldIcon.Create(ShieldState.Protected), ToolTipText = "FreeEDR", IsVisible = true };
            _tray.Clicked += (_, _) => ShowDashboard("home", null);
            TrayIcon.SetIcons(this, [_tray]);
            _context.Instance.Listen(onShow: () => Dispatcher.UIThread.Post(() => ShowDashboard(null, null)), onExit: () => Dispatcher.UIThread.Post(Exit));
            Tick();
            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            _timer.Tick += (_, _) => Tick();
            _timer.Start();
            if (_context.Options.ToastTitle is { Length: > 0 } tt) _c.Notifier.Show(tt, _context.Options.ToastText ?? "", "page|home", [("Open FreeEDR", "page|home")]);
            if (_context.Options.Screenshot is { } shots) { Dispatcher.UIThread.Post(() => _ = Screenshots(shots), DispatcherPriority.Background); }
            else if (!_c.Prefs.WelcomeDone) Dispatcher.UIThread.Post(ShowWelcome, DispatcherPriority.Background);
            else if (_context.Options.Show) ShowDashboard("home", null);
        }
        base.OnFrameworkInitializationCompleted();
    }

    private void Tick()
    {
        if (_inTick || _c is null) return;
        _inTick = true;
        try
        {
            var rebuilt = _c.State.Refresh();
            foreach (var e in _c.State.NewEvents) _c.Notifier?.Consider(e);
            _c.Notifier?.Tick();
            _c.Winget.Tick();
            WeeklyAndLearning();
            UpdateTray();
            if (rebuilt && _window is { IsVisible: true }) _window.RefreshAll();
        }
        catch (Exception e) { _context?.Log.Write($"Tick failed: {e.GetType().Name}: {e.Message}"); }
        finally { _inTick = false; }
    }

    /// <summary>The learning-week wrap-up (once, after 7 days) and the weekly summary notification (every 7 days).</summary>
    private void WeeklyAndLearning()
    {
        if (_c?.Notifier is null || !_c.State.EngineAlive) return;
        var now = DateTime.Now;
        if (Ps.ToDate(_c.State.Config.InstalledAt) is { } inst && now - inst >= TimeSpan.FromDays(7) && !_c.Prefs.LearningSummaryShown)
        {
            _c.Prefs.LearningSummaryShown = true;
            var s = PeriodSummary.Compute(_c.State.Inputs.Events, inst, now);
            _c.Notifier.Show("Learning week finished", $"{s.OneLine} From now on FreeEDR notifies you as set in Settings. Review the suggestions on Home.", "page|home", [("Open FreeEDR", "page|home")]);
            _c.Prefs.LastWeeklySummary = now.ToString("s");
            return;
        }
        var last = Ps.ToDate(_c.Prefs.LastWeeklySummary);
        if (last is null) { _c.Prefs.LastWeeklySummary = now.ToString("s"); return; }
        if (now - last.Value < TimeSpan.FromDays(7)) return;
        _c.Prefs.LastWeeklySummary = now.ToString("s");
        var sum = PeriodSummary.Compute(_c.State.Inputs.Events, now.AddDays(-7), now);
        _c.Notifier.Show("Your FreeEDR week", sum.OneLine, "page|home", [("See the summary", "page|home")]);
    }

    private void UpdateTray()
    {
        if (_tray is null || _c is null) return;
        var ov = _c.State.Overall;
        var st = _c.State;
        var paused = st.PauseState("edr") == "paused";
        var scanning = st.Status?.Child("scan")?.T("running") == true;
        var key = $"{ov.Key}|{ov.Text}|{paused}|{scanning}|{st.EngineAlive}";
        if (key == _menuKey) return;
        _menuKey = key;
        _tray.Icon = ShieldIcon.Create(ShieldIcon.From(ov.Key));
        _tray.ToolTipText = ov.Text.Length > 60 ? "FreeEDR - " + ov.Text[..57] + "..." : "FreeEDR - " + ov.Text;
        var menu = new NativeMenu();
        menu.Items.Add(new NativeMenuItem(ov.Text.Length > 60 ? ov.Text[..57] + "..." : ov.Text) { IsEnabled = false });
        menu.Items.Add(new NativeMenuItemSeparator());
        menu.Items.Add(Item("Open FreeEDR", () => ShowDashboard("home", null)));
        menu.Items.Add(Item(scanning ? "Scan running..." : "Scan now", () => _ = _c.ScanNow(), enabled: !scanning && st.EngineAlive));
        if (paused) menu.Items.Add(Item("Resume detection", () => _ = _c.Resume("edr"), enabled: st.EngineAlive));
        else
        {
            var pause = new NativeMenuItem("Pause detection") { IsEnabled = st.EngineAlive };
            var sub = new NativeMenu();
            sub.Items.Add(Item("For 15 minutes", () => _ = _c.Pause("edr", 15)));
            sub.Items.Add(Item("For 1 hour", () => _ = _c.Pause("edr", 60)));
            sub.Items.Add(Item("Until I resume it", () => _ = _c.Pause("edr", 0)));
            pause.Menu = sub;
            menu.Items.Add(pause);
        }
        menu.Items.Add(Item("Settings", () => ShowDashboard("settings", null)));
        menu.Items.Add(new NativeMenuItemSeparator());
        menu.Items.Add(Item("Hide the tray icon (protection keeps running)", Exit));
        _tray.Menu = menu;
    }

    private static NativeMenuItem Item(string text, Action a, bool enabled = true)
    {
        var mi = new NativeMenuItem(text) { IsEnabled = enabled };
        mi.Click += (_, _) => a();
        return mi;
    }

    public void ShowDashboard(string? page, string? select)
    {
        if (_exiting || _c is null) return;
        if (_window is null)
        {
            _window = new MainWindow(_c);
            Dialogs.Owner = _window;
            _window.Closing += (_, e) =>
            {
                if (_exiting) return;
                e.Cancel = true;   // closing the dashboard only hides it
                _window.Hide();
            };
            _c.Snack = (text, error) => Dispatcher.UIThread.Post(() =>
            {
                if (_window is { IsVisible: true }) _window.Snack(text, error);
                else _c.Notifier?.Show(error ? "FreeEDR: not done" : "FreeEDR", text, "page|home", []);
            });
        }
        _window.Show();
        if (_window.WindowState == WindowState.Minimized) _window.WindowState = WindowState.Normal;
        _window.Activate();
        _window.RefreshAll();
        if (page is not null || select is not null) _window.Navigate(page ?? "home", select);
    }

    public async void ShowWelcome()
    {
        if (_c is null) return;
        var w = new WelcomeWindow(_c.State.IsProfileOn, _c.Prefs.NotifyLevel);
        var tcs = new TaskCompletionSource();
        w.Closed += (_, _) => tcs.TrySetResult();
        w.Show();
        await tcs.Task;
        if (!w.Finished) return;
        _c.Prefs.NotifyLevel = w.NotifyLevel;
        _c.Prefs.WelcomeDone = true;
        if (w.ProfileChoice.Any(kv => kv.Value != _c.State.IsProfileOn(kv.Key))) await _c.SetProfiles(w.ProfileChoice);
        ShowDashboard("home", null);
    }

    /// <summary>--screenshot &lt;folder&gt;: renders every page (and the welcome) to PNG, then exits. Development only.</summary>
    private async Task Screenshots(string dir)
    {
        Directory.CreateDirectory(dir);
        ShowDashboard("home", null);
        _window!.Width = 1360; _window.Height = 880;
        foreach (var page in new[] { "home", "activity", "network", "updates", "allowed", "settings" })
        {
            var pick = page switch
            {
                "activity" => _c!.State.Model?.Sec["malware"].Rows[0].FirstOrDefault()?.Ev?.S("id"),
                "network" => _c!.State.Model?.Sec["wail2ban"].Rows[0].FirstOrDefault()?.Ev?.S("id"),
                _ => null,
            };
            _window.Navigate(page, pick);
            await Task.Delay(700);
            Render(_window, Path.Combine(dir, page + ".png"));
        }
        _window.ExerciseAllViews();
        await Task.Delay(300);
        var w = new WelcomeWindow(_c!.State.IsProfileOn, "important");
        w.Show();
        await Task.Delay(700);
        Render(w, Path.Combine(dir, "welcome.png"));
        w.Close();
        Exit();
    }

    private static void Render(Window w, string file)
    {
        var size = new PixelSize((int)w.Bounds.Width, (int)w.Bounds.Height);
        using var bmp = new Avalonia.Media.Imaging.RenderTargetBitmap(size, new Vector(96, 96));
        bmp.Render(w);
        bmp.Save(file, Avalonia.Media.Imaging.PngBitmapEncoderOptions.Default);
    }

    private void Exit()
    {
        if (_exiting) return;
        _exiting = true;
        _timer?.Stop();
        if (_tray is not null) _tray.IsVisible = false;
        _window?.Close();
        (ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.Shutdown();
    }
}
