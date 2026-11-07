using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using Edr.Tray;

namespace Edr.Setup;

/// <summary>
/// The setup window (code-built, no reflection bindings): choose → progress → result, in the dashboard's theme.
/// Install asks upgrade vs clean install when FreeEDR is already there, and whether to replace a foreign Sysmon
/// configuration; uninstall goes straight to progress. The work runs on a worker thread; log lines are posted here.
/// The window cannot be closed while it works.
/// </summary>
internal sealed class SetupWindow : Window
{
    private static readonly IBrush Text2 = Brush("#AEBBD3"), Muted = Brush("#7E8DA9"), Ok = Brush("#2FBF71"), Warn = Brush("#F5A524"),
                                   Danger = Brush("#F0505F"), Accent = Brush("#6E9BF0"), Line = Brush("#2D3F66"), Surface = Brush("#1E2C47");
    private const string IconFont = "Segoe Fluent Icons, Segoe MDL2 Assets";

    private readonly SetupContext _c;
    private readonly ContentControl _page = new();
    private bool _working, _done;
    private int _exit = 4;   // closed before starting = cancelled

    public event Action<int>? Finished;

    public SetupWindow(SetupContext c)
    {
        _c = c;
        Title = c.Mode == SetupMode.Install ? "FreeEDR Setup" : "Remove FreeEDR";
        Width = 640; Height = 560; MinWidth = 560; MinHeight = 480;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        CanResize = true;
        Icon = new WindowIcon(ShieldIcon.Bitmap(ShieldState.Protected, 64));
        var logo = new Image { Source = ShieldIcon.Bitmap(ShieldState.Protected, 64), Width = 30, Height = 30 };
        var brand = Row(10, logo, Stack(0, T("FreeEDR", 15, FontWeight.Bold), T(c.Mode == SetupMode.Install ? $"Setup {c.Options.Version}".Trim() : "Uninstall", 11.5, null, Muted)));
        brand.Margin = new Thickness(20, 16, 20, 8);
        var root = new DockPanel();
        DockPanel.SetDock(brand, Dock.Top);
        root.Children.Add(brand);
        _page.Margin = new Thickness(20, 4, 20, 16);
        root.Children.Add(_page);
        Content = root;
        Closing += (_, e) =>
        {
            if (_working) { e.Cancel = true; return; }
            if (!_done) { _done = true; Finished?.Invoke(_exit); }
        };
        if (c.Screenshot is { } dir) { Opened += async (_, _) => await Screenshots(dir); ShowChoose(); return; }
        if (c.Mode == SetupMode.Install) ShowChoose(); else Start(c.Options);
    }

    /// <summary>Development: renders the three pages to PNG with sample lines and exits. Runs no install step.</summary>
    private async Task Screenshots(string dir)
    {
        Directory.CreateDirectory(dir);
        async Task Shot(string name)
        {
            await Task.Delay(400);
            var px = new PixelSize((int)Bounds.Width, (int)Bounds.Height);
            using var rtb = new Avalonia.Media.Imaging.RenderTargetBitmap(px, new Vector(96, 96));
            rtb.Render(this);
            rtb.Save(Path.Combine(dir, name), Avalonia.Media.Imaging.PngBitmapEncoderOptions.Default);
        }
        await Shot("setup-choose.png");
        _working = true;
        _page.Content = null;
        StartView(_c.Options);
        foreach (var (k, t) in new[] { ('S', "Pre-flight"), ('O', "Running elevated, x64, all setup files present"), ('S', "Stopping the running version"), ('O', "Engine, scans, tools and trays stopped"),
                                       ('S', "Installing program files"), ('O', "Previous version backed up"), ('O', "17 files copied"), ('S', "Tools (Hayabusa, YARA, OSV-Scanner, Velociraptor)"),
                                       ('O', "Hayabusa present"), ('W', "Sample warning line"), ('S', "Sysmon sensor and its configuration") }) OnLine(k, t);
        await Shot("setup-progress.png");
        ShowResult(0);
        await Shot("setup-result.png");
        _done = true;
        Finished?.Invoke(0);
    }

    // ---- page 1: what will happen ---------------------------------------------------------------------

    private void ShowChoose()
    {
        var (installed, sysmonForeign, desktopIcon) = Installer.Inspect(_c.Paths);
        var body = Stack(12);
        body.Children.Add(T(installed is null ? "Install FreeEDR" : "FreeEDR is already installed", 19, FontWeight.SemiBold));
        body.Children.Add(T(installed is null
            ? "Real-time detection (Sysmon), malware fingerprints and YARA, Sigma event-log scans, vulnerability checks and Wail2Ban, for every account on this PC. FreeEDR detects and explains; it never stops or removes anything. Only Wail2Ban acts: it blocks computers that keep failing to sign in."
            : $"Installed: {installed}. Choose what happens to its settings and history.", 12.5, null, Text2));

        var upgrade = Choice("Upgrade, keep everything", "Settings, allow lists, trusted apps, verdicts, bans, events, logs and the event archive stay as they are. Only the programs are replaced (the previous version is backed up and comes back by itself if the new one does not start).", true);
        var clean = Choice("Clean install, start fresh", "Erases settings, allow lists, verdicts, Wail2Ban bans, events, logs, scan results, the event archive and every account's dashboard state, then installs as new. Kept: the record of your Windows settings from before FreeEDR (the uninstaller needs it).", false);
        if (installed is not null) body.Children.Add(Stack(8, upgrade.Card, clean.Card));

        var icon = new CheckBox { Content = T("FreeEDR icon on the desktop (all users)", 12.5), IsChecked = desktopIcon };
        body.Children.Add(icon);
        CheckBox? sysmon = null;
        if (sysmonForeign)
        {
            sysmon = new CheckBox { Content = T("Sysmon is already installed with another configuration. Replace it with FreeEDR's (it is saved and put back when FreeEDR is uninstalled).", 12.5, null, Warn) };
            body.Children.Add(sysmon);
        }
        body.Children.Add(T("FreeEDR installs Microsoft Sysinternals Sysmon (downloaded from Microsoft) and accepts its license for you: https://learn.microsoft.com/sysinternals/license-terms", 11, null, Muted));

        var go = Btn(installed is null ? "Install" : "Upgrade", "primary", () => { });
        var cancel = Btn("Cancel", "", () => Close());
        void UpdateGo()
        {
            var isClean = clean.Group.IsChecked == true;
            go.Content = installed is null ? "Install" : isClean ? "Erase and install" : "Upgrade";
            go.Classes.Set("primary", !isClean);
            go.Classes.Set("danger", isClean);
            go.IsEnabled = sysmon is null || sysmon.IsChecked == true;
        }
        go.Click += (_, _) => Start(_c.Options with
        {
            NoDesktopIcon = icon.IsChecked != true, ReplaceSysmonConfig = sysmon?.IsChecked == true || _c.Options.ReplaceSysmonConfig,
            Clean = installed is not null && clean.Group.IsChecked == true,
        });
        clean.Group.IsCheckedChanged += (_, _) => UpdateGo();
        if (sysmon is not null) sysmon.IsCheckedChanged += (_, _) => UpdateGo();
        UpdateGo();
        _page.Content = Layout(new ScrollViewer { Content = body }, Footer(cancel, go));
    }

    private static (Border Card, RadioButton Group) Choice(string title, string text, bool on)
    {
        var rb = new RadioButton { GroupName = "mode", IsChecked = on, VerticalAlignment = VerticalAlignment.Top, Margin = new Thickness(0, 0, 4, 0) };
        var d = new DockPanel();
        DockPanel.SetDock(rb, Dock.Left);
        d.Children.Add(rb);
        d.Children.Add(Stack(2, T(title, 12.5, FontWeight.SemiBold), T(text, 11.5, null, Text2)));
        var card = new Border { Classes = { "tile" }, Child = d, Cursor = new Avalonia.Input.Cursor(Avalonia.Input.StandardCursorType.Hand) };
        card.PointerPressed += (_, _) => rb.IsChecked = true;
        return (card, rb);
    }

    // ---- page 2: progress -----------------------------------------------------------------------------

    private readonly StackPanel _steps = new() { Spacing = 2 };
    private readonly ScrollViewer _stepsScroll = new();
    private readonly ProgressBar _bar = new() { Minimum = 0, Maximum = 14, Height = 4, Margin = new Thickness(0, 4, 0, 8) };
    private readonly TextBlock _now = T("", 12.5, null, Text2);
    private (TextBlock Icon, StackPanel Lines)? _current;
    private int _stepCount;

    private void Start(SetupOptions opt)
    {
        _working = true;
        StartView(opt);
        var ctx = _c with { Options = opt };
        Task.Run(() =>
        {
            int rc;
            try { rc = Program.RunHeadless(ctx, (k, t) => Dispatcher.UIThread.Post(() => OnLine(k, t))); }
            catch (Exception e) { Dispatcher.UIThread.Post(() => OnLine('E', e.Message)); rc = 1; }
            Dispatcher.UIThread.Post(() => ShowResult(rc));
        });
    }

    private void StartView(SetupOptions opt)
    {
        var title = T(_c.Mode == SetupMode.Uninstall ? "Removing FreeEDR" : opt.Clean ? "Erasing and installing FreeEDR" : "Installing FreeEDR", 19, FontWeight.SemiBold);
        _bar.Maximum = _c.Mode == SetupMode.Uninstall ? 10 : opt.Clean ? 15 : 14;
        _stepsScroll.Content = _steps;
        _page.Content = Layout(Stack(4, title, _now, _bar).Also(s => DockPanel.SetDock(s, Dock.Top)), new Border
        {
            Classes = { "card" }, Padding = new Thickness(12, 8), Child = _stepsScroll,
        });
    }

    private void OnLine(char kind, string text)
    {
        switch (kind)
        {
            case 'S':
                if (_current is { } prev && prev.Icon.Text == "") Mark(prev.Icon, "", Ok);
                var icon = new TextBlock { Text = "", FontFamily = new FontFamily(IconFont), FontSize = 13, Foreground = Accent, Width = 20, VerticalAlignment = VerticalAlignment.Top, Margin = new Thickness(0, 2, 0, 0) };
                var lines = Stack(1, T(text, 12.5, FontWeight.SemiBold));
                var row = new DockPanel { Margin = new Thickness(0, 4, 0, 2) };
                DockPanel.SetDock(icon, Dock.Left);
                row.Children.Add(icon);
                row.Children.Add(lines);
                if (_steps.Children.Count > 0) _steps.Children.Add(new Border { Height = 1, Background = Line, Margin = new Thickness(20, 2, 0, 0) });
                _steps.Children.Add(row);
                _current = (icon, lines);
                _now.Text = text;
                _bar.Value = Math.Min(_bar.Maximum - 0.5, ++_stepCount);
                break;
            case 'O' or 'I':
                _current?.Lines.Children.Add(T(text, 11.5, null, kind == 'O' ? Text2 : Muted));
                break;
            case 'W':
                if (_current is { } w) { Mark(w.Icon, "", Warn); w.Lines.Children.Add(T(text, 11.5, null, Warn)); }
                else _steps.Children.Add(T(text, 11.5, null, Warn));
                break;
            case 'E':
                if (_current is { } e) Mark(e.Icon, "", Danger);
                _steps.Children.Add(T(text, 12, FontWeight.SemiBold, Danger).Also(t => t.Margin = new Thickness(20, 6, 0, 0)));
                break;
        }
        _stepsScroll.ScrollToEnd();
    }

    private static void Mark(TextBlock icon, string glyph, IBrush color) { icon.Text = glyph; icon.Foreground = color; }

    // ---- page 3: result -------------------------------------------------------------------------------

    private void ShowResult(int rc)
    {
        _working = false;
        _done = true;
        _exit = rc;
        if (_current is { } last && last.Icon.Text == "") Mark(last.Icon, rc == 0 ? "" : "", rc == 0 ? Ok : Warn);
        _bar.Value = _bar.Maximum;
        var install = _c.Mode == SetupMode.Install;
        var (glyph, color, head, sub) = (install, rc) switch
        {
            (true, 0) => ("", Ok, "FreeEDR is installed and running", "Every protection part was checked. The shield is in the notification area and \"FreeEDR\" is in the Start menu."),
            (true, 3) => ("", Warn, "The previous version was restored", "The new version did not pass its checks, so the earlier one is running again. Details are in install.log."),
            (true, _) => ("", Danger, "Installation failed", "Nothing was left half-done that the uninstaller cannot remove. Details are in install.log."),
            (false, 0) => ("", Ok, "FreeEDR was removed", "The Windows settings it changed were put back."),
            _ => ("", Warn, "FreeEDR was removed, with warnings", "Some steps need a look: see the list above and FreeEDR-uninstall.log in %TEMP%."),
        };
        var banner = new Border
        {
            Classes = { "banner" }, Background = Tint(color, 0x1E), BorderBrush = Tint(color, 0x60), Margin = new Thickness(0, 10, 0, 0),
            Child = new DockPanel
            {
                Children =
                {
                    new TextBlock { Text = glyph, FontFamily = new FontFamily(IconFont), FontSize = 20, Foreground = color, VerticalAlignment = VerticalAlignment.Top, Margin = new Thickness(0, 0, 12, 0) }.Also(i => DockPanel.SetDock(i, Dock.Left)),
                    Stack(2, T(head, 14, FontWeight.SemiBold), T(sub, 12, null, Text2), T(install ? _c.Paths.InstallLog : Path.Combine(Path.GetTempPath(), "FreeEDR-uninstall.log"), 11, null, Muted)),
                },
            },
        };
        if (_page.Content is DockPanel d)
        {
            var close = Btn("Close", "primary", () => { _done = true; Finished?.Invoke(_exit); });
            var foot = Footer(close);
            d.Children.Insert(0, foot);
            DockPanel.SetDock(banner, Dock.Bottom);
            d.Children.Insert(1, banner);
        }
    }

    // ---- small helpers (theme classes from Theme.axaml) ------------------------------------------------

    private static DockPanel Layout(Control top, Control fill)
    {
        var d = new DockPanel();
        if (top is not ScrollViewer) { DockPanel.SetDock(top, Dock.Top); d.Children.Add(top); d.Children.Add(fill); }
        else
        {
            // choose page: content fills, footer docked at the bottom
            DockPanel.SetDock(fill, Dock.Bottom);
            d.Children.Add(fill);
            d.Children.Add(top);
        }
        return d;
    }

    private static Control Footer(params Button[] buttons)
    {
        var r = Row(8, buttons);
        r.HorizontalAlignment = HorizontalAlignment.Right;
        r.Margin = new Thickness(0, 12, 0, 0);
        DockPanel.SetDock(r, Dock.Bottom);
        return r;
    }

    private static Button Btn(string label, string classes, Action click)
    {
        var b = new Button { Content = label, MinWidth = 96, HorizontalContentAlignment = HorizontalAlignment.Center };
        foreach (var c in classes.Split(' ', StringSplitOptions.RemoveEmptyEntries)) b.Classes.Add(c);
        b.Click += (_, _) => click();
        return b;
    }

    private static TextBlock T(string text, double size = 12.5, FontWeight? weight = null, IBrush? fg = null)
    {
        var t = new TextBlock { Text = text, FontSize = size, TextWrapping = TextWrapping.Wrap };
        if (weight is { } w) t.FontWeight = w;
        if (fg is not null) t.Foreground = fg;
        return t;
    }

    private static StackPanel Stack(double spacing, params Control[] c) { var s = new StackPanel { Spacing = spacing }; foreach (var x in c) s.Children.Add(x); return s; }

    private static StackPanel Row(double spacing, params Control[] c) { var s = new StackPanel { Orientation = Orientation.Horizontal, Spacing = spacing }; foreach (var x in c) s.Children.Add(x); return s; }

    private static IBrush Brush(string hex) => new SolidColorBrush(Color.Parse(hex));

    private static IBrush Tint(IBrush b, byte a) => b is SolidColorBrush s ? new SolidColorBrush(Color.FromArgb(a, s.Color.R, s.Color.G, s.Color.B)) : b;
}

internal static class ControlExtensions
{
    public static T Also<T>(this T c, Action<T> a) { a(c); return c; }
}
