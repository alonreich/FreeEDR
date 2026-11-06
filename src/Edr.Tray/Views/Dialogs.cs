using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Edr.Core;

namespace Edr.Tray.Views;

/// <summary>Styled confirmation / message / input dialogs (the same look as the dashboard).</summary>
public static class Dialogs
{
    public static Window? Owner { get; set; }

    private static Window NewDialog(string title, double width = 480) => new()
    {
        Title = title,
        Width = width,
        SizeToContent = SizeToContent.Height,
        CanResize = false,
        ShowInTaskbar = Owner is not { IsVisible: true },
        WindowStartupLocation = Owner is { IsVisible: true } ? WindowStartupLocation.CenterOwner : WindowStartupLocation.CenterScreen,
        Icon = ShieldIcon.Create(ShieldState.Protected),
        Topmost = Owner is not { IsVisible: true },
    };

    private static async Task<T> Show<T>(Window w, Func<T> fallback)
    {
        var tcs = new TaskCompletionSource<T>();
        w.Closed += (_, _) => tcs.TrySetResult(w.Tag is T t ? t : fallback());
        if (Owner is { IsVisible: true } o) await w.ShowDialog(o); else w.Show();
        return await tcs.Task;
    }

    /// <summary>Yes/No with a highlighted main button. <paramref name="danger"/> paints it red.</summary>
    public static Task<bool> Confirm(string title, string message, string yes = "Continue", string no = "Cancel", bool danger = false, string? note = null)
    {
        var w = NewDialog(title);
        var body = Ui.Stack(14,
            Ui.Row(12, Ui.Icon(danger ? "" : "", 26, danger ? Palette.Danger : Palette.Accent), Ui.T(title, "h2")),
            Ui.T(message, "sub"));
        if (note is not null) body.Children.Add(new Border { Classes = { "banner" }, Background = Palette.Tint(Palette.Accent, 0x22), BorderBrush = Palette.Tint(Palette.Accent, 0x66), Child = Ui.T(note, "muted") });
        var yesBtn = Ui.Btn(yes, danger ? "danger" : "primary", () => { w.Tag = true; w.Close(); });
        var noBtn = Ui.Btn(no, "", () => { w.Tag = false; w.Close(); });
        yesBtn.IsDefault = true; noBtn.IsCancel = true;
        body.Children.Add(new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 8, 0, 0), Children = { noBtn, yesBtn } });
        w.Content = new Border { Padding = new Thickness(26, 22), Child = body };
        return Show(w, () => false);
    }

    public static Task<bool> Info(string title, string message, bool error = false)
    {
        var w = NewDialog(title);
        var ok = Ui.Btn("OK", "primary", () => { w.Tag = true; w.Close(); });
        ok.IsDefault = true; ok.IsCancel = true;
        w.Content = new Border
        {
            Padding = new Thickness(26, 22),
            Child = Ui.Stack(14, Ui.Row(12, Ui.Icon(error ? "" : "", 26, error ? Palette.Danger : Palette.Accent), Ui.T(title, "h2")), Ui.T(message, "sub"),
                new StackPanel { HorizontalAlignment = HorizontalAlignment.Right, Children = { ok } }),
        };
        return Show(w, () => true);
    }

    public static Task<string?> Prompt(string title, string message, string initial = "")
    {
        var w = NewDialog(title);
        var box = new TextBox { Text = initial };
        var ok = Ui.Btn("OK", "primary", () => { w.Tag = box.Text ?? ""; w.Close(); });
        var cancel = Ui.Btn("Cancel", "", () => { w.Tag = null; w.Close(); });
        ok.IsDefault = true; cancel.IsCancel = true;
        w.Content = new Border
        {
            Padding = new Thickness(26, 22),
            Child = Ui.Stack(14, Ui.T(title, "h2"), Ui.T(message, "sub"), box,
                new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10, HorizontalAlignment = HorizontalAlignment.Right, Children = { cancel, ok } }),
        };
        w.Opened += (_, _) => box.Focus();
        return Show<string?>(w, () => null);
    }

    /// <summary>Bulleted list of names, at most 8 (Format-NameList).</summary>
    public static string Names(IEnumerable<string> names)
    {
        var u = names.Where(n => n.Length > 0).Distinct().ToList();
        var txt = string.Join("\n", u.Take(8).Select(n => "  •  " + n));
        if (u.Count > 8) txt += $"\n  … and {u.Count - 8} more";
        return txt;
    }
}

/// <summary>First run: what FreeEDR does, which apps to trust, how much to be told (3 steps).</summary>
public sealed class WelcomeWindow : Window
{
    private int _step;
    private readonly ContentControl _host = new();
    private readonly Button _back;
    private readonly Button _next;
    private readonly TextBlock _progress = new() { Foreground = Palette.Muted, FontSize = 12, VerticalAlignment = VerticalAlignment.Center };
    private readonly Dictionary<string, CheckBox> _profiles = new();
    private readonly RadioButton _lvCritical = new() { Content = "Only critical alerts", GroupName = "lv" };
    private readonly RadioButton _lvImportant = new() { Content = "Important alerts (recommended)", GroupName = "lv" };
    private readonly RadioButton _lvAll = new() { Content = "Everything, including medium alerts and scan results", GroupName = "lv" };

    public Dictionary<string, bool> ProfileChoice { get; } = new();
    public string NotifyLevel { get; private set; } = "important";
    public bool Finished { get; private set; }

    public WelcomeWindow(Func<string, bool> profileOn, string level)
    {
        Title = "Welcome to FreeEDR";
        Width = 720; Height = 560; CanResize = false;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        Icon = ShieldIcon.Create(ShieldState.Protected);
        foreach (var p in Profiles.All.Where(p => p.Default || profileOn(p.Id) || Profiles.IsInstalled(p)))
            _profiles[p.Id] = new CheckBox { IsChecked = profileOn(p.Id), Content = Ui.Stack(2, Ui.T(p.Name, "h3"), Ui.T(p.What, "muted")) };
        (level switch { "critical" => _lvCritical, "all" => _lvAll, _ => _lvImportant }).IsChecked = true;
        _back = Ui.Btn("Back", "ghost", () => Go(-1));
        _next = Ui.Btn("Next", "primary big", () => Go(+1));
        var footer = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto,Auto"), Margin = new Thickness(0, 16, 0, 0) };
        footer.Children.Add(_progress);
        Grid.SetColumn(_back, 1); footer.Children.Add(_back);
        _next.Margin = new Thickness(10, 0, 0, 0);
        Grid.SetColumn(_next, 2); footer.Children.Add(_next);
        var root = new DockPanel { Margin = new Thickness(32, 28) };
        DockPanel.SetDock(footer, Dock.Bottom);
        root.Children.Add(footer);
        root.Children.Add(_host);
        Content = root;
        Render();
    }

    private void Go(int d)
    {
        if (_step == 2 && d > 0)
        {
            foreach (var (id, cb) in _profiles) ProfileChoice[id] = cb.IsChecked == true;
            NotifyLevel = _lvCritical.IsChecked == true ? "critical" : _lvAll.IsChecked == true ? "all" : "important";
            Finished = true;
            Close();
            return;
        }
        _step = Math.Clamp(_step + d, 0, 2);
        Render();
    }

    private void Render()
    {
        _back.IsVisible = _step > 0;
        _next.Content = _step == 2 ? "Finish" : "Next";
        _progress.Text = $"Step {_step + 1} of 3";
        _host.Content = _step switch
        {
            0 => Ui.Stack(16,
                Ui.Row(14, new Image { Source = ShieldIcon.Bitmap(ShieldState.Protected, 96), Width = 56, Height = 56 }, Ui.Stack(2, Ui.T("FreeEDR is watching your PC", "h1"), Ui.T("Free endpoint detection for Windows, built from trusted free tools.", "sub"))),
                Feature("", "It detects and explains - it never gets in your way", "Real-time Sysmon detection, malware fingerprints and YARA, Sigma event-log scans and vulnerability checks. Every alert says in plain words what happened and what to do. FreeEDR never stops, deletes or quarantines anything; Microsoft Defender stays your antivirus."),
                Feature("", "Wail2Ban blocks password guessing", "The one part that acts: computers that keep failing to sign in over Remote Desktop or file sharing are blocked in Windows Firewall for a while. You can switch it to report-only in Settings."),
                Feature("", "You decide", "Allow what you trust, flag what you don't, or simply mark an alert reviewed.")),
            1 => Ui.Stack(12, Ui.T("Which apps do you trust?", "h1"), Ui.T("Trusted apps run without alerts for their normal work. You can change this at any time under Allowed & trusted.", "sub"),
                new ScrollViewer { MaxHeight = 330, Content = Ui.Stack(10, _profiles.Values.Cast<Control>().ToArray()) }),
            _ => Ui.Stack(14, Ui.T("How much should FreeEDR tell you?", "h1"),
                Ui.T("During the first 7 days FreeEDR is learning what is normal on this PC: it only notifies you about critical alerts and then sums up the week.", "sub"),
                Ui.Card(Ui.Stack(10, _lvCritical, _lvImportant, _lvAll))),
        };
    }

    private static Control Feature(string icon, string title, string text) => Ui.Card(
        new DockPanel { Children = { Ui.Icon(icon, 22, Palette.Accent).Also(i => { i.Margin = new Thickness(0, 2, 16, 0); i.VerticalAlignment = VerticalAlignment.Top; DockPanel.SetDock(i, Dock.Left); }), Ui.Stack(4, Ui.T(title, "h3"), Ui.T(text, "sub")) } });
}

internal static class ControlExtensions
{
    public static T Also<T>(this T c, Action<T> a) { a(c); return c; }
}
