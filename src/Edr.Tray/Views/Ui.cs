using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Layout;
using Avalonia.Media;
using Edr.Core;

namespace Edr.Tray.Views;

public static class Palette
{
    public static bool IsLight { get; private set; }

    private static readonly List<(SolidColorBrush Brush, Color Dark, Color Light)> All = [];

    private static SolidColorBrush Themed(string dark, string light)
    {
        var b = new SolidColorBrush(Color.Parse(dark));
        All.Add((b, Color.Parse(dark), Color.Parse(light)));
        return b;
    }

    public static readonly SolidColorBrush Bg = Themed("#172238", "#EEF2F8");
    public static readonly SolidColorBrush Sidebar = Themed("#121B2E", "#E3E9F3");
    public static readonly SolidColorBrush Surface = Themed("#1E2C47", "#FFFFFF");
    public static readonly SolidColorBrush SurfaceHi = Themed("#263859", "#F0F4FA");
    public static readonly SolidColorBrush SurfaceLo = Themed("#1A2740", "#F6F8FC");
    public static readonly SolidColorBrush Line = Themed("#2D3F66", "#D0D9E8");
    public static readonly SolidColorBrush Text = Themed("#EAF0FB", "#142033");
    public static readonly SolidColorBrush Text2 = Themed("#AEBBD3", "#384867");
    public static readonly SolidColorBrush Muted = Themed("#95A3BD", "#56647E");
    public static readonly SolidColorBrush Accent = Themed("#4F8EFF", "#2563D9");
    public static readonly SolidColorBrush Ok = Themed("#2FBF71", "#1B8048");
    public static readonly SolidColorBrush Warn = Themed("#F5A524", "#9A5B00");
    public static readonly SolidColorBrush Danger = Themed("#F0505F", "#C42F3D");
    public static readonly SolidColorBrush ErrorText = Themed("#FF8A95", "#B42634");
    public static readonly SolidColorBrush Paused = Themed("#8C99B1", "#66728A");
    public static readonly SolidColorBrush Info = Themed("#3AB8E8", "#1874A3");
    public static readonly SolidColorBrush BadgeNeutral = Themed("#3B5487", "#4A5F8C");
    public static readonly SolidColorBrush BadgeWarn = Themed("#8A5A12", "#8A5000");
    public static readonly SolidColorBrush OkButtonText = Themed("#7FD6AA", "#146B3A");
    public static readonly SolidColorBrush DangerButtonText = Themed("#F09AA4", "#A3202E");
    public static readonly SolidColorBrush PrimaryButtonText = Themed("#FFFFFF", "#FFFFFF");

    public static void Apply(bool light)
    {
        IsLight = light;
        foreach (var (b, dark, lt) in All) b.Color = light ? lt : dark;
    }

    public static IBrush Brush(string hex) => new SolidColorBrush(Color.Parse(hex));

    public static IBrush Tint(IBrush b, byte alpha) => b is SolidColorBrush s ? new SolidColorBrush(Color.FromArgb(alpha, s.Color.R, s.Color.G, s.Color.B)) : b;

    public static IBrush ForSeverity(string sev) => sev.ToLowerInvariant() switch
    {
        "critical" => Danger, "high" => Brush("#FF7A45"), "medium" => Warn, "low" => Info, _ => Muted,
    };

    public static IBrush ForState(string key) => key switch { "ok" => Ok, "attention" => Warn, "paused" => Paused, _ => Danger };

    public static IBrush ForModule(string? blade) => (blade ?? "").ToLowerInvariant() switch
    {
        "realtime" => Brush("#6E9BF0"), "ioc" or "yara" => Brush("#B48CF0"), "defender" => Brush("#5CB3E6"),
        "sigma" => Brush("#4DBFA8"), "wail2ban" => Brush("#E0A74A"), "cve" or "patch" => Brush("#9AA9C4"), _ => Muted,
    };
}

public static class Ui
{
    public const string IconFont = "Segoe Fluent Icons, Segoe MDL2 Assets";

    public static TextBlock T(string text, string classes = "", double? size = null, IBrush? fg = null, FontWeight? weight = null)
    {
        var t = new TextBlock { Text = text };
        foreach (var c in classes.Split(' ', StringSplitOptions.RemoveEmptyEntries)) t.Classes.Add(c);
        if (size is { } s) t.FontSize = s;
        if (fg is not null) t.Foreground = fg;
        if (weight is { } w) t.FontWeight = w;
        return t;
    }

    public static TextBlock Icon(string glyph, double size = 16, IBrush? fg = null) =>
        new() { Text = glyph, FontFamily = new FontFamily(IconFont), FontSize = size, Foreground = fg ?? Palette.Text2, VerticalAlignment = VerticalAlignment.Center, TextWrapping = TextWrapping.NoWrap };

    public static Button Btn(string label, string classes, Action onClick, string? icon = null, string? tip = null)
    {
        object content = label;
        if (icon is not null)
            content = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Children = { Icon(icon, 14, null), new TextBlock { Text = label, VerticalAlignment = VerticalAlignment.Center, TextWrapping = TextWrapping.NoWrap } } };
        var b = new Button { Content = content };
        foreach (var c in classes.Split(' ', StringSplitOptions.RemoveEmptyEntries)) b.Classes.Add(c);
        if (icon is not null && content is StackPanel sp && sp.Children[0] is TextBlock ic) ic.Foreground = classes.Contains("primary") ? Palette.PrimaryButtonText : classes.Contains("ok") ? Palette.OkButtonText : classes.Contains("danger") ? Palette.DangerButtonText : Palette.Text2;
        b.Click += (_, _) => onClick();
        Avalonia.Automation.AutomationProperties.SetName(b, label);
        if (tip is not null) ToolTip.SetTip(b, tip);
        return b;
    }

    public static Border Card(Control child, string classes = "card", Thickness? margin = null)
    {
        var b = new Border { Child = child };
        foreach (var c in classes.Split(' ', StringSplitOptions.RemoveEmptyEntries)) b.Classes.Add(c);
        if (margin is { } m) b.Margin = m;
        return b;
    }

    public static Border Pill(string text, IBrush color, bool solid = false) => new()
    {
        Classes = { "pill" },
        Background = solid ? color : Palette.Tint(color, 0x2E),
        BorderBrush = Palette.Tint(color, 0x80),
        BorderThickness = new Thickness(1),
        Child = new TextBlock { Text = text, FontSize = 10.5, FontWeight = FontWeight.SemiBold, Foreground = solid ? Brushes.White : color, TextWrapping = TextWrapping.NoWrap },
        VerticalAlignment = VerticalAlignment.Center,
    };

    public static Border ModuleTag(string? blade)
    {
        var color = Palette.ForModule(blade);
        return new Border
        {
            CornerRadius = new CornerRadius(4), Padding = new Thickness(6, 1), Background = Palette.Tint(color, 0x24), VerticalAlignment = VerticalAlignment.Center,
            Child = new TextBlock { Text = Catalog.Module(blade).Name.ToUpperInvariant(), FontSize = 10, FontWeight = FontWeight.SemiBold, LetterSpacing = 0.4, Foreground = color, TextWrapping = TextWrapping.NoWrap },
        };
    }

    public static Border Dot(IBrush color, double size = 10) => new() { Width = size, Height = size, CornerRadius = new CornerRadius(size / 2), Background = color, VerticalAlignment = VerticalAlignment.Center };

    public static StackPanel Stack(double spacing = 10, params Control[] children)
    {
        var s = new StackPanel { Spacing = spacing };
        foreach (var c in children) s.Children.Add(c);
        return s;
    }

    public static StackPanel Row(double spacing = 10, params Control[] children)
    {
        var s = new StackPanel { Orientation = Orientation.Horizontal, Spacing = spacing };
        foreach (var c in children) s.Children.Add(c);
        return s;
    }

    public static WrapPanel Wrap(params Control[] children)
    {
        var w = new WrapPanel { Orientation = Orientation.Horizontal };
        foreach (var c in children) { c.Margin = new Thickness(0, 0, 8, 8); w.Children.Add(c); }
        return w;
    }

    public static ToggleButton Chip(string label, bool on, Action<bool> changed)
    {
        var t = new ToggleButton { Content = label, IsChecked = on };
        t.Classes.Add("chip");
        t.IsCheckedChanged += (_, _) => changed(t.IsChecked == true);
        return t;
    }

    public static string When(string time)
    {
        if (Ps.ToDate(time) is not { } d) return time;
        var days = (DateTime.Today - d.Date).Days;
        return days switch { 0 => $"Today {d:HH:mm}", 1 => $"Yesterday {d:HH:mm}", < 7 and > 1 => $"{d:ddd HH:mm}", _ => $"{d:dd MMM yyyy}" };
    }

    public static string Plural(int n, string word) => $"{n} {word}{(n == 1 ? "" : "s")}";

    public static string Fingerprint(object? root)
    {
        var sb = new System.Text.StringBuilder();
        Walk(root, sb);
        return sb.ToString();
    }

    private static void Walk(object? o, System.Text.StringBuilder sb)
    {
        if (o is null) return;
        if (o is not Control c) { sb.Append('"').Append(o).Append('"'); return; }
        sb.Append('<').Append(c.GetType().Name);
        if (!c.IsVisible) sb.Append(" hidden");
        if (!c.IsEnabled) sb.Append(" disabled");
        foreach (var cl in c.Classes) sb.Append(" .").Append(cl);
        if (c is TextBlock t) sb.Append(" \"").Append(t.Text).Append('"').Append(t.Foreground is SolidColorBrush f ? f.Color.ToString() : "");
        if (c is TextBox tb) sb.Append(" \"").Append(tb.Text).Append('"');
        if (c is ToggleButton tg) sb.Append(tg.IsChecked == true ? " on" : " off");
        if (c is NumericUpDown n) sb.Append(' ').Append(n.Value);
        if (c is SelectingItemsControl si) sb.Append(" #").Append(si.SelectedIndex);
        if (c is Border { Background: SolidColorBrush bg }) sb.Append(' ').Append(bg.Color.ToString());
        if (c is Expander ex) { sb.Append(ex.IsExpanded ? " open" : " closed"); Walk(ex.Header, sb); }
        sb.Append('>');
        switch (c)
        {
            case Panel p: foreach (var ch in p.Children) Walk(ch, sb); break;
            case Decorator d: Walk(d.Child, sb); break;
            case ContentControl cc: Walk(cc.Content, sb); break;
        }
        sb.Append("</>");
    }
}

public sealed class RowItem(Row row)
{
    public Row Row { get; } = row;

    public string Title => Row.Kind switch
    {
        "excl" or "builtin" => Row.Note,
        "block" => Row.Entry is { } b ? (b.T("image") ? Ps.Leaf(b.S("image")) : b.T("ip") ? b.S("ip") : b.S("title")) : Row.Cols.ElementAtOrDefault(1) ?? "",
        "defender" => Row.Cols.ElementAtOrDefault(1) ?? "",
        "fail" => $"{Row.Cols.ElementAtOrDefault(1)}  -  {Row.Cols.ElementAtOrDefault(2)}",
        "ban" or "banhist" => Row.Cols.ElementAtOrDefault(1) ?? "",
        "cve" => $"{Row.Entry?.S("cve")} in {Row.Entry?.S("package")} {Row.Entry?.S("version")}",
        "hist" => Row.Entry?.T("cve") == true ? $"{Row.Entry.S("cve")} in {Row.Entry.S("package")}" : Row.Entry?.S("name") ?? "",
        "app" => Row.Entry?.S("process") ?? "",
        "hidden" => Row.EntryId ?? "",
        "sys" => Row.Cols.ElementAtOrDefault(1) ?? "",
        _ => (Row.Ev?.S("title") ?? "") + (Row.Group.Count > 1 ? $"   ×{Row.Group.Count}" : ""),
    };

    public string Subtitle
    {
        get
        {
            var e = Row.Ev;
            switch (Row.Kind)
            {
                case "excl": return ModelBuilder.ExclType(Row.ExclList, Row.Entry!);
                case "builtin": return "Built into the Sysmon configuration";
                case "block": return Row.Entry?.S("note") ?? "";
                case "defender": return "Handled by Microsoft Defender  -  " + (Row.Cols.ElementAtOrDefault(2) ?? "");
                case "fail": return Row.Cols.ElementAtOrDefault(3) ?? "";
                case "ban": return $"{Row.Cols.ElementAtOrDefault(5)}  -  until {Row.Cols.ElementAtOrDefault(2)}  -  {Row.Cols.ElementAtOrDefault(4)}";
                case "banhist": return $"{Row.Cols.ElementAtOrDefault(2)}  -  {Row.Cols.ElementAtOrDefault(4)}";
                case "cve": return $"Fixed in {Row.Entry?.S("fixed")}  -  {Row.Entry?.S("summary")}";
                case "hist": return "Started from FreeEDR - the next check shows whether it worked";
                case "app": return $"{Row.Entry?.S("version")}  ->  {Row.Entry?.S("latest")}   ({Row.Entry?.S("appId")})";
                case "hidden": return "Hidden from the update list";
                case "sys": return Row.Cols.ElementAtOrDefault(2) ?? "";
            }
            if (e is null) return "";
            if (Ps.Eq(e.S("blade"), "wail2ban")) return $"{e.S("ip")}  ·  {Ip.NetLabel(e.S("ip"))}".Trim(' ', '·');
            var proc = Ps.Eq(e.S("blade"), "sigma") ? SigmaProcess.Of(e).Image : e.S("process");
            var par = ActionBuilder.ParentOf(e);
            if (proc.Length == 0) return "";
            return par.Length > 0 ? $"{Ps.Leaf(proc)}  ←  {Ps.Leaf(par)}" : Ps.Leaf(proc);
        }
    }

    public string Time => Row.Kind is "excl" ? Row.Entry?.S("added") ?? "" : Row.Time;
    public string Severity => Row.Kind is "cve" or "event" or "defender" or "sys" ? (Row.Ev?.S("severity") is { Length: > 0 } s ? s : Row.Sev) : Row.Sev;
}

public sealed class RowView : Border
{
    private readonly Border _bar = new() { Width = 3, CornerRadius = new CornerRadius(8, 0, 0, 8) };
    private readonly ContentControl _tag = new() { VerticalAlignment = VerticalAlignment.Center };
    private readonly TextBlock _title = new() { FontWeight = FontWeight.SemiBold, FontSize = 12.5, TextWrapping = TextWrapping.NoWrap, TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center };
    private readonly TextBlock _sub = new() { FontSize = 11.5, Foreground = Palette.Text2, TextWrapping = TextWrapping.NoWrap, TextTrimming = TextTrimming.CharacterEllipsis };
    private readonly TextBlock _time = new() { FontSize = 11, Foreground = Palette.Muted, TextWrapping = TextWrapping.NoWrap, HorizontalAlignment = HorizontalAlignment.Right };
    private readonly StackPanel _badges = new() { Orientation = Orientation.Horizontal, Spacing = 4, HorizontalAlignment = HorizontalAlignment.Right };

    protected override Type StyleKeyOverride => typeof(Border);

    public RowView()
    {
        Classes.Add("row");
        var grid = new Grid { ColumnDefinitions = new ColumnDefinitions("3,*,Auto"), MinHeight = 44 };
        grid.Children.Add(_bar);
        var line1 = new DockPanel();
        _tag.Margin = new Thickness(0, 0, 8, 0);
        DockPanel.SetDock(_tag, Dock.Left);
        line1.Children.Add(_tag);
        line1.Children.Add(_title);
        var mid = new StackPanel { Spacing = 2, Margin = new Thickness(10, 6, 8, 6), VerticalAlignment = VerticalAlignment.Center, Children = { line1, _sub } };
        Grid.SetColumn(mid, 1);
        grid.Children.Add(mid);
        var right = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Margin = new Thickness(0, 6, 10, 6), VerticalAlignment = VerticalAlignment.Center, Children = { _badges, _time } };
        _time.VerticalAlignment = VerticalAlignment.Center;
        Grid.SetColumn(right, 2);
        grid.Children.Add(right);
        Child = grid;
    }

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);
        if (DataContext is not RowItem it) return;
        _title.Text = ModelBuilder.Short(it.Title, 200);
        _sub.Text = ModelBuilder.Short(it.Subtitle, 260);
        _sub.IsVisible = it.Subtitle.Length > 0;
        _time.Text = Ui.When(it.Time);
        var blade = it.Row.Ev?.S("blade");
        _tag.Content = blade is { Length: > 0 } && it.Row.Kind is "event" or "fail" or "defender" or "cve" or "sys" ? Ui.ModuleTag(blade) : null;
        _tag.IsVisible = _tag.Content is not null;
        var sev = it.Severity;
        _bar.Background = it.Row.Pinned && !it.Row.Muted ? Palette.Warn : sev.Length > 0 ? Palette.ForSeverity(sev) : Palette.Line;
        _badges.Children.Clear();
        if (it.Row.Pinned && !it.Row.Muted) _badges.Children.Add(Ui.Pill("Was this you?", Palette.Warn));
        else if (sev.Length > 0 && it.Row.Kind is "event" or "cve" or "defender") _badges.Children.Add(Ui.Pill(sev, Palette.ForSeverity(sev)));
        if (it.Row.Muted && it.Row.Kind is "event" or "fail") _badges.Children.Add(Ui.Pill("Reviewed", Palette.Muted));
        if (it.Row.Kind == "excl" && it.Row.Entry?.T("profile") == true) _badges.Children.Add(Ui.Pill("Trusted app", Palette.Ok));
        if (it.Row.Kind == "ban") _badges.Children.Add(Ui.Pill(it.Row.Entry is not null ? "Permanent" : "Blocked", Palette.Danger));
        if (it.Row.Muted) Classes.Add("muted"); else Classes.Remove("muted");
        _title.FontWeight = it.Row.Muted ? FontWeight.Normal : FontWeight.SemiBold;
        _title.Foreground = it.Row.Muted ? Palette.Text2 : Palette.Text;
        _time.IsVisible = _time.Text?.Length > 0;
    }
}
