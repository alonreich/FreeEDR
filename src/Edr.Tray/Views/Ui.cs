using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Layout;
using Avalonia.Media;
using Edr.Core;

namespace Edr.Tray.Views;

/// <summary>Colors of the theme (same values as Theme.axaml) for code-built views.</summary>
public static class Palette
{
    public static readonly IBrush Bg = Brush("#172238");
    public static readonly IBrush Surface = Brush("#1E2C47");
    public static readonly IBrush SurfaceHi = Brush("#263859");
    public static readonly IBrush SurfaceLo = Brush("#1A2740");
    public static readonly IBrush Line = Brush("#2D3F66");
    public static readonly IBrush Text = Brush("#EAF0FB");
    public static readonly IBrush Text2 = Brush("#AEBBD3");
    public static readonly IBrush Muted = Brush("#7E8DA9");
    public static readonly IBrush Accent = Brush("#4F8EFF");
    public static readonly IBrush Ok = Brush("#2FBF71");
    public static readonly IBrush Warn = Brush("#F5A524");
    public static readonly IBrush Danger = Brush("#F0505F");
    public static readonly IBrush Paused = Brush("#8C99B1");
    public static readonly IBrush Info = Brush("#3AB8E8");

    public static IBrush Brush(string hex) => new SolidColorBrush(Color.Parse(hex));

    public static IBrush Tint(IBrush b, byte alpha) => b is SolidColorBrush s ? new SolidColorBrush(Color.FromArgb(alpha, s.Color.R, s.Color.G, s.Color.B)) : b;

    public static IBrush ForSeverity(string sev) => sev.ToLowerInvariant() switch
    {
        "critical" => Danger, "high" => Brush("#FF7A45"), "medium" => Warn, "low" => Info, _ => Muted,
    };

    public static IBrush ForState(string key) => key switch { "ok" => Ok, "attention" => Warn, "paused" => Paused, _ => Danger };
}

/// <summary>Small factory helpers so the code-built views stay readable.</summary>
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
        if (icon is not null && content is StackPanel sp && sp.Children[0] is TextBlock ic) ic.Foreground = classes.Contains("primary") || classes.Contains("ok") || classes.Contains("danger") ? Brushes.White : Palette.Text2;
        b.Click += (_, _) => onClick();
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
        Child = new TextBlock { Text = text, FontSize = 11.5, FontWeight = FontWeight.SemiBold, Foreground = solid ? Brushes.White : color, TextWrapping = TextWrapping.NoWrap },
        VerticalAlignment = VerticalAlignment.Center,
    };

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

    /// <summary>"ddd dd/MM HH:mm" relative to today ("Today 14:02", "Yesterday 09:10").</summary>
    public static string When(string time)
    {
        if (Ps.ToDate(time) is not { } d) return time;
        var days = (DateTime.Today - d.Date).Days;
        return days switch { 0 => $"Today {d:HH:mm}", 1 => $"Yesterday {d:HH:mm}", < 7 and > 1 => $"{d:ddd HH:mm}", _ => $"{d:dd MMM yyyy}" };
    }

    public static string Plural(int n, string word) => $"{n} {word}{(n == 1 ? "" : "s")}";
}

/// <summary>A list row with display text derived from the model row.</summary>
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
                case "hist": return "Update started from FreeEDR";
                case "app": return $"{Row.Entry?.S("version")}  ->  {Row.Entry?.S("latest")}   ({Row.Entry?.S("appId")})";
                case "hidden": return "Hidden from the update list";
                case "sys": return Row.Cols.ElementAtOrDefault(2) ?? "";
            }
            if (e is null) return "";
            var blade = Catalog.BladeNames.GetValueOrDefault(e.S("blade")) ?? e.S("blade");
            var proc = Ps.Eq(e.S("blade"), "sigma") ? SigmaProcess.Of(e).Image : e.S("process");
            var par = ActionBuilder.ParentOf(e);
            var parts = new List<string> { blade };
            if (Ps.Eq(e.S("blade"), "wail2ban")) parts.Add(Ip.NetLabel(e.S("ip")));
            if (proc.Length > 0) parts.Add(Ps.Leaf(proc));
            if (par.Length > 0) parts.Add("started by " + Ps.Leaf(par));
            return string.Join("  -  ", parts);
        }
    }

    public string Time => Row.Kind is "excl" ? Row.Entry?.S("added") ?? "" : Row.Time;
    public string Severity => Row.Kind is "cve" or "event" or "defender" or "sys" ? (Row.Ev?.S("severity") is { Length: > 0 } s ? s : Row.Sev) : Row.Sev;
}

/// <summary>The visual of one list row; updates itself when a recycled container gets a new item (no reflection bindings).</summary>
public sealed class RowView : Border
{
    private readonly Border _bar = new() { Width = 4, CornerRadius = new CornerRadius(11, 0, 0, 11) };
    private readonly TextBlock _title = new() { FontWeight = FontWeight.SemiBold, FontSize = 13.5, TextWrapping = TextWrapping.NoWrap, TextTrimming = TextTrimming.CharacterEllipsis };
    private readonly TextBlock _sub = new() { FontSize = 12.5, Foreground = Palette.Text2, TextWrapping = TextWrapping.NoWrap, TextTrimming = TextTrimming.CharacterEllipsis };
    private readonly TextBlock _time = new() { FontSize = 12, Foreground = Palette.Muted, TextWrapping = TextWrapping.NoWrap, HorizontalAlignment = HorizontalAlignment.Right };
    private readonly StackPanel _badges = new() { Orientation = Orientation.Horizontal, Spacing = 6, HorizontalAlignment = HorizontalAlignment.Right };

    protected override Type StyleKeyOverride => typeof(Border);   // themed as a Border ("Border.row")

    public RowView()
    {
        Classes.Add("row");
        var grid = new Grid { ColumnDefinitions = new ColumnDefinitions("4,*,Auto"), MinHeight = 58 };
        grid.Children.Add(_bar);
        var mid = new StackPanel { Spacing = 3, Margin = new Thickness(14, 10, 10, 10), VerticalAlignment = VerticalAlignment.Center, Children = { _title, _sub } };
        Grid.SetColumn(mid, 1);
        grid.Children.Add(mid);
        var right = new StackPanel { Spacing = 6, Margin = new Thickness(0, 10, 14, 10), VerticalAlignment = VerticalAlignment.Center, Children = { _time, _badges } };
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
        var sev = it.Severity;
        _bar.Background = it.Row.Pinned && !it.Row.Muted ? Palette.Warn : sev.Length > 0 ? Palette.ForSeverity(sev) : Palette.Line;
        _badges.Children.Clear();
        if (it.Row.Pinned && !it.Row.Muted) _badges.Children.Add(Ui.Pill("Was this you?", Palette.Warn));
        else if (sev.Length > 0 && it.Row.Kind is "event" or "cve" or "defender") _badges.Children.Add(Ui.Pill(sev, Palette.ForSeverity(sev)));
        if (it.Row.Muted && it.Row.Kind is "event" or "fail") _badges.Children.Add(Ui.Pill("Reviewed", Palette.Muted));
        if (it.Row.Kind == "excl" && it.Row.Entry?.T("profile") == true) _badges.Children.Add(Ui.Pill("Trusted app", Palette.Ok));
        if (it.Row.Kind == "ban") _badges.Children.Add(Ui.Pill(it.Row.Entry is not null ? "Permanent" : "Blocked", Palette.Danger));
        if (it.Row.Muted) Classes.Add("muted"); else Classes.Remove("muted");
        _time.IsVisible = _time.Text?.Length > 0;
    }
}
