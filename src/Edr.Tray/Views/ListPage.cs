using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Controls.Templates;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Edr.Core;

namespace Edr.Tray.Views;

/// <summary>One tab of a list page: rows, or a custom panel.</summary>
public sealed record ListTab(string Label, Func<IEnumerable<Row>> Rows, string Empty, Func<Control>? Custom = null);

/// <summary>
/// A page with a header, tabs (chips), optional part filters, search and "show reviewed", a virtualized list and the
/// details pane. Used by Activity, Network (Wail2Ban) and Updates.
/// The engine refreshes the model every 15 s: a refresh that changes nothing visible leaves the chips, the list and the
/// custom panel alone (keyboard focus, scroll position and edits survive); a real change keeps the scroll position.
/// </summary>
public sealed class ListPage : UserControl
{
    private readonly Controller _c;
    private readonly ListTab[] _tabs;
    private readonly (string Key, string Label)[] _filters;
    private readonly HashSet<string> _activeFilters = [];
    private readonly ListBox _list = new() { SelectionMode = SelectionMode.Multiple };
    private readonly DetailView _detail;
    private readonly TextBox _search = new() { PlaceholderText = "Search", Width = 230 };
    private readonly CheckBox _showReviewed = new() { Content = "Show reviewed", VerticalAlignment = VerticalAlignment.Center };
    private readonly StackPanel _tabBar = new() { Orientation = Orientation.Horizontal, Spacing = 8 };
    private readonly StackPanel _filterBar = new() { Orientation = Orientation.Horizontal, Spacing = 8 };
    private readonly List<ToggleButton> _tabChips = [];
    private readonly List<ToggleButton> _filterChips = [];   // [0] = "All parts"
    private readonly TextBlock _empty = new() { Classes = { "muted" }, HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 60, 0, 0), TextAlignment = TextAlignment.Center };
    private readonly ContentControl _customHost = new();
    private readonly Grid _split;
    private readonly ContentControl _headerExtra = new();
    private int _tab;
    private int _customTab = -1;     // the tab whose custom panel is on screen
    private string? _rowsSig;        // what the list shows (null = rebuild)
    private string? _selectKey;
    private bool _updating;
    private bool _syncing;           // chips are being set from code, not clicked

    public ListPage(Controller c, string title, string subtitle, ListTab[] tabs, (string Key, string Label)[]? filters = null, bool reviewToggle = false)
    {
        _c = c;
        _tabs = tabs;
        _filters = filters ?? [];
        _detail = new DetailView(c);
        _list.ItemTemplate = new FuncDataTemplate<RowItem>((_, _) => new RowView());
        _list.SelectionChanged += (_, _) => { if (!_updating) _detail.Show(Selected()); };
        _search.TextChanged += (_, _) => Fill();
        Avalonia.Automation.AutomationProperties.SetName(_search, $"Search {title}");
        _showReviewed.IsVisible = reviewToggle;
        _showReviewed.IsCheckedChanged += (_, _) => Fill();
        var ctx = new ContextMenu();
        ctx.Opening += (_, _) => BuildMenu(ctx);
        _list.ContextMenu = ctx;

        var header = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto") };
        header.Children.Add(Ui.Stack(4, Ui.T(title, "h1"), Ui.T(subtitle, "sub")));
        Grid.SetColumn(_headerExtra, 1);
        header.Children.Add(_headerExtra);

        var toolbar = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto,Auto"), Margin = new Thickness(0, 4, 0, 0) };
        toolbar.Children.Add(Ui.Stack(10, _tabBar, _filterBar));
        _showReviewed.Margin = new Thickness(12, 0);
        Grid.SetColumn(_showReviewed, 1); toolbar.Children.Add(_showReviewed);
        Grid.SetColumn(_search, 2); toolbar.Children.Add(_search);
        _search.VerticalAlignment = VerticalAlignment.Top;

        var listHost = new Panel { Children = { _list, _empty } };
        _split = new Grid { ColumnDefinitions = new ColumnDefinitions("*,12,400") };
        // The details pane gives way in a small window (42 % of the width, 300-400 px), so the list keeps room for its titles
        _split.SizeChanged += (_, e) =>
        {
            var w = Math.Clamp(Math.Round(e.NewSize.Width * 0.42), 300, 400);
            if (_split.ColumnDefinitions[2].Width.Value != w) _split.ColumnDefinitions[2].Width = new GridLength(w);
        };
        _split.Children.Add(listHost);
        Grid.SetColumn(_detail, 2);
        _split.Children.Add(_detail);

        var body = new Panel { Children = { _split, _customHost } };
        var root = new DockPanel { Margin = new Thickness(20, 16, 20, 14) };
        var top = Ui.Stack(10, header, toolbar);
        top.Margin = new Thickness(0, 0, 0, 10);
        DockPanel.SetDock(top, Dock.Top);
        root.Children.Add(top);
        root.Children.Add(body);
        Content = root;
        CreateChips();
        SyncBars();
    }

    public void SetHeaderExtra(Control? c)
    {
        // Same look as on screen: keep the live control (focus on its button survives the refresh)
        if (c is not null && _headerExtra.Content is Control cur && Ui.Fingerprint(cur) == Ui.Fingerprint(c)) return;
        _headerExtra.Content = c;
    }

    /// <summary>The chips are created once and only updated afterwards, so keyboard focus stays on them.</summary>
    private void CreateChips()
    {
        for (var i = 0; i < _tabs.Length; i++)
        {
            var idx = i;
            var chip = Ui.Chip(_tabs[i].Label, false, on =>
            {
                if (_syncing) return;
                if (on) { _tab = idx; SyncBars(); Fill(); }
                else SyncBars();   // the active tab cannot be switched off
            });
            _tabChips.Add(chip);
            _tabBar.Children.Add(chip);
        }
        if (_filters.Length == 0) return;
        var all = Ui.Chip("All parts", true, on =>
        {
            if (_syncing) return;
            if (on) _activeFilters.Clear();
            SyncBars();
            Fill();
        });
        _filterChips.Add(all);
        _filterBar.Children.Add(all);
        foreach (var (k, label) in _filters)
        {
            var key = k;
            var chip = Ui.Chip(label, false, on =>
            {
                if (_syncing) return;
                if (on) _activeFilters.Add(key); else _activeFilters.Remove(key);
                SyncBars();
                Fill();
            });
            _filterChips.Add(chip);
            _filterBar.Children.Add(chip);
        }
    }

    private void SyncBars()
    {
        _syncing = true;
        try
        {
            for (var i = 0; i < _tabs.Length; i++)
            {
                var count = _tabs[i].Custom is null && i == 0 ? _tabs[i].Rows().Count(r => !r.Muted) : 0;
                var label = count > 0 ? $"{_tabs[i].Label}  {count}" : _tabs[i].Label;
                if (!Equals(_tabChips[i].Content, label)) _tabChips[i].Content = label;
                if (_tabChips[i].IsChecked != (i == _tab)) _tabChips[i].IsChecked = i == _tab;
            }
            _filterBar.IsVisible = _filters.Length > 0 && _tabs[_tab].Custom is null;
            if (_filterChips.Count > 0)
            {
                _filterChips[0].IsChecked = _activeFilters.Count == 0;
                for (var i = 0; i < _filters.Length; i++) _filterChips[i + 1].IsChecked = _activeFilters.Contains(_filters[i].Key);
            }
        }
        finally { _syncing = false; }
    }

    private IReadOnlyList<Row> Selected() => _list.SelectedItems?.OfType<RowItem>().Select(i => i.Row).ToList() ?? [];

    public int TabCount => _tabs.Length;

    public void Select(string? key, int tab = -1)
    {
        if (tab >= 0 && tab < _tabs.Length) _tab = tab;
        _selectKey = key;
        SyncBars();
        Fill();
    }

    /// <summary>First tab, filtered to one part (e.g. "edr" = Real-time); an unknown part shows all parts.</summary>
    public void ShowPart(string part)
    {
        _tab = 0;
        _activeFilters.Clear();
        if (_filters.Any(f => f.Key == part)) _activeFilters.Add(part);
        SyncBars();
    }

    private ScrollViewer? ListScroller => _list.GetVisualDescendants().OfType<ScrollViewer>().FirstOrDefault();

    public void Fill()
    {
        var t = _tabs[_tab];
        _customHost.IsVisible = t.Custom is not null;
        _split.IsVisible = t.Custom is null;
        _search.IsVisible = t.Custom is null;
        if (t.Custom is not null)
        {
            _rowsSig = null;
            var next = t.Custom();
            var cur = _customHost.Content as Control;
            if (_customTab == _tab && cur is not null && Ui.Fingerprint(cur) == Ui.Fingerprint(next)) return;   // nothing changed: keep the live panel
            var keepOffset = _customTab == _tab && cur is ScrollViewer csv ? csv.Offset : (Vector?)null;
            _customHost.Content = next;
            _customTab = _tab;
            if (keepOffset is { } ko && next is ScrollViewer nsv) Dispatcher.UIThread.Post(() => nsv.Offset = ko, DispatcherPriority.Background);
            return;
        }
        _customTab = -1;
        var q = _search.Text?.Trim() ?? "";
        var rows = t.Rows().Where(r => (_showReviewed.IsChecked == true || !r.Muted || _tab != 0 || !_showReviewed.IsVisible) &&
                                       (_activeFilters.Count == 0 || _activeFilters.Contains(r.Sec)) &&
                                       (q.Length == 0 || Matches(r, q))).Select(r => new RowItem(r)).ToList();
        _empty.Text = t.Empty;
        _empty.IsVisible = rows.Count == 0;
        var sig = _tab + "\n" + string.Join("\n", rows.Select(Signature));
        if (sig == _rowsSig && _selectKey is null)
        {
            _detail.Show(Selected());   // same rows: the list and its focus stay; the pane updates only if it changed
            return;
        }
        var sameTab = _rowsSig is not null && _rowsSig.StartsWith(_tab + "\n", StringComparison.Ordinal);
        _rowsSig = sig;
        var offset = sameTab && _selectKey is null ? ListScroller?.Offset : null;
        var keep = _selectKey is not null ? [_selectKey] : Selected().Select(r => r.Key).ToHashSet();
        _updating = true;
        _list.ItemsSource = rows;
        _list.SelectedItems?.Clear();
        foreach (var it in rows.Where(it => keep.Contains(it.Row.Key) || (_selectKey is not null && it.Row.Group.Any(g => g.S("id") == _selectKey)))) _list.SelectedItems?.Add(it);
        _updating = false;
        if (_selectKey is not null && _list.SelectedItems?.Count > 0) _list.ScrollIntoView(_list.SelectedItems[0]!);
        else if (offset is { } o) Dispatcher.UIThread.Post(() => { if (ListScroller is { } sv) sv.Offset = o; }, DispatcherPriority.Background);
        _selectKey = null;
        _detail.Show(Selected());
    }

    /// <summary>Everything a row shows (and every fact its actions depend on), for the "anything changed?" test.</summary>
    private static string Signature(RowItem it)
    {
        var r = it.Row;
        return $"{r.Key}|{r.Kind}|{r.Muted}|{r.Pinned}|{r.Group.Count}|{it.Time}|{it.Severity}|{it.Title}|{it.Subtitle}|{r.Entry?.T("profile")}";
    }

    private static bool Matches(Row r, string q)
    {
        var it = new RowItem(r);
        bool Has(string? s) => s?.Contains(q, StringComparison.OrdinalIgnoreCase) == true;
        return Has(it.Title) || Has(it.Subtitle) || Has(r.Ev?.S("detail")) || Has(r.Ev?.S("process")) || r.Cols.Any(Has);
    }

    private void BuildMenu(ContextMenu menu)
    {
        var rows = Selected();
        var items = new List<MenuItem>();
        foreach (var a in _c.ActionsFor(rows))
        {
            var mi = new MenuItem { Header = a.Label, IsEnabled = a.Enabled, FontWeight = a.Primary ? FontWeight.SemiBold : FontWeight.Normal };
            mi.Click += (_, _) => _ = _c.Run(a, rows);
            items.Add(mi);
        }
        menu.ItemsSource = items;
    }

    public void Refresh()
    {
        SyncBars();
        Fill();
    }
}
