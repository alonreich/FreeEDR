using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Templates;
using Avalonia.Layout;
using Avalonia.Media;
using Edr.Core;

namespace Edr.Tray.Views;

/// <summary>One tab of a list page: rows, or a custom panel.</summary>
public sealed record ListTab(string Label, Func<IEnumerable<Row>> Rows, string Empty, Func<Control>? Custom = null);

/// <summary>
/// A page with a header, tabs (chips), optional part filters, search and "show reviewed", a virtualized list and the
/// details pane. Used by Activity, Network (Wail2Ban) and Updates.
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
    private readonly TextBlock _empty = new() { Classes = { "muted" }, HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 60, 0, 0), TextAlignment = TextAlignment.Center };
    private readonly ContentControl _customHost = new();
    private readonly Grid _split;
    private readonly ContentControl _headerExtra = new();
    private int _tab;
    private string? _selectKey;
    private bool _updating;

    public ListPage(Controller c, string title, string subtitle, ListTab[] tabs, (string Key, string Label)[]? filters = null, bool reviewToggle = false)
    {
        _c = c;
        _tabs = tabs;
        _filters = filters ?? [];
        _detail = new DetailView(c);
        _list.ItemTemplate = new FuncDataTemplate<RowItem>((_, _) => new RowView());
        _list.SelectionChanged += (_, _) => { if (!_updating) _detail.Show(Selected()); };
        _search.TextChanged += (_, _) => Fill();
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
        _split = new Grid { ColumnDefinitions = new ColumnDefinitions("*,16,420") };
        _split.Children.Add(listHost);
        Grid.SetColumn(_detail, 2);
        _split.Children.Add(_detail);

        var body = new Panel { Children = { _split, _customHost } };
        var root = new DockPanel { Margin = new Thickness(28, 24, 28, 20) };
        var top = Ui.Stack(16, header, toolbar);
        top.Margin = new Thickness(0, 0, 0, 16);
        DockPanel.SetDock(top, Dock.Top);
        root.Children.Add(top);
        root.Children.Add(body);
        Content = root;
        BuildBars();
    }

    public void SetHeaderExtra(Control? c) => _headerExtra.Content = c;

    private void BuildBars()
    {
        _tabBar.Children.Clear();
        for (var i = 0; i < _tabs.Length; i++)
        {
            var idx = i;
            var count = _tabs[i].Custom is null ? _tabs[i].Rows().Count(r => !r.Muted) : 0;
            var chip = Ui.Chip(count > 0 && i == 0 ? $"{_tabs[i].Label}  {count}" : _tabs[i].Label, i == _tab, on => { if (on) { _tab = idx; BuildBars(); Fill(); } else if (_tab == idx) BuildBars(); });
            _tabBar.Children.Add(chip);
        }
        _filterBar.Children.Clear();
        _filterBar.IsVisible = _filters.Length > 0 && _tabs[_tab].Custom is null;
        if (_filters.Length > 0)
        {
            _filterBar.Children.Add(Ui.Chip("All parts", _activeFilters.Count == 0, on => { if (on) { _activeFilters.Clear(); BuildBars(); Fill(); } }));
            foreach (var (k, label) in _filters)
                _filterBar.Children.Add(Ui.Chip(label, _activeFilters.Contains(k), on => { if (on) _activeFilters.Add(k); else _activeFilters.Remove(k); BuildBars(); Fill(); }));
        }
    }

    private IReadOnlyList<Row> Selected() => _list.SelectedItems?.OfType<RowItem>().Select(i => i.Row).ToList() ?? [];

    public int TabCount => _tabs.Length;

    public void Select(string? key, int tab = -1)
    {
        if (tab >= 0 && tab < _tabs.Length) _tab = tab;
        _selectKey = key;
        BuildBars();
        Fill();
    }

    public void Fill()
    {
        var t = _tabs[_tab];
        _customHost.IsVisible = t.Custom is not null;
        _split.IsVisible = t.Custom is null;
        _search.IsVisible = t.Custom is null;
        if (t.Custom is not null) { _customHost.Content = t.Custom(); return; }
        var q = _search.Text?.Trim() ?? "";
        var rows = t.Rows().Where(r => (_showReviewed.IsChecked == true || !r.Muted || _tab != 0 || !_showReviewed.IsVisible) &&
                                       (_activeFilters.Count == 0 || _activeFilters.Contains(r.Sec)) &&
                                       (q.Length == 0 || Matches(r, q))).Select(r => new RowItem(r)).ToList();
        var keep = _selectKey is not null ? [_selectKey] : Selected().Select(r => r.Key).ToHashSet();
        _updating = true;
        _list.ItemsSource = rows;
        _list.SelectedItems?.Clear();
        foreach (var it in rows.Where(it => keep.Contains(it.Row.Key) || (_selectKey is not null && it.Row.Group.Any(g => g.S("id") == _selectKey)))) _list.SelectedItems?.Add(it);
        _updating = false;
        if (_selectKey is not null && _list.SelectedItems?.Count > 0) _list.ScrollIntoView(_list.SelectedItems[0]!);
        _selectKey = null;
        _empty.Text = t.Empty;
        _empty.IsVisible = rows.Count == 0;
        _detail.Show(Selected());
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
        BuildBars();
        Fill();
    }
}
