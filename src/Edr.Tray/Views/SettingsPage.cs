using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using System.Text.Json.Nodes;
using Edr.Core;
using Edr.Tray.Services;

namespace Edr.Tray.Views;

public sealed class SettingsPage : UserControl
{
    private readonly Controller _c;
    private readonly StackPanel _root = new() { Spacing = 12, Margin = new Thickness(20, 16, 20, 20), MaxWidth = 980 };
    private readonly StackPanel _dynamic = new() { Spacing = 12 };
    private readonly ScrollViewer _scroll = new() { HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled };
    private readonly ContentControl _barHost = new();
    private Form? _form;
    private string _shown = "";
    private bool _wasUnsaved;
    private bool _restoreScroll = true;
    private DateTime _savedAt = DateTime.MinValue;
    private string _notice = "";

    private readonly ComboBox _level = new() { ItemsSource = new[] { "Only critical alerts", "Important alerts (recommended)", "Everything" }, Width = 300 };
    private readonly ComboBox _theme = new() { ItemsSource = new[] { "Same as Windows", "Dark", "Light" }, Width = 200 };
    private readonly TextBox _quiet = new() { PlaceholderText = "FortniteClient*, obs64*", MinWidth = 360, MaxWidth = 560 };
    private readonly TextBlock _learning = Ui.T("", "muted").Also(t => { t.TextWrapping = Avalonia.Media.TextWrapping.Wrap; t.MaxWidth = 560; });
    private readonly Field _quietField;

    public bool HasUnsaved => _form?.Changes().Count > 0;

    public event Action? UnsavedChanged;

    public SettingsPage(Controller c)
    {
        _c = c;
        Grid.SetIsSharedSizeScope(_root, true);
        _scroll.Content = _root;
        var dock = new DockPanel();
        DockPanel.SetDock(_barHost, Dock.Bottom);
        dock.Children.Add(_barHost);
        dock.Children.Add(_scroll);
        Content = dock;

        _quietField = new Field
        {
            IsDefault = () => QuietList(_quiet.Text).SequenceEqual(new EdrConfig().QuietProcesses, StringComparer.OrdinalIgnoreCase),
            Reset = () => _quiet.Text = string.Join(", ", new EdrConfig().QuietProcesses),
            Error = () => QuietError(QuietList(_quiet.Text)),
        };
        _quietField.DefaultLink.Click += (_, _) => _quietField.Reset();
        _root.Children.Add(Ui.Stack(4, Ui.T("Settings", "h1"),
            Ui.T("\"Just for you\" applies at once and only to your account. The PC settings below apply to everyone: change them, then Save in the bar at the bottom (Windows asks for administrator approval).", "sub")));
        _root.Children.Add(YouSection());
        _root.Children.Add(new UpdatePanel(c));
        _root.Children.Add(_dynamic);
        AddHandler(KeyDownEvent, OnKey, RoutingStrategies.Tunnel);
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        _restoreScroll = true;
    }

    public void RememberScroll()
    {
        if (_root.Children.Count > 0 && _scroll.Extent.Height > 0) _c.Prefs.SettingsScroll = _scroll.Offset.Y;
    }

    private async void OnKey(object? sender, KeyEventArgs e)
    {
        if (_form is null) return;
        if (e.Key == Key.S && e.KeyModifiers == KeyModifiers.Control)
        {
            e.Handled = true;
            if (_form.CanSave) await Save();
        }
        else if (e.Key == Key.Escape && HasUnsaved)
        {
            e.Handled = true;
            if (await Dialogs.Confirm("Discard changes", "Throw away your unsaved changes on this page?", "Discard", "Keep editing")) Discard();
        }
    }

    private static Control Section(string icon, string title, string sub, params Control[] body)
    {
        var s = Ui.Stack(14, Ui.Row(10, Ui.Icon(icon, 18, Palette.Accent), Ui.Stack(2, Ui.T(title, "h2"), Ui.T(sub, "muted"))));
        foreach (var b in body) s.Children.Add(b);
        return Ui.Card(s);
    }

    private static Button InfoButton(string label, string tip)
    {
        var info = new Button { Classes = { "info" }, Content = Ui.Icon("", 13, Palette.Muted), VerticalAlignment = VerticalAlignment.Top, Margin = new Thickness(4, 0, 0, 0) };
        info.Flyout = new Flyout { Content = new TextBlock { Text = tip, MaxWidth = 380, TextWrapping = Avalonia.Media.TextWrapping.Wrap } };
        ToolTip.SetTip(info, new TextBlock { Text = tip, MaxWidth = 380, TextWrapping = Avalonia.Media.TextWrapping.Wrap });
        ToolTip.SetShowDelay(info, 150);
        AutomationProperties.SetName(info, $"About {label}");
        AutomationProperties.SetHelpText(info, tip);
        return info;
    }

    private static Control Row(string label, Control input, string tip, Control? extra = null, Field? f = null, params Control[] below)
    {
        AutomationProperties.SetName(input, label);
        AutomationProperties.SetHelpText(input, tip);
        var text = Ui.T(label, "h3").Also(t => { t.MaxWidth = 240; t.TextWrapping = Avalonia.Media.TextWrapping.Wrap; t.VerticalAlignment = VerticalAlignment.Top; });
        var head = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 16, 0), Children = { text, InfoButton(label, tip) } };
        var g = new Grid { ColumnDefinitions = { new ColumnDefinition(GridLength.Auto) { SharedSizeGroup = "label", MinWidth = 200 }, new ColumnDefinition(GridLength.Star) } };
        g.Children.Add(head);
        var right = Ui.Stack(4);
        var line = Ui.Row(10, input);
        input.VerticalAlignment = VerticalAlignment.Center;
        if (extra is not null) line.Children.Add(extra);
        if (f is not null) line.Children.Add(f.DefaultLink);
        right.Children.Add(line);
        foreach (var b in below) { b.HorizontalAlignment = HorizontalAlignment.Left; right.Children.Add(b); }
        if (f is not null) right.Children.Add(f.ErrorText);
        Grid.SetColumn(right, 1);
        g.Children.Add(right);
        return g;
    }

    private sealed class Field
    {
        public required Func<bool> IsDefault { get; init; }
        public required Action Reset { get; init; }
        public Func<string> Error { get; init; } = () => "";
        public string Group { get; init; } = "";
        public Button DefaultLink { get; } = new() { Content = "Default", Classes = { "link" }, VerticalAlignment = VerticalAlignment.Center };
        public TextBlock ErrorText { get; } = new() { Foreground = Palette.ErrorText, FontSize = 11.5, IsVisible = false, TextWrapping = Avalonia.Media.TextWrapping.Wrap, MaxWidth = 560 };

        public Field() => ToolTip.SetTip(DefaultLink, "Put back the out-of-the-box value");

        public void Update()
        {
            DefaultLink.IsVisible = !IsDefault();
            var e = Error();
            ErrorText.Text = e;
            ErrorText.IsVisible = e.Length > 0;
        }
    }

    public void Refresh() => Refresh(false);

    private void Refresh(bool force)
    {
        SyncYou();
        var cfg = _c.State.Config;
        var now = cfg.UserJson();
        JsonObject? keep = null;
        if (!force && _form is not null && HasUnsaved)
        {
            if (JsonNode.DeepEquals(now, _form.FileBaseline)) { FinishRefresh(); return; }
            if (JsonNode.DeepEquals(now, _form.Loaded)) { _form.FileBaseline = now; FinishRefresh(); return; }
            keep = _form.Changes();
            _notice = "These settings were changed elsewhere (a reset, an import or the Network page): the new values are shown, and your own edits are kept.";
        }
        if (force) _notice = "";
        var form = new Form(this, cfg, _c.Prefs);
        var items = new List<Control>();
        items.AddRange(form.Sections);
        items.Add(BackupSection());
        items.Add(TroubleshootSection());
        items.Add(Section("", "Records & forensics", "Proof of what was changed, and deep investigation.",
            Ui.Wrap(
                Ui.Btn("Export audit log (CSV)", "", () => _ = ExportAudit(), icon: "", tip: "Every pause, allow, setting change and reset, with who did it and when, as a spreadsheet file."),
                Ui.Btn("Forensics (Velociraptor)", "", () => _ = _c.OpenForensics(), icon: "", tip: "Starts Velociraptor (needs administrator approval) and opens its page in your browser. If it already runs, its page opens again. Close its window to stop it."))));
        items.Add(Section("", "Help", "How FreeEDR works.",
            Ui.Wrap(
                Ui.Btn("User guide", "", _c.OpenUserGuide, icon: ""),
                Ui.Btn("Show the welcome tour", "", () => App.Instance?.ShowWelcome(), icon: "", tip: "The three first-run steps again: what FreeEDR does, which apps to trust, how much to be told."))));
        items.Add(DangerZone());
        var st = _c.State.Status;
        items.Add(Ui.T($"FreeEDR {ReadVersion()}  -  engine {st?.S("version")}  -  detect-only, Wail2Ban {(cfg.Wail2Ban.Block ? "blocking" : "report-only")}  -  {_c.State.Paths.Root}", "muted"));

        var fp = string.Join("\n", items.Select(Ui.Fingerprint));
        if (keep is null && !force && fp == _shown && _dynamic.Children.Count > 0) { FinishRefresh(); return; }
        var offset = _scroll.Offset;
        _shown = fp;
        _dynamic.Children.Clear();
        foreach (var i in items) _dynamic.Children.Add(i);
        _form = form;
        _barHost.Content = form.Bar;
        if (keep is not null) form.Load(keep);
        if (!_restoreScroll) Dispatcher.UIThread.Post(() => _scroll.Offset = offset, DispatcherPriority.Background);
        FinishRefresh();
        OnEdited();
    }

    private void FinishRefresh()
    {
        if (_form is { } f && !f.HasChanges) _notice = "";
        _form?.Update();
        if (!_restoreScroll || _dynamic.Children.Count == 0) return;
        _restoreScroll = false;
        var y = _c.Prefs.SettingsScroll;
        if (y > 0) Dispatcher.UIThread.Post(() => _scroll.Offset = new Vector(0, Math.Min(y, Math.Max(0, _scroll.Extent.Height - _scroll.Viewport.Height))), DispatcherPriority.Background);
    }

    private string SaveState()
    {
        var since = DateTime.Now - _savedAt;
        if (since > TimeSpan.FromMinutes(2)) return "";
        if (_c.State.Status?.S("settingsLoaded") is not { Length: > 0 }) return since < TimeSpan.FromSeconds(10) ? "Saved." : "";
        if (!_c.State.SettingsActive) return "Saved - waiting for the engine to pick it up...";
        return since < TimeSpan.FromSeconds(15) ? "Saved and active." : "";
    }

    private Control YouSection()
    {
        _level.SelectionChanged += (_, _) =>
        {
            var level = _level.SelectedIndex switch { 0 => "critical", 2 => "all", _ => "important" };
            if (level == _c.Prefs.NotifyLevel) return;
            _c.Prefs.NotifyLevel = level;
            _c.Say(_c.Prefs.SaveError.Length > 0 ? $"Not saved: {_c.Prefs.SaveError}" : "Notifications: saved for your account.", _c.Prefs.SaveError.Length > 0);
        };
        _theme.SelectionChanged += (_, _) =>
        {
            var t = _theme.SelectedIndex switch { 1 => "dark", 2 => "light", _ => "system" };
            if (t == _c.Prefs.Theme) return;
            _c.Prefs.Theme = t;
            App.Instance?.ApplyTheme(t);
        };
        _quiet.TextChanged += (_, _) =>
        {
            _quietField.Update();
            var list = QuietList(_quiet.Text);
            if (_quietField.Error().Length > 0 || list.SequenceEqual(_c.QuietList, StringComparer.Ordinal)) return;
            _c.Prefs.QuietProcesses = list;
            if (_c.Prefs.SaveError.Length > 0) _c.Say($"Quiet mode not saved: {_c.Prefs.SaveError}", true);
        };
        SyncYou();
        return Section("", "Just for you", "Your account only. Changes apply at once, no approval needed.",
            Row("Notify me about", _level, "Which alerts pop up as Windows notifications. \"Important\" shows high and critical alerts. \"Everything\" adds medium alerts and scan results. Critical alerts, \"Was this you?\" questions and sensor problems always notify. Everything is still listed in Activity.",
                below: _learning),
            Row("Quiet while these run", _quiet, "While one of these programs runs - a game, a presentation, a video call - FreeEDR holds back its pop-ups and shows one summary when the program closes. Detection keeps running the whole time: nothing is missed, only the pop-ups wait. Type program names separated by commas. * stands for \"anything\", so obs64* covers every OBS version. Names may contain spaces. This list is only for your account.",
                f: _quietField),
            Row("Theme", _theme, "Dark or light colors for this dashboard. \"Same as Windows\" follows Settings > Personalization > Colors > app mode, and changes with it."));
    }

    private void SyncYou()
    {
        _level.SelectedIndex = _c.Prefs.NotifyLevel switch { "critical" => 0, "all" => 2, _ => 1 };
        _theme.SelectedIndex = _c.Prefs.Theme switch { "dark" => 1, "light" => 2, _ => 0 };
        if (!_quiet.IsKeyboardFocusWithin && !QuietList(_quiet.Text).SequenceEqual(_c.QuietList, StringComparer.Ordinal))
            _quiet.Text = string.Join(", ", _c.QuietList);
        _quietField.Update();
        var learning = _c.Notifier?.InLearningWeek == true;
        _learning.Text = learning ? "Learning week: for the first 7 days only critical alerts notify, while FreeEDR learns what is normal on this PC." : "";
        _learning.IsVisible = learning;
    }

    private static List<string> QuietList(string? text) =>
        (text ?? "").Split([',', ';', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim()).Where(x => x.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    private static string QuietError(List<string> names)
    {
        var bad = names.FirstOrDefault(x => !EdrConfig.IsQuietName(x));
        return bad is null ? "" : $"\"{(bad.Length > 40 ? bad[..40] + "..." : bad)}\": use a program name like obs64*, not a folder.";
    }

    private sealed class Form
    {
        private static readonly int[] BanPresets = [3600, 86_400, 604_800, 2_592_000, 7_776_000, 31_536_000];

        private readonly SettingsPage _page;
        private readonly Preferences _prefs;
        private readonly List<Field> _fields = [];
        private readonly JsonObject _defaults = EdrConfig.UserDefaults();
        public List<Control> Sections { get; } = [];

        public JsonObject Loaded { get; private set; }
        public JsonObject FileBaseline { get; set; }

        public Border Bar { get; }
        private readonly Button _save;
        private readonly Button _discard;
        private readonly TextBlock _status = Ui.T("", "", 12.5).Also(t => { t.VerticalAlignment = VerticalAlignment.Center; t.TextWrapping = Avalonia.Media.TextWrapping.Wrap; });
        private readonly List<(string Key, Expander Ex, TextBlock Count)> _groups = [];

        private readonly ToggleSwitch _block, _ipv6;
        private readonly NumericUpDown _fails, _window;
        private readonly ComboBox _defender, _lookback, _maxPub, _maxPriv;
        private readonly List<int> _pubValues, _privValues;
        private readonly List<string> _lookbackValues = ["1d", "2d", "3d", "7d"];
        private readonly List<string> _times;
        private readonly WrapPanel _timeChips = new() { Orientation = Orientation.Horizontal };
        private readonly TimePicker _timePick = new() { ClockIdentifier = "24HourClock", MinuteIncrement = 5, SelectedTime = new TimeSpan(12, 0, 0) };
        private readonly TextBox _feed;
        private readonly ToggleButton _feedEye = new() { Classes = { "small" }, Content = Ui.Icon("", 14), VerticalAlignment = VerticalAlignment.Center };
        private readonly TextBlock _feedResult = Ui.T("", "muted").Also(t => { t.TextWrapping = Avalonia.Media.TextWrapping.Wrap; t.IsVisible = false; });
        private readonly TextBlock _ipv6Note = Ui.T("", "muted");
        private readonly TextBlock _windowNote = Ui.T("", "muted").Also(t => t.TextWrapping = Avalonia.Media.TextWrapping.Wrap);
        private readonly int _windowExact, _windowShown;

        public Form(SettingsPage page, EdrConfig cfg, Preferences prefs)
        {
            _page = page;
            _prefs = prefs;
            Loaded = cfg.UserJson();
            FileBaseline = cfg.UserJson();
            var w = cfg.Wail2Ban;
            var d = EdrConfig.FromJson(_defaults);

            _block = new ToggleSwitch { IsChecked = w.Block, OnContent = "On - block in Windows Firewall", OffContent = "Off - only report" };
            _fails = Number(w.FailCount, EdrConfig.Limits.FailCount.Min, EdrConfig.Limits.FailCount.Max);
            _windowExact = w.WindowSeconds;
            _windowShown = Math.Max(1, w.WindowSeconds / 60);
            _window = Number(_windowShown, EdrConfig.Limits.WindowSeconds.Min / 60, EdrConfig.Limits.WindowSeconds.Max / 60);
            if (w.WindowSeconds % 60 != 0) _windowNote.Text = $"The settings file says {w.WindowSeconds} seconds; shown rounded to whole minutes. It stays {w.WindowSeconds} seconds until you change it here.";
            _windowNote.IsVisible = _windowNote.Text?.Length > 0;
            (_maxPub, _pubValues) = BanChoice(w.MaxBanPublicSec);
            (_maxPriv, _privValues) = BanChoice(w.MaxBanPrivateSec);
            _ipv6 = new ToggleSwitch { IsChecked = w.BlockRdpIpv6, OnContent = "Blocked", OffContent = "Allowed" };
            var fBlock = Add("", () => _block.IsChecked == d.Wail2Ban.Block, () => _block.IsChecked = d.Wail2Ban.Block);
            var fFails = Add("w2b", () => _fails.Value == d.Wail2Ban.FailCount, () => _fails.Value = d.Wail2Ban.FailCount, () => NumberError(_fails));
            var fWindow = Add("w2b", () => WindowSeconds() == d.Wail2Ban.WindowSeconds, () => _window.Value = d.Wail2Ban.WindowSeconds / 60, () => NumberError(_window));
            var fPub = Add("w2b", () => Ban(_maxPub, _pubValues) == d.Wail2Ban.MaxBanPublicSec, () => SelectBan(_maxPub, _pubValues, d.Wail2Ban.MaxBanPublicSec));
            var fPriv = Add("w2b", () => Ban(_maxPriv, _privValues) == d.Wail2Ban.MaxBanPrivateSec, () => SelectBan(_maxPriv, _privValues, d.Wail2Ban.MaxBanPrivateSec));
            var fIpv6 = Add("w2b", () => _ipv6.IsChecked == d.Wail2Ban.BlockRdpIpv6, () => _ipv6.IsChecked = d.Wail2Ban.BlockRdpIpv6);
            Sections.Add(Section("", "Wail2Ban - sign-in attacks", "The only part of FreeEDR that blocks: computers that keep guessing passwords over the network.",
                Row("Block attackers", _block, "On: a computer that keeps typing wrong passwords to get into this PC (Remote Desktop, file sharing) is blocked in Windows Firewall - 5 minutes at first, then longer each time it comes back. Off: the same attacks are only reported in Network, nothing is blocked.", f: fBlock),
                Advanced("w2b", "attack threshold, block lengths, IPv6",
                    Row("Wrong passwords allowed", _fails, "How many wrong passwords from one computer are tolerated before FreeEDR treats it as an attack. Example: with 5, the 5th wrong password within the time window below triggers it. Lower catches attackers sooner; higher is kinder to people who often mistype.", f: fFails),
                    Row("Within (minutes)", _window, "The time window in which wrong passwords are counted. Example: 5 wrong passwords within 30 minutes. Someone guessing more slowly than that is not counted as an attack.", f: fWindow, below: _windowNote),
                    Row("Longest block, internet", _maxPub, "Each time the same internet computer comes back to guess again, its block gets longer: 5 minutes, 25 minutes, 2 hours, 10 hours, 2 days and so on - but never longer than this.", f: fPub),
                    Row("Longest block, home network", _maxPriv, "The same, for computers inside your own network (other PCs, phones, a family member's laptop). Kept shorter so someone at home who mistyped is not locked out for long.", f: fPriv),
                    Row("Remote Desktop over IPv6", _ipv6, "Wail2Ban cannot count wrong passwords that arrive over IPv6 (the newer kind of internet address). \"Blocked\" closes Remote Desktop to every IPv6 address instead. Leave it allowed if you connect to this PC over IPv6.", f: fIpv6, extra: _ipv6Note))));

            _defender = new ComboBox { ItemsSource = new[] { "Watch & report (recommended)", "Leave Defender alone" }, Width = 300, SelectedIndex = cfg.DefenderMode == "untouched" ? 1 : 0 };
            var fDef = Add("", () => _defender.SelectedIndex == (d.DefenderMode == "untouched" ? 1 : 0), () => _defender.SelectedIndex = d.DefenderMode == "untouched" ? 1 : 0);
            Sections.Add(Section("", "Microsoft Defender", "FreeEDR never makes Defender block more than you had before.",
                Row("Ransomware & attack rules", _defender, "Microsoft Defender has extra rules against ransomware and common attack tricks (\"attack surface reduction\" and \"Controlled folder access\"). \"Watch & report\" turns them on in audit mode: they watch and FreeEDR lists what they would have blocked, but nothing is blocked. A rule you had already set to block stays blocking. \"Leave Defender alone\" puts Defender's settings back as they were before FreeEDR. The change applies right away when you save.", f: fDef)));

            _times = [.. cfg.ScanTimes];
            var addTime = Ui.Btn("Add", "small", () =>
            {
                if (_timePick.SelectedTime is not { } t) return;
                var s = $"{(int)t.TotalHours:00}:{t.Minutes:00}";
                if (!_times.Contains(s)) { _times.Add(s); _times.Sort(StringComparer.Ordinal); }
                Chips();
                Edited();
            }, icon: "");
            AutomationProperties.SetName(_timePick, "New scan time");
            Chips();
            var fTimes = Add("", () => _times.SequenceEqual(d.ScanTimes), () => { _times.Clear(); _times.AddRange(d.ScanTimes); Chips(); }, () => _times.Count == 0 ? "Add at least one scan time." : "");
            var lb = cfg.SigmaLookback;
            if (!_lookbackValues.Contains(lb)) _lookbackValues.Add(lb);
            _lookback = new ComboBox { ItemsSource = _lookbackValues.Select(LookbackLabel).ToArray(), SelectedIndex = _lookbackValues.IndexOf(lb), Width = 200 };
            var fLook = Add("scan", () => Lookback() == d.SigmaLookback, () => _lookback.SelectedIndex = _lookbackValues.IndexOf(d.SigmaLookback));
            _feed = new TextBox { Text = cfg.IocFeedUrl, MinWidth = 360, MaxWidth = 520 };
            AutomationProperties.SetName(_feedEye, "Show the whole address");
            ToolTip.SetTip(_feedEye, "Show or hide the private part of the address");
            _feedEye.IsCheckedChanged += (_, _) => _feed.RevealPassword = _feedEye.IsChecked == true;
            _feed.LostFocus += (_, _) => Mask();
            Mask();
            var test = Ui.Btn("Test", "small", () => _ = TestFeed(), icon: "", tip: "Downloads the list now and counts the malware fingerprints in it.");
            var fFeed = Add("scan", () => (_feed.Text ?? "").Trim() == d.IocFeedUrl, () => _feed.Text = d.IocFeedUrl, () => EdrConfig.FeedProblem((_feed.Text ?? "").Trim()));
            var timesBox = Ui.Stack(6, _timeChips, Ui.Row(8, _timePick, addTime));
            Sections.Add(Section("", "Scans", "Malware list update, event-log check (Sigma), Python vulnerability check and tool versions.",
                Row("Scan at", timesBox, "When the full scan runs each day (24-hour clock). Remove a time with its ×, add one with the clock and Add. A scan missed while the PC was off runs 5 minutes after it starts.", f: fTimes),
                Advanced("scan", "how far back, malware list address",
                    Row("Check logs from the last", _lookback, "How far back each scan reads the Windows event logs for signs of an attack. Longer finds older traces but makes each scan take more time.", f: fLook),
                    Row("Malware list address", _feed, "Where FreeEDR downloads its list of known malware fingerprints at each scan. Leave the default unless you have your own list in the same format (one SHA256 fingerprint per line). An address with a private key is hidden here and in the logs; the eye button shows it.", f: fFeed, extra: Ui.Row(8, _feedEye, test), below: _feedResult))));

            var restore = Ui.Btn("Restore default settings...", "ghost", () => _ = RestoreDefaults(), icon: "",
                tip: "Puts every PC setting on this page back to its out-of-the-box value in the form. Nothing changes until you Save. Your allows, flagged items and history are not touched.");
            Sections.Add(Ui.Card(Ui.Row(12, restore, Ui.T("Puts the PC settings above back to their out-of-the-box values. You review them, then Save.", "muted").Also(t => { t.VerticalAlignment = VerticalAlignment.Center; t.TextWrapping = Avalonia.Media.TextWrapping.Wrap; t.MaxWidth = 520; }))));

            _block.IsCheckedChanged += (_, _) => Edited();
            _ipv6.IsCheckedChanged += (_, _) => Edited();
            foreach (var n in new[] { _fails, _window }) n.ValueChanged += (_, _) => Edited();
            foreach (var cb in new[] { _defender, _lookback, _maxPub, _maxPriv }) cb.SelectionChanged += (_, _) => Edited();
            _feed.TextChanged += (_, _) => { _feedResult.Text = ""; _feedResult.IsVisible = false; Edited(); };
            foreach (var f in _fields) { var ff = f; f.DefaultLink.Click += (_, _) => { ff.Reset(); Edited(); }; }

            _save = Ui.Btn("Save settings", "primary big", () => _ = _page.Save(), icon: "", tip: "Ctrl+S");
            _discard = Ui.Btn("Discard changes", "ghost", () => _page.Discard(), tip: "Esc");
            var bar = new DockPanel();
            var buttons = Ui.Row(10, _discard, _save);
            buttons.Margin = new Thickness(16, 0, 0, 0);
            DockPanel.SetDock(buttons, Dock.Right);
            bar.Children.Add(buttons);
            bar.Children.Add(_status);
            Bar = new Border { Classes = { "savebar" }, Child = bar, IsVisible = false };
            AutomationProperties.SetLiveSetting(_status, AutomationLiveSetting.Polite);
        }

        public bool HasChanges => Changes().Count > 0;

        public bool CanSave => HasChanges && _fields.All(f => f.Error().Length == 0);

        public JsonObject Changes() => EdrConfig.Changes(Loaded, Pending());

        public JsonObject Pending() => new()
        {
            ["scanTimes"] = _times.ToJsonArray(),
            ["iocFeedUrl"] = (_feed.Text ?? "").Trim(),
            ["sigmaLookback"] = Lookback(),
            ["defenderMode"] = _defender.SelectedIndex == 1 ? "untouched" : "audit",
            ["wail2ban"] = new JsonObject
            {
                ["block"] = _block.IsChecked == true, ["blockRdpIpv6"] = _ipv6.IsChecked == true,
                ["failCount"] = (int)(_fails.Value ?? 0), ["windowSeconds"] = WindowSeconds(),
                ["maxBanPublicSec"] = Ban(_maxPub, _pubValues), ["maxBanPrivateSec"] = Ban(_maxPriv, _privValues),
            },
        };

        public void Load(JsonObject edits)
        {
            if (edits["scanTimes"] is JsonArray st) { _times.Clear(); _times.AddRange(st.Select(Ps.Str).Where(EdrConfig.IsTime)); Chips(); }
            if (edits.ContainsKey("iocFeedUrl")) { _feed.Text = edits.Str("iocFeedUrl"); Mask(); }
            if (edits.Str("sigmaLookback") is { Length: > 0 } lb)
            {
                if (!_lookbackValues.Contains(lb)) { _lookbackValues.Add(lb); _lookback.ItemsSource = _lookbackValues.Select(LookbackLabel).ToArray(); }
                _lookback.SelectedIndex = _lookbackValues.IndexOf(lb);
            }
            if (edits.Str("defenderMode") is "audit" or "untouched") _defender.SelectedIndex = edits.Str("defenderMode") == "untouched" ? 1 : 0;
            if (edits["wail2ban"] is JsonObject w)
            {
                if (w.ContainsKey("block")) _block.IsChecked = w.Truthy("block");
                if (w.ContainsKey("blockRdpIpv6")) _ipv6.IsChecked = w.Truthy("blockRdpIpv6");
                if (w.ContainsKey("failCount")) _fails.Value = w.Int("failCount") is > 0 and var n ? n : null;
                if (w.ContainsKey("windowSeconds")) _window.Value = w.Int("windowSeconds") is > 0 and var s ? Math.Max(1, s / 60) : null;
                if (w.ContainsKey("maxBanPublicSec")) SelectBan(_maxPub, _pubValues, w.Int("maxBanPublicSec"));
                if (w.ContainsKey("maxBanPrivateSec")) SelectBan(_maxPriv, _privValues, w.Int("maxBanPrivateSec"));
            }
            Update();
        }

        public void Saved()
        {
            Loaded = Pending();
            Update();
        }

        public void Update()
        {
            foreach (var f in _fields) f.Update();
            var blocking = _block.IsChecked == true;
            _maxPub.IsEnabled = _maxPriv.IsEnabled = _ipv6.IsEnabled = blocking;
            _ipv6Note.Text = blocking ? "" : "Needs \"Block attackers\" on.";
            _windowNote.IsVisible = _windowNote.Text?.Length > 0 && (int?)_window.Value == _windowShown;
            foreach (var (key, ex, count) in _groups)
            {
                var g = _fields.Where(f => f.Group == key).ToList();
                var changed = g.Count(f => !f.IsDefault());
                count.Text = changed > 0 ? $"·  {changed} not at default" : "";
                if (g.Any(f => f.Error().Length > 0)) ex.IsExpanded = true;
            }
            var dirty = HasChanges;
            var errors = _fields.Count(f => f.Error().Length > 0);
            var state = _page.SaveState();
            var parts = new List<string>();
            if (_page._notice.Length > 0 && dirty) parts.Add(_page._notice);
            if (dirty) parts.Add(errors > 0 ? $"Fix {Ui.Plural(errors, "field")} marked in red to save." : $"Unsaved changes: {Ui.Plural(CountLeaves(Changes()), "setting")}.");
            else if (state.Length > 0) parts.Add(state);
            _status.Text = string.Join("  ", parts);
            _status.Foreground = dirty ? (errors > 0 ? Palette.ErrorText : Palette.Warn) : Palette.Muted;
            _save.IsEnabled = dirty && errors == 0;
            _save.IsVisible = _discard.IsVisible = dirty;
            Bar.IsVisible = dirty || state.Length > 0;
        }

        private static int CountLeaves(JsonObject o) => o.Sum(kv => kv.Value is JsonObject inner ? CountLeaves(inner) : 1);

        private void Edited()
        {
            Update();
            _page.OnEdited();
        }

        private Field Add(string group, Func<bool> isDefault, Action reset, Func<string>? error = null)
        {
            var f = new Field { IsDefault = isDefault, Reset = reset, Error = error ?? (() => ""), Group = group };
            _fields.Add(f);
            return f;
        }

        private Expander Advanced(string key, string summary, params Control[] rows)
        {
            var count = Ui.T("", "muted", null, Palette.Warn);
            var ex = new Expander
            {
                Header = Ui.Row(8, Ui.T("Advanced", "h3"), Ui.T(summary, "muted"), count),
                IsExpanded = _prefs.AdvancedOpen(key),
                HorizontalAlignment = HorizontalAlignment.Stretch,
                Content = Ui.Stack(14, rows).Also(s => s.Margin = new Thickness(0, 6, 0, 2)),
            };
            AutomationProperties.SetName(ex, $"Advanced: {summary}");
            ex.PropertyChanged += (_, e) => { if (e.Property == Expander.IsExpandedProperty) _prefs.SetAdvancedOpen(key, ex.IsExpanded); };
            _groups.Add((key, ex, count));
            return ex;
        }

        private async Task RestoreDefaults()
        {
            if (!await Dialogs.Confirm("Restore default settings", "Put every PC setting on this page back to its out-of-the-box value? You can review them before you Save. Allows, flagged items, bans and history are not touched.", "Restore")) return;
            foreach (var f in _fields) f.Reset();
            Edited();
        }

        private async Task TestFeed()
        {
            _feedResult.IsVisible = true;
            _feedResult.Text = "Testing...";
            _feedResult.Foreground = Palette.Muted;
            var (ok, text) = await Controller.TestFeed((_feed.Text ?? "").Trim());
            _feedResult.Text = text;
            _feedResult.Foreground = ok ? Palette.Ok : Palette.ErrorText;
        }

        private void Mask()
        {
            var secret = EdrConfig.FeedHasSecret((_feed.Text ?? "").Trim());
            _feed.PasswordChar = secret ? '•' : default;
            _feedEye.IsVisible = secret;
            if (!secret) _feedEye.IsChecked = false;
        }

        private void Chips()
        {
            _timeChips.Children.Clear();
            foreach (var t in _times.ToList())
            {
                var chip = Ui.Btn($"{t}  ×", "small", () => { _times.Remove(t); Chips(); Edited(); }, tip: $"Remove {t}");
                AutomationProperties.SetName(chip, $"Remove scan time {t}");
                chip.Margin = new Thickness(0, 0, 6, 0);
                _timeChips.Children.Add(chip);
            }
        }

        private string Lookback() => _lookback.SelectedIndex >= 0 && _lookback.SelectedIndex < _lookbackValues.Count ? _lookbackValues[_lookback.SelectedIndex] : "2d";

        private static string LookbackLabel(string v) => v switch
        {
            "1d" => "24 hours", "2d" => "2 days", "3d" => "3 days", "7d" => "7 days",
            _ when v.EndsWith('h') => $"{v[..^1]} hours", _ => $"{v.TrimEnd('d')} days",
        };

        private int WindowSeconds() => _window.Value is not { } v ? 0 : (int)v == _windowShown ? _windowExact : (int)v * 60;

        private static (ComboBox, List<int>) BanChoice(int seconds)
        {
            var values = BanPresets.ToList();
            if (!values.Contains(seconds)) { values.Add(seconds); values.Sort(); }
            return (new ComboBox { ItemsSource = values.Select(Duration).ToArray(), SelectedIndex = values.IndexOf(seconds), Width = 200 }, values);
        }

        private static int Ban(ComboBox cb, List<int> values) => cb.SelectedIndex >= 0 && cb.SelectedIndex < values.Count ? values[cb.SelectedIndex] : 0;

        private static void SelectBan(ComboBox cb, List<int> values, int seconds)
        {
            if (seconds <= 0) return;
            if (!values.Contains(seconds))
            {
                values.Add(seconds);
                values.Sort();
                cb.ItemsSource = values.Select(Duration).ToArray();
            }
            cb.SelectedIndex = values.IndexOf(seconds);
        }

        private static string Duration(int s) => s switch
        {
            _ when s % 31_536_000 == 0 => Ui.Plural(s / 31_536_000, "year"),
            _ when s % 86_400 == 0 => Ui.Plural(s / 86_400, "day"),
            _ when s % 3600 == 0 => Ui.Plural(s / 3600, "hour"),
            _ when s % 60 == 0 => Ui.Plural(s / 60, "minute"),
            _ => Ui.Plural(s, "second"),
        };

        private static NumericUpDown Number(int value, int min, int max) =>
            new() { Value = Math.Clamp(value, min, max), Minimum = min, Maximum = max, Width = 140, FormatString = "0", Increment = 1 };

        private static string NumberError(NumericUpDown n) =>
            n.Value is null ? $"Enter a number from {n.Minimum:0} to {n.Maximum:0}." : "";
    }

    private Control BackupSection() => Section("", "Backup & import", "Your PC settings, your quiet-mode list and the allows in one file - for a new PC or a reinstall.",
        Ui.Wrap(
            Ui.Btn("Back up settings...", "", () => _ = Backup(), icon: "", tip: "Saves the PC settings on this page, your quiet-mode list and every allow (Allowed & trusted) to a file you choose. No passwords or alerts are in it; a private key in the malware list address is only included if you say so."),
            Ui.Btn("Import settings...", "", () => _ = Import(), icon: "", tip: "Reads a backup file, shows what it would change, then applies it with administrator approval. Allows that are already here are skipped.")));

    private Control TroubleshootSection()
    {
        var logs = Ui.Btn("Open logs", "", () => { }, icon: "", tip: "The engine's log (what it did and any errors) and the scan log.");
        var menu = new MenuFlyout();
        void Item(string text, Action a) { var mi = new MenuItem { Header = text }; mi.Click += (_, _) => a(); menu.Items.Add(mi); }
        Item("Engine log", _c.OpenEngineLog);
        Item("Scan log", _c.OpenScanLog);
        Item("Show the logs folder", () => { if (!Shell.ShowInExplorer(_c.State.Paths.EngineLog)) _c.Say("The engine log does not exist yet.", true); });
        logs.Flyout = menu;
        return Section("", "Troubleshoot", "Check that FreeEDR works.",
            Ui.Wrap(
                Ui.Btn("Send a harmless test alert", "", _c.TestDetection, icon: "", tip: "Starts a harmless command that looks suspicious, so you can see an alert arrive in Activity within seconds."),
                logs,
                Ui.Btn("Restart engine", "", () => _ = _c.RestartEngine(), icon: "", tip: "Stops and starts the FreeEDR service (administrator approval). Detection pauses for a few seconds.")));
    }

    private Control DangerZone()
    {
        var body = Ui.Stack(12,
            Ui.Row(10, Ui.Icon("", 18, Palette.Danger), Ui.Stack(2, Ui.T("Danger zone", "h2"), Ui.T("Cannot be undone.", "muted"))),
            Ui.Row(12, Ui.Btn("Reset FreeEDR to defaults...", "danger", () => _ = _c.FactoryReset(), icon: ""),
                Ui.T("Deletes every allow, flagged item and ban, the alert history and every account's reviewed marks, and puts the PC settings back to their defaults. Kept: the Microsoft Defender choice, each account's \"Just for you\" choices, logs, scan results and the event-log archive.", "muted").Also(t => { t.VerticalAlignment = VerticalAlignment.Center; t.MaxWidth = 560; t.TextWrapping = Avalonia.Media.TextWrapping.Wrap; })));
        return Ui.Card(body, "dangerzone");
    }

    public void RenderFull(string file)
    {
        var size = new PixelSize((int)Math.Ceiling(_root.Bounds.Width + 40), (int)Math.Ceiling(_root.Bounds.Height + 40));
        if (size.Width <= 40 || size.Height <= 40) return;
        using var bmp = new Avalonia.Media.Imaging.RenderTargetBitmap(size, new Vector(96, 96));
        using (var ctx = bmp.CreateDrawingContext())
            ctx.FillRectangle(Palette.Bg, new Rect(0, 0, size.Width, size.Height));
        bmp.Render(_root);
        bmp.Save(file, Avalonia.Media.Imaging.PngBitmapEncoderOptions.Default);
    }

    internal void OnEdited()
    {
        if (_wasUnsaved != HasUnsaved) { _wasUnsaved = HasUnsaved; UnsavedChanged?.Invoke(); }
    }

    private void Discard()
    {
        _notice = "";
        Refresh(true);
        OnEdited();
    }

    public async Task<bool> SaveFromOutside() => _form?.CanSave == true ? await Save() : !HasUnsaved;

    private string ReadVersion()
    {
        try { return File.Exists(_c.State.Paths.VersionFile) ? File.ReadAllText(_c.State.Paths.VersionFile).Trim() : "(development)"; }
        catch (IOException) { return ""; }
    }

    private async Task<bool> Save()
    {
        if (_form is not { CanSave: true } form) return false;
        var changes = form.Changes();
        if (changes.Str("defenderMode") is { Length: > 0 } dm && !await Dialogs.Confirm("Microsoft Defender", dm == "audit"
                ? "Turn on Defender's ransomware and attack rules in audit mode? Nothing is blocked; FreeEDR lists what they would have blocked."
                : "Put Defender's settings back as they were before FreeEDR? FreeEDR then only reads Defender's own detections.", "Apply")) return false;
        if (!await _c.SaveSettings(changes)) return false;
        _savedAt = DateTime.Now;
        _notice = "";
        form.Saved();
        OnEdited();
        return true;
    }

    private async Task Backup()
    {
        var top = TopLevel.GetTopLevel(this);
        if (top is null) return;
        JsonObject backup;
        try { backup = await _c.CreateBackup(); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { _c.Say($"The backup was not made: the settings could not be read ({e.Message}).", true); return; }
        if (backup["settings"] is JsonObject settings)
        {
            settings["quietProcesses"] = _c.QuietList.ToJsonArray();
            if (EdrConfig.FeedHasSecret(settings.Str("iocFeedUrl")))
            {
                var choice = await Dialogs.Choose("Back up settings",
                    "Your malware list address contains a private key or password. Anyone who gets the backup file could read it.",
                    ["Leave the address out", "Include it", "Cancel"]);
                if (choice is < 0 or 2) return;
                if (choice == 0) settings.Remove("iocFeedUrl");
            }
        }
        var file = await top.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Back up FreeEDR settings", SuggestedFileName = $"FreeEDR-settings-{DateTime.Now:yyyyMMdd}.json", DefaultExtension = "json",
            FileTypeChoices = [new FilePickerFileType("FreeEDR settings") { Patterns = ["*.json"] }],
        });
        if (file is null) return;
        try
        {
            var text = JsonFile.ToText(backup);
            await using var s = await file.OpenWriteAsync();
            s.SetLength(0);
            await using var w = new StreamWriter(s, JsonFile.Utf8NoBom);
            await w.WriteAsync(text);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            _c.Say($"The backup was not saved: {file.Name} could not be written ({e.Message}).", true);
            return;
        }
        var local = file.TryGetLocalPath();
        _c.Say($"Settings backed up: {local ?? file.Name}", false, local is not null ? "Show in folder" : null, local is not null ? () => { Shell.ShowInExplorer(local); } : null);
    }

    private async Task Import()
    {
        var top = TopLevel.GetTopLevel(this);
        if (top is null) return;
        var files = await top.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Import FreeEDR settings", AllowMultiple = false, FileTypeFilter = [new FilePickerFileType("FreeEDR settings") { Patterns = ["*.json"] }],
        });
        if (files.Count == 0) return;
        JsonObject? backup;
        try
        {
            await using var s = await files[0].OpenReadAsync();
            if (s.CanSeek && s.Length > SettingsBackup.MaxBytes) { await Dialogs.Info("Import settings", "This file is too large to be a FreeEDR settings backup.", true); return; }
            var buf = new byte[SettingsBackup.MaxBytes + 1];
            var n = 0;
            int r;
            while (n < buf.Length && (r = await s.ReadAsync(buf.AsMemory(n))) > 0) n += r;
            if (n > SettingsBackup.MaxBytes) { await Dialogs.Info("Import settings", "This file is too large to be a FreeEDR settings backup.", true); return; }
            backup = JsonFile.Parse(System.Text.Encoding.UTF8.GetString(buf, 0, n).TrimStart('﻿')) as JsonObject;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            await Dialogs.Info("Import settings", $"The file could not be read: {e.Message}", true);
            return;
        }
        if (HasUnsaved && !await Dialogs.Confirm("Import settings", "You have unsaved changes on this page. Importing reloads the page and throws them away.", "Import anyway")) return;
        await _c.ImportBackup(backup);
        Discard();
    }

    private async Task ExportAudit()
    {
        var top = TopLevel.GetTopLevel(this);
        if (top is null) return;
        var file = await top.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Export audit log", SuggestedFileName = $"FreeEDR-audit-{DateTime.Now:yyyyMMdd-HHmm}.csv", DefaultExtension = "csv",
            FileTypeChoices = [new FilePickerFileType("CSV") { Patterns = ["*.csv"] }],
        });
        if (file is null) return;
        try
        {
            await using (var s = await file.OpenWriteAsync())
            await using (var w = new StreamWriter(s, new System.Text.UTF8Encoding(true)))
                await w.WriteAsync(_c.AuditCsv());
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            _c.Say($"The audit log was not saved: {file.Name} could not be written (is it open in another program, or is the folder read-only?). Close it or pick another place, then export again.", true);
            return;
        }
        var local = file.TryGetLocalPath();
        _c.Say(local is not null ? $"Audit log saved: {local}" : $"Audit log saved: {file.Name}", false,
            local is not null ? "Show in folder" : null, local is not null ? () => { Shell.ShowInExplorer(local); } : null);
    }
}
