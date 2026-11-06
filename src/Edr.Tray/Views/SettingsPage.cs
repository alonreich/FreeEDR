using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Platform.Storage;
using System.Text.Json.Nodes;
using Edr.Core;
using Edr.Tray.Services;

namespace Edr.Tray.Views;

/// <summary>Settings: notifications (this account), and FreeEDR's settings (saved with one administrator prompt).</summary>
public sealed class SettingsPage : UserControl
{
    private readonly Controller _c;
    private readonly StackPanel _root = new() { Spacing = 18, Margin = new Thickness(28, 24, 28, 28), MaxWidth = 980 };
    private readonly ScrollViewer _scroll = new();

    public SettingsPage(Controller c)
    {
        _c = c;
        _scroll.Content = _root;
        Content = _scroll;
    }

    private static Control Section(string icon, string title, string sub, params Control[] body)
    {
        var s = Ui.Stack(14, Ui.Row(10, Ui.Icon(icon, 18, Palette.Accent), Ui.Stack(2, Ui.T(title, "h2"), Ui.T(sub, "muted"))));
        foreach (var b in body) s.Children.Add(b);
        return Ui.Card(s);
    }

    private static Control Field(string label, Control input, string? help = null)
    {
        var g = new Grid { ColumnDefinitions = new ColumnDefinitions("230,*") };
        var l = Ui.Stack(2, Ui.T(label, "h3"));
        if (help is not null) l.Children.Add(Ui.T(help, "muted"));
        g.Children.Add(l);
        Grid.SetColumn(input, 1);
        input.VerticalAlignment = VerticalAlignment.Center;
        if (input is not TextBox || !double.IsNaN(input.Width)) input.HorizontalAlignment = HorizontalAlignment.Left;
        g.Children.Add(input);
        return g;
    }

    public void Refresh()
    {
        var offset = _scroll.Offset;
        _root.Children.Clear();
        var cfg = _c.State.Config;
        _root.Children.Add(Ui.Stack(4, Ui.T("Settings", "h1"), Ui.T("Notifications are yours alone; everything else applies to the whole PC and asks for administrator approval when saved.", "sub")));

        // Notifications (per account, no prompt)
        var lv = new ComboBox { ItemsSource = new[] { "Only critical alerts", "Important alerts (recommended)", "Everything" }, Width = 300 };
        lv.SelectedIndex = _c.Prefs.NotifyLevel switch { "critical" => 0, "all" => 2, _ => 1 };
        lv.SelectionChanged += (_, _) => _c.Prefs.NotifyLevel = lv.SelectedIndex switch { 0 => "critical", 2 => "all", _ => "important" };
        _root.Children.Add(Section("", "Notifications", "For this account only.",
            Field("Notify me about", lv, "Critical alerts, \"Was this you?\" questions and sensor problems always notify. During the first 7 days only critical alerts do."),
            Field("Learning week", Ui.T(_c.Notifier?.InLearningWeek == true ? "Active - FreeEDR is learning what is normal on this PC." : "Finished.", "sub"))));

        // Quiet apps
        var quiet = new TextBox { Text = string.Join(", ", cfg.QuietProcesses), PlaceholderText = "FortniteClient*, obs64*" };
        // Scans
        var times = new TextBox { Text = string.Join(", ", cfg.ScanTimes), Width = 220 };
        var lookback = new ComboBox { ItemsSource = new[] { "1d", "2d", "3d", "7d" }, SelectedItem = cfg.SigmaLookback, Width = 120 };
        if (lookback.SelectedItem is null) lookback.SelectedIndex = 1;
        var feed = new TextBox { Text = cfg.IocFeedUrl };
        // Wail2Ban
        var block = new ToggleSwitch { IsChecked = cfg.Wail2Ban.Block, OnContent = "Block attackers in Windows Firewall", OffContent = "Report only" };
        var fails = new NumericUpDown { Value = cfg.Wail2Ban.FailCount, Minimum = 2, Maximum = 100, Width = 140, FormatString = "0" };
        var window = new NumericUpDown { Value = cfg.Wail2Ban.WindowSeconds / 60, Minimum = 1, Maximum = 1440, Width = 140, FormatString = "0" };
        var maxPub = new NumericUpDown { Value = cfg.Wail2Ban.MaxBanPublicSec / 86400, Minimum = 1, Maximum = 365, Width = 140, FormatString = "0" };
        var maxPriv = new NumericUpDown { Value = Math.Max(1, cfg.Wail2Ban.MaxBanPrivateSec / 86400), Minimum = 1, Maximum = 365, Width = 140, FormatString = "0" };
        var ipv6 = new ToggleSwitch { IsChecked = cfg.Wail2Ban.BlockRdpIpv6, OnContent = "Blocked", OffContent = "Not blocked" };
        // Defender
        var defender = new ComboBox { ItemsSource = new[] { "Audit mode: report what Defender would block (recommended)", "Leave Microsoft Defender exactly as it is" }, Width = 460 };
        defender.SelectedIndex = cfg.DefenderMode == "untouched" ? 1 : 0;

        _root.Children.Add(Section("", "Quiet mode", "Notifications wait while these programs run (games, presentations); you get one summary afterwards.",
            Field("Programs (wildcards)", quiet, "Process names, comma-separated.")));
        _root.Children.Add(Section("", "Scans", "Malware hashes, Sigma event-log scan, vulnerability check and tool versions.",
            Field("Scan times", times, "24-hour times, comma-separated. A scan missed while the PC was off runs 5 minutes after start."),
            Field("Event logs to scan", lookback, "How far back each Sigma scan looks."),
            Field("Malware hash feed", feed, "HTTPS address of a SHA256 list (signature-base format).")));
        _root.Children.Add(Section("", "Wail2Ban", "The only part of FreeEDR that blocks: computers that keep failing to sign in over the network.",
            Field("When an address keeps failing", block),
            Field("Failed sign-ins before a ban", fails),
            Field("Within (minutes)", window),
            Field("Longest ban, internet (days)", maxPub, "Bans grow 5 min, 25 min, 2 h, 10 h, 2 days, ... up to this."),
            Field("Longest ban, local network (days)", maxPriv),
            Field("Remote Desktop over IPv6", ipv6, "Block inbound Remote Desktop from every IPv6 address (failures there cannot be counted).")));
        _root.Children.Add(Section("", "Microsoft Defender", "FreeEDR never makes Defender block more than you had before.",
            Field("Attack surface reduction and ransomware protection", defender, "Audit mode lists what Defender's ASR rules and Controlled folder access would have blocked. A setting that was stronger before FreeEDR is never lowered.")));

        var save = Ui.Btn("Save settings", "primary big", () => _ = Save(), icon: "");
        var reset = Ui.Btn("Undo changes", "ghost", Refresh);
        _root.Children.Add(Ui.Row(10, save, reset));
        _pending = () => new JsonObject
        {
            ["quietProcesses"] = Split(quiet.Text).ToJsonArray(),
            ["scanTimes"] = Split(times.Text).ToJsonArray(),
            ["sigmaLookback"] = lookback.SelectedItem as string ?? "2d",
            ["iocFeedUrl"] = feed.Text?.Trim() ?? "",
            ["defenderMode"] = defender.SelectedIndex == 1 ? "untouched" : "audit",
            ["wail2ban"] = new JsonObject
            {
                ["block"] = block.IsChecked == true, ["blockRdpIpv6"] = ipv6.IsChecked == true,
                ["failCount"] = (int)(fails.Value ?? 5), ["windowSeconds"] = (int)(window.Value ?? 30) * 60,
                ["maxBanPublicSec"] = (int)(maxPub.Value ?? 90) * 86400, ["maxBanPrivateSec"] = (int)(maxPriv.Value ?? 7) * 86400,
            },
        };

        // Maintenance
        var maint = Ui.Wrap(
            Ui.Btn("Send a harmless test alert", "", _c.TestDetection, icon: ""),
            Ui.Btn("Restart engine", "", () => _ = _c.RestartEngine(), icon: ""),
            Ui.Btn("Open engine log", "", () => Shell.Notepad(_c.State.Paths.EngineLog), icon: ""),
            Ui.Btn("Open scan log", "", () => Shell.Notepad(_c.State.Paths.ScanLog), icon: ""),
            Ui.Btn("Export audit log (CSV)", "", () => _ = ExportAudit(), icon: ""),
            Ui.Btn("Forensics (Velociraptor)", "", _c.OpenForensics, icon: ""),
            Ui.Btn("User guide", "", () => Shell.OpenFile(Path.Combine(_c.State.Paths.DocsDir, "user", "USER_GUIDE.md")), icon: ""),
            Ui.Btn("Show the welcome again", "ghost", () => { _c.Prefs.WelcomeDone = false; App.Instance?.ShowWelcome(); }));
        _root.Children.Add(Section("", "Maintenance", "Diagnostics and records.", maint));
        _root.Children.Add(Section("", "Reset", "Back to a fresh install.",
            Ui.Row(12, Ui.Btn("Reset FreeEDR to defaults...", "danger", () => _ = _c.FactoryReset(), icon: ""),
                Ui.T("Removes every allow, verdict and ban, and clears the alert history.", "muted").Also(t => t.VerticalAlignment = VerticalAlignment.Center))));
        var st = _c.State.Status;
        _root.Children.Add(Ui.T($"FreeEDR {ReadVersion()}  -  engine {st?.S("version")}  -  detect-only, Wail2Ban {(cfg.Wail2Ban.Block ? "blocking" : "report-only")}  -  {_c.State.Paths.Root}", "muted"));
        _scroll.Offset = offset;
    }

    private Func<JsonObject>? _pending;

    private string ReadVersion()
    {
        try { return File.Exists(_c.State.Paths.VersionFile) ? File.ReadAllText(_c.State.Paths.VersionFile).Trim() : "(development)"; }
        catch (IOException) { return ""; }
    }

    private static IEnumerable<string> Split(string? s) => (s ?? "").Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim()).Where(x => x.Length > 0);

    private async Task Save()
    {
        if (_pending is null) return;
        var cfg = _pending();
        foreach (var t in (cfg["scanTimes"] as JsonArray)!.Select(Ps.Str)) if (!EdrConfig.IsTime(t)) { await Dialogs.Info("Settings", $"\"{t}\" is not a time (use 24-hour times like 06:00, 18:00).", true); return; }
        if (!cfg.Str("iocFeedUrl").StartsWith("https://", StringComparison.OrdinalIgnoreCase)) { await Dialogs.Info("Settings", "The malware hash feed must be an https:// address.", true); return; }
        var defenderChanged = cfg.Str("defenderMode") != _c.State.Config.DefenderMode;
        if (defenderChanged && !await Dialogs.Confirm("Microsoft Defender", cfg.Str("defenderMode") == "audit"
                ? "Put Defender's attack surface reduction rules and Controlled folder access into audit mode? Nothing is blocked; FreeEDR lists what they would have blocked."
                : "Put Defender's settings back as they were before FreeEDR? FreeEDR then only reads Defender's own detections.", "Apply")) return;
        if (await _c.SaveSettings(cfg)) Refresh();
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
        await using var s = await file.OpenWriteAsync();
        await using var w = new StreamWriter(s, new System.Text.UTF8Encoding(true));
        await w.WriteAsync(_c.AuditCsv());
        _c.Snack?.Invoke("Audit log exported.", false);
    }
}
