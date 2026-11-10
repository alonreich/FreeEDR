using System.Diagnostics;
using System.Security;
using Edr.Core;
using Microsoft.Win32;
using Windows.Data.Xml.Dom;
using Windows.UI.Notifications;

namespace Edr.Tray.Services;

public sealed class Notifier
{
    public const string Aumid = "FreeEDR.Tray";
    private readonly TrayState _state;
    private readonly Preferences _prefs;
    private readonly Action<string> _activated;
    private readonly Queue<DateTime> _recent = new();
    private readonly List<Rec> _digest = [];
    private readonly List<Rec> _quietQueue = [];
    private DateTime _digestDue = DateTime.MaxValue;
    private DateTime _lastQuietCheck = DateTime.MinValue;
    private bool _engineDownShown;
    private ToastNotifier? _notifier;

    public Notifier(TrayState state, Preferences prefs, Action<string> activated)
    {
        _state = state;
        _prefs = prefs;
        _activated = activated;
    }

    public void Register(string iconPng)
    {
        try
        {
            using var k = Registry.CurrentUser.CreateSubKey($@"Software\Classes\AppUserModelId\{Aumid}");
            k.SetValue("DisplayName", "FreeEDR");
            if (File.Exists(iconPng)) k.SetValue("IconUri", iconPng);
            k.SetValue("IconBackgroundColor", "FF1E2C47");
            _notifier = ToastNotificationManager.CreateToastNotifier(Aumid);
        }
        catch (Exception e) { Trace.WriteLine($"Toast registration failed: {e.Message}"); }
    }

    public bool InLearningWeek => Ps.ToDate(_state.Config.InstalledAt) is { } t && DateTime.Now - t < TimeSpan.FromDays(7);

    public void Consider(Rec e)
    {
        if (!ShouldNotify(e)) return;
        if (QuietAppRunning()) { _quietQueue.Add(e); return; }
        while (_recent.Count > 0 && (DateTime.Now - _recent.Peek()).TotalSeconds > 60) _recent.Dequeue();
        if (_recent.Count >= 3)
        {
            _digest.Add(e);
            if (_digestDue == DateTime.MaxValue) _digestDue = DateTime.Now.AddSeconds(60);
            return;
        }
        _recent.Enqueue(DateTime.Now);
        ShowEvent(e);
    }

    private bool ShouldNotify(Rec e)
    {
        var rank = Catalog.Rank(e.S("severity")) ?? 0;
        var blade = e.S("blade");
        var kind = e.S("kind");
        var detection = blade is "realtime" or "ioc" or "yara" or "sigma" or "defender";
        var pinned = Ps.Match(e.S("title"), Catalog.ConfirmPattern);
        if (blade == "system" && kind == "health") return rank >= 3 || !InLearningWeek;
        if (blade == "system" && kind == "tool-update") return true;
        if (InLearningWeek) return (detection && rank >= 4) || pinned;
        return _prefs.NotifyLevel switch
        {
            "critical" => (detection && rank >= 4) || pinned,
            "all" => (detection && rank >= 2) || (blade == "wail2ban" && rank >= 2) || (blade == "system" && kind == "scan"),
            _ => (detection && rank >= 3) || (blade == "wail2ban" && rank >= 2) ||
                 (blade == "system" && kind == "scan" && (e.S("trigger") == "manual" || rank >= 2 || e.I("newSigma") > 0)),
        };
    }

    private void ShowEvent(Rec e)
    {
        var id = e.S("id");
        var rank = Catalog.Rank(e.S("severity")) ?? 0;
        var proc = Ps.Leaf(e.S("process"));
        var body = e.S("blade") == "system" ? e.S("detail") : (proc.Length > 0 ? proc + " - " : "") + (Hints.For(e).What is { Length: > 0 } w ? Short(w, 160) : "Open FreeEDR to see what it means and what to do.");
        var pinned = Ps.Match(e.S("title"), Catalog.ConfirmPattern);
        var buttons = new List<(string Label, string Args)>();
        if (pinned) { buttons.Add(("Yes, it was me", $"me|{id}")); buttons.Add(("🤔 Explain for Dummies", $"explain|{id}")); buttons.Add(("Review", $"open|{id}")); }
        else if (e.S("blade") == "system") buttons.Add(("Open FreeEDR", "page|home"));
        else { buttons.Add(("Review", $"open|{id}")); buttons.Add(("🤔 Explain for Dummies", $"explain|{id}")); buttons.Add(("Mark reviewed", $"review|{id}")); }

        try
        {
            var (_, fgName, _) = Edr.Core.Native.Win32.ForegroundProcess();
            if (fgName.Length > 0 && !fgName.Equals("FreeEDR-Tray", StringComparison.OrdinalIgnoreCase)
                && !fgName.Equals("explorer", StringComparison.OrdinalIgnoreCase)
                && !fgName.Equals("SearchHost", StringComparison.OrdinalIgnoreCase)
                && !fgName.Equals("TextInputHost", StringComparison.OrdinalIgnoreCase)
                && !fgName.Equals("LockApp", StringComparison.OrdinalIgnoreCase))
            {
                var quietList = _prefs.QuietProcesses ?? _state.Config.QuietProcesses;
                if (!quietList.Any(q => q.Equals(fgName, StringComparison.OrdinalIgnoreCase) || q.Equals(fgName + "*", StringComparison.OrdinalIgnoreCase)))
                {
                    buttons.Add(($"Quiet while {fgName} runs", $"quiet|{fgName}"));
                }
            }
        }
        catch { }

        var scenario = rank >= 4 ? "reminder" : "";
        Show((rank >= 4 ? "Critical: " : "") + e.S("title"), body, $"open|{id}", buttons, scenario);
    }

    public void Tick()
    {
        if (_digest.Count > 0 && DateTime.Now >= _digestDue)
        {
            var n = _digest.Count;
            var crit = _digest.Count(x => Catalog.Rank(x.S("severity")) >= 4);
            _digest.Clear();
            _digestDue = DateTime.MaxValue;
            Show($"{n} more alert{(n == 1 ? "" : "s")}", crit > 0 ? $"{crit} of them critical. Open FreeEDR to review them together." : "Open FreeEDR to review them together.",
                 "page|activity", [("Review all", "page|activity")]);
        }
        if (_quietQueue.Count > 0 && (DateTime.Now - _lastQuietCheck).TotalSeconds >= 10)
        {
            _lastQuietCheck = DateTime.Now;
            if (!QuietAppRunning())
            {
                var n = _quietQueue.Count;
                var high = _quietQueue.Count(x => Catalog.Rank(x.S("severity")) >= 3);
                _quietQueue.Clear();
                Show($"While you were gaming: {n} alert{(n == 1 ? "" : "s")}", $"{high} high or critical. Open FreeEDR to review them.", "page|activity", [("Review", "page|activity")]);
            }
        }
        var alive = _state.EngineAlive;
        if (!alive && !_engineDownShown && _state.Status is not null)
        {
            _engineDownShown = true;
            Show("FreeEDR engine is not running", "Detection is off. Open FreeEDR > Settings > Restart engine, or restart the PC.", "page|home", [("Open FreeEDR", "page|home")], "reminder");
        }
        if (alive) _engineDownShown = false;
    }

    public void Show(string title, string text, string launchArgs, IReadOnlyList<(string Label, string Args)> buttons, string scenario = "")
    {
        if (_notifier is null) return;
        try
        {
            var sb = new System.Text.StringBuilder();
            sb.Append($"<toast launch=\"{Esc(launchArgs)}\"{(scenario.Length > 0 ? $" scenario=\"{scenario}\"" : "")}><visual><binding template=\"ToastGeneric\">");
            sb.Append($"<text hint-maxLines=\"2\">{Esc(Short(title, 120))}</text><text>{Esc(Short(text, 260))}</text>");
            sb.Append("<text placement=\"attribution\">FreeEDR</text></binding></visual>");
            if (buttons.Count > 0)
            {
                sb.Append("<actions>");
                foreach (var (label, args) in buttons.Take(5)) sb.Append($"<action content=\"{Esc(label)}\" arguments=\"{Esc(args)}\" activationType=\"foreground\"/>");
                if (scenario == "reminder") sb.Append("<action content=\"Dismiss\" arguments=\"dismiss\" activationType=\"system\"/>");
                sb.Append("</actions>");
            }
            sb.Append("</toast>");
            var xml = new XmlDocument();
            xml.LoadXml(sb.ToString());
            var toast = new ToastNotification(xml) { ExpirationTime = DateTimeOffset.Now.AddDays(2) };
            toast.Activated += (_, a) =>
            {
                if (a is ToastActivatedEventArgs args) _activated(args.Arguments);
            };
            _notifier.Show(toast);
        }
        catch (Exception e) { Trace.WriteLine($"Toast failed: {e.Message}"); }
    }

    private bool QuietAppRunning()
    {
        if (Edr.Core.Native.Win32.IsFullScreenGameRunning()) return true;
        IReadOnlyList<string> patterns = _prefs.QuietProcesses ?? _state.Config.QuietProcesses;
        if (patterns.Count == 0) return false;
        try
        {
            foreach (var p in Process.GetProcesses())
                using (p)
                {
                    var name = p.ProcessName;
                    if (patterns.Any(pat =>
                    {
                        var clean = EdrConfig.CleanQuietName(pat);
                        return Ps.Like(name, clean) || Ps.Like(name, pat);
                    })) return true;
                }
        }
        catch (InvalidOperationException) { }
        return false;
    }

    private static string Short(string s, int max) => s.Length > max ? s[..(max - 3)] + "..." : s;
    private static string Esc(string s) => SecurityElement.Escape(s) ?? "";
}
