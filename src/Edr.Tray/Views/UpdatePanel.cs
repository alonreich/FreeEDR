using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Edr.Core;
using Edr.Tray.Services;

namespace Edr.Tray.Views;

public sealed class UpdatePanel : UserControl
{
    private readonly Controller _c;

    public UpdatePanel(Controller c)
    {
        _c = c;
        c.Updater.Changed += Build;
        Build();
    }

    private static TextBlock Wrap(string text, string classes) => Ui.T(text, classes).Also(t => t.TextWrapping = TextWrapping.Wrap);

    private void Build()
    {
        var u = _c.Updater;
        var info = u.Info;
        var installed = u.Installed.Length > 0 ? u.Installed : "(development copy)";
        var pill = u.Phase switch
        {
            UpdatePhase.Checking => Ui.Pill("Checking...", Palette.Info),
            UpdatePhase.Downloading => Ui.Pill("Downloading", Palette.Info),
            UpdatePhase.Installing => Ui.Pill("Installing", Palette.Info),
            UpdatePhase.Ready => Ui.Pill($"{info?.Latest} ready to install", Palette.Warn),
            UpdatePhase.Available when u.Skipped => Ui.Pill($"{info?.Latest} skipped", Palette.Muted),
            UpdatePhase.Available => Ui.Pill($"{info?.Latest} available", Palette.Warn),
            UpdatePhase.UpToDate => Ui.Pill("Up to date", Palette.Ok),
            UpdatePhase.Failed => Ui.Pill("Not checked", Palette.Danger),
            _ => Ui.Pill(u.DevInstall ? "Developer build" : "Not checked yet", Palette.Muted),
        };
        var stack = Ui.Stack(12,
            Ui.Row(10, Ui.Icon("", 18, Palette.Accent), Ui.Stack(2, Ui.Row(10, Ui.T("FreeEDR updates", "h2"), pill),
                Ui.T("New versions come only from FreeEDR's GitHub releases. Before Setup starts, FreeEDR checks the download's SHA256 fingerprint and its digital signature.", "muted"))),
            Wrap($"Installed: FreeEDR {installed}" + (info is not null ? $"   -   latest release: {info.Latest}{(info.Published is { } p ? $" ({p:dd/MM/yyyy})" : "")}" : "") +
                 (u.LastCheck is { } lc ? $"   -   last check: {lc:ddd dd/MM HH:mm}" : ""), "sub"));
        if (u.Interrupted is { } stuck) stack.Children.Add(Ui.Card(Ui.Stack(6, Ui.T("The last update did not finish", "h3"), Wrap(stuck, "sub")), "tile"));
        if (u.Message.Length > 0) stack.Children.Add(Wrap(u.Message, u.Phase == UpdatePhase.Failed ? "sub error" : "sub"));
        if (u.DevInstall && u.Phase == UpdatePhase.Idle)
            stack.Children.Add(Wrap("This is a developer build: FreeEDR does not check for updates by itself. \"Check now\" shows the latest release.", "muted"));
        if (u.Phase == UpdatePhase.Downloading)
        {
            stack.Children.Add(new ProgressBar { Minimum = 0, Maximum = Math.Max(1, u.Total), Value = u.Done, Height = 6, MaxWidth = 560, HorizontalAlignment = HorizontalAlignment.Left });
            stack.Children.Add(Ui.T($"{AppRelease.Describe(u.Done)} of {AppRelease.Describe(u.Total)} - you can keep working; FreeEDR keeps protecting this PC.", "muted"));
        }
        if (info is not null && info.Notes.Length > 0 && u.Phase is UpdatePhase.Available or UpdatePhase.Ready)
            stack.Children.Add(Ui.Card(Ui.Stack(6, Ui.T(Changelog.IsCombined(info.Notes) ? $"What's new since your version (up to {info.Latest})" : $"What's new in {info.Latest}", "h3"), Wrap(info.Notes, "sub")), "tile"));

        var buttons = new List<Control>();
        switch (u.Phase)
        {
            case UpdatePhase.Available or UpdatePhase.Ready:
                buttons.Add(Ui.Btn(u.Phase == UpdatePhase.Ready ? $"Install {info?.Latest}" : $"Download and install {info?.Latest}", "primary", () => _ = _c.InstallUpdate(), icon: "",
                    tip: "Asks first. Setup keeps your settings and puts the previous version back by itself if the new one does not pass its checks."));
                buttons.Add(u.Skipped
                    ? Ui.Btn("Remind me about this version", "", u.Unskip)
                    : Ui.Btn("Skip this version", "", u.Skip, tip: "No more reminders for this version; a later one is offered as usual."));
                break;
            case UpdatePhase.Downloading:
                buttons.Add(Ui.Btn("Stop download", "", u.Cancel, tip: "What was downloaded is kept; the next try continues from there."));
                break;
        }
        if (!u.Busy) buttons.Add(Ui.Btn("Check now", "", () => _ = u.Check(manual: true), icon: "", tip: "Checks GitHub immediately for newer signed FreeEDR releases."));
        buttons.Add(Ui.Btn("What's new in my version", "ghost", () => _ = _c.ShowWhatsNew(), tip: "Shows the release notes and improvements included in your installed version."));
        if (info is not null) buttons.Add(Ui.Btn("Release page", "ghost", () => Shell.OpenUrl(info.PageUrl), tip: "Opens the GitHub release page for this version in your default web browser."));
        stack.Children.Add(Ui.Wrap([.. buttons]));

        var auto = new CheckBox
        {
            Content = "Check for new versions automatically (once a day, in the background)",
            IsChecked = _c.Prefs.UpdateCheck,
            IsEnabled = !u.DevInstall
        };
        ToolTip.SetTip(auto, u.DevInstall ? "Automatic update checks are disabled in development builds." : "Checks once every 24 hours in the background for signed FreeEDR releases.");
        Avalonia.Automation.AutomationProperties.SetHelpText(auto, u.DevInstall ? "Automatic update checks are disabled in development builds." : "Checks once every 24 hours in the background for signed FreeEDR releases.");
        auto.IsCheckedChanged += (_, _) => _c.Prefs.UpdateCheck = auto.IsChecked == true;
        stack.Children.Add(auto);
        Content = Ui.Card(stack);
    }
}
