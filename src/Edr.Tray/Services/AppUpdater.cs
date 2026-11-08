using System.ComponentModel;
using System.Diagnostics;
using Avalonia.Threading;
using Edr.Core;

namespace Edr.Tray.Services;

public enum UpdatePhase { Idle, Checking, UpToDate, Available, Downloading, Ready, Installing, Failed }

public sealed class AppUpdater
{
    private static readonly TimeSpan Every = TimeSpan.FromHours(24);
    private readonly AppRelease _release;
    private readonly Preferences _prefs;
    private DateTime _next;
    private DateTime _purgeAt = DateTime.Now.AddMinutes(2);
    private bool _interruptedChecked;
    private CancellationTokenSource? _cts;

    public AppUpdater(EdrPaths paths, Preferences prefs)
    {
        _release = new AppRelease(paths);
        _prefs = prefs;
        var last = Ps.ToDate(prefs.LastUpdateCheck);
        _next = last is { } l && DateTime.Now - l < Every ? l + Every : DateTime.Now.AddMinutes(3);
        Installed = _release.InstalledText();
        var marker = _release.PendingUpgrade();
        if (marker is not null)
            Interrupted = $"An update of FreeEDR{(marker.Str("to").Length > 0 ? " to " + marker.Str("to") : "")} did not finish (for example the PC restarted while Setup ran). " +
                          "Run FreeEDR Setup again: it finishes the update, or puts your previous version back from the backup it made.";
        _ = Task.Run(_release.PurgeInstalled);
    }

    public string? Interrupted { get; private set; }

    public string Installed { get; private set; }
    public bool DevInstall => Installed.Length == 0 || AppVersion.IsDev(Installed);
    public UpdatePhase Phase { get; private set; } = UpdatePhase.Idle;
    public AppUpdateInfo? Info { get; private set; }
    public string Message { get; private set; } = "";
    public long Done { get; private set; }
    public long Total { get; private set; }
    public DateTime? LastCheck => Ps.ToDate(_prefs.LastUpdateCheck);
    public bool Busy => Phase is UpdatePhase.Checking or UpdatePhase.Downloading or UpdatePhase.Installing;
    public bool Skipped => Info is { } i && _prefs.SkippedVersion == i.Latest.ToString();

    public event Action? Changed;
    public Action<AppUpdateInfo>? Found { get; set; }

    private void Set(UpdatePhase phase, string message)
    {
        Phase = phase;
        Message = message;
        Dispatcher.UIThread.Post(() => Changed?.Invoke());
    }

    public void Tick()
    {
        if (!Busy && DateTime.Now >= _purgeAt)
        {
            _purgeAt = DateTime.Now.AddHours(6);
            _ = Task.Run(_release.PurgeInstalled);
        }
        if (Interrupted is not null && !_interruptedChecked && !Busy)
        {
            _interruptedChecked = true;
            _ = Check(manual: true);
            return;
        }
        if (Busy || DateTime.Now < _next) return;
        _next = DateTime.Now + Every;
        if (!_prefs.UpdateCheck || DevInstall) return;
        _ = Check(manual: false);
    }

    public async Task Check(bool manual)
    {
        if (Busy) return;
        Installed = _release.InstalledText();
        Set(UpdatePhase.Checking, "Checking GitHub for a new FreeEDR release...");
        var reinstall = Interrupted is not null;
        var (info, msg, reached) = await Task.Run(() => _release.Check(reinstall: reinstall));
        _prefs.LastUpdateCheck = DateTime.Now.ToString("s");
        if (info is null)
        {
            Info = null;
            Set(reached ? UpdatePhase.UpToDate : UpdatePhase.Failed, msg);
            if (!reached) _next = DateTime.Now + TimeSpan.FromHours(2);
            return;
        }
        Info = info;
        var path = _release.SetupPath(info);
        if (File.Exists(path)) Set(UpdatePhase.Ready, $"FreeEDR {info.Latest} is downloaded and ready to install.");
        else Set(UpdatePhase.Available, msg);
        if (!manual && !Skipped && _prefs.NotifiedVersion != info.Latest.ToString())
        {
            _prefs.NotifiedVersion = info.Latest.ToString();
            Dispatcher.UIThread.Post(() => Found?.Invoke(info));
        }
    }

    public void Skip()
    {
        if (Info is null) return;
        _prefs.SkippedVersion = Info.Latest.ToString();
        Set(Phase, $"FreeEDR {Info.Latest} is skipped: you are not reminded of it again. A later version is offered as usual.");
    }

    public void Unskip()
    {
        _prefs.SkippedVersion = "";
        Set(Phase, Message);
    }

    public void Cancel() => _cts?.Cancel();

    public async Task<bool> DownloadAndInstall()
    {
        if (Busy || Info is not { } info) return false;
        var cts = _cts = new CancellationTokenSource();
        string setup;
        try
        {
            Done = 0; Total = info.Size;
            Set(UpdatePhase.Downloading, $"Downloading FreeEDR {info.Latest} ({AppRelease.Describe(info.Size)})...");
            var shown = DateTime.MinValue;
            var progress = new Progress<(long Done, long Total)>(p =>
            {
                Done = p.Done; Total = p.Total;
                if (DateTime.Now - shown < TimeSpan.FromMilliseconds(300) && p.Done < p.Total) return;
                shown = DateTime.Now;
                Changed?.Invoke();
            });
            setup = await Task.Run(() => _release.Download(info, progress, cts.Token));
        }
        catch (OperationCanceledException)
        {
            Set(UpdatePhase.Available, "Download stopped. What was downloaded is kept: the next try continues from there.");
            return false;
        }
        catch (Exception e) when (e is IOException or HttpRequestException or InvalidDataException or UnauthorizedAccessException)
        {
            Set(UpdatePhase.Failed, $"The update was not downloaded: {e.Message} Nothing was changed; try again later.");
            return false;
        }
        finally { _cts = null; cts.Dispose(); }

        var (ok, verdict, lockHandle) = await Task.Run(() => _release.Verify(info, setup));
        if (!ok || lockHandle is null)
        {
            JsonFile.TryDelete(setup);
            Set(UpdatePhase.Failed, $"{verdict} Nothing was changed.");
            return false;
        }
        Set(UpdatePhase.Installing, $"{verdict} Starting FreeEDR Setup: confirm the administrator prompt. Setup shows each step; the dashboard closes while it runs and comes back by itself.");
        Process? p;
        try { p = Process.Start(new ProcessStartInfo(setup) { UseShellExecute = true, WorkingDirectory = Path.GetDirectoryName(setup)! }); }
        catch (Win32Exception e) when (e.NativeErrorCode == 1223)
        {
            lockHandle.Dispose();
            Set(UpdatePhase.Ready, $"Installation cancelled at the administrator prompt. Nothing was changed: FreeEDR {info.Latest} stays ready to install.");
            return false;
        }
        catch (Win32Exception e)
        {
            lockHandle.Dispose();
            Set(UpdatePhase.Failed, $"FreeEDR Setup could not be started: {e.Message}");
            return false;
        }
        _ = Task.Run(async () =>
        {
            try { if (p is not null) await p.WaitForExitAsync(); }
            catch (InvalidOperationException) { }
            finally { lockHandle.Dispose(); p?.Dispose(); }
            Installed = _release.InstalledText();
            if (AppVersion.Parse(Installed) is { } now && now >= info.Latest && _release.PendingUpgrade() is null)
            {
                JsonFile.TryDelete(setup);
                Interrupted = null;
                Set(UpdatePhase.UpToDate, $"FreeEDR {Installed} is installed.");
            }
            else Set(UpdatePhase.Ready, $"Setup ended without installing {info.Latest} (cancelled, or it did not pass its checks and the previous version was kept). install.log has the details; you can try again.");
        });
        return true;
    }

    public string? InstalledNotes() => _release.InstalledNotes();

    public string? NotesSince(Version? since) => _release.NotesSinceInstalled(since);
}
