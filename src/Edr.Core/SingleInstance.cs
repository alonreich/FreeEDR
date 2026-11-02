namespace Edr.Core;

/// <summary>
/// One tray per session. The first instance owns the mutex and listens for two named events:
/// Show (a second launch, e.g. the Start-menu shortcut) and Exit (the installer closing the tray).
/// </summary>
public sealed class SingleInstance : IDisposable
{
    private readonly Mutex _mutex;
    private readonly EventWaitHandle _show;
    private readonly EventWaitHandle _exit;
    private readonly ManualResetEvent _stop = new(false);
    private Thread? _listener;

    private SingleInstance(Mutex mutex, EventWaitHandle show, EventWaitHandle exit)
    {
        _mutex = mutex;
        _show = show;
        _exit = exit;
    }

    /// <summary>The owning instance, or null after asking the running one to show its dashboard.</summary>
    public static SingleInstance? Acquire(InstanceNames names, bool signalShowIfRunning = true)
    {
        var mutex = new Mutex(true, names.Mutex, out var created);
        var show = new EventWaitHandle(false, EventResetMode.AutoReset, names.ShowEvent);
        var exit = new EventWaitHandle(false, EventResetMode.AutoReset, names.ExitEvent);
        if (created) return new SingleInstance(mutex, show, exit);
        if (signalShowIfRunning) show.Set();
        mutex.Dispose(); show.Dispose(); exit.Dispose();
        return null;
    }

    /// <summary>Calls the handlers on a background thread; marshal to the UI thread yourself.</summary>
    public void Listen(Action onShow, Action onExit)
    {
        _listener = new Thread(() =>
        {
            var handles = new WaitHandle[] { _show, _exit, _stop };
            while (true)
            {
                switch (WaitHandle.WaitAny(handles))
                {
                    case 0: onShow(); break;
                    case 1: onExit(); return;
                    default: return;
                }
            }
        }) { IsBackground = true, Name = "EDR-Tray signals" };
        _listener.Start();
    }

    public void Dispose()
    {
        _stop.Set();
        _listener?.Join(1000);
        try { _mutex.ReleaseMutex(); } catch (ApplicationException) { }   // released on another thread or already gone
        _mutex.Dispose(); _show.Dispose(); _exit.Dispose(); _stop.Dispose();
    }
}
