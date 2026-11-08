namespace Edr.Core;

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
        try { _mutex.ReleaseMutex(); } catch (ApplicationException) { }
        _mutex.Dispose(); _show.Dispose(); _exit.Dispose(); _stop.Dispose();
    }
}
