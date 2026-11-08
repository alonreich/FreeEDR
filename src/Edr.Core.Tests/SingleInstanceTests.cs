using Edr.Core;
using Xunit;

namespace Edr.Core.Tests;

public class SingleInstanceTests
{
    private static InstanceNames UniqueNames()
    {
        var id = Guid.NewGuid().ToString("N");
        return new InstanceNames($@"Local\EDR-Test-{id}", $@"Local\EDR-Test-Show-{id}", $@"Local\EDR-Test-Exit-{id}");
    }

    [Fact]
    public void Second_launch_signals_show_and_gets_no_instance()
    {
        var names = UniqueNames();
        using var first = SingleInstance.Acquire(names);
        Assert.NotNull(first);
        using var shown = new ManualResetEventSlim();
        first.Listen(onShow: shown.Set, onExit: () => { });

        SingleInstance? second = null;
        var t = new Thread(() => second = SingleInstance.Acquire(names));
        t.Start(); t.Join();

        Assert.Null(second);
        Assert.True(shown.Wait(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken), "the running instance should be asked to show the dashboard");
    }

    [Fact]
    public void Exit_event_stops_the_listener()
    {
        var names = UniqueNames();
        using var first = SingleInstance.Acquire(names);
        Assert.NotNull(first);
        using var exited = new ManualResetEventSlim();
        first.Listen(onShow: () => { }, onExit: exited.Set);

        using (var ev = EventWaitHandle.OpenExisting(names.ExitEvent)) ev.Set();

        Assert.True(exited.Wait(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken));
    }

    [Fact]
    public void Dev_names_do_not_collide_with_the_installed_tray()
    {
        var prod = InstanceNames.For(dev: false);
        var dev = InstanceNames.For(dev: true);
        Assert.Equal(@"Local\FreeEDR-Tray", prod.Mutex);
        Assert.Equal(@"Local\FreeEDR-Tray-Exit", prod.ExitEvent);
        Assert.NotEqual(prod.Mutex, dev.Mutex);
        Assert.NotEqual(prod.ShowEvent, dev.ShowEvent);
    }
}
