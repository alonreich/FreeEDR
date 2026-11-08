namespace Edr.Core;

public sealed record InstanceNames(string Mutex, string ShowEvent, string ExitEvent)
{
    public static InstanceNames For(bool dev)
    {
        var s = dev ? "-Dev" : "";
        return new InstanceNames($@"Local\FreeEDR-Tray{s}", $@"Local\FreeEDR-Tray-Show{s}", $@"Local\FreeEDR-Tray-Exit{s}");
    }
}
