namespace Edr.Core;

/// <summary>
/// Kernel object names shared with EDR-Tray.ps1 and Install-EDR.ps1 (EDR-Common.ps1 $TrayMutex etc.): one tray per session, "show the dashboard"
/// from a second launch, and the installer's exit signal. <c>--dev</c> appends a suffix so a development build can
/// run next to the installed tray.
/// </summary>
public sealed record InstanceNames(string Mutex, string ShowEvent, string ExitEvent)
{
    public static InstanceNames For(bool dev)
    {
        var s = dev ? "-Dev" : "";
        return new InstanceNames($@"Local\FreeEDR-Tray{s}", $@"Local\FreeEDR-Tray-Show{s}", $@"Local\FreeEDR-Tray-Exit{s}");
    }
}
