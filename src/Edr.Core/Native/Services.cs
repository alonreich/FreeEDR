using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Edr.Core.Native;

[SupportedOSPlatform("windows")]
public static unsafe partial class Services
{
    public enum State { Missing = 0, Stopped = 1, StartPending = 2, StopPending = 3, Running = 4, ContinuePending = 5, PausePending = 6, Paused = 7 }

    private const uint ScManagerAll = 0xF003F, ScConnect = 0x0001;
    private const uint ServiceAll = 0xF01FF, ServiceQuery = 0x0004, ServiceStart = 0x0010, ServiceStop = 0x0020, DeleteAccess = 0x10000;

    public static State Query(string name)
    {
        var scm = OpenSCManagerW(null, null, ScConnect);
        if (scm == 0) return State.Missing;
        try
        {
            var s = OpenServiceW(scm, name, ServiceQuery);
            if (s == 0) return State.Missing;
            try { return QueryServiceStatus(s, out var st) ? (State)st.dwCurrentState : State.Missing; }
            finally { CloseServiceHandle(s); }
        }
        finally { CloseServiceHandle(scm); }
    }

    public static bool Exists(string name) => Query(name) != State.Missing;

    public static bool Start(string name, int waitSeconds = 20)
    {
        var ok = WithService(name, ServiceStart | ServiceQuery, s => StartServiceW(s, 0, 0) || Marshal.GetLastWin32Error() == 1056);
        return ok && WaitFor(name, State.Running, waitSeconds);
    }

    public static bool Stop(string name, int waitSeconds = 30)
    {
        if (Query(name) is State.Missing or State.Stopped) return true;
        WithService(name, ServiceStop | ServiceQuery, s => ControlService(s, 1, out _));
        return WaitFor(name, State.Stopped, waitSeconds);
    }

    public static bool WaitFor(string name, State want, int seconds)
    {
        for (var i = 0; i < seconds * 4; i++)
        {
            var st = Query(name);
            if (st == want || (want == State.Stopped && st == State.Missing)) return true;
            Thread.Sleep(250);
        }
        return Query(name) == want;
    }

    public static void CreateOrUpdate(string name, string displayName, string description, string binaryPath, string[]? requiredPrivileges = null, bool serviceSid = false)
    {
        var scm = OpenSCManagerW(null, null, ScManagerAll);
        if (scm == 0) throw new IOException($"Cannot open the service manager (error {Marshal.GetLastWin32Error()})");
        try
        {
            var s = OpenServiceW(scm, name, ServiceAll);
            if (s == 0)
            {
                s = CreateServiceW(scm, name, displayName, ServiceAll, 0x10, 2, 1,
                                   binaryPath, null, 0, null, null, null);
                if (s == 0) throw new IOException($"CreateService failed (error {Marshal.GetLastWin32Error()})");
            }
            else if (!ChangeServiceConfigW(s, 0x10, 2, 1, binaryPath, null, 0, null, null, null, displayName))
                throw new IOException($"ChangeServiceConfig failed (error {Marshal.GetLastWin32Error()})");
            try
            {
                fixed (char* d = description)
                {
                    var desc = new ServiceDescription { lpDescription = (nint)d };
                    ChangeServiceConfig2W(s, 1, &desc);
                }
                var actions = stackalloc ScAction[3];
                actions[0] = new ScAction { Type = 1, Delay = 10_000 };
                actions[1] = new ScAction { Type = 1, Delay = 30_000 };
                actions[2] = new ScAction { Type = 1, Delay = 60_000 };
                var fa = new ServiceFailureActions { dwResetPeriod = 86_400, cActions = 3, lpsaActions = (nint)actions };
                ChangeServiceConfig2W(s, 2, &fa);
                var flag = new FailureActionsFlag { fFailureActionsOnNonCrashFailures = 1 };
                ChangeServiceConfig2W(s, 4, &flag);
                if (serviceSid)
                {
                    var sid = 1u;
                    if (!ChangeServiceConfig2W(s, 5, &sid)) throw new IOException($"Service SID type failed (error {Marshal.GetLastWin32Error()})");
                }
                if (requiredPrivileges is { Length: > 0 })
                {
                    var multi = string.Join("\0", requiredPrivileges) + "\0\0";
                    fixed (char* m = multi)
                    {
                        var p = (nint)m;
                        if (!ChangeServiceConfig2W(s, 6, &p)) throw new IOException($"Required privileges failed (error {Marshal.GetLastWin32Error()})");
                    }
                }
            }
            finally { CloseServiceHandle(s); }
        }
        finally { CloseServiceHandle(scm); }
    }

    public static bool Delete(string name) => WithService(name, DeleteAccess | ServiceStop | ServiceQuery, s => DeleteService(s) || Marshal.GetLastWin32Error() == 1072);

    private static bool WithService(string name, uint access, Func<nint, bool> action)
    {
        var scm = OpenSCManagerW(null, null, ScConnect);
        if (scm == 0) return false;
        try
        {
            var s = OpenServiceW(scm, name, access);
            if (s == 0) return false;
            try { return action(s); }
            finally { CloseServiceHandle(s); }
        }
        finally { CloseServiceHandle(scm); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus { public uint dwServiceType, dwCurrentState, dwControlsAccepted, dwWin32ExitCode, dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint; }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceDescription { public nint lpDescription; }

    [StructLayout(LayoutKind.Sequential)]
    private struct ScAction { public uint Type, Delay; }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceFailureActions { public uint dwResetPeriod; public nint lpRebootMsg, lpCommand; public uint cActions; public nint lpsaActions; }

    [StructLayout(LayoutKind.Sequential)]
    private struct FailureActionsFlag { public int fFailureActionsOnNonCrashFailures; }

    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint OpenSCManagerW(string? machine, string? db, uint access);

    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint OpenServiceW(nint scm, string name, uint access);

    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint CreateServiceW(nint scm, string name, string display, uint access, uint type, uint start, uint error, string path,
                                               string? group, nint tag, string? deps, string? user, string? password);

    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ChangeServiceConfigW(nint s, uint type, uint start, uint error, string? path, string? group, nint tag, string? deps,
                                                     string? user, string? password, string? display);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ChangeServiceConfig2W(nint s, uint level, void* info);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryServiceStatus(nint s, out ServiceStatus status);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool StartServiceW(nint s, uint argc, nint argv);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ControlService(nint s, uint control, out ServiceStatus status);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DeleteService(nint s);

    [LibraryImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseServiceHandle(nint h);
}

[SupportedOSPlatform("windows")]
public static unsafe partial class ServiceHost
{
    private static string _name = "";
    private static Action<CancellationToken>? _run;
    private static nint _statusHandle;
    private static readonly CancellationTokenSource Stop = new();
    private static ServiceStatusRaw _status;

    public static bool TryRun(string name, Action<CancellationToken> run)
    {
        _name = name;
        _run = run;
        var namePtr = Marshal.StringToHGlobalUni(name);
        try
        {
            var table = stackalloc TableEntry[2];
            table[0] = new TableEntry { Name = namePtr, Proc = (nint)(delegate* unmanaged[Stdcall]<uint, nint, void>)&ServiceMain };
            table[1] = default;
            return StartServiceCtrlDispatcherW(table);
        }
        finally { Marshal.FreeHGlobal(namePtr); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvStdcall)])]
    private static void ServiceMain(uint argc, nint argv)
    {
        var namePtr = Marshal.StringToHGlobalUni(_name);
        _statusHandle = RegisterServiceCtrlHandlerExW(namePtr, &Handler, 0);
        Marshal.FreeHGlobal(namePtr);
        if (_statusHandle == 0) return;
        Report(4, 0x1 | 0x4);
        try { _run?.Invoke(Stop.Token); }
        catch (Exception) { Report(1, 0, exitCode: 1); return; }
        Report(1, 0);
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvStdcall)])]
    private static uint Handler(uint control, uint eventType, nint eventData, nint context)
    {
        switch (control)
        {
            case 1:
            case 5:
                Report(3, 0, waitHint: 30_000);
                Stop.Cancel();
                return 0;
            case 4:
                return 0;
            default:
                return 120;
        }
    }

    private static void Report(uint state, uint accept, uint exitCode = 0, uint waitHint = 0)
    {
        _status.dwServiceType = 0x10;
        _status.dwCurrentState = state;
        _status.dwControlsAccepted = accept;
        _status.dwWin32ExitCode = exitCode;
        _status.dwWaitHint = waitHint;
        _status.dwCheckPoint = state is 2 or 3 ? _status.dwCheckPoint + 1 : 0;
        fixed (ServiceStatusRaw* p = &_status) SetServiceStatus(_statusHandle, p);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TableEntry { public nint Name; public nint Proc; }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusRaw { public uint dwServiceType, dwCurrentState, dwControlsAccepted, dwWin32ExitCode, dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint; }

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool StartServiceCtrlDispatcherW(TableEntry* table);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    private static partial nint RegisterServiceCtrlHandlerExW(nint name, delegate* unmanaged[Stdcall]<uint, uint, nint, nint, uint> handler, nint context);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetServiceStatus(nint handle, ServiceStatusRaw* status);
}
