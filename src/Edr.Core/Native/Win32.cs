using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Edr.Core.Native;

/// <summary>Small Win32 helpers (LibraryImport source-generated P/Invoke, NativeAOT-safe).</summary>
[SupportedOSPlatform("windows")]
public static partial class Win32
{
    // ---- command lines -------------------------------------------------------------------------------

    /// <summary>CommandLineToArgvW: how Windows programs split their command line.</summary>
    public static string[] SplitCommandLine(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return [];
        var p = CommandLineToArgvW(commandLine, out var argc);
        if (p == 0) return [];
        try
        {
            var result = new string[argc];
            for (var i = 0; i < argc; i++) result[i] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(p, i * IntPtr.Size)) ?? "";
            return result;
        }
        finally { LocalFree(p); }
    }

    [LibraryImport("shell32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial nint CommandLineToArgvW(string lpCmdLine, out int pNumArgs);

    [LibraryImport("kernel32.dll")]
    private static partial nint LocalFree(nint hMem);

    // ---- file identity -------------------------------------------------------------------------------

    /// <summary>Volume serial + file index + size + last write: a cache key that changes when the file is replaced.</summary>
    public static string? FileIdentity(string path)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (GetFileInformationByHandle(fs.SafeFileHandle.DangerousGetHandle(), out var fi))
            {
                var index = ((ulong)fi.FileIndexHigh << 32) | fi.FileIndexLow;
                var size = ((ulong)fi.FileSizeHigh << 32) | fi.FileSizeLow;
                var write = ((long)fi.LastWriteHigh << 32) | fi.LastWriteLow;
                return $"{fi.VolumeSerialNumber:X8}:{index:X16}:{size}:{write}";
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        return null;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public uint CreationLow, CreationHigh, AccessLow, AccessHigh;
        public uint LastWriteLow, LastWriteHigh;
        public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFileInformationByHandle(nint hFile, out ByHandleFileInformation info);

    // ---- processes -----------------------------------------------------------------------------------

    public sealed record ProcInfo(int Pid, int ParentPid, string Path, DateTime Created);

    /// <summary>One snapshot of every process: id, parent id, full image path (when readable) and start time.</summary>
    public static Dictionary<int, ProcInfo> ProcessSnapshot()
    {
        var map = new Dictionary<int, ProcInfo>();
        var snap = CreateToolhelp32Snapshot(0x2, 0);   // TH32CS_SNAPPROCESS
        if (snap == -1) return map;
        try
        {
            var e = new ProcessEntry32 { dwSize = (uint)Marshal.SizeOf<ProcessEntry32>() };
            if (!Process32FirstW(snap, ref e)) return map;
            do
            {
                var pid = (int)e.th32ProcessID;
                if (pid <= 4) continue;
                var (path, created) = ImageAndStart(pid);
                map[pid] = new ProcInfo(pid, (int)e.th32ParentProcessID, path, created);
            } while (Process32NextW(snap, ref e));
        }
        finally { CloseHandle(snap); }
        return map;
    }

    public static (string Path, DateTime Created) ImageAndStart(int pid)
    {
        var h = OpenProcess(0x1000, false, (uint)pid);   // PROCESS_QUERY_LIMITED_INFORMATION
        if (h == 0) return ("", DateTime.MinValue);
        try
        {
            var buf = new char[1024];
            var len = (uint)buf.Length;
            var path = QueryFullProcessImageNameW(h, 0, buf, ref len) ? new string(buf, 0, (int)len) : "";
            var created = GetProcessTimes(h, out var c, out _, out _, out _) ? DateTime.FromFileTime(c) : DateTime.MinValue;
            return (path, created);
        }
        finally { CloseHandle(h); }
    }

    /// <summary>The command line of another process (Windows 8.1+, ProcessCommandLineInformation), or "".</summary>
    public static string CommandLineOf(int pid)
    {
        var h = OpenProcess(0x1000, false, (uint)pid);
        if (h == 0) return "";
        try
        {
            var size = 0;
            NtQueryInformationProcess(h, 60, 0, 0, ref size);
            if (size <= 0 || size > 1 << 20) return "";
            var buf = Marshal.AllocHGlobal(size);
            try
            {
                if (NtQueryInformationProcess(h, 60, buf, size, ref size) != 0) return "";
                var length = (ushort)Marshal.ReadInt16(buf);
                var str = Marshal.ReadIntPtr(buf, IntPtr.Size);   // UNICODE_STRING.Buffer (after Length, MaximumLength + padding)
                return str == 0 ? "" : Marshal.PtrToStringUni(str, length / 2) ?? "";
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        finally { CloseHandle(h); }
    }

    /// <summary>Terminates a process (installer/uninstaller only: stopping FreeEDR's own processes).</summary>
    public static void Kill(int pid)
    {
        try { using var p = System.Diagnostics.Process.GetProcessById(pid); p.Kill(true); p.WaitForExit(5000); }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException or Win32Exception or NotSupportedException) { }
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct ProcessEntry32
    {
        public uint dwSize, cntUsage, th32ProcessID;
        public nint th32DefaultHeapID;
        public uint th32ModuleID, cntThreads, th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        public fixed char szExeFile[260];
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nint CreateToolhelp32Snapshot(uint flags, uint pid);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool Process32FirstW(nint snap, ref ProcessEntry32 entry);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool Process32NextW(nint snap, ref ProcessEntry32 entry);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nint OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);

    [LibraryImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryFullProcessImageNameW(nint h, uint flags, [Out] char[] name, ref uint size);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetProcessTimes(nint h, out long creation, out long exit, out long kernel, out long user);

    [LibraryImport("ntdll.dll")]
    private static partial int NtQueryInformationProcess(nint h, int infoClass, nint info, int length, ref int returnLength);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CloseHandle(nint h);

    // ---- Application event log ("wail2ban" source) ---------------------------------------------------

    /// <summary>Writes one entry to the Application log (types: 4 information, 2 warning, 1 error). Never throws.</summary>
    public static void WriteAppEvent(string source, string text, int id, ushort type = 4)
    {
        var h = RegisterEventSourceW(null, source);
        if (h == 0) return;
        try
        {
            var p = Marshal.StringToHGlobalUni(text);
            var arr = Marshal.AllocHGlobal(IntPtr.Size);
            try
            {
                Marshal.WriteIntPtr(arr, p);
                ReportEventW(h, type, 0, (uint)id, 0, 1, 0, arr, 0);
            }
            finally { Marshal.FreeHGlobal(arr); Marshal.FreeHGlobal(p); }
        }
        finally { DeregisterEventSource(h); }
    }

    [LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial nint RegisterEventSourceW(string? server, string source);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ReportEventW(nint h, ushort type, ushort category, uint id, nint sid, ushort numStrings, uint dataSize, nint strings, nint data);

    [LibraryImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DeregisterEventSource(nint h);

    // ---- identity ------------------------------------------------------------------------------------

    public static bool IsAdministrator()
    {
        using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(id).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    public static bool IsSystem()
    {
        using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
        return id.User?.Value == EdrPaths.SystemSid;
    }
}
