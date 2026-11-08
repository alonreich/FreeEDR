using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Edr.Core.Native;

[SupportedOSPlatform("windows")]
public static unsafe partial class Sandbox
{
    public sealed record Result(bool Started, int Exit, string Output, string Error);

    public static Result RunCapture(string exe, IEnumerable<string> args, int timeoutSeconds = 60, int memoryMb = 512, string? workDir = null,
                                    IReadOnlyDictionary<string, string>? env = null, CancellationToken ct = default, int maxOutputChars = 1_000_000)
    {
        nint proc = 0, tok = 0, low = 0, admins = 0, job = 0, pipeRead = 0, pipeWrite = 0, attrs = 0;
        var pi = default(ProcessInformation);
        try
        {
            if (!OpenProcessToken(GetCurrentProcess(), 0x0001 | 0x0002 | 0x0008 | 0x0080, out proc)) return Fail("OpenProcessToken");
            if (!ConvertStringSidToSidW("S-1-5-32-544", out admins) || !ConvertStringSidToSidW("S-1-16-4096", out low)) return Fail("ConvertStringSidToSid");
            var disable = new SidAndAttributes { Sid = admins, Attributes = 0 };
            if (!CreateRestrictedToken(proc, 0x1, 1, &disable, 0, 0, 0, 0, out tok)) return Fail("CreateRestrictedToken");
            var label = new TokenMandatoryLabel { Label = new SidAndAttributes { Sid = low, Attributes = 0x20 } };
            if (!SetTokenInformation(tok, 25, &label, (uint)(sizeof(TokenMandatoryLabel) + GetLengthSid(low)))) return Fail("SetTokenInformation(integrity)");

            job = CreateJobObjectW(0, null);
            if (job == 0) return Fail("CreateJobObject");
            var limits = new JobExtendedLimits();
            limits.Basic.LimitFlags = 0x2000 | 0x0008 | 0x0100 | 0x0400;
            limits.Basic.ActiveProcessLimit = 1;
            limits.ProcessMemoryLimit = (nuint)((long)memoryMb * 1024 * 1024);
            if (!SetInformationJobObject(job, 9, &limits, (uint)sizeof(JobExtendedLimits))) return Fail("SetInformationJobObject");

            var sa = new SecurityAttributes { Length = (uint)sizeof(SecurityAttributes), Inherit = 1 };
            if (!CreatePipe(out pipeRead, out pipeWrite, &sa, 0)) return Fail("CreatePipe");
            SetHandleInformation(pipeRead, 1, 0);

            nuint attrSize = 0;
            InitializeProcThreadAttributeList(0, 1, 0, ref attrSize);
            attrs = Marshal.AllocHGlobal((nint)attrSize);
            if (!InitializeProcThreadAttributeList(attrs, 1, 0, ref attrSize)) { Marshal.FreeHGlobal(attrs); attrs = 0; return Fail("InitializeProcThreadAttributeList"); }
            var inherit = pipeWrite;
            if (!UpdateProcThreadAttribute(attrs, 0, 0x20002, &inherit, (nuint)sizeof(nint), 0, 0)) return Fail("UpdateProcThreadAttribute");

            var si = new StartupInfoEx { Info = new StartupInfo { Cb = (uint)sizeof(StartupInfoEx), Flags = 0x100, StdOutput = pipeWrite, StdError = pipeWrite }, AttributeList = attrs };
            var cmd = CommandLine(exe, args) + "\0";
            var block = EnvironmentBlock(env);
            fixed (char* c = cmd)
            fixed (char* e = block)
            {
                var flags = 0x00000004u | 0x08000000 | 0x01000000 | 0x00080000 | (block is null ? 0u : 0x400);
                if (!CreateProcessAsUserW(tok, exe, c, 0, 0, true, flags, (nint)e, workDir ?? Path.GetDirectoryName(exe), &si, &pi)
                    && !CreateProcessAsUserW(tok, exe, c, 0, 0, true, flags & ~0x01000000u, (nint)e, workDir ?? Path.GetDirectoryName(exe), &si, &pi))
                    return Fail("CreateProcessAsUser");
            }
            if (!AssignProcessToJobObject(job, pi.Process)) { TerminateProcess(pi.Process, 1); return Fail("AssignProcessToJobObject"); }
            CloseHandle(pipeWrite); pipeWrite = 0;

            using var reader = new StreamReader(new FileStream(new SafeFileHandle(pipeRead, ownsHandle: true), FileAccess.Read, 4096), Encoding.UTF8);
            pipeRead = 0;
            var output = reader.ReadToEndAsync();
            ResumeThread(pi.Thread);
            var deadline = DateTime.UtcNow.AddSeconds(timeoutSeconds);
            while (WaitForSingleObject(pi.Process, 500) != 0)
            {
                if (!ct.IsCancellationRequested && DateTime.UtcNow < deadline) continue;
                TerminateJobObject(job, 1);
                output.Wait(2000);
                return new(true, -1, "", ct.IsCancellationRequested ? "cancelled" : "timeout");
            }
            GetExitCodeProcess(pi.Process, out var exit);
            var text = output.Wait(5000) ? output.Result : "";
            if (text.Length > maxOutputChars) text = text[..maxOutputChars];
            return new(true, (int)exit, text, "");
        }
        finally
        {
            if (pi.Thread != 0) CloseHandle(pi.Thread);
            if (pi.Process != 0) CloseHandle(pi.Process);
            if (pipeWrite != 0) CloseHandle(pipeWrite);
            if (pipeRead != 0) CloseHandle(pipeRead);
            if (attrs != 0) { DeleteProcThreadAttributeList(attrs); Marshal.FreeHGlobal(attrs); }
            if (job != 0) CloseHandle(job);
            if (tok != 0) CloseHandle(tok);
            if (proc != 0) CloseHandle(proc);
            if (low != 0) LocalFree(low);
            if (admins != 0) LocalFree(admins);
        }
    }

    private static string? EnvironmentBlock(IReadOnlyDictionary<string, string>? overrides)
    {
        if (overrides is null || overrides.Count == 0) return null;
        var vars = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (System.Collections.DictionaryEntry kv in Environment.GetEnvironmentVariables()) vars[(string)kv.Key] = (string?)kv.Value ?? "";
        foreach (var (k, v) in overrides) vars[k] = v;
        var sb = new StringBuilder();
        foreach (var (k, v) in vars) sb.Append(k).Append('=').Append(v).Append('\0');
        return sb.Append('\0').ToString();
    }

    public static bool LowIntegrityFolder(string dir)
    {
        Directory.CreateDirectory(dir);
        var (rc, _) = Tools.RunCapture(Path.Combine(EdrPaths.System32, "icacls.exe"), [dir, "/setintegritylevel", "(OI)(CI)low"], timeoutSeconds: 30);
        return rc == 0;
    }

    private static Result Fail(string step) => new(false, -1, "", $"{step} failed (error {Marshal.GetLastPInvokeError()})");

    public static string CommandLine(string exe, IEnumerable<string> args)
    {
        var sb = new StringBuilder();
        Quote(sb, exe);
        foreach (var a in args) { sb.Append(' '); Quote(sb, a); }
        return sb.ToString();
    }

    private static void Quote(StringBuilder sb, string a)
    {
        if (a.Length > 0 && a.IndexOfAny([' ', '\t', '\n', '\v', '"']) < 0) { sb.Append(a); return; }
        sb.Append('"');
        for (var i = 0; i < a.Length; i++)
        {
            var slashes = 0;
            while (i < a.Length && a[i] == '\\') { slashes++; i++; }
            if (i == a.Length) { sb.Append('\\', slashes * 2); break; }
            if (a[i] == '"') sb.Append('\\', slashes * 2 + 1).Append('"');
            else sb.Append('\\', slashes).Append(a[i]);
        }
        sb.Append('"');
    }

    [StructLayout(LayoutKind.Sequential)] private struct SidAndAttributes { public nint Sid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)] private struct TokenMandatoryLabel { public SidAndAttributes Label; }
    [StructLayout(LayoutKind.Sequential)] private struct SecurityAttributes { public uint Length; public nint Descriptor; public int Inherit; }
    [StructLayout(LayoutKind.Sequential)] private struct ProcessInformation { public nint Process, Thread; public uint ProcessId, ThreadId; }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfo
    {
        public uint Cb;
        public nint Reserved, Desktop, Title;
        public uint X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags;
        public ushort ShowWindow, Reserved2Size;
        public nint Reserved2, StdInput, StdOutput, StdError;
    }

    [StructLayout(LayoutKind.Sequential)] private struct StartupInfoEx { public StartupInfo Info; public nint AttributeList; }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobBasicLimits
    {
        public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
        public uint LimitFlags;
        public nuint MinimumWorkingSetSize, MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public nuint Affinity;
        public uint PriorityClass, SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobExtendedLimits
    {
        public JobBasicLimits Basic;
        public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes;
        public nuint ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }

    [LibraryImport("kernel32.dll")] private static partial nint GetCurrentProcess();
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool CloseHandle(nint h);
    [LibraryImport("kernel32.dll")] private static partial nint LocalFree(nint h);
    [LibraryImport("advapi32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool OpenProcessToken(nint process, uint access, out nint token);
    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool ConvertStringSidToSidW(string sid, out nint psid);
    [LibraryImport("advapi32.dll")] private static partial uint GetLengthSid(nint sid);
    [LibraryImport("advapi32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CreateRestrictedToken(nint existing, uint flags, uint disableCount, SidAndAttributes* disable, uint deletePrivCount, nint deletePrivs, uint restrictCount, nint restrict, out nint newToken);
    [LibraryImport("advapi32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool SetTokenInformation(nint token, int cls, void* info, uint length);
    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)] private static partial nint CreateJobObjectW(nint attributes, string? name);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool SetInformationJobObject(nint job, int cls, void* info, uint length);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool AssignProcessToJobObject(nint job, nint process);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool TerminateJobObject(nint job, uint exit);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool TerminateProcess(nint process, uint exit);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool CreatePipe(out nint read, out nint write, SecurityAttributes* sa, uint size);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool SetHandleInformation(nint h, uint mask, uint flags);
    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)][return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CreateProcessAsUserW(nint token, string? app, char* cmdLine, nint procAttr, nint threadAttr, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint flags, nint env, string? cwd, StartupInfoEx* si, ProcessInformation* pi);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool InitializeProcThreadAttributeList(nint list, uint count, uint flags, ref nuint size);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool UpdateProcThreadAttribute(nint list, uint flags, nuint attribute, void* value, nuint size, nint previous, nint returnSize);
    [LibraryImport("kernel32.dll")] private static partial void DeleteProcThreadAttributeList(nint list);
    [LibraryImport("kernel32.dll", SetLastError = true)] private static partial uint ResumeThread(nint thread);
    [LibraryImport("kernel32.dll", SetLastError = true)] private static partial uint WaitForSingleObject(nint h, uint ms);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool GetExitCodeProcess(nint process, out uint exit);
}
