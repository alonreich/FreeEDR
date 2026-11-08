using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Win32.SafeHandles;

namespace Edr.Core.Native;

[SupportedOSPlatform("windows")]
public static unsafe partial class DropFile
{
    public enum Outcome { Taken, Busy, Gone, Rejected }

    public readonly record struct Result(Outcome Outcome, JsonObject? Command, string Reason);

    public static Result Take(string path, int max)
    {
        var (status, h) = Open(path, 0x80000000 | 0x00010000 | 0x00100000);
        if (status == StatusAccessDenied)
            return TryDelete(path) ? new(Outcome.Rejected, null, "not readable by the engine (removed unread)") : new(Outcome.Busy, null, "access denied");
        if (status != 0) return Classify(status, path);
        using (h)
        {
            if (!GetFileInformationByHandle(h, out var fi)) return new(Outcome.Busy, null, $"cannot query the file (error {Marshal.GetLastPInvokeError()})");
            if ((fi.FileAttributes & 0x10) != 0) return new(Outcome.Rejected, null, "a folder, not a file");
            if ((fi.FileAttributes & 0x400) != 0)
                return MarkDeleted(h) ? new(Outcome.Rejected, null, "a link (removed, not followed)") : new(Outcome.Busy, null, "a link that cannot be removed");
            if (fi.NumberOfLinks > 1)
                return MarkDeleted(h) ? new(Outcome.Rejected, null, "a hard link to another file (the name was removed, the file was not read)") : new(Outcome.Busy, null, "a hard link that cannot be removed");
            var size = ((long)fi.FileSizeHigh << 32) | fi.FileSizeLow;
            if (size > max) return MarkDeleted(h) ? new(Outcome.Rejected, null, $"larger than {max} bytes (removed)") : new(Outcome.Busy, null, "too large and cannot be removed");

            var buf = new byte[max + 1];
            var got = 0;
            using (var fs = new FileStream(h, FileAccess.Read, 0))
            {
                int n;
                while (got < buf.Length && (n = fs.Read(buf, got, buf.Length - got)) > 0) got += n;
                if (got > max) return MarkDeleted(h) ? new(Outcome.Rejected, null, $"larger than {max} bytes (removed)") : new(Outcome.Busy, null, "too large and cannot be removed");
                if (!MarkDeleted(h)) return new(Outcome.Busy, null, $"cannot be removed (error {Marshal.GetLastPInvokeError()})");
            }
            var text = new UTF8Encoding(false, false).GetString(buf, 0, got);
            if (text.Length > 0 && text[0] == '\uFEFF') text = text[1..];
            return new(Outcome.Taken, JsonFile.Parse(text) as JsonObject, "");
        }
    }

    public static bool TryDelete(string path)
    {
        var (status, h) = Open(path, 0x00010000 | 0x00100000);
        if (status != 0) return status == StatusNameNotFound || status == StatusPathNotFound;
        using (h) return MarkDeleted(h);
    }

    private const int StatusOplockBreakInProgress = 0x00000108;
    private const int StatusNameNotFound = unchecked((int)0xC0000034);
    private const int StatusPathNotFound = unchecked((int)0xC000003A);
    private const int StatusSharingViolation = unchecked((int)0xC0000043);
    private const int StatusDeletePending = unchecked((int)0xC0000056);
    private const int StatusAccessDenied = unchecked((int)0xC0000022);
    private const int StatusFileIsADirectory = unchecked((int)0xC00000BA);

    private static Result Classify(int status, string path) => status switch
    {
        StatusNameNotFound or StatusPathNotFound or StatusDeletePending => new(Outcome.Gone, null, "gone"),
        StatusOplockBreakInProgress => new(Outcome.Busy, null, "another program holds an opportunistic lock on it"),
        StatusSharingViolation => new(Outcome.Busy, null, "another program has it open"),
        StatusFileIsADirectory => new(Outcome.Rejected, null, "a folder, not a file"),
        StatusAccessDenied => new(Outcome.Busy, null, "access denied"),
        _ => new(Outcome.Busy, null, $"cannot be opened (NTSTATUS 0x{status:X8}): {Path.GetFileName(path)}"),
    };

    private static (int Status, SafeFileHandle Handle) Open(string path, uint access)
    {
        var full = Path.GetFullPath(path);
        var nt = full.StartsWith(@"\\?\", StringComparison.Ordinal) ? @"\??\" + full[4..]
               : full.StartsWith(@"\\", StringComparison.Ordinal) ? @"\??\UNC\" + full[2..]
               : @"\??\" + full;
        fixed (char* p = nt)
        {
            var name = new UnicodeString { Length = (ushort)(nt.Length * 2), MaximumLength = (ushort)(nt.Length * 2), Buffer = p };
            var oa = new ObjectAttributes { Length = (uint)sizeof(ObjectAttributes), ObjectName = &name, Attributes = 0x40 };
            const uint options = 0x40 | 0x20 | 0x100 | 0x00200000;
            var status = NtCreateFile(out var handle, access, &oa, out _, 0, 0x80, 0x1, 1, options, 0, 0);
            var h = new SafeFileHandle(handle, ownsHandle: true);
            if (status == StatusOplockBreakInProgress || status < 0) { h.Dispose(); return (status, h); }
            return (0, h);
        }
    }

    private static bool MarkDeleted(SafeFileHandle h)
    {
        byte delete = 1;
        return SetFileInformationByHandle(h, 4, &delete, 1);
    }

    [StructLayout(LayoutKind.Sequential)] private struct UnicodeString { public ushort Length, MaximumLength; public char* Buffer; }

    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        public uint Length;
        public nint RootDirectory;
        public UnicodeString* ObjectName;
        public uint Attributes;
        public nint SecurityDescriptor, SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)] private struct IoStatusBlock { public nint Status, Information; }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public uint CreationLow, CreationHigh, AccessLow, AccessHigh;
        public uint LastWriteLow, LastWriteHigh;
        public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
    }

    [LibraryImport("ntdll.dll")]
    private static partial int NtCreateFile(out nint handle, uint access, ObjectAttributes* oa, out IoStatusBlock io, nint allocationSize,
                                            uint fileAttributes, uint shareAccess, uint disposition, uint options, nint eaBuffer, uint eaLength);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFileInformationByHandle(SafeFileHandle h, out ByHandleFileInformation info);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetFileInformationByHandle(SafeFileHandle h, int infoClass, void* info, uint size);
}
