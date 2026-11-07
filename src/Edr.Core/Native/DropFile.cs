using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Win32.SafeHandles;

namespace Edr.Core.Native;

/// <summary>
/// Takes one request file out of a drop folder (control\ or the user-writable inbox\) without trusting the file:
///   * the last path part is opened itself, never followed (a symbolic link or junction is removed, not read);
///   * an opportunistic lock on the file does not make the reader wait (FILE_COMPLETE_IF_OPLOCKED: the file is "busy");
///   * nobody can write while it is read (share read only), and at most <c>max</c> bytes are read (a longer file is removed);
///   * a file with more than one name (hard link) is never read; only its drop-folder name is removed;
///   * the file is marked for deletion on the same handle before its content is used (no replay, no second open).
/// </summary>
[SupportedOSPlatform("windows")]
public static unsafe partial class DropFile
{
    public enum Outcome { Taken, Busy, Gone, Rejected }

    public readonly record struct Result(Outcome Outcome, JsonObject? Command, string Reason);

    /// <summary>Reads and removes one request file. Taken: <see cref="Result.Command"/> is the parsed request (null if
    /// it was not a JSON object; the file is removed either way). Busy: try again later. Never blocks on another
    /// process's lock or oplock.</summary>
    public static Result Take(string path, int max)
    {
        var (status, h) = Open(path, 0x80000000 | 0x00010000 | 0x00100000);   // GENERIC_READ | DELETE | SYNCHRONIZE
        if (status == StatusAccessDenied)   // e.g. its owner denied SYSTEM reading it: removed unread (the folder grants delete)
            return TryDelete(path) ? new(Outcome.Rejected, null, "not readable by the engine (removed unread)") : new(Outcome.Busy, null, "access denied");
        if (status != 0) return Classify(status, path);
        using (h)
        {
            if (!GetFileInformationByHandle(h, out var fi)) return new(Outcome.Busy, null, $"cannot query the file (error {Marshal.GetLastPInvokeError()})");
            if ((fi.FileAttributes & 0x10) != 0) return new(Outcome.Rejected, null, "a folder, not a file");   // FILE_ATTRIBUTE_DIRECTORY
            if ((fi.FileAttributes & 0x400) != 0)   // FILE_ATTRIBUTE_REPARSE_POINT: the link itself is open, so only the link goes
                return MarkDeleted(h) ? new(Outcome.Rejected, null, "a link (removed, not followed)") : new(Outcome.Busy, null, "a link that cannot be removed");
            if (fi.NumberOfLinks > 1)
                return MarkDeleted(h) ? new(Outcome.Rejected, null, "a hard link to another file (the name was removed, the file was not read)") : new(Outcome.Busy, null, "a hard link that cannot be removed");
            var size = ((long)fi.FileSizeHigh << 32) | fi.FileSizeLow;
            if (size > max) return MarkDeleted(h) ? new(Outcome.Rejected, null, $"larger than {max} bytes (removed)") : new(Outcome.Busy, null, "too large and cannot be removed");

            var buf = new byte[max + 1];
            var got = 0;
            using (var fs = new FileStream(h, FileAccess.Read, 0))
            {
                // The handle shares read only, so the size cannot change while it is open; read at most max + 1 bytes anyway
                int n;
                while (got < buf.Length && (n = fs.Read(buf, got, buf.Length - got)) > 0) got += n;
                if (got > max) return MarkDeleted(h) ? new(Outcome.Rejected, null, $"larger than {max} bytes (removed)") : new(Outcome.Busy, null, "too large and cannot be removed");
                // Removed before it is used: a request runs at most once, even if it fails later
                if (!MarkDeleted(h)) return new(Outcome.Busy, null, $"cannot be removed (error {Marshal.GetLastPInvokeError()})");
            }
            var text = new UTF8Encoding(false, false).GetString(buf, 0, got);
            if (text.Length > 0 && text[0] == '\uFEFF') text = text[1..];
            return new(Outcome.Taken, JsonFile.Parse(text) as JsonObject, "");
        }
    }

    /// <summary>Removes a file (or the link itself) without following it and without waiting on an oplock.</summary>
    public static bool TryDelete(string path)
    {
        var (status, h) = Open(path, 0x00010000 | 0x00100000);   // DELETE | SYNCHRONIZE
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

    /// <summary>NtCreateFile: the file itself (FILE_OPEN_REPARSE_POINT), never a folder, share read only, and an
    /// oplock break is reported (STATUS_OPLOCK_BREAK_IN_PROGRESS) instead of waited for.</summary>
    private static (int Status, SafeFileHandle Handle) Open(string path, uint access)
    {
        var full = Path.GetFullPath(path);
        var nt = full.StartsWith(@"\\?\", StringComparison.Ordinal) ? @"\??\" + full[4..]
               : full.StartsWith(@"\\", StringComparison.Ordinal) ? @"\??\UNC\" + full[2..]
               : @"\??\" + full;
        fixed (char* p = nt)
        {
            var name = new UnicodeString { Length = (ushort)(nt.Length * 2), MaximumLength = (ushort)(nt.Length * 2), Buffer = p };
            var oa = new ObjectAttributes { Length = (uint)sizeof(ObjectAttributes), ObjectName = &name, Attributes = 0x40 };   // OBJ_CASE_INSENSITIVE
            // FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_COMPLETE_IF_OPLOCKED | FILE_OPEN_REPARSE_POINT
            const uint options = 0x40 | 0x20 | 0x100 | 0x00200000;
            var status = NtCreateFile(out var handle, access, &oa, out _, 0, 0x80, 0x1, 1, options, 0, 0);   // FILE_SHARE_READ, FILE_OPEN
            var h = new SafeFileHandle(handle, ownsHandle: true);
            if (status == StatusOplockBreakInProgress || status < 0) { h.Dispose(); return (status, h); }
            return (0, h);
        }
    }

    private static bool MarkDeleted(SafeFileHandle h)
    {
        byte delete = 1;
        return SetFileInformationByHandle(h, 4, &delete, 1);   // FileDispositionInfo
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
