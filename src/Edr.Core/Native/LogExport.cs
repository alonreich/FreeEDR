using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Edr.Core.Native;

[SupportedOSPlatform("windows")]
public static partial class LogExport
{
    private const long EmptyLog = 69_632;

    public sealed record Result(int Logs, int Failed, long Bytes, string FirstError);

    public static Result Recent(TimeSpan lookback, string toDir, long maxBytes, CancellationToken ct, string? logsDir = null)
    {
        logsDir ??= Path.Combine(EdrPaths.System32, "winevt", "Logs");
        Directory.CreateDirectory(toDir);
        var ms = (long)Math.Max(1, lookback.TotalMilliseconds);
        var query = $"*[System[TimeCreated[timediff(@SystemTime) <= {ms}]]]";
        int logs = 0, failed = 0;
        long bytes = 0;
        var firstError = "";
        foreach (var file in Directory.EnumerateFiles(logsDir, "*.evtx").Where(f => new FileInfo(f).Length > EmptyLog).Order(StringComparer.OrdinalIgnoreCase))
        {
            ct.ThrowIfCancellationRequested();
            if (bytes > maxBytes) { failed++; firstError = firstError.Length > 0 ? firstError : $"copies over {maxBytes / 1024 / 1024} MB: the remaining logs were skipped"; break; }
            var name = Path.GetFileNameWithoutExtension(file);
            var channel = name.Replace("%4", "/", StringComparison.Ordinal);
            var target = Path.Combine(toDir, name + ".evtx");
            if (EvtExportLog(0, channel, query, target, 0x1))
            {
                logs++;
                bytes += new FileInfo(target).Length;
            }
            else
            {
                var err = Marshal.GetLastPInvokeError();
                if (err is 15007 or 5) continue;
                failed++;
                if (firstError.Length == 0) firstError = $"{channel}: error {err}";
            }
        }
        return new Result(logs, failed, bytes, firstError);
    }

    [LibraryImport("wevtapi.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool EvtExportLog(nint session, string path, string query, string targetFilePath, uint flags);
}
