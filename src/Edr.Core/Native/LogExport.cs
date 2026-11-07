using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Edr.Core.Native;

/// <summary>
/// Copies the recent records of every Windows event log that holds any into .evtx files (EvtExportLog with a time
/// filter; the Windows event log service reads the logs, nothing is parsed here). Used for the Sigma scan: Hayabusa's
/// live mode (-l) refuses to run without administrator rights, and it must not get them (it parses log content any
/// program can write), so it scans these copies from the sandbox instead (-d).
/// </summary>
[SupportedOSPlatform("windows")]
public static partial class LogExport
{
    /// <summary>An empty .evtx file is 68 KB (header + one chunk): smaller or equal means no records to copy.</summary>
    private const long EmptyLog = 69_632;

    public sealed record Result(int Logs, int Failed, long Bytes, string FirstError);

    /// <summary>Exports the records of the last <paramref name="lookback"/> from each log file in <paramref name="logsDir"/>
    /// (default: %SystemRoot%\System32\winevt\Logs) into <paramref name="toDir"/> (created empty). Stops when the
    /// copies pass <paramref name="maxBytes"/> or <paramref name="ct"/> is cancelled.</summary>
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
            var channel = name.Replace("%4", "/", StringComparison.Ordinal);   // the log file name encodes '/' as %4
            var target = Path.Combine(toDir, name + ".evtx");
            if (EvtExportLog(0, channel, query, target, 0x1))   // EvtExportLogChannelPath
            {
                logs++;
                bytes += new FileInfo(target).Length;
            }
            else
            {
                var err = Marshal.GetLastPInvokeError();
                if (err is 15007 or 5) continue;   // ERROR_EVT_CHANNEL_NOT_FOUND (file not named after its channel), access denied: not a scan failure
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
