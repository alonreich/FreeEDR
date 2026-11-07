using System.Collections.Concurrent;
using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.Json.Nodes;
using Edr.Core;
using Edr.Core.Native;

namespace Edr.Engine;

/// <summary>
/// Tamper-resistant copy of the Windows event logs that matter for an investigation, kept under the admin-only
/// data\archive\ folder: clearing a Windows log (wevtutil cl, Event Viewer) does not erase what was already copied.
/// Own subscriptions (bookmarked, so nothing is skipped across restarts) feed a bounded queue; one below-normal-priority
/// thread writes batches every few seconds as gzip members appended to data\archive\yyyy-MM-dd\&lt;log&gt;.xml.gz (one
/// event XML per line). Not urgent and never in the detection path: a full queue makes the archive's own callback wait
/// (the events stay in the Windows log). Retention: 90 days and 1 GB, oldest days first; paused when the disk has less
/// than 2 GB free.
/// </summary>
internal sealed class EventArchive(Context ctx) : IDisposable
{
    public sealed record Source(string Key, string Channel, string XPath);

    public static readonly Source[] Sources =
    [
        new("sysmon", "Microsoft-Windows-Sysmon/Operational", "*"),
        new("security", "Security", Ids(1102, 4624, 4625, 4648, 4688, 4697, 4698, 4699, 4700, 4701, 4702, 4719, 4720, 4722, 4723, 4724, 4725, 4726,
                                        4728, 4729, 4732, 4733, 4738, 4740, 4756, 4757, 4767, 4781, 4794)),
        new("system", "System", Ids(104, 1074, 6005, 6006, 6008, 7040, 7045)),
        new("defender", "Microsoft-Windows-Windows Defender/Operational", "*"),
        new("powershell", "Microsoft-Windows-PowerShell/Operational", Ids(4104)),
        new("tasks", "Microsoft-Windows-TaskScheduler/Operational", Ids(106, 140, 141)),
        new("rdp", "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", Ids(131, 140)),
        new("sessions", "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", Ids(21, 22, 24, 25)),
        new("wmi", "Microsoft-Windows-WMI-Activity/Operational", Ids(5857, 5860, 5861)),
    ];

    public const long MaxBytes = 1L << 30;           // 1 GB
    public const int KeepDays = 90;
    public const long MinFreeBytes = 2L << 30;       // pause below 2 GB free
    private const int QueueCapacity = 5_000;
    private const int BatchMax = 1_000;
    private static readonly TimeSpan FlushEvery = TimeSpan.FromSeconds(5);

    private sealed record Item(string Key, string Xml, string? Bookmark, DateTime Time);

    private readonly BlockingCollection<Item> _queue = new(QueueCapacity);
    private readonly CancellationTokenSource _stop = new();
    private readonly Dictionary<string, EventSubscription> _subs = [];
    private readonly ConcurrentDictionary<string, string> _bookmarks = new();
    private Thread? _writer;
    private long _written, _dropped, _bytes;
    private volatile string _error = "";
    private DateTime _lastWrite, _lastRetention = DateTime.MinValue;

    public string Dir => Path.Combine(ctx.Paths.DataDir, "archive");
    private string BookmarksFile => Path.Combine(Dir, "bookmarks.json");

    private static string Ids(params int[] ids) => $"*[System[({string.Join(" or ", ids.Select(i => $"EventID={i}"))})]]";

    public void Start()
    {
        Directory.CreateDirectory(Dir);
        if (JsonFile.ReadObject(BookmarksFile) is { } o)
            foreach (var (k, v) in o) if (Ps.Str(v).Length > 0) _bookmarks[k] = Ps.Str(v);
        _bytes = DirSize();
        foreach (var s in Sources) Subscribe(s);
        _writer = new Thread(WriterLoop) { IsBackground = true, Name = "Event archive", Priority = ThreadPriority.BelowNormal };
        _writer.Start();
        ctx.Log.Info($"Event archive: {_subs.Count} of {Sources.Length} logs copied to {Dir}");
    }

    /// <summary>Retries logs that could not be opened (e.g. a channel that appears later). Called every 5 minutes.</summary>
    public void RetryMissing()
    {
        foreach (var s in Sources.Where(s => !_subs.ContainsKey(s.Key))) Subscribe(s);
    }

    private void Subscribe(Source s)
    {
        void OnEvent(string xml, string? bm) => Enqueue(new Item(s.Key, xml, bm, DateTime.Now));
        void OnError(int code) => _error = $"{s.Key}: subscription error {code}";
        try
        {
            try { _subs[s.Key] = EventSubscription.Start(s.Channel, s.XPath, _bookmarks.GetValueOrDefault(s.Key), OnEvent, OnError); }
            catch (InvalidDataException)
            {
                // The bookmarked record is gone (log cleared or wrapped): carry on from now; the gap is in the engine log
                ctx.Log.Warn($"Event archive: bookmark for {s.Key} no longer valid (log cleared or wrapped) - continuing from now");
                _bookmarks.TryRemove(s.Key, out _);
                _subs[s.Key] = EventSubscription.Start(s.Channel, s.XPath, null, OnEvent, OnError);
            }
        }
        catch (IOException) { /* channel missing or not readable: RetryMissing tries again */ }
    }

    private void Enqueue(Item it)
    {
        if (_queue.TryAdd(it)) return;
        try
        {
            while (!_stop.IsCancellationRequested)
                if (_queue.TryAdd(it, 250, _stop.Token)) return;
        }
        catch (Exception e) when (e is OperationCanceledException or InvalidOperationException or ObjectDisposedException) { }
        Interlocked.Increment(ref _dropped);
    }

    private void WriterLoop()
    {
        var batch = new List<Item>(BatchMax);
        while (!_stop.IsCancellationRequested)
        {
            try
            {
                batch.Clear();
                var until = DateTime.UtcNow + FlushEvery;
                while (batch.Count < BatchMax)
                {
                    var left = until - DateTime.UtcNow;
                    if (left <= TimeSpan.Zero || !_queue.TryTake(out var it, (int)Math.Ceiling(left.TotalMilliseconds), _stop.Token)) break;
                    batch.Add(it);
                }
                if (batch.Count > 0) Write(batch);
                if (DateTime.Now - _lastRetention > TimeSpan.FromMinutes(10)) { _lastRetention = DateTime.Now; Retention(); }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { _error = e.Message; Thread.Sleep(5000); }
        }
        // Stopping: write what is queued
        batch.Clear();
        while (_queue.TryTake(out var rest)) batch.Add(rest);
        if (batch.Count > 0) try { Write(batch); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>Writes one record now (tests).</summary>
    internal void Append(string key, string xml, DateTime time) => Write([new Item(key, xml, null, time)]);

    private void Write(List<Item> batch)
    {
        var free = FreeBytes();
        if (free is { } f && f < MinFreeBytes)
        {
            Interlocked.Add(ref _dropped, batch.Count);
            _error = $"paused: less than {MinFreeBytes >> 30} GB free on the system drive";
            return;
        }
        foreach (var g in batch.GroupBy(i => (Day: i.Time.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), i.Key)))
        {
            var day = Path.Combine(Dir, g.Key.Day);
            Directory.CreateDirectory(day);
            var file = Path.Combine(day, g.Key.Key + ".xml.gz");
            var before = File.Exists(file) ? new FileInfo(file).Length : 0;
            using (var fs = new FileStream(file, FileMode.Append, FileAccess.Write, FileShare.Read))
            using (var gz = new GZipStream(fs, CompressionLevel.Fastest))   // one gzip member per batch (concatenated members are valid gzip)
            using (var w = new StreamWriter(gz, JsonFile.Utf8NoBom))
                foreach (var it in g) w.Write(OneLine(it.Xml) + "\n");
            _bytes += new FileInfo(file).Length - before;
        }
        foreach (var it in batch) if (it.Bookmark is not null) _bookmarks[it.Key] = it.Bookmark;
        var o = new JsonObject();
        foreach (var (k, v) in _bookmarks) o[k] = v;
        JsonFile.WriteAtomic(BookmarksFile, o);
        Interlocked.Add(ref _written, batch.Count);
        _lastWrite = DateTime.Now;
        if (_error.StartsWith("paused", StringComparison.Ordinal)) _error = "";
    }

    /// <summary>One event per line: line breaks inside the XML become character references.</summary>
    public static string OneLine(string xml) => xml.Replace("\r", "&#13;", StringComparison.Ordinal).Replace("\n", "&#10;", StringComparison.Ordinal);

    /// <summary>Oldest days go first: anything older than 90 days, then until the archive is under 1 GB (today is kept).</summary>
    private void Retention()
    {
        var days = new DirectoryInfo(Dir).GetDirectories().Where(d => DateTime.TryParseExact(d.Name, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out _))
                                         .OrderBy(d => d.Name, StringComparer.Ordinal).ToList();
        var total = DirSize();
        var today = DateTime.Now.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        foreach (var d in days)
        {
            if (d.Name == today) break;
            var old = string.CompareOrdinal(d.Name, DateTime.Now.AddDays(-KeepDays).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)) < 0;
            if (!old && total <= MaxBytes) break;
            var size = d.GetFiles("*", SearchOption.AllDirectories).Sum(f => f.Length);
            try { d.Delete(true); total -= size; ctx.Log.Info($"Event archive: removed {d.Name} ({size / 1024 / 1024} MB, {(old ? "older than 90 days" : "over 1 GB")})"); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { ctx.Log.Warn($"Event archive: could not remove {d.Name}: {e.Message}"); }
        }
        _bytes = total;
    }

    private long DirSize()
    {
        try { return Directory.Exists(Dir) ? new DirectoryInfo(Dir).GetFiles("*.gz", SearchOption.AllDirectories).Sum(f => f.Length) : 0; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return _bytes; }
    }

    private long? FreeBytes()
    {
        try { return new DriveInfo(Path.GetPathRoot(Dir)!).AvailableFreeSpace; }
        catch (Exception e) when (e is IOException or ArgumentException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>For status.json: what the archive holds and whether it keeps up.</summary>
    public JsonObject Status() => new()
    {
        ["logs"] = _subs.Count, ["of"] = Sources.Length, ["written"] = Interlocked.Read(ref _written), ["dropped"] = Interlocked.Read(ref _dropped),
        ["queued"] = _queue.Count, ["mb"] = Math.Round(_bytes / 1024.0 / 1024.0, 1),
        ["lastWrite"] = _lastWrite == default ? null : _lastWrite.ToString("s", CultureInfo.InvariantCulture), ["error"] = _error.Length > 0 ? _error : null,
    };

    /// <summary>Reads one archive file back (concatenated gzip members), one event XML per line. For tests and exports.</summary>
    public static IEnumerable<string> ReadFile(string file)
    {
        using var fs = File.OpenRead(file);
        using var gz = new GZipStream(fs, CompressionMode.Decompress);
        using var r = new StreamReader(gz, Encoding.UTF8);
        while (r.ReadLine() is { } line) if (line.Length > 0) yield return line;
    }

    public void Dispose()
    {
        _stop.Cancel();
        foreach (var s in _subs.Values) s.Dispose();
        _subs.Clear();
        _writer?.Join(10_000);
        _queue.CompleteAdding();
    }
}
