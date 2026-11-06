using System.Text;
using System.Text.Json.Nodes;
using System.Xml;

namespace Edr.Core;

/// <summary>Everything the model is built from: the engine's files plus the per-user tray files.</summary>
public sealed class EdrInputs
{
    public List<Rec> Events { get; } = [];
    public Dictionary<string, int> EvictedCounts { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, Rec> LastBans { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, Rec> EvictedPinned { get; } = new(StringComparer.OrdinalIgnoreCase);
    public string? Claude { get; set; }
    public Rec? Status { get; set; }
    public Rec? Cve { get; set; }
    public Rec? ScanResult { get; set; }
    /// <summary>exclusions.json lists in <see cref="Catalog.ExclusionLists"/> order (missing lists are empty).</summary>
    public Dictionary<string, List<Rec>> Exclusions { get; set; } = EmptyExclusions();
    public List<Rec> Blocks { get; set; } = [];
    public List<Rec> History { get; set; } = [];
    public HashSet<string> Reviewed { get; } = new(StringComparer.Ordinal);
    /// <summary>Hidden winget app IDs, in file order.</summary>
    public List<string> Ignored { get; } = [];
    public HashSet<string> RuleNames { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Built-in Sysmon exclusions (games, anti-cheat, EDR), shown read-only in EDR > Allowed.</summary>
    public List<string> BuiltIn { get; } = [];
    /// <summary>winget results (phase 4); empty until the first check.</summary>
    public List<Rec> PatchEvents { get; } = [];
    public DateTime? PatchChecked { get; set; }

    public static Dictionary<string, List<Rec>> EmptyExclusions() => Catalog.ExclusionLists.ToDictionary(l => l.List, _ => new List<Rec>());

    public void RecordEvicted(Rec e)
    {
        var b = e.S("blade");
        if (Ps.Eq(b, "wail2ban"))
        {
            if (Ps.Eq(e.S("kind"), "fail") && e.T("ip"))
            {
                var k = $"fail|{e.S("ip")}";
                EvictedCounts[k] = EvictedCounts.GetValueOrDefault(k, 0) + 1;
            }
            else if (Ps.Eq(e.S("kind"), "login") && e.T("ip") && e.T("user"))
            {
                var k = $"login|{e.S("ip")}|{e.S("user")}";
                EvictedCounts[k] = EvictedCounts.GetValueOrDefault(k, 0) + 1;
            }
            else if (e.T("ip") && e.T("expires"))
            {
                var k = e.S("ip");
                if (!LastBans.TryGetValue(k, out var cur) || Ps.Order.Compare(e.S("time"), cur.S("time")) > 0)
                {
                    LastBans[k] = e;
                }
            }
            return;
        }
        if (Catalog.BladeSection.ContainsKey(b))
        {
            if (Ps.Eq(b, "defender"))
            {
                if (Ps.Eq(e.S("kind"), "asr-audit") || Ps.Eq(e.S("kind"), "cfa-audit"))
                {
                    var k = $"{b}|{e.S("title")}|{e.S("process")}|{e.S("parent")}";
                    EvictedCounts[k] = EvictedCounts.GetValueOrDefault(k, 0) + 1;
                }
                else
                {
                    var k = $"defBlocked|{e.S("kind")}|{e.S("path")}|{e.S("process")}|{e.S("threat")}";
                    EvictedCounts[k] = EvictedCounts.GetValueOrDefault(k, 0) + 1;
                }
            }
            else if (Ps.Eq(b, "sigma") && Ps.Match(e.S("title"), Catalog.DefenderSigmaTitles))
            {
                var tm = Ps.Rx(@"Threat: ([^\xA6]+)").Match(e.S("detail"));
                var threat = tm.Success ? tm.Groups[1].Value.Trim() : e.S("title");
                var k = $"defBlocked|malware||{SigmaProcess.Of(e).Image}|{threat}";
                EvictedCounts[k] = EvictedCounts.GetValueOrDefault(k, 0) + 1;
            }
            else if (Ps.Eq(b, "sigma"))
            {
                var sp = SigmaProcess.Of(e);
                var k = $"sigma|{e.S("title")}|{sp.Image}|{sp.Parent}";
                EvictedCounts[k] = EvictedCounts.GetValueOrDefault(k, 0) + 1;
            }
            else
            {
                var k = $"{b}|{e.S("title")}|{e.S("process")}|{e.S("parent")}";
                EvictedCounts[k] = EvictedCounts.GetValueOrDefault(k, 0) + 1;
            }
        }
        if (Claude is null)
        {
            var par = Ps.Eq(b, "sigma") ? SigmaProcess.Of(e).Parent : e.S("parent");
            Claude = new[] { par }.Concat(e.Strings("ancestors")).FirstOrDefault(p => Ps.Match(p, @"\\claude\.exe$"));
        }
        if (Ps.Match(e.S("title"), Catalog.ConfirmPattern) && e.T("id") && !Reviewed.Contains(e.S("id")))
        {
            EvictedPinned[e.S("id")] = e;
        }
    }

    /// <summary>Reads everything once (the tray keeps an <see cref="EventTail"/> for later updates).</summary>
    public static EdrInputs Load(EdrPaths paths)
    {
        var x = new EdrInputs();
        x.Status = ReadJson(paths.StatusFile);
        x.Cve = ReadJson(paths.CveFile);
        x.ScanResult = ReadJson(paths.ScanResultFile);
        x.Exclusions = ReadExclusions(paths.ExclusionsFile);
        x.Blocks = ReadJson(paths.BlocklistFile)?.Recs("items").ToList() ?? [];
        x.History = ReadJson(paths.HistoryFile)?.Recs("items").ToList() ?? [];
        foreach (var l in ReadLines(paths.ReviewedFile)) x.Reviewed.Add(l);
        x.Ignored.AddRange(ReadLines(paths.IgnoredAppsFile).Distinct(StringComparer.OrdinalIgnoreCase));
        x.ReadSysmonConfig(paths.SysmonConfig);
        new EventTail(paths.EventsFile).ReadNew(x.Events, x, drainAll: true);
        return x;
    }

    /// <summary>Read-Json: shared read (the engine may be writing), UTF-8, null when missing/empty/invalid.</summary>
    public static Rec? ReadJson(string path)
    {
        for (var i = 0; i < 5; i++)
        {
            try
            {
                if (!File.Exists(path)) return null;
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var sr = new StreamReader(fs, Encoding.UTF8);
                var text = sr.ReadToEnd();
                return string.IsNullOrWhiteSpace(text) ? null : Rec.Parse(text);
            }
            catch (IOException) { Thread.Sleep(150); }
        }
        return null;
    }

    public static Dictionary<string, List<Rec>> ReadExclusions(string path)
    {
        var e = EmptyExclusions();
        var x = ReadJson(path);
        if (x is null) return e;
        foreach (var (list, _) in Catalog.ExclusionLists)
            if (x[list] is not null) e[list] = x.Recs(list).ToList();
        return e;
    }

    private static IEnumerable<string> ReadLines(string path)
    {
        if (!File.Exists(path)) return [];
        try { return File.ReadAllLines(path).Where(l => l.Length > 0).Select(l => l.Trim()).ToList(); }
        catch (IOException) { return []; }
    }

    private void ReadSysmonConfig(string path)
    {
        try
        {
            if (!File.Exists(path)) return;
            var doc = new XmlDocument();
            doc.Load(path);
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (XmlElement g in doc.SelectNodes("/Sysmon/EventFiltering/RuleGroup[@name='BuiltInExclusions']/ProcessCreate/Image")!)
                if (g.InnerText.Length > 0 && seen.Add(g.InnerText)) BuiltIn.Add(g.InnerText);
            foreach (XmlElement n in doc.SelectNodes("//EventFiltering//*[@name]")!)
                if (n.LocalName != "RuleGroup") RuleNames.Add(n.GetAttribute("name"));
        }
        catch (XmlException) { }
        catch (IOException) { }
    }
}

/// <summary>
/// Reads events.jsonl incrementally (Read-NewEvents): only up to the last complete line, from a byte offset;
/// a shorter file means it was rotated and is read again from the start.
/// </summary>
public sealed class EventTail(string path, int? capacity = null, int budget = EventTail.DefaultBudget)
{
    public const int DefaultCapacity = 10000;
    public const int DefaultBudget = 2 * 1024 * 1024; // 2 MB

    public int Capacity { get; } = capacity ?? (int.TryParse(Environment.GetEnvironmentVariable("EDR_EVENT_CAP"), out var c) ? c : DefaultCapacity);
    public long Offset { get; private set; }

    /// <summary>Appends new events to <paramref name="events"/>; returns them. Clears or trims the list on rotation/cap.</summary>
    public IReadOnlyList<Rec> ReadNew(List<Rec> events, EdrInputs? inputs = null, bool drainAll = false)
    {
        if (!File.Exists(path)) return [];
        var added = new List<Rec>();
        do
        {
            byte[] bytes;
            int read;
            long len;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                len = fs.Length;
                if (len < Offset)
                {
                    Offset = 0;
                    while (events.Count > 5000)
                    {
                        var evicted = events[0];
                        events.RemoveAt(0);
                        inputs?.RecordEvicted(evicted);
                    }
                }
                if (len == Offset) break;
                var toRead = (int)Math.Min(len - Offset, (long)budget);
                if (toRead <= 0) break;
                fs.Seek(Offset, SeekOrigin.Begin);
                bytes = new byte[toRead];
                read = fs.ReadAtLeast(bytes, bytes.Length, throwOnEndOfStream: false);
            }
            if (read <= 0) break;
            var lastNl = Array.LastIndexOf(bytes, (byte)'\n', read - 1);
            if (lastNl < 0) break;
            Offset += lastNl + 1;
            foreach (var line in Encoding.UTF8.GetString(bytes, 0, lastNl + 1).Split('\n'))
            {
                if (line.Trim().Length == 0) continue;
                if (Rec.Parse(line) is { } e)
                {
                    added.Add(e);
                    events.Add(e);
                    if (events.Count > Capacity)
                    {
                        var evicted = events[0];
                        events.RemoveAt(0);
                        inputs?.RecordEvicted(evicted);
                    }
                }
            }
        } while (drainAll && Offset < new FileInfo(path).Length);

        return added;
    }
}
