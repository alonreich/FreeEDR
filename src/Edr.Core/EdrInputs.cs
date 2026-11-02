using System.Text;
using System.Text.Json.Nodes;
using System.Xml;

namespace Edr.Core;

/// <summary>Everything the model is built from: the engine's files plus the per-user tray files.</summary>
public sealed class EdrInputs
{
    public List<Rec> Events { get; } = [];
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

    /// <summary>Reads everything once (the tray keeps an <see cref="EventTail"/> for later updates).</summary>
    public static EdrInputs Load(EdrPaths paths)
    {
        var x = new EdrInputs();
        new EventTail(paths.EventsFile).ReadNew(x.Events);
        x.Status = ReadJson(paths.StatusFile);
        x.Cve = ReadJson(paths.CveFile);
        x.ScanResult = ReadJson(paths.ScanResultFile);
        x.Exclusions = ReadExclusions(paths.ExclusionsFile);
        x.Blocks = ReadJson(paths.BlocklistFile)?.Recs("items").ToList() ?? [];
        x.History = ReadJson(paths.HistoryFile)?.Recs("items").ToList() ?? [];
        foreach (var l in ReadLines(paths.ReviewedFile)) x.Reviewed.Add(l);
        x.Ignored.AddRange(ReadLines(paths.IgnoredAppsFile).Distinct(StringComparer.OrdinalIgnoreCase));
        x.ReadSysmonConfig(paths.SysmonConfig);
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
public sealed class EventTail(string path)
{
    public long Offset { get; private set; }

    /// <summary>Appends new events to <paramref name="events"/>; returns them. Clears the list on rotation.</summary>
    public IReadOnlyList<Rec> ReadNew(List<Rec> events)
    {
        if (!File.Exists(path)) return [];
        byte[] bytes;
        int read;
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        {
            var len = fs.Length;
            if (len < Offset)
            {
                Offset = 0;
                if (events.Count > 5000) events.RemoveRange(0, events.Count - 5000);
            }
            if (len == Offset) return [];
            fs.Seek(Offset, SeekOrigin.Begin);
            bytes = new byte[len - Offset];
            read = fs.ReadAtLeast(bytes, bytes.Length, throwOnEndOfStream: false);
        }
        if (read <= 0) return [];
        var lastNl = Array.LastIndexOf(bytes, (byte)'\n', read - 1);
        if (lastNl < 0) return [];
        Offset += lastNl + 1;
        var added = new List<Rec>();
        foreach (var line in Encoding.UTF8.GetString(bytes, 0, lastNl + 1).Split('\n'))
        {
            if (line.Trim().Length == 0) continue;
            if (Rec.Parse(line) is { } e) added.Add(e);
        }
        events.AddRange(added);
        return added;
    }
}
