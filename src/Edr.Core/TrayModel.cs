namespace Edr.Core;

/// <summary>One line in a dashboard list (New-Row).</summary>
public sealed class Row
{
    public required string Kind { get; init; }   // event, block, defender, excl, builtin, fail, ban, banhist, cve, app, hidden, hist, sys
    public string Sec { get; set; } = "";
    public int List { get; set; }
    public string Time { get; init; } = "";
    public string Sev { get; init; } = "";
    public required string[] Cols { get; init; }
    public string Key { get; set; } = "";
    /// <summary>The representative event (the newest of a group).</summary>
    public Rec? Ev { get; set; }
    public IReadOnlyList<Rec> Group { get; set; } = [];
    /// <summary>The exclusion, block, CVE item, history item or patch event behind the row.</summary>
    public Rec? Entry { get; set; }
    /// <summary>A hidden app's winget ID (Entry is a plain string in the PowerShell tray).</summary>
    public string? EntryId { get; set; }
    public string ExclList { get; set; } = "";
    public Rec? Ban { get; set; }
    public bool Muted { get; set; }
    public string Note { get; set; } = "";
    public bool Pinned { get; set; }
}

public sealed class SectionModel(SectionInfo info)
{
    public SectionInfo Info { get; } = info;
    public List<Row>[] Rows { get; } = [[], [], []];
    /// <summary>Open (not reviewed) items in the first list.</summary>
    public int Count { get; set; }
    /// <summary>Red: a security tab with something that needs a decision.</summary>
    public bool Alert { get; set; }
    public int Attention { get; set; }
}

/// <summary>The one sentence on the Overview: Key is ok / attention / paused / down.</summary>
public sealed record Overall(string Key, string Text, string Sub);

public sealed class TrayModel
{
    public Dictionary<string, SectionModel> Sec { get; } = Catalog.Sections.ToDictionary(s => s.Key, s => new SectionModel(s));
    public List<Row> Messages { get; set; } = [];
    public int Attention { get; set; }
    public int Pinned { get; set; }
    /// <summary>claude.exe seen as a parent or ancestor of an alert (offers "Allow Claude Code").</summary>
    public string? Claude { get; set; }
}
