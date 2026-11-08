namespace Edr.Core;

public sealed class Row
{
    public required string Kind { get; init; }
    public string Sec { get; set; } = "";
    public int List { get; set; }
    public string Time { get; init; } = "";
    public string Sev { get; init; } = "";
    public required string[] Cols { get; init; }
    public string Key { get; set; } = "";
    public Rec? Ev { get; set; }
    public IReadOnlyList<Rec> Group { get; set; } = [];
    public Rec? Entry { get; set; }
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
    public int Count { get; set; }
    public bool Alert { get; set; }
    public int Attention { get; set; }
}

public sealed record Overall(string Key, string Text, string Sub);

public sealed class TrayModel
{
    public Dictionary<string, SectionModel> Sec { get; } = Catalog.Sections.ToDictionary(s => s.Key, s => new SectionModel(s));
    public List<Row> Messages { get; set; } = [];
    public int Attention { get; set; }
    public int Pinned { get; set; }
    public string? Claude { get; set; }
}
