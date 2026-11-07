namespace Edr.Core;

/// <summary>Program and parent of a Sigma hit parsed from Hayabusa details.</summary>
public sealed record SigmaProcess(string Image, string Parent)
{
    private const char Sep = '\u00A6';   // Hayabusa's "¦" field separator

    /// <summary>Parses "Proc: C:\x.exe ¦ ParentCmdline: "C:\y\claude.exe" --flags ¦ ..."</summary>
    public static SigmaProcess FromDetails(string? details)
    {
        var f = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in (details ?? "").Split(Sep))
        {
            var m = Ps.Rx(@":\s").Match(part);
            if (!m.Success) continue;
            var key = part[..m.Index].Trim();
            var value = part[(m.Index + m.Length)..].Trim().TrimEnd('\u00C2').Trim();   // 0xC2: UTF-8 "¦" read as ANSI
            f.TryAdd(key, value);
        }
        var img = new[] { "Proc", "Image", "SrcProc", "Process" }
            .Select(k => f.GetValueOrDefault(k)).FirstOrDefault(v => v is not null && Ps.Match(v, @"\.exe$")) ?? "";
        // Sysmon names it ParentImage, the Security log (4688) ParentProcessName
        var par = f.GetValueOrDefault("ParentImage") ?? f.GetValueOrDefault("ParentProcessName") ?? "";
        if (par.Length == 0 && f.TryGetValue("ParentCmdline", out var pc) && pc.Length > 0)
        {
            var q = Ps.Rx("^\"([^\"]+\\.exe)\"").Match(pc);
            var u = Ps.Rx(@"^([^\s""]+\.exe)(\s|$)").Match(pc);
            par = q.Success ? q.Groups[1].Value : u.Success ? u.Groups[1].Value : "";
        }
        return new SigmaProcess(img, par);
    }

    /// <summary>Get-SigmaInfo: new events carry process/parent; older ones are parsed from the details text.</summary>
    public static SigmaProcess Of(Rec e)
    {
        if (e.SigmaCache is { } c) return c;
        var sp = FromDetails(e.S("detail"));
        if (sp.Image.Length == 0 && Ps.Match(e.S("process"), @"\.exe$")) sp = sp with { Image = e.S("process") };
        if (e.T("parent") && (Ps.Match(e.S("parent"), "^\"[^\"]+\\.exe\"$") || Ps.Match(e.S("parent"), @"^[^\s""]+\.exe$")))
            sp = sp with { Parent = e.S("parent") };
        e.SigmaCache = sp;
        return sp;
    }
}
