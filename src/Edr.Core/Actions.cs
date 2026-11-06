using System.Text.Json.Nodes;

namespace Edr.Core;

/// <summary>What a button does. The UI runs it; <see cref="ActionBuilder"/> decides which ones a selection offers.</summary>
public enum ActionKind
{
    Flag, ItWasMe, Allow, AllowRule, AllowParent, AllowSigner, AllowParentEverywhere, AllowSubnet, TrustApp, MarkReviewed, MarkUnreviewed,
    BackToDetected, MoveToAllowed, AllowInDefender, OpenWindowsSecurity, BanIp, RemoveAllow, UpdateCve, ReadAdvisory, IgnoreCve, UpdateApp,
    UpdateAllApps, HideApp, ShowApp, UpdateAgain, UpdateTool, OpenUrl, ScanWithDefender, VirusTotal, OpenLocation, CopyDetails,
}

public sealed record TrayAction(ActionKind Kind, string Label, bool Primary = false, bool Enabled = true, string? Arg = null, string Style = "");

/// <summary>
/// The actions for the selected rows (port of Get-Actions): the first primary one is the usual choice. The same list
/// feeds the buttons and the right-click menu. FreeEDR only detects, so "Flag as threat" records a verdict and the
/// follow-up actions hand the file to Microsoft Defender or VirusTotal.
/// </summary>
public static class ActionBuilder
{
    public static List<TrayAction> For(IReadOnlyList<Row> rows, Func<string, string?> signerOf, Func<Rec, AllowProfile?> profileFor,
                                       Func<string, bool> parentAllowed, Func<Row, bool> ownCve, Func<Rec, bool> isReviewed)
    {
        var acts = new List<TrayAction>();
        if (rows.Count == 0) return acts;
        var r = rows[0];
        var same = rows.Where(x => x.Kind == r.Kind).ToList();
        var n = same.Count;
        var sfx = n > 1 ? $" ({n})" : "";
        var info = Catalog.Section(r.Sec == "overview" ? "edr" : r.Sec);
        var e = r.Ev;
        switch (r.Kind)
        {
            case "event" or "fail":
            {
                if (r.Pinned)
                {
                    acts.Add(new(ActionKind.ItWasMe, $"Yes, it was me{sfx}", Primary: true, Style: "ok"));
                    acts.Add(new(ActionKind.Flag, r.Sec == "wail2ban" ? $"No - ban this IP{sfx}" : $"No, it wasn't me{sfx}", Primary: true, Style: "danger"));
                }
                else acts.Add(new(ActionKind.Flag, info.Block + sfx, Primary: true, Style: r.Sec == "wail2ban" ? "danger" : ""));
                acts.Add(new(ActionKind.Allow, info.Allow + sfx));
                var par = e is null ? "" : ParentOf(e);
                if (r.Sec == "edr" && n == 1 && e is not null)
                {
                    if (e.T("rule") && e.T("process")) acts.Add(new(ActionKind.AllowRule, "Allow for this rule only"));
                    if (par.Length > 0) acts.Add(new(ActionKind.AllowParent, $"Allow everything {Ps.Leaf(par)} starts"));
                    var sg = signerOf(e.S("process"));
                    if (sg is not null && !PatternRules.IsUnsafeSigner(sg)) acts.Add(new(ActionKind.AllowSigner, $"Allow everything signed by {Short(sg, 28)}", Arg: sg));
                }
                if (r.Sec == "sigma" && n == 1 && par.Length > 0) acts.Add(new(ActionKind.AllowParent, $"Ignore every rule for {Ps.Leaf(par)}"));
                if (r.Sec is "edr" or "sigma" && e is not null && profileFor(e) is { } prof)
                    acts.Insert(0, new(ActionKind.TrustApp, $"Trust the app: {prof.Name}", Primary: true, Arg: prof.Id, Style: "ok"));
                if (r.Sec is "edr" or "sigma" && n == 1 && par.Length > 0 && !parentAllowed(par))
                    acts.Add(new(ActionKind.AllowParentEverywhere, $"Allow {Ps.Leaf(par)} in real-time and event logs", Arg: par));
                if (r.Sec == "wail2ban" && n == 1 && e is not null && Ps.Rx(@"^(\d+\.\d+\.\d+)\.\d+$").Match(e.S("ip")) is { Success: true } m)
                    acts.Add(new(ActionKind.AllowSubnet, $"Trust the network {m.Groups[1].Value}.0/24"));
                if (!(r.Pinned && !r.Muted))
                {
                    var events = same.SelectMany(x => x.Group.Count > 0 ? x.Group : x.Ev is not null ? [x.Ev] : []).ToList();
                    acts.Add(events.Any(x => !isReviewed(x)) ? new(ActionKind.MarkReviewed, $"Mark reviewed{sfx}") : new(ActionKind.MarkUnreviewed, $"Mark unreviewed{sfx}"));
                }
                break;
            }
            case "block":
                acts.Add(new(ActionKind.BackToDetected, $"Remove the verdict{sfx}", Primary: true));
                acts.Add(new(ActionKind.MoveToAllowed, $"Move to {info.Subs[2]}{sfx}"));
                break;
            case "defender":
                acts.Add(new(ActionKind.AllowInDefender, $"Allow in Microsoft Defender{sfx}", Primary: true));
                acts.Add(new(ActionKind.OpenWindowsSecurity, "Open Windows Security"));
                break;
            case "ban" or "banhist":
                if (r.Entry is null) acts.Add(new(ActionKind.BanIp, $"Ban permanently{sfx}", Primary: true, Style: "danger"));
                acts.Add(new(ActionKind.MoveToAllowed, $"Trust this IP{sfx}"));
                acts.Add(new(ActionKind.BackToDetected, $"Unban and watch again{sfx}"));
                break;
            case "excl":
                acts.Add(new(ActionKind.RemoveAllow, r.Sec == "wail2ban" ? $"Stop trusting{sfx}" : $"Remove the allow{sfx}", Primary: true));
                break;
            case "builtin":
                acts.Add(new(ActionKind.RemoveAllow, "Built-in (games, anti-cheat, FreeEDR)", Enabled: false));
                break;
            case "cve":
                acts.Add(same.All(ownCve) ? new(ActionKind.UpdateCve, $"Update now{sfx}", Primary: true) : new(ActionKind.UpdateCve, "Belongs to another account", Enabled: false));
                if (n == 1 && r.Entry is not null) acts.Add(new(ActionKind.ReadAdvisory, "Read the advisory", Arg: AdvisoryUrl(r.Entry)));
                acts.Add(new(ActionKind.IgnoreCve, $"Ignore{sfx}"));
                break;
            case "hist":
                if (r.Sec == "cve") acts.Add(same.All(ownCve) ? new(ActionKind.UpdateAgain, $"Update again{sfx}") : new(ActionKind.UpdateAgain, "Belongs to another account", Enabled: false));
                else acts.Add(new(ActionKind.UpdateAgain, $"Update again{sfx}"));
                acts.Add(new(ActionKind.BackToDetected, $"Move back to {info.Subs[0]}{sfx}"));
                acts.Add(new(ActionKind.MoveToAllowed, $"Move to {info.Subs[2]}{sfx}"));
                break;
            case "app":
                acts.Add(new(ActionKind.UpdateApp, $"Update now{sfx}", Primary: true));
                acts.Add(new(ActionKind.UpdateAllApps, "Update all apps"));
                acts.Add(new(ActionKind.HideApp, $"Hide{sfx}"));
                break;
            case "hidden":
                acts.Add(new(ActionKind.ShowApp, $"Show again{sfx}", Primary: true));
                acts.Add(new(ActionKind.UpdateApp, $"Update now{sfx}"));
                break;
            case "sys":
                if (e is not null && Ps.Eq(e.S("kind"), "tool"))
                {
                    if (e.T("tool")) acts.Add(new(ActionKind.UpdateTool, $"Update {e.S("tool")} now", Primary: true, Arg: e.S("tool")));
                    if (e.T("url")) acts.Add(new(ActionKind.OpenUrl, "Open the release page", Arg: e.S("url")));
                }
                break;
        }
        if (e is not null && n == 1 && e.T("process") && IsAny(e.S("blade"), "realtime", "ioc", "yara", "defender") && File.Exists(e.S("process")))
        {
            acts.Add(new(ActionKind.ScanWithDefender, "Scan with Microsoft Defender", Arg: e.S("process")));
            acts.Add(new(ActionKind.VirusTotal, "Look up on VirusTotal", Arg: e.S("process")));
            acts.Add(new(ActionKind.OpenLocation, "Open file location", Arg: e.S("process")));
        }
        acts.Add(new(ActionKind.CopyDetails, "Copy details"));
        return acts;
    }

    public static string ParentOf(Rec e) => Ps.Eq(e.S("blade"), "sigma") ? SigmaProcess.Of(e).Parent : e.S("parent");

    /// <summary>Public advisory page: NVD for a CVE id, OSV for the rest (GHSA, PYSEC, ...).</summary>
    public static string AdvisoryUrl(Rec v)
    {
        var cve = v.S("cve");
        if (Ps.Rx(@"^CVE-\d{4}-\d+$").IsMatch(cve)) return $"https://nvd.nist.gov/vuln/detail/{cve}";
        var id = Ps.Rx(@"[^A-Za-z0-9\-_.:]").Replace(v.T("id") ? v.S("id") : cve, "");
        return $"https://osv.dev/vulnerability/{id}";
    }

    private static string Short(string s, int max) => s.Length > max ? s[..(max - 3)] + "..." : s;
    private static bool IsAny(string v, params string[] o) => o.Any(x => Ps.Eq(v, x));

    // ---- engine operations (port of Get-BlockOp / Get-AllowOp / ...) ------------------------------------

    public static JsonObject? FlagOp(Rec? e)
    {
        if (e is null) return null;
        var b = e.S("blade");
        if (IsAny(b, "realtime", "ioc", "yara"))
            return e.T("process") && Path.IsPathRooted(e.S("process")) ? new() { ["action"] = "block", ["blade"] = b, ["image"] = e.S("process"), ["sha256"] = e.S("sha256"), ["title"] = e.S("title") } : null;
        if (Ps.Eq(b, "sigma")) return new() { ["action"] = "block", ["blade"] = "sigma", ["title"] = e.S("title") };
        if (Ps.Eq(b, "wail2ban") && e.T("ip")) return new() { ["action"] = "block", ["blade"] = "wail2ban", ["ip"] = e.S("ip") };
        return null;
    }

    public static JsonObject? AllowOp(Rec? e, string variant, Func<string, string?> signerOf)
    {
        if (e is null) return null;
        var p = e.S("process");
        switch (e.S("blade").ToLowerInvariant())
        {
            case "realtime":
                if (variant == "parent" && e.T("parent"))
                    return new() { ["action"] = "exclude", ["blade"] = "realtime", ["rule"] = "*", ["image"] = "", ["parent"] = PatternRules.VersionlessPattern(e.S("parent")), ["parentSigner"] = SafeSigner(signerOf(e.S("parent"))) };
                if (variant == "signer")
                {
                    var sg = signerOf(p);
                    return sg is not null && !PatternRules.IsUnsafeSigner(sg) ? new() { ["action"] = "exclude", ["blade"] = "realtime", ["rule"] = "*", ["image"] = "", ["parent"] = "", ["signer"] = sg } : null;
                }
                if (p.Length == 0) return null;
                return new() { ["action"] = "exclude", ["blade"] = "realtime", ["rule"] = variant == "rule" && e.T("rule") ? e.S("rule") : "*", ["image"] = PatternRules.EscapeWildcards(p), ["raw"] = p };
            case "ioc": return e.T("sha256") ? new() { ["action"] = "exclude", ["blade"] = "ioc", ["sha256"] = e.S("sha256"), ["image"] = p } : null;
            case "yara": return p.Length > 0 ? new() { ["action"] = "exclude", ["blade"] = "yara", ["image"] = PatternRules.EscapeWildcards(p), ["raw"] = p } : null;
            case "sigma":
            {
                var par = SigmaProcess.Of(e).Parent;
                if (variant == "parent" && par.Length > 0)
                    return new() { ["action"] = "exclude", ["blade"] = "sigma", ["title"] = "*", ["parent"] = PatternRules.VersionlessPattern(par), ["parentSigner"] = SafeSigner(signerOf(par)) };
                return new() { ["action"] = "exclude", ["blade"] = "sigma", ["title"] = e.S("title") };
            }
            case "wail2ban":
            {
                if (!e.T("ip")) return null;
                var c = e.S("ip");
                if (variant == "net" && Ps.Rx(@"^(\d+\.\d+\.\d+)\.\d+$").Match(c) is { Success: true } m) c = m.Groups[1].Value + ".0/24";
                return new() { ["action"] = "exclude", ["blade"] = "wail2ban", ["cidr"] = c, ["note"] = "added from the dashboard" };
            }
            case "defender":
                switch (Ps.Rx("-audit$").Replace(e.S("kind"), ""))
                {
                    case "asr": return new() { ["action"] = "exclude", ["blade"] = "defender", ["kind"] = "asr", ["path"] = e.T("path") ? e.S("path") : p };
                    case "cfa": return p.Length > 0 ? new() { ["action"] = "exclude", ["blade"] = "defender", ["kind"] = "cfa", ["path"] = p } : null;
                    case "malware": return e.T("threatId") ? new() { ["action"] = "exclude", ["blade"] = "defender", ["kind"] = "threat", ["path"] = e.S("threatId"), ["note"] = e.S("threat") } : null;
                }
                break;
        }
        return null;
    }

    public static JsonObject? AllowOpFromBlock(Rec b) => b.S("blade").ToLowerInvariant() switch
    {
        "realtime" => new() { ["action"] = "exclude", ["blade"] = "realtime", ["rule"] = "*", ["image"] = PatternRules.EscapeWildcards(b.S("image")), ["raw"] = b.S("image") },
        "ioc" when b.T("sha256") => new() { ["action"] = "exclude", ["blade"] = "ioc", ["sha256"] = b.S("sha256"), ["image"] = b.S("image") },
        "ioc" or "yara" => new() { ["action"] = "exclude", ["blade"] = "yara", ["image"] = PatternRules.EscapeWildcards(b.S("image")), ["raw"] = b.S("image") },
        "sigma" => new() { ["action"] = "exclude", ["blade"] = "sigma", ["title"] = b.S("title") },
        "wail2ban" => new() { ["action"] = "exclude", ["blade"] = "wail2ban", ["cidr"] = b.S("ip"), ["note"] = "added from the dashboard" },
        _ => null,
    };

    /// <summary>Both allows for "everything started by this program" (real-time and Sigma), tied to its signature.</summary>
    public static JsonObject[] ParentEverywhereOps(string parent, Func<string, string?> signerOf)
    {
        var pat = PatternRules.VersionlessPattern(parent);
        var sg = SafeSigner(signerOf(parent));
        return
        [
            new() { ["action"] = "exclude", ["blade"] = "realtime", ["rule"] = "*", ["image"] = "", ["parent"] = pat, ["parentSigner"] = sg },
            new() { ["action"] = "exclude", ["blade"] = "sigma", ["title"] = "*", ["parent"] = pat, ["parentSigner"] = sg },
        ];
    }

    private static string SafeSigner(string? s) => s is not null && !PatternRules.IsUnsafeSigner(s) ? s : "";

    // ---- CVE updates ------------------------------------------------------------------------------------

    public sealed record PipCommand(string FilePath, string[] Arguments, string Display);

    /// <summary>A python path the tray may run: "py", a Store alias (python3.11), or a rooted python.exe without shell metacharacters.</summary>
    public static string SafePython(string? py)
    {
        if (string.IsNullOrWhiteSpace(py)) return "py";
        var p = py.Trim();
        if (Ps.Eq(p, "py") || Ps.Rx(@"^python(\d+(\.\d+)?)?$").IsMatch(p)) return p;
        if (Ps.Rx(@"['"";`$\x00-\x1f\x7f-\x9f]").IsMatch(p)) return "py";
        try
        {
            if (!Path.IsPathRooted(p) || Path.GetFullPath(p) != p || !Ps.Eq(Path.GetFileName(p), "python.exe") || !File.Exists(p)) return "py";
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return "py"; }
        return p;
    }

    /// <summary>The account may update this package: it owns the Python (scan recorded its SID) or it is in an admin-only folder.</summary>
    public static bool OwnsCve(Rec v, string currentSid, string userProfile)
    {
        var owner = v.S("owner");
        if (owner.Length > 0 && Ps.Eq(owner, currentSid)) return true;
        var p = v.S("path");
        if (p.Length == 0 || Ps.Rx(@"['"";`$\x00-\x1f\x7f-\x9f]").IsMatch(p)) return false;
        try
        {
            var full = Path.GetFullPath(p.Replace('/', '\\')).TrimEnd('\\');
            foreach (var root in new[] { EdrPaths.ProgramFiles, EdrPaths.ProgramFilesX86, EdrPaths.SystemRoot }.Where(x => x.Length > 0))
            {
                var r = Path.GetFullPath(root).TrimEnd('\\');
                if (full.StartsWith(r + "\\", StringComparison.OrdinalIgnoreCase) || Ps.Eq(full, r)) return true;
            }
            if (owner.Length == 0 && userProfile.Length > 0)
            {
                var up = Path.GetFullPath(userProfile).TrimEnd('\\');
                if (full.StartsWith(up + "\\", StringComparison.OrdinalIgnoreCase)) return true;
            }
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { }
        return false;
    }

    public static List<PipCommand> CveCommands(IEnumerable<Rec> items, string currentSid, string userProfile)
    {
        var targets = new Dictionary<string, (string Py, string Pkg, string Min)>(StringComparer.OrdinalIgnoreCase);
        var order = new List<string>();
        foreach (var v in items)
        {
            if (!OwnsCve(v, currentSid, userProfile)) continue;
            var pkg = v.T("fixPackage") ? v.S("fixPackage") : v.S("package");
            var py = v.T("python") ? v.S("python") : "py";
            var min = Ps.Eq(pkg, v.S("package")) ? v.S("fixed") : "";
            var k = $"{py}|{pkg}";
            if (!targets.TryGetValue(k, out var t)) { targets[k] = (py, pkg, min); order.Add(k); }
            else if (min.Length > 0 && PyVersion.Compare(min, t.Min) > 0) targets[k] = t with { Min = min };
        }
        return order.Select(k =>
        {
            var t = targets[k];
            var pkg = Ps.Rx(@"[^a-zA-Z0-9_\-.]").Replace(t.Pkg, "");
            var min = Ps.Rx(@"[^a-zA-Z0-9_\-.]").Replace(t.Min, "");
            var py = SafePython(t.Py);
            var spec = min.Length > 0 ? $"{pkg}>={min}" : pkg;
            return new PipCommand(py, ["-m", "pip", "install", "--upgrade", spec], $"{(py.Contains(' ') ? $"\"{py}\"" : py)} -m pip install --upgrade {spec}");
        }).ToList();
    }

    public static bool IsValidWingetId(string id) => Ps.Rx(@"^[a-zA-Z0-9_\-.]+$").IsMatch(id);
}
