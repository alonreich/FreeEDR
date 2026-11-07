using System.Globalization;
using System.Text.Json.Nodes;

namespace Edr.Core;

/// <summary>
/// Sorts every event, verdict and scan result into its section and list: originally a port of the PowerShell
/// tray (Update-Model, Find-Exclusion, Find-Block, Get-Overall); the golden tests keep it stable.
/// </summary>
public sealed class ModelBuilder(EdrInputs inputs, ISignerLookup signers)
{
    private readonly EdrInputs _in = inputs;
    private readonly ISignerLookup _signers = new CachedSigners(signers, int.MaxValue, stamped: false);   // one build: per path

    // ---- per-event helpers --------------------------------------------------------------------------

    /// <summary>Alerts from a rule no longer in the Sysmon config (old LocalEDR rules) or Hayabusa re-reporting Sysmon.</summary>
    public bool IsRetired(Rec e)
    {
        if (e.T("oldRule")) return true;
        var blade = e.S("blade");
        if (Ps.Eq(blade, "sigma") && Ps.Match(e.S("title"), @"\(Sysmon Alert\)$")) return true;
        return Ps.Eq(blade, "realtime") && e.T("rule") && _in.RuleNames.Count > 0 &&
               !Ps.Eq(e.S("rule"), "WMI persistence") && !_in.RuleNames.Contains(e.S("rule"));
    }

    public bool IsReviewed(Rec e) => e.T("legacy") || _in.Reviewed.Contains(e.S("id")) || IsRetired(e);

    private bool AllReviewed(IEnumerable<Rec> members) => members.All(IsReviewed);

    /// <summary>The parent pattern matches one of the first N ancestors, signed by parentSigner if set (same rule as the engine).</summary>
    public bool ParentMatches(Rec r, IEnumerable<string> chain)
    {
        var n = Math.Max(1, r.I("ancestors"));
        foreach (var c in chain.Where(c => c.Length > 0).Take(n))
        {
            if (!Ps.Like(c, r.S("parent"))) continue;
            if (r.T("parentSigner") && !Ps.Eq(_signers.SignerOf(c), r.S("parentSigner"))) continue;
            return true;
        }
        return false;
    }

    /// <summary>Mirrors the engine's exclusion logic; returns the matching exclusion entry.</summary>
    public Rec? FindExclusion(Rec e)
    {
        var x = _in.Exclusions;
        switch (e.S("blade").ToLowerInvariant())
        {
            case "realtime":
            {
                string img = e.S("process"), par = e.S("parent"), rule = e.S("rule");
                foreach (var p in x["realtimePath"])
                    if (img.Length > 0 && p.T("prefix") && img.StartsWith(p.S("prefix"), StringComparison.OrdinalIgnoreCase)) return p;
                foreach (var r in x["realtime"])
                {
                    if (r.T("rule") && r.S("rule") != "*" && !Ps.Eq(r.S("rule"), rule)) continue;
                    if (r.T("image") && !Ps.Like(img, r.S("image"))) continue;
                    if (r.T("detail"))
                    {
                        if (Ps.Eq(r.S("match"), "exact"))
                        {
                            if (!string.Equals(e.S("detail").Trim(), r.S("detail").Trim(), StringComparison.OrdinalIgnoreCase)) continue;
                        }
                        else
                        {
                            if (!Ps.Like(e.S("detail"), r.S("detail"))) continue;
                        }
                    }
                    if (r.T("parent") && !ParentMatches(r, [par, .. e.Strings("ancestors")])) continue;
                    if (r.T("signer") && !Ps.Eq(_signers.SignerOf(img), r.S("signer"))) continue;
                    if (!r.T("image") && !r.T("parent") && !r.T("signer") && !r.T("detail")) continue;
                    return r;
                }
                break;
            }
            case "ioc":
                foreach (var r in x["ioc"]) if (e.T("sha256") && Ps.Eq(r.S("sha256"), e.S("sha256"))) return r;
                break;
            case "yara":
                foreach (var r in x["yara"]) if (e.T("process") && Ps.Like(e.S("process"), r.S("image"))) return r;
                break;
            case "sigma":
            {
                var par = SigmaProcess.Of(e).Parent;
                foreach (var r in x["sigma"])
                {
                    var anyRule = !r.T("title") || r.S("title") == "*";
                    if (!anyRule && !Ps.Eq(r.S("title"), e.S("title"))) continue;
                    if (r.T("parent") && !ParentMatches(r, [par])) continue;
                    if (anyRule && !r.T("parent")) continue;
                    return r;
                }
                break;
            }
            case "wail2ban":
                if (e.T("ip")) foreach (var r in x["wail2ban"]) if (Ip.InCidr(e.S("ip"), r.S("cidr"))) return r;
                break;
            case "defender":
                foreach (var r in x["defender"])
                {
                    if (Ps.Eq(r.S("kind"), "threat")) { if (e.T("threatId") && Ps.Eq(r.S("path"), e.S("threatId"))) return r; }
                    else if (Ps.Eq(r.S("kind"), AuditKind(e.S("kind"))) && (Ps.Eq(r.S("path"), e.S("path")) || Ps.Eq(r.S("path"), e.S("process")))) return r;
                }
                break;
        }
        return null;
    }

    /// <summary>Defender audit kinds ("asr-audit") are allowed like their blocking kinds ("asr").</summary>
    private static string AuditKind(string kind) => kind.EndsWith("-audit", StringComparison.OrdinalIgnoreCase) ? kind[..^6] : kind;

    public Rec? FindBlock(Rec e)
    {
        var b = e.S("blade");
        foreach (var k in _in.Blocks)
        {
            if (IsAny(b, "realtime", "ioc", "yara"))
            {
                if (!IsAny(k.S("blade"), "realtime", "ioc", "yara")) continue;
                if ((e.T("process") && k.T("image") && Ps.Eq(k.S("image"), e.S("process"))) ||
                    (k.T("sha256") && e.T("sha256") && Ps.Eq(k.S("sha256"), e.S("sha256")))) return k;
            }
            else if (Ps.Eq(b, "sigma")) { if (Ps.Eq(k.S("blade"), "sigma") && Ps.Eq(k.S("title"), e.S("title"))) return k; }
            else if (Ps.Eq(b, "wail2ban")) { if (Ps.Eq(k.S("blade"), "wail2ban") && e.T("ip") && Ps.Eq(k.S("ip"), e.S("ip"))) return k; }
        }
        return null;
    }

    public Rec? FindCveExclusion(Rec v)
    {
        var ids = new[] { v.S("id"), v.S("cve") }.Concat(v.Strings("aliases")).Where(s => s.Length > 0).ToList();
        return _in.Exclusions["cve"].FirstOrDefault(x => ids.Any(i => Ps.Eq(i, x.S("cve"))));
    }

    private bool UpdatedSince(string sec, string key, DateTime since) =>
        _in.History.Any(h => Ps.Eq(h.S("sec"), sec) && Ps.Eq(h.S("key"), key) && Ps.ToDate(h.S("time")) is { } t && t > since);

    public static string ExclText(string list, Rec x)
    {
        switch (list)
        {
            case "realtimePath": return $"Any program under {x.S("prefix")}";
            case "realtime":
            {
                var what = new List<string>();
                if (x.T("image")) what.Add($"program {(x.T("raw") ? x.S("raw") : x.S("image"))}");
                if (x.T("parent"))
                    what.Add($"started by {x.S("parent")}{(x.I("ancestors") > 1 ? $" (up to {x.S("ancestors")} levels up)" : "")}{(x.T("parentSigner") ? $" signed by {x.S("parentSigner")}" : "")}");
                if (x.T("signer")) what.Add(x.T("image") ? $"signed by {x.S("signer")}" : $"every program signed by {x.S("signer")}");
                if (x.T("detail")) what.Add(Ps.Eq(x.S("match"), "exact") ? $"command line is {x.S("detail")}" : $"command line like {x.S("detail")}");
                var r = x.S("rule") == "*" || !x.T("rule") ? "all rules" : $"rule \"{x.S("rule")}\"";
                return string.Join(", ", what) + "  -  " + r;
            }
            case "ioc": return $"{x.S("image")}  (SHA256 {x.S("sha256")})";
            case "yara": return x.T("raw") ? x.S("raw") : x.S("image");
            case "sigma":
            {
                var rule = !x.T("title") || x.S("title") == "*" ? "Any Sigma rule" : $"Rule \"{x.S("title")}\"";
                return x.T("parent") ? $"{rule}, when started by {x.S("parent")}{(x.T("parentSigner") ? $" signed by {x.S("parentSigner")}" : "")}" : rule;
            }
            case "wail2ban": return $"Never block {x.S("cidr")}{(x.T("note") ? $"  ({x.S("note")})" : "")}";
            case "cve": return $"{x.S("cve")}{(x.T("package") ? $" in {x.S("package")}" : "")}";
            case "defender":
                return Ps.Eq(x.S("kind"), "threat") ? $"Defender threat ID {x.S("path")}{(x.T("note") ? $" ({x.S("note")})" : "")}" : x.S("path");
        }
        return "";
    }

    public static string ExclType(string list, Rec x) => x.T("profile")
        ? $"Trusted app: {(Catalog.ProfileNames.TryGetValue(x.S("profile"), out var pn) ? pn : x.S("profile"))}"
        : list switch
    {
        "realtimePath" => "Folder",
        "realtime" => x.T("signer") && !x.T("image") ? "Publisher (digital signature)"
                    : x.T("parent") ? "Everything it starts (any version)"
                    : x.T("rule") && x.S("rule") != "*" ? "Program, one rule" : "Program, all rules",
        "ioc" => "File fingerprint (not malware)",
        "yara" => "File skipped by YARA",
        "defender" => x.S("kind").ToLowerInvariant() switch
        {
            "cfa" => "Defender: Controlled folder access",
            "threat" => "Defender: threat allowed",
            _ => "Defender: ASR rules",
        },
        _ => "",
    };

    // ---- formatting ---------------------------------------------------------------------------------

    public static string Short(string? text, int max = 220)
    {
        var t = Ps.Rx(@"\s+").Replace(text ?? "", " ");
        return t.Length > max ? t[..(max - 3)] + "..." : t;
    }

    public static string FormatSev(string sev) => sev.Length > 0 ? "\u25CF " + sev : "";

    public static string FormatWhen(string? value, string fmt = "ddd dd/MM HH:mm") =>
        string.IsNullOrEmpty(value) ? "never" : Ps.ToDate(value) is { } d ? d.ToString(fmt, CultureInfo.CurrentCulture) : value;

    private static string Minute(string s) => s.Length > 16 ? s[..16] : s;

    private static bool IsAny(string value, params string[] options) => options.Any(o => Ps.Eq(value, o));

    private static Row NewRow(string kind, string time, string sev, params string[] cols) =>
        new() { Kind = kind, Time = time, Sev = sev, Cols = cols };

    private static void Add(TrayModel m, string sec, int list, Row r)
    {
        r.Sec = sec; r.List = list;
        m.Sec[sec].Rows[list].Add(r);
    }

    /// <summary>Group-Object: groups in order of first appearance, keys compared case-insensitively.</summary>
    private static List<List<T>> GroupBy<T>(IEnumerable<T> items, Func<T, string> key)
    {
        var map = new Dictionary<string, List<T>>(StringComparer.OrdinalIgnoreCase);
        var order = new List<List<T>>();
        foreach (var i in items)
        {
            var k = key(i);
            if (!map.TryGetValue(k, out var g)) { map[k] = g = []; order.Add(g); }
            g.Add(i);
        }
        return order;
    }

    private static List<Rec> ByTime(IEnumerable<Rec> items) => items.OrderBy(e => e.S("time"), Ps.Order).ToList();

    private Row EventRow(string sec, Rec rep, IReadOnlyList<Rec> members, int totalCount = 0)
    {
        var count = totalCount > 0 ? totalCount : members.Count;
        var pinned = Ps.Match(rep.S("title"), Catalog.ConfirmPattern);
        var title = (pinned ? "Was this you?   " : "") + rep.S("title");
        if (count > 1) title += $"   (x{count})";
        var detail = Short(rep.S("detail"));
        string[] cols = sec switch
        {
            "malware" => [FormatSev(rep.S("severity")), rep.S("time"), Catalog.BladeNames.GetValueOrDefault(rep.S("blade")) ?? "", title, Ps.Leaf(rep.S("process")), detail],
            "edr" => [FormatSev(rep.S("severity")), rep.S("time"), title, Ps.Leaf(rep.S("process")), Ps.Leaf(rep.S("parent")), detail],
            "wail2ban" => [rep.S("time"), rep.S("ip"), title, Ip.NetLabel(rep.S("ip"))],
            _ => SigmaCols(rep, title, detail),
        };
        var r = NewRow("event", rep.S("time"), rep.S("severity"), cols);
        r.Ev = rep; r.Group = members; r.Key = rep.S("id"); r.Pinned = pinned;
        r.Muted = AllReviewed(members);
        return r;
    }

    private static string[] SigmaCols(Rec rep, string title, string detail)
    {
        var sp = SigmaProcess.Of(rep);
        return [FormatSev(rep.S("severity")), rep.S("time"), title, Ps.Leaf(sp.Image), Ps.Leaf(sp.Parent), detail];
    }

    // ---- the model ----------------------------------------------------------------------------------

    public TrayModel Build()
    {
        var m = new TrayModel();
        var sys = new List<Rec>();
        var det = new Dictionary<string, List<Rec>> { ["malware"] = [], ["edr"] = [], ["sigma"] = [] };
        var defBlocked = new List<Rec>();
        var fails = new List<Rec>();
        var banHist = new List<Rec>();
        var logins = new List<Rec>();
        var blockEv = new Dictionary<string, List<Rec>>(StringComparer.OrdinalIgnoreCase);
        var exclEv = new Dictionary<string, List<Rec>>(StringComparer.OrdinalIgnoreCase);
        var avSeen = new HashSet<string>(StringComparer.Ordinal);
        string? claude = _in.Claude;

        foreach (var ev in _in.Events)
        {
            var e = ev;
            var b = e.S("blade");
            if (Ps.Eq(b, "system") || (Ps.Eq(b, "patch") && Ps.Eq(e.S("kind"), "tool"))) { sys.Add(e); continue; }
            if (Ps.Eq(b, "wail2ban"))
            {
                if (Ps.Eq(e.S("kind"), "fail")) fails.Add(e);
                else if (Ps.Eq(e.S("kind"), "login")) logins.Add(e);
                else if (e.T("ip") && e.T("expires")) banHist.Add(e);
                continue;
            }
            if (!IsAny(b, "realtime", "ioc", "yara", "sigma", "defender")) continue;   // cve: the CVE tab shows the latest scan
            if (claude is null)
            {
                var par = Ps.Eq(b, "sigma") ? SigmaProcess.Of(e).Parent : e.S("parent");
                claude = new[] { par }.Concat(e.Strings("ancestors")).FirstOrDefault(p => Ps.Match(p, @"\\claude\.exe$"));
                if (claude is not null) _in.Claude = claude;
            }
            if (Ps.Eq(b, "defender") && e.T("threat"))
                avSeen.Add($"{e.S("threat")}|{Minute(e.T("eventTime") ? e.S("eventTime") : e.S("time"))}");
            if (Ps.Eq(b, "sigma") && Ps.Match(e.S("title"), Catalog.DefenderSigmaTitles))
            {
                // Hayabusa repeating a Defender detection: shown once, in Anti-Malware, as blocked by Defender
                var tm = Ps.Rx(@"Threat: ([^\xA6]+)").Match(e.S("detail"));
                var threat = tm.Success ? tm.Groups[1].Value.Trim() : e.S("title");
                var t16 = Minute(e.T("eventTime") ? e.S("eventTime") : e.S("time"));
                if (!avSeen.Add($"{threat}|{t16}")) continue;
                e = new Rec(new JsonObject(Rec.NodeOptions)
                {
                    ["id"] = e.S("id"), ["time"] = e.S("time"), ["blade"] = "defender", ["kind"] = "malware", ["severity"] = e.S("severity"),
                    ["title"] = $"Defender detected malware: {threat}", ["threat"] = threat, ["process"] = SigmaProcess.Of(e).Image,
                    ["detail"] = e.S("detail"), ["eventTime"] = e.S("eventTime"),
                });
                b = "defender";
            }
            if (FindBlock(e) is { } bk) { AddTo(blockEv, bk.S("id"), e); continue; }
            if (FindExclusion(e) is { } x) { AddTo(exclEv, x.S("id"), e); continue; }
            if (Ps.Eq(b, "defender") && !IsAny(e.S("kind"), "asr-audit", "cfa-audit")) { defBlocked.Add(e); continue; }   // Defender already blocked it (audit = only reported: Detected)
            if (Ps.Eq(e.S("kind"), "blocked-start")) continue;
            det[Catalog.BladeSection[b]].Add(e);
        }

        // Any unreviewed pinned events whose group is no longer in the ring buffer
        foreach (var (pid, pe) in _in.EvictedPinned)
        {
            if (_in.Reviewed.Contains(pid)) continue;
            var b = pe.S("blade");
            if (!Catalog.BladeSection.TryGetValue(b, out var psec)) continue;
            var pkey = Ps.Eq(b, "sigma")
                ? $"sigma|{pe.S("title")}|{SigmaProcess.Of(pe).Image}|{SigmaProcess.Of(pe).Parent}"
                : $"{b}|{pe.S("title")}|{pe.S("process")}|{pe.S("parent")}";
            bool exists = det[psec].Any(e => {
                var k = Ps.Eq(e.S("blade"), "sigma")
                    ? $"sigma|{e.S("title")}|{SigmaProcess.Of(e).Image}|{SigmaProcess.Of(e).Parent}"
                    : $"{e.S("blade")}|{e.S("title")}|{e.S("process")}|{e.S("parent")}";
                return Ps.Eq(k, pkey);
            });
            if (!exists)
            {
                det[psec].Add(pe);
            }
        }

        // Detected: identical alerts collapsed into one row (x N)
        foreach (var sec in new[] { "malware", "edr", "sigma" })
        {
            var groups = GroupBy(det[sec], e => Ps.Eq(e.S("blade"), "sigma")
                ? $"sigma|{e.S("title")}|{SigmaProcess.Of(e).Image}|{SigmaProcess.Of(e).Parent}"
                : $"{e.S("blade")}|{e.S("title")}|{e.S("process")}|{e.S("parent")}");
            foreach (var g in groups)
            {
                var members = ByTime(g);
                var key = Ps.Eq(members[0].S("blade"), "sigma")
                    ? $"sigma|{members[0].S("title")}|{SigmaProcess.Of(members[0]).Image}|{SigmaProcess.Of(members[0]).Parent}"
                    : $"{members[0].S("blade")}|{members[0].S("title")}|{members[0].S("process")}|{members[0].S("parent")}";
                var total = members.Count + _in.EvictedCounts.GetValueOrDefault(key, 0);
                Add(m, sec, 0, EventRow(sec, members[^1], members, total));
            }
        }

        // Blocked by the user
        foreach (var bk in _in.Blocks)
        {
            var hits = blockEv.TryGetValue(bk.S("id"), out var h) ? ByTime(h) : [];
            var state = bk.S("note");
            if (bk.I("hits") != 0) state += $" Stopped {bk.S("hits")} time(s) since.";
            Row? r = null; var sec = "";
            switch (bk.S("blade").ToLowerInvariant())
            {
                case "realtime": r = NewRow("block", bk.S("added"), "", bk.S("added"), Ps.Leaf(bk.S("image")), bk.S("title"), state, bk.S("image")); sec = "edr"; break;
                case "ioc":
                case "yara": r = NewRow("block", bk.S("added"), "", bk.S("added"), bk.S("title"), Ps.Leaf(bk.S("image")), state, bk.S("image")); sec = "malware"; break;
                case "sigma": r = NewRow("block", bk.S("added"), "", bk.S("added"), bk.S("title"), hits.Count.ToString(CultureInfo.InvariantCulture), state); sec = "sigma"; break;
            }
            if (r is null) continue;
            r.Entry = bk; r.Key = bk.S("id"); r.Group = hits;
            if (hits.Count > 0) r.Ev = hits[^1];
            Add(m, sec, 1, r);
        }

        // Blocked by Microsoft Defender (already handled; listed so it can be allowed)
        foreach (var g in GroupBy(defBlocked, e => $"{e.S("kind")}|{e.S("path")}|{e.S("process")}|{e.S("threat")}"))
        {
            var members = ByTime(g);
            var rep = members[^1];
            var key = $"defBlocked|{rep.S("kind")}|{rep.S("path")}|{rep.S("process")}|{rep.S("threat")}";
            var count = members.Count + _in.EvictedCounts.GetValueOrDefault(key, 0);
            var title = rep.S("title") + (count > 1 ? $"   (x{count})" : "");
            var r = NewRow("defender", rep.S("time"), rep.S("severity"), rep.S("time"), title, Ps.Leaf(rep.S("process")), "Blocked by Microsoft Defender",
                           rep.T("path") ? rep.S("path") : rep.S("detail"));
            r.Ev = rep; r.Group = members; r.Key = rep.S("id");
            Add(m, "malware", 1, r);
        }

        // Allowed (exclusions)
        foreach (var (list, sec) in Catalog.ExclusionLists)
        {
            foreach (var x in _in.Exclusions[list])
            {
                var text = ExclText(list, x);
                string[] cols = sec switch
                {
                    "cve" => [x.S("added"), x.S("cve"), x.S("package")],
                    "wail2ban" => [x.S("added"), x.S("cidr"), x.S("note")],
                    "sigma" => [x.S("added"), x.S("title")],
                    _ => [x.S("added"), text, ExclType(list, x)],
                };
                var r = NewRow("excl", x.S("added"), "", cols);
                r.Entry = x; r.ExclList = list; r.Key = x.S("id"); r.Note = text;
                if (exclEv.TryGetValue(x.S("id"), out var ev)) r.Group = ev;
                Add(m, sec, 2, r);
            }
        }
        foreach (var bi in _in.BuiltIn)
        {
            var r = NewRow("builtin", "", "", "built-in", $"Any program under {bi}", "Games / anti-cheat / EDR (Sysmon config)");
            r.Key = $"builtin-{bi}"; r.Note = $"Any program under {bi}";
            Add(m, "edr", 2, r);
        }

        BuildWail2Ban(m, fails, logins, banHist);
        BuildCveAndApps(m);

        // Newest first ("Was this you?" on top); the CVE list worst first
        foreach (var s in m.Sec.Values)
        {
            for (var i = 0; i < 3; i++)
            {
                s.Rows[i] = s.Info.Key == "cve" && i == 0
                    ? s.Rows[i].OrderByDescending(r => Catalog.Rank(r.Sev) ?? -1).ThenBy(r => r.Entry?.S("package") ?? "", Ps.Order).ToList()
                    : s.Rows[i].OrderByDescending(r => r.Pinned && !r.Muted).ThenByDescending(r => r.Time, Ps.Order).ToList();
            }
        }

        // Counts: the tab shows how many open items; red only for security items that need a decision
        foreach (var s in m.Sec.Values)
        {
            var open = s.Rows[0].Where(r => !r.Muted).ToList();
            var serious = open.Count(r => s.Info.Key == "cve" || Catalog.Rank(r.Sev) >= 2);
            s.Count = open.Count;
            s.Alert = s.Info.Security && serious > 0;
            if (s.Info.Key is "malware" or "edr" or "sigma" or "wail2ban") { s.Attention = serious; m.Attention += serious; }
            m.Pinned += open.Count(r => r.Pinned);
        }

        m.Messages = sys.OrderByDescending(e => e.S("time"), Ps.Order).Take(300).Select(e =>
        {
            var r = NewRow("sys", e.S("time"), e.S("severity"), e.S("time"), e.S("title"), Short(e.S("detail"), 200));
            r.Ev = e; r.Key = e.S("id"); r.Sec = "overview";
            return r;
        }).ToList();
        m.Claude = claude;
        return m;
    }

    private void BuildWail2Ban(TrayModel m, List<Rec> fails, List<Rec> logins, List<Rec> banHist)
    {
        var bannedIp = new Dictionary<string, Rec>(StringComparer.OrdinalIgnoreCase);
        foreach (var b in _in.Status?.Child("wail2ban")?.Recs("banned") ?? []) bannedIp[b.S("ip")] = b;
        var perm = new Dictionary<string, Rec>(StringComparer.OrdinalIgnoreCase);
        foreach (var bk in _in.Blocks.Where(k => Ps.Eq(k.S("blade"), "wail2ban") && k.T("ip"))) perm[bk.S("ip")] = bk;
        var lastBan = new Dictionary<string, Rec>(StringComparer.OrdinalIgnoreCase);
        var lastBanOrder = new List<string>();
        foreach (var e in banHist)
        {
            var k = e.S("ip");
            if (!lastBan.TryGetValue(k, out var cur)) { lastBan[k] = e; lastBanOrder.Add(k); }
            else if (Ps.Order.Compare(e.S("time"), cur.S("time")) > 0) lastBan[k] = e;
        }
        foreach (var (k, ev) in _in.LastBans)
        {
            if (!lastBan.TryGetValue(k, out var cur)) { lastBan[k] = ev; lastBanOrder.Add(k); }
            else if (Ps.Order.Compare(ev.S("time"), cur.S("time")) > 0) lastBan[k] = ev;
        }

        foreach (var g in GroupBy(fails, e => e.S("ip")))
        {
            var ip = g[0].S("ip");
            if (bannedIp.ContainsKey(ip) || perm.ContainsKey(ip)) continue;
            if (FindExclusion(g[0]) is not null) continue;
            var since = lastBan.TryGetValue(ip, out var lb) ? lb.S("time") : "";
            var members = ByTime(g.Where(e => Ps.Order.Compare(e.S("time"), since) > 0));
            if (members.Count == 0) continue;
            var rep = members[^1];
            var failCount = members.Count + _in.EvictedCounts.GetValueOrDefault($"fail|{ip}", 0);
            var r = NewRow("fail", rep.S("time"), "Low", rep.S("time"), ip, $"{failCount} failed logon{(failCount != 1 ? "s" : "")}", Ip.NetLabel(ip));
            r.Ev = rep; r.Group = members; r.Key = $"fail-{ip}";
            r.Muted = AllReviewed(members);
            Add(m, "wail2ban", 0, r);
        }
        // Successful logins from the internet (one row per address and user)
        foreach (var g in GroupBy(logins, e => $"{e.S("ip")}|{e.S("user")}"))
        {
            var members = ByTime(g);
            var rep = members[^1];
            if (perm.ContainsKey(rep.S("ip")) || FindExclusion(rep) is not null) continue;
            var key = $"login|{rep.S("ip")}|{rep.S("user")}";
            var total = members.Count + _in.EvictedCounts.GetValueOrDefault(key, 0);
            Add(m, "wail2ban", 0, EventRow("wail2ban", rep, members, total));
        }
        foreach (var ip in bannedIp.Keys.Concat(perm.Keys).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            bannedIp.TryGetValue(ip, out var b); perm.TryGetValue(ip, out var bk); lastBan.TryGetValue(ip, out var ev);
            var since = bk is not null ? bk.S("added") : ev is not null ? ev.S("time") : "";
            var until = bk is not null ? "Permanent" : b is not null ? b.S("expires") : "";
            var how = bk is not null ? "By you (permanent)" : "Automatic (failed logons)";
            var r = NewRow("ban", since, "", since, ip, until, b is not null ? b.S("strikes") : "", Ip.NetLabel(ip), how);
            r.Entry = bk; r.Ban = b; r.Key = $"ban-{ip}";
            r.Ev = ev ?? new Rec(new JsonObject(Rec.NodeOptions) { ["blade"] = "wail2ban", ["ip"] = ip, ["title"] = $"Blocked {ip}", ["time"] = since });
            Add(m, "wail2ban", 1, r);
        }
        foreach (var ip in lastBanOrder)
        {
            if (bannedIp.ContainsKey(ip) || perm.ContainsKey(ip)) continue;
            var ev = lastBan[ip];
            if (FindExclusion(ev) is not null) continue;
            var r = NewRow("banhist", ev.S("time"), "", ev.S("time"), ip, $"Expired ({ev.S("expires")})", ev.S("strike"), Ip.NetLabel(ip), "Automatic - expired");
            r.Ev = ev; r.Muted = true; r.Key = $"hist-{ip}";
            Add(m, "wail2ban", 1, r);
        }
    }

    private void BuildCveAndApps(TrayModel m)
    {
        // CVE: the latest scan, only packages with a released fix (the scan drops the rest)
        var scanned = Ps.ToDate(_in.Cve?.S("scanned")) ?? DateTime.MinValue;
        foreach (var v in _in.Cve?.Recs("items") ?? [])
        {
            if (FindCveExclusion(v) is not null) continue;
            if (UpdatedSince("cve", v.S("id"), scanned)) continue;
            var r = NewRow("cve", FormatWhen(_in.Cve!.S("scanned"), "yyyy-MM-dd HH:mm:ss"), v.S("severity"),
                           FormatSev(v.S("severity")), v.S("cve"), v.S("package"), v.S("version"), v.S("fixed"), Short(v.S("summary"), 200));
            r.Entry = v; r.Key = $"cve-{v.S("id")}-{v.S("path")}";
            Add(m, "cve", 0, r);
        }

        // App updates (winget)
        var ignored = new HashSet<string>(_in.Ignored, StringComparer.OrdinalIgnoreCase);
        var checkedAt = _in.PatchChecked ?? DateTime.MinValue;
        foreach (var p in _in.PatchEvents)
        {
            if (ignored.Contains(p.S("appId"))) continue;
            if (UpdatedSince("apps", p.S("appId"), checkedAt)) continue;
            var r = NewRow("app", p.S("time"), "Info", p.S("process"), p.S("version"), p.S("latest"), p.S("appId"));
            r.Entry = p; r.Ev = p; r.Key = $"app-{p.S("appId")}";
            Add(m, "apps", 0, r);
        }
        foreach (var id in _in.Ignored)
        {
            var r = NewRow("hidden", "", "", id);
            r.EntryId = id; r.Key = $"hidden-{id}";
            Add(m, "apps", 2, r);
        }

        // Updates started from the dashboard (CVE + apps)
        foreach (var hx in _in.History)
        {
            Row r;
            var sec = hx.S("sec");
            if (Ps.Eq(sec, "cve")) r = NewRow("hist", hx.S("time"), "", hx.S("time"), hx.S("cve"), hx.S("package"), hx.S("version"), hx.S("fixed"));
            else if (Ps.Eq(sec, "apps")) r = NewRow("hist", hx.S("time"), "", hx.S("time"), hx.S("name"), hx.S("version"), hx.S("latest"));
            else continue;
            r.Entry = hx; r.Key = hx.S("id");
            Add(m, sec.ToLowerInvariant(), 1, r);
        }
    }

    private static void AddTo(Dictionary<string, List<Rec>> map, string key, Rec e)
    {
        if (!map.TryGetValue(key, out var l)) map[key] = l = [];
        l.Add(e);
    }

    // ---- the Overview sentence ----------------------------------------------------------------------

    public static bool EngineAlive(Rec? status, DateTime now) =>
        status is not null && status.T("heartbeat") && Ps.ToDate(status.S("heartbeat")) is { } hb && (now - hb).TotalSeconds < 90;

    /// <summary>Get-PauseState: the blade's state object (engine v1 called the EDR blade "realtime").</summary>
    public static Rec? PauseState(Rec? status, string blade) =>
        status is null ? null : blade == "edr" && !status.T("edr") ? status.Child("realtime") : status.Child(blade);

    public static string FormatUntil(Rec st)
    {
        var u = st.S("pausedUntil");
        if (Ps.Eq(u, Catalog.UntilResumed) || Ps.Eq(u, "until-resumed")) return "until you resume it";
        if (string.IsNullOrEmpty(u)) return "";
        return "until " + (Ps.ToDate(u) is { } d ? d.ToString("HH:mm", CultureInfo.CurrentCulture) : u);
    }

    /// <summary>One sentence that tells the user what matters right now (Get-Overall).</summary>
    public static Overall GetOverall(TrayModel? model, Rec? st, DateTime now)
    {
        if (!EngineAlive(st, now))
            return new("down", "Protection is OFF - EDR engine is not running", "Open FreeEDR and click Restart engine, or restart the PC.");
        var edr = PauseState(st, "edr");
        var w2b = st!.Child("wail2ban");
        var problems = new List<string>();
        var sysmon = st.Child("sysmon");
        if (sysmon is null || !sysmon.T("ok")) problems.Add($"Sysmon sensor: {sysmon?.S("message")}");
        if (edr is not null && Ps.Eq(edr.S("state"), "error")) problems.Add($"EDR: {edr.S("error")}");
        if (w2b is not null && Ps.Eq(w2b.S("state"), "error")) problems.Add($"Wail2Ban: {w2b.S("error")}");
        if (st.I("lagSeconds") >= 30) problems.Add($"Event processing lag: {st.I("lagSeconds")}s ({st.I("backlog")} queued)");
        if (problems.Count > 0) return new("down", "Protection has a problem", string.Join("  |  ", problems));

        var att = model?.Attention ?? 0;
        if (model is { Pinned: > 0 })
            return new("attention", $"Please confirm {model.Pinned} item{(model.Pinned != 1 ? "s" : "")}: was this you?",
                       "Logins from the internet, cleared logs or account changes. Answer \"Yes, it was me\" or \"No, it wasn't me\" for each one.");
        var cve = model?.Sec["cve"].Count ?? 0;
        var paused = new List<string>();
        if (edr is not null && Ps.Eq(edr.S("state"), "paused")) paused.Add($"EDR is paused {FormatUntil(edr)}");
        else
            // One part paused on its own also shows as paused (grey shield), not as "You're protected"
            foreach (var (b, label) in Catalog.PauseLabels)
                if (st!.Child(b) is { } bs && Ps.Eq(bs.S("state"), "paused")) paused.Add($"{label} is paused {FormatUntil(bs)}");
        if (w2b is not null && Ps.Eq(w2b.S("state"), "paused")) paused.Add($"Wail2Ban is paused {FormatUntil(w2b)}");
        if (att > 0)
        {
            // The same number as Activity's "To review" tab and the sidebar badge: every open item (red because of the serious ones)
            var secs = new[] { "malware", "edr", "sigma" }.Select(s => model!.Sec[s]).ToList();
            var open = secs.Sum(s => s.Count);
            var parts = secs.Where(s => s.Count > 0).Select(s => $"{s.Info.Name}: {s.Count}");
            var sub = string.Join(",  ", parts) + ".  Open Activity, pick an item, then allow it, flag it or mark it reviewed.";
            if (paused.Count > 0) sub = string.Join("; ", paused) + ". " + sub;
            return new("attention", $"{open} item{(open != 1 ? "s" : "")} need{(open == 1 ? "s" : "")} your review", sub);
        }
        if (paused.Count > 0) return new("paused", "Protection partly paused", string.Join("; ", paused) + ".");
        var scan = st.Child("scan");
        if (scan?["ok"] is JsonValue ok && ok.TryGetValue(out bool okb) && !okb) return new("attention", "Last scan had problems", scan.S("summary"));
        var subOk = $"Nothing needs your attention. Last update: {FormatWhen(scan?.S("lastEnd"), "ddd HH:mm")}. Next: {FormatWhen(scan?.S("nextDue"), "ddd HH:mm")}.";
        if (cve > 0) subOk += $"  {cve} security update{(cve != 1 ? "s" : "")} waiting in Updates.";
        return new("ok", "You're protected", subOk);
    }
}
