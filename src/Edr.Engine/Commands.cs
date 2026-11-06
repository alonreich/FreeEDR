using System.Globalization;
using System.Text.Json.Nodes;
using Edr.Core;
using Edr.Core.Native;

namespace Edr.Engine;

/// <summary>
/// Command intake: control\ (admin-only, from the elevated helper) first, then inbox\ (any account: only resume and
/// scan-now). At most 25 files per folder per sweep, files over 64 KB are discarded, a file is deleted before it runs.
/// <see cref="Execute"/> is the single validation gate (the tray's checks are advisory).
/// </summary>
internal sealed class Commands(Context ctx, Wail2Ban w2b, Scanner scanner)
{
    private readonly Dictionary<string, DateTime> _locked = new(StringComparer.OrdinalIgnoreCase);

    public void Read()
    {
        foreach (var (dir, trusted) in new[] { (ctx.Paths.ControlDir, true), (ctx.Paths.InboxDir, false) })
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var f in Directory.EnumerateFiles(dir, "*.json").Take(25).ToList())
            {
                if (_locked.TryGetValue(f, out var t) && (DateTime.Now - t).TotalMinutes < 5) continue;
                JsonObject? cmd = null;
                try
                {
                    if (new FileInfo(f).Length > PatternRules.MaxPayload) { ctx.Log.Warn($"Command file '{f}' exceeds 64KB; discarded"); File.Delete(f); continue; }
                    cmd = JsonFile.ReadObject(f);
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { continue; }
                var deleted = false;
                for (var i = 0; i < 3 && !deleted; i++)
                {
                    try { File.Delete(f); deleted = true; _locked.Remove(f); }
                    catch (Exception e) when (e is IOException or UnauthorizedAccessException) { Thread.Sleep(50); }
                }
                if (!deleted) { _locked[f] = DateTime.Now; ctx.Log.Warn($"Could not delete command file '{f}'; locked by another process"); continue; }
                if (cmd is null) continue;
                try { Execute(cmd, trusted); }
                catch (Exception e) { ctx.Log.Error($"Command failed: {e.Message}"); }
            }
        }
        // Half-written requests (a .tmp the tray could not rename) are never read: removed after 2 minutes
        try
        {
            foreach (var t in Directory.Exists(ctx.Paths.InboxDir) ? new DirectoryInfo(ctx.Paths.InboxDir).GetFiles("*.tmp") : [])
                if (t.LastWriteTime < DateTime.Now.AddMinutes(-2)) JsonFile.TryDelete(t.FullName);
        }
        catch (IOException) { }
    }

    public void Execute(JsonObject cmd, bool trusted)
    {
        var action = cmd.Str("action");
        if (!trusted && !PatternRules.InboxActions.Contains(action)) { ctx.Log.Warn($"Ignored '{action}' from inbox (needs admin)"); return; }
        if (action != "batch" && !PatternRules.IsValidOp(cmd)) { ctx.Log.Warn($"Refused invalid '{action}' request"); return; }
        var user = cmd.Str("user").Length > 0 ? cmd.Str("user") : "administrator";
        switch (action)
        {
            case "pause":
            {
                var b = cmd.Str("blade");
                var m = cmd.Int("minutes");
                var until = m > 0 ? DateTime.Now.AddMinutes(m).ToString("s", CultureInfo.InvariantCulture) : Catalog.UntilResumed;
                ctx.State.Set(b + "PausedUntil", until);
                ctx.State.Save();
                if (b is "edr" or "sigma" or "cve") scanner.Stop($"{b} paused");
                var dur = m > 0 ? $"{m}m" : "indefinite";
                ctx.Audit("PAUSE", b, user, $"[DURATION: {dur}] [UNTIL: {until}]", $"Forensic Audit: Rubric '{b}' paused for {dur} by '{user}'. Until: {until}");
                ctx.Event("system", "Medium", $"{Catalog.PauseNames.GetValueOrDefault(b, b)} paused {(m > 0 ? $"for {m} minutes" : "until you resume it")}",
                          detail: $"Forensic Audit: Rubric {b} paused for {dur} by {user} until {until}",
                          extra: new() { ["kind"] = "audit", ["rubric"] = b, ["action"] = "pause", ["user"] = user, ["duration"] = dur, ["until"] = until });
                break;
            }
            case "resume":
            {
                var b = cmd.Str("blade");
                if (ctx.State.PausedUntil(b).Length == 0) return;
                ctx.State.Set(b + "PausedUntil", null);
                ctx.State.Save();
                ctx.Audit("RESUME", b, user, "[DURATION: 0] [UNTIL: NOW]", $"Forensic Audit: Rubric '{b}' resumed by '{user}'");
                ctx.Event("system", "Info", $"{Catalog.PauseNames.GetValueOrDefault(b, b)} resumed", detail: $"Forensic Audit: Rubric {b} resumed by {user}",
                          extra: new() { ["kind"] = "audit", ["rubric"] = b, ["action"] = "resume", ["user"] = user });
                break;
            }
            case "scan-now": scanner.StartManual(); break;
            case "block": Flag(cmd); break;
            case "unblock": Unflag(cmd.Str("id")); break;
            case "batch":
                if (cmd["ops"] is not JsonArray ops || ops.Count > PatternRules.MaxBatch) { ctx.Log.Warn("Refused batch (missing or over the cap)"); return; }
                foreach (var op in ops.OfType<JsonObject>())
                {
                    if (!PatternRules.BatchActions.Contains(op.Str("action"))) continue;
                    if (op.Str("user").Length == 0) op["user"] = user;
                    Execute(op, trusted);
                }
                break;
            case "unban": Unban(Ip.Normalize(cmd.Str("ip"))!); break;
            case "exclude": Exclude(cmd, user); break;
            case "unexclude": Unexclude(cmd.Str("id"), user); break;
            default: ctx.Log.Warn($"Command '{action}' is handled by the control helper, not the engine"); break;
        }
    }

    /// <summary>"Flag as threat": a verdict on record. Detect-only: a program is never stopped or moved. Only an IP ban
    /// is enforced (Wail2Ban, permanent firewall block), unless Wail2Ban is set to report only.</summary>
    private void Flag(JsonObject cmd)
    {
        var blade = cmd.Str("blade");
        var entry = new JsonObject
        {
            ["id"] = Guid.NewGuid().ToString("N"), ["added"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture), ["blade"] = blade,
            ["title"] = cmd.Str("title"), ["image"] = "", ["sha256"] = "", ["ip"] = "", ["enforce"] = false, ["quarantine"] = "", ["note"] = "", ["hits"] = 0,
        };
        switch (blade)
        {
            case "realtime" or "ioc" or "yara":
            {
                var img = cmd.Str("image");
                if (ctx.Blocks.Items.Any(b => Ps.Eq(b.Str("image"), img))) return;
                entry["image"] = img; entry["sha256"] = cmd.Str("sha256");
                entry["note"] = "Flagged as a threat by you. FreeEDR only detects: the program was not stopped or moved. Scan it with Microsoft Defender, which can remove it.";
                break;
            }
            case "sigma":
                if (ctx.Blocks.Items.Any(b => b.Str("blade") == "sigma" && b.Str("title") == entry.Str("title"))) return;
                entry["note"] = "Confirmed as a threat by you.";
                break;
            case "wail2ban":
            {
                var ip = Ip.Normalize(cmd.Str("ip"))!;
                if (w2b.IsSelf(ip) || ctx.Blocks.Items.Any(b => b.Str("ip") == ip)) return;
                if (w2b.Whitelisted(ip) is not null) { ctx.Log.Warn($"Cannot ban {ip}: it is in the trusted list"); return; }
                entry["ip"] = ip;
                if (ctx.Cfg.Wail2Ban.Block)
                {
                    entry["enforce"] = true;
                    Firewall.RemoveBan(ip);
                    try { Firewall.AddBan(ip, "never"); }
                    catch (Exception e) when (e is IOException or ArgumentException) { ctx.Event("wail2ban", "High", $"Failed to block {ip}", detail: e.Message, extra: new() { ["ip"] = ip }); return; }
                    entry["note"] = "Blocked permanently in Windows Firewall by you.";
                    ctx.AppEvent($"Blocked {ip} permanently (by user)", 1000);
                }
                else entry["note"] = "Flagged by you. Wail2Ban is set to report only, so the address is not blocked.";
                w2b.RemoveExpiredBans();
                break;
            }
            default: return;
        }
        ctx.Blocks.Items.Add(entry);
        ctx.Blocks.Save();
        var what = entry.Str("image").Length > 0 ? entry.Str("image") : entry.Str("ip").Length > 0 ? entry.Str("ip") : entry.Str("title");
        var verb = blade == "wail2ban" && entry.Truthy("enforce") ? "Banned" : "Flagged";
        ctx.Log.Audit($"{verb} ({blade}) by user: {what} - {entry.Str("note")}");
        ctx.Event("system", "Info", $"{verb} by you: {(entry.Str("image").Length > 0 ? Ps.Leaf(entry.Str("image")) : what)}", detail: entry.Str("note"), extra: new() { ["kind"] = "verdict" });
    }

    private void Unflag(string id)
    {
        var hit = ctx.Blocks.Items.FirstOrDefault(b => b.Str("id") == id);
        if (hit is null) return;
        var note = "Removed.";
        // Files quarantined by versions before 2026-11 are restored to where they were
        var q = hit.Str("quarantine");
        if (q.Length > 0 && File.Exists(q))
        {
            var dest = hit.Str("image");
            if (File.Exists(dest)) dest += $".restored-{DateTime.Now:yyyyMMddHHmmss}";
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                File.Move(q, dest);
                note = $"Restored from quarantine to {dest}.";
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                ctx.Log.Error($"Restore from quarantine failed: {e.Message}");
                ctx.Event("system", "Medium", $"Could not restore {Ps.Leaf(hit.Str("image"))} from quarantine", detail: e.Message, extra: new() { ["kind"] = "status" });
                return;
            }
        }
        if (hit.Str("blade") == "wail2ban" && hit.Str("ip").Length > 0)
        {
            Firewall.RemoveBan(hit.Str("ip"));
            ctx.AppEvent($"Removed IP {hit.Str("ip")} from firewall rules", 2000);
            w2b.RemoveExpiredBans();
        }
        ctx.Blocks.Items.Remove(hit);
        ctx.Blocks.Save();
        var what = hit.Str("image").Length > 0 ? hit.Str("image") : hit.Str("ip").Length > 0 ? hit.Str("ip") : hit.Str("title");
        ctx.Log.Audit($"Verdict removed ({hit.Str("blade")}) by user: {what} - {note}");
        ctx.Event("system", "Info", $"Verdict removed by you: {(hit.Str("image").Length > 0 ? Ps.Leaf(hit.Str("image")) : what)}", detail: note, extra: new() { ["kind"] = "verdict" });
    }

    private void Unban(string ip)
    {
        foreach (var b in ctx.Blocks.Items.Where(b => b.Str("ip") == ip).ToList()) Unflag(b.Str("id"));
        Firewall.RemoveBan(ip);
        w2b.Forget(ip);
        ctx.Log.Audit($"Unbanned {ip} by user");
        ctx.AppEvent($"Removed IP {ip} from firewall rules", 2000);
        ctx.Event("wail2ban", "Info", $"Unblocked {ip} (by you)", extra: new() { ["ip"] = ip, ["kind"] = "unban" });
        w2b.RemoveExpiredBans();
    }

    private void Exclude(JsonObject c, string user)
    {
        switch (c.Str("blade"))
        {
            case "realtime":
            {
                var anc = c.Str("parent").Length > 0 ? Math.Clamp(c.Int("ancestors"), 1, Catalog.MaxAncestors) : 0;
                var f = new JsonObject
                {
                    ["rule"] = c.Str("rule").Length > 0 ? c.Str("rule") : "*", ["image"] = c.Str("image"), ["parent"] = c.Str("parent"), ["raw"] = c.Str("raw"),
                    ["signer"] = c.Str("signer"), ["parentSigner"] = c.Str("parentSigner"), ["ancestors"] = anc, ["detail"] = c.Str("detail"), ["profile"] = c.Str("profile"),
                };
                if (c.Str("match").Length > 0) f["match"] = c.Str("match");
                if (ctx.Excl.Exists("realtime", f, ["rule", "image", "parent", "signer", "parentSigner", "detail", "match"])) return;
                ctx.Excl.Add("realtime", f, user);
                break;
            }
            case "ioc": ctx.Excl.Add("ioc", new() { ["sha256"] = c.Str("sha256"), ["image"] = c.Str("image") }, user); break;
            case "yara": ctx.Excl.Add("yara", new() { ["image"] = c.Str("image"), ["raw"] = c.Str("raw") }, user); break;
            case "sigma":
            {
                var f = new JsonObject { ["title"] = c.Str("title").Length > 0 ? c.Str("title") : "*", ["parent"] = c.Str("parent"), ["parentSigner"] = c.Str("parentSigner"), ["profile"] = c.Str("profile") };
                if (ctx.Excl.Exists("sigma", f, ["title", "parent", "parentSigner"])) return;
                ctx.Excl.Add("sigma", f, user);
                break;
            }
            case "cve": ctx.Excl.Add("cve", new() { ["cve"] = c.Str("cve"), ["package"] = c.Str("package") }, user); break;
            case "wail2ban":
            {
                var cidr = c.Str("cidr");
                ctx.Excl.Add("wail2ban", new() { ["cidr"] = cidr, ["note"] = c.Str("note") }, user);
                foreach (var b in ctx.Blocks.Items.Where(b => b.Str("ip").Length > 0 && Ip.InCidr(b.Str("ip"), cidr)).ToList()) Unflag(b.Str("id"));
                foreach (var b in w2b.Banned.OfType<JsonObject>().Select(o => o.Str("ip")).Where(ip => Ip.InCidr(ip, cidr)).ToList()) { Firewall.RemoveBan(b); w2b.Forget(b); }
                w2b.RemoveExpiredBans();
                break;
            }
            case "defender":
            {
                var kind = c.Str("kind").Length > 0 ? c.Str("kind") : "asr";
                var (ok, err) = Defender.AddAllow(kind, c.Str("path"));
                if (ok) ctx.Excl.Add("defender", new() { ["kind"] = kind, ["path"] = c.Str("path"), ["note"] = c.Str("note") }, user);
                else ctx.Event("system", "Medium", "Could not add Defender exclusion", detail: $"{c.Str("path")} : {err}", extra: new() { ["kind"] = "status" });
                break;
            }
        }
    }

    private void Unexclude(string id, string user)
    {
        if (ctx.Excl.Find(id) is not { } hit) return;
        if (hit.List == "defender")
        {
            var (ok, err) = Defender.RemoveAllow(hit.Entry.Str("kind"), hit.Entry.Str("path"));
            if (!ok) ctx.Log.Error($"Remove Defender exclusion failed: {err}");
        }
        ctx.Excl.Remove(hit.List, hit.Entry, user);
    }
}
