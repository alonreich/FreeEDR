using System.Globalization;
using System.Text.Json.Nodes;
using Edr.Core;
using Edr.Core.Native;

namespace Edr.Engine;

/// <summary>
/// Runs the requests from the drop folders (control\ admin-only, from the elevated helper; inbox\ any account: only
/// resume and scan-now) and from the pipe. The folders are read by <see cref="CommandIntake"/>'s worker threads (a
/// file is removed before it runs); this class only executes, on the engine's main loop.
/// <see cref="Execute"/> is the single validation gate (the tray's checks are advisory).
/// </summary>
internal sealed class Commands(Context ctx, Wail2Ban w2b, Scanner scanner)
{
    /// <summary>Runs what the intake workers queued (main loop). At most 50 per call so the event path is never starved.</summary>
    public void RunQueued(CommandIntake intake)
    {
        for (var i = 0; i < 50 && intake.TryDequeue(out var r); i++)
        {
            // control\: the elevated helper wrote its own account name; inbox\ cannot prove who wrote the file
            if (!r.Trusted) r.Cmd["user"] = "a local account (inbox)";
            try { Execute(r.Cmd, r.Trusted); }
            catch (Exception e) { ctx.Log.Error($"Command failed: {e.Message}"); }
        }
    }

    /// <summary>Validates and runs one request (from control\ / inbox\ or the pipe). False = refused (not allowed for this
    /// caller, or not a valid request); true = accepted (a no-op such as resuming what is not paused counts as done).</summary>
    public bool Execute(JsonObject cmd, bool trusted)
    {
        var action = cmd.Str("action");
        if (!trusted && !PatternRules.InboxActions.Contains(action)) { ctx.Log.Warn($"Ignored '{action}' from an unelevated caller (needs admin)"); return false; }
        if (action != "batch" && !PatternRules.IsValidOp(cmd)) { ctx.Log.Warn($"Refused invalid '{action}' request"); return false; }
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
                if (ctx.State.PausedUntil(b).Length == 0) return true;
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
                if (cmd["ops"] is not JsonArray ops || ops.Count > PatternRules.MaxBatch) { ctx.Log.Warn("Refused batch (missing or over the cap)"); return false; }
                var all = true;
                foreach (var op in ops.OfType<JsonObject>())
                {
                    if (!PatternRules.BatchActions.Contains(op.Str("action"))) continue;
                    op["user"] = user;   // every step is recorded under the batch's (verified) caller
                    all &= Execute(op, trusted);
                }
                return all;
            case "unban": Unban(Ip.Normalize(cmd.Str("ip"))!); break;
            case "exclude": Exclude(cmd, user); break;
            case "unexclude": Unexclude(cmd.Str("id"), user); break;
            case "note":   // an event from FreeEDR's elevated helper or installer: the engine is the only writer of events.jsonl
            {
                var extra = new JsonObject { ["kind"] = cmd.Str("kind"), ["by"] = user };
                if (cmd.Str("tool").Length > 0) extra["tool"] = cmd.Str("tool");
                if (cmd.ContainsKey("ok")) extra["ok"] = cmd.Truthy("ok");
                ctx.Event("system", cmd.Str("severity"), cmd.Str("title"), cmd.Str("process"), cmd.Str("detail"), extra);
                break;
            }
            default: ctx.Log.Warn($"Command '{action}' is handled by the control helper, not the engine"); return false;
        }
        return true;
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
