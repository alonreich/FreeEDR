using System.Globalization;
using System.Net.NetworkInformation;
using System.Text.Json.Nodes;
using Edr.Core;
using Edr.Core.Native;

namespace Edr.Engine;

internal sealed class Wail2Ban(Context ctx)
{
    private sealed record Attempt(DateTime Time, string Source);
    private sealed class Strike { public int Count; public double Epoch; }

    private readonly Dictionary<string, List<Attempt>> _attempts = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<string> _order = new();
    private readonly Dictionary<string, Strike> _strikes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _loginSeen = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _selfIps = new(StringComparer.OrdinalIgnoreCase);
    private bool _strikesDirty;
    private DateTime _lastStrikesSave = DateTime.Now;
    private bool _capWarned;

    public JsonArray Banned { get; private set; } = [];
    public int TrackedIps => _attempts.Count;

    private static double Epoch() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0;

    public void UpdateSelfIps()
    {
        _selfIps.Clear();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                foreach (var a in ni.GetIPProperties().UnicastAddresses)
                    if (Ip.Normalize(a.Address.ToString()) is { } n) _selfIps.Add(n);
        }
        catch (NetworkInformationException e) { ctx.Log.Warn($"Could not read local IPs: {e.Message}"); }
    }

    public bool IsSelf(string ip) => _selfIps.Contains(ip);

    public string? Whitelisted(string ip) => ctx.Excl["wail2ban"].FirstOrDefault(w => Ip.InCidr(ip, w.Str("cidr")))?.Str("cidr");

    public void ReadStrikes()
    {
        _strikes.Clear();
        var file = File.Exists(ctx.Paths.StrikesFile) ? ctx.Paths.StrikesFile : File.Exists(ctx.Paths.StrikesFile + ".bak") ? ctx.Paths.StrikesFile + ".bak" : null;
        if (file is null) return;
        try
        {
            foreach (var line in File.ReadAllLines(file))
            {
                var p = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (p.Length < 2 || !int.TryParse(p[1], out var c)) continue;
                var ep = p.Length >= 3 && double.TryParse(p[2], NumberStyles.Float, CultureInfo.InvariantCulture, out var e) ? e : Epoch();
                _strikes[p[0]] = new Strike { Count = c, Epoch = ep };
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { ctx.Log.Warn($"Failed to read strikes from {file}: {e.Message}"); }
    }

    public void SaveStrikes(bool force = false)
    {
        _strikesDirty = true;
        if (!force && (DateTime.Now - _lastStrikesSave).TotalSeconds < 30) return;
        var text = string.Concat(_strikes.Select(kv => $"{kv.Key} {kv.Value.Count} {kv.Value.Epoch.ToString(CultureInfo.InvariantCulture)}\r\n"));
        try { JsonFile.WriteTextAtomic(ctx.Paths.StrikesFile, text); _strikesDirty = false; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { ctx.Log.Error($"Save-Strikes failed: {e.Message}"); }
        _lastStrikesSave = DateTime.Now;
    }

    public int StrikesOf(string ip) => _strikes.TryGetValue(ip, out var s) ? s.Count : 0;

    public (double Seconds, int Strike) BanDuration(string ip)
    {
        var now = Epoch();
        var count = 0;
        if (_strikes.TryGetValue(ip, out var s))
        {
            count = s.Count;
            var decay = (int)Math.Floor((now - s.Epoch) / 86400);
            if (decay > 0) count = Math.Max(0, count - decay);
        }
        count++;
        _strikes[ip] = new Strike { Count = count, Epoch = now };
        SaveStrikes();
        var cap = Ip.IsPrivate(ip) ? ctx.Cfg.Wail2Ban.MaxBanPrivateSec : ctx.Cfg.Wail2Ban.MaxBanPublicSec;
        return (Math.Min(Math.Pow(5, count) * 60, cap), count);
    }

    public void AddFailure(string rawIp, string source, DateTime when, bool replay)
    {
        if (ctx.State.IsPaused("wail2ban")) return;
        var ip = Ip.Normalize(rawIp);
        if (ip is null || ip is "0.0.0.0" or "255.255.255.255" or "::" || _selfIps.Contains(ip) || Whitelisted(ip) is not null) return;
        if (replay && _strikes.TryGetValue(ip, out var st) && when <= DateTimeOffset.FromUnixTimeMilliseconds((long)(st.Epoch * 1000)).LocalDateTime) return;

        var window = ctx.Cfg.Wail2Ban.WindowSeconds;
        var cutoff = DateTime.Now.AddSeconds(-window);
        if (_attempts.TryGetValue(ip, out var list)) list.RemoveAll(a => a.Time < cutoff);
        else
        {
            if (_attempts.Count >= ctx.Cfg.Wail2Ban.MaxTrackedIps)
            {
                while (_order.Count > 0)
                {
                    var oldest = _order.Dequeue();
                    if (!_attempts.Remove(oldest)) continue;
                    if (!_capWarned) { ctx.Log.Warn($"Wail2Ban tracked IP cap ({ctx.Cfg.Wail2Ban.MaxTrackedIps}) reached; evicting oldest IPs"); _capWarned = true; }
                    break;
                }
            }
            _attempts[ip] = list = [];
            _order.Enqueue(ip);
        }
        if (list.Any(a => Math.Abs((a.Time - when).TotalSeconds) <= 3)) return;
        list.Add(new Attempt(when, source));
        var limit = ctx.Cfg.Wail2Ban.FailCount;
        if (list.Count >= limit)
        {
            Ban(ip, list.Count);
            _attempts.Remove(ip);
        }
        else if (!replay)
            ctx.Event("wail2ban", "Low", $"Failed network logon from {ip}", detail: $"Failure {list.Count} of {limit} within {window / 60} minutes (source: {source}).",
                      extra: new() { ["ip"] = ip, ["kind"] = "fail", ["source"] = source });
    }

    private void Ban(string ip, int count)
    {
        if (Whitelisted(ip) is { } why) { ctx.Log.Warn($"{ip} reached {count} failed logons but is whitelisted ({why})"); return; }
        var scope = Ip.IsPrivate(ip) ? "private/LAN address" : "public internet address";
        if (!ctx.Cfg.Wail2Ban.Block)
        {
            ctx.Log.Audit($"Password guessing from {ip} ({count} failed logons) - report only, not blocked");
            ctx.Event("wail2ban", "Medium", $"Password guessing from {ip} ({count} failed logons)",
                      detail: $"Wail2Ban is set to report only, so the address was not blocked. Source is a {scope}.",
                      extra: new() { ["ip"] = ip, ["kind"] = "guess", ["threshold"] = true });
            return;
        }
        if (Firewall.HasBan(ip)) { ctx.Log.Warn($"{ip} already blocked"); return; }
        var (seconds, strike) = BanDuration(ip);
        var expire = DateTime.Now.AddSeconds(seconds).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
        try
        {
            Firewall.AddBan(ip, expire);
            var msg = $"Blocked {ip} until {expire} ({count} failed logons, strike {strike})";
            ctx.Log.Audit(msg);
            ctx.AppEvent(msg, 1000);
            ctx.Event("wail2ban", "Medium", $"Blocked {ip} after {count} failed logons", detail: $"Blocked for {Format.Duration(seconds)} (strike {strike}), until {expire}. Source is a {scope}.",
                      extra: new() { ["ip"] = ip, ["expires"] = expire, ["strike"] = strike, ["threshold"] = true });
        }
        catch (Exception e) when (e is IOException or ArgumentException or System.ComponentModel.Win32Exception)
        {
            var msg = $"Could not add firewall block for {ip}: {e.Message}";
            ctx.Log.Error(msg);
            ctx.AppEvent(msg, 1001, 1);
            ctx.Event("wail2ban", "High", $"Failed to block {ip}", detail: msg, extra: new() { ["ip"] = ip });
        }
    }

    public void LogonSuccess(EventRecord r)
    {
        if (ctx.State.IsPaused("wail2ban")) return;
        var ip = IpFrom(r, fallback: false);
        if (ip is null || _selfIps.Contains(ip) || Ip.IsPrivate(ip) || Whitelisted(ip) is not null) return;
        var user = $"{r["TargetDomainName"]}\\{r["TargetUserName"]}".Trim('\\');
        var key = $"{ip}|{user}";
        if (_loginSeen.TryGetValue(key, out var seen) && (DateTime.Now - seen).TotalMinutes < 30) return;
        _loginSeen[key] = DateTime.Now;
        var how = r["LogonType"] == "10" ? "Remote Desktop" : "network logon (file sharing, or Remote Desktop with NLA)";
        var proc = r["ProcessName"] is { Length: > 0 } pn && pn != "-" ? pn : "";
        ctx.Log.Audit($"Successful {how} as {user} from public IP {ip}");
        ctx.Event("wail2ban", "High", $"Successful login as {user} from {ip} (public internet)", proc,
                  $"{how}. Workstation: {r["WorkstationName"]}. Authentication: {r["AuthenticationPackageName"]}.",
                  new() { ["ip"] = ip, ["kind"] = "login", ["user"] = user, ["logonType"] = r["LogonType"] });
    }

    public static string? IpFrom(EventRecord r, bool fallback = true)
    {
        foreach (var k in new[] { "IpAddress", "IPString", "ClientIP", "ClientAddress", "Address" })
            if (Ip.Normalize(r[k]) is { } n) return n;
        if (!fallback) return null;
        foreach (var v in r.Data.Values)
        {
            var m = Ps.Rx(@"(\d{1,3}(\.\d{1,3}){3})").Match(v);
            if (m.Success && Ip.Normalize(m.Groups[1].Value) is { } n) return n;
        }
        return null;
    }

    public void SyncRecentFailures()
    {
        foreach (var r in EventSubscription.Query("Security", "(EventID=4625)", TimeSpan.FromSeconds(ctx.Cfg.Wail2Ban.WindowSeconds)))
            if (IpFrom(r, fallback: false) is { } ip) AddFailure(ip, "Security", r.Time, replay: true);
    }

    public void Housekeeping()
    {
        var cutoff = DateTime.Now.AddSeconds(-ctx.Cfg.Wail2Ban.WindowSeconds);
        foreach (var k in _attempts.Keys.ToList())
        {
            _attempts[k].RemoveAll(a => a.Time < cutoff);
            if (_attempts[k].Count == 0) _attempts.Remove(k);
        }
        if (_attempts.Count < ctx.Cfg.Wail2Ban.MaxTrackedIps) _capWarned = false;
        if (_order.Count > _attempts.Count * 2 + 1000)
        {
            var keep = _order.Where(_attempts.ContainsKey).ToList();
            _order.Clear();
            foreach (var k in keep) _order.Enqueue(k);
        }
        var now = Epoch();
        foreach (var (k, s) in _strikes.ToList())
        {
            var decay = (int)Math.Floor((now - s.Epoch) / 86400);
            var decayed = decay > 0 ? Math.Max(0, s.Count - decay) : s.Count;
            if (decayed == 0 && now - s.Epoch >= 604_800) { _strikes.Remove(k); _strikesDirty = true; }
        }
        foreach (var (k, t) in _loginSeen.ToList()) if ((DateTime.Now - t).TotalMinutes >= 30) _loginSeen.Remove(k);
        if (_strikesDirty) SaveStrikes(force: true);
    }

    public void RemoveExpiredBans()
    {
        var list = new JsonArray();
        try
        {
            foreach (var b in Firewall.BanRules())
            {
                if (b.Expires is { } exp && exp < DateTime.Now)
                {
                    if (Firewall.RemoveBan(b.Ip)) { ctx.Log.Audit($"Ban expired, unblocked {b.Ip}"); ctx.AppEvent($"Removed IP {b.Ip} from firewall rules", 2000); }
                    continue;
                }
                list.Add((JsonNode)new JsonObject
                {
                    ["ip"] = b.Ip,
                    ["expires"] = b.Permanent ? "Permanent" : b.Expires?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "",
                    ["strikes"] = StrikesOf(b.Ip), ["private"] = Ip.IsPrivate(b.Ip), ["permanent"] = b.Permanent,
                });
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException) { ctx.Log.Error($"Expired-ban cleanup failed: {e.Message}"); }
        Banned = list;
    }

    public void RepairPermanentBans()
    {
        if (!ctx.Cfg.Wail2Ban.Block) return;
        foreach (var b in ctx.Blocks.Items.Where(b => b.Str("blade") == "wail2ban" && b.Str("ip").Length > 0))
        {
            if (Firewall.HasBan(b.Str("ip"))) continue;
            try { Firewall.AddBan(b.Str("ip"), "never"); ctx.Log.Audit($"Re-applied permanent block for {b.Str("ip")}"); }
            catch (Exception e) when (e is IOException or ArgumentException) { ctx.Log.Warn($"Could not re-apply the block for {b.Str("ip")}: {e.Message}"); }
        }
    }

    public void ApplyRdpIpv6Setting()
    {
        try
        {
            if (ctx.Cfg.Wail2Ban.Block && ctx.Cfg.Wail2Ban.BlockRdpIpv6) Firewall.AddRdpIpv6Blocks();
            else Firewall.RemoveRdpIpv6Blocks();
        }
        catch (Exception e) when (e is IOException or System.ComponentModel.Win32Exception) { ctx.Log.Error($"IPv6 RDP block rules: {e.Message}"); }
    }

    public void Forget(string ip)
    {
        _strikes.Remove(ip);
        _attempts.Remove(ip);
        SaveStrikes(force: true);
    }
}

internal static class Format
{
    public static string Duration(double seconds)
    {
        var t = TimeSpan.FromSeconds(seconds);
        if (t.TotalDays >= 1) return t.TotalDays.ToString("0.#", CultureInfo.InvariantCulture) + " days";
        if (t.TotalHours >= 1) return t.TotalHours.ToString("0.#", CultureInfo.InvariantCulture) + " hours";
        return t.TotalMinutes.ToString("0", CultureInfo.InvariantCulture) + " minutes";
    }
}
