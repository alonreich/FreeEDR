using System.Diagnostics;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace Edr.Core.Native;

/// <summary>An inbound block rule of Wail2Ban: "a a a wail2ban block IP: &lt;ip&gt;", description "Expire: &lt;time|never&gt;".</summary>
public sealed record BanRule(string Ip, string Description)
{
    public bool Permanent => Description.Trim().EndsWith("never", StringComparison.OrdinalIgnoreCase);

    public DateTime? Expires
    {
        get
        {
            var m = Ps.Rx(@"^Expire:\s*(.+)$").Match(Description.Trim());
            return m.Success && !Permanent && DateTime.TryParse(m.Groups[1].Value.Trim(), System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var d) ? d : null;
        }
    }
}

/// <summary>
/// Windows Firewall access for Wail2Ban: rules are read from the firewall's own registry store (fast, no COM) and
/// added/removed with netsh (the address is validated before it reaches the command line).
/// </summary>
[SupportedOSPlatform("windows")]
public static class Firewall
{
    private const string RulesKey = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";

    /// <summary>Every rule's fields (Name, Desc, Action, Dir, RA4, ...) from the local store.</summary>
    public static IEnumerable<Dictionary<string, string>> AllRules()
    {
        using var k = Registry.LocalMachine.OpenSubKey(RulesKey);
        if (k is null) yield break;
        foreach (var n in k.GetValueNames())
        {
            if (k.GetValue(n) is not string s) continue;
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["Id"] = n };
            foreach (var part in s.Split('|'))
            {
                var i = part.IndexOf('=');
                if (i > 0) d.TryAdd(part[..i], part[(i + 1)..]);
            }
            yield return d;
        }
    }

    public static List<BanRule> BanRules() =>
        AllRules().Where(r => r.TryGetValue("Name", out var n) && n.StartsWith(EdrPaths.FwRulePrefix + " ", StringComparison.Ordinal))
                  .Select(r => new BanRule(r["Name"][(EdrPaths.FwRulePrefix.Length + 1)..].Trim(), r.GetValueOrDefault("Desc") ?? ""))
                  .GroupBy(b => b.Ip, StringComparer.OrdinalIgnoreCase).Select(g => g.First()).ToList();

    public static bool HasBan(string ip) => BanRules().Any(b => Ps.Eq(b.Ip, ip));

    public static void AddBan(string ip, string expireText)
    {
        var n = Ip.Normalize(ip) ?? throw new ArgumentException("invalid address", nameof(ip));
        if (!Ps.Rx(@"^(never|\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})$").IsMatch(expireText)) throw new ArgumentException("invalid expiry", nameof(expireText));
        var rc = Netsh($"advfirewall firewall add rule name=\"{EdrPaths.FwRulePrefix} {n}\" dir=in action=block protocol=any remoteip={n} profile=any enable=yes description=\"Expire: {expireText}\"");
        if (rc != 0) throw new IOException($"netsh could not add the block rule for {n} (exit {rc})");
    }

    public static bool RemoveBan(string ip)
    {
        var n = Ip.Normalize(ip);
        if (n is null || !HasBan(n)) return false;
        return Netsh($"advfirewall firewall delete rule name=\"{EdrPaths.FwRulePrefix} {n}\"") == 0;
    }

    /// <summary>Removes every Wail2Ban block rule (factory reset, uninstall). Returns how many addresses were unblocked.</summary>
    public static int RemoveAllBans()
    {
        var n = 0;
        foreach (var b in BanRules()) if (RemoveBan(b.Ip)) n++;
        return n;
    }

    public static readonly string[] RdpIpv6Rules = ["Block RDP IPv6 (TCP 3389)", "Block RDP IPv6 (UDP 3389)"];

    public static bool RuleExists(string displayName) => AllRules().Any(r => r.TryGetValue("Name", out var n) && n == displayName);

    public static void AddRdpIpv6Blocks()
    {
        foreach (var (name, proto) in new[] { (RdpIpv6Rules[0], "TCP"), (RdpIpv6Rules[1], "UDP") })
            if (!RuleExists(name)) Netsh($"advfirewall firewall add rule name=\"{name}\" dir=in action=block protocol={proto} localport=3389 remoteip=::/1,8000::/1 profile=any");
    }

    public static void RemoveRdpIpv6Blocks()
    {
        foreach (var name in RdpIpv6Rules) if (RuleExists(name)) Netsh($"advfirewall firewall delete rule name=\"{name}\"");
    }

    private static int Netsh(string args)
    {
        var psi = new ProcessStartInfo(Path.Combine(EdrPaths.System32, "netsh.exe"), args)
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
        };
        using var p = Process.Start(psi)!;
        p.StandardOutput.ReadToEnd();
        p.StandardError.ReadToEnd();
        if (!p.WaitForExit(30_000)) { try { p.Kill(); } catch (InvalidOperationException) { } return -1; }
        return p.ExitCode;
    }
}

/// <summary>Runs Windows PowerShell for the few settings only its cmdlets expose (Defender preferences, firewall rule by id).
/// Values reach the script through environment variables, never through the script text.</summary>
[SupportedOSPlatform("windows")]
public static class PowerShellRunner
{
    public sealed record Result(int ExitCode, string Output, string Error);

    public static Result Run(string script, IDictionary<string, string>? env = null, int timeoutSeconds = 120)
    {
        var psi = new ProcessStartInfo(EdrPaths.WindowsPowerShell)
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = System.Text.Encoding.UTF8,
        };
        foreach (var a in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                                  "[Console]::OutputEncoding = [Text.Encoding]::UTF8; $ErrorActionPreference = 'Stop'; " + script })
            psi.ArgumentList.Add(a);
        psi.Environment.Remove("PSModulePath");   // Windows PowerShell 5.1 must use its own module path
        if (env is not null) foreach (var (k, v) in env) psi.Environment[k] = v;
        using var p = Process.Start(psi)!;
        var outTask = p.StandardOutput.ReadToEndAsync();
        var errTask = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(timeoutSeconds * 1000)) { try { p.Kill(true); } catch (InvalidOperationException) { } return new Result(-1, "", "timeout"); }
        return new Result(p.ExitCode, outTask.Result, errTask.Result);
    }
}
