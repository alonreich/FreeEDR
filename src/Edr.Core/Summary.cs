namespace Edr.Core;

/// <summary>What happened in a period (the weekly summary card and toast, and the learning-week wrap-up).</summary>
public sealed record PeriodSummary(DateTime From, DateTime To, int Alerts, int Critical, int High, int SignInFailures, int Bans, int InternetLogins,
                                   int ScansOk, int ScansFailed, IReadOnlyList<(string Title, int Count)> Noisiest, IReadOnlyDictionary<string, int> ByPart)
{
    public string OneLine =>
        Alerts == 0 && Bans == 0 && SignInFailures == 0
            ? "A quiet week: nothing was detected."
            : $"{Alerts} alert{(Alerts == 1 ? "" : "s")} ({Critical} critical, {High} high), {Bans} ban{(Bans == 1 ? "" : "s")}, {SignInFailures} failed sign-in{(SignInFailures == 1 ? "" : "s")}.";

    public static PeriodSummary Compute(IEnumerable<Rec> events, DateTime from, DateTime to)
    {
        int alerts = 0, crit = 0, high = 0, fails = 0, bans = 0, logins = 0, scanOk = 0, scanBad = 0;
        var titles = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var parts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in events)
        {
            if (Ps.ToDate(e.S("time")) is not { } t || t < from || t > to) continue;
            var blade = e.S("blade");
            if (Ps.Eq(blade, "system"))
            {
                if (Ps.Eq(e.S("kind"), "scan")) { if (e.T("ok")) scanOk++; else scanBad++; }
                continue;
            }
            if (Ps.Eq(blade, "wail2ban"))
            {
                if (Ps.Eq(e.S("kind"), "fail")) fails++;
                else if (Ps.Eq(e.S("kind"), "login")) logins++;
                else if (e.T("expires") || e.T("threshold")) bans++;
                continue;
            }
            if (!Catalog.BladeSection.TryGetValue(blade, out var sec) || sec is "apps") continue;
            alerts++;
            if (Ps.Eq(e.S("severity"), "Critical")) crit++;
            else if (Ps.Eq(e.S("severity"), "High")) high++;
            titles[e.S("title")] = titles.GetValueOrDefault(e.S("title")) + 1;
            parts[sec] = parts.GetValueOrDefault(sec) + 1;
        }
        var noisy = titles.OrderByDescending(kv => kv.Value).Take(3).Select(kv => (kv.Key, kv.Value)).ToList();
        return new PeriodSummary(from, to, alerts, crit, high, fails, bans, logins, scanOk, scanBad, noisy, parts);
    }
}
