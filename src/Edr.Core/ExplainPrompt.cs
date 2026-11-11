using System.Text;

namespace Edr.Core;

public static class ExplainPrompt
{
    public const string UserInstruction =
        "Please in a short condensed and oversimplified way explain to the end user:\n" +
        "1. What the issue caught/detect is actually is? What it means and what are the risks/implications of such event/incident?\n" +
        "2. What normally causes this, and what actually triggered it right now?\n" +
        "3. What are the chances of such being a legitimate operation and should I exclude it and if so then why? Provide precentage or ask me oversimplified questions in order to clarify or not whether or not this is actually a legitimae false positive which should be exclude or not. provide raw cmd as admin or powershell commands if needed but make sure to highlight in which termanl cmd or powershell shall I run these. Explain to the end user that it needs to paste the output back clearly so no confusion there.\n" +
        "4. Explain to me like a 10 Years old what exactly happened here, what was the flow of the incident, what touched what, and why.\n" +
        "for all of these keep the explanation short short short and oversimplified. if end user asks on something only then elaborate on the topic.";

    public static string Build(Rec e, DateTimeOffset now, IReadOnlyList<Rec>? related = null)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== SYSTEM & FREEEDR CONTEXT ===");
        sb.AppendLine("Application: FreeEDR (Free single-PC EDR + Wail2Ban for Windows)");
        sb.AppendLine("Detection Model: Detect-only (FreeEDR detects, explains and logs; it never stops, deletes or quarantines files outside of Wail2Ban firewall bans).");
        sb.AppendLine($"Machine Local Time: {now:yyyy-MM-dd HH:mm:ss zzz} (UTC offset: {now:zzz})");
        sb.AppendLine();

        sb.AppendLine("=== DETECTED INCIDENT TELEMETRY ===");
        sb.AppendLine($"Blade (Module): {e.S("blade")} ({Catalog.BladeNames.GetValueOrDefault(e.S("blade"), e.S("blade"))})");
        sb.AppendLine($"Alert Title: {e.S("title")}");
        if (e.T("rule") && e.S("rule") != e.S("title")) sb.AppendLine($"Rule Name: {e.S("rule")}");
        sb.AppendLine($"Severity: {e.S("severity")}");
        sb.AppendLine($"Event Logged Time: {e.S("time")}");
        if (e.T("eventTime")) sb.AppendLine($"Original Event Time: {e.S("eventTime")}");

        var sigma = Ps.Eq(e.S("blade"), "sigma");
        var prog = sigma ? SigmaProcess.Of(e).Image : e.S("process");
        var par = ActionBuilder.ParentOf(e);
        if (prog.Length > 0) sb.AppendLine($"Target / Process: {prog}");
        if (par.Length > 0) sb.AppendLine($"Started By (Parent): {par}");
        var anc = e.Strings("ancestors");
        if (anc.Count > 0) sb.AppendLine($"Process Ancestor Chain: {string.Join(" -> ", anc)}");
        if (e.T("user")) sb.AppendLine($"User Account: {e.S("user")}");
        if (e.T("ip")) sb.AppendLine($"Network Address: {e.S("ip")} ({Ip.NetLabel(e.S("ip"))})");
        if (e.T("sha256")) sb.AppendLine($"File SHA256: {e.S("sha256")}");
        if (e.T("threat")) sb.AppendLine($"Threat: {e.S("threat")}");
        if (e.T("sysmonId")) sb.AppendLine($"Sysmon Event ID: {e.S("sysmonId")}");
        if (e.T("eventId")) sb.AppendLine($"Windows Event ID: {e.S("eventId")}");
        if (e.T("detail")) sb.AppendLine($"Command / Telemetry Details:\n{e.S("detail")}");
        sb.AppendLine();

        if (related is { Count: > 0 })
        {
            sb.AppendLine("=== RECENT SURROUNDING / RELATED LOGS ===");
            foreach (var r in related)
            {
                var rprog = Ps.Eq(r.S("blade"), "sigma") ? SigmaProcess.Of(r).Image : r.S("process");
                var detail = r.S("detail");
                if (detail.Length == 0 && r.T("ip")) detail = $"IP: {r.S("ip")}";
                sb.AppendLine($"[{r.S("time")}] [{r.S("blade")}] {r.S("title")}{(rprog.Length > 0 ? $" | Process: {rprog}" : "")}{(detail.Length > 0 ? $" | Detail: {ModelBuilder.Short(detail, 160)}" : "")}");
            }
            sb.AppendLine();
        }

        sb.AppendLine("=== USER QUESTION & INSTRUCTIONS ===");
        sb.AppendLine(UserInstruction);

        return sb.ToString();
    }
}
