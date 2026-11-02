namespace Edr.Core;

/// <summary>A dashboard tab: three lists (0 needs a decision, 1 blocked/done, 2 allowed), named per section.</summary>
public sealed record SectionInfo(string Key, string Name, string[] Subs, string Block, string Allow, bool Security);

/// <summary>Fixed tables of EDR-Common.ps1 and EDR-Tray.ps1.</summary>
public static class Catalog
{
    public const string UntilResumed = "9999-12-31T00:00:00";

    public static readonly SectionInfo[] Sections =
    [
        new("malware", "Anti-Malware", ["Detected", "Blocked", "Allowed"], "Quarantine", "Allow", true),
        new("edr", "EDR", ["Detected", "Blocked", "Allowed"], "Block program", "Allow", true),
        new("sigma", "Sigma", ["Detected", "Blocked", "Allowed"], "Confirm as threat", "Allow this rule (ignore it)", true),
        new("cve", "CVE", ["Detected", "Updated", "Ignored"], "Update now", "Ignore", true),
        new("apps", "App Updates", ["Available", "Updated", "Hidden"], "Update now", "Hide", false),
        new("wail2ban", "Wail2Ban", ["Detected", "Blocked", "Allowed"], "Block IP", "Always allow", true),
    ];

    public static SectionInfo Section(string key) => Sections.First(s => s.Key == key);

    public static readonly Dictionary<string, string> BladeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ["edr"] = "EDR (real-time, YARA, IOC, Sigma, CVE)",
        ["realtime"] = "Real-time (Sysmon)",
        ["ioc"] = "Malware hash (IOC)",
        ["yara"] = "YARA file scan",
        ["sigma"] = "Event-log scan (Sigma)",
        ["defender"] = "Microsoft Defender",
        ["wail2ban"] = "Wail2Ban (password guessing)",
        ["cve"] = "Vulnerability (CVE)",
        ["patch"] = "App updates (winget)",
        ["system"] = "EDR health",
    };

    public static readonly Dictionary<string, string> BladeSection = new(StringComparer.OrdinalIgnoreCase)
    {
        ["ioc"] = "malware", ["yara"] = "malware", ["defender"] = "malware", ["realtime"] = "edr",
        ["sigma"] = "sigma", ["cve"] = "cve", ["patch"] = "apps", ["wail2ban"] = "wail2ban",
    };

    /// <summary>exclusions.json lists in Get-EmptyExclusions order, and the tab each one is shown in.</summary>
    public static readonly (string List, string Section)[] ExclusionLists =
    [
        ("realtimePath", "edr"), ("realtime", "edr"), ("ioc", "malware"), ("yara", "malware"),
        ("sigma", "sigma"), ("wail2ban", "wail2ban"), ("cve", "cve"), ("defender", "malware"),
    ];

    /// <summary>$SeverityRank; unknown severities have no rank (PowerShell $null).</summary>
    public static int? Rank(string? severity) => (severity ?? "").ToLowerInvariant() switch
    {
        "critical" => 4, "high" => 3, "medium" => 2, "low" => 1, "info" => 0, _ => null,
    };

    /// <summary>Alerts only the user can judge: pinned on top of Detected with "Was this you?"</summary>
    public const string ConfirmPattern = "Successful login as|External Remote .* from Public IP|Log File Cleared|^Log Cleared|Event log cleared|New user or admin group change|Defender tampering|Defender exclusion added";

    /// <summary>Hayabusa rules that only repeat Microsoft Defender's own detections</summary>
    public const string DefenderSigmaTitles = "^(Antivirus - |Defender Alert)";

    public static readonly string[] UnsafeSigners = ["Microsoft Windows", "Microsoft Windows Publisher", "Microsoft Corporation"];
    public const string ClaudeSigner = "Anthropic, PBC";
    public static readonly string[] ClaudeRealtimeRules = ["Encoded PowerShell command", "PowerShell download or in-memory execution"];
    public static readonly string[] ClaudeSigmaTitles = ["PowerShell Base64 Encoded FromBase64String Cmdlet", "Script Interpreter Execution From Suspicious Folder"];
    public const int MaxAncestors = 3;

    /// <summary>$PauseLabels of the parts that can be paused on their own (shown in the overall status).</summary>
    public static readonly (string Blade, string Label)[] PauseLabels =
        [("realtime", "Real-Time EDR"), ("malware", "Anti-Malware"), ("sigma", "Sigma Event-Log Scan"), ("cve", "CVE Vulnerability Scan")];

    /// <summary>Names of the trusted-app profiles ($AllowProfiles in EDR-Common.ps1), for the Allowed lists.</summary>
    public static readonly Dictionary<string, string> ProfileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ["claude-code"] = "Claude Code (Anthropic)", ["openai-codex"] = "ChatGPT / Codex (OpenAI)", ["antigravity"] = "Antigravity (Google AI IDE)",
        ["vcpkg"] = "Visual Studio Build Tools (vcpkg shell)", ["onedrive"] = "Microsoft OneDrive", ["office"] = "Microsoft Office updates (Click-to-Run)",
        ["google-drive"] = "Google Drive", ["razer"] = "Razer (Synapse / Cortex / App Engine)", ["installers"] = "Software installers (one-time RunOnce entries)",
    };
}
