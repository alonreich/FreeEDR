namespace Edr.Core;

/// <summary>A dashboard tab: three lists (0 needs a decision, 1 blocked/done, 2 allowed), named per section.</summary>
public sealed record SectionInfo(string Key, string Name, string[] Subs, string Block, string Allow, bool Security);

/// <summary>Fixed tables shared by the engine and the dashboard.</summary>
public static class Catalog
{
    public const string UntilResumed = "9999-12-31T00:00:00";

    public static readonly SectionInfo[] Sections =
    [
        new("malware", "Anti-Malware", ["Detected", "Flagged", "Allowed"], "Flag as threat", "Allow", true),
        new("edr", "Real-time", ["Detected", "Flagged", "Allowed"], "Flag as threat", "Allow", true),
        new("sigma", "Event logs", ["Detected", "Confirmed", "Allowed"], "Confirm as threat", "Ignore this rule", true),
        new("cve", "CVE", ["Detected", "Updated", "Ignored"], "Update now", "Ignore", true),
        new("apps", "App Updates", ["Available", "Updated", "Hidden"], "Update now", "Hide", false),
        new("wail2ban", "Wail2Ban", ["Sign-in attempts", "Banned IPs", "Trusted IPs"], "Ban IP", "Trust IP", true),
    ];

    public static SectionInfo Section(string key) => Sections.First(s => s.Key == key);

    public static readonly Dictionary<string, string> BladeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ["edr"] = "EDR (real-time, YARA, IOC, Sigma, CVE)",
        ["malware"] = "Anti-Malware (IOC & YARA)",
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
    public const int MaxAncestors = 3;

    /// <summary>$PauseLabels of the parts that can be paused on their own (shown in the overall status).</summary>
    public static readonly (string Blade, string Label)[] PauseLabels =
        [("realtime", "Real-Time EDR"), ("malware", "Anti-Malware"), ("sigma", "Sigma Event-Log Scan"), ("cve", "CVE Vulnerability Scan")];

    /// <summary>Names of the trusted-app profiles (Profiles.All), for the Allowed lists.</summary>
    public static readonly Dictionary<string, string> ProfileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ["claude-code"] = "Claude Code (Anthropic)", ["openai-codex"] = "ChatGPT / Codex (OpenAI)", ["antigravity"] = "Antigravity (Google AI IDE)",
        ["vcpkg"] = "Visual Studio Build Tools (vcpkg shell)", ["onedrive"] = "Microsoft OneDrive", ["office"] = "Microsoft Office updates (Click-to-Run)",
        ["google-drive"] = "Google Drive", ["razer"] = "Razer (Synapse / Cortex / App Engine)", ["installers"] = "Software installers (one-time RunOnce entries)",
        ["wpbbin"] = "OEM Motherboard Boot Binary (wpbbin.exe)", ["freeedr-build"] = "FreeEDR Project Build Output",
    };

    /// <summary>Real-time rule name -> severity ($RuleSeverity). Unknown rules are Medium, WMI persistence High.</summary>
    public static readonly Dictionary<string, string> RuleSeverity = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Credential dumping tool"] = "Critical", ["LSASS memory dump"] = "Critical", ["Code injected into LSASS"] = "Critical",
        ["LSASS memory read (credential theft)"] = "High", ["Shadow copy or recovery tampering"] = "Critical", ["Defender tampering"] = "High",
        ["Defender exclusion added"] = "High", ["Event log cleared"] = "High", ["Encoded PowerShell command"] = "High",
        ["PowerShell download or in-memory execution"] = "High", ["Office app started a shell"] = "High", ["Winlogon hijack"] = "High",
        ["Debugger hijack (IFEO)"] = "High", ["Unsigned driver loaded"] = "High", ["mshta script execution"] = "High",
        ["certutil download or decode"] = "High", ["regsvr32/rundll32 script abuse"] = "High", ["bitsadmin download"] = "Medium",
        ["Script run from Downloads or Temp"] = "Medium", ["New user or admin group change"] = "High",
        ["Windows script/LOLBin made a network connection"] = "Medium", ["Startup entry added or changed (Run key)"] = "Medium",
        ["File added to a Startup folder"] = "Medium", ["Scheduled task created from command line"] = "Medium", ["Executable launched from Downloads"] = "Low",
        ["Command line imitates FreeEDR's own scripts"] = "High",
    };

    /// <summary>Scope of each pause, shown before pausing and in the audit log.</summary>
    public static readonly Dictionary<string, string> PauseScope = new(StringComparer.OrdinalIgnoreCase)
    {
        ["edr"] = "Pauses all detection: real-time, Anti-Malware, Sigma and CVE scans. Wail2Ban and Microsoft Defender keep running.",
        ["realtime"] = "Pauses real-time Sysmon detection. Scans, Wail2Ban and Defender keep running.",
        ["malware"] = "Pauses malware-hash (IOC) and YARA checks. Real-time detection, Wail2Ban and Defender keep running.",
        ["sigma"] = "Pauses the scheduled and manual Sigma event-log scans. Everything else keeps running.",
        ["cve"] = "Pauses the Python vulnerability (OSV) checks. Everything else keeps running.",
        ["wail2ban"] = "Pauses counting failed sign-ins and new bans. Existing bans stay until they expire.",
    };

    public static readonly Dictionary<string, string> PauseNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ["edr"] = "All detection", ["realtime"] = "Real-time detection", ["malware"] = "Anti-Malware", ["sigma"] = "Event-log scan",
        ["cve"] = "Vulnerability scan", ["wail2ban"] = "Wail2Ban",
    };
}
