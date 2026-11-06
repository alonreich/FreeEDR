using System.Runtime.Versioning;
using System.Text.Json.Nodes;
using Edr.Core.Native;

namespace Edr.Core;

/// <summary>
/// Microsoft Defender settings FreeEDR manages. FreeEDR never makes Defender block more: attack-surface-reduction
/// rules and Controlled folder access run in audit mode (reported, never blocked), and a setting that was stronger
/// before the first install is never lowered. With defenderMode = "untouched" nothing is changed at all.
/// </summary>
[SupportedOSPlatform("windows")]
public static class Defender
{
    public static readonly string[] AsrRules =
    [
        "56a863a9-875e-4185-98a7-b882c64b5ce5", "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "5beb7efe-fd9a-4556-801d-275e5ffc04cc",
        "d3e037e1-3eb8-44c8-a917-57927947596d", "3b576869-a4ec-4529-8536-b80a7769e899", "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
        "26190899-1602-49e8-8b27-eb1d0a1ce869", "e6db77e5-3df2-4cf1-b95a-636979351e5b", "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",
        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", "c1db55ab-c21a-4637-bb3f-a12568109d35",
        "01443614-cd74-433a-b99e-2ecdc07bfc25", "d1e49aac-8f56-4280-b9ba-993a6d77406c",
    ];

    /// <summary>Audit-only by design: they would report every new or self-built program, so their audit events are not listed.</summary>
    public static readonly string[] AlwaysAudit = ["01443614-cd74-433a-b99e-2ecdc07bfc25", "d1e49aac-8f56-4280-b9ba-993a6d77406c"];

    public static readonly Dictionary<string, string> AsrNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ["56a863a9-875e-4185-98a7-b882c64b5ce5"] = "Block abuse of exploited vulnerable signed drivers",
        ["7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"] = "Block Adobe Reader from creating child processes",
        ["d4f940ab-401b-4efc-aadc-ad5f3c50688a"] = "Block Office apps from creating child processes",
        ["9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"] = "Block credential stealing from LSASS",
        ["be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"] = "Block executable content from email",
        ["01443614-cd74-433a-b99e-2ecdc07bfc25"] = "Block untrusted executables (prevalence/age)",
        ["5beb7efe-fd9a-4556-801d-275e5ffc04cc"] = "Block obfuscated scripts",
        ["d3e037e1-3eb8-44c8-a917-57927947596d"] = "Block JS/VBS launching downloaded executables",
        ["3b576869-a4ec-4529-8536-b80a7769e899"] = "Block Office apps creating executable content",
        ["75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"] = "Block Office apps injecting into other processes",
        ["26190899-1602-49e8-8b27-eb1d0a1ce869"] = "Block Office communication apps creating child processes",
        ["e6db77e5-3df2-4cf1-b95a-636979351e5b"] = "Block persistence through WMI event subscription",
        ["d1e49aac-8f56-4280-b9ba-993a6d77406c"] = "Block process creation from PSExec/WMI",
        ["b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"] = "Block untrusted/unsigned processes from USB",
        ["92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"] = "Block Win32 API calls from Office macros",
        ["c1db55ab-c21a-4637-bb3f-a12568109d35"] = "Advanced protection against ransomware",
    };

    private static readonly Dictionary<int, string> AsrActionName = new() { [0] = "Disabled", [1] = "Enabled", [2] = "AuditMode", [6] = "Warn" };
    private static readonly Dictionary<int, int> AsrRank = new() { [0] = 0, [2] = 1, [6] = 2, [1] = 3 };
    private static readonly Dictionary<int, string> CfaName = new() { [0] = "Disabled", [1] = "Enabled", [2] = "AuditMode", [3] = "BlockDiskModificationOnly", [4] = "AuditDiskModificationOnly" };
    private static readonly Dictionary<int, int> CfaRank = new() { [0] = 0, [2] = 1, [4] = 1, [3] = 2, [1] = 3 };

    /// <summary>Games allowed through Controlled folder access (Epic / Fortnite / Easy Anti-Cheat).</summary>
    public static IEnumerable<string> GameExes()
    {
        var pf = EdrPaths.ProgramFiles;
        var pf86 = EdrPaths.ProgramFilesX86;
        return new[] { $@"{pf}\Epic Games\*\*\Binaries\Win64\*.exe", $@"{pf86}\Epic Games\Launcher\Portal\Binaries\Win64\*.exe", $@"{pf86}\EasyAntiCheat_EOS\*.exe" }
            .SelectMany(PathGlob.Expand).Where(File.Exists);
    }

    /// <summary>Current preferences: asr [{id, action}], cfa, cfaApps, asrExclusions, threatIds. Null when Defender cannot be read.</summary>
    public static JsonObject? ReadPreferences()
    {
        var r = PowerShellRunner.Run("""
            $p = Get-MpPreference
            $ids = @($p.AttackSurfaceReductionRules_Ids); $acts = @($p.AttackSurfaceReductionRules_Actions)
            $asr = for ($i = 0; $i -lt $ids.Count; $i++) { if ($ids[$i]) { [pscustomobject]@{ id = ([string]$ids[$i]).ToLower(); action = [int]$acts[$i] } } }
            [pscustomobject]@{ asr = @($asr); cfa = [int]$p.EnableControlledFolderAccess
              cfaApps = @($p.ControlledFolderAccessAllowedApplications | Where-Object { $_ })
              asrExclusions = @($p.AttackSurfaceReductionOnlyExclusions | Where-Object { $_ })
              threatIds = @($p.ThreatIDDefaultAction_Ids | Where-Object { $_ } | ForEach-Object { [string]$_ }) } | ConvertTo-Json -Depth 4 -Compress
            """);
        return r.ExitCode == 0 ? JsonFile.Parse(r.Output.Trim()) as JsonObject : null;
    }

    /// <summary>Status for the dashboard (status.json "defender").</summary>
    public static JsonObject? Status()
    {
        var r = PowerShellRunner.Run("""
            $s = Get-MpComputerStatus; $p = Get-MpPreference
            $a = @($p.AttackSurfaceReductionRules_Actions)
            [pscustomobject]@{ realtime = [bool]$s.RealTimeProtectionEnabled; tamper = [bool]$s.IsTamperProtected
              signatureAgeDays = [int]$s.AntivirusSignatureAge
              asrBlockRules = @($a | Where-Object { $_ -eq 1 }).Count; asrAuditRules = @($a | Where-Object { $_ -eq 2 }).Count
              controlledFolders = switch ([int]$p.EnableControlledFolderAccess) { 1 { 'On' } 2 { 'Audit' } default { 'Off' } } } | ConvertTo-Json -Compress
            """, timeoutSeconds: 60);
        return r.ExitCode == 0 ? JsonFile.Parse(r.Output.Trim()) as JsonObject : null;
    }

    /// <summary>ASR rules + Controlled folder access in audit mode, never below what <paramref name="baseline"/> recorded.</summary>
    public static List<string> ApplyAudit(JsonObject? baseline, IEnumerable<string> gameExes)
    {
        var notes = new List<string>();
        var cur = ReadPreferences();
        if (cur is null) { notes.Add("WARN Defender settings cannot be read"); return notes; }
        var have = cur.Objects("asr").ToDictionary(a => a.Str("id"), a => a.Int("action"), StringComparer.OrdinalIgnoreCase);
        var known = baseline?.Truthy("known") == true;
        var baseAsr = known ? baseline!.Objects("asr").ToDictionary(a => a.Str("id"), a => a.Int("action"), StringComparer.OrdinalIgnoreCase) : [];
        var setIds = new List<string>();
        var setActs = new List<string>();
        var kept = 0;
        foreach (var id in AsrRules)
        {
            var want = 2;
            if (baseAsr.TryGetValue(id, out var b) && AsrRank.TryGetValue(b, out var br) && br > AsrRank[want]) { want = b; kept++; }
            if (!have.TryGetValue(id, out var h) || h != want) { setIds.Add(id); setActs.Add(AsrActionName[want]); }
        }
        if (setIds.Count > 0)
        {
            var r = PowerShellRunner.Run("Add-MpPreference -AttackSurfaceReductionRules_Ids ($env:EDR_IDS -split ',') -AttackSurfaceReductionRules_Actions ($env:EDR_ACTS -split ',')",
                new Dictionary<string, string> { ["EDR_IDS"] = string.Join(",", setIds), ["EDR_ACTS"] = string.Join(",", setActs) });
            notes.Add(r.ExitCode == 0 ? $"OK {AsrRules.Length} ASR rules in audit mode (reported, never blocked)" : $"WARN ASR rules: {r.Error.Trim()}");
        }
        else notes.Add($"OK {AsrRules.Length} ASR rules already in audit mode");
        if (kept > 0) notes.Add($"OK {kept} ASR rules kept at the stronger setting they had before FreeEDR");

        var cfaWant = 2;
        var baseCfa = known ? baseline!.Int("controlledFolderAccess") : 0;
        if (CfaRank.TryGetValue(baseCfa, out var bc) && bc > CfaRank[cfaWant]) { cfaWant = baseCfa; notes.Add($"OK Controlled folder access kept at '{CfaName[cfaWant]}', as it was before FreeEDR"); }
        if (cur.Int("cfa") != cfaWant)
        {
            var r = PowerShellRunner.Run("Set-MpPreference -EnableControlledFolderAccess $env:EDR_V", new Dictionary<string, string> { ["EDR_V"] = CfaName[cfaWant] });
            notes.Add(r.ExitCode == 0 ? $"OK Controlled folder access: {CfaName[cfaWant]}" : $"WARN Controlled folder access: {r.Error.Trim()}");
        }
        var games = gameExes.ToList();
        if (games.Count > 0)
        {
            var r = PowerShellRunner.Run("foreach ($g in ($env:EDR_APPS -split '\\|')) { Add-MpPreference -ControlledFolderAccessAllowedApplications $g }",
                new Dictionary<string, string> { ["EDR_APPS"] = string.Join("|", games) });
            notes.Add(r.ExitCode == 0 ? $"OK {games.Count} Epic/Fortnite/Easy Anti-Cheat programs allowed through Controlled folder access" : $"WARN game allow-list: {r.Error.Trim()}");
        }
        return notes;
    }

    /// <summary>Puts ASR rules, Controlled folder access and FreeEDR's allows back as the baseline recorded (Windows defaults otherwise).</summary>
    public static List<string> Restore(JsonObject? baseline, JsonObject? managed, IEnumerable<JsonObject> dashboardAllows)
    {
        var notes = new List<string>();
        var cur = ReadPreferences();
        if (cur is null) { notes.Add("WARN Defender settings cannot be read - skipped"); return notes; }
        var known = baseline?.Truthy("known") == true;
        var baseApps = known && baseline!["cfaAllowedApps"] is JsonArray ba ? ba.Select(Ps.Str).ToHashSet(StringComparer.OrdinalIgnoreCase) : new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var baseAsrEx = known && baseline!["asrExclusions"] is JsonArray be ? be.Select(Ps.Str).ToHashSet(StringComparer.OrdinalIgnoreCase) : new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var baseThreats = known && baseline!["threatIdActions"] is JsonArray bt ? bt.Select(Ps.Str).ToHashSet() : [];

        var removeApps = new List<string>();
        var removeAsrEx = new List<string>();
        var removeThreats = new List<string>();
        foreach (var e in dashboardAllows)
        {
            var path = e.Str("path");
            switch (e.Str("kind"))
            {
                case "threat": if (!baseThreats.Contains(path)) removeThreats.Add(path); break;
                case "cfa": if (!baseApps.Contains(path)) removeApps.Add(path); break;
                default: if (!baseAsrEx.Contains(path)) removeAsrEx.Add(path); break;
            }
        }
        var currentApps = cur["cfaApps"] is JsonArray ca ? ca.Select(Ps.Str).ToHashSet(StringComparer.OrdinalIgnoreCase) : [];
        var managedApps = managed?["cfaApps"] is JsonArray ma ? ma.Select(Ps.Str) : [];
        foreach (var g in managedApps.Concat(GameExes()).Distinct(StringComparer.OrdinalIgnoreCase))
            if (currentApps.Contains(g) && !baseApps.Contains(g)) removeApps.Add(g);

        var r1 = PowerShellRunner.Run("""
            foreach ($x in ($env:EDR_APPS -split '\|' | Where-Object { $_ })) { Remove-MpPreference -ControlledFolderAccessAllowedApplications $x -ErrorAction SilentlyContinue }
            foreach ($x in ($env:EDR_ASREX -split '\|' | Where-Object { $_ })) { Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $x -ErrorAction SilentlyContinue }
            foreach ($x in ($env:EDR_THREATS -split '\|' | Where-Object { $_ })) { Remove-MpPreference -ThreatIDDefaultAction_Ids ([long]$x) -ErrorAction SilentlyContinue }
            Remove-MpPreference -ExclusionProcess 'FreeEDR-Setup.exe' -ErrorAction SilentlyContinue
            Remove-MpPreference -ThreatIDDefaultAction_Ids 2147731250 -ErrorAction SilentlyContinue
            """, new Dictionary<string, string>
        {
            ["EDR_APPS"] = string.Join("|", removeApps.Distinct()), ["EDR_ASREX"] = string.Join("|", removeAsrEx.Distinct()), ["EDR_THREATS"] = string.Join("|", removeThreats.Distinct()),
        });
        notes.Add(r1.ExitCode == 0 ? $"OK {removeApps.Count + removeAsrEx.Count + removeThreats.Count} Defender allows / exclusions added by FreeEDR removed" : $"WARN Defender allows: {r1.Error.Trim()}");

        var baseAsr = known ? baseline!.Objects("asr").ToDictionary(a => a.Str("id"), a => a.Int("action"), StringComparer.OrdinalIgnoreCase) : [];
        var set = cur.Objects("asr").Select(a => a.Str("id")).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var managedAsr = managed?["asrRules"] is JsonArray mr ? mr.Select(Ps.Str) : [];
        var restoreIds = new List<string>(); var restoreActs = new List<string>(); var removeIds = new List<string>();
        foreach (var id in AsrRules.Concat(managedAsr).Select(i => i.ToLowerInvariant()).Distinct())
        {
            if (baseAsr.TryGetValue(id, out var a) && AsrActionName.TryGetValue(a, out var an)) { restoreIds.Add(id); restoreActs.Add(an); }
            else if (set.Contains(id)) removeIds.Add(id);
        }
        var cfa = known && CfaName.ContainsKey(baseline!.Int("controlledFolderAccess")) ? baseline!.Int("controlledFolderAccess") : 0;
        var r2 = PowerShellRunner.Run("""
            if ($env:EDR_RIDS) { Add-MpPreference -AttackSurfaceReductionRules_Ids ($env:EDR_RIDS -split ',') -AttackSurfaceReductionRules_Actions ($env:EDR_RACTS -split ',') }
            if ($env:EDR_DIDS) { Remove-MpPreference -AttackSurfaceReductionRules_Ids ($env:EDR_DIDS -split ',') }
            Set-MpPreference -EnableControlledFolderAccess $env:EDR_CFA
            """, new Dictionary<string, string>
        {
            ["EDR_RIDS"] = string.Join(",", restoreIds), ["EDR_RACTS"] = string.Join(",", restoreActs), ["EDR_DIDS"] = string.Join(",", removeIds), ["EDR_CFA"] = CfaName[cfa],
        });
        notes.Add(r2.ExitCode == 0
            ? $"OK ASR rules: {restoreIds.Count} set back to their earlier action, {removeIds.Count} removed; Controlled folder access: {CfaName[cfa]}{(known ? "" : " (Windows default)")}"
            : $"WARN ASR / Controlled folder access: {r2.Error.Trim()}");
        return notes;
    }

    /// <summary>Adds one Defender allow made from the dashboard (kind cfa | threat | asr).</summary>
    public static (bool Ok, string Error) AddAllow(string kind, string path) => Allow("Add", kind, path);

    public static (bool Ok, string Error) RemoveAllow(string kind, string path) => Allow("Remove", kind, path);

    private static (bool Ok, string Error) Allow(string verb, string kind, string path)
    {
        var script = kind switch
        {
            "threat" => verb == "Add" ? "Add-MpPreference -ThreatIDDefaultAction_Ids ([long]$env:EDR_P) -ThreatIDDefaultAction_Actions 6" : "Remove-MpPreference -ThreatIDDefaultAction_Ids ([long]$env:EDR_P)",
            "cfa" => $"{verb}-MpPreference -ControlledFolderAccessAllowedApplications $env:EDR_P",
            _ => $"{verb}-MpPreference -AttackSurfaceReductionOnlyExclusions $env:EDR_P",
        };
        var r = PowerShellRunner.Run(script, new Dictionary<string, string> { ["EDR_P"] = path });
        return (r.ExitCode == 0, r.Error.Trim());
    }
}
