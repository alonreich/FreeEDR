# Detection: blades, the real-time pipeline, scans, allows and trusted apps

Read for: changes to `src\Edr.Engine` detection code (`Realtime`, `Scanner`, `DefenderEvents`, `Engine` health),
`Detection` / `OwnProcess` / `Profiles` / `PatternRules` in Edr.Core, `config\sysmonconfig.template.xml`, `rules\*.yar`.
Wail2Ban is in [WAIL2BAN.md](WAIL2BAN.md); commands/verdicts in [COMMANDS_AND_IPC.md](COMMANDS_AND_IPC.md).

FreeEDR **only detects**: no blade stops, deletes or quarantines anything (Wail2Ban's firewall bans are the one exception).

## 1. Blades ("Caught by")
| Blade (GUI name) | `blade` | What it does | When | Source |
|---|---|---|---|---|
| **Real-time (Sysmon)** | `realtime` | Process starts, risky Windows tools, LSASS access, persistence (Run keys, Startup folder, Winlogon, IFEO, WMI), unsigned drivers, Defender tampering, log clearing | Instantly | Sysmon + `config\sysmonconfig.xml` |
| **Malware hash (IOC)** | `ioc` | SHA256 of the program behind a real-time alert vs. known-malware hashes | Instantly | Neo23x0 signature-base, refreshed each scan |
| **YARA file scan** | `yara` | The program behind every real-time alert vs. credential-theft and ransomware rules | Instantly (background worker) | `rules\custom_edr.yar`, `rules\ransomware.yar` |
| **Event-log scan (Sigma)** | `sigma` | Community Sigma rules over recent event logs (high and critical) | scan times, or Scan now | Hayabusa 4.3.1 (rules updated each run) |
| **Vulnerability (CVE)** | `cve` | Python packages with a vulnerability **that has a released fix** | Each scan | OSV-Scanner 2.7.0 |
| **App updates (winget)** | `patch` | Installed apps with updates | Each scan time (in the tray) | winget |
| **Microsoft Defender** | `defender` | Defender detections, ASR / Controlled folder access blocks or (audit mode) would-have-blocked | Instantly | Defender Operational log |
| **Wail2Ban** | `wail2ban` | Password guessing and internet logins: [WAIL2BAN.md](WAIL2BAN.md) | Instantly | Security 4625 / 4624 + RDP 140 |
| **EDR health** | `system` | Heartbeat, Sysmon health and stale rule sets, scan problems, pause/resume, verdicts, tool updates | Continuous | The engine |

Pause groups (`EngineState.IsPaused`): `edr` (master) pauses `realtime`, `malware`, `ioc`, `yara`, `sigma`, `cve`.
`malware` pauses IOC + YARA. Defender is never paused; Wail2Ban has its own pause.

## 2. Severity and display
| Severity | Examples | Notification (default level) | Counts as "to review" |
|---|---|---|---|
| Critical | malware hash, YARA match, LSASS dump/injection, shadow-copy deletion | yes (also in the learning week) | yes |
| High | encoded PowerShell, download cradles, Defender tampering, unsigned driver, internet login, Sigma high | yes | yes |
| Medium | Run-key changes, LOLBin network use, Wail2Ban bans, ASR/CFA blocks | Wail2Ban only (level "Everything": all) | yes, except Wail2Ban bans and Defender blocks |
| Low / Info | program run from Downloads, scan results, app updates, status | scan/health only | no |

Real-time severities: `Catalog.RuleSeverity` (unknown = Medium, WMI = High). Sigma: `crit*` level or "Severe" in the
title = Critical, else High. A test (`SysmonRuleTests`) checks that every rule name has a severity and an explanation (`Hints.Rules`).

## 3. Real-time pipeline (`Realtime.Handle`)
Subscriptions (`Native\EventSubscription`, wevtapi `EvtSubscribe`) on Sysmon IDs 1, 3, 6, 8, 10, 11, 12, 13, 14, 19,
20, 21 (and the Security, RDP and Defender channels) push each event's XML and updated bookmark into one bounded queue.
The main loop drains up to 50 records per cycle and runs commands, the exclusion reload and the heartbeat every 50
records or 2 s, so nothing is starved under a flood. Bookmarks are saved to `data\bookmarks.json` every 15 s and at
shutdown; a subscription resumes after its bookmark (`EvtSubscribeStartAfterBookmark | Strict`). A bookmark Windows
rejects falls back to "now" with a Medium "Events may have been missed" alert. A failed subscription is retried every 5 minutes.

Order per record:
1. `realtime` paused → drop. Rule name from `RuleName` (`-` = none); WMI 19/20/21 without a name = "WMI persistence"; no
   rule → drop.
2. **Own-process trust** (`OwnProcess.Check`): FreeEDR's own executables (exact path under the install folder) and
   their children - elevated ones for the engine/helper/installer, a short allow-list for the tray (Explorer, Notepad,
   winget, MpCmdRun, cmd/conhost, Windows Terminal) - are dropped. A command line that names FreeEDR's programs or old
   scripts without passing raises High "Command line imitates FreeEDR's own scripts" (once per command line).
3. Stale-rule check: a rule name not in `config\sysmonconfig.xml` → `oldRule` + health "restart the PC" (E10).
4. Detail text per event ID (command line, connection, driver signature, injected target, LSASS access mask, file,
   registry value, WMI). Allows (`Detection.RealtimeExcluded`, §6) → drop. The process chain is read only when an allow
   needs it.
5. EID 1: the grandparent and up are stored as `ancestors` for "allowed by" in the tray.
6. Not `malware`-paused: IOC lookup (SHA256 from `Hashes`, IOC allows) → `ioc`, Critical, "Known malware: <name>". Files
   outside `%SystemRoot%` that no YARA allow covers go to the **YARA worker** (bounded queue of 200): `yara64.exe -C
   data\rules.yarc <file>` (≤ 50 MB, result cached per path + last write); a match turns the alert into `yara`,
   Critical, "YARA match: <rule>". A full queue records `yaraSkipped = true` instead of blocking intake.
7. `EventWriter` appends to `events.jsonl`.

**Ancestors**: parent from the event, then up to 3 levels from one process snapshot (ToolHelp + `QueryFullProcessImageName`
+ creation time, refreshed at most every 2 s); each step must have the logged path and an earlier start (PID reuse).

**Signers** (`SignerCache`): WinVerifyTrust + the embedded signer, cached per file identity (volume serial, file index,
size, last write); files under the profiles folder or temp folders are verified live every time.

## 4. Scheduled scan (`Scanner`, a background task in the engine)
Scheduling: at each `scanTimes` slot; a slot missed while the PC was off runs 5 minutes after the engine starts. Scan now
at most every 2 minutes. A scan running over 2 hours is cancelled. Pausing `edr`/`sigma`/`cve` cancels a running scan.
Steps (result `data\scan-result.json`, log `data\scan.log`):
* **A. IOC feed**: HTTPS download; replaces the list only with HTTP 200 and ≥ 100 valid hash lines (E4).
* **B. Sigma**: `hayabusa update-rules`, then `hayabusa dfir-timeline -l -w -q -Q -K -C -m high --time-offset <lookback>`
  in Hayabusa's folder (E6). The CSV is streamed; the newest 2,000 rows are kept (Q10), more marks the step failed.
* **C. CVE**: `osv-scanner scan source -r <dir> --format json` for every account's `AppData\Local\Programs\Python` and
  Store Python packages; one row per vulnerability group with a released fix newer than the installed version, with
  `owner` (SID), `python` and `fixPackage` (pip for libraries vendored in `pip\_vendor`). A folder with no readable
  result fails the step and the CVE list keeps its previous content (Q1).
* **D. Tool versions**: GitHub `releases/latest` for the four tools → "EDR tool update" Info events once per new version
  (`kind = tool`, `tool` = name): the Updates page offers a one-click update ([COMMANDS_AND_IPC.md](COMMANDS_AND_IPC.md) `update-tool`).

`Scanner.Complete` (engine thread): a result older than the scan start is ignored; one alert per detected event (key
title|computer|channel|recordId, 20,000 kept, E6); Hayabusa's "(Sysmon Alert)" repeats are dropped; Hayabusa's
"Antivirus - …" / "Defender Alert" findings become `defender` events once (de-duplicated against live Defender events,
key threat|minute); Sigma allows; `cve-current.json` rewritten only when the OSV step succeeded; CVE events once per id.

## 5. Defender and health
* Defender events: 1116 (malware; Severe → Critical, High → High, else Medium), 1121 (ASR blocked), 1123 (CFA blocked),
  1122 / 1124 (audit mode: would have blocked, Low, never notified). Allowed threat IDs / programs are skipped
  (`Detection.DefenderExcluded`). The two always-audit ASR rules (`01443614-…`, `d1e49aac-…`) are not listed.
* Defender status every 10 minutes (`Defender.Status`, Windows PowerShell's `Get-MpComputerStatus`/`Get-MpPreference`).
* `status.json` health: `backlog` (queue + YARA queue), `dropped` (YARA skipped), `lagSeconds`. The tray shows lag ≥ 5 s;
  ≥ 30 s marks protection as having a problem.
* Sysmon health every minute: service `Sysmon64` (restarted at most every 5 minutes), driver `SysmonDrv`, readable log,
  stale rule set within the last hour. Changes raise "Sysmon sensor is not working" (High) / "healthy again"; the last
  state is kept in `state.json` (E14).

## 6. Allows (`config\exclusions.json`)
Lists `realtimePath, realtime, ioc, yara, sigma, wail2ban, cve, defender`, each an array of `{id, added, ...}`.
* `realtime`: `{rule ('*' or a name), image, parent, signer, parentSigner, ancestors (1-3), detail, match ('exact' or
  wildcard), raw, profile}`. At least one of image/parent/signer/detail; patterns must pass `PatternRules.IsSpecific`
  (no match-all; image/parent need a 3+ character `.exe` segment or a rooted folder that is not a drive root; parent `*`
  only with a safe parentSigner; detail ≥ 3 literal characters). `Microsoft Windows` / `Microsoft Windows Publisher` /
  `Microsoft Corporation` are refused as parentSigner, and as signer unless an image narrows it. The engine re-checks
  specificity at match time ("never a blanket ignore everything").
* `realtimePath`: legacy `{prefix}` (old game/EDR folders removed by the installer; nothing adds new ones).
* `sigma`: `{title ('*' or a title), parent, parentSigner, profile}`; `*` needs a specific parent.
* `ioc`: `{sha256, image}` · `yara`: `{image, raw}` · `cve`: `{cve, package}` · `wail2ban`: `{cidr, note}`.
* `defender`: `{kind (cfa | threat | asr), path, note}`, applied with `Add-MpPreference` (CFA paths rooted, no
  wildcards; threat IDs numeric) and removed with `Remove-MpPreference`.
* Wildcards follow PowerShell's `-like` (case-insensitive, `* ? [ ]`, backtick escape; `Ps.Like`).
* **Never allow `pwsh.exe` / `powershell.exe` itself for all rules**; the installer removes such allows (E15).
* Tray helpers: *Allow everything X starts* uses `PatternRules.VersionlessPattern` (version/hash folders → `*`) and the
  parent's signature when it has one.

## 7. Trusted-app profiles (`Profiles` in Edr.Core)
One profile = a set of allows stored with `profile = <id>`, switched on or off as a whole. The installer switches on
every default profile whose app is found **once** (`allowProfilesInitialized`). The table of profiles is in
[user/USER_GUIDE.md](../user/USER_GUIDE.md) §3. Paths come from `EdrPaths.ProfilesRoot` / Program Files (a test checks no
account name appears). Claude Code's launcher lines use exact matching (`match = 'exact'`) so a command line that only
contains the marker still alerts (T5). `Profiles.FindFor` offers "Trust the app" on an alert a profile that is off would hide.

## 8. Sysmon config and games (`config\sysmonconfig.template.xml`)
* Include-only rules, named (the name is the alert title), an explicit "Off" group for high-volume event types; validated
  on Sysmon 15.22 / schema 4.91. Conditions used: `is`, `contains (any|all)`, `begin with`, `end with`, `excludes all`.
* `BuiltInExclusions`: Epic Games, Easy Anti-Cheat, BattlEye, the Epic launcher, FortniteGame and the FreeEDR folder.
  `{ROOT}` is replaced at install.
* Sysmon 15.22 crashes (0xC0000409) on `condition="end with any"`: use `contains any` (a test checks it).
* "New user or admin group change": `net`/`net1` with ` user ` **and** ` /add`, or ` localgroup ` **and** ` /add`, or
  `Add-LocalGroupMember` / `New-LocalUser` (T2, T4). "Encoded PowerShell command": an encoded flag and **no**
  ` -command ` / ` -c ` (an encoded command cannot be combined with -Command; T3).
* `.yar` files: ASCII without BOM. Credential-tool strings stay hex-encoded (AMSI).

## 9. Known detection gaps
None open from the corpus (`tests\data\process-corpus.json`, `SysmonRuleTests`). Sigma "Suspicious Encoded/Download
Execution" can be noisy on developer PCs (T6, live WARN): allow it per parent if so.
