# Data files: every file in C:\Program Files\FreeEDR, settings, and the engine ↔ tray contract

Read for: changes to anything FreeEDR reads or writes (paths come from `EdrPaths` in Edr.Core), the settings file, the
status file, or the JSON helpers (`JsonFile`).

## 1. Layout
```
C:\Program Files\FreeEDR\
  bin\FreeEDR-Engine.exe, FreeEDR-Control.exe, FreeEDR-Installer.exe      NativeAOT programs
  bin\tray\FreeEDR-Tray.exe (+ libSkiaSharp.dll, libHarfBuzzSharp.dll, av_libglesv2.dll)
  bin\hayabusa\ (hayabusa.exe + rules\, config\), bin\yara64.exe, bin\yarac64.exe, bin\osv-scanner.exe, bin\velociraptor.exe
  config\edr-config.json      settings (§2)
  config\exclusions.json      allow lists (engine/DETECTION.md §6)
  config\blocklist.json       verdicts: flagged programs/rules, permanent IP bans ({items: [...]})
  config\sysmonconfig.template.xml, config\sysmonconfig.xml
  rules\custom_edr.yar, rules\ransomware.yar, rules\ioc_sha256.txt
  data\events.jsonl (+ events-<time>.jsonl, 5 kept; rotation at 20 MB)
  data\status.json            engine heartbeat and state (§3), every 15 s
  data\state.json             pauses, scan bookkeeping, already-reported sets, sysmonOk
  data\bookmarks.json         one event log bookmark per subscription (no events lost across restarts)
  data\wail2ban_strikes.txt   "ip strikes epoch" per line (engine/WAIL2BAN.md)
  data\scan-result.json, data\cve-current.json, data\hayabusa_last_scan.csv
  data\engine.log, data\scan.log, data\rules.yarc (compiled YARA)
  data\preinstall.json, data\managed.json, data\sysmon-original.reg   uninstall records
  data\backup-<time>\         previous programs (newest 3)
  data\archive\yyyy-MM-dd\<log>.xml.gz, data\archive\bookmarks.json   event-log archive (engine/DETECTION.md §1; 90 days / 1 GB)
  docs\THIRD_PARTY_NOTICES.txt   the embedded tools, versions and licenses (written by the build)
  data\download\              downloads in progress (removed after use)
  data\sandbox\               the only folder the sandboxed scanners can write (low integrity label; Hayabusa CSV, OSV TEMP)
  control\                    admin-only requests (FreeEDR-Control.exe)
  inbox\                      user requests (resume, scan-now)
  user\<SID>\                 each account's tray files (§4)
  docs\, README.md, version.txt, install.log
  quarantine\                 only if left by a version before 2026-11-06 (restored when its verdict is removed)
```

## 2. Settings (`config\edr-config.json`, `EdrConfig`)
| Key | Default | Meaning |
|---|---|---|
| `scanTimes` | `["06:00","18:00"]` | scan slots (24 h); a missed slot runs 5 min after the engine starts |
| `quietProcesses` | `["FortniteClient*","FortniteLauncher*"]` | starting quiet-mode list for accounts that have not picked their own (`preferences.json` `quietProcesses`); not edited on the Settings page |
| `iocFeedUrl` | Neo23x0 signature-base hash list | HTTPS only; abuse.ch exports are replaced by the default |
| `sigmaLookback` | `2d` | Hayabusa `--time-offset` (`\d{1,3}[dh]`) |
| `defenderMode` | `audit` | `audit` = ASR + Controlled folder access in audit mode; `untouched` = FreeEDR leaves Defender as it is |
| `allowProfilesInitialized` | `false` → `true` after the first install | recommended trusted apps are switched on once |
| `installedAt` | first install time | start of the tray's 7-day learning week |
| `wail2ban.block` | `true` | `false` = report only (no firewall rules) |
| `wail2ban.blockRdpIpv6` | `false` | inbound Remote Desktop blocked for every IPv6 address |
| `wail2ban.windowSeconds` / `failCount` | 1800 / 5 | ban after this many failures within the window (60-86400 s / 2-1000) |
| `wail2ban.maxBanPublicSec` / `maxBanPrivateSec` | 90 days / 7 days | ban length caps (W7; 300 s to 1 year) |

Numbers outside their range (`EdrConfig.Limits`) are clamped the same way on every read (`FromJson`) and save (`Apply`),
so the dashboard always shows the value the engine uses. The helper's audit line and the scan log show the feed address
with any user name, password or query replaced by `(hidden)` (`EdrConfig.RedactUrl`).
| `wail2ban.maxTrackedIps` | 50000 | tracked-address cap |
Obsolete keys (`enforce`, `scanTime`, `userProfile`) are dropped when the file is rewritten. Changes come from the
Settings page through `set-config` ([engine/COMMANDS_AND_IPC.md](../engine/COMMANDS_AND_IPC.md)), as a change set (only the
values the user changed); the engine checks the file every 5 s and reports the version it runs with as `status.json`
`settingsLoaded`. One rule for the hash feed (`EdrConfig.FeedProblem`: https, a host, not MalwareBazaar) in the
dashboard, the helper and every read, so a saved address is never dropped later. Settings ▸ *Back up settings* writes
`{format: "FreeEDR settings backup", version: 1, created, settings{...the keys above except installedAt,
allowProfilesInitialized, maxTrackedIps}, allows{realtime, sigma, ioc, yara, cve, wail2ban, defender: [entries without
id/added]}}`; import turns it into `set-config` + `exclude` requests (`SettingsBackup.PlanImport`).

## 3. Engine → tray contract
| File | Notes |
|---|---|
| `data\events.jsonl` | one JSON object per line: `id, time (yyyy-MM-dd HH:mm:ss), blade, severity, title, process, detail` + optional fields (`rule, parent, ancestors[], sha256, user, sysmonId, ip, kind, threat, threatId, path, oldRule, yaraRule, yaraSkipped, yaraNotScanned, expires, strike, threshold, ...`). The tray tails it from a byte offset, up to the last complete line, 2 MB per tick; a shorter file means it was rotated. Unknown fields are ignored |
| `data\status.json` | `heartbeat` (older than 90 s = engine down), `engineStarted`, `version`, `mode` (`detect-only`), `backlog`, `dropped`, `intakeDropped`, `lagSeconds`, `eventWriteFailures`, `edr {state, pausedUntil, error, iocHashes, yaraRules, yaraNotScanned}`, `realtime`/`malware`/`sigma`/`cve {state, pausedUntil}`, `wail2ban {state, pausedUntil, error, banned[], rdp140, block, tracked}`, `sysmon {ok, message, service, driver}`, `defender {realtime, tamper, signatureAgeDays, asrBlockRules, asrAuditRules, controlledFolders}`, `defenderMode`, `scan {running, lastStart, lastEnd, ok, summary, nextDue, times}`, `blocks`, `installedAt`, `settingsLoaded` (UTC write time of the settings file the engine runs with), `archive {logs, of, written, dropped, queued, mb, lastWrite, error}`, `pipe {name, clients, subscribers, refused, error}`, `commandIntake {queued, control {taken, refused, waiting, stuck}, inbox {...}}` |
| `data\scan-result.json` | `started, finished, steps[{name, ok, message, time}], sigma[], vulns[], tools[{name, current, latest, outdated, url}], toolCheck` |
| `data\cve-current.json` | `{scanned, items[]}`: the latest OSV result (only vulnerabilities with a released fix), with `owner` (SID), `python`, `fixPackage` |

## 4. Per-account tray files (`user\<SID>\`)
`reviewed.txt` (one event id per line), `ignored-apps.txt` (hidden winget ids), `history.json` (updates started from the
dashboard), `preferences.json` (notification level, theme (`system` (default) / `dark` / `light`), quiet-mode list
(`quietProcesses`; missing = the PC's starting list), window (normal size and position, maximized), welcome done, learning
summary shown, last weekly summary, last page, Settings scroll position, which Settings *Advanced* parts are open), `insights.json` (how often each alert was marked reviewed, dismissed suggestions), `winget.txt`,
`freeedr.png` (notification icon), `tray.log`.

## 5. JSON helpers (`JsonFile`)
* **Shared reads** (`FileShare.ReadWrite | Delete`, 5 retries) - another process may be writing.
* **Atomic writes**: temp file, `Flush(true)`, `File.Replace` keeping `<file>.bak` (or `Move` for a new file).
* **Strict reads** (settings, allows, verdicts, state): an empty/invalid file is restored from `.bak` (the damaged copy is
  kept as `.corrupt-<time>`, a High "Settings file damaged - restored from backup" event is raised); without a usable
  backup the read fails and the engine starts with empty in-memory data **without** writing it over the damaged file
  until there is real data to save.
* `EventWriter` appends under a lock. **The engine is the only writer of `events.jsonl`** (audit 2026-11-07, finding 6):
  FreeEDR's elevated helper and installer send their messages to it as a `note` request (`EngineNote.Send`: the pipe,
  or `control\` when the engine is down), so rotation (at 20 MB) never races another process. A write that fails (disk
  full, file locked for over a second) is counted (`status.json` `eventWriteFailures`); at most every 10 minutes the
  engine writes the count and reason to engine.log and to the Application log (source `wail2ban`, event 4000) and
  raises "Alerts could not be recorded" (High). A failed rotation keeps appending to the current file.
* `CommandDrop` writes requests as `.tmp` and renames them to `.json`; the engine takes them with `Native\DropFile`
  ([engine/COMMANDS_AND_IPC.md](../engine/COMMANDS_AND_IPC.md) §2).
