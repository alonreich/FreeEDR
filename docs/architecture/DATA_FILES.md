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
  data\download\              downloads in progress (removed after use)
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
| `quietProcesses` | `["FortniteClient*","FortniteLauncher*"]` | notifications wait while a matching process runs |
| `iocFeedUrl` | Neo23x0 signature-base hash list | HTTPS only; abuse.ch exports are replaced by the default |
| `sigmaLookback` | `2d` | Hayabusa `--time-offset` (`\d{1,3}[dh]`) |
| `defenderMode` | `audit` | `audit` = ASR + Controlled folder access in audit mode; `untouched` = FreeEDR leaves Defender as it is |
| `allowProfilesInitialized` | `false` → `true` after the first install | recommended trusted apps are switched on once |
| `installedAt` | first install time | start of the tray's 7-day learning week |
| `wail2ban.block` | `true` | `false` = report only (no firewall rules) |
| `wail2ban.blockRdpIpv6` | `false` | inbound Remote Desktop blocked for every IPv6 address |
| `wail2ban.windowSeconds` / `failCount` | 1800 / 5 | ban after this many failures within the window |
| `wail2ban.maxBanPublicSec` / `maxBanPrivateSec` | 90 days / 7 days | ban length caps (W7) |
| `wail2ban.maxTrackedIps` | 50000 | tracked-address cap |
Obsolete keys (`enforce`, `scanTime`, `userProfile`) are dropped when the file is rewritten. Changes come from the
Settings page through `set-config` ([engine/COMMANDS_AND_IPC.md](../engine/COMMANDS_AND_IPC.md)); the engine reloads the
file within a minute.

## 3. Engine → tray contract
| File | Notes |
|---|---|
| `data\events.jsonl` | one JSON object per line: `id, time (yyyy-MM-dd HH:mm:ss), blade, severity, title, process, detail` + optional fields (`rule, parent, ancestors[], sha256, user, sysmonId, ip, kind, threat, threatId, path, oldRule, yaraRule, yaraSkipped, expires, strike, threshold, ...`). The tray tails it from a byte offset, up to the last complete line, 2 MB per tick; a shorter file means it was rotated. Unknown fields are ignored |
| `data\status.json` | `heartbeat` (older than 90 s = engine down), `engineStarted`, `version`, `mode` (`detect-only`), `backlog`, `dropped`, `lagSeconds`, `edr {state, pausedUntil, error, iocHashes, yaraRules}`, `realtime`/`malware`/`sigma`/`cve {state, pausedUntil}`, `wail2ban {state, pausedUntil, error, banned[], rdp140, block, tracked}`, `sysmon {ok, message, service, driver}`, `defender {realtime, tamper, signatureAgeDays, asrBlockRules, asrAuditRules, controlledFolders}`, `defenderMode`, `scan {running, lastStart, lastEnd, ok, summary, nextDue, times}`, `blocks`, `installedAt` |
| `data\scan-result.json` | `started, finished, steps[{name, ok, message, time}], sigma[], vulns[], tools[{name, current, latest, outdated, url}], toolCheck` |
| `data\cve-current.json` | `{scanned, items[]}`: the latest OSV result (only vulnerabilities with a released fix), with `owner` (SID), `python`, `fixPackage` |

## 4. Per-account tray files (`user\<SID>\`)
`reviewed.txt` (one event id per line), `ignored-apps.txt` (hidden winget ids), `history.json` (updates started from the
dashboard), `preferences.json` (notification level, window, welcome done, learning summary shown, last weekly summary,
last page), `insights.json` (how often each alert was marked reviewed, dismissed suggestions), `winget.txt`,
`freeedr.png` (notification icon), `tray.log`.

## 5. JSON helpers (`JsonFile`)
* **Shared reads** (`FileShare.ReadWrite | Delete`, 5 retries) - another process may be writing.
* **Atomic writes**: temp file, `Flush(true)`, `File.Replace` keeping `<file>.bak` (or `Move` for a new file).
* **Strict reads** (settings, allows, verdicts, state): an empty/invalid file is restored from `.bak` (the damaged copy is
  kept as `.corrupt-<time>`, a High "Settings file damaged - restored from backup" event is raised); without a usable
  backup the read fails and the engine starts with empty in-memory data **without** writing it over the damaged file
  until there is real data to save.
* `EventWriter` appends under a lock; `CommandDrop` writes requests as `.tmp` and renames them to `.json`.
