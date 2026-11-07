# Current status and open items (2026-11-06)

Read for: knowing what is already broken or pending before you start, so you do not chase known FAILs/WARNs. Update this
file when you close or open an item.

## Migration
2026-11-06: FreeEDR is C# 14 / .NET 10 / Avalonia, every program NativeAOT ([tray/TRAY_REWRITE_PLAN.md](../tray/TRAY_REWRITE_PLAN.md)).
The 20 improvement proposals P1-P20 are implemented ([DECISIONS.md](DECISIONS.md) §9). **Installed on the owner's PC
2026-11-06 15:13** (2026.11.6.1406; updated 15:25 to 2026.11.6.1520, dev build, unsigned): upgrade from the PowerShell version succeeded, the old scheduled
task and scripts were removed by the installer, the "FreeEDR" service runs, the tray started unelevated. The legacy
PowerShell scripts and `src\parity.ps1` (replaced by the golden model tests) were deleted on 2026-11-06 with the
owner's approval.

## Test bundle
Last result (2026.11.6.1520 installed): `TEST RESULT: OK  pass=146 fail=0 warn=1 skip=0` (see `tests\results\last-run.txt`);
the WARN is L1.
2026-11-06 18:39: **2026.11.6.1823 installed** (pre-ship audit fixes, dev build, unsigned; install result SUCCESS, the
engine dropped the stale Sysmon/Defender bookmarks and watches both again). `TEST RESULT: OK  pass=144 fail=0 warn=3
skip=0`. WARNs: the old engine's L4 errors before 18:39 (age out of the one-hour window), the OSV step for the
Microsoft Store Python in the scan made by the old engine (re-check after the next scan), and L1.

| ID | Item | Status |
|---|---|---|
| T2 | Sysmon rule "New user or admin group change" missed `net user <name> <password> /add` | **Resolved** (rule split: net/net1 + ` user ` + ` /add`) |
| T3 | "Encoded PowerShell command" fired on ` -e ` inside a -Command text | **Resolved** (`excludes all` -command / -c) |
| T4 | "New user or admin group change" fired on `net localgroup administrators` (listing) | **Resolved** (needs ` /add`) |
| T5 | A command line that copies Claude Code's launcher text was hidden | **Resolved** (exact match) |
| T6 | Sigma "Suspicious Encoded/Download Execution" is noisy on developer PCs | To review (Live WARN when it happens) |
| T8 | Sysmon itself has not yet loaded the T2-T4 rule changes (`contains all`, two `CommandLine` filters in one rule) | **Resolved** 2026-11-06: the installer applied the config ("Sysmon config applied") and the Sysmon blade checked on |
| L1 | 05-Live WARN: noisy certutil alerts from the old flood test (x500) | Ages out of the 7-day window (~2026-11-08) |
| L3 | Installed tray (2026.11.6.1406) crashes on the second build of Allowed & trusted > Trusted apps (control re-parented) | **Resolved** 2026-11-06 (fix installed in 2026.11.6.1520) |
| L2 | 05-Live "Folder permissions" failed when the engine consumed a `control\` command file between listing and `Get-Acl` | **Resolved** (the test skips files that disappear) |

## Security audit (2026-11-02) — carried into the C# version
| Rank | Area | C# implementation |
|---|---|---|
| 1 | Own-process filter bypass | `OwnProcess.Check`: exact executable paths under the admin-only folder, elevated children only, tray child allow-list, near-miss alert |
| 2 | CVE update cross-user execution | `ActionBuilder.OwnsCve` (owner SID / admin-only path), `SafePython`, argument vectors |
| 3 | Elevated command channel wildcards | `PatternRules.IsSpecific` / `IsValidOp` / `IsValidCommand` in the helper **and** the engine; payload 64 KB, batch 100 |
| 4 | Trusted-app spoofing | exact detail match, Antigravity off by default, signer cache keyed on file identity, live checks in user-writable folders |
| 5 | Engine hot path / event loss | `EvtSubscribe` bookmarks, one process snapshot per 2 s, bounded YARA queue with `yaraSkipped`, cadence inside the drain loop, backlog/dropped/lag metrics |
| 6 | State file wipe / lost update | `JsonFile` atomic write + `.bak`, strict reads with recovery, no empty overwrite after unrecoverable damage |
| 7 | Wail2Ban quadratic tracking | per-address lists, 50k cap with eviction, 60 s housekeeping, debounced strikes file |
| 8 | Tray unbounded events / re-entrancy | `EventTail` cap 10,000 with eviction aggregates, 2 MB per tick, tick guard, non-blocking UAC requests |

## Pre-ship architectural audit (2026-11-06)
| Rank | Finding | Fix |
|---|---|---|
| 1 | Elevated helper trusted any caller's payload and `--root` (a planted Defender baseline could disable ASR and Controlled folder access) | `--root` removed from FreeEDR-Control.exe and FreeEDR-Installer.exe; the helper shows the decoded request (`RequestSummary`) in its own elevated Yes/No window, default No; exit code 4 = declined |
| 2 | Engine intake queue (100,000 XML items) dropped events silently while bookmarks moved on | queue 10,000 with backpressure in the event log callback; drops (only while stopping/re-subscribing) counted in `intakeDropped` and alerted |
| 3 | Scan thread and engine loop shared `EngineState` without a lock | every `EngineState` access under one re-entrant lock |
| 4 | Tray read files and rebuilt the model (with signature checks) on the UI thread | `TrayState.RefreshAsync` worker, published snapshot, materialized records, thread-safe bounded signer cache |
| 5 | Engine signer cache key (size + last write) could be kept after an in-place rewrite | key = volume + file index + NTFS change-journal number (`Win32.FileChangeStamp`); no stamp = live check |
| 6 | YARA parsed attacker files as SYSTEM | `Native\Sandbox`: restricted token, low integrity, one-process Job with memory cap; no unsandboxed fallback |
| L4 | Found by 05-Live: after the log was cleared/wrapped, the installed engine (2026.11.6.1520) retried a stale bookmark (error 15011) every 5 minutes, so Sysmon and Defender were not watched from 2026-11-06 17:28 | `EventSubscription.Start` treats 15011/15012 as a rejected bookmark: the watcher restarts from now with "Events may have been missed". **Resolved** (installed 2026.11.6.1823) |

Still open from this audit: Hayabusa and OSV-Scanner still run with the engine's rights (Hayabusa must read the Security
log and both write output into `data\`; sandboxing them needs a writable low-integrity output folder and a log-reader
token). Tests: `HardeningTests` (C#).

## Pre-ship architectural audit, round 2 (2026-11-07) - built, not installed
| Rank | Finding | Fix |
|---|---|---|
| 1 | Any account could stall the SYSTEM engine's main loop through `inbox\` (oplock, a file grown after the size check, locked files with sleeps), so detection and Wail2Ban stopped while the service looked alive | `CommandIntake`: one worker thread per drop folder, never the main loop; `Native\DropFile.Take` (NtCreateFile: no link followed, `FILE_COMPLETE_IF_OPLOCKED`, share read only, ≤ 64 KB read from the one handle, hard links never read, delete-on-handle before use); busy files never block new ones; stuck worker alerted; inbox requests recorded as "a local account (inbox)" |
| 2 | The helper's confirmation could hide the decisive part of a request (batch cut at 20 lines, values cut at 160 characters, field order from the payload) | `RequestSummary.Build`: the whole request or exit code 6 (refused); nothing cut; deciding fields first in a fixed order; control/bidi/zero-width characters replaced; built-in trusted apps as one line only when exactly the built-in allows; removals shown by content; settings as old → new; the helper always records its own account name |
| 3 | YARA errors, timeouts and > 50 MB files counted as clean and were cached on path + last write (timestamps can be set back) | `ScanFile` → hit / clean / not scanned; not-scanned is never cached, is shown on the alert (`yaraNotScanned`) and counted (`edr.yaraNotScanned`, hourly health alert); cache key = `Win32.FileChangeStamp` |
| 4 | Tool updates trusted GitHub's "latest" with only GitHub's own digest, then ran the new binary as admin/SYSTEM; `hayabusa update-rules` ran unsandboxed as SYSTEM | Updates only for tools with a pinned Authenticode publisher (Velociraptor: Rapid7 LLC), signature checked before the swap; unsigned tools only with a FreeEDR release; version queries in the sandbox (version resource for an elevation-only manifest); `update-rules` sandboxed on a staged copy, copied back only on success |
| 5 | Any account could hold all 16 pipe connections (unlimited subscriptions, 30 s silent connections, byte-by-byte reads) | Per-account caps (4 connections, 3 subscriptions; key = SID + elevation from the client's process token), 4 slots never used by subscriptions, 5 s first-line deadline, a talking subscriber is dropped, buffered `EnginePipe.LineReader` |
| 6 | Alerts could be lost silently (swallowed write errors; the helper and the engine both rotated `events.jsonl`) | The engine is the only writer (helper/installer send `note` via `EngineNote.Send`); failed writes counted (`eventWriteFailures`), reported every 10 minutes to engine.log, Application log event 4000 and a High alert |

Verified in this session: C# tests (156: 155 passed, 1 known SKIP), the sandboxed `hayabusa update-rules` against a
low-integrity copy (exit 0, rules updated through git), dev build 2026-11-07 OK, `TEST RESULT: OK  pass=147 fail=0
warn=2 skip=0`. WARNs: "not the latest build installed" (not installed: needs the owner's approval) and L5. Not
verified: the installed engine.

| ID | Item | Status |
|---|---|---|
| L5 | 05-Live WARN "Last scan had no failed steps": in the installed build (2026.11.6.1823) the sandboxed `hayabusa dfir-timeline -l` stops at once with "[ERROR] -l, --live-analysis needs to be run as Administrator on Windows" (exit 0, no CSV), so the **Sigma event-log scan finds nothing since the first sandbox build**. Needs a fix: the engine exports the recent records of the logs to a sandbox folder (`wevtutil epl` with a time filter) and Hayabusa scans that folder (`-d`) instead of `-l`. The OSV part of that WARN is the known Store-Python item | **Fixed in the build, not installed** (2026-11-07): `Native\LogExport` copies the lookback window of every log with records into `data\sandbox\evtx\`, sandboxed Hayabusa scans it with `-d` (checked unelevated: 25 logs, 4 detections, CSV written); an `[ERROR]` line now fails the step, no CSV without an error = 0 hits |

## Installed 2026-11-07 10:48 (audit round 2 + L5 + Settings audit; dev build, unsigned)
`INSTALL RESULT: SUCCESS` (upgrade, `/VERYSILENT`). Live: a scan at 10:48 ran the sandboxed `update-rules` (5,021 rules),
copied 30 logs (66 MB) and the Sigma scan found 300 hits (4 new alerts) - **L5 resolved**. `TEST RESULT: OK  pass=148
fail=0 warn=1 skip=0`; the WARN is the known OSV step for the Microsoft Store Python (exit 128).

| ID | Item | Status |
|---|---|---|
| L6 | The first working Sigma scan raised "UEFI Persistence Via Wpbbin" although the built-in *wpbbin* trusted app allows it: Security-log (4688) hits name the parent `ParentProcessName`, which `SigmaProcess.FromDetails` did not read (only Sysmon's `ParentImage`), so no Sigma allow with a parent could match a Security-log hit | **Resolved**: installed 2026-11-07 11:24 (`INSTALL RESULT: SUCCESS`; `TEST RESULT: OK  pass=148 fail=0 warn=1 skip=0`, the WARN = Store-Python OSV). The alert raised before can be marked reviewed |
| L7 | The same scan reported 3 log clears ("Log Cleared", "Important Log File Cleared") from 2026-11-06 - the clears behind L4 | Real events, not false positives: the owner should confirm they were their own |

## Tray UI/UX audit, round 2 (2026-11-07 night) - 9 items, installed 2026-11-07 23:24 (`INSTALL RESULT: SUCCESS`; after install `TEST RESULT: OK  pass=149 fail=0 warn=1 skip=0`, the WARN = Store-Python OSV)
| Rank | Finding | Fix |
|---|---|---|
| 1 | Review counts disagreed (badge/tiles counted High+Critical, the "To review" tab every open item) | Badge, Home tiles, hero sentence and tab all use `SectionModel.Count`; `Attention` only colours red/grey (test `Overall_review_count_matches_the_open_items_of_Activity`) |
| 2 | Every elevated confirmation said "Continue" | `Controller.Send(..., yes)`: *Ban IP*, *Flag as threat*, *Confirm as threat*, *Allow*, *Trust*, *Ignore*, *Remove allow*, *Unban*, *Move back*, *Allow all*, *Trust* / *Stop trusting* |
| 3 | The Undo message hid on a timer even while hovered/focused | Countdown paused while the pointer is on the bar or focus is in it, restarted on leave |
| 4 | Closing the welcome with X brought it back at every sign-in | *Skip tour* + user close = `welcomeDone`; programmatic close is not a skip (checked live via UI Automation: X sets `welcomeDone`) |
| 5 | *Apply changes* (Trusted apps) always active | Enabled only with pending switches; tooltip shows on disabled |
| 6 | Four label sets for the Was-this-you answer | *Yes, it was me* / *No, it wasn't me* / *No - ban this IP* everywhere; hero text no longer says "on Home" |
| 7 | Trusted apps / FreeEDR tools panels centred off-grid | Left-aligned (max 1000 px) |
| 8 | List squeezed at the minimum window | Details pane 42 % of the width, 300-400 px; `--screenshot` renders `*-min.png` at 980 x 620 |
| 9 | Coverage gaps | Checked: light theme renders, minimum-size renders, welcome X live, second instance hands over to the first (dashboard shown, exit 0). Still manual: Narrator walkthrough, Windows high-contrast, 150-200 % DPI, real toasts, UAC decline paths |

Verified: dev build 2026-11-07 23:16 (WARN = unsigned only), C# tests 187 (186 passed, 1 known SKIP), `TEST RESULT: OK
pass=148 fail=0 warn=2 skip=0` (WARNs: not installed yet, Store-Python OSV).

## Settings audit, round 2 (2026-11-07) - 14 items, installed 2026-11-07 23:00 (`INSTALL RESULT: SUCCESS`; after install `TEST RESULT: OK  pass=148 fail=0 warn=1 skip=0`, the WARN = Store-Python OSV)
Wiring: one range table `EdrConfig.Limits` for every read and save, and the form compares with the file's exact values
(`EdrConfig.UserJson`), so the page never shows a clamped or rounded value as the active one (#1). A file changed
elsewhere while the form is dirty (reset, import, Network switch) is shown with the user's edits kept (`Form.Load`) and a
notice (#2). Reset texts say the Defender choice and each account's own choices stay (#3). Layout: save bar pinned under
the page (#4); quiet mode moved to "Just for you" as a per-account preference (`preferences.json` `quietProcesses`, no
UAC; the PC value is the starting list; backup / import carry it) (#5); ⓘ is a real button with flyout and focus ring
(#6); ban caps as presets (#7); expert fields in a collapsed *Advanced* part per section (#8); shorter labels (#9).
Dialogs one at a time, in front, scrolling (#10). Feed address with a key: masked with an eye toggle, `(hidden)` in the
helper's audit line and the scan log, backup asks (#11). Shared label column, test result under its field (#12). Theme
default *Same as Windows* for accounts that never picked one (#13). Settings reopens at its scroll position, also after a
tray restart (#14). Tests: `SettingsTests` (ranges, baseline, redaction, quiet list in backups, quiet-name rule).
Result (repository build, before install): `TEST RESULT: OK  pass=147 fail=0 warn=2 skip=0`; WARNs = installed copy
older than this build (expected until installed) and the known Store-Python OSV step.

## Settings audit (2026-11-07) - 20 items, built, installed 2026-11-07 10:48
Wiring: change-set saves (#1), one feed rule + *Test* (#2), IPv6 block and ban lengths only while blocking (#3, #8),
quiet names with spaces (#4), inline validation with no hidden defaults (#5). Defaults: *Restore default settings* and
per-field *Default* links (#6). Backup / import through normal requests (#7). Plain labels, ⓘ tooltips, chips + time
picker, *Look back* in words (#9-#11). Sections regrouped by importance (#12). Engine reloads settings every 5 s and
reports `settingsLoaded`; the page shows waiting / active (#13). Forensics: one Velociraptor at a time, minimized (#14).
Welcome tour: one, modal to the dashboard, returns to the page (#15). Unsaved settings: asked on tray exit, Ctrl+S / Esc
(#16). Accessibility: accessible names and help on every field, focus rings, Dark / Light / Same as Windows theme with
tested contrast (#17). Danger zone card (#18). *Open logs* menu (#19). Window reopens on an attached screen with its
normal size (#20). Tests: `SettingsTests`. Visual check: `--screenshot` renders `settings-full.png` (dark and light).

## Owner requests (2026-11-06 evening) - built, not installed (owner: not now)
Build 2026.11.6.1903 (dev): `TEST RESULT: OK  pass=143 fail=0 warn=4 skip=0`. WARNs: "not the latest build installed",
the old engine's L4 errors (before 18:39), the OSV step for the Microsoft Store Python, L1.
| # | Request | Done |
|---|---|---|
| R1 | Setup in the app's look, no console | FreeEDR-Installer.exe is an Avalonia window (choose / progress / result); Setup.iss shows no wizard pages |
| R2 | Baseline embedded, only updates downloaded | Pinned tools + IOC seed ship in Setup (EmbedTools, `obj\tools-cache`, THIRD_PARTY_NOTICES); Sysmon still downloaded (license) |
| R4 | Clear which module caught an alert, less clutter | Module tags, one-line rows, "Caught by", key facts + folded technical details |
| R5 | Slicker, calmer UI | Smaller type/spacing, tinted ok/danger buttons, flat primary |
| R6 | Upgrade vs clean install | Setup window choice; `FactoryReset.Apply(everything)`; `/Clean=1` |
| R7 | Logs survive a cleared Event Viewer | `EventArchive` (data\archive\, background, 90 days / 1 GB) + live Security 1102 / System 104 alert |

Architecture (owner accepted A1-A5, 2026-11-06): dashboard auto-restart, sandboxed Hayabusa/OSV, engine pipe with
drop-folder fallback, least-privilege service, engine-down banner. C# tests: 133 (1 SKIP: labelling a folder low
integrity needs WRITE_OWNER, checked live). Build 2026.11.6.1937: `TEST RESULT: OK  pass=144 fail=0 warn=5 skip=0`. New live checks (`sc qprivs`, `status.json` pipe/archive) report WARN until
the new build is installed.
Not verified on screen: the setup window in a real install, and the details pane with a selected alert (screenshots
cover Home, Activity and the three setup pages).

## Tray UI/UX audit (2026-11-06 night) - installed 2026-11-06 23:43
**Installed** with the owner's approval (2026.11.6.2333, `/VERYSILENT` upgrade, exit 0; service running, new tray
started). After the install: `TEST RESULT: OK  pass=148 fail=0 warn=1 skip=0`; the WARN is the last scan's failed
steps (Sigma no output, OSV for the Microsoft Store Python), engine side, from a scan before the install.
Build 2026.11.6.2333 (dev): `TEST RESULT: OK  pass=147 fail=0 warn=2 skip=0`. WARNs: "not the latest build installed"
and the last scan's failed steps (Sigma no output, OSV for the Microsoft Store Python; engine side, not the tray).
Checked at runtime with UI Automation on a dev tray over `synthetic-a` (edits survive refreshes, badge, discard,
expander, Undo, tile Enter/Invoke, danger-dialog Enter, persistent error messages).
| # | Finding | Fix |
|---|---|---|
| U1 | Unsaved Settings edits wiped by the 15 s refresh | `SettingsPage.HasUnsaved`: no rebuild while dirty; Save/Discard enabled only then |
| U2 | Refresh reset focus, scroll, *Technical details*, chips | `Ui.Fingerprint`: unchanged views keep their live controls; chips updated in place; scroll kept |
| U3 | Home tiles mouse-only; 4 of 5 tiles opened Home (unknown page keys) | `LinkTile` (focus, Enter/Space, UIA button); tiles open Activity filtered to the part / Network / Updates |
| U4 | Muted text 4.16:1; reviewed rows at 55 % opacity | Muted `#95A3BD`; reviewed rows use a darker card |
| U5 | Notification level instant, rest needs Save, no warning | Copy says which is which; *Unsaved* badge on Settings; leaving Settings tells the edits wait there |
| U6 | No undo for *Mark reviewed* / *It was me* | *Undo* in the message bar |
| U7 | *Update all apps* started winget at once; "Updated" looked like success | Confirmation; tab *Started here* |
| U8 | Audit export failed silently | Error message; success names the file + *Show in folder* |
| U9 | Errors vanished after 5 s, not announced | Errors stay until *Dismiss*; live region |
| U10 | Silent no-ops (logs, Velociraptor, guide, VirusTotal, file location) | Each says why; .md without an app opens in Notepad |
| U11 | "Home > Activity" in the tool-update error | "Activity > Messages" |
| U12 | Enter confirmed danger dialogs | Enter / first focus = Cancel in danger dialogs |
| U13 | Welcome window fixed size; icon buttons without accessible names | Resizable welcome with scrolling steps; `Ui.Btn` names every button |
Not verified: Narrator speech, 200 % text scaling, Windows high-contrast themes (the theme is dark only), the audit
export to a locked file (needs the file picker).

## Owner decisions still open
* Code-signing certificate for the build (P18): Azure Trusted Signing or another code-signing certificate.
* Controlled folder access allows for explorer.exe, dllhost.exe and a user-writable development build; a real-time allow of
  sihost.exe for all rules → recommended: remove the CFA allows; narrow the sihost allow to one rule.
