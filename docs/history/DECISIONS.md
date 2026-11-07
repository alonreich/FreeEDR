# History, review findings and the owner's decisions

Read for: understanding **why** something is built a certain way before changing it, or when a finding ID (C1, E2, W7,
Q11, A4, …) is mentioned. Not needed for routine fixes. Current open items: [STATUS.md](STATUS.md).

> **Corrections (doc audit 2026-11-02).** Some rows below describe the intent of a change more than the code. As the code
> stands: the process cache TTL is 2 minutes (F5 says 30 s); the YARA cache is keyed on path + last-write time, not SHA-256
> (F6); OSV output is read as one JSON document, not streamed (F7); Hayabusa keeps the newest 2,000 rows (F7 says 200;
> Q10 is current); inbox file names are not validated and requests are written without BOM (F4). Keep the rows as the
> historical record; the current behaviour is in the `docs\engine\` and `docs\architecture\` files.

## 1. Origin
* **C:\Wail2Ban**: a Windows port of fail2ban (glasnt, 2012) with local fixes. It ran as SYSTEM via the task
  `start wail2ban onstartup`, used WMI `Win32_NTLogEvent` for 4625 and `netsh` for bans. There was no GUI.
* **C:\LocalEDR**: a Sysmon tray watcher (`Watcher.ps1`, task `LocalEDR-TrayWatcher`) plus a daily scan
  (`UpdateAndScan.ps1`, task `LocalEDR-DailyScan`) with Hayabusa, YARA, OSV-Scanner, an abuse.ch hash feed and Velociraptor.
* **C:\EDR** (2026-10-31 to 2026-11-02): the merged EDR + Wail2Ban, task `EDR`. Renamed to **FreeEDR** and moved to
  `C:\Program Files\FreeEDR` (E17).

## 2. First review (2026-10-31)
| ID | Finding | Decision → result |
|---|---|---|
| C1 | Both folders were writable by Authenticated Users and the Codex sandbox group, yet their scripts ran as SYSTEM/elevated (privilege escalation) | **Accepted** → admin-only ACL, UAC for weakening actions |
| C2 | RDP open on a Public network with NLA off | **Declined** (a remote client needed NLA off) → documented; LAN/VPN scoping recommended |
| C3 | Wail2Ban had banned 127.0.0.1 and a Hyper-V/WSL address (36 strikes) | **Declined** auto-whitelisting private ranges ("127.0.0.1 should never RDP") → instead W7 caps private bans at 7 days |
| W1 | Self-whitelist and unban used regex/substring matching (10.0.0.1 matched 10.0.0.15) | Accepted → exact matching |
| W2 | Errors never reached the log file | Accepted → every level logged |
| W3 | Log was ~95% repeated startup lines | Accepted → one start line, auto-trim |
| W4 | Full firewall enumeration after every event | Accepted → once per minute |
| W5 | Only 4625, IPv4 | Accepted → + RdpCoreTS 140, IPv6 parsing, de-duplication |
| W6 | Broken `wail2ban_htmlgen.ps1` | Accepted → removed (replaced by the dashboard) |
| W7 | Ban escalation reached 90 days quickly, even for LAN | Accepted → private/LAN cap 7 days |
| T1 | Tray watcher task had a 72 h time limit, so it was killed after 3 days | Accepted → single SYSTEM task, no limit, watchdog |
| T2 | Daily scan skipped if the PC was off at 12:00 | Accepted → catch-up scheduling in the engine |
| T3 | No health monitoring | Accepted → heartbeat, Sysmon self-check, red shield |
| G1–G7 | Frozen tray during scans, no Wail2Ban UI, one-click "STOP all", Notepad log, no status icon, Fortnite alerts dropped, unreadable balloons | Accepted → the current tray/dashboard |
| S1 | Detect-only; Defender under-used | Accepted → ASR + Controlled folder access |
| E1 | "IEX" matched **msIEXec**, "-enc" matched "-encoding" | Fixed → image-scoped, space-delimited patterns (`Encoded PowerShell command`, `PowerShell download or in-memory execution`) |
| E2 | Any command line containing `C:\LocalEDR\` was ignored (trivial evasion) | Fixed → only FreeEDR's own scripts are ignored, identified by parent/command line pointing at the admin-only `$Root\EDR-*.ps1` (still a string match: see `AI_AGENT_PROMPT\1-*`) |
| E3 | The whole development folder was excluded (invisible) | Fixed → blanket exclusion removed; specific exclusions through right-click. The development folder is watched like any other folder |
| E4 | abuse.ch MalwareBazaar export returned HTTP 410; the HTML error page was saved as the hash list (0 hashes) | Fixed → Neo23x0 signature-base feed with threat names; download validated (≥100 hashes) before replacing |
| E5 | `ransomware.yar` contained "404: Not Found" | Fixed → real rules (backup destruction, embedded ransom note) |
| E6 | The Sigma scan never produced output; only the last 5 hits; each rule title alerted only once forever | Root cause: **Hayabusa 4.x renamed `csv-timeline` to `dfir-timeline`**; also needs its own folder as working directory. Fixed → `dfir-timeline -l -w -m high --time-offset 2d`, dedupe by rule+computer+channel+record |
| E7 | Only 7 Sysmon rules | Fixed → curated include-only config (validated on Sysmon 15.22 / schema 4.91): process, network LOLBins, drivers, LSASS access, Startup folder, registry persistence, WMI; game-safe |
| E8 | Patch check reported only a count | Fixed → one row per app with Update / Update all / Hide |
| E9 | Duplicate binaries and zips; tools never updated | Fixed → leftovers removed, version check every scan shown as "EDR tool update" |

## 3. Second review (2026-11-01 / 02)
Context: the "credentials / LSASS" alerts were analysed first. All were false positives from AI-assisted development: an
old LocalEDR rule matched the word "MiniDump" in a `grep`, and Defender/AMSI blocked test scripts that contained
credential-tool strings (Hayabusa then repeated those Defender detections as Sigma alerts). No LSASS rule was weakened, and
no Defender exclusion was added.

| ID | Finding | Decision → result |
|---|---|---|
| E10 | Sysmon kept running the old LocalEDR rules after the config was applied (stuck driver), producing 400+ unexplained alerts | Fixed → the engine compares alert rule names with `sysmonconfig.xml` and reports "restart the PC"; retired-rule alerts are hidden as reviewed |
| W8 | Successful network logins from public IPs were only visible hours later as Sigma SMB alerts (a phone over mobile data) | Accepted → live 4624 (type 3/10) watcher, High "Was this you?" alert in Wail2Ban |
| E11 | Claude Code's PowerShell tool raised 2 High alerts per command; an "allow everything started by claude.exe" or "allow pwsh.exe" would hide credential theft run through it | Fixed → *Allow Claude Code*: only those 2 EDR + 2 Sigma rules, claude.exe up to 3 levels up (process chain read live, PID reuse checked, stored as `ancestors`), valid Anthropic signature; generic "started by" allows also carry the parent's signature |
| E12 | Run-key noise from OneDrive / Google Drive / Razer at every sign-in; the user's OneDrive allow was version-pinned and for all rules | Fixed → versionless allows (now the trusted-app profiles) and the pinned one replaced |
| E13 | Velociraptor 0.77.3 available; its asset is now `.exe.gz`; installer never upgraded existing tools | Fixed → gzip support, pinned 0.77.3 (GitHub digest verified), safe in-place upgrade with roll-back |
| E14 | "Sysmon sensor is not working" never got its "healthy again" when a reboot fixed it | Fixed → last Sysmon health kept in `state.json` |
| E15 | Real-time allows of `pwsh.exe` (Program Files, Windows PowerShell and a user-writable Codex copy) for all rules hid every PowerShell attack | Fixed → installer removes such allows without a parent or signer (WARN line) |
| E16 | Installing meant copying a folder and starting PowerShell elevated by hand; no checks before an install | Added → `build.cmd` / `dev_build.cmd`: gates, then one Inno Setup installer `compiled\FreeEDR-Setup.exe` that runs `Install-EDR.ps1` (a standard installer package, not a program carrying hidden payloads, so antivirus scans every file); exit codes and `-NoPause` |
| E17 | Owner's decision: official name **FreeEDR**; production in `C:\Program Files\FreeEDR`, development in the repository folder, no files anywhere else | Done → `$Root` in Program Files; tray files in `user\`; downloads in `data\download`; Velociraptor datastore in `data\velociraptor`; task / tray / shortcut / mutex / installer names `FreeEDR`; build temp files and NuGet caches in `obj\`; the installer moves an install from `C:\EDR` and removes the old one after verification |
| C4 | RDP shadow firewall rule open to any address | Accepted → disabled by the installer |
| — | Sigma bug in the PowerShell tray: a confirmed rule with exactly one matching event showed an empty "Matches" column | Fixed (one PSCustomObject has no `.Count`) |
| — | Python CVEs listed are all inside pip's own bundled libraries (pip 26.2.2 is the newest) | No action possible → they clear with a future pip release, or Ignore in the CVE tab |
| — | Controlled folder access allows for explorer.exe, dllhost.exe and a user-writable development build; a real-time allow of sihost.exe for all rules | **Open** (owner's decision) → recommended: remove the CFA allows; narrow the sihost allow to one rule |

## 4. Third review: architectural hardening and UX overhaul (2026-11-02)
| ID | Finding / Area | Category | Decision → Result |
|---|---|---|---|
| F1 | `Global\FreeEDR-Engine` mutex lacked an ACL; an unprivileged process could squat it | Security & Concurrency | **Fixed** → `MutexSecurity` ACL (SYSTEM + Administrators); live-process check for abandoned/squatted mutexes |
| F2 | External tool executions interpolated command strings | Security & Boundaries | **Fixed** → argument arrays (`& $exe @args`) |
| F3 | WinForms UI thread blocked during event polling and model updates | Concurrency & UI | **Fixed** → `DoEvents()` in long loops (re-entrancy risk: `AI_AGENT_PROMPT\8-*`) |
| F4 | Inbox command processing: race conditions, unbounded size | Boundaries & IPC | **Fixed** → `.tmp` → rename, 64KB limit, 25 files per sweep |
| F5 | Process ancestor queries without caching | Resources & Concurrency | **Fixed** → `$script:ProcCache` |
| F6 | YARA scanned large files; `events-*.jsonl` accumulated | Resources & Streams | **Fixed** → YARA result cache, 50MB limit; 5 rotated event files kept |
| F7 | Hayabusa and OSV outputs loaded entirely into memory | Resources & Streams | **Fixed** → Hayabusa CSV streamed into a bounded queue |
| UX1 | All-or-nothing pause | UI/UX & Controls | **Implemented** → per-part pause/resume for 6 parts with scope descriptions and Event ID 3000 audit |
| UX2 | Inconsistent tab terminology and buttons | UI/UX & Flow | **Implemented** → 3 standard lists per section, unified actions |
| UX3 | Network login alerts needed deep navigation | UI/UX & Guidance | **Implemented** → "Was this you?" triage banner |
| UX4 | No visible audit history | Forensics | **Implemented** → Forensics & Action History with CSV export and Event ID 3000 |
| UX5 | Audit CSV export to admin-only `data\` failed | Permissions & I/O | **Fixed** → Save dialog, default Documents |
| UX6 | Triage card showed success even when UAC was dismissed | UI State | **Fixed** → success only after a verified UAC return code |
| UX7 | UAC wait blocked the UI (`WaitForExit(15000)`) | UI Responsiveness | **Fixed** → `DoEvents()` polling loop every 50 ms |
| UX8 | `&` in buttons/menus became accelerators | Microcopy | **Fixed** → `UseMnemonic = $false`, `&&` in menus |
| UX9 | Empty-state placeholders clipped / unreadable | Visuals & A11y | **Fixed** → column 0, `#646464` (5.9:1) |
| UX10 | Generic "Blocked" tab misleading for CVE/App Updates | Microcopy | **Fixed** → CVE `Detected / Updated / Ignored`, Apps `Available / Updated / Hidden` |

Also in this milestone: keyboard focus rectangles on section tabs and Overview tiles (TabStop, Enter/Space), defensive
clipboard handling with a "Details copied" toast, ASCII tokens instead of emoji in triage headers.

## 5. Fourth review: QA defects, false positives, detect-only (2026-11-02)
Owner decisions: FreeEDR only **detects and logs** in every category for now, and the apps the owner works with (AI coding
assistants, OneDrive, …) must run without alerts out of the box, switchable back at any time.

| ID | Finding | Decision → Result |
|---|---|---|
| Q1 | OSV scan wrote into `data\download`, which every install deletes: the CVE step "succeeded" with 0 results and emptied the CVE tab | **Fixed** → the scan creates the folder; a folder without a readable result fails the step and the previous CVE list is kept |
| Q2 | Engine start copied a Real-time pause into the master pause | **Fixed** → leftover migration removed |
| Q3 | `Get-CachedProcess([int]$Pid)` always threw (`$PID` is read-only), so parents above the direct parent were never checked | **Fixed** → `$ProcId` |
| Q4 | Resume of one part while the master switch was paused did nothing but reported success | **Fixed** → the tray offers to resume the master switch instead |
| Q5 | Shield stayed green while one part was paused | **Fixed** → overall status lists every paused part (tray and C# model) |
| Q6 | `inbox\` permission (W) did not allow renaming the request file | **Fixed** → (W,D); the tray deletes a failed `.tmp`, the engine removes leftovers after 2 minutes |
| Q7 | Audit CSV export wrote into the admin-only `data\` | **Fixed** → Save dialog |
| Q8 | Garbled triage button text | **Fixed** → plain text |
| Q9 | Audit details read from a non-existent `extra` object | **Fixed** → read from the event itself |
| Q10 | Sigma hits beyond the newest 200 were silently dropped | **Fixed** → 2,000 kept; more marks the step as failed |
| Q11 | Engine restart replayed failed logons (duplicate events, possible re-ban) | **Fixed** → replay only refills the counter |
| Q12 | Real-time pause did not pause blocklist enforcement | **Fixed** |
| Q13 | `Write-EngineLog` called before it was defined | **Fixed** |
| Q14 | Very large multi-row actions exceeded the command-line limit with a misleading message | **Fixed** → "select fewer items" |
| FP | Live false positives (Claude Code, ChatGPT/Codex, Antigravity, vcpkg shell, OneDrive, Office Click-to-Run, Google Drive, Razer, installer RunOnce, FreeEDR's own Run-key write) | **Trusted-app profiles**; FreeEDR's own Run-key write skipped by the engine; realtime allows gained `detail` (command-line wildcard) because short-lived launchers are often gone before their parent can be looked up. In testing, 67 of 73 real-time alerts on a development PC were covered |
| D1 | Detect-only | `enforce` (default false): no process kill, quarantine, Wail2Ban/permanent bans (threshold reported as "Password guessing"), no new IPv6 RDP rules; Block verdicts become "Flag" (lists named Flagged); Defender ASR + CFA in Audit mode, their audit events listed as Low |

## 6. Fifth review: installation, other users, uninstall (2026-11-02)
Owner decision: fix all findings (every account gets the tray and can read all alerts; desktop icon for all users,
optional; uninstall without a record of the original settings removes FreeEDR's ASR rules and turns Controlled folder
access off; proxy-aware downloads instead of bundling the tools).

| ID | Finding | Result |
|---|---|---|
| A1 | ACL, Run value, shortcut and tray start used the account that approved the UAC prompt | Group-based ACL, HKLM Run, all-users shortcuts; tray started per signed-in user through a one-shot Users-group task |
| A2 | Only the installing user could read the folder or get a tray | BUILTIN\Users read; private `user\<SID>\` per account |
| A3 | An upgrade by another admin removed the previous user's write access | Fixed by A2 |
| A4 | Detect-only install lowered existing Defender protection | Never lower a setting that was stronger before the first install |
| A5 | A failed first install left changes behind | Settings > Apps entry always registered |
| A6 | `data\backup-*` grew forever | Newest 3 kept |
| A7 | Unqualified `powershell.exe` in task, Run, shortcut | Full path |
| A8 | Scripts ran elevated from the user's `%TEMP%` | Unpacked to admin-only `$Root\setup-src` |
| B1 | Not in Settings > Apps, no version | Inno uninstaller entry; `version.txt` |
| B2 | Start menu shortcut only for one account, no desktop icon | All-users Start menu + desktop |
| C1 | No uninstaller | `Uninstall-EDR.ps1` |
| C2 | Defender allows stayed after uninstall | Recorded in `preinstall.json`, restored / removed |
| C3 | RDP shadow rule stayed disabled | Re-enabled when it was on before |
| C4 | Sysmon removal optional and blind; a foreign Sysmon config overwritten unsaved | Removed only when FreeEDR installed it; otherwise saved and restored |
| C5 | Event source `wail2ban` stayed | Removed unless it existed before |
| C6 | Manual uninstall incomplete | Replaced by the uninstaller |
| D1 | No proxy support, GitHub API rate limit | Windows proxy for curl, `--ssl-revoke-best-effort`, release-page fallback |
| D2 | ARM64 accepted but broken | x64 only |
| D3 | A Sysmon under another service name made the install fail late | Pre-flight check; foreign `Sysmon64` config only replaced with permission |
| D4 | AllSigned / scripts off / Constrained Language failed obscurely | Setup and Install-EDR refuse with a clear message |
| D5 | Microsoft Entra ID accounts (S-1-12-1-…) skipped by the CVE scan | `Get-UserAccounts` includes them |
| D6 | `C:\Users` / `C:\Program Files` hard-coded in profiles and game allows | `$ProfilesRoot`, `$PF`, `$PF86` |
| D7 | Closing the installer window with X showed FAILED | Setup always passes `-NoPause` |
| D8 | Sysinternals license accepted silently | Named and linked on Setup's welcome page |

## 7. Test bundle, first runs (2026-11-02)
| ID | Finding | Status |
|---|---|---|
| T1 | Trusted apps window: "Select recommended" and "Apply" were `GetNewClosure()` handlers and could not call script functions | **Fixed** → handlers use `.Tag` / `$this` |
| T2–T7 | Sysmon rule gaps, launcher-text spoofing, noisy Sigma rule, PenTest placeholder | See [STATUS.md](STATUS.md) |

## 8. Milestones
* **2026-11-01**: LSASS alerts analysed (all false positives, no rule weakened); stale Sysmon rule set detection; internet
  logins ("Was this you?"), signature-tied allows, *Allow Claude Code*, Sigma allows per parent, Defender de-duplication;
  Run-key noise, pinned OneDrive allow, all-rules PowerShell allows, `scanTime` and the RDP-shadow rule cleaned up;
  Velociraptor 0.77.3; `build.cmd` / `dev_build.cmd` and the single-file installer; renamed to FreeEDR; C# tray phases 0–1.
* **2026-11-02**: architectural hardening + UX overhaul (§4); QA + detect-only + trusted apps (§5); installation review
  (§6); test bundle (§7); documentation split into `docs\` with `project_structure.txt` as the agent entry point.
* **2026-11-04**: installation verification & false positive defaults: installer probe-checks all 6 protection blades before declaring success; post-installation completion toast notification; default trusted-app profiles for vcpkg developer shell wildcard scripts, OEM motherboard boot binary (`wpbbin.exe`), and FreeEDR project build outputs (`FreeEDR-Setup*.exe`, `FreeEDR-Tray*.exe`) across all directories.
* **2026-11-06**: migration to C# 14 / .NET 10 / Avalonia, all NativeAOT, and the 20 improvement proposals (§9).

## 9. Product review: detect-only polish and the C# migration (2026-11-06)
Owner decisions: FreeEDR is **log and detect only; Wail2Ban is the only part that enforces**. "Address and resolve all 20
proposals" and "migrate the app entirely to C# 14 .NET 10 Avalonia, all NativeAOT, with a darker blue (not too dark)
theme and clear, professional buttons".

| ID | Proposal | Result |
|---|---|---|
| P1 | Remove the `enforce` mode | Done: no process kill, quarantine or block enforcement anywhere; `enforce` is dropped from the settings; verdicts only flag; Defender ASR/CFA never in block mode. Legacy quarantined files are restored when their verdict is removed |
| P2 | Make Wail2Ban consistent, with its own switch | Done: `wail2ban.block` (block / report only) in Settings and on the Network page; permanent bans re-applied whenever blocking is on; IPv6 RDP rules behind `wail2ban.blockRdpIpv6` (off) |
| P3 | Fix docs and labels about the firewall | Done: every doc rewritten for detect-only + Wail2Ban |
| P4 | Option to leave Defender untouched | Done: `defenderMode` = `audit` (default) / `untouched`; switching applies or restores Defender at once |
| P5 | Follow-up actions without blocking | Done: *Scan with Microsoft Defender* (MpCmdRun custom scan), *Look up on VirusTotal* (hash only), *Open file location* |
| P6 | Simpler dashboard | Done: Home / Activity / Network / Updates / Allowed & trusted / Settings, one details pane, filter chips |
| P7 | Smaller tray menu | Done: status, Open, Scan now, Pause detection ▸, Settings, Hide |
| P8 | Native notifications with buttons, rate limit | Done: WinRT toasts (AUMID per user), Review / Mark reviewed / Yes it was me, 3 per minute + digest |
| P9 | One notification setting | Done: critical / important / all, per account |
| P10 | First-run welcome | Done: 3 steps (what it does, trusted apps, notification level) |
| P11 | Updates in one place, not counted in the shield | Done: Updates page (CVE + apps + tools); attention counts only detection |
| P12 | Remove Gemini | Done: *Read the advisory* (NVD / OSV) instead |
| P13 | Native C# tray | Done, and the whole product: engine service, control helper, installer, tray |
| P14 | Fix T2-T4 | Done in the Sysmon template; corpus tests pass (Sysmon's acceptance verified at the next install, STATUS T8) |
| P15 | Suggest allowing after 3 reviews | Done: Insights (per account) on Home and in the details pane |
| P16 | Learning week | Done: 7 days from `installedAt`, critical-only notifications, banner, wrap-up notification |
| P17 | Weekly summary | Done: Home card + weekly notification |
| P18 | Code signing | Build support done (`EDR_SIGN_THUMBPRINT` or Azure Trusted Signing); needs the owner's certificate |
| P19 | One-click tool updates | Done: `update-tool` via the elevated helper; GitHub SHA256 digest required; roll-back if the new copy does not run |
| P20 | Fix the live permission test | Done: ReadAndExecute is not write access; only write/delete/ACL rights fail |

Other changes in the migration: the scheduled task became the Windows service "FreeEDR" (restart on failure); event log
bookmarks through `EvtSubscribe`/`EvtCreateBookmark` instead of reflection; the scan runs inside the engine; firewall
rules are read from the firewall's registry store; the installer no longer adds the `FreeEDR-Setup.exe` Defender process
exclusion (a name-based exclusion any program could use) and removes it from existing installs - only the specific
Inno Setup threat-ID allow stays; AllSigned / Constrained Language PowerShell policies no longer block FreeEDR.

## 10. Pre-ship architectural audit and owner requests (2026-11-06)
Owner: "fix all" findings of the pre-ship audit, then seven requests. Details: [STATUS.md](STATUS.md).

| ID | Finding / request | Decision and result |
|---|---|---|
| S1 | Elevated helper trusted any caller's payload and `--root` | No `--root` in the helper or installer; the helper shows the decoded request in its own elevated Yes/No window (UAC only names the program) |
| S2 | Engine queue dropped events silently | 10,000-item queue with backpressure in the event-log callback; counted, alerted drops |
| S3 | Scan thread and engine loop shared `EngineState` | One re-entrant lock |
| S4 | Tray did I/O and model building on the UI thread | Worker refresh, published snapshot |
| S5 | Signer cache key could be kept after an in-place rewrite | NTFS change-journal number in the key |
| S6 | YARA parsed attacker files as SYSTEM | `Native\Sandbox` (low integrity, no privileges, Job object), no unsandboxed fallback. Hayabusa and OSV-Scanner still run with the engine's rights (open) |
| L4 | Stale bookmark (15011) left Sysmon/Defender unwatched after a cleared log | Treated as a rejected bookmark: restart from now with "Events may have been missed" |
| R1 | Setup in the app's look, no console | FreeEDR-Installer.exe is an Avalonia window; Inno Setup shows no pages of its own |
| R2 | Ship the baseline, download only updates | **Reverses §6 ("downloads instead of bundling")**: the pinned tools and an IOC seed ship inside Setup (~100 MB); Sysmon is still downloaded because the Sysinternals license does not allow redistribution; tools already installed are never downgraded |
| R4 | Clear which part caught an alert, less clutter | Module tags, one-line rows, "Caught by", folded technical details |
| R5 | Slicker, calmer look | Smaller type and spacing, tinted ok/danger buttons, flat primary |
| R6 | Upgrade vs clean install | Setup window choice / `/Clean=1`; clean = `FactoryReset.Apply(everything)`, but the pre-install record of Windows settings stays (the uninstaller needs it) and a legacy `quarantine\` (users' files) is never deleted |
| R7 | A cleared Event Viewer must not blind FreeEDR | `EventArchive` copies the important logs to `data\archive\` in the background (90 days / 1 GB, below-normal priority, paused under 2 GB free); Security 1102 / System 104 are alerted live |
| A1 | Dashboard crash leaves no tray | `RegisterApplicationRestart`: Windows restarts it after a crash or hang |
| A2 | Hayabusa / OSV-Scanner ran as SYSTEM | Sandboxed like YARA; `data\sandbox\` (low integrity) is their only writable folder; Hayabusa rule updates stay unsandboxed |
| A3 | File-based IPC between processes | Named pipe `\\.\pipe\FreeEDR-Engine` with token-based caller identity, answers and change notices; drop folders kept only as the offline queue |
| A4 | Engine with full SYSTEM rights | Still LocalSystem (needed for the Security log, firewall, Defender, Sysmon) but only the required privileges (`EdrPaths.EnginePrivileges`) and a service SID |
| A5 | Dashboard silent when the engine is down | Home banner with *Restart engine* / *Open engine log* |
| R3 | Review of this PC's alerts | All false positives or legitimate (agent edits of the Sysmon template, own test files, Office, ASUS WPBT driver); open questions to the owner: an SMB sign-in from 46.19.85.255, two log clears by `alon`, built-in accounts renamed `delete22`-`delete26` |
