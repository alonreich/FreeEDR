# FreeEDR — free home EDR + Wail2Ban for Windows 11

Free single-PC endpoint detection and response (EDR) for Windows 11, built only from free tools, with a tray icon and dashboard written for non-experts.
* Detects in real time; updates and scans twice a day (06:00 + 18:00).
* **Detect-only (default):** FreeEDR detects and logs in every category and never stops, quarantines or firewall-blocks anything, so it never interrupts your work. Your verdicts *flag* items. (Setting `enforce: true` in `config\edr-config.json` brings back blocking, see §6.)
* **Trusted apps:** apps you work with (Claude Code, ChatGPT/Codex, Antigravity, OneDrive, Office, Google Drive, Razer, Visual Studio's vcpkg shell) run without alerts out of the box; one window switches each of them on or off at any time (§4, *Trusted apps*).
* Microsoft Defender's attack-surface rules and Controlled folder access run in **audit** mode: Defender reports what it would have blocked and FreeEDR lists it. Defender's own antivirus is unchanged.

| Where | What |
|---|---|
| `C:\Program Files\FreeEDR\` | **The installation** (production). Scripts, settings, data, tools, quarantine and the tray's own files. Admin-only; your account reads it |
| `<repo>\` (wherever you cloned this repository) | **The development folder**: source, docs, build scripts, the C# tray rewrite and `compiled\FreeEDR-Setup.exe` |

Install or upgrade: run **`compiled\FreeEDR-Setup.exe`** (one file; it asks for administrator rights once). Details, building and the manual way: [Installation_Process.md](Installation_Process.md). Current state of the project: [§10](#10-status-2026-11-02).

---

## 1. What protects you (the "blades")

Each alert names the part of FreeEDR that caught it (**"Caught by"**). Every alert can be excluded in exactly that part with a right-click.

| Blade (as shown in the GUI) | What it does | When | Source |
|---|---|---|---|
| **Real-time (Sysmon)** | Watches process starts, risky Windows tools, LSASS (password store) access, persistence (Run keys, Startup folder, Winlogon, IFEO, WMI), unsigned drivers, Defender tampering, log clearing | Instantly | Sysmon + `config\sysmonconfig.xml` |
| **Malware hash (IOC)** | Compares the SHA256 of every program behind a real-time alert with a list of known-malware hashes | Instantly | Neo23x0 signature-base (≈1,200 curated SHA256s, with threat names), refreshed twice a day |
| **YARA file scan** | Scans the program behind every real-time alert for credential-theft tools and ransomware patterns | Instantly | `rules\custom_edr.yar`, `rules\ransomware.yar` |
| **Event-log scan (Sigma)** | Runs thousands of community Sigma rules over the last 2 days of Windows event logs (high and critical only) | Twice a day (06:00 and 18:00), or "Update now" | Hayabusa 4.3.1 (rules updated each run) |
| **Vulnerability (CVE)** | Finds known-vulnerable Python packages. **Only vulnerabilities that have a released fix are listed**; patched packages disappear at the next run | Twice a day | OSV-Scanner 2.7.0 |
| **App updates (winget)** | Lists installed apps that have updates, one row per app | Twice a day (same times) | winget (in the tray) |
| **Microsoft Defender** | Shows Defender malware detections, and what ASR / Controlled folder access blocked or (audit mode, the default) would have blocked | Instantly | Defender Operational log |
| **Wail2Ban (password guessing)** | Reports an IP after 5 failed network logons in 30 minutes ("Password guessing", notified); reports successful logins from the internet. Firewall bans only with `enforce: true` | Instantly | Security 4625 / 4624 + RDP 140 events |
| **EDR health** | Engine heartbeat, Sysmon service/driver health and stale rule sets, scan problems, pause/resume | Continuous | The engine itself |

### Granular Per-Rubric Pause/Play & Forensics
Protection controls are granular: each rubric can be paused and resumed independently (for 15 minutes, 1 hour, or until resumed) from its tab banner, dashboard overview tile, or tray context menu:
* **Anti-Malware (`malware`)**: Pauses IOC malware hash lookups and YARA file scanning. Real-time Sysmon process tracking, firewall bans, and Defender remain fully operational.
* **Real-time EDR (`realtime`)**: Pauses real-time Sysmon process tracking and live blocklist enforcement. Scanners, firewall rules, and Defender remain active.
* **Sigma (`sigma`)**: Pauses scheduled and manual Hayabusa event-log scanning. Real-time EDR, Anti-Malware, and Wail2Ban remain active.
* **CVE (`cve`)**: Pauses OSV vulnerability checks of Python packages. All other protections remain active.
* **Wail2Ban (`wail2ban`)**: Pauses failed logon tracking and new automated firewall bans. Existing bans stay active until expiration.
* **Master EDR Switch (`edr`)**: Pauses all real-time EDR detection, blocking, YARA, IOC, Sigma, and CVE scans simultaneously.

**Forensic Audit Logging (Event ID 3000):** Every pause and resume action produces an immutable audit record in both `data\engine.log` (`[FORENSIC-AUDIT]`) and the Windows Application Event Log (Event ID 3000), logging the timestamp, affected rubric, action, duration, expiration, and user initiator.

---

## 2. How it works

```
                       ┌───────────────────────── SYSTEM (scheduled task "FreeEDR") ─────────────────────────┐
 Windows event logs ──►│ EDR-Engine.ps1                                                                      │
  • Sysmon             │  ├─ Real-time: Sysmon event → own-process filter → exclusions → stop if blocked → IOC → YARA│
  • Security 4625/4624 │  ├─ Wail2Ban: failed logon → count per IP (30 min) → firewall block (5^n minutes)  │
  • RdpCoreTS 140      │  ├─ Logins: successful network/RDP logon from a public IP → "Was this you?"        │
  • Defender           │  ├─ Defender: 1116 / 1121 / 1123 → event                                            │
                       │  ├─ Scheduler: 06:00 + 18:00 (catch-up after downtime) → EDR-Scan.ps1 (Sigma/CVE/IOC)│
                       │  ├─ Blocking: your Block/Quarantine verdicts (config\blocklist.json, quarantine\)  │
                       │  ├─ Health: Sysmon service+driver+rule set, watcher restart, heartbeat every 15 s  │
                       │  └─ Commands: control\ (admin) and inbox\ (user: resume, scan-now only)            │
                       └──────────────┬───────────────────────────────────────────────▲───────────────────────┘
                                      │ data\events.jsonl, data\status.json            │ commands (JSON files)
                       ┌──────────────▼────────────────── your session (not elevated) ┴───────────────────────┐
                       │ EDR-Tray.ps1: tray shield + dashboard + notifications + winget check (files: user\)  │
                       │ pause / exclude / block / unblock / unban → EDR-Control.ps1 via UAC → control\       │
                       └──────────────────────────────────────────────────────────────────────────────────────┘
```

* **One scheduled task, `FreeEDR`**, runs `EDR-Engine.ps1` as SYSTEM at boot. A 5-minute repeating trigger acts as a watchdog: if the engine ever exits, it is back within 5 minutes. A second copy never runs (`IgnoreNew` plus the global mutex `Global\FreeEDR-Engine`). The mutex is secured with an explicit `MutexSecurity` ACL granting FullControl only to SYSTEM and BUILTIN\Administrators, and the engine verifies live process execution if a collision occurs. Every step of the engine loop is wrapped in `Invoke-Safely`, so one bad event cannot stop it.
* **The tray** (`EDR-Tray.ps1`) starts at sign-in from `HKCU\...\Run\FreeEDR Tray`, unelevated. It reads the engine's files and writes only its own files in `user\`. It never touches protection directly. UI message dispatching (`Application.DoEvents()`) prevents interface freezing during large event stream loading.
* **Every verdict or weakening action** (pause, stop, block, unblock, allow, unallow, unban, restart engine) shows a Windows **UAC prompt**, then `EDR-Control.ps1` drops a command atomically (`.tmp` write followed by `[IO.File]::Move`) into the admin-only `control\` folder. The engine reads it (bounded to 25 files max, 64KB max with locked file retry prevention), applies it and writes the result. Only `resume` and `scan-now` can be requested without UAC (via the user-writable `inbox\` folder).
* **Caching & Concurrency:** Process ancestry lookups use an in-memory cache (`$script:ProcCache`), YARA file scans enforce a 50MB file boundary and in-memory cache (`$script:YaraCache`), and the engine drains pending events in batches of up to 50 records per cycle. Log rotation preserves the past 5 archive files (`events-*.jsonl`), and scanners use memory-safe streaming (200-item circular queue for Hayabusa and streaming JSON for OSV-Scanner).
* **C:\Program Files\FreeEDR is admin-only.** Administrators and SYSTEM have full control. Your normal (unelevated) account can read it, write requests into `inbox\` and write the tray's files in `user\`. `quarantine\` is SYSTEM + Administrators only. Other users have no access. Malware running as you cannot modify the scripts that run as SYSTEM.
* **Everything FreeEDR keeps is in that one folder** (settings, events, logs, tools, downloads in progress, the Velociraptor GUI's datastore, the tray's files). Outside it there are only Windows integrations: the Sysmon service and driver (Sysmon installs itself into `C:\Windows`), the scheduled task, the `HKCU\...\Run` value, the Start-menu shortcut "FreeEDR", firewall rules, Defender settings and the Application event source `wail2ban`.

### Alert severity and what is shown

| Severity | Examples | Notification | Counts as "to review" |
|---|---|---|---|
| Critical | malware hash, YARA match, LSASS dump/injection, shadow-copy deletion | yes (red) | yes |
| High | encoded PowerShell, download cradles, Defender tampering, unsigned driver, successful login from the internet, Sigma high | yes | yes |
| Medium | Run-key changes, LOLBin network use, "blocked program started again"; Wail2Ban bans and ASR/CFA blocks (listed under Blocked) | Wail2Ban bans, blocked-program restarts | yes, except Wail2Ban bans and Defender blocks |
| Low / Info | program run from Downloads, scan results, app updates, status | scan/health only | no |

* Identical alerts (same blade + title + program + parent) are **grouped into one row** with a count, for example "(x6)". Acting on the row acts on all of them.
* While a "quiet" program is running (default: Fortnite), notifications are held back. When it closes you get **one summary**. Nothing is lost.

---

## 3. Using it

### Tray icon (bottom-right shield)
* **Green ✓**: protected, nothing to review. **Amber !**: something needs review, or the last scan had problems. **Grey II**: something is paused. **Red X**: protection is off or broken (engine stopped, Sysmon not working).
* **Left-click**: open the dashboard (window title "FreeEDR").
* **Right-click**:
  * Status line, then **Open dashboard**
  * **Open ▸** one entry per tab (Anti-Malware, EDR, Sigma, CVE, App Updates, Wail2Ban) with its count; red = security items to review
  * **Protection Rubric Pause/Resume Menus:**
    * **Real-time EDR: On ▸** Pause for 15 minutes / Pause for 1 hour / Stop until I resume (or Resume)
    * **Anti-Malware: On ▸** Pause for 15 minutes / Pause for 1 hour / Stop until I resume (or Resume)
    * **Sigma scan: On ▸** Pause for 15 minutes / Pause for 1 hour / Stop until I resume (or Resume)
    * **CVE scan: On ▸** Pause for 15 minutes / Pause for 1 hour / Stop until I resume (or Resume)
    * **Wail2Ban: On ▸** Pause for 15 minutes / Pause for 1 hour / Stop until I resume (or Resume)
    * **Master switch (all EDR): On ▸** Pause/resume all detection blades together
  * **Update and scan now**
  * **Trusted apps (no alerts for apps you trust)...** (§4, *Trusted apps*)
  * **Advanced ▸** Send a harmless test detection, Velociraptor forensics GUI (admin; its datastore is `data\velociraptor`), Open documentation, Open engine log, Restart engine (admin)
  * **Hide tray icon** (protection keeps running; it comes back at the next sign-in)

### Dashboard
* **Top bar**: **Search** (filters every list) and **Show reviewed items**.
* **Overview tab**:
  * **Status Header**: One sentence telling you what matters right now, **Update and scan now**, **Mark all reviewed**, **Trusted apps...**.
  * **Guided "Was This You?" Interactive Triage Banner**: Whenever unreviewed high-priority alerts occur (logins from public internet, cleared event logs, account changes), a prominent triage card appears at the top with two immediate one-click actions:
    * `Yes, this was me`: marks it reviewed (future ones are still reported).
    * `X  No, it was not me`: flags it as a threat (detect-only: nothing is stopped; with `enforce: true` the IP or program is blocked).
  * **Status & Rubric Tiles**: One tile per rubric (green = all clear, amber = items waiting, red = security items to review, grey = paused) with direct **Pause... / Resume** links, plus *Sensors* and *Updates and scans*.
  * **Forensic Audit History & CSV Export**: Displays the ledger of all system actions, verdicts, and Event ID 3000 audit records, with a one-click **Export Audit Log (CSV)** button opening a `SaveFileDialog` (defaulting to Documents, avoiding admin permission issues).
* **Standardized 3-Stage Lifecycle Tabs**: Every section is standardized to identical 3-stage lifecycle tabs:

| Section | Stage 1 (Needs review) | Stage 2 (Neutralized / Actioned) | Stage 3 (Trusted / Inactive) |
|---|---|---|---|
| **Anti-Malware** | **Detected**: malware hashes, YARA hits, Defender audit reports | **Flagged**: what you flagged + what Defender blocked itself | **Allowed**: trusted file hashes & paths |
| **EDR** | **Detected**: real-time process tracking alerts | **Flagged**: programs you flagged as threats | **Allowed**: allowed programs, rules, parents, signers & trusted apps |
| **Sigma** | **Detected**: Hayabusa event-log detections | **Flagged**: confirmed attacker behaviors & threats | **Allowed**: allowed / ignored rules & parent chains |
| **CVE** | **Detected**: fixable Python package vulnerabilities | **Updated**: packages updated via pip | **Ignored**: ignored / accepted CVEs |
| **App Updates** | **Available**: winget updates available | **Updated**: applications updated | **Hidden**: hidden application IDs |
| **Wail2Ban** | **Detected**: failed logons, password guessing & public internet logins | **Flagged**: addresses you flagged (+ firewall bans with `enforce: true`) | **Allowed**: allowed IP addresses & CIDRs (/24) |

With `enforce: true` the second list is called **Blocked** and the actions block / quarantine again.

* Every list is newest first and also holds everything decided before. Identical alerts are grouped into one row "(xN)".
* **Unified Action Buttons**: Every row provides consistent, intuitive action buttons under the details pane and right-click menu:
  * **Flag as threat / Confirm as threat / Flag as hostile** (Anti-Malware and EDR / Sigma / Wail2Ban): records your verdict; the item moves to Flagged. Nothing is stopped. In CVE / App Updates the same button is **Update now** (opens a terminal updater).
  * **Allow**: adds an exclusion in that specific rubric so matching activity is trusted and not alerted on again.
  * **Trust the whole app: …**: shown when a trusted-app profile that is off covers the alert (for example Claude Code); one click trusts that app everywhere.
  * **Mark Reviewed / Mark Unreviewed**: Hides a detection without creating an exclusion (future instances are still evaluated).
* **Lifecycle Transitions**: Items can be moved smoothly across lifecycle tabs at any time (e.g. unblocking moves an item from *Blocked* back to *Detected* or *Allowed*; quarantined files are automatically restored to their original location upon unblocking).
* Windows and security components (under `C:\Windows`, Defender, the FreeEDR folder) are only stopped once, never quarantined or blocked permanently.
  * More ways to allow: *Allow everything started by … (any version)* in EDR **and Sigma**; *Allow everything started by … in EDR and Sigma* (one click for both); *Allow everything signed by <publisher>* (EDR, checked against the file's digital signature, survives updates; refused for Microsoft Windows / Microsoft Corporation). Every "started by" allow is tied to the parent's digital signature when it has one (not Windows' own tools).
  * **Claude Code** (a Trusted apps profile, §4): ignores only the rules its PowerShell tool trips, *Encoded PowerShell command* and *PowerShell download or in-memory execution* (EDR) plus *PowerShell Base64 Encoded FromBase64String Cmdlet* and *Script Interpreter Execution From Suspicious Folder* (Sigma), when claude.exe **validly signed by Anthropic, PBC** is up to 3 levels above the program (claude.exe → cmd.exe → pwsh → powershell; read from the live process list, PID reuse checked, stored on each alert as `ancestors`), or when the command line is exactly Claude Code's own shell launcher / syntax check (its short-lived `cmd.exe` is often gone before the engine can look it up). Everything else Claude Code runs is still checked by every other rule.
  * **Never allow `pwsh.exe` / `powershell.exe` itself for all rules**: that hides every PowerShell attack. The installer removes such allows (any copy, also bundled ones such as Codex's).
* **"Was this you?"** items are pinned on top of Detected: successful logins from the internet, cleared event logs, new users/admins, Defender tampering. *Yes, it was me* marks it reviewed (future ones are still reported); *No, it wasn't me* blocks the IP / program or confirms the threat.
* **Retired rules**: real-time alerts from a rule that is not in the current Sysmon config (e.g. the old LocalEDR rules) and Hayabusa's "(Sysmon Alert)" repeats are hidden as reviewed.
* **Sigma** shows the real program and the program that started it (read from the event), and Hayabusa's "Antivirus - …" / "Defender Alert" findings appear once, in Anti-Malware ▸ Quarantined (blocked by Defender), not again under Sigma.
* **Details pane** (opens when you click a row, *Close details* hides it): *What happened*, *What to do* (plain language), then the raw details. The buttons above it are the same actions as the right-click menu; the bold one is the usual choice.
* CVE extras: **Ask Gemini about CVE-…** (Gemini CLI with the prompt below) and *Ask Gemini in the browser* (prompt copied, paste with Ctrl+V). A library bundled inside pip (`pip\_vendor`) is fixed by updating pip, once pip itself ships the fixed version.

The Gemini prompt is fixed:
> I found this cve `<CVE>` on my windows os pc. 1. please explain to me in a short condensed and oversimplified way what that CVE actually is. 2. How can this CVE be taken advantage by an attacker? what prerequisites conditions must be met first for the attacker to even be able to access it and invoke this cve. 3. Please provide me the commands to resolve it in cmd as admin or powershell as admin.

Block, unblock, allow and unallow show one confirmation and one Windows UAC prompt (several steps, such as unblock + allow, are sent together). They take effect within 5 seconds.

---

## 4. Wail2Ban details

* **Counts:** failed network logons per IP from Security **4625** (RDP, SMB, any network logon with a source IP) and **RemoteDesktopServices-RdpCoreTS 140**. One RDP failure logged in both places counts once.
* **Ban:** 5 failures within 30 minutes → inbound block-all firewall rule `a a a wail2ban block IP: <ip>` (group "EDR Wail2Ban"; the names are kept so existing bans stay managed).
* **Escalation:** ban length is 5^strike minutes (5 min, 25 min, ~2 h, ~10 h, ~2 days, …). One strike is forgiven per 24 h without a new ban. Maximum is **90 days for public IPs** and **7 days for private/LAN/loopback IPs**.
* **Successful logins from the internet:** Security **4624** (logon type 3 network / 10 Remote Desktop) from a public, non-allowed address raises a **High** "Successful login as <user> from <ip> (public internet)" alert (once per address+user per 30 min), pinned as *Was this you?*.
* **Never banned:** this PC's own addresses (refreshed every 5 minutes) and anything in the whitelist (Wail2Ban tab > Allowed, or "Always allow").
* Inbound **RDP over IPv6 is blocked entirely** (rules `Block RDP IPv6 (TCP/UDP 3389)`).
* The installer disables the Windows rule **Remote Desktop - Shadow (TCP-In)** (session shadowing is not used; the rule allowed any address).
* **Pausing** Wail2Ban stops new bans. Existing bans stay until they expire or you unban them.
* Ban and unban actions are also written to the Windows **Application** log, source `wail2ban` (IDs 1000/1001/2000).

### Trusted apps (no alerts for apps you trust)
Open: tray ▸ **Trusted apps...**, or Overview ▸ **Trusted apps...**. It also opens once by itself at the first tray start after an install. Tick an app to trust it, untick it to see its alerts again, **Apply** (one confirmation, one administrator prompt). Each app's allows are listed in its tab ▸ Allowed with the type *Trusted app: <name>*.

| App | What is no longer reported | Default |
|---|---|---|
| Claude Code (Anthropic) | Its PowerShell tool (2 EDR + 2 Sigma rules), see §3 | on |
| ChatGPT / Codex (OpenAI) | PowerShell started by ChatGPT.exe / codex.exe signed by OpenAI OpCo, LLC (commands, notification sounds) | on |
| Antigravity (Google AI IDE) | PowerShell started from its install folder (Antigravity is not signed, so only its folder ties the allow) | on |
| Visual Studio Build Tools (vcpkg shell) | `iex (get-content ...\VC\vcpkg\vcpkg-init.cmd -raw)` in developer shells | on |
| Microsoft OneDrive | Everything from `C:\Program Files\Microsoft OneDrive`, the per-user OneDrive folder and OneDriveSetup in Downloads (per-user copies only when signed by Microsoft) | on |
| Microsoft Office updates | Click-to-Run service and the scheduled tasks it creates | on |
| Google Drive | Everything from `C:\Program Files\Google\Drive File Stream` | on |
| Razer | Everything from the Razer install folders | on |
| Software installers | One-time `RunOnce` start-up entries | off (malware can use RunOnce too) |

"On" is applied once by the installer, only for apps found on the PC; after that only you change it (upgrades never re-add what you switched off). FreeEDR's own start-up entry, written by its installer, is never reported. The profiles are defined in `$AllowProfiles` (`EDR-Common.ps1`).

## 5. Games (Fortnite / Epic / Easy Anti-Cheat)

* Sysmon ignores everything under Epic Games, Easy Anti-Cheat, BattlEye, the Epic launcher, FortniteGame and the FreeEDR folder. This covers process starts, LSASS access, registry and file events, so there is no logging overhead and no anti-cheat false alarms.
* The Sysmon rules are **include-only**: only suspicious activity is logged, and image-load, DNS, pipe, file-delete and similar high-volume events are off. CPU and disk use stay near zero while gaming.
* Fortnite, the Epic launcher and Easy Anti-Cheat programs are pre-allowed through Defender **Controlled folder access**.
* No ASR rule touches games. The two ASR rules most likely to disturb normal software ("untrusted executables by prevalence" and "PSExec/WMI process creation") are **audit-only**.
* Notifications are queued while Fortnite runs (see §2).

## 6. Files and folders

### Installation: `C:\Program Files\FreeEDR\`
| Path | Purpose |
|---|---|
| `EDR-Engine.ps1` | The engine (SYSTEM). Wail2Ban, real-time, logins, Defender, scheduler, health, commands |
| `EDR-Scan.ps1` | Scheduled scan (twice a day): IOC feed, Sigma rule update + Hayabusa, OSV (fixable CVEs only), tool-version check |
| `EDR-Tray.ps1` | Tray + dashboard (unelevated) |
| `EDR-Control.ps1` | Elevated helper started through UAC; validates a command and drops it in `control\` |
| `EDR-Common.ps1` | Shared paths (`$Root`), names, defaults, JSON/IP/signature helpers |
| `Install-EDR.ps1` | Install / upgrade / repair / move from `C:\EDR` / legacy migration |
| `README.md`, `Installation_Process.md` | This documentation (tray ▸ Advanced ▸ Open documentation) |
| `config\sysmonconfig.template.xml` | Sysmon rules (template; `{ROOT}` is filled in at install; nothing user-specific) |
| `config\sysmonconfig.xml` | The rendered config that is applied to Sysmon |
| `config\edr-config.json` | Settings (scan times, IOC feed, Wail2Ban thresholds, quiet programs) |
| `config\exclusions.json` | All exclusions/whitelist = the *Allowed* sub-tabs (managed by the engine; edit through the GUI) |
| `config\blocklist.json` | Your Block / Quarantine / Confirm / permanent IP block verdicts = the *Blocked* sub-tabs (managed by the engine) |
| `quarantine\` | Quarantined files (`<id>.quarantine`), SYSTEM + Administrators only |
| `rules\*.yar` | YARA rules (plain ASCII, **no BOM**) |
| `rules\ioc_sha256.txt` | Malware hash list (`sha256;threat name`) |
| `bin\` | hayabusa\ (4.3.1), yara64.exe + yarac64.exe (4.6.0), osv-scanner.exe (2.7.0), velociraptor.exe (0.77.3) |
| `data\events.jsonl` | All events (one JSON per line; rotated at 20 MB) |
| `data\scan-result.json` | Last scan output (steps with times, Sigma hits, CVEs); feeds the tab status lines |
| `data\hayabusa_last_scan.csv` | Raw Hayabusa output of the last Sigma scan |
| `data\cve-current.json` | Latest CVE scan (only fixable vulnerabilities) = the CVE tab |
| `data\status.json` | Live status for the tray (heartbeat every 15 s) |
| `data\state.json` | Pause state, scan times, dedupe memory, last Sysmon health |
| `data\wail2ban_strikes.txt` | `ip strikes epoch` per line |
| `data\engine.log`, `data\scan.log` | Logs (trimmed automatically) |
| `data\velociraptor\` | Datastore of the Velociraptor forensics GUI |
| `data\download\` | Installer downloads in progress (removed at the end of every install) |
| `data\legacy\` | Logs imported from the old C:\Wail2Ban and C:\LocalEDR |
| `data\backup-*` | Previous script versions, saved by each upgrade |
| `control\`, `inbox\` | Command drop folders (admin-only / user-writable) |
| `user\` | The tray's own files, writable by the installing user: `reviewed.txt`, `ignored-apps.txt`, `history.json` (CVE/app updates started from the dashboard), `winget.txt`, `tray.log` |
| `install.log` | Transcript of the last Install-EDR.ps1 run |

### Development folder: `<repo>\` (not installed)
| Path | Purpose |
|---|---|
| the files above | Source of truth for everything the installer copies (the `$ProjectFiles` list in `Install-EDR.ps1`) |
| `build.cmd` | Release build of the installer. `.\compiled` is wiped first and then holds exactly one file, `FreeEDR-Setup.exe`. Builds only; nothing is installed or published |
| `dev_build.cmd` | Dev build: the same checks, `.\compiled` is not wiped first, the version says "dev build" |
| `build\EdrBuild\` | The build pipeline (C#): project files, encodings, PowerShell 5.1 parse, C# tests incl. tray parity, NativeAOT tray publish, live self-test of both trays, staging, Inno Setup, single-file check. Writes `.\build.log` (first line OK / WARN / FAIL) |
| `build\env.cmd`, `nuget.config` | Keep every build file inside the dev folder: temp files, NuGet packages and the .NET CLI home go to `.\obj` |
| `build\installer\FreeEDR-Setup.iss` | Inno Setup script of `FreeEDR-Setup.exe`: unpacks the project files to a temporary folder and runs `Install-EDR.ps1` (exit 0 / 3 / 1 = success / rolled back / failed). Silent: `FreeEDR-Setup.exe /VERYSILENT` |
| `compiled\FreeEDR-Setup.exe` | The single-file installer (about 2 MB) |
| `src\` | The C# tray rewrite (.NET 10, Avalonia 12, NativeAOT; `FreeEDR-Tray.exe`), in progress and not installed yet: [docs/Tray-Rewrite-Plan.md](docs/Tray-Rewrite-Plan.md). `src\parity.ps1` compares it with `EDR-Tray.ps1` on the live data |
| `docs\` | Plans and design notes |
| `obj\`, `build.log` | Build output (safe to delete) |

### Settings (`config\edr-config.json`)
| Key | Default | Meaning |
|---|---|---|
| `scanTimes` | `["06:00", "18:00"]` | Update + scan times: IOC feed, Sigma rules + event logs, CVE, tool versions, and the winget check (missed runs start 5 min after the next engine start). The old `scanTime` key is removed by the installer |
| `sigmaLookback` | `2d` | How far back each Sigma scan looks |
| `iocFeedUrl` | signature-base hash-iocs.txt | Malware hash feed (`sha256` or `sha256;name` lines) |
| `quietProcesses` | `FortniteClient*`, `FortniteLauncher*` | Hold notifications while these run |
| `enforce` | `false` | `false` = detect-only: nothing is stopped, quarantined or firewall-blocked; Defender ASR / Controlled folder access in audit mode. `true` = block verdicts, Wail2Ban bans, Defender block mode (re-run the installer after changing it, for the Defender part) |
| `allowProfilesInitialized` | `false` | Set by the installer after it switched on the recommended trusted apps once |
| `wail2ban.windowSeconds` / `failCount` | 1800 / 5 | Ban threshold |
| `wail2ban.maxBanPublicSec` / `maxBanPrivateSec` | 7776000 / 604800 | Ban caps (90 d / 7 d) |

Edit it from an elevated editor, then restart the engine (tray ▸ Advanced ▸ Restart engine).

## 7. Microsoft Defender settings applied

Detect-only (default): all 16 ASR rules and Controlled folder access run in **audit** mode. Defender logs what it would have blocked (events 1122 / 1124); FreeEDR lists those as Low items in Anti-Malware ▸ Detected (the two always-audit rules below are not listed: they would report every new or self-built program). Nothing is blocked. With `enforce: true` and a re-run of the installer:

* **ASR rules in block mode (14):** vulnerable signed drivers, Adobe Reader child processes, Office child processes, credential stealing from LSASS, executable content from email, obfuscated scripts, JS/VBS launching downloads, Office creating executables, Office code injection, Office communication child processes, WMI persistence, unsigned USB processes, Win32 API from Office macros, advanced ransomware protection.
* **ASR audit-only (2):** untrusted executables (prevalence/age), PSExec/WMI process creation.
* **Controlled folder access:** on (audit in detect-only mode), with Epic/Fortnite/EAC pre-allowed. Blocks appear in Anti-Malware ▸ Flagged / Blocked with *Move to Allowed (allow in Defender)*. Allow only programs in admin-only folders; a program in a folder your account can write to (for example a development build) lets any malware pass by replacing it.

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| Red shield, "engine is not running" | Tray ▸ Advanced ▸ Restart engine. The watchdog also restarts it within 5 minutes. See `data\engine.log`. |
| "Sysmon driver is StopPending - restart the PC" | Restart Windows. The driver was stopped mid-way (the old LocalEDR STOP button did this). |
| "Sysmon still runs an old rule set … restart the PC" | An alert arrived with a rule name that is not in `config\sysmonconfig.xml`, so the driver still uses an older config (applied configs wait for a reboot when the driver is stuck). Restart Windows. |
| Many alerts from a trusted tool (for example an AI coding assistant running encoded PowerShell) | Tray ▸ **Trusted apps...** (Claude Code, ChatGPT/Codex, Antigravity, OneDrive, ...), or on the alert ▸ *Trust the whole app*. Other tools: EDR tab ▸ click the alert ▸ *Allow everything started by … (any version)*. Never allow PowerShell itself (§3) |
| `FreeEDR-Setup.exe` says ROLLED BACK or FAILED | Read `C:\Program Files\FreeEDR\install.log` (the same text the PowerShell window showed). ROLLED BACK = the new version did not start, the previous one is running again (for a move from `C:\EDR`: the old install there) |
| "Could not delete all of C:\EDR" during an upgrade | A file there was still in use. FreeEDR already runs from `C:\Program Files\FreeEDR`; delete `C:\EDR` after a restart |
| Last scan had problems | Overview ▸ *Updates and scans* tile ▸ Open scan log (`data\scan.log`) |
| A program you blocked is needed again | EDR (or Anti-Malware) tab ▸ Blocked / Quarantined ▸ *Move back to Detected* or *Move to Allowed*. A quarantined file is restored to its original folder |
| A program you trust is blocked by Defender | Anti-Malware ▸ Quarantined ▸ click the Defender row ▸ *Move to Allowed (allow in Defender)* |
| Tray icon missing | Start menu ▸ "FreeEDR" |
| Installer says Sysmon rejected the config | The previous config is restored automatically. Check the message, fix `config\sysmonconfig.template.xml`, rebuild and re-run the installer. |

## 9. Known limits
* Detect-only by default: FreeEDR never stops, removes or blocks anything; automatic removal is done by Microsoft Defender's antivirus. Firewall rules created by older versions (Wail2Ban bans, IPv6 RDP blocks) are left as they are. With `enforce: true`, a blocked program is stopped right after it starts (within ~5 seconds), not prevented from starting.
* FreeEDR does not change Remote Desktop settings. If Remote Desktop is on with Network Level Authentication (NLA) off, RDP is reachable before login: Wail2Ban reports password guessing and successful logins from the internet, but pre-authentication exploits cannot be stopped. Keep NLA on, or limit the Remote Desktop firewall rules to your LAN or a VPN.
* The IOC list is a curated, small, high-confidence list, not a full malware database. Defender's cloud protection covers the rest.
* The vulnerability scan covers Python packages; Windows and app patching is surfaced through winget and Windows Update.
* The installer is not code-signed, so SmartScreen may show "unknown publisher" for `FreeEDR-Setup.exe`.

## 10. Status (2026-11-02)

**Done in the QA + false-positive review of 2026-11-02** (details: Installation_Process.md §8.2d; needs a re-install to take effect):
* **Detect-only everywhere** (`enforce: false`): no process stops, no quarantine, no firewall bans; Wail2Ban reports "Password guessing"; Defender ASR / Controlled folder access in audit mode, their reports listed; verdicts *flag*.
* **Trusted apps** window + recommended profiles on by default (Claude Code, ChatGPT/Codex, Antigravity, vcpkg shell, OneDrive, Office, Google Drive, Razer), switchable at any time; alerts offer *Trust the whole app*. In testing on a real development PC, 67 of 73 real-time alerts were covered.
* 14 QA defects fixed, among them: CVE scan silently empty after every install, Real-time pause turning into a full pause after a restart, parent-chain lookup that never worked (`$Pid`), resume buttons that did nothing under the master pause, green shield while paused, resume / scan-now always asking for administrator approval, audit export that always failed, garbled triage buttons.

**Done in the release milestone of 2026-11-02** (architectural, security, and UI/UX audit):
* **Security & Concurrency Remediations (7 audit flaws resolved):**
  1. *Command Injection breakout elimination:* Strict regex whitelisting and argument-array execution across Gemini CLI, terminal launch, CVE, and winget operations in `EDR-Tray.ps1`.
  2. *Global Mutex Squatting DoS prevention:* Hardened `Global\FreeEDR-Engine` initialization with explicit `MutexSecurity` ACL (SYSTEM + Administrators only) and fallback live process inspection.
  3. *Synchronous WMI/Subprocess Starvation:* Implemented `$script:ProcCache` in `Get-Ancestors`, 50MB file size boundary on YARA scans with `$script:YaraCache`, and batch event draining (up to 50 events/cycle).
  4. *Insecure File IPC & Race Conditions:* Converted command writing to atomic `.tmp` -> `[IO.File]::Move` operations, and bounded engine command polling to 25 files max and 64KB max with locked file handling.
  5. *Tray UI Freezing:* Added cooperative UI message pumping (`[Windows.Forms.Application]::DoEvents()`) during large event stream loading in `EDR-Tray.ps1`.
  6. *Event Log Rotation & In-Memory Retention:* Implemented 5-file retention quota for historical `events-*.jsonl` archives and retained recent in-memory event buffers upon log rotation.
  7. *Scan Memory Safety:* Replaced unbounded scan loading with a 200-row streaming circular queue for Hayabusa and streaming JSON parsing for OSV-Scanner.
* **UI/UX & Forensics Enhancements (10 Audit Flaws Resolved):**
  1. *Audit CSV Export Permission Isolation:* Replaced hardcoded protected directory write with interactive `SaveFileDialog` (defaulting to My Documents), resolving `UnauthorizedAccessException` for unelevated tray users.
  2. *Triage Action Feedback Guard:* Tied triage button execution and "Threat Neutralized" toast strictly to verified UAC command issuance return codes (`Send-Ops`), preventing false success feedback.
  3. *Responsive UAC Execution:* Converted synchronous blocking process wait (`$p.WaitForExit(15000)`) in `Send-AdminCommand` to a cooperative `DoEvents()` polling loop, keeping the UI interactive.
  4. *Mnemonic Ampersand Text Rendering:* Enabled `UseMnemonic = $false` on action and triage buttons and escaped `&&` in context menus, eliminating unexpected accelerators and missing ampersands ("Block & Neutralize").
  5. *Accessible ListView Empty States:* Relocated placeholder items to Column 0 with enhanced contrast (`#646464`, 5.9:1 ratio), ensuring empty state cues are immediately visible.
  6. *Semantic Sub-Tab Nomenclature:* Aligned sub-tab labels semantically across CVE (`Detected`, `Updated`, `Ignored`) and App Updates (`Available`, `Updated`, `Hidden`) in both WinForms tray and C# Core catalog.
  7. *Tab Navigation Keyboard Focus Cues:* Implemented high-contrast `ControlPaint.DrawFocusRectangle` on custom-drawn dashboard section tabs.
  8. *Overview Tile Keyboard Navigation:* Added `TabStop = $true`, Enter/Space activation, and focus rectangle rendering on Overview rubric tiles for keyboard accessibility.
  9. *Defensive Clipboard Operation:* Wrapped row detail clipboard export in `ExternalException` handling with instant user toast feedback ("Details copied").
  10. *Glyph Fallback Rendering:* Replaced unrenderable Unicode emoji in triage headers with clean ASCII tokens (`[!]`), eliminating missing-glyph tofu boxes on native GDI.
  11. *Granular Per-Rubric Pause/Play:* Dedicated controls for Anti-Malware, Real-Time EDR, Sigma, CVE, Wail2Ban, or Master EDR, backed by `state.json` and tamper-resistant forensic audit logging (`[FORENSIC-AUDIT]`, Event ID 3000).

**Done in the review of 2026-11-01** (details and decisions: Installation_Process.md §8.2, E10–E16, W8, C4):
* LSASS / credential alerts analysed: all false positives from AI-assisted development (an old rule matching "MiniDump" in a `grep`; Defender/AMSI blocking test scripts with credential-tool strings). No LSASS rule was weakened.
* Health: a stale Sysmon rule set is now detected ("restart the PC"); Sysmon health survives engine restarts. Alerts from retired rules are hidden as reviewed.
* New: successful logins from public IPs ("Was this you?"), signature-tied allows, *Allow Claude Code*, Sigma allows per parent program, Defender findings de-duplicated between Sigma and Anti-Malware.
* Cleaned up: Run-key noise (OneDrive / Google Drive / Razer), the version-pinned OneDrive allow, all-rules PowerShell allows, the obsolete `scanTime` setting, the open RDP-shadow firewall rule. Velociraptor updated to 0.77.3.
* Build: `build.cmd` / `dev_build.cmd` and the single-file installer; renamed to **FreeEDR**, installed to `C:\Program Files\FreeEDR`.
* C# tray rewrite: phases 0 (skeleton, NativeAOT) and 1 (model, parity with the PowerShell tray) done; phases 2–5 open ([plan](docs/Tray-Rewrite-Plan.md)).

**Recommendations after installing**
* Review Anti-Malware ▸ Allowed: Controlled folder access allows for Windows programs (`explorer.exe`, `dllhost.exe`) or for programs in folders your account can write to weaken ransomware protection.
* Prefer "Allow only for rule ..." over "all rules" allows for Windows components.
* Remote Desktop: keep NLA on, or limit it to your LAN / a VPN (§9).
