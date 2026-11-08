# FreeEDR user guide

Read for: end users, and agents changing anything the user sees (tray menu, dashboard pages and actions, notifications, trusted apps, user docs).

How to use the dashboard, trusted apps, games, Defender settings, troubleshooting and known limits.
Installing: [README](../../README.md#install) and §0 below. Uninstalling: [install/UNINSTALL.md](../install/UNINSTALL.md).

FreeEDR **detects and explains; it never stops, deletes or quarantines anything**. Microsoft Defender stays your
antivirus. The one part that acts is **Wail2Ban**: it blocks computers that keep failing to sign in over the network
(Remote Desktop, file sharing) in Windows Firewall, for a while. You can switch Wail2Ban to report-only.

## 0. Installing and upgrading
* Run `FreeEDR-Setup.exe` and approve the administrator prompt. A FreeEDR window (the dashboard's look) shows what will
  happen, then every step and the result. You can untick the desktop icon. If Sysmon is already installed with someone
  else's configuration, tick that FreeEDR may replace it (the old one is saved and put back when you uninstall).
* When FreeEDR is already installed, choose:
  * **Upgrade, keep everything** - settings, allow lists, trusted apps, verdicts, bans, events, logs and the event archive
    stay; only the programs change. A failed upgrade puts the previous version back by itself.
  * **Clean install, start fresh** - erases all of that (and every account's reviewed/history lists, and the learning
    week starts again), then installs as new. The record of your Windows settings from before FreeEDR is kept, so
    uninstalling still restores them.
* The tools come inside Setup; only Sysmon is downloaded from Microsoft when it is not installed. Later, FreeEDR
  downloads only updates (tool updates you start, Sigma rules and the malware hash list during scans).

## 1. The shield in the notification area
* **Green ✓** protected, nothing to review · **Amber !** something needs review or the last scan had problems ·
  **Grey II** something is paused · **Red X** protection is off or broken (engine stopped, Sysmon not working).
* **Click**: open the dashboard. **Right-click** (short menu): the status line, *Open FreeEDR*, *Scan now*,
  *Pause detection ▸* (15 minutes / 1 hour / until I resume it) or *Resume detection*, *Settings*, and *Hide the tray
  icon* (protection keeps running; it comes back at the next sign-in or from the Start menu).

## 2. The dashboard
A sidebar with six pages. A badge shows the same number as the page's first tab (every open item); it is red when one of
them is serious (High or Critical), otherwise grey. Home's tiles and its sentence use the same count.

* **Home**
  * One sentence about what matters now, **Scan now** and **Review alerts**; badges show *Detect-only* and the Wail2Ban mode.
  * **Was this you?** for sign-ins from the internet, cleared logs, new users/admins, Defender tampering. The same
    question asked several times is one line (×N): *Yes, it was me* (marks them reviewed; future ones are still reported)
    or *No, it wasn't me* (flags them as a threat; for an internet sign-in: *No - ban this IP*). The details pane and the
    notification use the same labels.
  * One **tile per protection** (Real-time, Anti-Malware, Event logs, Wail2Ban, Updates, Sensors & scans) with its state
    and **Pause ▸ / Resume**. Click a tile (or Tab to it and press Enter) to open its page: the detection tiles open
    Activity filtered to that part, Wail2Ban opens Network, Updates opens Updates.
  * **Learning week** banner during the first 7 days, **Suggestions** ("you keep marking this reviewed - allow it?") and
    **Your week** (alerts, bans, failed sign-ins, scans, the most frequent alerts).
* **Activity**: every alert, newest first. Tabs *To review* · *Flagged* · *Messages* (FreeEDR's own status, scans and
  the audit trail); filters *Anti-Malware* · *Real-time* · *Event logs*; search; *Show reviewed*. Identical alerts are
  grouped (×N); acting on the row acts on all of them. Each row starts with a colored tag naming the part of FreeEDR
  that caught it (REAL-TIME, ANTI-MALWARE, DEFENDER, EVENT-LOG SCAN, WAIL2BAN, VULNERABILITIES) and shows only the
  program and what started it. Select one or more rows: the **details pane** shows *Caught by* (the part and how),
  *What happened*, *What to do*, the key facts (program, started by, user, address, threat), the buttons, and a folded
  **Technical details** section (full paths, chain above it, command line, hash, event time).
  The right-click menu offers the same actions.
* **Network** (Wail2Ban): *Sign-in attempts* (failed sign-ins per address, successful sign-ins from the internet),
  *Banned* (blocked addresses, automatic or permanent), *Trusted* (addresses Wail2Ban never blocks). Top right: the mode
  and **Switch to report only / Turn blocking on**.
* **Updates**: *Vulnerabilities* (fixable Python CVEs), *App updates* (winget; *Update* asks first, then opens one winget
  window per app), *Started here* (updates started from FreeEDR - the next check shows whether they worked), and **FreeEDR tools**
  (Hayabusa, YARA, OSV-Scanner, Velociraptor: version and whether a newer one exists. *Update to x.y* works for a tool
  whose releases are digitally signed by its publisher (Velociraptor): the download must carry that signature and match
  the SHA256 fingerprint GitHub publishes, and the old version is kept if the new one does not start. Hayabusa, YARA and
  OSV-Scanner do not sign their releases, so FreeEDR does not install them from GitHub: checked versions come with
  FreeEDR updates).
* **Allowed & trusted**: *Trusted apps* (§3), *Your allows*, *Flagged*, *Ignored updates*. Removing an allow makes FreeEDR
  report it again.
* **Settings** (§6).

### Actions (buttons and right-click menu)
* **Flag as threat / Confirm as threat**: records your verdict (moves to *Flagged*). Nothing is stopped: use **Scan with
  Microsoft Defender** (a Defender scan of that file in a window you can watch; Defender removes what it finds) and
  **Look up on VirusTotal** (only the file's SHA256 leaves the PC).
* **Ban IP** (Wail2Ban): a permanent firewall block until you unban it (recorded only, when Wail2Ban is report-only).
* **Allow** (no more alerts for it). More precise variants: *Allow for this rule only*, *Allow everything X starts* (any
  version; tied to X's digital signature when it has one), *Allow everything signed by …* (refused for Microsoft
  Windows / Microsoft Corporation), *Allow X in real-time and event logs*, *Trust the network a.b.c.0/24*.
* **Trust the app: …**: shown when a trusted-app profile that is off covers the alert.
* **Mark reviewed / unreviewed**: hides or shows an alert without allowing anything. *Mark reviewed* and *Yes, it was me* show
  an **Undo** button in the message at the bottom for 10 seconds; the message stays while the mouse is on it or keyboard
  focus is in it.
* **Update now** (CVE: `python -m pip install --upgrade <package>>=<fixed>` in a window; a library bundled inside pip is
  fixed by updating pip; apps: `winget upgrade`), **Read the advisory** (NVD or OSV page).
* **Open file location**, **Copy details**.
* Changes that weaken detection (allow, flag, pause, settings) show one confirmation and one Windows administrator (UAC)
  prompt; several steps are sent together. They take effect within a few seconds. Resume and Scan now need no prompt.
  After the UAC prompt FreeEDR shows the whole change in its own window (it scrolls when the change is long); only
  **Yes** carries it out, and Enter, Esc or closing the window mean No. The dashboard waits for the real result: if it
  takes longer than 2 minutes (the window is still open, or a tool download is running) it says so and keeps waiting.
  If FreeEDR could not confirm a change in time, the message says it may still be carried out - check the lists before
  you repeat it. *Scan now* says why when no scan starts (detection paused, or a scan started less than 2 minutes ago).
* Allows hide alerts about what a program **does**. A program that is a known piece of malware (malware hash list) or
  matches a YARA rule is still reported, also when it was started by a program you allowed (*Allow everything X
  starts*); only an allow of that malware hash or YARA finding itself silences it.
* **Never allow `pwsh.exe` / `powershell.exe` itself for all rules**: that hides every PowerShell attack.

## 3. Trusted apps (no alerts for apps you trust)
Allowed & trusted ▸ *Trusted apps*, or the welcome at the first start. Switch an app on or off, **Apply changes** (enabled once a
switch differs from what is applied; one confirmation, one administrator prompt). Each app's allows are listed under *Your allows* as *Trusted app: <name>*.

| App | What is no longer reported | Default |
|---|---|---|
| Claude Code (Anthropic) | Its PowerShell tool (2 real-time + 2 event-log rules) when claude.exe signed by Anthropic, PBC started it (up to 3 levels up), or the command line is Claude Code's own launcher (exact text) | on |
| ChatGPT / Codex (OpenAI) | PowerShell started by ChatGPT.exe / codex.exe signed by OpenAI OpCo, LLC | on |
| Antigravity (Google AI IDE) | PowerShell started from its install folder (not signed, so only its folder ties the allow) | off |
| Visual Studio Build Tools (vcpkg shell) | The developer shell script loading `*vcpkg-init.cmd*` | on |
| Microsoft OneDrive | Everything from its install and per-user folders and OneDriveSetup in Downloads (per-user copies only when signed by Microsoft) | on |
| Microsoft Office updates | Click-to-Run and the scheduled tasks it creates | on |
| Google Drive | Everything from `C:\Program Files\Google\Drive File Stream` | on |
| Razer | Everything from the Razer install folders | on |
| Software installers | One-time `RunOnce` start-up entries | off (malware can use RunOnce too) |
| OEM Motherboard Boot Binary (wpbbin.exe) | The UEFI platform binary started at boot by smss.exe | on |
| FreeEDR Project Build Output | FreeEDR's own installer and build outputs | on |

"On" is applied once by the installer, only for apps found on the PC; after that only you change it.

## 4. Notifications
* Native Windows notifications with buttons: **Review**, **Mark reviewed**, **Yes, it was me**.
* **Settings ▸ Notifications** (this account only): *Only critical alerts* · *Important alerts* (default: high and
  critical detections, Wail2Ban bans, failed scans) · *Everything* (also medium alerts and every scan result). "Was this
  you?" questions, sensor problems and tool updates always notify.
* **Learning week**: for 7 days after the install only critical alerts (and "Was this you?") notify; then one summary.
* Bursts: at most 3 per minute; the rest arrive as one "N more alerts" notification.
* **Quiet mode**: while a program from *Settings ▸ Just for you ▸ Quiet while these run* runs (default: Fortnite),
  notifications wait; you get one summary afterwards. Each account has its own list (no administrator prompt).
* **Your week**: one summary notification every 7 days.

## 5. Games (Fortnite / Epic / Easy Anti-Cheat)
* Sysmon ignores everything under Epic Games, Easy Anti-Cheat, BattlEye, the Epic launcher, FortniteGame and the FreeEDR
  folder: no logging overhead, no anti-cheat false alarms. Include-only rules keep CPU and disk use near zero.
* Fortnite, the Epic launcher and Easy Anti-Cheat are pre-allowed through Defender Controlled folder access.

## 6. Settings
Every setting has an ⓘ button: point at it, or tab to it and press Enter or Space, for a plain explanation (Esc closes
it). A **Default** link appears next to a value that differs from FreeEDR's out-of-the-box value; a value that is not
valid is marked in red under the field and **Save** stays off until it is fixed. Settings reopens where you left it.

**Just for you** (your account only, applies at once): *Notify me about* (critical / important (default) / everything;
during the first 7 days only critical alerts notify), *Quiet while these run* (program names separated by commas; spaces
belong to the name, * matches anything; default: Fortnite) and *Theme* (Same as Windows (default), Dark, Light).

**PC settings** (everyone on this PC): change them; a bar pinned to the bottom of the window then shows how many settings
changed, with **Discard changes** (Esc) and **Save settings** (Ctrl+S; one administrator prompt; only the values you
changed are sent). If the settings are changed elsewhere while you edit (a reset, an import, the switch on the Network
page), the page shows the new values, keeps your own edits and says so in the bar. **Restore default settings** puts the
out-of-the-box values in the form for you to review and save. After saving the bar says *waiting for the engine* and
then *active* (within a few seconds). Unsaved changes stay in the form - also when you open another page - the Settings
button shows *Unsaved*, and hiding the tray icon asks first. Fields most people never change sit in a collapsed
**Advanced** part of their section (it shows how many of them are not at their default and remembers if you left it open):
* **Wail2Ban**: *Block attackers* (on: firewall blocks; off: only reported). Advanced: *Wrong passwords allowed* (5,
  from 2 to 1000) *within* 30 minutes; *Longest block* for internet (90 days) and home-network (7 days) addresses, chosen
  from 1 hour, 1 day, 7 days, 30 days, 90 days or 1 year; *Remote Desktop over IPv6* (allowed). The block lengths and
  the IPv6 switch are only available while blocking is on. A value in the settings file that the form cannot show
  exactly (e.g. a window of 90 seconds) is shown as such and kept until you change it.
* **Microsoft Defender** - *Ransomware & attack rules*: *Watch & report* (default: Defender's attack surface reduction
  rules and Controlled folder access report what they would have blocked; a rule that already blocked stays blocking)
  or *Leave Defender alone* (Defender's settings go back to how they were before FreeEDR; FreeEDR only reads its own
  detections). Applies right away when saved.
* **Scans**: *Scan at* (06:00 and 18:00; remove a time with ×, add one with the clock and **Add**). Advanced: *Check
  logs from the last* (2 days); *Malware list address* (the address of the hash list; **Test** downloads it and counts
  the hashes). An address with a private key or password is shown as dots (the eye button shows it) and is hidden in
  the logs.

**Backup & import**: *Back up settings* saves the PC settings, your quiet-mode list and every allow to a file (if the
malware list address holds a private key, you choose whether it goes in); *Import settings* shows what a backup would
change and applies it - the PC settings and allows with administrator approval (in steps of at most 20 changes; allows
already here are skipped, allows too broad for FreeEDR's rules are refused), your quiet-mode list without.

**Troubleshoot**: send a harmless test alert, *Open logs* (engine log, scan log, logs folder), restart the engine.
**Records & forensics**: export the audit log (CSV); *Forensics* starts Velociraptor (administrator) in a minimized
window and opens its page - a second click opens the page of the running one; close its window to stop it.
**Help**: user guide, the welcome tour again (it opens in front of the dashboard, once). *Skip tour* (or closing the
welcome window) keeps the current choices and the tour does not come back at the next sign-in.

**Danger zone**: *Reset FreeEDR to defaults* (PC settings, allow lists - also the Microsoft Defender allows added from
FreeEDR, removed from Defender - verdicts, bans, events and every account's reviewed lists; the Microsoft Defender
choice, each account's *Just for you* choices, the install date, logs and event archive stay; for a completely fresh
start use Setup's *Clean install*). The open dashboard empties its alert list at once. A Defender allow Defender would
not remove stays listed, so you can remove it later; if the reset cannot finish, the engine is started again and the
message says so.

The dashboard reopens where and as large as you left it (on a screen that is still attached; a maximized window keeps
its normal size for later).

**Event-log archive.** FreeEDR copies the Windows logs that matter for an investigation (Sysmon, Defender, sign-ins and
account changes, new services, PowerShell scripts, scheduled tasks, Remote Desktop) into
`C:\Program Files\FreeEDR\data\archive\` as it goes, compressed, one folder per day (90 days, 1 GB at most). Someone
who clears Event Viewer cannot erase what was already copied, and the clear itself is reported at once
("Event log cleared - Was this you?"). Only administrators can read or change the archive.

Every pause, resume, allow, verdict and settings change is recorded (engine log, Windows Application log Event ID 3000
from source `wail2ban`, and *Activity ▸ Messages*).

## 7. Troubleshooting
| Symptom | Fix |
|---|---|
| Red shield, "engine is not running" / Home says "The FreeEDR engine is not responding" | *Restart engine* on that banner (or Settings ▸ Restart engine). The service also restarts itself after a failure. See `data\engine.log` |
| The dashboard crashed | Windows starts it again by itself (after it ran at least a minute); otherwise Start menu ▸ FreeEDR. Protection keeps running: the dashboard is only a viewer |
| "Sysmon driver is StopPending - restart the PC" | Restart Windows |
| "Sysmon still runs an old rule set … restart the PC" | An alert used a rule name that is not in `config\sysmonconfig.xml`: the driver still uses an older config. Restart Windows |
| Many alerts from a trusted tool | Allowed & trusted ▸ Trusted apps, or on the alert ▸ *Trust the app*. Other tools: *Allow everything X starts* |
| No notifications | Settings ▸ Just for you (notification level, quiet-mode list); Windows Settings ▸ System ▸ Notifications ▸ FreeEDR; quiet-mode program running? |
| Setup says "The previous version was restored" or "Installation failed" | Read `C:\Program Files\FreeEDR\install.log` |
| You cancelled Setup before a first install | Nothing was set up; Settings > Apps > FreeEDR > Uninstall removes the leftover entry and changes no setting |
| Last scan had problems | Home ▸ Sensors & scans, or Settings ▸ Open scan log |
| A tool update failed | Activity ▸ Messages shows why; the previous version stays in place |
| Tray icon missing | Start menu or desktop ▸ "FreeEDR". For an account created after the install the tray waits until the engine created its folder (up to a minute) |

## 8. Known limits
* Detect-only: FreeEDR never stops, removes or blocks programs; Microsoft Defender's antivirus does removal. Wail2Ban
  bans block network sign-ins only.
* With Remote Desktop NLA off, RDP is reachable before sign-in: Wail2Ban reports and blocks guessing, but cannot stop
  pre-authentication exploits. Keep NLA on, or limit Remote Desktop to your LAN or a VPN.
* The IOC list is a curated, high-confidence list, not a full malware database. Defender's cloud protection covers the rest.
* The vulnerability scan covers Python packages; apps are covered through winget and Windows Update.
* Unsigned unless the build is code-signed: SmartScreen may show "unknown publisher".
* x64 Windows only. Updates need github.com and the malware hash feed; a first install without Sysmon needs
  download.sysinternals.com (Windows proxy settings are used).
* Every account on the PC can read all alerts, including other users' command lines.

## 9. Recommendations after installing
* Review Allowed & trusted ▸ *Your allows*: Controlled folder access allows for Windows programs (`explorer.exe`,
  `dllhost.exe`) or for programs in folders your account can write to weaken ransomware protection.
* Prefer *Allow for this rule only* over all-rules allows for Windows components.
* Remote Desktop: keep NLA on, or limit it to your LAN / a VPN.
