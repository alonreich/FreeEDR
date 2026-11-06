# FreeEDR user guide

Read for: end users, and agents changing anything the user sees (tray menu, dashboard pages and actions, notifications, trusted apps, user docs).

How to use the dashboard, trusted apps, games, Defender settings, troubleshooting and known limits.
Installing: [README](../../README.md#install). Uninstalling: [install/UNINSTALL.md](../install/UNINSTALL.md).

FreeEDR **detects and explains; it never stops, deletes or quarantines anything**. Microsoft Defender stays your
antivirus. The one part that acts is **Wail2Ban**: it blocks computers that keep failing to sign in over the network
(Remote Desktop, file sharing) in Windows Firewall, for a while. You can switch Wail2Ban to report-only.

## 1. The shield in the notification area
* **Green ✓** protected, nothing to review · **Amber !** something needs review or the last scan had problems ·
  **Grey II** something is paused · **Red X** protection is off or broken (engine stopped, Sysmon not working).
* **Click**: open the dashboard. **Right-click** (short menu): the status line, *Open FreeEDR*, *Scan now*,
  *Pause detection ▸* (15 minutes / 1 hour / until I resume it) or *Resume detection*, *Settings*, and *Hide the tray
  icon* (protection keeps running; it comes back at the next sign-in or from the Start menu).

## 2. The dashboard
A sidebar with six pages; red badges count what needs your review.

* **Home**
  * One sentence about what matters now, **Scan now** and **Review alerts**; badges show *Detect-only* and the Wail2Ban mode.
  * **Was this you?** cards for sign-ins from the internet, cleared logs, new users/admins, Defender tampering:
    *Yes, it was me* (marks it reviewed; future ones are still reported) or *No, it wasn't me* (flags it as a threat; for
    an internet sign-in: bans the address).
  * One **tile per protection** (Real-time, Anti-Malware, Event logs, Wail2Ban, Updates, Sensors & scans) with its state
    and **Pause ▸ / Resume**. Click a tile to open its page.
  * **Learning week** banner during the first 7 days, **Suggestions** ("you keep marking this reviewed - allow it?") and
    **Your week** (alerts, bans, failed sign-ins, scans, the most frequent alerts).
* **Activity**: every alert, newest first. Tabs *To review* · *Flagged* · *Messages* (FreeEDR's own status, scans and
  the audit trail); filters *Anti-Malware* · *Real-time* · *Event logs*; search; *Show reviewed*. Identical alerts are
  grouped (×N); acting on the row acts on all of them. Select one or more rows: the **details pane** shows *What
  happened*, *What to do*, the facts (program, started by, chain above it, user, hash, command line) and the buttons.
  The right-click menu offers the same actions.
* **Network** (Wail2Ban): *Sign-in attempts* (failed sign-ins per address, successful sign-ins from the internet),
  *Banned* (blocked addresses, automatic or permanent), *Trusted* (addresses Wail2Ban never blocks). Top right: the mode
  and **Switch to report only / Turn blocking on**.
* **Updates**: *Vulnerabilities* (fixable Python CVEs), *App updates* (winget), *Updated*, and **FreeEDR tools**
  (Hayabusa, YARA, OSV-Scanner, Velociraptor: version, *Update to x.y* in one click - the download is checked against the
  SHA256 fingerprint GitHub publishes and the old version is kept if the new one does not start).
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
* **Mark reviewed / unreviewed**: hides or shows an alert without allowing anything.
* **Update now** (CVE: `python -m pip install --upgrade <package>>=<fixed>` in a window; a library bundled inside pip is
  fixed by updating pip; apps: `winget upgrade`), **Read the advisory** (NVD or OSV page).
* **Open file location**, **Copy details**.
* Changes that weaken detection (allow, flag, pause, settings) show one confirmation and one Windows administrator (UAC)
  prompt; several steps are sent together. They take effect within a few seconds. Resume and Scan now need no prompt.
* **Never allow `pwsh.exe` / `powershell.exe` itself for all rules**: that hides every PowerShell attack.

## 3. Trusted apps (no alerts for apps you trust)
Allowed & trusted ▸ *Trusted apps*, or the welcome at the first start. Switch an app on or off, **Apply** (one
confirmation, one administrator prompt). Each app's allows are listed under *Your allows* as *Trusted app: <name>*.

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
* **Quiet mode**: while a program from *Settings ▸ Quiet mode* runs (default: Fortnite), notifications wait; you get one
  summary afterwards.
* **Your week**: one summary notification every 7 days.

## 5. Games (Fortnite / Epic / Easy Anti-Cheat)
* Sysmon ignores everything under Epic Games, Easy Anti-Cheat, BattlEye, the Epic launcher, FortniteGame and the FreeEDR
  folder: no logging overhead, no anti-cheat false alarms. Include-only rules keep CPU and disk use near zero.
* Fortnite, the Epic launcher and Easy Anti-Cheat are pre-allowed through Defender Controlled folder access.

## 6. Settings
Notifications apply to your account immediately. Everything else applies to the whole PC and is saved with one
administrator prompt:
* **Quiet mode** programs · **Scans**: times (default 06:00, 18:00), how far back the event-log scan looks, the malware
  hash feed.
* **Wail2Ban**: *Block attackers in Windows Firewall* or *Report only*; failed sign-ins before a ban (5) within minutes
  (30); longest ban for internet (90 days) and local (7 days) addresses; block Remote Desktop over IPv6 (off).
* **Microsoft Defender**: *Audit mode* (default: ASR rules and Controlled folder access report what they would have
  blocked; a setting that was stronger before FreeEDR is never lowered) or *Leave Microsoft Defender exactly as it is*
  (FreeEDR only reads Defender's own detections).
* **Maintenance**: send a harmless test alert, restart the engine, open the engine/scan logs, export the audit log
  (CSV), forensics (Velociraptor GUI, administrator), user guide, show the welcome again. **Reset** to defaults.

Every pause, resume, allow, verdict and settings change is recorded (engine log, Windows Application log Event ID 3000
from source `wail2ban`, and *Activity ▸ Messages*).

## 7. Troubleshooting
| Symptom | Fix |
|---|---|
| Red shield, "engine is not running" | Settings ▸ Restart engine. The service also restarts itself after a failure. See `data\engine.log` |
| "Sysmon driver is StopPending - restart the PC" | Restart Windows |
| "Sysmon still runs an old rule set … restart the PC" | An alert used a rule name that is not in `config\sysmonconfig.xml`: the driver still uses an older config. Restart Windows |
| Many alerts from a trusted tool | Allowed & trusted ▸ Trusted apps, or on the alert ▸ *Trust the app*. Other tools: *Allow everything X starts* |
| No notifications | Settings ▸ Notifications level; Windows Settings ▸ System ▸ Notifications ▸ FreeEDR; quiet-mode program running? |
| `FreeEDR-Setup.exe` says ROLLED BACK or FAILED | Read `C:\Program Files\FreeEDR\install.log` |
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
* x64 Windows only. Downloads need github.com and download.sysinternals.com (Windows proxy settings are used).
* Every account on the PC can read all alerts, including other users' command lines.

## 9. Recommendations after installing
* Review Allowed & trusted ▸ *Your allows*: Controlled folder access allows for Windows programs (`explorer.exe`,
  `dllhost.exe`) or for programs in folders your account can write to weaken ransomware protection.
* Prefer *Allow for this rule only* over all-rules allows for Windows components.
* Remote Desktop: keep NLA on, or limit it to your LAN / a VPN.
