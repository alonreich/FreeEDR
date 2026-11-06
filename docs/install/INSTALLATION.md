# Installation: target end state, prerequisites, what the installer does, verification

Read for: changes to `src\Edr.Setup` (FreeEDR-Installer.exe), `build\installer\FreeEDR-Setup.iss`, permissions,
Defender/firewall settings, the service, tray start entries, or the post-install checks. Uninstall:
[UNINSTALL.md](UNINSTALL.md). Build gates and the test loop: [agents/AGENT_WORKFLOW.md](../agents/AGENT_WORKFLOW.md).

Never run the installer or uninstaller on the owner's PC without their approval.

## 0. Target end state (acceptance checklist)
1. `C:\Program Files\FreeEDR` exists with the layout in [architecture/DATA_FILES.md](../architecture/DATA_FILES.md), owner
   Administrators. Administrators and SYSTEM: full control; BUILTIN\Users (every account, unelevated): read and execute.
   Exceptions: `inbox\` lets Users write and delete (requests are written as `.tmp` and renamed); `user\` can only be
   listed by Users, and each account's own `user\<SID>\` is modifiable by that account only (created by the installer and
   the engine, never by users); a `quarantine\` left by versions before 2026-11-06 stays SYSTEM + Administrators only.
2. `bin\FreeEDR-Engine.exe`, `bin\FreeEDR-Control.exe`, `bin\FreeEDR-Installer.exe`, `bin\tray\FreeEDR-Tray.exe` (+ its
   three native DLLs), the tools (`bin\hayabusa\hayabusa.exe`, `bin\yara64.exe`, `bin\yarac64.exe`, `bin\osv-scanner.exe`,
   `bin\velociraptor.exe`, each SHA256-pinned), `config\`, `rules\`, `docs\`, `README.md`, `version.txt`.
3. Windows service **FreeEDR** ("FreeEDR engine"): LocalSystem, automatic start, own process, restarts after 10 s / 30 s /
   60 s on failure (also on non-crash failures). Running.
4. Sysmon64 service and SysmonDrv driver running with `config\sysmonconfig.xml` (the template with `{ROOT}` replaced).
5. Tray: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\FreeEDR Tray` = `"C:\Program Files\FreeEDR\bin\tray\FreeEDR-Tray.exe"`;
   all-users Start menu shortcut "FreeEDR" (and desktop, unless `/TASKS="!desktopicon"`), target `FreeEDR-Tray.exe --show`.
6. Microsoft Defender (defenderMode `audit`, the default): the 16 ASR rules FreeEDR manages in audit mode, Controlled
   folder access in audit mode, Epic/Fortnite/Easy Anti-Cheat allowed through Controlled folder access - never lower than
   what was set before the first install. One threat-ID allow for the Inno Setup ML false positive (2147731250).
   defenderMode `untouched`: none of this.
7. Firewall: "Remote Desktop - Shadow (TCP-In)" disabled. Wail2Ban creates its own inbound block rules at run time.
8. Application event source `wail2ban` registered. Settings > Apps entry "FreeEDR" with the version.
9. `data\status.json` heartbeat fresh, every part `on`, `mode` = `detect-only`.

## 1. Prerequisites
* **Target PC**: Windows 10 1809+ / 11, x64 (Setup refuses ARM64), Microsoft Defender, internet access to github.com,
  api.github.com and download.sysinternals.com (the Windows proxy settings are used). No .NET runtime is needed.
* **Build PC**: .NET 10 SDK (`winget install Microsoft.DotNet.SDK.10`), Visual Studio 2022 Build Tools with the C++
  workload (NativeAOT linker), Inno Setup 6.3+ (`winget install JRSoftware.InnoSetup`). Optional: a code-signing
  certificate ([agents/AGENT_WORKFLOW.md](../agents/AGENT_WORKFLOW.md) §3).

## 2. Running it
* `compiled\FreeEDR-Setup.exe` (one UAC prompt). Unattended: `/VERYSILENT [/TASKS="!desktopicon"] [/ReplaceSysmonConfig=1]`.
* Setup unpacks to the admin-only `C:\Program Files\FreeEDR\setup-src`, runs
  `setup-src\bin\FreeEDR-Installer.exe install --source <setup-src> --no-pause --version <v>` in a console window, reports
  the result and deletes `setup-src`. Exit codes of the installer: 0 SUCCESS, 3 ROLLED BACK, 1 FAILED; Setup returns 0
  only for SUCCESS.
* The installer can also be run directly (elevated): `FreeEDR-Installer.exe install [--source <folder>] [--silent]
  [--no-desktop-icon] [--replace-sysmon-config] [--version <text>] [--no-pause]`.
* Log: `C:\Program Files\FreeEDR\install.log` (copy in `%TEMP%\FreeEDR-install.log`).

## 3. What the installer does (Installer.cs, in this order)
1. **Pre-flight**: elevated, x64, all setup files present; refuses a Sysmon installed under another service name; asks
   (or needs `--replace-sysmon-config` when silent) before replacing a foreign Sysmon configuration.
2. **Stops the running version**: the service, the scheduled tasks of the PowerShell versions (`FreeEDR`, `EDR`, legacy
   Wail2Ban/LocalEDR tasks are disabled), every account's tray (exit event, then by process), FreeEDR's tools.
3. **Backup** of the previous programs (and PowerShell scripts of an older version) and the Sysmon config to
   `data\backup-<time>`; the newest 3 backups are kept.
4. **Copies the files** from `setup-src`; writes `version.txt`.
5. **Baseline** (first install only): `data\preinstall.json` records Defender's ASR rules, Controlled folder access,
   allowed apps, ASR exclusions, threat-ID actions, the RDP shadow rule, a foreign Sysmon (its config is exported to
   `data\sysmon-original.reg`) and whether the event source existed.
6. **Tools**: each pinned tool is downloaded from its GitHub release when missing and its SHA256 checked (Velociraptor is
   also replaced when its hash differs).
7. **Sysmon**: downloads Sysmon.zip from Sysinternals when Sysmon is not installed, checks the Microsoft signature,
   renders the config, installs (`-i`) or updates (`-c`); a rejected config is rolled back to the previous one.
8. **Settings**: loads `edr-config.json` strictly (a damaged file is restored from `.bak`), sets `installedAt` once
   (the tray's learning week), removes PowerShell-itself allows for all rules (E15) and old whole-folder game allows,
   switches the recommended trusted apps on **once** (only for apps found), rewrites hardened profiles that are on, adds
   new default profiles once; downloads the first IOC list; registers the event source.
9. **Permissions**: `icacls` as in §0 (owner Administrators, inheritance reset, Users read-only, inbox W+D, user\
   list-only, each `user\<SID>\` modify for that account).
10. **Defender** per defenderMode (§0.6); **firewall**: disables the RDP shadow rule. `data\managed.json` records the ASR
    rules, Controlled folder access apps, shortcuts, service and old tasks FreeEDR touched (lists only grow).
11. **Service** FreeEDR created or updated (§0.3); **tray** Run value and shortcuts; per-user Run values of old versions
    are removed from every account's hive.
12. **Verify**: restarts the service, waits up to 90 s for a fresh heartbeat, checks every part (engine, Sysmon, Wail2Ban,
    YARA rules compiled, Hayabusa, OSV-Scanner, all tools). All OK: removes the old scheduled tasks and PowerShell scripts
    and leftover `C:\EDR`, `C:\LocalEDR`, `C:\Wail2Ban`; result SUCCESS. Otherwise **roll-back**: the backed-up programs
    (and Sysmon config) are restored; after a PowerShell version the service is removed and its scheduled task and tray
    start come back; result ROLLED BACK.
13. **Starts the tray** for every signed-in account (a one-shot scheduled task for the Users group, unelevated) with a
    notification of the result.

A first install that fails is not rolled back step by step: Settings > Apps > FreeEDR > Uninstall removes what it set up.

## 4. Verification after an install
```
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1     # unelevated; 05-Live checks the installed copy
Get-Service FreeEDR, Sysmon64
Get-Content "C:\Program Files\FreeEDR\data\status.json"
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='wail2ban'} -MaxEvents 5
```
Then: dashboard opens from the Start menu; Settings ▸ *Send a harmless test alert* appears in Activity within seconds
(rule "PowerShell download or in-memory execution").
