# Installation_Process.md — building and installing FreeEDR from nothing (for AI agents)

Audience: AI agent / technical installer. Goal: identical end state (automation, GUI, protections). Follow steps in order; never skip verification. Read §8 before changing anything.

| Folder | Role |
|---|---|
| `<repo>\` (wherever this repository is cloned) | **Development**: source of truth, docs, build scripts, `compiled\FreeEDR-Setup.exe`. All edits, builds and build outputs happen here |
| `C:\Program Files\FreeEDR\` | **Production**: the installation (`$Root` in `EDR-Common.ps1`). Written only by the installer and the engine |

Nothing else is created on disk except Windows integrations (§0, item 10). Before 2026-11-02 the install lived in `C:\EDR` (task `EDR`, tray files in `%LOCALAPPDATA%\EDR`); the installer moves such an install (§4.2a).

---

## 0. Target end state (acceptance checklist)

When finished, all of these must be true:

1. Folder `C:\Program Files\FreeEDR` exists with the layout in §2 / README §6. Administrators and SYSTEM have full control, the installing user has read-only access, and nobody else has access. Exceptions for the installing user: `inbox\` is writable with delete (W,D: commands written atomically as `.tmp` → rename, which needs delete access; max 64KB, max 25 files drained per sweep) and `user\` is modifiable (the tray's own files). `quarantine\` is SYSTEM + Administrators only.
2. Sysmon is installed (service `Sysmon64`, driver `SysmonDrv`, both Running) with the rendered `C:\Program Files\FreeEDR\config\sysmonconfig.xml`.
3. Tools exist and match their pinned SHA256 hashes (§4.4):
   * `bin\hayabusa\hayabusa.exe` (4.3.1, plus its `rules\` and `config\` folders)
   * `bin\yara64.exe` and `yarac64.exe` (4.6.0)
   * `bin\osv-scanner.exe` (2.7.0)
   * `bin\velociraptor.exe` (0.77.3)
4. Exactly **one** FreeEDR scheduled task, `\FreeEDR`, exists (no `\EDR`). It runs as SYSTEM with highest privileges, has a boot trigger plus a time trigger repeating every 5 minutes, multiple instances = IgnoreNew, no execution time limit, and its action is `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Program Files\FreeEDR\EDR-Engine.ps1"`. Single-instance synchronization uses `Global\FreeEDR-Engine` protected with an explicit `MutexSecurity` ACL granting SYSTEM and Administrators full control, refusing unelevated denial-of-service squatting, and cross-checks live running process IDs to handle abandoned mutexes.
5. `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\FreeEDR Tray` starts `EDR-Tray.ps1` unelevated (`-STA -WindowStyle Hidden`), and the Start-menu shortcut "FreeEDR" opens the dashboard (`-Show`). No `EDR Tray` value and no "EDR Security" shortcut remain.
6. `data\status.json` has a heartbeat under 30 seconds old. In it, `edr.state` and `wail2ban.state` are `on` (with granular per-blade statuses in `edr.blades`: `malware`, `realtime`, `sigma`, `cve`), `edr.yaraRules` lists `custom_edr.yar` and `ransomware.yar`, and `edr.iocHashes` is above 1000 after the first scan.
7. Microsoft Defender: in the default **detect-only** mode (`enforce: false` in `edr-config.json`) all 16 ASR rules and Controlled folder access are in **Audit** mode (Defender reports, FreeEDR lists the reports, nothing is blocked). With `enforce: true`: 14 ASR rules in Block, 2 in Audit, Controlled folder access Enabled. Epic/Fortnite/EAC executables are allowed through Controlled folder access either way. The firewall rule `RemoteDesktop-Shadow-In-TCP` is disabled.
7b. The recommended trusted-app profiles (README §3, *Trusted apps*) are switched on once for the apps found on the PC (`allowProfilesInitialized: true` in `edr-config.json`); their exclusions carry `profile: <id>`.
8. No legacy tasks (`start wail2ban onstartup`, `LocalEDR-TrayWatcher`, `LocalEDR-DailyScan`, `EDR`) and no legacy folders (`C:\Wail2Ban`, `C:\LocalEDR`, `C:\EDR`, `%LOCALAPPDATA%\EDR`) remain.
9. Tray ▸ Advanced ▸ "Send a harmless test detection" produces a High alert "PowerShell download or in-memory execution" in the dashboard within seconds. Overview features a guided triage banner ("Was this you?") with one-click actions (`Yes, this was me` vs `No, it was not me`), and a **Trusted apps...** button. The first tray start after an install opens the Trusted apps window once.
10. Outside the two folders there are only Windows integrations: Sysmon (`C:\Windows\Sysmon64.exe` + driver, installed by Sysmon itself), the task, the `HKCU\...\Run` value, the Start-menu shortcut, firewall rules, Defender settings and the Application event source `wail2ban`.

---

## 1. Prerequisites

| Requirement | Check | Notes |
|---|---|---|
| Windows 10/11 x64 | `[Environment]::Is64BitOperatingSystem` | Built and tested on Windows 11 Pro 26300 |
| Local administrator account | `whoami /groups` shows `S-1-5-32-544` | The installer must run elevated (UAC "Yes") |
| Windows PowerShell 5.1 | `powershell.exe -c $PSVersionTable.PSVersion` | All FreeEDR scripts target 5.1 (`powershell.exe`), not PowerShell 7 |
| `curl.exe` | built into Windows 10 1803+ | Used for downloads and the GitHub API |
| Internet access | github.com, api.github.com, download.sysinternals.com, raw.githubusercontent.com | Needed only on a fresh PC and for the twice-daily feed/rule updates |
| Microsoft Defender active | `Get-MpComputerStatus` | ASR/CFA need Defender as the active antivirus |
| winget (optional) | `winget --version` | Enables the "App updates" list |
| Gemini CLI (optional) | `npm install -g @google/gemini-cli`, then `gemini` once to sign in | Enables "Ask Gemini about CVE-…". Without it, the browser fallback is used |

Only to **build** `FreeEDR-Setup.exe` (not needed to install):

| Requirement | Check | Notes |
|---|---|---|
| .NET 10 SDK | `dotnet --list-sdks` shows 10.0.x (pinned 10.0.403 in `src\global.json`, roll-forward latestFeature) | Runs `build\EdrBuild` and the C# tray tests |
| Visual Studio 2022 Build Tools with C++ | `vswhere -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64` | NativeAOT linker for the C# tray (the build adds `vswhere.exe` to PATH itself) |
| Inno Setup 6.3+ | `C:\Program Files (x86)\Inno Setup 6\ISCC.exe` | `winget install JRSoftware.InnoSetup`, or set `EDR_ISCC` to ISCC.exe |

---

## 2. The project files

`<repo>` (the repository folder) holds the source of truth. The installer copies exactly these files (the `$ProjectFiles` list in `Install-EDR.ps1`; the build reads that list, so the two never drift):

```
<repo>\
  README.md                         user + architecture documentation, current status (§10)
  Installation_Process.md           this file
  Install-EDR.ps1                   installer / upgrader / repair / move from C:\EDR / legacy migration
  EDR-Common.ps1                    shared paths ($Root = C:\Program Files\FreeEDR), names, defaults, helpers
  EDR-Engine.ps1                    SYSTEM engine (Wail2Ban, logins, real-time, Defender, scheduler, health)
  EDR-Scan.ps1                      scheduled scan, 06:00 + 18:00 (IOC feed, Hayabusa/Sigma, OSV fixable CVEs, tool versions)
  EDR-Control.ps1                   elevated command helper (UAC)
  EDR-Tray.ps1                      tray icon + dashboard
  config\sysmonconfig.template.xml  Sysmon rules template ({ROOT} placeholder; nothing user-specific)
  rules\custom_edr.yar              YARA: credential-theft tool strings (hex) + shadow deletion
  rules\ransomware.yar              YARA: backup destruction + embedded ransom note
```

The script file names keep their `EDR-` prefix; the product name is **FreeEDR** (window titles, task, tray, installer, docs).

Development-only (not installed): `build.cmd`, `dev_build.cmd`, `build\env.cmd`, `nuget.config`, `build\EdrBuild\` (build pipeline), `build\installer\FreeEDR-Setup.iss` (Inno Setup script), `src\` (C# tray rewrite, in progress: `docs\Tray-Rewrite-Plan.md`), `docs\`, and the build outputs `compiled\`, `obj\`, `build.log`. Every file a build writes stays in this folder: `build\env.cmd` points `TEMP`/`TMP`, the NuGet package and HTTP caches and the .NET CLI home at `obj\`, and `nuget.config` does the same for plain `dotnet` commands.

Encoding rules (they matter, see §8; `build.cmd` checks them):
* `*.ps1` must be **UTF-8 with BOM**. Windows PowerShell 5.1 reads BOM-less files as ANSI and corrupts non-ASCII characters.
* `*.yar` must be **ASCII without BOM**. YARA rejects a BOM with `error: non-ascii character`, and the rule file is then silently skipped.
* Do not put credential-theft tool names (the mimikatz command strings) in plain text inside `.ps1` files. AMSI/Defender blocks such scripts ("This script contains malicious content"). The YARA file keeps them hex-encoded for the same reason.

---

## 3. Installation (recommended: the single-file installer)

**Build it** in `<repo>`: `build.cmd` (release: wipes `.\compiled`, which then holds only `FreeEDR-Setup.exe`) or `dev_build.cmd` (dev: `.\compiled` not wiped, version marked "dev build"). Run them through `cmd.exe` by full path. Both run the same gates and stop at the first failure:
1. the `$ProjectFiles` exist; encodings (§2); all scripts parse in Windows PowerShell 5.1;
2. the C# tests pass (incl. parity of the C# tray with `EDR-Tray.ps1` on three fixtures, and signature checks); the C# tray publishes as NativeAOT;
3. both trays build the same model from this PC's live `C:\Program Files\FreeEDR` data (skipped when FreeEDR is not installed; `--skip-live` to skip);
4. staging, Inno Setup, exactly one file in `.\compiled`, SHA256 printed.

Result: `.\build.log`, first line OK / WARN / FAIL. A build installs and publishes nothing. Version: `yyyy.M.d.HHmm` (e.g. 2026.11.1.2331), plus "(dev build)" for dev builds.

**Option A - `compiled\FreeEDR-Setup.exe`.** Run it and answer "Yes" to the administrator prompt. It unpacks the project files to Inno Setup's temporary folder (removed when Setup exits) and runs `Install-EDR.ps1` from there in 64-bit Windows PowerShell, in a visible window (steps 3-5 below apply), then reports SUCCESS / ROLLED BACK / FAILED. Unattended: `FreeEDR-Setup.exe /VERYSILENT` (exit code 0 = success, 1 = otherwise). It writes nothing itself (no Setup log, no uninstaller entry; uninstall: §7).

**Option B - run the installer script** from the development folder.

1. Open **Windows PowerShell as Administrator**.
2. Run:
   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File <repo>\Install-EDR.ps1
   ```
   Optional switches: `-AllowNewerTools` (if a pinned GitHub release no longer exists; the latest release is then installed and the hash is reported instead of enforced) and `-NoPause`.
3. Read the output. Every line is `OK` or `WARN`, and the last line is `INSTALL RESULT: SUCCESS | ROLLED BACK | FAILED`. The full transcript is written to `C:\Program Files\FreeEDR\install.log`. `$env:EDR_NO_PAUSE=1` or `-NoPause` skips the final "Press Enter". Exit code: 0 = SUCCESS, 3 = ROLLED BACK, 1 = FAILED.
4. If the output says `Sysmon driver is ... - restart the PC`, restart Windows.
5. Continue with **§5 Verification**.

The installer performs exactly the manual steps in §4, in that order. It is idempotent: re-running it repairs or upgrades and never deletes `data\` or your exclusions.

---

## 4. What the installer does (manual equivalent, step by step)

Use this section to understand, audit or reproduce the installer without running it. All commands run elevated. `$Root` = `C:\Program Files\FreeEDR` (the 64-bit Program Files folder, `$env:ProgramW6432`).

### 4.1 Pre-flight
1. Create `$Root` and `$Root\data\download` (downloads in progress; removed at the end), start the transcript `$Root\install.log`.
2. Confirm admin rights. Read the installing user's SID (`[Security.Principal.WindowsIdentity]::GetCurrent().User.Value`); it is used only for the folder permissions (§4.7) and never stored.
3. Confirm all project files from §2 exist next to the installer.

### 4.2a Move from `C:\EDR` (only if `C:\EDR\EDR-Engine.ps1` exists)
1. Stop and **disable** (not delete) the task `EDR`; signal `Local\EDR-Tray-Exit` and `Local\FreeEDR-Tray-Exit`; stop processes whose command line matches `EDR-(Engine|Tray|Scan).ps1`, and the tools running from `C:\EDR`.
2. Copy every sub-folder of `C:\EDR` (config, data incl. events/bans/state/backups, quarantine, bin, rules, …) into `$Root` with `robocopy /E /COPY:DAT`, folder by folder. The old top-level scripts and docs are not copied (the new ones come from the installer; `robocopy /XF` is not used because it would also drop the scripts inside `data\backup-*`).
3. Copy `%LOCALAPPDATA%\EDR` (reviewed alerts, hidden apps, history, winget.txt, tray.log) into `$Root\user`.
4. `C:\EDR`, `%LOCALAPPDATA%\EDR`, the task `EDR`, the Run value `EDR Tray` and the "EDR Security" shortcut are removed only after verification succeeds (§4.12).

### 4.2 Install project files
1. If `$Root\EDR-Engine.ps1` already exists (upgrade), copy the current `*.ps1`, `config\sysmonconfig.xml` and `rules\*.yar` to `$Root\data\backup-<yyyyMMdd-HHmmss>\`.
2. Copy every project file from §2 into `$Root`, keeping sub-folders.
3. Create `config`, `data`, `data\legacy`, `rules`, `bin`, `control`, `inbox`, `user`.

### 4.3 Legacy migration (only if `C:\Wail2Ban` or `C:\LocalEDR` exist)
1. Stop and disable the tasks `start wail2ban onstartup`, `LocalEDR-TrayWatcher` and `LocalEDR-DailyScan`. Stop processes whose command line matches `LocalEDR\(Watcher|UpdateAndScan).ps1` or `Wail2Ban\wail2ban.ps1`.
2. `robocopy C:\LocalEDR\bin "$Root\bin" /E`.
3. Copy `C:\Wail2Ban\bannedIPLog.ini` to `data\wail2ban_strikes.txt` (same format: `ip strikes epoch`).
4. Copy `Detections.log` and `wail2ban_log.log` to `data\legacy\`.
5. Import `[Whitelist]` entries of `wail2ban_config.ini` into `exclusions.json` → `wail2ban[]`.
6. Convert `Detections.log` lines into `data\events.jsonl` with `legacy: true`. These count as already reviewed.
7. The old ones are deleted only after verification succeeds (§4.12).

### 4.4 Tools (pinned, hash-verified)
For each tool, if the target file is missing, read the GitHub API `https://api.github.com/repos/<repo>/releases/tags/<tag>`, download the asset whose name matches the pattern into `data\download\`, extract it, and verify SHA256. **Refuse the tool on a hash mismatch.**

| Tool | Repo | Tag | Asset pattern | Target | SHA256 of target |
|---|---|---|---|---|---|
| Hayabusa | Yamato-Security/hayabusa | v4.3.1 | `-win-x64.zip` (not live-response) | `bin\hayabusa\hayabusa.exe` (zip extracted into `bin\hayabusa\`, exe renamed) | `411CE8749115C85B359ADE15B9824B38650B06274DC816D1D4B9035859C8C573` |
| YARA | VirusTotal/yara | v4.6.0 | `win64.zip` | `bin\yara64.exe` (+ `yarac64.exe`) | `6B4897B945F408080645EC06E2D2540F067A57A68D5E5830781CDC1D88FC41E2` |
| OSV-Scanner | google/osv-scanner | v2.7.0 | `windows_amd64.exe` | `bin\osv-scanner.exe` | `9964ED64EC9A387391EB4CC006AD5C531154821AEF29B793E02C448DE4686438` |
| Velociraptor | Velocidex/velociraptor | v0.77.3 | `windows-amd64.exe.gz` (gzip, extracted by the installer; older tags: `.exe`) | `bin\velociraptor.exe` (signed Rapid7 LLC) | `3D20A5A2D272E3EB2BCCAE4A80EBE469FC1A6F63EB4A8F8A586DBAE356437D32` |

Velociraptor is marked `Upgrade`: an installed copy with a different hash is renamed to `.old`, the pinned version is installed, and on any failure (file in use, download, hash) the old copy is put back with a WARN. The other tools are installed only when missing.

Then:
1. Delete `bin\*.zip` and any `bin\hayabusa\hayabusa-*-win-x64.exe` identical to `hayabusa.exe` (download leftovers).
2. Sysmon: if service `Sysmon64` is missing, download `https://download.sysinternals.com/files/Sysmon.zip` into `data\download\` and extract it. Require `Get-AuthenticodeSignature Sysmon64.exe` to be **Valid** and signed by **Microsoft**. (Sysinternals has no version pinning; the signature is the integrity check.)

### 4.5 Sysmon configuration
1. Read `config\sysmonconfig.template.xml`, replace `{ROOT}` with `$Root` (the config holds no user-specific path: per-user folders such as Downloads or the Epic launcher are matched with `contains`), and write `config\sysmonconfig.xml` (UTF-8, no BOM).
2. Fresh install: `Sysmon64.exe -accepteula -i "$Root\config\sysmonconfig.xml"`. Existing install: `C:\Windows\Sysmon64.exe -accepteula -c "$Root\config\sysmonconfig.xml"`.
3. Run Sysmon with `$ErrorActionPreference = 'Continue'`. Sysmon prints its banner to **stderr**, and under `Stop` PowerShell 5.1 turns that into a terminating error.
4. On a non-zero exit, write the previous `sysmonconfig.xml` back and re-apply it.
5. If `SysmonDrv` is not `Running`, a reboot is required.

What the config contains: include-only rules (named; the name is the alert title), an explicit "Off" group for every high-volume event type, and built-in exclusions for Epic Games, Easy Anti-Cheat, BattlEye, FortniteGame and the FreeEDR folder. See the comments inside the template.

### 4.6 Settings, exclusions, history
1. `config\edr-config.json`: start from the defaults in `EDR-Common.ps1` → `Get-DefaultConfig` and keep any existing values. The obsolete `userProfile` key (older versions) is removed: the scan finds every user's profile itself (`Get-UserProfiles`, from the registry ProfileList). A legacy `iocFeedUrl` on `bazaar.abuse.ch` is replaced automatically (those exports return HTTP 410). Remove the obsolete `scanTime` key.
2. `config\exclusions.json`: keys `realtimePath, realtime, ioc, yara, sigma, wail2ban, cve, defender`, each an array of `{id, added, ...}`.
   * Remove these `realtimePath` prefixes, which are now built into the Sysmon config or deliberately no longer excluded: the Epic/Fortnite paths, `$Root\` and `C:\EDR\`.
   * `realtime` entries: `{rule ('*' or a rule name), image (wildcard), parent (wildcard), signer, parentSigner, ancestors, detail (wildcard on the command line / registry value), profile}`. At least one of image/parent/signer/detail must be set. `parent` matches one of the first `ancestors` (1–3) processes above the program; `parentSigner` requires that file to carry a valid signature of that publisher. Microsoft Windows / Microsoft Corporation are refused as parentSigner, and as signer unless an image path narrows it (OneDrive profile).
   * `sigma` entries: `{title ('*' or a rule title), parent (wildcard), parentSigner, profile}`; `*` needs a parent.
   * Replace a version-pinned "all rules" OneDrive allow (`rule '*'`, image under `C:\Program Files\Microsoft OneDrive\<version>\`).
   * Trusted-app profiles (`$AllowProfiles` in `EDR-Common.ps1`): only while `allowProfilesInitialized` is false, add the entries of every profile with `default = $true` whose app is found (`detect` paths), tagged `profile = <id>`; drop the older untagged Run-key allows of OneDrive / Google Drive / Razer (the profiles cover them) and tag older "Allow Claude Code" entries as `claude-code`; then set `allowProfilesInitialized = true`. Later installs never re-add a profile the user switched off.
   * Remove `realtime` allows of any `pwsh.exe` / `powershell.exe` / `powershell_ise.exe` (any folder, including bundled copies such as Codex's under `%USERPROFILE%\.cache`) for all rules that have no parent or signer. They hide every PowerShell attack.
   * `wail2ban` entries: `{cidr, note}`.
3. Create the event source: `New-EventLog -LogName Application -Source wail2ban` (if missing).
4. `data\state.json`: stores persistent engine state, including granular pause keys (`edr`, `wail2ban`, `malware`, `realtime`, `sigma`, `cve`) with expiry timestamps. Actions are written to the forensic audit log (`[FORENSIC-AUDIT]`, Event ID 3000 in the Application event log).
5. Inter-process commands (`inbox\cmd-*.json`): must be written via atomic temp files (`.tmp` → move), UTF-8 BOM encoded, max 64KB file size limit. Engine enforces alphanumeric filename validation and drains at most 25 files per polling sweep.

### 4.7 Permissions (the most important security step)
```powershell
$Root = 'C:\Program Files\FreeEDR'
icacls $Root /setowner *S-1-5-32-544 /T /C /Q
icacls $Root /inheritance:r /grant:r *S-1-5-32-544:(OI)(CI)F *S-1-5-18:(OI)(CI)F *<USER-SID>:(OI)(CI)RX
icacls "$Root\*" /reset /T /C /Q
icacls "$Root\inbox" /grant *<USER-SID>:(OI)(CI)(W,D)   # D: renaming the request .tmp -> .json needs delete access
icacls "$Root\user" /grant *<USER-SID>:(OI)(CI)M
icacls "$Root\quarantine" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F   # if it exists
```
Inheritance is removed so nothing from the parent folder applies, and the reset makes every file inherit exactly these rights. The quarantine is set again after the reset (before 2026-11-02 the reset gave the user read access to quarantined files until the engine re-created the folder). The owner must be Administrators, because an owner can always rewrite the ACL. Without this step an unelevated process could edit scripts that run as SYSTEM.

### 4.8 Microsoft Defender and firewall
Detect-only (default, `enforce: false`): use `AuditMode` for the 14 rules below and `Set-MpPreference -EnableControlledFolderAccess AuditMode`. Block mode (`enforce: true`) as written:
```powershell
# Block
'56a863a9-875e-4185-98a7-b882c64b5ce5','7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c','d4f940ab-401b-4efc-aadc-ad5f3c50688a',
'9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2','be9ba2d9-53ea-4cdc-84e5-9b1eeee46550','5beb7efe-fd9a-4556-801d-275e5ffc04cc',
'd3e037e1-3eb8-44c8-a917-57927947596d','3b576869-a4ec-4529-8536-b80a7769e899','75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84',
'26190899-1602-49e8-8b27-eb1d0a1ce869','e6db77e5-3df2-4cf1-b95a-636979351e5b','b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4',
'92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b','c1db55ab-c21a-4637-bb3f-a12568109d35' |
  ForEach-Object { Add-MpPreference -AttackSurfaceReductionRules_Ids $_ -AttackSurfaceReductionRules_Actions Enabled }
# Audit only (too disruptive for development work)
'01443614-cd74-433a-b99e-2ecdc07bfc25','d1e49aac-8f56-4280-b9ba-993a6d77406c' |
  ForEach-Object { Add-MpPreference -AttackSurfaceReductionRules_Ids $_ -AttackSurfaceReductionRules_Actions AuditMode }
Set-MpPreference -EnableControlledFolderAccess Enabled
Get-ChildItem 'C:\Program Files\Epic Games\*\*\Binaries\Win64\*.exe','C:\Program Files (x86)\Epic Games\Launcher\Portal\Binaries\Win64\*.exe','C:\Program Files (x86)\EasyAntiCheat_EOS\*.exe' |
  ForEach-Object { Add-MpPreference -ControlledFolderAccessAllowedApplications $_.FullName }
# RDP shadowing is not used, and its rule allowed any address
Get-NetFirewallRule -Name RemoteDesktop-Shadow-In-TCP | Disable-NetFirewallRule
```
Use `Add-MpPreference`, never `Set-MpPreference`, for ASR rules: `Set` replaces the whole list.

### 4.9 Scheduled task
Register `\FreeEDR` from XML (see the `$xml` block in `Install-EDR.ps1`) with:
* Principal: `S-1-5-18`, `HighestAvailable`.
* Triggers: `BootTrigger`, plus a `TimeTrigger` with `Repetition Interval PT5M` (the watchdog).
* Settings: `MultipleInstancesPolicy IgnoreNew`, `ExecutionTimeLimit PT0S`, `StartWhenAvailable true`, battery restrictions off, `Priority 5`, `RestartOnFailure PT1M x999`.
* Action: `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Program Files\FreeEDR\EDR-Engine.ps1"`, working directory `C:\Program Files\FreeEDR`.

The task is invisible to unelevated `Get-ScheduledTask`; that is normal. A second engine never runs (`IgnoreNew` + mutex `Global\FreeEDR-Engine`). The mutex is constructed with an explicit `System.Security.AccessControl.MutexSecurity` ACL granting SYSTEM and `Builtin\Administrators` full control to prevent unelevated pre-creation denial of service, and cross-checks running process IDs to recover immediately if a prior engine crashed with an abandoned mutex.

### 4.10 Tray
1. `Set-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name 'FreeEDR Tray' -Value 'powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "C:\Program Files\FreeEDR\EDR-Tray.ps1"'`.
2. Create the shortcut `%APPDATA%\Microsoft\Windows\Start Menu\Programs\FreeEDR.lnk` → same command plus `-Show`, icon `imageres.dll,73`, window style minimized.
3. Close any running tray: signal the named events `Local\FreeEDR-Tray-Exit` and (older trays) `Local\EDR-Tray-Exit`; as a fallback, stop processes whose command line contains `EDR-Tray.ps1`. The tray's single-instance names are `Local\FreeEDR-Tray`, `Local\FreeEDR-Tray-Show`, `Local\FreeEDR-Tray-Exit`.
4. UI structure: Overview dashboard plus 6 security rubrics, each organized into standardized 3-stage lifecycle tabs (`Detected`, `Blocked`, `Allowed`), unified action buttons (in detect-only mode `Flag as threat` / `Confirm as threat` / `Flag as hostile`, then `Allow`, `Mark Reviewed`; the second list is named `Flagged`), granular per-rubric Pause/Play controls with exact scope descriptions, an interactive triage banner ("Was this you?"), and a Forensics & Action History ledger with one-click CSV export (a Save dialog, default Documents). Long-running UI loops invoke `[System.Windows.Forms.Application]::DoEvents()` to prevent UI freezes.

### 4.11 Start and verify
1. Stop the task and any `EDR-Engine.ps1` process, then `Start-ScheduledTask FreeEDR`.
2. Poll `data\status.json` for up to 90 s until `engineStarted` is after the start time and `heartbeat` is under 30 s old.
3. Required: engine heartbeat, `wail2ban.state != error`, all tools present. Reported: `edr.state != error`, 2 YARA rule files compiled.

### 4.12 Finish
* Verified + moved from `C:\EDR` → unregister the task `EDR`, remove the Run value `EDR Tray` and the "EDR Security" shortcut, delete `C:\EDR` and `%LOCALAPPDATA%\EDR` (a file still in use gives a WARN: delete it after a restart).
* Verified + legacy present → delete the 3 legacy tasks and the `C:\Wail2Ban` and `C:\LocalEDR` folders.
* Not verified + upgrade → restore `data\backup-*` scripts and Sysmon config, restart the task → `ROLLED BACK`.
* Not verified + moved from `C:\EDR` → disable `FreeEDR`, remove `FreeEDR Tray`, re-enable and start `EDR`, start the old tray → `ROLLED BACK` (the old install in `C:\EDR` was never changed).
* Not verified + legacy → disable `FreeEDR`, re-enable and start the legacy tasks → `ROLLED BACK`.
* Remove `data\download\`. Start the tray unelevated: `Start-Process explorer.exe "<path to FreeEDR.lnk>"`. Explorer launches it at medium integrity.

---

## 5. Verification (run after every install)

Run these from an **unelevated** PowerShell. Read access to the install folder is expected.

```powershell
$R = 'C:\Program Files\FreeEDR'
$st = Get-Content "$R\data\status.json" -Raw | ConvertFrom-Json
"{0}s old | edr={1} wail2ban={2} sysmon={3} yara={4} ioc={5}" -f [int]((Get-Date)-[datetime]$st.heartbeat).TotalSeconds, $st.edr.state, $st.wail2ban.state, $st.sysmon.message, ($st.edr.yaraRules -join ','), $st.edr.iocHashes
Get-Content "$R\data\engine.log" -Tail 20
try { Add-Content "$R\EDR-Engine.ps1" '#' -ErrorAction Stop; 'FAIL: writable' } catch { 'OK: scripts are read-only for users' }
try { Get-ChildItem "$R\quarantine" -ErrorAction Stop | Out-Null; 'FAIL: quarantine readable' } catch { 'OK: quarantine is admin-only' }
Test-Path C:\Wail2Ban, C:\LocalEDR, C:\EDR, "$env:LOCALAPPDATA\EDR"   # all False
```
Then in the GUI:
1. Tray ▸ Advanced ▸ **Send a harmless test detection** → a High alert appears; right-click it to see the exclusion options.
2. Tray ▸ **Update and scan now** → after 1–3 minutes, "Scan finished: …". The Overview *Updates and scans* tile shows OK. If not, open `data\scan.log`. `data\cve-current.json` now exists (CVE tab).
3. Diagnostics without UI: `powershell -STA -File "C:\Program Files\FreeEDR\EDR-Tray.ps1" -SelfTest` prints every tab's list counts, status lines and the actions offered for the first row of each list. `$env:EDR_SELFTEST_DUMP='<folder>'` also saves the inputs it read plus `model.json`; `$env:EDR_SELFTEST_ROOT='<folder>'` reads a fixture (`data\`, `config\`, `local\`) instead of the install folder. These are used by the C# tray's parity tests (`docs\Tray-Rewrite-Plan.md`); `src\parity.ps1` in the development folder runs that comparison on the live data.
4. Tray ▸ **EDR protection ▸ Pause for 15 minutes** (or individual blade pause: Anti-Malware, Real-time Sysmon, Sigma Rules, or Vulnerability Scanner) → UAC → the shield turns grey / status updates → **Resume** turns it green. Verify forensic audit log entry with `Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='wail2ban'; Id=3000} -MaxEvents 5`.
5. Same for **Wail2Ban** (Pause RDP Protection).
6. Overview ▸ Forensics & Action History ▸ click **Export Audit CSV** → verify `data\FreeEDR-Audit-Export-*.csv` is generated with valid timestamp, action, target, user, and outcome columns.
7. External tool command invocation verification: verify all scanner subprocesses (`hayabusa.exe`, `yara64.exe`, `osv-scanner.exe`, `velociraptor.exe`) are executed via argument arrays (`& $exe @args`) without shell string interpolation.

---

## 6. Post-install tuning

* Claude Code (`claude.exe`) runs PowerShell with `-EncodedCommand` (syntax check) and `Invoke-Expression` (its launcher), which raises "Encoded PowerShell command" / "PowerShell download or in-memory execution" for every command. The Claude Code trusted-app profile (on by default when Claude Code is installed; tray ▸ Trusted apps) covers only those rules. Do not allow PowerShell itself.
* Remote Desktop: keep NLA on. If a client needs NLA off, limit the "Remote Desktop" firewall rules to your LAN range or a VPN.
* Controlled folder access: allow only programs in admin-only folders (README §7).

---

## 7. Uninstall

Elevated:
```powershell
Stop-ScheduledTask FreeEDR; Unregister-ScheduledTask FreeEDR -Confirm:$false
Remove-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name 'FreeEDR Tray'
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\FreeEDR.lnk"
Get-NetFirewallRule -DisplayName 'a a a wail2ban block IP:*' | Remove-NetFirewallRule
Get-NetFirewallRule -DisplayName 'Block RDP IPv6 (*3389)' | Remove-NetFirewallRule
C:\Windows\Sysmon64.exe -u                              # optional: remove Sysmon
Remove-Item 'C:\Program Files\FreeEDR' -Recurse -Force   # deletes history, exclusions and quarantined files
```
The Defender ASR/CFA settings and the disabled RDP-shadow rule stay; change them in Windows Security if wanted. The development folder is separate and is not touched.

---

## 8. Why it is built this way (history and decisions)

### 8.1 Origin
* **C:\Wail2Ban**: a Windows port of fail2ban (glasnt, 2012) with local fixes. It ran as SYSTEM via the task `start wail2ban onstartup`, used WMI `Win32_NTLogEvent` for 4625 and `netsh` for bans. There was no GUI.
* **C:\LocalEDR**: a Sysmon tray watcher (`Watcher.ps1`, task `LocalEDR-TrayWatcher`) plus a daily scan (`UpdateAndScan.ps1`, task `LocalEDR-DailyScan`) with Hayabusa, YARA, OSV-Scanner, an abuse.ch hash feed and Velociraptor.
* **C:\EDR** (2026-10-31 to 2026-11-02): the merged EDR + Wail2Ban, task `EDR`. Renamed to **FreeEDR** and moved to `C:\Program Files\FreeEDR` (E17).

### 8.2 First review: findings and the owner's decisions (2026-10-31)
| ID | Finding | Decision → result |
|---|---|---|
| C1 | Both folders were writable by Authenticated Users and the Codex sandbox group, yet their scripts ran as SYSTEM/elevated (privilege escalation) | **Accepted** → admin-only ACL (§4.7), UAC for weakening actions |
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
| E2 | Any command line containing `C:\LocalEDR\` was ignored (trivial evasion) | Fixed → only FreeEDR's own scripts are ignored, identified by parent/command line pointing at the admin-only `$Root\EDR-*.ps1` |
| E3 | The whole development folder was excluded (invisible) | Fixed → blanket exclusion removed; specific exclusions through right-click. (The development folder is therefore watched like any other folder.) |
| E4 | abuse.ch MalwareBazaar export returned HTTP 410; the HTML error page was saved as the hash list (0 hashes) | Fixed → Neo23x0 signature-base feed with threat names; download validated (≥100 hashes) before replacing |
| E5 | `ransomware.yar` contained "404: Not Found" | Fixed → real rules (backup destruction, embedded ransom note) |
| E6 | The Sigma scan never produced output; only the last 5 hits; each rule title alerted only once forever | Root cause: **Hayabusa 4.x renamed `csv-timeline` to `dfir-timeline`**; also needs its own folder as working directory. Fixed → `dfir-timeline -l -w -m high --time-offset 2d`, up to 200 hits, dedupe by rule+computer+channel+record |
| E7 | Only 7 Sysmon rules | Fixed → curated include-only config (validated on Sysmon 15.22 / schema 4.91) (process, network LOLBins, drivers, LSASS access, Startup folder, registry persistence, WMI), game-safe |
| E8 | Patch check reported only a count | Fixed → one row per app with Update / Update all / Hide |
| E9 | Duplicate binaries and zips; tools never updated | Fixed → leftovers removed, version check every scan (twice a day) shown as "EDR tool update" |

### 8.2b Second review (2026-11-01 / 02): findings and decisions
Context: the "credentials / LSASS" alerts were analysed first. All were false positives from AI-assisted development: an old LocalEDR rule matched the word "MiniDump" in a `grep`, and Defender/AMSI blocked test scripts that contained credential-tool strings (Hayabusa then repeated those Defender detections as Sigma alerts). No LSASS rule was weakened, and no Defender exclusion was added.

| ID | Finding | Decision → result |
|---|---|---|
| E10 | Sysmon kept running the old LocalEDR rules after the config was applied (stuck driver), producing 400+ unexplained alerts | Fixed → the engine compares alert rule names with `sysmonconfig.xml` and reports "restart the PC"; retired-rule alerts are hidden as reviewed |
| W8 | Successful network logins from public IPs were only visible hours later as Sigma SMB alerts (a phone over mobile data) | Accepted → live 4624 (type 3/10) watcher, High "Was this you?" alert in Wail2Ban |
| E11 | Claude Code's PowerShell tool raised 2 High alerts per command (pwsh `-EncodedCommand` syntax check; cmd → pwsh `Invoke-Expression` launcher); an "allow everything started by claude.exe" or "allow pwsh.exe" would hide credential theft run through it | Fixed → *Allow Claude Code*: only those 2 EDR + 2 Sigma rules, claude.exe up to 3 levels up (process chain read live, PID reuse checked, stored as `ancestors`), valid Anthropic signature; generic "started by" allows also carry the parent's signature |
| E12 | Run-key noise from OneDrive / Google Drive / Razer at every sign-in; the user's OneDrive allow was version-pinned and for all rules | Fixed → installer adds Run-key-only, versionless allows and replaces the pinned one |
| E13 | Velociraptor 0.77.3 available; its asset is now `.exe.gz`; installer never upgraded existing tools | Fixed → gzip support, pinned 0.77.3 (GitHub digest verified), safe in-place upgrade with roll-back |
| E14 | "Sysmon sensor is not working" never got its "healthy again" when a reboot fixed it (engine restarted with a clean state) | Fixed → last Sysmon health is kept in `state.json` |
| E15 | Real-time allows of `pwsh.exe` (Program Files, Windows PowerShell and a user-writable Codex copy) for all rules hid every PowerShell attack | Fixed → installer removes "all rules" allows of any pwsh.exe / powershell.exe / powershell_ise.exe without a parent or signer, wherever it lives (a WARN line); use *Allow Claude Code* |
| E16 | Installing meant copying a folder and starting PowerShell elevated by hand; no checks before an install | Added → `build.cmd` / `dev_build.cmd`: gates, then one Inno Setup installer `compiled\FreeEDR-Setup.exe` that runs `Install-EDR.ps1` (a standard installer package, not a program carrying hidden payloads, so antivirus scans every file); Install-EDR got exit codes and `-NoPause` |
| E17 | Owner's decision: official name **FreeEDR**; production in `C:\Program Files\FreeEDR`, development in the repository folder, no files anywhere else | Done → `$Root` in Program Files; tray files in `user\` instead of `%LOCALAPPDATA%\EDR`; downloads in `data\download`; Velociraptor GUI datastore in `data\velociraptor`; task / tray / shortcut / mutex / installer names `FreeEDR`; build temp files and NuGet caches in the dev folder's `obj\`; the installer moves an install from `C:\EDR` and removes the old one after verification |
| C4 | RDP shadow firewall rule open to any address | Accepted → disabled by the installer |
| — | Sigma-scan bug in the PowerShell tray: a confirmed rule with exactly one matching event showed an empty "Matches" column and no details | Fixed (see §8.3) |
| — | Python CVEs listed are all inside pip's own bundled libraries (pip 26.2.2 is the newest) | No action possible → they clear with a future pip release, or Ignore in the CVE tab |
| — | Controlled folder access allows for explorer.exe, dllhost.exe and a user-writable development build; a real-time allow of sihost.exe for all rules | **Open** (owner's decision) → recommended: remove the CFA allows; narrow the sihost allow to one rule |

### 8.2c Third review: Architectural Hardening & UX Overhaul (2026-11-02)
Context: Full release-blocking architectural and security audit of the entire codebase, followed by comprehensive UI/UX overhaul and forensic audit logging.

| ID | Finding / Area | Category | Decision → Result |
|---|---|---|---|
| F1 | `Global\FreeEDR-Engine` named mutex lacked ACL; unprivileged local attacker could squat mutex to prevent engine startup | Security & Concurrency | **Fixed** → Initialized mutex with explicit `MutexSecurity` ACL granting SYSTEM (`*S-1-5-18`) and Administrators (`*S-1-5-32-544`) full control. Engine verifies live PID to self-heal abandoned locks. |
| F2 | External tool executions (`hayabusa`, `yara64`, `osv-scanner`, `velociraptor`) interpolated command strings, risking argument injection | Security & Boundaries | **Fixed** → Replaced all string interpolation commands with safe PowerShell argument array splatting (`& $exe @args`). |
| F3 | WinForms UI thread blocked during event polling and model updates, freezing tray window under load | Concurrency & UI | **Fixed** → Inserted `[System.Windows.Forms.Application]::DoEvents()` in all rendering loops, list builders, and polling passes. |
| F4 | Inbox command processing (`inbox\cmd-*.json`) suffered from race conditions, traversal risks, and unbounded file size | Boundaries & IPC | **Fixed** → Implemented atomic file creation pattern (`.tmp` → move), enforced 64KB max payload boundary, sanitized file names to alphanumeric characters, and capped queue processing at 25 files per polling sweep. |
| F5 | Process ancestor queries invoked repeated WMI/Get-Process calls without caching, causing high CPU and memory churn | Resources & Concurrency | **Fixed** → Introduced `$script:ProcCache` with process ID, CreationTime, and 30-second TTL invalidation to avoid redundant lookups. |
| F6 | YARA scanner buffered large files unconditionally causing OOM; `events-*.jsonl` accumulated without retention quota | Resources & Streams | **Fixed** → Introduced $script:YaraCache SHA-256 result caching to skip redundant scans of unchanged binaries; added 50MB single-file size boundary skip check in YARA file iteration; enforced strict 5-file maximum retention quota on rotated `events-*.jsonl` files. |
| F7 | Hayabusa and OSV-Scanner loaded entire multi-megabyte JSON/CSV outputs into memory at once | Resources & Streams | **Fixed** → Implemented 200-record streaming circular queue for Hayabusa output ingestion; switched OSV-Scanner parsing to streaming JSON lines. |
| UX1 | All-or-nothing pause controls confused users who needed to pause only one blade (e.g., malware or CVE) | UI/UX & Controls | **Implemented** → Added granular per-rubric Pause/Play for all 6 blades (`malware`, `realtime`, `sigma`, `cve`, `wail2ban`, `edr`) with clear scope descriptions, `state.json` wiring, and Event ID 3000 audit logging. |
| UX2 | Inconsistent status terminology and disparate action buttons across tabs confused operators | UI/UX & Flow | **Implemented** → Standardized 3-stage lifecycle tabs across every rubric (`Detected`, `Blocked`, `Allowed`) and unified action buttons (`Block & Neutralize`, `Trust & Exclude`, `Mark Reviewed`). |
| UX3 | Network login alerts (Event ID 4624) required deep navigation to review | UI/UX & Guidance | **Implemented** → Added prominent guided triage banner on Overview ("Was this you?") with one-click `Yes, This Was Me` vs `No, Block Immediately` actions. |
| UX4 | Administrative actions had no visible audit history or export capability | Forensics & Compliance | **Implemented** → Added Forensics & Action History Viewer directly on Overview with one-click CSV export (via `SaveFileDialog`) and Event ID 3000 Windows Application event logging. |
| UX5 | Unelevated tray threw UnauthorizedAccessException when exporting audit CSV to admin-only `data\` folder | Permissions & I/O | **Fixed** → Replaced hardcoded path with Windows `SaveFileDialog` defaulting to user Documents folder. |
| UX6 | Triage card emitted "Threat Neutralized" toast even if UAC prompt was dismissed | UI State & Feedback | **Fixed** → Guarded success toasts and UI updates behind verified UAC dispatch return code. |
| UX7 | Long UAC command elevation blocked UI thread with synchronous WaitForExit(15000) | UI Responsiveness | **Fixed** → Converted to cooperative loop pumping `Application.DoEvents()` every 50ms with timeout check. |
| UX8 | Ampersand characters in action buttons and context menus rendered as keyboard accelerators or disappeared | Microcopy & Controls | **Fixed** → Disabled `UseMnemonic` on buttons and escaped ampersands as `&&` in context menus. |
| UX9 | Empty state placeholders were clipped off-screen or unreadable against dark backgrounds | Visuals & A11y | **Fixed** → Anchored placeholder text in Column 0 and increased contrast to `#646464` (5.9:1 WCAG AA). |
| UX10 | Generic "Blocked" tab was misleading for benign updated Python packages and winget apps | Microcopy & Flow | **Fixed** → Standardized semantic sub-tabs for CVE (`Detected / Updated / Ignored`) and Apps (`Available / Updated / Hidden`). |

### 8.2d Fourth review: QA defects, false positives, detect-only (2026-11-02)
Context: QA audit of the scripts (14 defects) and a review of the live alerts on this PC. Owner decisions: FreeEDR only **detects and logs** in every category for now (nothing is stopped, quarantined or firewall-blocked), and the apps the owner works with (AI coding assistants, OneDrive, ...) must run without alerts out of the box, switchable back at any time.

| ID | Finding | Decision → Result |
|---|---|---|
| Q1 | OSV scan wrote into `data\download`, which every install deletes: the CVE step "succeeded" with 0 results and emptied the CVE tab | **Fixed** → the folder is created by the scan; a folder without a readable result fails the step and the previous CVE list is kept |
| Q2 | Engine start copied a Real-time pause into the master pause (everything paused after a restart) | **Fixed** → leftover migration removed |
| Q3 | `Get-CachedProcess([int]$Pid)` always threw (`$PID` is read-only), so parents above the direct parent were never checked | **Fixed** → parameter renamed `$ProcId` |
| Q4 | Resume of one part while the master switch was paused did nothing but reported success | **Fixed** → the tray offers to resume the master switch instead |
| Q5 | Shield stayed green while one part was paused | **Fixed** → overall status lists every paused part (tray and C# model) |
| Q6 | `inbox\` permission (W) did not allow renaming the request file: resume / scan-now always asked for UAC and left `.tmp` files | **Fixed** → inbox gets (W,D); the tray deletes a failed `.tmp`, the engine removes leftovers after 2 minutes |
| Q7 | Audit CSV export wrote into the admin-only `data\` and always failed | **Fixed** → Save dialog, default Documents |
| Q8 | Garbled triage button text (double-encoded symbols) | **Fixed** → plain text |
| Q9 | Audit details read from a non-existent `extra` object | **Fixed** → read from the event itself |
| Q10 | Sigma hits beyond the newest 200 were silently dropped | **Fixed** → 2,000 kept; more marks the step as failed with a pointer to the CSV |
| Q11 | Engine restart replayed failed logons (duplicate events, possible re-ban) | **Fixed** → replay only refills the counter, skips failures before the last ban/report |
| Q12 | Real-time pause did not pause blocklist enforcement | **Fixed** (and enforcement is off in detect-only mode) |
| Q13 | `Write-EngineLog` called before it was defined | **Fixed** → defined first |
| Q14 | Very large multi-row actions exceeded the command-line limit with a misleading "approval not given" | **Fixed** → clear "select fewer items" message |
| FP | Live false positives (Claude Code PowerShell tool, ChatGPT/Codex, Antigravity, vcpkg shell, OneDrive, Office Click-to-Run, Google Drive, Razer, installer RunOnce, FreeEDR's own Run-key write) | **Trusted-app profiles** (`$AllowProfiles`): recommended ones on by default when the app is found, one-click on/off in the Trusted apps window, alerts offer "Trust the whole app". FreeEDR's own Run-key write is skipped by the engine. Realtime exclusions gained `detail` (command-line wildcard) because short-lived launchers (Claude Code's `cmd.exe` and syntax-check `pwsh`) are often gone before their parent can be looked up |
| D1 | Detect-only | `enforce` in `edr-config.json` (default false): no process kill, no quarantine, no Wail2Ban/permanent firewall bans (threshold reported as "Password guessing", Medium, notified), no new IPv6 RDP block rules; Block verdicts become "Flag" (lists named Flagged); Defender ASR + Controlled folder access in Audit mode, their audit events (1122 / 1124) listed as Low in Anti-Malware > Detected. Existing firewall rules are left as they are |

### 8.3 Bugs found and fixed while building (do not reintroduce)
* **Global Mutex squatting and privilege boundaries:** Named mutexes created without `MutexSecurity` ACL can be opened or created by low-integrity processes on Windows, causing denial of service. Always apply explicit ACLs granting only SYSTEM and Administrators.
* **`$Pid` as a parameter name:** `$PID` is PowerShell's read-only automatic variable; `function f([int]$Pid)` throws on every call (and inside a `try` the failure is silent). Use `$ProcId`.
* **Output into `data\download`:** the installer deletes that folder at the end of every install; anything the engine or scan writes there must create it first.
* **Unbounded file scanning in YARA:** Attempting to scan multi-gigabyte container images or ISOs into memory with YARA can trigger OOM crashes in the engine. Keep a 50MB single-file size threshold for real-time memory sweeps.
* **Atomic inbox IPC:** Writing directly to a monitored directory risks the consumer reading a half-written file. Always write to a `.tmp` file in the same directory and move/rename atomically.
* **External CLI argument arrays:** Never build shell execution strings with string interpolation (`"& '$exe' $args"`). Always invoke native CLIs using argument arrays (`& $exe @args`) to prevent argument injection and quoting bugs.
* **YARA never worked before:** `custom_edr.yar` had a UTF-8 BOM, so YARA exited with "non-ascii character" for every scan. Keep `.yar` files BOM-less ASCII. The engine test-compiles each rule file at start and logs any it skips.
* **Task Scheduler "restart on failure" does not restart a script that exits with a non-zero code.** The engine once crashed and stayed down. Fixes: every engine step is wrapped (`Invoke-Safely`), and the task has a 5-minute repeating trigger with `IgnoreNew` as a watchdog.
* **PowerShell 5.1 gotchas:**
  * `New-Object 'HashSet[string]' ($array)` spreads the array into constructor arguments (crash). Build sets with a loop.
  * `$null` passed to a .NET `string` parameter becomes `""` (`[IO.File]::Replace(a, b, $null)` failed). Use `[NullString]::Value`.
  * A single `PSCustomObject` has no `.Count`. Wrap results in `@()`. This includes `$x = if (...) { @(...) }`, which unrolls a 1-item array: write `$x = @(if (...) { ... })` (the tray's "Matches" column was empty for one hit).
  * Variable names are case-insensitive: `$dl` and `$Dl` are the same variable (the installer's download folder was nearly overwritten by a file path). Use clearly different names.
  * `Sort-Object` is not stable: rows that tie on the sort key may come in any order.
  * Piping a native program into `Select-Object -First n` can stop that program before it finishes (a self-test then writes no dump). Collect the output with `@(...)` first.
  * `Start-Process -ArgumentList` joins its arguments with spaces and does not quote them. Every path argument must carry its own quotes (`"`"$Root\x.ps1`""`) since the install folder is `C:\Program Files\FreeEDR`.
  * Native stderr plus `$ErrorActionPreference='Stop'` throws (Sysmon banner).
  * A scriptblock created with `GetNewClosure()` loses script-scope functions. Use control `.Tag` and `$this` in event handlers instead.
* **robocopy `/XF` excludes a file name at every level**, not only at the top. Copying `C:\EDR` with `/XF EDR-*.ps1` would have dropped the scripts inside `data\backup-*`; the move copies folder by folder instead.
* **`icacls <root>\* /reset /T`** also resets `quarantine\`; its admin-only ACL must be applied again afterwards (§4.7).
* **Sysmon 15.22 crashes (exit 0xC0000409) on `condition="end with any"`.** Use `contains any`. To diagnose a rejected config, apply it with one RuleGroup at a time.
* **A stuck Sysmon driver** (`SysmonDrv` StopPending) makes `Sysmon64 -c` print "Sysmon is not installed. Configuration updated." The config is stored and takes effect after a reboot (E10 reports this).
* **Hayabusa re-reports Sysmon rule hits** as "Proc Exec (Sysmon Alert)" and similar. These are dropped in `Complete-Scan`, because the real-time blade already alerted on them, and the tray hides old ones.
* **AMSI:** scripts containing credential-tool command strings in plain text are blocked by Defender. Keep such strings out of `.ps1` files.
* **Clipboard Locking:** External tools (RDP, Office) lock the Win32 clipboard intermittently. Always wrap `[Clipboard]::SetText` in `try / catch` handling `ExternalException`.
* **WinForms Button Mnemonics:** Setting button `.Text = 'Block & Neutralize'` turns `&` into an accelerator (`_N`) unless `.UseMnemonic = $false`. Context menus need `&&`.
* **ListView Empty Item Layout:** In `Details` mode with multiple columns, placing placeholder text on SubItems makes it render past column boundaries. Put placeholder text directly on `ListViewItem($text)` (Column 0).
* **Clipboard Locking:** External tools (RDP, Office) lock the Win32 clipboard intermittently. Always wrap `[Clipboard]::SetText` in `try / catch` handling `ExternalException`.
* **WinForms Button Mnemonics:** Setting button `.Text = 'Block & Neutralize'` turns `&` into an accelerator (`_N`) unless `.UseMnemonic = $false`. Context menus need `&&`.
* **ListView Empty Item Layout:** In `Details` mode with multiple columns, placing placeholder text on SubItems makes it render past column boundaries. Put placeholder text directly on `ListViewItem($text)` (Column 0).
* **Clipboard Locking:** External tools (RDP, Office) lock the Win32 clipboard intermittently. Always wrap `[Clipboard]::SetText` in `try / catch` handling `ExternalException`.
* **WinForms Button Mnemonics:** Setting button `.Text = 'Block & Neutralize'` turns `&` into an accelerator (`_N`) unless `.UseMnemonic = $false`. Context menus need `&&`.
* **ListView Empty Item Layout:** In `Details` mode with multiple columns, placing placeholder text on SubItems makes it render past column boundaries. Put placeholder text directly on `ListViewItem($text)` (Column 0).
* **Own-process noise:** the tray launches Gemini with `-Command`, not `-EncodedCommand`, so FreeEDR does not flag itself. The test detection is started through `cmd /c start` so it is not treated as a tray child.
* **Global mutex** (`Global\FreeEDR-Engine`) needs SYSTEM/admin. When testing the engine unelevated, rename it.
* **NativeAOT linking** needs `vswhere.exe` on PATH (the VS installer does not add it); `build\EdrBuild` and `src\publish.ps1` add it.

### 8.4 Design rules for future changes
* The engine runs as SYSTEM and must never stop. Wrap new work in `Invoke-Safely` and keep it out of the event path when slow.
* The tray is unelevated, reads the install folder and writes only `user\` and `inbox\`. New engine commands: add the verb to `$allowed` (and, if batchable, the batch whitelist) in `EDR-Control.ps1`, plus the batch filter in `Invoke-EdrCommand`, and validate fields there. Only `resume` and `scan-now` are allowed from `inbox\`.
* Every alert must carry `blade`, `severity`, `title`, and enough fields for a precise block/exclusion. Add its actions in `Get-Actions` (`EDR-Tray.ps1`; feeds both the buttons and the right-click menu) and an explanation in `$RuleHints`/`$BladeHints`.
* New Sysmon rules must be include-only, named, and given a severity in `$RuleSeverity`. Check that they stay quiet while gaming (Epic/EAC paths are excluded in the `BuiltInExclusions` group).
* Paths come from `EDR-Common.ps1` (`$Root`, `$UserDir`, `$DownloadDir`, …); never hard-code `C:\EDR`, `%LOCALAPPDATA%` / `%TEMP%`, a user name or a user's profile path (use `Get-UserProfiles` when every user's folders are needed). FreeEDR keeps every file under `$Root`.
* Edit files only in the repository folder, run `dev_build.cmd` there (all gates must pass), then run `compiled\FreeEDR-Setup.exe`. It backs up, installs, verifies and rolls back by itself. Never edit `C:\Program Files\FreeEDR` directly.
* A new file FreeEDR needs at runtime goes into `$ProjectFiles` in `Install-EDR.ps1`; the build and the installer pick it up from there.
* The C# tray must keep matching `EDR-Tray.ps1` until it replaces it: change both, then run the tests (`dev_build.cmd` does) or `src\parity.ps1`.
