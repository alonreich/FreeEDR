# Architecture: processes, trust boundaries, folders

Read for: any change that crosses a process boundary (engine ↔ tray ↔ control helper ↔ installer), touches permissions,
or adds a component. Details per area: [engine/DETECTION.md](../engine/DETECTION.md),
[engine/COMMANDS_AND_IPC.md](../engine/COMMANDS_AND_IPC.md), [engine/WAIL2BAN.md](../engine/WAIL2BAN.md),
[DATA_FILES.md](DATA_FILES.md), [tray/TRAY_GUI.md](../tray/TRAY_GUI.md).

## 1. Two folders
| Folder | Role |
|---|---|
| `<repo>\` | **Development**: source, docs, build pipeline, `compiled\FreeEDR-Setup.exe`. All edits and build outputs happen here |
| `C:\Program Files\FreeEDR\` | **Production**: the installation (`EdrPaths.DefaultRoot`, the 64-bit Program Files folder). Written only by the installer, the engine and the elevated helper. Admin-only; every account reads it and has its own private tray folder `user\<SID>\` |

Outside these two folders there are only Windows integrations: the Sysmon service and driver, the **FreeEDR** service,
the `HKLM\...\Run` value, the all-users "FreeEDR" shortcuts, the Settings > Apps entry, Wail2Ban's firewall rules,
Defender settings, the Application event source `wail2ban`, and each account's notification registration
(`HKCU\Software\Classes\AppUserModelId\FreeEDR.Tray`, written by that account's tray). The uninstaller removes or restores
each of them ([install/UNINSTALL.md](../install/UNINSTALL.md)).

## 2. How it works
```
                    ┌──────────────── SYSTEM: Windows service "FreeEDR" (FreeEDR-Engine.exe) ────────────────┐
 Windows event logs │ EventSubscription (wevtapi, bookmarks) ──► one queue ──► main loop (batches of 50)        │
  • Sysmon          │  ├─ Realtime: Sysmon record → own-process trust → allows → IOC → YARA worker → event     │
  • Security        │  ├─ Wail2Ban: failed logon → count per IP → firewall block 5^n min (or report only)       │
    4625 / 4624     │  ├─ Logins: successful network/RDP logon from a public IP → "Was this you?"              │
  • RdpCoreTS 140   │  ├─ DefenderEvents: 1116 / 1121 / 1122 / 1123 / 1124                                      │
  • Defender        │  ├─ Scanner (background task): IOC feed, Hayabusa/Sigma, OSV, tool versions             │
                    │  ├─ Health: Sysmon service+driver+rule set, watcher restart, heartbeat every 15 s       │
                    │  └─ Commands: pipe \\.\pipe\FreeEDR-Engine (control\ / inbox\ when engine is down)   │
                    └───────────┬─────────────────────────────────────────────────────▲──────────────────────┘
                                │ data\events.jsonl, status.json, cve-current.json     │ control\*.json
                                ▼                                                      │
   FreeEDR-Tray.exe (each signed-in account, unelevated) ──── UAC ────► FreeEDR-Control.exe (elevated, validates)
        └─ inbox\*.json (resume, scan-now)
```
* **Detect-only.** No FreeEDR program stops processes or moves files. Wail2Ban's inbound firewall rules are the one
  enforcement, switchable to report-only (`wail2ban.block`).
* **Backend and frontend are separate processes.** The engine (service, SYSTEM) never depends on a dashboard: a crashed
  or hung dashboard cannot stop it; Windows restarts the service on failure, and Windows restarts a crashed or hung
  dashboard (`RegisterApplicationRestart`; a deliberate exit or an installer stop does not). When the dashboard cannot
  reach the engine, Home shows "The FreeEDR engine is not responding" with *Restart engine* and *Open engine log*.
* **Native IPC.** Requests and change notices go over the engine's named pipe `\\.\pipe\FreeEDR-Engine`; the caller is
  identified by its Windows token; per-account connection caps keep one account from taking it from the others.
  `control\` / `inbox\` remain only as the offline queue, read by worker threads with `Native\DropFile` (no link
  followed, no oplock waited on, at most 64 KB), never by the main loop
  ([engine/COMMANDS_AND_IPC.md](../engine/COMMANDS_AND_IPC.md) §1-2). `events.jsonl` / `status.json` stay the engine's
  data store, which the dashboards read; the engine is the only writer of `events.jsonl`.
* **Least privilege.** The engine stays LocalSystem (Security log, firewall, Defender, Sysmon need it) but its service
  keeps only the privileges in `EdrPaths.EnginePrivileges` (no SeDebug, SeTcb, SeLoadDriver, SeBackup, SeRestore,
  SeTakeOwnership, ...) and has its own service SID (`NT SERVICE\FreeEDR`).
* **One validation gate.** `PatternRules.IsValidCommand/IsValidOp` (Edr.Core) runs in the elevated helper before a request
  is written and in the engine before it is executed; the tray's own checks are advisory.
* **UAC is not consent to a payload.** Any unelevated process can start the helper, so the helper shows the decoded
  request in its own elevated confirmation (default No; the whole request or the helper refuses it) and always uses the installed folder (no `--root` in the helper
  or the installer) ([engine/COMMANDS_AND_IPC.md](../engine/COMMANDS_AND_IPC.md) §2).
* **Evidence survives a cleared log.** The engine copies the important Windows logs to the admin-only
  `data\archive\` in the background and reports any log clear live ([engine/DETECTION.md](../engine/DETECTION.md) §1).
* **Setup has a window, not a console.** FreeEDR-Installer.exe uses Avalonia with the dashboard's theme (Theme.axaml
  linked from Edr.Tray); the pinned tools ship inside Setup ([install/INSTALLATION.md](../install/INSTALLATION.md) §2).
* **Untrusted-input parsers are sandboxed.** YARA, Hayabusa's event-log scan and OSV-Scanner run at low integrity with
  no privileges in a Job object (`Native\Sandbox`), never with the engine's SYSTEM rights; their only writable place is
  `data\sandbox\` (labelled low integrity, admin-only DACL) ([engine/DETECTION.md](../engine/DETECTION.md) §3, §4).
* **NativeAOT.** All four programs are self-contained native executables; JSON is handled with `JsonNode` and the UI is
  built in code, so nothing depends on reflection.

## 3. Processes and trust
| Process | Account | Started by | May write |
|---|---|---|---|
| FreeEDR-Engine.exe | LocalSystem | service manager (automatic, restart on failure) | everything under the install folder, firewall rules, Defender allows |
| FreeEDR-Control.exe | an administrator (UAC) | the tray (`runas`) | `control\`, `config\edr-config.json` (set-config), service control, tools (update-tool), factory reset |
| FreeEDR-Installer.exe | an administrator | FreeEDR-Setup.exe / Settings > Apps | everything it installs (§1) |
| FreeEDR-Tray.exe | each signed-in user, unelevated | `HKLM\...\Run`, Start menu | `user\<SID>\`, `inbox\`, its HKCU notification registration |

**Own-process trust** (`OwnProcess.Check`): FreeEDR's executables are identified by their exact path under the admin-only
install folder. Their children are trusted only when they run elevated (engine/helper/installer) or are one of the
programs the tray starts (Explorer, Notepad, winget, Defender's scanner, cmd/conhost, Windows Terminal). A command line
that only names FreeEDR's programs is reported as "Command line imitates FreeEDR's own scripts".

## 4. Kernel objects and names
| Name | Use |
|---|---|
| `Global\FreeEDR-Engine` | engine single instance (ACL: SYSTEM + Administrators) |
| `\\.\pipe\FreeEDR-Engine` | the engine's request / notification pipe (owner SYSTEM/Administrators, local only) |
| `Local\FreeEDR-Tray`, `Local\FreeEDR-Tray-Show`, `Local\FreeEDR-Tray-Exit` | one tray per session, "show the dashboard", installer-driven exit (`-Dev` suffix with `--dev`) |
| Service `FreeEDR` | the engine |
| AppUserModelID `FreeEDR.Tray` | native notifications |
| Event source `wail2ban` | Application log (1000 ban, 1001 ban failed, 2000 unban, 3000 forensic audit, 4000 alerts could not be written to events.jsonl) |

## 5. Permissions (set by the installer)
Owner Administrators; Administrators + SYSTEM full; Users read+execute; `inbox\` + Users (W,D); `user\` Users list-only,
`user\<SID>\` modify for that account. Details: [install/INSTALLATION.md](../install/INSTALLATION.md) §0.
