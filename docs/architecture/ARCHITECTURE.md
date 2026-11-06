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
                    │  └─ Commands: control\ (admin) and inbox\ (user: resume, scan-now only)                 │
                    └───────────┬─────────────────────────────────────────────────────▲──────────────────────┘
                                │ data\events.jsonl, status.json, cve-current.json     │ control\*.json
                                ▼                                                      │
   FreeEDR-Tray.exe (each signed-in account, unelevated) ──── UAC ────► FreeEDR-Control.exe (elevated, validates)
        └─ inbox\*.json (resume, scan-now)
```
* **Detect-only.** No FreeEDR program stops processes or moves files. Wail2Ban's inbound firewall rules are the one
  enforcement, switchable to report-only (`wail2ban.block`).
* **One validation gate.** `PatternRules.IsValidCommand/IsValidOp` (Edr.Core) runs in the elevated helper before a request
  is written and in the engine before it is executed; the tray's own checks are advisory.
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
| `Local\FreeEDR-Tray`, `Local\FreeEDR-Tray-Show`, `Local\FreeEDR-Tray-Exit` | one tray per session, "show the dashboard", installer-driven exit (`-Dev` suffix with `--dev`) |
| Service `FreeEDR` | the engine |
| AppUserModelID `FreeEDR.Tray` | native notifications |
| Event source `wail2ban` | Application log (1000 ban, 1001 ban failed, 2000 unban, 3000 forensic audit) |

## 5. Permissions (set by the installer)
Owner Administrators; Administrators + SYSTEM full; Users read+execute; `inbox\` + Users (W,D); `user\` Users list-only,
`user\<SID>\` modify for that account. Details: [install/INSTALLATION.md](../install/INSTALLATION.md) §0.
