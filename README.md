# 🛡️ FreeEDR

**A free endpoint detection & response (EDR) system for a single Windows PC, built entirely from free tools, with a
dashboard that non-experts can understand.**

![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-0078D6)
![.NET](https://img.shields.io/badge/C%23%2014-.NET%2010%20NativeAOT-512BD4)
![UI](https://img.shields.io/badge/UI-Avalonia-8B44AC)
![Mode](https://img.shields.io/badge/mode-detect--only-success)

FreeEDR watches your PC in real time, scans event logs and Python packages twice a day, catches password guessing on
Remote Desktop and file sharing, and explains every alert in plain language. **It only detects and logs**: it never
stops, deletes or quarantines anything, so it never gets in the way of your work. Microsoft Defender stays your
antivirus. The one part that acts is **Wail2Ban**, which blocks computers that keep failing to sign in over the network
(you can switch it to report-only).

---

## ✨ What it does

| | Protection | How |
|---|---|---|
| ⚡ | **Real-time detection** | Sysmon watches process starts, risky Windows tools, LSASS (password store) access, persistence, unsigned drivers, Defender tampering, log clearing |
| 🧬 | **Malware hash + YARA** | The program behind every alert is checked against known-malware hashes and YARA rules for credential theft and ransomware |
| 📜 | **Sigma event-log scan** | Thousands of community Sigma rules over the recent event logs (Hayabusa), at 06:00 and 18:00 |
| 🐍 | **Vulnerabilities (CVE)** | Python packages with a known, **fixable** vulnerability (OSV-Scanner), with a one-click update |
| 📦 | **App updates** | Installed apps with updates available (winget) |
| 🔐 | **Wail2Ban** | Blocks password guessing over RDP/SMB in Windows Firewall, and asks "Was this you?" about sign-ins from the internet |
| 🛡️ | **Microsoft Defender** | Defender's detections, and what its attack-surface-reduction rules would have blocked (audit mode) |
| ❤️ | **Self-health** | Engine heartbeat, Sysmon sensor health, scan problems |

Highlights:
* **Clear answers:** every alert says what happened and what to do, with buttons for *Allow*, *Flag as threat*,
  *Scan with Microsoft Defender*, *Look up on VirusTotal* or *Mark reviewed*.
* **Learns with you:** a 7-day learning week with only critical notifications, suggestions to allow what you keep marking
  reviewed, and a weekly summary.
* **Trusted apps:** Claude Code, ChatGPT/Codex, OneDrive, Office, Google Drive and more run without alerts; switch each on or off.
* **Game-friendly:** Fortnite / Epic / Easy Anti-Cheat are excluded and notifications wait while you play.
* **Native and fast:** every program is a NativeAOT executable; no PowerShell, no runtime to install.
* **Everything in one folder** (`C:\Program Files\FreeEDR`), admin-only; a real uninstaller puts every Windows setting back.

## 🚀 Install

1. Download or build **`compiled\FreeEDR-Setup.exe`**.
2. Run it and approve the administrator prompt. It installs Sysmon and the tools (hash-verified), sets everything up,
   checks every part, and rolls back if the new version does not start.
3. The shield appears in the notification area and a short welcome asks which apps you trust.

Listed in **Settings > Apps** as "FreeEDR"; **Uninstall** there removes everything and restores the Windows settings it
changed. Unattended: `FreeEDR-Setup.exe /VERYSILENT`. Requirements: Windows 10 1809+/11 x64, Microsoft Defender.
Details: [docs/install/INSTALLATION.md](docs/install/INSTALLATION.md).

## 🖥️ Using it

| Shield | Meaning |
|---|---|
| 🟢 ✓ | Protected, nothing to review |
| 🟠 ! | Something needs your review, or the last scan had problems |
| ⚪ II | Something is paused |
| 🔴 X | Protection is off or broken |

The dashboard has **Home** (status, "Was this you?", one tile per protection with pause/resume, suggestions, your week),
**Activity** (every alert, filterable, with the details pane), **Network** (Wail2Ban), **Updates** (vulnerabilities,
app updates, FreeEDR's own tools with one-click updates), **Allowed & trusted** and **Settings**. Full guide:
**[docs/user/USER_GUIDE.md](docs/user/USER_GUIDE.md)**.

## 🏗️ How it works

```
 Windows event logs ──► FreeEDR-Engine.exe (Windows service "FreeEDR", SYSTEM)
   Sysmon · Security        real-time · Wail2Ban · Defender · scans · health
   RDP · Defender                    │ data\events.jsonl, status.json          ▲ requests (JSON files)
                                     ▼                                          │
                         FreeEDR-Tray.exe (each user, unelevated) ── UAC ──► FreeEDR-Control.exe ──► control\
```

* The engine runs as a SYSTEM service that restarts itself on failure.
* The dashboard only reads; every change that weakens detection (allow, pause, settings) needs a Windows UAC approval and
  is validated again by the engine.
* All programs sit in an admin-only folder, so malware running as a user cannot change them.

More: [docs/architecture/ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md).

## 🧰 Built with

[Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) ·
[YARA](https://github.com/VirusTotal/yara) ·
[Hayabusa](https://github.com/Yamato-Security/hayabusa) (Sigma) ·
[OSV-Scanner](https://github.com/google/osv-scanner) ·
[Velociraptor](https://github.com/Velocidex/velociraptor) ·
[Neo23x0 signature-base](https://github.com/Neo23x0/signature-base) ·
Microsoft Defender · C# 14 / .NET 10 NativeAOT · [Avalonia](https://avaloniaui.net) · Inno Setup

## 👩‍💻 Development

```
<repo>\
  src\                     the product: Edr.Core, Edr.Engine, Edr.Control, Edr.Setup, Edr.Tray, Edr.Core.Tests
  config\, rules\          Sysmon template, YARA rules
  build.cmd, dev_build.cmd, build\   build pipeline -> compiled\FreeEDR-Setup.exe
  tests\                   test bundle
  docs\                    documentation (index: project_structure.txt)
```

Workflow for every change:
```
dev_build.cmd                                                         # all build gates must pass
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1   # unelevated; read tests\results\last-run.txt
```
Building needs the .NET 10 SDK, Visual Studio 2022 C++ Build Tools (NativeAOT linker) and Inno Setup 6.3+. A build never
installs anything. Optional code signing: see [docs/agents/AGENT_WORKFLOW.md](docs/agents/AGENT_WORKFLOW.md) §3.

**AI agents:** start at [`project_structure.txt`](project_structure.txt). Rules: [AGENTS.md](AGENTS.md).

## 📚 Documentation

| Doc | For |
|---|---|
| [User guide](docs/user/USER_GUIDE.md) | Dashboard, trusted apps, games, Defender, troubleshooting, limits |
| [Installation](docs/install/INSTALLATION.md) · [Uninstall](docs/install/UNINSTALL.md) | What Setup does, step by step, and how to verify it |
| [Architecture](docs/architecture/ARCHITECTURE.md) · [Data files](docs/architecture/DATA_FILES.md) | Processes, permissions, every file and setting |
| [Detection](docs/engine/DETECTION.md) · [Commands](docs/engine/COMMANDS_AND_IPC.md) · [Wail2Ban](docs/engine/WAIL2BAN.md) | Engine internals |
| [Dashboard](docs/tray/TRAY_GUI.md) · [Migration history](docs/tray/TRAY_REWRITE_PLAN.md) | The tray app |
| [Agent workflow](docs/agents/AGENT_WORKFLOW.md) · [Pitfalls](docs/reference/POWERSHELL_PITFALLS.md) | Contributing |
| [Status](docs/history/STATUS.md) · [Decisions](docs/history/DECISIONS.md) | Open items, history and why things are built this way |

## ⚠️ Known limits

Detect-only (removal is left to Microsoft Defender) · Python-only CVE scan · x64 only · unsigned unless a code-signing
certificate is configured for the build (SmartScreen may warn) · every account on the PC can see all alerts. Full list:
[user guide §8](docs/user/USER_GUIDE.md#8-known-limits).
