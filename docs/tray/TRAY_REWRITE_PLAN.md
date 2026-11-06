# C# migration - history (completed 2026-11-06)

Read for: why FreeEDR is built the way it is after the move from PowerShell to C#, and what changed for an existing
install. Current implementation: [TRAY_GUI.md](TRAY_GUI.md), [architecture/ARCHITECTURE.md](../architecture/ARCHITECTURE.md).

## 1. Path
* 2026-11-01: plan for a C# tray (Avalonia, NativeAOT) next to the PowerShell engine; phases 0-1 (skeleton, model with
  golden parity tests against `EDR-Tray.ps1 -SelfTest`).
* 2026-11-06: owner decision - migrate **everything** to C# 14 / .NET 10 / Avalonia, all NativeAOT, and address the 20
  improvement proposals (P1-P20 in [history/DECISIONS.md](../history/DECISIONS.md) §9). Result:
  | Before (PowerShell 5.1) | After (C#, NativeAOT) |
  |---|---|
  | `EDR-Engine.ps1` + `EDR-Scan.ps1`, scheduled task "FreeEDR" with a 5-minute watchdog | `FreeEDR-Engine.exe`, Windows service "FreeEDR" (restart on failure); the scan is a background task in the engine |
  | `EventLogWatcher` + reflection on private bookmark fields | `EvtSubscribe` with real bookmarks (`Native\EventSubscription`) |
  | `EDR-Control.ps1` through `powershell -Verb RunAs` | `FreeEDR-Control.exe` (`requireAdministrator`) |
  | `Install-EDR.ps1` / `Uninstall-EDR.ps1` | `FreeEDR-Installer.exe install / uninstall` |
  | `EDR-Tray.ps1` (WinForms, 4,000 lines) | `FreeEDR-Tray.exe` (Avalonia, dark-blue theme, six pages) |
  | Get-CimInstance process list, Get-AuthenticodeSignature, COM firewall | ToolHelp snapshot, WinVerifyTrust, netsh + firewall registry store |
  | `-EncodedCommand`-safe launches, AllSigned limitation | no scripts: AllSigned / Constrained Language policies no longer block FreeEDR |
* Windows PowerShell is still used for the few settings only its cmdlets expose (Defender preferences, a firewall rule by
  id, shortcuts, the one-shot tray start task); values travel in environment variables, never in the script text.
* The golden model tests (`src\Edr.Core.Tests\Fixtures`) were kept: the dashboard model is unchanged except the wording of
  the overall sentence and the section names (Real-time, Event logs); the golden files were refreshed for that.

## 2. Upgrade of an existing (PowerShell) install
The installer stops and disables the old scheduled tasks, stops the PowerShell engine and trays, backs up the scripts,
installs the programs and the service, and - after a successful check - deletes the old tasks and scripts. If the check
fails it removes the service and re-enables the PowerShell engine and tray (ROLLED BACK). Settings, allows, verdicts,
bans, strikes, events and every account's tray files are kept (same file formats). Program verdicts of the old
"enforce" mode stay listed as flagged; a file quarantined by the old version is restored when its verdict is removed.
