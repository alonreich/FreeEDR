# Uninstall: what is removed and restored

Read for: changes to `src\Edr.Setup\Uninstaller.cs`, or to anything the installer sets up outside `C:\Program Files\FreeEDR`
(every such change needs its undo here). Installation: [INSTALLATION.md](INSTALLATION.md).

Run: **Settings > Apps > FreeEDR > Uninstall** (Setup's `CurUninstallStepChanged` runs
`C:\Program Files\FreeEDR\bin\FreeEDR-Installer.exe uninstall --from-setup` and waits), or elevated
`FreeEDR-Installer.exe uninstall`. Best effort: a failed step is a WARN and the next one still runs. Result line
`UNINSTALL RESULT: SUCCESS` (exit 0), `DONE WITH n WARNING(S)` (exit 1: only files still in use after the restore worked)
or `INCOMPLETE` (exit 5, below). Log: `%TEMP%\FreeEDR-uninstall.log`.

**The restore record is never lost.** When a step before "Files" warns (a Windows setting not put back), the uninstaller
keeps `data\preinstall.json`, `data\managed.json`, the Sysmon backup and `bin\`, deletes the rest and exits 5. Setup
then keeps the folder (it deletes `C:\Program Files\FreeEDR` only after exit 0 or 1, never with a fixed
`[UninstallDelete]`), registers **Settings > Apps > "FreeEDR (finish removal)"**
(`HKLM\...\Uninstall\FreeEDR-FinishRemoval`, runs `bin\FreeEDR-Installer.exe uninstall`) and says so. A later successful
run removes that entry too. A helper that cannot start counts as a failure (folder kept).

The uninstaller shows the setup window's progress and result pages (no console; `--silent` runs headless). When nothing
was ever set up (Setup cancelled before its first step: no `preinstall.json`, `managed.json` or engine), it changes no
Windows setting and only the folder is removed.

The settings recorded before the first install (`data\preinstall.json`) are restored; when nothing is on record (an older
install already changed them), FreeEDR's additions are removed and Windows' defaults apply.

| Step | What happens |
|---|---|
| Stop | Service **FreeEDR** stopped and deleted; scheduled tasks `FreeEDR`, `EDR`, `FreeEDR tray start` (and any in `managed.json`) removed; every account's tray, the engine, scans and tools stopped (also PowerShell processes of older versions) |
| Tray start | `HKLM\...\Run\FreeEDR Tray` removed; per-user `FreeEDR Tray` / `EDR Tray` values removed from every account's hive; all-users and per-user "FreeEDR" shortcuts removed |
| Firewall | Every Wail2Ban block rule (`a a a wail2ban block IP: *`) removed; IPv6 RDP block rules removed; "Remote Desktop - Shadow (TCP-In)" enabled again only if it was on before |
| Defender | Allows made from the dashboard (threat IDs, ASR exclusions, Controlled folder access apps), the game allow-list and the setup threat-ID allow removed (unless on record from before); ASR rules set back to their earlier action or removed; Controlled folder access back to its earlier value (Windows default: off) |
| Sysmon | Removed (service, driver, program, event log file) when FreeEDR installed it; a Sysmon that was there before stays, with its earlier configuration imported back |
| Event source | `wail2ban` removed unless it existed before |
| Files | Settings > Apps entry (direct runs only) and the "finish removal" entry, `C:\Program Files\FreeEDR` (events, settings, allow/block lists, tools), leftover `C:\EDR`, `C:\LocalEDR`, `C:\Wail2Ban`. Files still in use are reported; delete the folder after a restart |

The per-user notification registration (`HKCU\Software\Classes\AppUserModelId\FreeEDR.Tray`) is harmless and left in place.
