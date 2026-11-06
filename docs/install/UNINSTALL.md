# Uninstall: what is removed and restored

Read for: changes to `src\Edr.Setup\Uninstaller.cs`, or to anything the installer sets up outside `C:\Program Files\FreeEDR`
(every such change needs its undo here). Installation: [INSTALLATION.md](INSTALLATION.md).

Run: **Settings > Apps > FreeEDR > Uninstall** (runs `C:\Program Files\FreeEDR\bin\FreeEDR-Installer.exe uninstall --from-setup`,
then Setup removes the folder), or elevated `FreeEDR-Installer.exe uninstall`. Best effort: a failed step is a WARN and the
next one still runs. Result line `UNINSTALL RESULT: SUCCESS` (exit 0) or `DONE WITH n WARNING(S)` (exit 1). Log:
`%TEMP%\FreeEDR-uninstall.log`.

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
| Files | Settings > Apps entry (direct runs only), `C:\Program Files\FreeEDR` (events, settings, allow/block lists, tools), leftover `C:\EDR`, `C:\LocalEDR`, `C:\Wail2Ban`. Files still in use are reported; delete the folder after a restart |

The per-user notification registration (`HKCU\Software\Classes\AppUserModelId\FreeEDR.Tray`) is harmless and left in place.
