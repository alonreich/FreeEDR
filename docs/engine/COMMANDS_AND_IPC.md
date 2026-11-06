# Commands, IPC, pause/audit and verdicts

Read for: `src\Edr.Control` (FreeEDR-Control.exe), `src\Edr.Engine\Commands.cs`, `PatternRules` (Edr.Core), the tray's
`Services\Commands.cs` / `Controller.cs`, pause/resume, forensic audit logging. Allow schemas: [DETECTION.md](DETECTION.md) §6.

## 1. Two drop folders
| Folder | Who writes | Verbs the engine accepts |
|---|---|---|
| `control\` | `FreeEDR-Control.exe`, elevated through UAC (admin-only folder) | `pause`, `resume`, `scan-now`, `unban`, `exclude`, `unexclude`, `block`, `unblock`, `batch` |
| `inbox\` | the unelevated tray, any account | only `resume` and `scan-now` (anything else is logged "needs admin" and ignored) |

`restart-engine`, `set-config`, `restore-defaults` and `update-tool` are carried out by the elevated helper itself.

## 2. Flow
1. Tray `Commands.Admin`: JSON → base64 → `ShellExecute runas "C:\Program Files\FreeEDR\bin\FreeEDR-Control.exe" --payload <b64>`
   (about 32,000 characters at most: above 30,000 the tray asks for fewer items). Waits without blocking the UI;
   UAC declined → "Cancelled, nothing was changed". Exit codes: 0 done, 2 refused (invalid), 3 failed, 5 not elevated.
2. `FreeEDR-Control.exe` (manifest `requireAdministrator`): payload ≤ 64 KB, valid JSON, `PatternRules.IsValidCommand`
   (known verb; batch 1-100 batchable ops each valid). Then either does the work (§3) or writes `control\<time>-<rand>.tmp`
   and renames it to `.json`.
3. Engine `Commands.Read` every loop and every 50 records / 2 s under load: `control\` first, then `inbox\`; at most 25
   `*.json` per folder per sweep; files over 64 KB deleted unread; a file is deleted **before** it runs (3 tries; a locked
   file is skipped for 5 minutes); inbox `.tmp` files older than 2 minutes are removed. `Commands.Execute` validates every
   request again with `PatternRules.IsValidOp`.
4. Tray `Commands.User`: `inbox\<time>-<rand>.tmp` → `.json`; when that fails, it falls back to the elevated helper.

## 3. Verbs
| Verb | Fields | Effect |
|---|---|---|
| `pause` | `blade` (`edr`, `realtime`, `malware`, `sigma`, `cve`, `wail2ban`), `minutes` (0 = until resumed: `9999-12-31T00:00:00`), `user` | sets `<blade>PausedUntil` in `state.json`; `edr`/`sigma`/`cve` stop a running scan; forensic audit (§4) |
| `resume` | `blade`, `user` | clears the pause; forensic audit |
| `scan-now` | — | starts the scan (at most every 2 min; refused while `edr` is paused) |
| `exclude` | `blade` + list fields | adds an allow (duplicates are not added; a profile tag is added to an untagged twin). `wail2ban` allows also unban every matching address; `defender` allows are applied in Defender first |
| `unexclude` | `id` | removes the allow (and the Defender allow) |
| `block` | `blade`, `image`, `sha256`, `ip`, `title` | verdict (§5) |
| `unblock` | `id` | removes the verdict (restores a legacy quarantined file) |
| `unban` | `ip` | removes verdicts and the firewall rule for that address, forgets its strikes |
| `batch` | `ops[]` | several steps behind one UAC prompt (e.g. unblock + exclude = "move to Allowed") |
| `restart-engine` | — | helper: stop and start the service |
| `set-config` | `config` (any of the keys in [architecture/DATA_FILES.md](../architecture/DATA_FILES.md) §2), `restart` | helper: validates and clamps each value, writes `edr-config.json` atomically, audit line + Event ID 3000; a changed `defenderMode` applies audit mode or restores Defender at once; the engine reloads the file within a minute |
| `restore-defaults` | — | helper: stops the service; default settings (keeps `installedAt`, `defenderMode`); allows = the recommended trusted apps; empty verdicts; every Wail2Ban rule removed; strikes, state, bookmarks and events deleted; every account's reviewed/history/hidden/insights files deleted; starts the service |
| `update-tool` | `name` (Hayabusa, YARA, OSV-Scanner, Velociraptor) | helper: `Tools.UpdateToLatest` (GitHub latest release, asset must carry a SHA256 digest and match it, swapped in with roll-back if the new copy does not run); event `kind = tool-update`; YARA restarts the engine to recompile rules |

## 4. Pause/resume and forensic audit
Timed pauses expire automatically ("<part> resumed automatically" Info event). Every pause, resume, exclude, unexclude,
settings change and factory reset writes `[FORENSIC-AUDIT] [<UTC>] [USER: <user>] [RUBRIC: <part>] [ACTION: ...] ...` to
`data\engine.log` and Event ID 3000 to the Application log (source `wail2ban`); pause/resume/allow changes also add a
`system` event with `kind = 'audit'` (Activity ▸ Messages, CSV export in Settings). Scope texts: `Catalog.PauseScope`.

## 5. Verdicts (`config\blocklist.json`)
FreeEDR only detects: a verdict never stops or moves a program.
| Blade | Effect |
|---|---|
| `realtime` / `ioc` / `yara` | "Flagged as a threat by you": on record; the tray offers *Scan with Microsoft Defender* and *Look up on VirusTotal* |
| `sigma` | "Confirmed as a threat by you" (past log entries; nothing to stop) |
| `wail2ban` | permanent inbound firewall block (`Expire: never`), re-applied every minute if removed by hand; with `wail2ban.block = false` only recorded |

Every verdict writes a `system` Info event `kind = 'verdict'` and an audit log line.
