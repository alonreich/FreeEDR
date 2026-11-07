# Commands, IPC, pause/audit and verdicts

Read for: `src\Edr.Control` (FreeEDR-Control.exe), `src\Edr.Engine\Commands.cs`, `PatternRules` (Edr.Core), the tray's
`Services\Commands.cs` / `Controller.cs`, pause/resume, forensic audit logging. Allow schemas: [DETECTION.md](DETECTION.md) §6.

## 1. The engine's pipe, and the drop folders as the offline queue
**Primary channel: the named pipe `\\.\pipe\FreeEDR-Engine`** (`EnginePipe` in Edr.Core, `PipeServer` in the engine).
One JSON object per line (UTF-8, ≤ 64 KB). `{"op":"command","cmd":{...}}` is answered with `{"ok":..,"message":".."}`;
`{"op":"subscribe"}` keeps the connection open and receives `{"type":"changed"}` at most every 300 ms after a new event
or status write (the dashboard then refreshes at once; its timer is a 5 s safety net).
* **Who may do what is decided by the caller's Windows token**, read from the pipe (impersonation), never by the request:
  an elevated administrator (Administrators enabled: the helper after UAC) may send every engine verb; any other
  account only `resume` and `scan-now`. The audit user is the token's account name (also for every step of a batch).
* **ACL**: SYSTEM, Administrators and the creating account full; Authenticated Users read/write (no new instances);
  NETWORK denied (local only). Created as the first instance: if another program already holds the name, the engine
  logs it and raises "FreeEDR's command channel is blocked".
* **Clients trust only a pipe owned by SYSTEM or Administrators** (a normal account cannot create that), so a squatted
  pipe never receives a request; they fall back to the drop folders.
* Requests are queued and run on the engine's main loop (`PipeServer.Drain` → `Commands.Execute`, which now returns
  accepted / refused), so command handling stays single-threaded. A request waits ≤ 25 s.
* **No account can take the pipe from the others** (audit 2026-11-07, finding 5): 16 connections at most, of which 4
  never go to subscriptions; per account (SID + elevated or not, from the client process's token via
  `Win32.PipeClientKey`) at most 4 connections and 3 subscriptions (one dashboard per session); the first line must
  arrive within 5 s; a subscriber that sends anything after `subscribe` is dropped. Lines are read in 4 KB blocks
  (`EnginePipe.LineReader`); a line over 64 KB ends the connection. Refused connections: `status.json` `pipe.refused`.

**Offline queue: the drop folders**, used only when the pipe is not reachable (engine stopped or starting); the engine
reads them at its next start and while it runs (§2, step 3):

| Folder | Who writes | Verbs the engine accepts |
|---|---|---|
| `control\` | `FreeEDR-Control.exe`, elevated through UAC (admin-only folder), and FreeEDR's own elevated programs | `pause`, `resume`, `scan-now`, `unban`, `exclude`, `unexclude`, `block`, `unblock`, `batch`, `note` |
| `inbox\` | the unelevated tray, any account | only `resume` and `scan-now` (anything else is logged "needs admin" and ignored) |

`restart-engine`, `set-config`, `restore-defaults` and `update-tool` are carried out by the elevated helper itself.

## 2. Flow
1. Tray `Commands.Admin`: JSON → base64 → `ShellExecute runas "C:\Program Files\FreeEDR\bin\FreeEDR-Control.exe" --payload <b64>`
   (about 32,000 characters at most: above 30,000 the tray asks for fewer items). Waits without blocking the UI;
   UAC declined → "Cancelled, nothing was changed". Exit codes: 0 done, 2 refused (invalid), 3 failed, 4 declined in the
   helper's confirmation (also "Cancelled"), 5 not elevated, 6 too large to confirm in one window (the tray says "at
   most 20 changes per approval"; `Commands.Ops` checks this first, so no UAC prompt appears for it).
2. `FreeEDR-Control.exe` (manifest `requireAdministrator`): payload ≤ 64 KB, valid JSON, `PatternRules.IsValidCommand`
   (known verb; batch 1-100 batchable ops each valid). The UAC prompt only names the program and any unelevated process
   can start it with its own payload, so the helper then shows the decoded request (`RequestSummary`) in its own elevated
   Yes/No window, default No (UIPI keeps unelevated programs from clicking it). **The window shows the whole request
   or the helper refuses it** (exit 6; audit 2026-11-07, finding 2): no value is shortened and no step is left out (more
   than 20 lines or 6,000 characters = refused); the fields that decide what an allow covers come first in a fixed order
   (`image`, `parent`, `parentSigner`, `signer`, `ancestors`, `rule`, `match`, `detail`, `raw`, `title`, `path`, ...), so
   the payload cannot push them out of view; control and Unicode formatting characters (line breaks, right-to-left
   overrides, zero-width) are replaced. Compact forms only where the content is FreeEDR's own: a trusted-app profile
   whose allows are exactly the built-in ones is one line ("Trust the app ..."), and anything added to it lists every
   allow; allows and verdicts to remove are shown as what they cover (looked up in `exclusions.json` /
   `blocklist.json`), not as ids; `set-config` is shown as the settings that change (old → new). The audit user of a
   request the helper forwards is always the elevated account's name, never what the payload says. It always works on
   the installed folder (`EdrPaths.DefaultRoot`): there is no `--root`, so a caller cannot hand it its own settings or
   Defender baseline. FreeEDR-Installer.exe has no `--root` either. Then either does the work (§3) or sends the request
   over the pipe (exit 0 accepted, 2 refused by the engine, with the reason in engine.log); only when no trusted engine
   answers does it write `control\<time>-<rand>.tmp` and rename it to `.json`.
3. Engine `CommandIntake`: **one worker thread per folder, never the main loop** (audit 2026-11-07, finding 1: any
   account can write `inbox\`, so nothing about a file there may delay detection). Every second, at most 25 `*.json` per
   folder, each taken with `Native\DropFile.Take` (NtCreateFile): the file itself is opened, never a link it names (a
   symbolic link or junction is removed, not followed); an opportunistic lock is reported, not waited for
   (`FILE_COMPLETE_IF_OPLOCKED` → "busy"); it shares read only, so nobody can write it while it is read, and at most
   64 KB are read (a larger file is removed unread); a file with more than one name (hard link) is never read, only its
   drop-folder name is removed; a file the engine may not read is removed unread; the file is marked for deletion on the
   same handle **before** its content is used (a request runs at most once). A busy file is retried after 30 s and never
   takes the place of new requests (logged once after 5 minutes). Parsed requests are queued (≤ 200) and run on the main
   loop (`Commands.RunQueued`, ≤ 50 per pass); an inbox request is recorded as "a local account (inbox)", whatever name
   it claims. A worker stuck on one file operation for over a minute raises "FreeEDR's inbox/control folder is blocked"
   (High; detection is not affected). Inbox `.tmp` files older than 2 minutes are removed the same way. `status.json`
   `commandIntake`: queued, and per folder taken / refused / waiting / stuck. `Commands.Execute` validates every request
   again with `PatternRules.IsValidOp`.
4. Tray `Commands.User` (resume, scan-now): over the pipe (answered at once); engine not reachable → `inbox\<time>-<rand>.tmp`
   → `.json`; when that fails too, the elevated helper.

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
| `set-config` | `config` (any of the keys in [architecture/DATA_FILES.md](../architecture/DATA_FILES.md) §2), `restart` | helper: validates and clamps each value, writes `edr-config.json` atomically, audit line + Event ID 3000; a changed `defenderMode` applies audit mode or restores Defender at once; the engine reloads the file within 5 s (`status.json` `settingsLoaded`). The dashboard sends only the values that changed |
| `restore-defaults` | — | helper: stops the service; `FactoryReset.Apply(everything: false)` (Edr.Core, shared with Setup's clean install): default settings (keeps `installedAt`, `defenderMode`); allows = the recommended trusted apps; empty verdicts; every Wail2Ban rule removed; strikes, state, bookmarks and events (also rotated `events-*.jsonl` and `.corrupt-*` copies) deleted; pending `control\` / `inbox\` requests deleted; every account's reviewed/history/hidden/insights files deleted; logs, scan results and the event archive stay; starts the service |
| `update-tool` | `name` (Hayabusa, YARA, OSV-Scanner, Velociraptor) | helper: `Tools.UpdateToLatest`, **only for a tool whose releases are Authenticode-signed by a pinned publisher** (`ToolSpec.Publisher`; today Velociraptor, "Rapid7 LLC"; audit 2026-11-07, finding 4): GitHub's latest release, the asset must carry GitHub's SHA256 digest and match it (transfer check), the executable must carry a valid signature of that publisher (origin check: GitHub computes its digest from whatever was uploaded), and it must answer its version query before it replaces the installed copy (roll-back otherwise). Hayabusa, YARA and OSV-Scanner publish unsigned releases: refused with "not digitally signed"; they change only with a FreeEDR release (a new pin). Version queries run in the sandbox (for a tool whose manifest demands elevation, its version resource is read). Event `kind = tool-update` (through `note`); YARA restarts the engine to recompile rules |
| `note` | `blade` = `system`, `severity` (Info, Medium, High), `title` (≤ 200), `process` (≤ 260), `detail` (≤ 4,000), `kind` (status, health, tool-update), `tool`, `ok` | an event from FreeEDR's own elevated programs (`EngineNote.Send`: the helper's Defender and tool-update messages, the installer's "installation verified"), written by the engine, so the engine is the only writer of `events.jsonl` (audit 2026-11-07, finding 6). Not in `AdminActions`: the helper refuses it in a payload; the engine accepts it only from an elevated caller or `control\`; no other fields are allowed |

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
