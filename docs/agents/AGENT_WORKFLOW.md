# Agent workflow: the mandatory build → test → report loop

Read for: every session that edits files (C# sources, Sysmon config, YARA rules, installer, build, tests, docs).

> Entry point for every session: [`project_structure.txt`](../../project_structure.txt). This file is the loop **every**
> code change goes through.

## 1. Hard rules
1. Edit files only in the repository folder. Never edit `C:\Program Files\FreeEDR` (the installation) directly.
2. Do **not** run `compiled\FreeEDR-Setup.exe` or `FreeEDR-Installer.exe install|uninstall` on the owner's PC without their
   explicit approval. They change system settings (Defender, firewall, Sysmon, the service, registry).
3. A run with a FAIL means the change is **not done**.
4. Keep these docs true: when your change alters behaviour described in `docs\`, update that doc in the same change
   (and the routing table in `project_structure.txt` if you add a doc).

## 2. The loop
```
 edit (repo only)
   │
   ▼
 dev_build.cmd  ──FAIL──► fix, repeat            (cmd.exe, full path; every gate must pass)
   │ OK
   ▼
 tests\Run-Tests.ps1 (UNELEVATED)  ──FAIL──► fix, repeat
   │
   ▼
 read tests\results\last-run.txt: look into EVERY FAIL and WARN (fix the cause, or explain why it is acceptable)
   │
   ▼
 report: the TEST RESULT line + every SKIP that left your change untested
   │
   ▼
 (only with the owner's approval) run compiled\FreeEDR-Setup.exe → it backs up, installs, verifies, rolls back by itself
   │
   ▼
 tests\Run-Tests.ps1 again: the 05-Live suite now checks the installed copy
```
Commands:
```
cmd.exe /c "<repo>\dev_build.cmd"
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1
```
Options of `Run-Tests.ps1`: `-Suite <pattern>`, `-SkipLive` (repository only), `-NoAttack`. Exit code 0 = no FAIL.
Results: `tests\results\` (git-ignored: paths and user names). C# tests alone: `cd src; dotnet test --project Edr.Core.Tests -c Release`.
After an intended change of the dashboard model, refresh the golden files: `FREEEDR_UPDATE_GOLDEN=1` and run the C# tests once.

Add tests with every feature (`src\Edr.Core.Tests`), and everyday / attack command lines to `tests\data\process-corpus.json`
for detection changes (attack samples base64-encoded so antivirus does not flag the file).

## 3. Build gates (`build.cmd` / `dev_build.cmd`, implemented in `build\EdrBuild\`)
1. data files (`Gates.DataFiles`) and the four projects exist; `.yar` ASCII without BOM, docs/config valid UTF-8;
2. the C# tests pass (`src\Edr.Core.Tests`);
3. NativeAOT publish of `Edr.Engine`, `Edr.Control`, `Edr.Setup`, `Edr.Tray` (warnings are errors) into `obj\EdrBuild\publish`;
4. the published tray builds its model from this PC's live install (skipped when FreeEDR is not installed; `--skip-live`);
5. staging (`bin\` programs without .pdb, data files) + optional **code signing** of FreeEDR's own exes (`FreeEDR-*.exe`,
   never the third-party tools) + **EmbedTools**: the pinned Hayabusa (with rules), YARA, OSV-Scanner and Velociraptor from
   `obj\tools-cache` (downloaded once, SHA256 must match the pin, otherwise the build fails: delete the cache and build
   again), a malware hash seed (`seed\ioc_sha256.txt`, refreshed daily, WARN if the feed is down) and
   `docs\THIRD_PARTY_NOTICES.txt`; then Inno Setup, signing of
   `FreeEDR-Setup.exe`, exactly one file in `.\compiled`, SHA256 printed.

**Code signing (P18).** Unsigned builds work (a WARN line says so). To sign, set before the build:
* `EDR_SIGN_THUMBPRINT` = SHA1 thumbprint of a code-signing certificate in your certificate store, or
* `EDR_SIGN_DLIB` + `EDR_SIGN_METADATA` = Azure Trusted Signing (path to `Azure.CodeSigning.Dlib.dll` and its `metadata.json`).
Optional: `EDR_SIGN_TIMESTAMP` (default `http://timestamp.acs.microsoft.com`), `EDR_SIGNTOOL` (path to signtool.exe; default:
PATH, then the newest Windows 10/11 SDK). A configured signing that fails fails the build.

Result: `.\build.log`, first line OK / WARN / FAIL. A build installs and publishes nothing. Version `yyyy.M.d.HHmm`, plus
"(dev build)" for dev builds. `build.cmd` wipes `.\compiled` first; `dev_build.cmd` does not. Prerequisites:
[install/INSTALLATION.md](../install/INSTALLATION.md) §1.

## 4. Test bundle (`tests\`, Windows PowerShell 5.1 runner)
| Suite | What it checks |
|---|---|
| `01-Sanity` | data files and projects, build/installer consistency, no PowerShell product scripts, encodings, Sysmon template, no credential-tool strings, detect-only (no process kill), installer ↔ uninstaller symmetry, manifests, documentation routing |
| `02-Unit` | C#: `PatternRules`, `Ip`, `EdrConfig`, `JsonFile`/`EventWriter`/`CommandDrop`, `ActionBuilder`, `PeriodSummary`, `Profiles`, golden dashboard models, engine internals (OSV parsing, CSV, Wail2Ban counting and ban lengths), signatures, single instance, hardening (`HardeningTests`: request summary, YARA sandbox, change stamp, engine-state locking, tray snapshots), event archive (`ArchiveTests`), audit round 2 (`AuditFixTests`: drop-file intake with links / oplocks / growing files, full-disclosure confirmation, YARA not-scanned, signed-only tool updates, single events writer; pipe caps in `PipeTests`), settings (`SettingsTests`: change-set saves, feed rule, backup / import, both themes and their contrast), QA round 3 (`QaRound3Tests`: malware checks behind allows, Defender allows kept while active, OSV outcomes, scan-now reasons, the event list after a reset, bounded netsh, the scrolling confirmation window; busy / failed pipe answers in `PipeTests`) |
| `03-FalsePositive` | C#: the Sysmon rules against everyday and attack command lines (`process-corpus.json`), the engine's allow decisions |
| `04-PenTest` | C#: own-process trust spoofing, command-channel abuse, CVE-update injection, damaged settings files. Live (unelevated): program/settings folders not writable, inbox refuses forbidden requests, the helper refuses to run unelevated |
| `05-Live` | the installed FreeEDR: installed = latest build, service running, heartbeat, detect-only mode, sensors, engine errors, scan steps, folder permissions, owner, tray start, Settings > Apps entry, noisy alerts |

Known open test results: [docs/history/STATUS.md](../history/STATUS.md).

Visual checks without installing: tray `--dev --root "C:\Program Files\FreeEDR" --local <copy of user\<SID>> --screenshot <dir>`
([tray/TRAY_GUI.md](../tray/TRAY_GUI.md) §5); setup window `set __COMPAT_LAYER=RunAsInvoker` then
`FreeEDR-Installer.exe --screenshot <dir>` (renders its three pages, installs nothing).

## 5. Design rules for every change
* **Detect-only.** Never add code that stops a process or moves/deletes a user's file. Wail2Ban's firewall bans are the one
  enforcement, behind `wail2ban.block`.
* The engine runs as SYSTEM and must never stop: wrap new work in `Engine.Safely` and keep slow work out of the event path
  (background task or worker, bounded queues). State shared with a worker thread needs a lock (`EngineState` has one).
  A parser of untrusted input runs in `Native\Sandbox` (low integrity, no privileges, Job object), never as SYSTEM.
* The tray's UI thread does no file I/O, parsing or model building: `TrayState.RefreshAsync` (worker) publishes a
  snapshot; UI edits of tray state go through `TrayState`'s methods (they take its lock).
* Elevated programs take no folder from their caller (no `--root` in FreeEDR-Control.exe / FreeEDR-Installer.exe) and
  the helper confirms the decoded request in its own window.
* The tray is unelevated, reads the install folder and writes only its own `user\<SID>\` and `inbox\` (offline queue).
* A file in a folder an unprivileged account can write (`inbox\`, `user\<SID>\`) is opened with `Native\DropFile` (no
  link followed, no oplock waited on, bounded read) and never on the engine's main loop.
* Only the engine writes `data\events.jsonl`; another FreeEDR program sends its message with `EngineNote.Send`.
* Engine requests go over the pipe (`EnginePipe.SendAsync`; the engine decides from the caller's token); the drop folders
  are only the fallback when the engine is down. New push notices: call `Context.Changed` / `PipeServer.Changed`.
* The engine service keeps only `EdrPaths.EnginePrivileges`: new engine code that needs another privilege must add it
  there (and say why) or fail in the field.
* New engine commands: add the verb to `PatternRules` (`AdminActions`, `BatchActions` if batchable, `IsValidOp` field
  validation) and handle it in `Commands.Execute` or `FreeEDR-Control.exe`. Only `resume` and `scan-now` from `inbox\`.
* Every alert carries `blade`, `severity`, `title` and enough fields for a precise allow; add its actions in `ActionBuilder`
  and an explanation in `Hints`.
* New Sysmon rules: include-only, named, a severity in `Catalog.RuleSeverity`, an explanation in `Hints.Rules` (a test
  checks both), quiet while gaming.
* Paths only from `EdrPaths`; never hard-code `C:\Program Files`, a user name or a profile path in logic (profiles use
  `EdrPaths.ProfilesRoot`).
* Anything new the installer changes outside the install folder is recorded (`preinstall.json` / `managed.json`) and undone
  in `Uninstaller.cs`. Never lower a Windows protection setting that was stronger before FreeEDR.
* NativeAOT: `JsonNode` (no reflection serialization), code-built views (no reflection bindings), `LibraryImport`.
  Read [reference/POWERSHELL_PITFALLS.md](../reference/POWERSHELL_PITFALLS.md) before writing NativeAOT or test code.
