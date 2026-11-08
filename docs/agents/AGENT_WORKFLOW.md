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
   `FreeEDR-Setup.exe`; release builds (and dev builds with `EDR_BUILD_UPDATE=1`) also build `FreeEDR-Update.exe`, the
   same package without the bundled tools and seed (`Tools.IsPackagedToolFile`; the installer keeps the installed tools or
   downloads a changed pin), for the dashboard's update; only those installers and their `.sha256` in `.\compiled`.

**Code signing (P18).** Dev builds may be unsigned (a WARN line says so). **Release builds (`build.cmd`) must be signed**
and fail otherwise; `EDR_ALLOW_UNSIGNED=1` allows an unsigned release (WARN; the update check then relies on GitHub's
SHA256 digest alone, and a signed install never accepts an unsigned update). To sign, set before the build:
* `EDR_SIGN_THUMBPRINT` = SHA1 thumbprint of a code-signing certificate in your certificate store, or
* `EDR_SIGN_DLIB` + `EDR_SIGN_METADATA` = Azure Trusted Signing (path to `Azure.CodeSigning.Dlib.dll` and its `metadata.json`).
Optional: `EDR_SIGN_TIMESTAMP` (default `http://timestamp.acs.microsoft.com`), `EDR_SIGNTOOL` (path to signtool.exe; default:
PATH, then the newest Windows 10/11 SDK). A configured signing that fails fails the build.

Result: `.\build.log`, first line OK / WARN / FAIL. A build installs and publishes nothing. `.\compiled` holds
`FreeEDR-Setup.exe` and `FreeEDR-Setup.exe.sha256` (plus `FreeEDR-Update.exe` and its `.sha256` when built). `build.cmd` wipes `.\compiled` first; `dev_build.cmd` does not.
Prerequisites: [install/INSTALLATION.md](../install/INSTALLATION.md) §1.

**Versions (`build\EdrBuild\Release.cs`).** Release: `EDR_VERSION`, else the `v<version>` tag on HEAD (`YYYY.M.D` or
`YYYY.M.D.N`), else a local release build `0.yyMM.ddHH.mm` (UTC) with a WARN and "(local release build <commit>)": like a
dev build it ranks below every published release, so published updates are still offered over it and never ask to
"downgrade". Dev: `0.yyMM.ddHH.mm` (UTC) plus "(dev build <commit>)", so a dev build never ranks above a
release and installing one over a release asks first. Every program's informational version is `<version>+<commit>`
(`.dirty` with uncommitted changes, WARN in release builds). Release builds must embed the malware hash seed (64 KB or
more); its fetch time and SHA256 are written to `THIRD_PARTY_NOTICES.txt` and `build.log`.

**Changelog gate** (`Release.ChangelogGate`, `Changelog.Problems`). `docs\CHANGELOG.md` must exist with a
`## Unreleased` section holding exactly the headings `### What's new for you` and `### Technical` (no other headings, no
entries outside them; a user entry needs a technical entry too; a technical-only change is fine). **Every code change
records itself**: when `src`, `build`, `config` or `rules` has uncommitted changes and the changelog has none, a dev
build WARNs and a release build fails; a commit that changed code after the last commit of the changelog fails every
build. This works before the first release tag. Once a `v*` tag exists: code changed since the tag needs Unreleased
entries, and the released sections must be unchanged since the tag (`Changelog.ReleasedKept`: corrections go into a new
entry). A tagged / `EDR_VERSION` release build needs a `## <version>` section with "What's new for you" entries.

## 3a. Releases (`.github\workflows\release.yml`)
The workflow must be on the default branch to appear under Actions. **Before the first real release, run it once with
*Dry run* ticked**: it does everything up to a verified draft, then deletes the draft and its staging branch (nothing is
published, the branch is not changed). Then run **Actions > Release > Run workflow** with a version newer than the last
tag. The workflow:
1. checks the version (format, newer than every tag, no published release of it) and deletes a leftover draft or
   `release-staging/v<v>` branch of an earlier run;
2. `EdrBuild --promote-changelog <v>` moves "Unreleased" under `## <v> - <date>` (idempotent) and commits it **locally**;
   the release notes (`Changelog.ReleaseBody`) put the plain-English part first and the technical part in a collapsed
   `<details>` block;
3. `build.cmd --skip-live` (every gate, signing, `FreeEDR-Setup.exe` + `FreeEDR-Update.exe`);
4. `tests\Run-Tests.ps1 -SkipLive`: a FAIL, a SKIP for any reason other than `-SkipLive`, or a suite without a PASS
   stops the release (the hosted runner is elevated; only the live permission checks depend on that, and `-SkipLive`
   skips them);
5. pushes the commit to `release-staging/v<v>` only, creates a **draft** release (invisible to update checks) with both
   installers, their `.sha256`, sizes and the marker `<!-- freeedr-release-workflow: verified -->`, downloads both back
   and compares each SHA256 with GitHub's asset digest;
6. merges the release commit into the branch and pushes it (before publishing, so a published release always has its
   changelog on the branch), publishes, and waits up to 60 s for `releases/latest` to be it;
7. removes the `FreeEDR-Setup*` / `FreeEDR-Update*` assets of every **verified** release (the marker) older than the
   **five** newest verified ones (Windows x64 is the only platform; tags, notes and history stay; releases made by hand are
   neither counted nor touched).
A failed **or cancelled** run before publishing deletes the draft and the staging branch, and when the branch was already
pushed, reverts the changelog commit there (the entries go back under Unreleased). Secrets: `SIGN_PFX_BASE64` +
`SIGN_PFX_PASSWORD` (imported, thumbprint signing) or `EDR_SIGN_DLIB` + `EDR_SIGN_METADATA`; repository variable
`ALLOW_UNSIGNED_RELEASE=1` for unsigned releases. The push needs write access for `github-actions[bot]` (allow it in
branch protection). The repository must be public: the dashboard's update check reads the API without a token.

**Changing the signing certificate's subject** (company name, place): installed copies accept an update only from the
same normalized subject (CN, O, L, S, C) or one in `AppRelease.TrustedSuccessorSubjects`. Add the new subject there, ship
that release signed with the **old** certificate, then sign later releases with the new one.

## 4. Test bundle (`tests\`, Windows PowerShell 5.1 runner)
| Suite | What it checks |
|---|---|
| `01-Sanity` | data files and projects, build/installer consistency, no PowerShell product scripts, encodings, Sysmon template, no credential-tool strings, detect-only (no process kill), installer ↔ uninstaller symmetry, manifests, documentation routing |
| `02-Unit` | C#: `PatternRules`, `Ip`, `EdrConfig`, `JsonFile`/`EventWriter`/`CommandDrop`, `ActionBuilder`, `PeriodSummary`, `Profiles`, golden dashboard models, engine internals (OSV parsing, CSV, Wail2Ban counting and ban lengths), signatures, single instance, hardening (`HardeningTests`: request summary, YARA sandbox, change stamp, engine-state locking, tray snapshots), event archive (`ArchiveTests`), audit round 2 (`AuditFixTests`: drop-file intake with links / oplocks / growing files, full-disclosure confirmation, YARA not-scanned, signed-only tool updates, single events writer; pipe caps in `PipeTests`), settings (`SettingsTests`: change-set saves, feed rule, backup / import, both themes and their contrast), QA round 3 (`QaRound3Tests`: malware checks behind allows, Defender allows kept while active, OSV outcomes, scan-now reasons, the event list after a reset, bounded netsh, the scrolling confirmation window; busy / failed pipe answers in `PipeTests`), releases and updates (`ReleaseTests`: version order, changelog promotion, release parsing, signer rule, no re-download, download lock, Velociraptor kept, roll-back / uninstall safeguards) |
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
