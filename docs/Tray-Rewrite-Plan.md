# Tray rewrite plan — EDR-Tray.ps1 → FreeEDR-Tray.exe (C# / Avalonia / NativeAOT)

Status (2026-11-02): **phases 0 and 1 done; phases 2–5 open.** Source is in `src\` (`EdrTray.sln`). `dev_build.cmd` / `build.cmd` in the development folder test and publish it on every build (NativeAOT to `obj\EdrBuild\tray`). For the tray alone, `powershell -File src\publish.ps1` writes `obj\publish\tray\`. Nothing of it is installed yet: the installed tray is still `EDR-Tray.ps1`.

Since 2026-11-02 the product is called **FreeEDR**: install folder `C:\Program Files\FreeEDR`, exe `FreeEDR-Tray.exe`, kernel object names `Local\FreeEDR-Tray*`, tray files in `C:\Program Files\FreeEDR\user\`. Namespaces stay `Edr.*`.

### Phase 1 results (2026-11-01)
* `Edr.Core` ports Update-Model, Find-Exclusion/Find-Block/Find-CveExclusion, the exclusion texts, Get-Overall, Get-SigmaProcess, the IP helpers and Read-NewEvents (`EventTail`). Records stay JSON (`Rec` over `JsonNode`, case-insensitive) with PowerShell's `[string]`, truthiness and `-like` semantics in `Ps`, so the decisions match exactly. All of this is AOT-safe without source-generated typed models; typed view models come with the UI in phase 2.
* Real signature checks: `Native\AuthenticodeSigners` (WinVerifyTrust plus the embedded signer, `LibraryImport`). Catalog-signed Windows files return no publisher; that never changes a decision, because Microsoft publishers are refused as allow targets.
* **Semantic Lifecycle Sub-Tabs Aligned:** Standardized sub-tabs in `Catalog.cs` and `EDR-Tray.ps1`: `cve` (`Detected`, `Updated`, `Ignored`) and `apps` (`Available`, `Updated`, `Hidden`) replacing generic Allowed/Blocked terms with rubric-appropriate states.
* **Semantic Lifecycle Sub-Tabs Aligned:** Standardized sub-tabs in `Catalog.cs` and `EDR-Tray.ps1`: `cve` (`Detected`, `Updated`, `Ignored`) and `apps` (`Available`, `Updated`, `Hidden`) replacing generic Allowed/Blocked terms with rubric-appropriate states.
* **Semantic Lifecycle Sub-Tabs Aligned:** Standardized sub-tabs in `Catalog.cs` and `EDR-Tray.ps1`: `cve` (`Detected`, `Updated`, `Ignored`) and `apps` (`Available`, `Updated`, `Hidden`) replacing generic Allowed/Blocked terms with rubric-appropriate states.
* **Parity:** `EDR-Tray.ps1 -SelfTest` gained `EDR_SELFTEST_DUMP=<folder>` (writes the exact inputs it read plus `model.json`) and `EDR_SELFTEST_ROOT=<folder>` (reads a fixture instead of the install folder). Fixtures in `src\Edr.Core.Tests\Fixtures\`: `live-2026-11-01` (a snapshot of this PC; personal data, keep it local) and `synthetic-a` / `synthetic-b` (built by `make_synthetic.py`: Wail2Ban fails/bans/logins, user blocks, CVE items and history, hidden apps, Defender de-duplication, wildcard/ancestor/CIDR/signer allows, retired rules, pause states). All 3 match. `src\parity.ps1` checks the live data at any time (`FreeEDR-Tray.exe --selftest --compare <dump>`), and every build runs that check when FreeEDR is installed. 8 unit tests.
* Allowed difference: PowerShell 5.1 `Sort-Object` is not stable. When the members of a grouped "(xN)" row share their newest timestamp, either tray may show a different one of them (its id and detail). The check tolerates exactly this.
* **Bug found and fixed in EDR-Tray.ps1:** a confirmed Sigma rule with exactly one matching event showed an empty "Matches" column and no details (one PSCustomObject has no `.Count`).
* Moved to phase 3: building each row's action list. It belongs with the actions, and phase 3 tests it per verb.

### Phase 0 results (2026-11-01)
* Pinned: Avalonia 12.1.4, CommunityToolkit.Mvvm 8.4.2, xunit.v3 4.0.2 (Microsoft Testing Platform runner, set in `src\global.json`). SDK 10.0.403. NuGet packages are kept in the development folder (`obj\nuget\packages`, via `nuget.config`).
* NativeAOT publish: 0 warnings (warnings are errors). Output is `FreeEDR-Tray.exe` (about 21 MB after phase 1) plus Avalonia's native `libSkiaSharp.dll`, `libHarfBuzzSharp.dll` and `av_libglesv2.dll`. These cannot be embedded, so the deploy is a folder (`bin\tray\`), not one file.
* Startup to window: about 200–250 ms warm. The first launch of a new build takes about 6 s while Defender scans it. Working set about 65–78 MB.
* Tested: single instance (a second launch exits with code 0 and makes the first show its window), and the Exit named event (`Local\FreeEDR-Tray-Exit`, as the installer uses) closes it. `--dev` uses `…-Dev` names so it runs next to the installed tray.
* The AOT linker needs `vswhere.exe` on PATH. `publish.ps1` and `build\EdrBuild` add the VS Installer folder.
* Not checked by eye yet: the drawn shield icon in the notification area. Run `obj\publish\tray\FreeEDR-Tray.exe --dev --show` (after `src\publish.ps1`).

## 1. Goal and scope
* Replace `EDR-Tray.ps1` (2,200 lines, WinForms built from PowerShell 5.1) with a native exe, `C:\Program Files\FreeEDR\bin\tray\FreeEDR-Tray.exe`. It must look, behave and decide exactly the same, or better.
* **In scope:** tray icon and menu (including granular per-rubric pause/resume submenus with explicit scope descriptions), dashboard (Overview with guided triage banner and forensic audit ledger, plus 6 sections × 3 standardized lifecycle sub-tabs: Detected, Blocked, Allowed), details pane, unified actions (`Block & Neutralize`, `Trust & Exclude`, `Mark Reviewed`), notifications, quiet mode during games, winget check, the Gemini helpers, CSV audit export, and self-test.
* **Out of scope (for now):** the engine, the scan, the installer logic and the Sysmon config. `EDR-Engine.ps1` stays in PowerShell as SYSTEM. The file contract below does not change, so the old and new trays can run side by side, one at a time.

## 2. Decisions
| Topic | Choice | Why |
|---|---|---|
| Runtime | **.NET 10 (LTS, to Nov 2028), C# 14.** SDK 10.0.403 is installed | .NET 9's support ended in May 2026 |
| UI | **Avalonia 12.1.4**, pinned exactly. Fluent theme, light and dark | Built-in `TrayIcon`, compiled bindings, works with AOT |
| Pattern | MVVM with **CommunityToolkit.Mvvm** (source generators, no reflection) | AOT-safe |
| JSON | `System.Text.Json` without reflection: `JsonNode` for the engine's open-ended records (phase 1), source generation (`JsonSerializerContext`) for typed models | Reflection-based serialization is off under AOT |
| Publish | Deployed as a folder: the exe plus 3 native DLLs (see Status). `PublishAot=true`, `win-x64`, `InvariantGlobalization=false`, `IlcOptimizationPreference=Size`. Trim/AOT warnings are errors | No runtime to install, starts in about 0.2 s. The VS 2022 Build Tools with the C++ linker are installed |
| Notifications | `Shell_NotifyIcon` with `NIF_INFO` via P/Invoke. Windows 11 shows these as toasts | The same as today's `ShowBalloonTip`. No WinRT/CsWinRT under AOT. Click-to-open works through `NIN_BALLOONUSERCLICK` |
| Tray icon | Avalonia `TrayIcon`. The shield icons (green ✓, amber !, grey II, red X) are drawn at runtime, as today | |
| Elevation | Unchanged: `ShellExecute` with verb `runas` → `powershell.exe -File "C:\Program Files\FreeEDR\EDR-Control.ps1" -Payload <base64>` | The engine-side validation stays the single gate. A small elevated `EDR-Control.exe` may come later |
| Signatures | `WinVerifyTrust` plus the embedded signer (done in phase 1, `Native\AuthenticodeSigners`), cached per path | Replaces `Get-AuthenticodeSignature`. Needed for the signer, parentSigner and Claude rules |
| Build | `build.cmd` / `dev_build.cmd` (build\EdrBuild) build and test it; phase 5 packs it into `FreeEDR-Setup.exe` | Decided 2026-11-01; the target PC needs no SDK |

## 3. Solution layout (`src\` in the development folder)
```
EdrTray.sln
  Edr.Core\        no UI. Paths, Rec + PowerShell semantics (Ps), file readers (EdrInputs, EventTail), the model builder
                   (grouping, exclusion and block matching, retired rules, "Was this you?"), model dump + parity check,
                   IP helpers, Get-SigmaProcess, Native\AuthenticodeSigners, SingleInstance, TrayLog.
                   Phase 3 adds action building (Get-BlockOp, Get-AllowOp, Claude/parent ops)
  Edr.Tray\        Avalonia app (FreeEDR-Tray.exe): TrayIcon + menu, MainWindow (Overview + sections), DetailsPane, dialogs,
                   --selftest / --dump / --compare
  Edr.Core.Tests\  xUnit v3. Parity (golden) tests on Fixtures\*, signatures, single instance
  publish.ps1, parity.ps1
```
Rule: **everything that decides something is in Edr.Core** and tested without UI. Edr.Tray only shows and dispatches. (A separate `Edr.Win32` project was planned; the few P/Invokes live in `Edr.Core\Native\` instead.)

## 4. Contract with the engine (must not change)
All paths are under `C:\Program Files\FreeEDR` (`EdrPaths.DefaultRoot`).

| Item | Direction | Notes |
|---|---|---|
| `data\events.jsonl` | read, tail | UTF-8 lines. Keep a byte offset and read only up to the last `\n`. Rotation = length shrinks → re-read from the start. Open with `FileShare.ReadWrite \| Delete`. Unknown fields are ignored; optional ones: `ancestors[]`, `oldRule`, `parent`, `kind`, `ip`, `threat`, … |
| `data\status.json` | read every 2 s | Heartbeat older than 90 s = engine down (red shield). Reports master states and granular blade states (`status.edr.blades`: `malware`, `realtime`, `sigma`, `cve`, and `wail2ban.state`) |
| `data\scan-result.json`, `data\cve-current.json` | read when changed | Section status lines, CVE tab |
| `config\exclusions.json`, `config\blocklist.json` | read when changed | Allowed / Blocked sub-tabs. Fields as in Installation_Process §4.6 (signer, parentSigner, ancestors) |
| `config\sysmonconfig.xml` | read once | Rule names (retired rules) and the built-in exclusions |
| `control\` via EDR-Control.ps1 (UAC) | write | Verbs: pause, unban, exclude, unexclude, block, unblock, batch, restart-engine. Supports granular rubric targets (`malware`, `realtime`, `sigma`, `cve`, `wail2ban`, `edr`) with forensic audit logging (Event ID 3000) |
| `inbox\` | write | Only `resume` and `scan-now`. Written atomically as `.tmp` → rename, UTF-8 BOM, max 64KB, max 25 files drained per sweep |
| `user\` | read/write | `reviewed.txt` (one id per line, LF or CRLF), `ignored-apps.txt`, `history.json`, `winget.txt`, `tray.log`. Same files as the PowerShell tray, so reviewed state carries over |
| `Local\FreeEDR-Tray`, `Local\FreeEDR-Tray-Show`, `Local\FreeEDR-Tray-Exit` | mutex / events | Single instance, "show dashboard", installer-driven exit. Same names as `EDR-Tray.ps1`, so the installer works with either tray |

## 5. Phases and exit criteria
**Phase 0 — skeleton (½ day). DONE 2026-11-01.** Solution, AOT publish works, a tray icon with Exit, single instance plus the Show/Exit events.

**Phase 1 — Core model with parity tests (1–1½ days). DONE 2026-11-01.** `Update-Model` and its helpers: grouping "(xN)", Find-Exclusion/Find-Block, retired rules, Defender de-duplication of Sigma rows, the pinned "Was this you?" items, the Wail2Ban rows, CVE/App rows with history, attention counts, the overall sentence. *Done:* same counts per tab and sub-tab, the same rows (all columns) and the same overall sentence as `EDR-Tray.ps1 -SelfTest` on 3 fixtures and on the live data. (First-row actions moved to phase 3.)

**Phase 2 — read-only dashboard (1–1½ days).** Overview tiles and messages, interactive triage banner ("Was this you?"), Forensics & Action History ledger with CSV export, 6 sections × 3 standardized lifecycle sub-tabs (Anti-Malware/EDR/Sigma/Wail2Ban: `Detected`, `Blocked`, `Allowed`; CVE: `Detected`, `Updated`, `Ignored`; App Updates: `Available`, `Updated`, `Hidden`), virtualized lists (sortable, newest first), search, "Show reviewed items", details pane (What happened / What to do / raw fields; port `$RuleHints` and `$BladeHints` as a static table), section status lines with links. Includes full keyboard accessibility (`FocusVisual`, tile navigation, WCAG AA empty states).
*Done when:* every screen matches today's content and design conventions. Checked with screenshots of the real data, at 100% and 150% scaling, in light and dark.

**Phase 3 — actions (1 day).** Unified action bar and right-click menu from one `GetActions(rows)`: standardized buttons (`Block & Neutralize`, `Trust & Exclude`, `Mark Reviewed`), granular per-rubric Pause/Play (Malware, Real-time Sysmon, Sigma Rules, CVE, Wail2Ban, Master EDR) with explicit scope tooltips and Event ID 3000 audit logging, all Allow variants (program, rule, parent, signer, *Allow Claude Code*), back-moves, Mark reviewed, interactive "Was this you?" Yes/No quick actions with feedback guards, Copy details with defensive clipboard error handling, Open file location, pause/resume, scan now, restart engine, test detection, `SaveFileDialog`-based CSV audit export, non-blocking UAC execution loop, CVE pip update and App winget update in a terminal, the Gemini CLI/web helpers.
*Done when:* each verb sends byte-for-byte the same JSON as the PowerShell tray (unit test per op), the action labels of every fixture row match `-SelfTest`, and a UAC round-trip works on this PC for allow, unallow, block, unblock and pause.

**Phase 4 — tray and notifications (½–1 day).** The tray menu tree (status, Open ▸ per tab with counts, EDR/Wail2Ban pause submenus, Advanced ▸), the shield state, notification rules (`Invoke-Notify` severity table, engine-down toast once, quiet-mode queue and summary while `FortniteClient*` runs), the 2-second tick, winget check at the scan times.
*Done when:* the notification test matrix (Critical/High/Wail2Ban/health/scan, quiet on/off) passes manually, and memory stays flat over 24 h (under 80 MB working set).

**Phase 5 — switch-over (½ day).** Stage the published tray folder as `bin\tray\` into `FreeEDR-Setup.exe`. `Install-EDR.ps1` then copies it, points `HKCU\…\Run\FreeEDR Tray` and the "FreeEDR" Start-menu shortcut at `bin\tray\FreeEDR-Tray.exe`, and keeps `EDR-Tray.ps1` as a fallback (`-UsePsTray` switch). Update README §3/§6 and Installation_Process §4.10/§5/§8.
*Done when:* a fresh install and an upgrade both give `INSTALL RESULT: SUCCESS`, and the acceptance checklist in Installation_Process §0 still holds.

**Remaining:** about 3½–4½ working days (phases 2–5).

## 6. Security rules (carry over, do not weaken)
* The tray stays **unelevated**: it reads `C:\Program Files\FreeEDR` and writes only `user\` and `inbox\`. Every protective change goes through UAC → EDR-Control.ps1 → validation in the engine. The tray never edits config files.
* The exe sits in admin-only `C:\Program Files\FreeEDR\bin\tray`. A user-level process cannot replace it.
* Signer checks (Allow Claude Code) are advisory in the tray. The engine re-checks the signature at match time, as it does now.
* No network calls from the tray except the user-started Gemini web page (browser) and winget (its own process).
* No secrets. The Gemini CLI runs in the user's own terminal.

## 7. Risks and mitigations
| Risk | Mitigation |
|---|---|
| Behaviour drift from the 2,200-line script | Golden tests against `-SelfTest` output (phase 1 done; every build runs them). Port function by function, keeping the names (`FindExclusion` ↔ `Find-Exclusion`) |
| AOT breaks reflection-based Avalonia/XAML features | Compiled bindings only (`AvaloniaUseCompiledBindingsByDefault`), no `ReflectionBinding`, warnings as errors |
| Toast clicks under AOT | Shell_NotifyIcon P/Invoke, no WinRT |
| PowerShell-only helpers (wildcards, `-like`) behave differently | `Ps.Like` with PowerShell `-like` semantics (case-insensitive, `* ? [ ]`, backtick escape), covered by the parity fixtures |
| Two trays running at once | Same mutex name: the second one exits |
| Engine changes later (new fields) | Records are open JSON (`Rec`); unknown blades shown as generic rows |

## 8. Decisions needed from you
1. Keep **EDR-Control.ps1** for elevation (recommended), or build a small elevated **EDR-Control.exe** in phase 5.
2. ~~Build on this PC or in the installer~~ — **decided 2026-11-01:** built by `build.cmd` / `dev_build.cmd` and packed into `compiled\FreeEDR-Setup.exe`.
3. Visual style: keep today's layout 1:1 first (recommended), and redesign only after parity.
4. Later: port the engine to a .NET Windows service (phase 6, separate decision).
