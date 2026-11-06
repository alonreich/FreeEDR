# NativeAOT, Avalonia, PowerShell 5.1, encoding and Windows pitfalls (bugs that already happened: do not reintroduce)

Read for: any C# (NativeAOT) or PowerShell edit (the test bundle, and the few Windows PowerShell calls the programs make).
Short, scan it before writing code. Avalonia-specific rules: [tray/TRAY_GUI.md](../tray/TRAY_GUI.md) §6.

## NativeAOT / C# (the product)
* Trim/AOT warnings are errors. `JsonArray.Add(jsonObject)` binds to the generic `Add<T>` (IL2026/IL3050): write
  `Add((JsonNode)x)`. Use `JsonNode`/`JsonObject`, never reflection-based `JsonSerializer` on own types.
* P/Invoke with `LibraryImport`; structs passed by `ref` must be blittable (`fixed char[]`, not `ByValTStr` strings).
* Event log bookmarks: use `EvtCreateBookmark` / `EvtUpdateBookmark` / `EvtRender(EvtRenderBookmark)` (`Native\EventSubscription`),
  never the private fields of `EventBookmark` (the PowerShell engine did that through reflection).
* A program that needs elevation declares `requireAdministrator` in its manifest; the tray starts it with
  `UseShellExecute = true, Verb = "runas"`; Win32 error 1223 = the user declined UAC.
* Windows PowerShell calls from C# (`PowerShellRunner`): pass values in environment variables (`$env:EDR_X`), never in the
  script text; remove `PSModulePath` so 5.1 loads its own modules.
* `dotnet test` must run from `src\` (global.json selects the Microsoft Testing Platform runner).
* Shell heredocs / Python string literals ate backslashes in Windows paths while editing (a backslash + n became a
  newline in the Sysmon XML, a backslash + t a tab in a .csproj): edit Windows paths with an editor, then check the file.
* The test file that looks for credential-tool strings must not contain them itself: AMSI blocks the whole script.

## Encoding (the build checks these)
* `*.ps1` must be **UTF-8 with BOM**. Windows PowerShell 5.1 reads BOM-less files as ANSI and corrupts non-ASCII characters.
* `*.yar` must be **ASCII without BOM**. YARA rejects a BOM with `error: non-ascii character` and the rule file is then
  silently skipped (YARA never worked before this was found). The engine test-compiles each rule file at start and logs any it skips.
* Do not put credential-theft tool names (the mimikatz command strings) in plain text inside `.ps1` files: AMSI/Defender
  blocks such scripts ("This script contains malicious content"). The YARA file keeps them hex-encoded.

## PowerShell 5.1 language gotchas
* `$PID` is read-only: `function f([int]$Pid)` throws on every call (silently inside `try`). Use `$ProcId`.
* `New-Object 'HashSet[string]' ($array)` spreads the array into constructor arguments (crash). Build sets with a loop.
* `$null` passed to a .NET `string` parameter becomes `""` (`[IO.File]::Replace(a, b, $null)` failed). Use `[NullString]::Value`.
* A single `PSCustomObject` has no `.Count`. Wrap results in `@()`. This includes `$x = if (...) { @(...) }`, which unrolls
  a 1-item array: write `$x = @(if (...) { ... })` (the tray's Sigma "Matches" column was empty for one hit).
* Variable names are case-insensitive: `$dl` and `$Dl` are the same variable. Use clearly different names.
* `Sort-Object` is not stable: rows that tie on the sort key may come in any order (the C# parity check tolerates exactly this).
* Piping a native program into `Select-Object -First n` can stop that program before it finishes. Collect with `@(...)` first.
* `Start-Process -ArgumentList` joins arguments with spaces and does not quote them. Every path argument needs its own quotes
  (`"`"$Root\x.ps1`""`) since the install folder is `C:\Program Files\FreeEDR`.
* Native stderr plus `$ErrorActionPreference='Stop'` throws (Sysmon prints its banner to stderr).
* A scriptblock created with `GetNewClosure()` loses script-scope functions. Use control `.Tag` and `$this` in event handlers.
* Define a function before the first call that runs at script level (`Write-EngineLog` was used before its definition).

## Process, IPC and security patterns
* Never build shell strings with interpolation (`"& '$exe' $args"`). Invoke native CLIs with argument arrays (`& $exe @args`).
* Writing directly into a monitored folder lets the consumer read a half-written file: write a `.tmp` in the same folder and
  rename. A rename needs delete access on the file (`inbox\` has W,D).
* Named kernel objects in `Global\` need an explicit ACL (`MutexSecurity`: SYSTEM + Administrators); otherwise an
  unelevated process can squat them. When testing the engine unelevated, rename its mutex.
* Keep a 50 MB size limit for real-time YARA scans (multi-GB files caused memory trouble).
* `data\download` is deleted at the end of every install: anything the engine or scan writes there must create it first.
* Task Scheduler "restart on failure" does not restart a script that exits with a non-zero code: wrap every engine step in
  `Invoke-Safely` and keep the 5-minute watchdog trigger.

## Windows tools
* `robocopy /XF` excludes a file name at every level, not only the top (it would have dropped scripts inside `data\backup-*`).
* `icacls <root>\* /reset /T` also resets `quarantine\`: apply its admin-only ACL again afterwards.
* Sysmon 15.22 crashes (0xC0000409) on `condition="end with any"`: use `contains any`. Diagnose a rejected config one
  RuleGroup at a time.
* A stuck Sysmon driver (`SysmonDrv` StopPending) makes `Sysmon64 -c` print "Sysmon is not installed. Configuration
  updated."; the config takes effect after a reboot.
* Hayabusa 4.x renamed `csv-timeline` to `dfir-timeline` and needs its own folder as working directory. It re-reports
  Sysmon rule hits as "… (Sysmon Alert)": drop them.
* NativeAOT linking needs `vswhere.exe` on PATH; `build\EdrBuild` and `src\publish.ps1` add it.
