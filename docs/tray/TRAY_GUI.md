# Dashboard implementation (`src\Edr.Tray`, FreeEDR-Tray.exe)

Read for: changes to the tray app. What the user sees is specified in [user/USER_GUIDE.md](../user/USER_GUIDE.md); the
files it reads in [architecture/DATA_FILES.md](../architecture/DATA_FILES.md) §3-4.

## 1. Process model
* Avalonia 12 (Fluent theme, dark variant + `Theme.axaml`), NativeAOT, `net10.0-windows10.0.19041.0` (Windows SDK
  projection for native notifications), unelevated (`asInvoker`), one instance per session (`Local\FreeEDR-Tray`); a
  second launch signals `Local\FreeEDR-Tray-Show`; the installer closes it with `Local\FreeEDR-Tray-Exit`.
* Started from `HKLM\...\Run\FreeEDR Tray`; `--show` opens the dashboard; `--toast-title/--toast-text/--toast-level`
  show one notification at start (installer). `--dev` uses `-Dev` instance names; `--root`/`--local` read another folder.
* `App`: the engine's pipe pushes "changed" (`EnginePipe.SubscribeAsync`, reconnects every 5 s) → `Tick` at once; a
  5-second `DispatcherTimer` → `Tick` is the safety net. (re-entrancy guarded; a refresh asked for during a tick runs right after):
  `TrayState.RefreshAsync` runs `Refresh` **on a worker thread** (tails `events.jsonl` 2 MB per tick, re-reads files whose
  timestamp changed, rebuilds the model with `ModelBuilder` when anything changed); the UI thread only awaits it. The
  worker owns the working inputs and publishes an immutable snapshot (`TrayState.Inputs`, `EdrInputs.Snapshot`) with the
  model; the UI's own edits (reviewed, history, hidden apps, winget results) take the state's lock, which the worker holds
  only while reading files, never while building. Parsed records are fully materialized (`Rec.Parse`) so both threads
  can read them; signer lookups are cached thread-safely per path + last write (`CachedSigners`, 5,000 entries). The
  `Controller` asks for a refresh (`RefreshRequested`) instead of rebuilding itself. Then on the UI thread: new
  events → `Notifier.Consider`, `Notifier.Tick`, `WingetCheck.Tick`, weekly summary / learning-week wrap-up, tray icon
  and menu (rebuilt only when the state changes), visible window refresh.
* **Refresh keeps what the user is doing** (UI audit 2026-11-06). The engine rewrites `status.json` every 15 s, so the
  visible page is refreshed that often. Each view builds its new tree and compares `Ui.Fingerprint` (types, texts,
  colors, visibility, enabled/checked/selected state) with the live tree; an unchanged view keeps its live controls, so
  focus, caret, scroll, open menus and text selections survive. `ListPage` creates its chips once (updated in place),
  re-binds the list only when a row signature changed (keeping the scroll offset), and keeps a custom tab's panel when
  it looks the same. `DetailView` keeps *Technical details* open once opened and keeps its scroll for the same
  selection. `SettingsPage`: "Just for you" (notification level, quiet-mode list in `Preferences.QuietProcesses`, theme)
  is built once and synced on refresh (a box being typed in is left alone). The PC form compares with
  `EdrConfig.UserJson()` - the file's exact values, never the rounded display - and never rebuilds while it has unsaved
  changes (`HasUnsaved`), unless the file changed elsewhere (reset, import, Network switch): then it is rebuilt from the
  file and the user's change set is put back (`Form.Load`) with a notice in the save bar. The save bar (`Border.savebar`)
  is pinned under the scrolled page while there are changes or a save state; *Save settings* (Ctrl+S) is enabled only
  with changes and no field error, *Discard* (Esc, asks) only with changes; the Settings nav button shows an *Unsaved* badge, leaving Settings says the edits wait
  there, and hiding the tray icon offers *Save and close / Close without saving / Cancel* (`App.ExitAsked`; an
  installer-driven exit cannot wait). Save sends only the changed values (`set-config` with a change set), so a value
  changed elsewhere meanwhile (the Wail2Ban switch on Network, another admin) is never overwritten. Each PC setting is a
  `Field`: ⓘ button (`Button.info`: Tab stop with focus ring, flyout on click / Enter / Space, tooltip on hover) +
  accessible name/help text, a *Default* link while it differs from `EdrConfig.UserDefaults()`,
  an inline error (`EdrConfig.FeedProblem`, empty numbers, no scan time, folder-like quiet names); number ranges from
  `EdrConfig.Limits`; ban caps as presets (1 h ... 1 year; a file value that is none of them is its own item); a window
  in seconds that are not whole minutes is kept exactly while not edited; dependencies (ban lengths and IPv6 block need
  *Block attackers*); scan times as chips + `TimePicker`; *Check logs from the last* as words, a value set by hand kept as
  its own item; the feed has *Test* (`Controller.TestFeed`, ≤ 64 MB, 30 s) and is masked with an eye toggle when it holds
  a key (`EdrConfig.FeedHasSecret`). Expert fields sit in an `Expander` per section ("Advanced", open state in
  `Preferences.AdvancedOpen`, opens by itself on an error, shows how many fields are not at the default). The label column
  is one `SharedSizeGroup` for the page. The scroll position is kept in `Preferences.SettingsScroll`. After a save the page shows
  *waiting for the engine* until `status.json` `settingsLoaded` reaches the file's write time (`TrayState.SettingsActive`),
  then *active*. Sections in order: Just for you (notifications, quiet mode, theme: apply at once), Wail2Ban, Defender,
  Scans, *Restore default settings*, Backup & import (`SettingsBackup`; the account's quiet list rides along, a feed key
  only when the user says so), Troubleshoot (test alert, *Open
  logs* menu, restart engine), Records & forensics, Help, Danger zone (`Border.dangerzone`). Trusted-app switches flipped but not applied are kept (`AllowedPage._want`).
* Message bar (`MainWindow.Snack`): information hides after 6 s (10 s with a button), errors stay until *Dismiss*; the
  countdown waits while the pointer is on the bar or keyboard focus is in it and starts again when they leave (WCAG 2.2.1);
  optional action button (*Undo* after *Mark reviewed* / *Yes, it was me*, *Show in folder* after the audit export,
  *Back to Settings*); announced by screen readers (`AutomationProperties.LiveSetting`). Actions that cannot do anything
  (missing log, declined UAC for Velociraptor, file gone, no VirusTotal hash, no app for .md) say why.
* Accessibility: `Ui.Btn` names every button by its label (icon buttons have panel content); Home tiles are `LinkTile`
  (focusable, Enter/Space, an invokable button for UI Automation); nav buttons carry their badge count; danger dialogs
  make Enter and the first focus *Cancel*; muted text `#95A3BD` (>= 4.5:1 on cards and selected rows); reviewed rows use
  a darker card instead of opacity. The welcome window can be resized and its steps scroll; *Skip tour* or its X (`WelcomeWindow.Skipped`: a user close,
  not a programmatic one such as the installer's exit) sets `welcomeDone`, so the tour does not return at every sign-in.
* Counts (UI audit 2026-11-07): the sidebar badge, Home's tiles and hero sentence and a list page's first tab all show
  `SectionModel.Count` (every open item); `Attention` (High/Critical) only decides red vs grey.
* Every elevated confirmation (`Controller.Send`) names its action on the main button (*Ban IP*, *Allow*, *Trust*,
  *Flag as threat*, *Remove allow*, *Unban*, ...), never "Continue". The *Was this you?* answers are *Yes, it was me* /
  *No, it wasn't me* / *No - ban this IP* on Home, in the details pane and in notifications.
* List pages: the details pane is 42 % of the page width, 300-400 px, so the list keeps room at the minimum window size
  (980 x 620). Custom tab panels (Trusted apps, FreeEDR tools) are left-aligned with the header (max 1000 px). Trusted
  apps' *Apply changes* is enabled only while a switch differs from what is applied (tooltip says why, also disabled).
* Bounded memory: `EventTail` keeps 10,000 events (`EDR_EVENT_CAP`), evicted events keep their group counts, last bans
  and pinned "Was this you?" items (`EdrInputs.RecordEvicted`).
* `EventTail` follows the events file by identity (volume + file index, `Win32.FileIdOf`), not only by length: another
  file (rotation, or a file deleted and written again) is read from its start even when it is already longer than the
  old read position. When the file is gone or replaced and no `events-*.jsonl` archive exists, the history was deleted
  (reset to defaults, clean install): the list and the evicted aggregates are emptied (`WasReset`, `EdrInputs.ClearHistory`)
  so the old alerts do not come back as unreviewed. A rotation always leaves an archive, so its events stay.
* Elevated requests (`Services\Commands.Admin`): the tray waits for the helper's real exit code (`FromExitCode`) and
  stays busy until then; it never tries to end the elevated helper. After 2 minutes (`SlowAfter`; its window still
  open, or a tool download) it says it is still waiting (`Commands.Slow`); after 30 minutes it reports *Unconfirmed*.
  Results: *Unconfirmed* (exit 7 / no pipe answer: may still be carried out, do not repeat yet), *Incomplete* (exit 8 /
  the engine's `failed`: the reason is an event in Activity). `Commands.User` (resume, scan-now) shows the engine's own
  reason (`LastMessage`), e.g. why a scan did not start.
* Closing the dashboard hides it; *Hide the tray icon* exits the tray (protection keeps running).

* Crash recovery: `Win32.RegisterRestart("--restarted")` at start (not in `--dev` / screenshot runs): Windows restarts
  the tray after a crash or hang (it must have run 60 s); "Hide the tray icon" and the installer's stop are clean exits.
* Home shows a red banner "The FreeEDR engine is not responding" (heartbeat older than 90 s) with *Restart engine*
  (elevated helper) and *Open engine log*.

## 2. Code map
| File | Role |
|---|---|
| `App.axaml(.cs)` | tray icon + short menu, tick, notifications wiring, welcome, window management, `--screenshot` |
| `MainWindow.axaml(.cs)` | sidebar (Home, Activity, Network, Updates, Allowed & trusted, Settings) with badges, page host, in-app message bar |
| `Theme.axaml` | colors and control styles: cards, hero, tiles, pills, banners; buttons `primary` (flat blue), `ok` / `danger` (tinted), `ghost`, `link`, `small`, `big`; nav buttons; filter chips; list rows. Also linked into FreeEDR-Installer.exe (the setup window) - a change here changes both |
| `Controller.cs` | every action: verdicts (`Flag`, `Allow` variants, `Back`), trusted apps, pause/resume, scan, settings, factory reset, tool update, CVE/app updates, notification activation, audit CSV |
| `Views\HomePage.cs` | hero status, "Was this you?" (one line per question, ×N, answers all of them), protection tiles with pause menus, learning banner, suggestions, weekly summary |
| `Views\ListPage.cs` | tabs (chips), part filters, search, show reviewed, virtualized `ListBox` of `RowView`, right-click menu, `DetailView` |
| `Views\DetailView.cs` | header with "Caught by" (`Catalog.Module` + module tag), action buttons (`ActionBuilder`), the "reviewed 3 times" suggestion, what happened / what to do (`Hints`), key facts, "Technical details" `Expander` (paths, chain, command line, hash, event time) |
| `Views\AllowedPage.cs` | trusted-app switches + allows, flagged, ignored; `ToolPanel` (FreeEDR tools; one-click update only for a tool with signed releases, otherwise the button is off with the reason) |
| `Views\SettingsPage.cs` | per-account notifications and theme; PC settings form (`Form`/`Field`) saved as a change set through `set-config`; backup / import; troubleshoot, records, help, danger zone |
| `Views\Dialogs.cs` | styled confirm / info / prompt dialogs (one at a time: a second request waits and the open one comes to the front; modal to the dashboard when it is shown, topmost otherwise; at most 90 % of the screen high, a long message scrolls), `WelcomeWindow` (3 steps) |
| `Views\Ui.cs` | palette (`ForModule`), factories (`ModuleTag`), `RowItem` (display text of a model row: title, "program ← parent"), `RowView` (one line: tag + title, sub-line, severity + time; updates itself on `DataContextChanged`, no reflection bindings) |
| `Services\TrayState.cs` | inputs, model, overall sentence, per-account files (reviewed, history, hidden apps); refresh on a worker (`RefreshAsync`), published snapshot, lock for UI edits |
| `Services\Commands.cs` | UAC requests to FreeEDR-Control.exe (non-blocking), inbox requests, `Shell` (argument-vector launches) |
| `Services\Notifier.cs` | WinRT toasts with buttons, AUMID registration (HKCU), levels, learning week, rate limit + digest, quiet mode, engine-down warning |
| `Services\Preferences.cs` | `preferences.json` (incl. `theme`; a failed save is reported, `SaveError`), `Insights` (review counts, dismissed suggestions) |
| `Services\WingetCheck.cs` | `winget upgrade` at the scan times, table parser |
| `ShieldIcon.cs` | the shield drawn at runtime (gradient, glyph per state) |

Everything that decides something lives in Edr.Core and is tested without UI: `ModelBuilder` (lists, grouping, allow and
verdict matching, retired rules, overall sentence), `ActionBuilder` (which actions a selection offers, engine requests,
CVE pip commands), `Hints`, `PeriodSummary`, `Profiles.FindFor`.

### Look (2026-11-06)
Compact and calm: base text 12.5, h1 19 / h2 14.5 / h3 12.5; buttons 30 px (small 26) with medium weight; cards 10 px
radius, 14 px padding; list rows one line high (module tag + title, program ← parent, then severity and time). Button
intents are tinted, not saturated: primary flat blue `#3565C4`, ok = green text on `#1D3A35`, danger = rose text on
`#3A2333`. Module colors: `Palette.ForModule`. Details pane: header with "Caught by", key facts, `Expander` "Technical
details" (closed). Home groups identical "Was this you?" questions into one line per question (up to 6).

## 3. Notifications (`Notifier`)
* Native Windows toasts (`ToastNotificationManager`, AUMID `FreeEDR.Tray` registered per user with the shield icon).
  Buttons: *Review* (`open|<id>`), *Mark reviewed* (`review|<id>`), *Yes, it was me* (`me|<id>`), *Open FreeEDR* (`page|home`).
  Critical alerts use the reminder scenario.
* Levels (Settings, per account): critical / important (default) / all. Always: health problems, "Was this you?", tool updates.
* Learning week (7 days from `installedAt`): only critical detections and "Was this you?"; then one wrap-up.
* Rate limit: 3 per 60 s, the rest as one digest after a minute. Quiet mode: queued while a `quietProcesses` program runs,
  one summary afterwards. Engine-down warning once (heartbeat > 90 s). No notifications for events read at start-up.

## 4. Insights
* Marking an alert reviewed counts it per group (`blade|title|process|parent`; Sigma: title + parent). From the third
  time FreeEDR suggests allowing it (Home ▸ Suggestions and the details pane); *Keep showing it* dismisses the suggestion.
* Weekly summary (`PeriodSummary`): alerts by severity, bans, failed sign-ins, scans, the three most frequent alerts.

## 5. Development modes
* `FreeEDR-Tray.exe --selftest [--dump <dir>] [--compare <dir>]`: builds the model from the live data (or a dump), prints a
  summary; used by the build's live self-test.
* `--dev --root <dir> --local <dir> --screenshot <dir>`: renders every page, Home / Activity / Network again at the
  minimum window size (`*-min.png`), and the welcome to PNG and exits (design checks
  against fixture data, e.g. `src\Edr.Core.Tests\Fixtures\synthetic-a\inputs`).

## 6. Avalonia / AOT rules (bugs that already happened)
* A subclass of `Border` is not styled by `Border.x` selectors unless it overrides `StyleKeyOverride => typeof(Border)`.
* Recycled list containers keep their control: update row visuals in `OnDataContextChanged`, not at template build time.
* `JsonArray.Add(JsonObject)` picks the generic `Add<T>` (AOT warning = error): cast to `JsonNode`.
* `TextBlock` with `NoWrap` still shows embedded newlines: collapse whitespace (`ModelBuilder.Short`) for one-line text.
* A control can have only one parent. A view rebuilt on every visit or refresh (a `ListTab.Custom` builder) must create
  its controls each time, never add a control kept in a field (the Trusted apps tab crashed the tray on its second build).
  `--screenshot` opens every page and tab twice (`MainWindow.ExerciseAllViews`); it never exits if a view throws.
* More: [reference/POWERSHELL_PITFALLS.md](../reference/POWERSHELL_PITFALLS.md).
