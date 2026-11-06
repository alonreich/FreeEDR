# Dashboard implementation (`src\Edr.Tray`, FreeEDR-Tray.exe)

Read for: changes to the tray app. What the user sees is specified in [user/USER_GUIDE.md](../user/USER_GUIDE.md); the
files it reads in [architecture/DATA_FILES.md](../architecture/DATA_FILES.md) §3-4.

## 1. Process model
* Avalonia 12 (Fluent theme, dark variant + `Theme.axaml`), NativeAOT, `net10.0-windows10.0.19041.0` (Windows SDK
  projection for native notifications), unelevated (`asInvoker`), one instance per session (`Local\FreeEDR-Tray`); a
  second launch signals `Local\FreeEDR-Tray-Show`; the installer closes it with `Local\FreeEDR-Tray-Exit`.
* Started from `HKLM\...\Run\FreeEDR Tray`; `--show` opens the dashboard; `--toast-title/--toast-text/--toast-level`
  show one notification at start (installer). `--dev` uses `-Dev` instance names; `--root`/`--local` read another folder.
* `App`: a 2-second `DispatcherTimer` → `Tick` (re-entrancy guarded): `TrayState.Refresh` (tails `events.jsonl` 2 MB per
  tick, re-reads files whose timestamp changed, rebuilds the model with `ModelBuilder` when anything changed), new
  events → `Notifier.Consider`, `Notifier.Tick`, `WingetCheck.Tick`, weekly summary / learning-week wrap-up, tray icon
  and menu (rebuilt only when the state changes), visible window refresh.
* Bounded memory: `EventTail` keeps 10,000 events (`EDR_EVENT_CAP`), evicted events keep their group counts, last bans
  and pinned "Was this you?" items (`EdrInputs.RecordEvicted`).
* Closing the dashboard hides it; *Hide the tray icon* exits the tray (protection keeps running).

## 2. Code map
| File | Role |
|---|---|
| `App.axaml(.cs)` | tray icon + short menu, tick, notifications wiring, welcome, window management, `--screenshot` |
| `MainWindow.axaml(.cs)` | sidebar (Home, Activity, Network, Updates, Allowed & trusted, Settings) with badges, page host, in-app message bar |
| `Theme.axaml` | colors and control styles: cards, hero, tiles, pills, banners; buttons `primary` (gradient), `ok`, `danger`, `ghost`, `link`, `small`, `big`; nav buttons; filter chips; list rows |
| `Controller.cs` | every action: verdicts (`Flag`, `Allow` variants, `Back`), trusted apps, pause/resume, scan, settings, factory reset, tool update, CVE/app updates, notification activation, audit CSV |
| `Views\HomePage.cs` | hero status, "Was this you?" cards, protection tiles with pause menus, learning banner, suggestions, weekly summary |
| `Views\ListPage.cs` | tabs (chips), part filters, search, show reviewed, virtualized `ListBox` of `RowView`, right-click menu, `DetailView` |
| `Views\DetailView.cs` | what happened / what to do (`Hints`), facts, action buttons (`ActionBuilder`), the "reviewed 3 times" suggestion |
| `Views\AllowedPage.cs` | trusted-app switches + allows, flagged, ignored; `ToolPanel` (FreeEDR tools with one-click update) |
| `Views\SettingsPage.cs` | notification level (per account), PC settings saved through `set-config`, maintenance, reset |
| `Views\Dialogs.cs` | styled confirm / info / prompt dialogs, `WelcomeWindow` (3 steps) |
| `Views\Ui.cs` | palette, factories, `RowItem` (display text of a model row), `RowView` (updates itself on `DataContextChanged`, no reflection bindings) |
| `Services\TrayState.cs` | inputs, model, overall sentence, per-account files (reviewed, history, hidden apps) |
| `Services\Commands.cs` | UAC requests to FreeEDR-Control.exe (non-blocking), inbox requests, `Shell` (argument-vector launches) |
| `Services\Notifier.cs` | WinRT toasts with buttons, AUMID registration (HKCU), levels, learning week, rate limit + digest, quiet mode, engine-down warning |
| `Services\Preferences.cs` | `preferences.json`, `Insights` (review counts, dismissed suggestions) |
| `Services\WingetCheck.cs` | `winget upgrade` at the scan times, table parser |
| `ShieldIcon.cs` | the shield drawn at runtime (gradient, glyph per state) |

Everything that decides something lives in Edr.Core and is tested without UI: `ModelBuilder` (lists, grouping, allow and
verdict matching, retired rules, overall sentence), `ActionBuilder` (which actions a selection offers, engine requests,
CVE pip commands), `Hints`, `PeriodSummary`, `Profiles.FindFor`.

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
* `--dev --root <dir> --local <dir> --screenshot <dir>`: renders every page and the welcome to PNG and exits (design checks
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
