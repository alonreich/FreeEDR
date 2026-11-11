# FreeEDR changelog

Read for: every code change (add your entry under "Unreleased" in the same change) and every release (the release
workflow turns "Unreleased" into the version's notes, which the GitHub release and the dashboard's "What's new" show).

How to write an entry (agents and people alike; `build\EdrBuild` fails a build when code changed since the last release
tag and "Unreleased" is empty):
* **What's new for you**: one plain-English line per change a user can notice: what changed and why it matters to them.
  No file names, class names or jargon. Leave out changes nobody can notice.
* **Technical**: one line per meaningful technical change, with the files or areas, for engineers.
* Never edit a released section; fix a mistake with a new entry. Do not add headings other than the two below.

## Unreleased

### What's new for you
- "Explain for Dummies" on popup notifications now reliably copies the incident explanation prompt to your clipboard even if the dashboard window is closed, and provides the most recent incident timeline logs.
- Settings search now accurately finds and highlights all settings cards (including quiet mode, themes, and IPv6) and hides unrelated cards.
- Restoring a settings backup now reliably restores your personal theme, notification preferences, and update check choices.
- Trusted app profiles for Zoom, Teams, Slack, and Dropbox now require genuine publisher digital signatures on update binaries and Downloads execution, and Zoom only activates when Zoom is installed.
- Network ban history in the details panel no longer displays duplicate IP address lines.
- Settings has been completely upgraded: an instant search bar finds any setting across the dashboard, quiet mode features one-click game auto-detection and removable chips, popup notifications now offer a direct button to silence notifications for whichever game or app is in focus, and themes and notifications switch with clean segmented controls.
- FreeEDR now includes an "🤔 Explain for Dummies" button on every alert, detail view, context menu, and toast notification that automatically prepares an oversimplified AI prompt with full incident context, timeline, and surrounding logs and opens Gemini in your browser.
- FreeEDR now includes smart trusted app profiles out of the box for common enterprise and developer apps (Microsoft Teams, Slack, Cisco Webex, Visual Studio Code, Git for Windows, Docker Desktop, Google Chrome, and Dropbox), preventing false-positive alerts on standard tools.
- FreeEDR now includes trusted app profiles for Microsoft Edge updates and Zoom web launchers out of the box, preventing false-positive alerts when Edge cleans up update tasks or Zoom launches meetings from Downloads.
- Exporting the audit log over an existing file now replaces it cleanly without leaving stale data at the end.
- Theme and notification choice buttons in Settings stay selected if you click them again.
- The Home dashboard Updates card now counts both app updates and security updates.
- "Show the logs folder" in Settings opens the folder even if the engine log has not been created yet.

### Technical
- Added native Win32 clipboard fallback in Win32.cs and Controller.cs to support clipboard copy when the Avalonia window is closed; updated ExplainPrompt.cs to select recent surrounding events via TakeLast and include IP context when detail is empty.
- Enhanced SettingsPage.cs FilterSettings with recursive text inspection across controls and expanders, correctly matching row options and filtering out non-matching cards.
- Fixed Controller.cs ImportBackup to detect and restore personal user preferences (theme, notification level, update check) when PC settings match baseline.
- Hardened Profiles.cs with Authenticode digital signature requirements for Teams, Slack, Dropbox update binaries and Zoom Downloads execution; added Zoom installation detection paths.
- Fixed DetailView.cs ban history facts handler to prevent duplicate Address and Network rows.
- Enhanced Settings UI (`SettingsPage.cs`): added instant search filtering, segmented theme/notification pill controls, responsive quiet mode chips with `Win32.RunningApplications` auto-detection and D3D full-screen game detection (`SHQueryUserNotificationState`), foreground process detection in `Notifier.cs` with toast quiet action button, sanitized exception messages in `Controller.TestFeed`, and updated `SettingsBackup.cs` with user preferences.
- Fixed audit log export stream truncation (`SettingsPage.cs`), toggle button uncheck prevention (`SettingsPage.cs`), and logs folder fallback handling.
- `Commands.cs`: `ShowInExplorer` now opens folders directly and formats `/select` argument without leading space.
- `HomePage.cs` and `ModelBuilder.cs`: included both CVE and winget app update counts in dashboard tile and overall protection status text.
- `AppRelease.cs`: `NormalizeSubject` now parses comma-delimited and quoted certificate subjects; added unit test assertions in `ReleaseTests.cs`.
- Added `ExplainPrompt` builder (`src\Edr.Core\ExplainPrompt.cs`), `ActionKind.ExplainForDummies` in `src\Edr.Core\Actions.cs`, and handling in `src\Edr.Tray\Controller.cs`, `DetailView.cs`, and `Notifier.cs`.
- Added `teams`, `slack`, `webex`, `vscode`, `git`, `docker`, `chrome`, and `dropbox` default profiles to `src\Edr.Core\Profiles.cs`, `src\Edr.Core\Catalog.cs`, and `src\Edr.Setup\Installer.cs`.
- `src\Edr.Engine\Archive.cs`: clear transient subscription errors once source subscription succeeds or receives events so temporary startup delays do not latch permanent errors in `status.json`.
- Added `edge` and `zoom` default profiles to `src\Edr.Core\Profiles.cs`, `src\Edr.Core\Catalog.cs`, and `src\Edr.Setup\Installer.cs`.
- `Fixtures\live-2026-11-01`: normalized synthetic event fixture telemetry (paths and IPs) in `events.jsonl` and `model.json`.
- `Fixtures\live-2026-11-01`: replaced the real exclusion list, app inventory, vulnerable package names and advisory IDs with dummy values (`ExampleAppN`, `example-pkg-x`, `CVE-2099-*`) so the fixture no longer documents the source PC's security posture; golden `model.json` refreshed.
- `release.yml`: the changelog commit is titled `Release <version>: changelog` again (`${env:VERSION}`; `$env:VERSION:` made PowerShell read the colon as part of the name, so 2026.11.8's commit is titled "Release  changelog").

## 2026.11.8 - 2026-11-08

### What's new for you
- FreeEDR now tells you when a new version is out. Settings > FreeEDR updates shows your version and the latest one, checks quietly once a day (you can turn that off), and installs an update with one click after checking that the download is genuine. You can also skip a version or check by hand.
- After an update, FreeEDR shows a short "What's new" once, so you know what changed.
- If an update does not pass its checks, FreeEDR now puts back everything as it was: the programs, your settings, the detection rules, the tools and the version number Windows shows.
- Setup no longer installs an older FreeEDR over a newer one by accident: it asks first.
- Removing FreeEDR can no longer lose the record of the Windows settings it has to put back. If something cannot be restored, the record is kept and Settings > Apps offers "FreeEDR (finish removal)" to try again.
- A Velociraptor update you installed from the dashboard is no longer undone by the next FreeEDR update.
- Settings > Apps now shows FreeEDR's real size on disk.
- If an update stops with an error, the dashboard now always comes back by itself and tells you that your previous version was put back.
- If the PC restarts in the middle of an update, FreeEDR notices next time, tells you, and offers to run Setup again: it finishes the update or puts your previous version back.
- If you skipped a few versions, the update prompt and "What's new" now list what changed in every version since yours, not only the newest.
- Updates from the dashboard are much smaller to download, and the downloaded installer is deleted once it is installed.
- FreeEDR now checks the full identity of the publisher who signed an update, so an update signed by someone with a similar name is refused.
- A version built at home no longer blocks the official update from being offered.

### Technical
- New `Edr.Core\AppRelease.cs`: `AppVersion` (parse / downgrade / release format), `Changelog` (sections, user part, promotion) and `AppRelease` (GitHub latest-release check of `alonreich/FreeEDR`, resumable download into `user\<SID>\update\` with disk-space check, stall timeout and three retries, SHA256 against GitHub's asset digest, signer must match the installed engine's signer). Tray: `Services\AppUpdater.cs`, Settings card, tray menu entry, one notification per version, "What's new" once per upgrade (`docs\CHANGELOG.md` is now installed).
- `Installer.cs`: backup before `--clean`, backup and roll-back now cover `config\`, `rules\*.yar`, `docs\`, `version.txt`, README and the tools the upgrade replaces; downgrade refused without `--allow-downgrade`; `EstimatedSize` written to the Settings > Apps entry.
- `Tools.KeepInstalled`: a tool is kept when it matches its pin, or (Velociraptor) when it is signed by the pinned publisher and not older than the pin; an unsigned tool that differs from its pin is now replaced by the pinned one on upgrade.
- `FreeEDR-Setup.iss`: `InitializeSetup` downgrade check (`/AllowDowngrade=1` for silent installs); `DisplayVersion` re-synced from `version.txt` after a failed or rolled-back upgrade; uninstall runs the helper from `CurUninstallStepChanged` and deletes the folder only when it succeeded (exit 5 keeps the records and registers "FreeEDR (finish removal)"); `[UninstallDelete]` and the fixed `UninstallDisplaySize` removed.
- `Uninstaller.cs`: when a restore step warns, `preinstall.json`, `managed.json`, the Sysmon backup and `bin\` are kept, exit code 5.
- `build\EdrBuild`: version from `EDR_VERSION` or the `v<version>` tag (UTC time stamp otherwise, WARN), dev builds `0.yyMM.ddHH.mm` (never above a release), informational version `<version>+<commit>`; changelog gate; release builds must be signed (`EDR_ALLOW_UNSIGNED=1` to override) and must embed the malware hash seed (its SHA256 and date go into `THIRD_PARTY_NOTICES.txt`); `compiled\FreeEDR-Setup.exe.sha256`; `--promote-changelog`.
- `.github\workflows\release.yml`: manual release (version input): changelog promotion, build, tests 01-04, draft release, asset download and SHA256 check, publish, then keep installers of the five newest releases only (older releases keep tags and notes).
- Release audit 2026-11-08 (11 findings): `Installer.Run` restarts the trays in `finally` after any outcome once they were stopped, rolls back on any exception, writes `data\upgrade-pending.json` (backup, from/to, pid) and reuses its backup after an interrupted upgrade, deletes it on success / roll-back, purges installed downloads in every `user\<SID>\update\`; `Sys.StopFreeEdrProcesses` spares `user\*\update\` (`IsUpdateDownload`); `Tools.IsPackagedToolFile` shared by installer and build.
- `AppRelease`: signer rule on the normalized certificate subject (`AuthenticodeSigners.SubjectOf`, `NormalizeSubject`, `TrustedSuccessorSubjects` for a planned certificate change); prefers the `FreeEDR-Update.exe` asset; `NotesSince` combines the notes of every release after the installed one (`releases?per_page=30`); `PurgeDownloads` / `PurgeInstalled`; `PendingUpgrade`; `Check(reinstall)` offers the installed version again after an interrupted update; 404 message names a private repository. Tray: interrupted-update card and notification, multi-version "What's new" (`Changelog.UserPartsBetween`, `Combine`).
- `build\EdrBuild`: untagged release builds are `0.yyMM.ddHH.mm` "(local release build)" (`AppVersion.LocalNumber`), never above a release; changelog gate checks the Unreleased structure (`Changelog.Problems`), that released sections are unchanged since the last tag (`Changelog.ReleasedKept`) and that no code changed after the last changelog edit (uncommitted: WARN in dev builds, error in release builds; committed: error), before the first tag too; release builds also produce `compiled\FreeEDR-Update.exe` (+ `.sha256`) without bundled tools (`EDR_BUILD_UPDATE=1` in dev builds); `--promote-changelog` writes `Changelog.ReleaseBody` (user part first, technical part in `<details>`); `FreeEDR-Setup.iss` takes `OutputName`.
- `release.yml`: `dry_run` input; leftover draft / staging branch removed first; release commit pushed to `release-staging/v<v>` and merged into the branch only after both assets are verified, before publishing; test gate fails on SKIPs not caused by `-SkipLive` and on suites without a PASS; `releases/latest` retried for 60 s; retention counts only releases with the workflow's marker; clean-up on failure or cancel removes the draft and staging branch and reverts a pushed changelog commit.
- `release.yml`: a staging branch is deleted only when `git ls-remote` finds it, and steps whose last command may fail on purpose end with `exit 0` (the first dry run failed because pwsh on Actions returns the last native exit code, here a `git push --delete` of a branch that did not exist).
- Tests run the same on the release runner (elevated, other programs installed): golden model tests read each fixture's recorded `signers.json` (`FixtureSigners`, `FREEEDR_RECORD_SIGNERS=1` to record) instead of the PC's real signatures; pipe tests accept the Administrators owner of an elevated session's pipes (`TestAccount`); the "normal account" pipe test and the sandbox start tests are skipped, with the reason, in an elevated non-SYSTEM session; `release.yml` allows only runner-related skip reasons (`ALLOWED_SKIPS`). The same skip covers the tool-version, Hayabusa / OSV-Scanner start and "cannot write" sandbox tests, which run on the runner once its tool cache is filled (there the sandboxed child exits 0xC0000142).
