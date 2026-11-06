# Current status and open items (2026-11-06)

Read for: knowing what is already broken or pending before you start, so you do not chase known FAILs/WARNs. Update this
file when you close or open an item.

## Migration
2026-11-06: FreeEDR is C# 14 / .NET 10 / Avalonia, every program NativeAOT ([tray/TRAY_REWRITE_PLAN.md](../tray/TRAY_REWRITE_PLAN.md)).
The 20 improvement proposals P1-P20 are implemented ([DECISIONS.md](DECISIONS.md) §9). **Installed on the owner's PC
2026-11-06 15:13** (2026.11.6.1406; updated 15:25 to 2026.11.6.1520, dev build, unsigned): upgrade from the PowerShell version succeeded, the old scheduled
task and scripts were removed by the installer, the "FreeEDR" service runs, the tray started unelevated. The legacy
PowerShell scripts and `src\parity.ps1` (replaced by the golden model tests) were deleted on 2026-11-06 with the
owner's approval.

## Test bundle
Last result (2026.11.6.1520 installed): `TEST RESULT: OK  pass=146 fail=0 warn=1 skip=0` (see `tests\results\last-run.txt`);
the WARN is L1.

| ID | Item | Status |
|---|---|---|
| T2 | Sysmon rule "New user or admin group change" missed `net user <name> <password> /add` | **Resolved** (rule split: net/net1 + ` user ` + ` /add`) |
| T3 | "Encoded PowerShell command" fired on ` -e ` inside a -Command text | **Resolved** (`excludes all` -command / -c) |
| T4 | "New user or admin group change" fired on `net localgroup administrators` (listing) | **Resolved** (needs ` /add`) |
| T5 | A command line that copies Claude Code's launcher text was hidden | **Resolved** (exact match) |
| T6 | Sigma "Suspicious Encoded/Download Execution" is noisy on developer PCs | To review (Live WARN when it happens) |
| T8 | Sysmon itself has not yet loaded the T2-T4 rule changes (`contains all`, two `CommandLine` filters in one rule) | **Resolved** 2026-11-06: the installer applied the config ("Sysmon config applied") and the Sysmon blade checked on |
| L1 | 05-Live WARN: noisy certutil alerts from the old flood test (x500) | Ages out of the 7-day window (~2026-11-08) |
| L3 | Installed tray (2026.11.6.1406) crashes on the second build of Allowed & trusted > Trusted apps (control re-parented) | **Resolved** 2026-11-06 (fix installed in 2026.11.6.1520) |
| L2 | 05-Live "Folder permissions" failed when the engine consumed a `control\` command file between listing and `Get-Acl` | **Resolved** (the test skips files that disappear) |

## Security audit (2026-11-02) — carried into the C# version
| Rank | Area | C# implementation |
|---|---|---|
| 1 | Own-process filter bypass | `OwnProcess.Check`: exact executable paths under the admin-only folder, elevated children only, tray child allow-list, near-miss alert |
| 2 | CVE update cross-user execution | `ActionBuilder.OwnsCve` (owner SID / admin-only path), `SafePython`, argument vectors |
| 3 | Elevated command channel wildcards | `PatternRules.IsSpecific` / `IsValidOp` / `IsValidCommand` in the helper **and** the engine; payload 64 KB, batch 100 |
| 4 | Trusted-app spoofing | exact detail match, Antigravity off by default, signer cache keyed on file identity, live checks in user-writable folders |
| 5 | Engine hot path / event loss | `EvtSubscribe` bookmarks, one process snapshot per 2 s, bounded YARA queue with `yaraSkipped`, cadence inside the drain loop, backlog/dropped/lag metrics |
| 6 | State file wipe / lost update | `JsonFile` atomic write + `.bak`, strict reads with recovery, no empty overwrite after unrecoverable damage |
| 7 | Wail2Ban quadratic tracking | per-address lists, 50k cap with eviction, 60 s housekeeping, debounced strikes file |
| 8 | Tray unbounded events / re-entrancy | `EventTail` cap 10,000 with eviction aggregates, 2 MB per tick, tick guard, non-blocking UAC requests |

## Owner decisions still open
* Code-signing certificate for the build (P18): Azure Trusted Signing or another code-signing certificate.
* Controlled folder access allows for explorer.exe, dllhost.exe and a user-writable development build; a real-time allow of
  sihost.exe for all rules → recommended: remove the CFA allows; narrow the sihost allow to one rule.
