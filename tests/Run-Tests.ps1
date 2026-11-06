# Run-Tests.ps1 - the FreeEDR test bundle. MANDATORY after every code change (see AGENTS.md / CLAUDE.md):
#     powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1            (unelevated: the live
#                                                                                           permission pen tests need it)
#     options: -Suite <name pattern>   only matching suites (e.g. -Suite PenTest)
#              -SkipLive               only the repository checks (no reads of C:\Program Files\FreeEDR)
#              -NoAttack               live pen tests without the inbox injection (it drops one forbidden request)
# Suites (tests\NN-*.Tests.ps1): Sanity (files, encodings, Sysmon template, installer <-> uninstaller symmetry, docs),
# Unit (the C# core: rules, settings, JSON files, actions, golden dashboard models, engine internals), FalsePositive
# (Sysmon rules + allow decisions against everyday and attack command lines), PenTest (own-process trust spoofing,
# command channel, CVE-update injection, permissions of the live install), Live (health of the installed FreeEDR).
# The C# tests (src\Edr.Core.Tests) are built and run once; each one is reported in the suite that owns it.
# Result: one line per check, a summary, tests\results\last-run.txt + .json. Exit code 0 = no FAIL, 1 = FAIL.
# Investigate every FAIL and WARN before declaring a change done; a SKIP says what was not covered.
param([string]$Suite = '*', [switch]$SkipLive, [switch]$NoAttack)

# FreeEDR targets Windows PowerShell 5.1; the tests run there too
if ($PSVersionTable.PSVersion.Major -ge 6) {
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-Suite', $Suite)
    if ($SkipLive) { $a += '-SkipLive' }; if ($NoAttack) { $a += '-NoAttack' }
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" @a
    exit $LASTEXITCODE
}

$ErrorActionPreference = 'Stop'
$Repo = Split-Path $PSScriptRoot
. "$PSScriptRoot\TestKit.ps1"
$ResultsDir = "$PSScriptRoot\results"
New-Item -ItemType Directory -Path $ResultsDir -Force | Out-Null
$started = Get-Date
$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "FreeEDR tests  $($started.ToString('yyyy-MM-dd HH:mm:ss'))  repo: $Repo  $(if ($elevated) { 'ELEVATED (live permission tests are skipped)' } else { 'unelevated' })" -ForegroundColor Cyan

foreach ($f in Get-ChildItem "$PSScriptRoot\*.Tests.ps1" | Sort-Object Name) {
    $name = $f.BaseName -replace '^\d+-' -replace '\.Tests$'
    if ($name -notlike $Suite) { continue }
    $global:FreeEdrTestSuite = $name
    Write-Host "`n== $name" -ForegroundColor Cyan
    try { & $f.FullName -Repo $Repo -Live:(-not $SkipLive) -Attack:(-not $NoAttack) -Elevated:$elevated -Work $ResultsDir }
    catch { [void]$global:FreeEdrTestResults.Add([pscustomobject]@{ Suite = $name; Name = '(suite crashed)'; Result = 'FAIL'; Detail = "$($_.Exception.Message) $($_.InvocationInfo.PositionMessage)" }); Write-Host "  FAIL suite crashed: $($_.Exception.Message)" -ForegroundColor Red }
}

$count = @{}
foreach ($k in 'PASS', 'FAIL', 'WARN', 'SKIP') { $count[$k] = @($global:FreeEdrTestResults | Where-Object { $_.Result -eq $k }).Count }
$summary = "TEST RESULT: $(if ($count.FAIL) { 'FAIL' } else { 'OK' })  pass=$($count.PASS) fail=$($count.FAIL) warn=$($count.WARN) skip=$($count.SKIP)  ($([int]((Get-Date) - $started).TotalSeconds) s)"
$lines = @($summary, '') + @($global:FreeEdrTestResults | Where-Object { $_.Result -ne 'PASS' } | ForEach-Object { "$($_.Result) [$($_.Suite)] $($_.Name)`n     $($_.Detail)" })
[IO.File]::WriteAllText("$ResultsDir\last-run.txt", ($lines -join "`r`n") + "`r`n")
[IO.File]::WriteAllText("$ResultsDir\last-run.json", (@{ started = $started.ToString('s'); summary = $summary; results = @($global:FreeEdrTestResults) } | ConvertTo-Json -Depth 4))
Write-Host "`n$summary" -ForegroundColor $(if ($count.FAIL) { 'Red' } elseif ($count.WARN) { 'Yellow' } else { 'Green' })
if ($count.FAIL + $count.WARN) {
    Write-Host 'Not passed:' -ForegroundColor Yellow
    foreach ($r in $global:FreeEdrTestResults | Where-Object { $_.Result -in 'FAIL', 'WARN' }) { Write-Host "  $($r.Result) [$($r.Suite)] $($r.Name)" -ForegroundColor $(if ($r.Result -eq 'FAIL') { 'Red' } else { 'Yellow' }) }
}
Write-Host "Details: $ResultsDir\last-run.txt"
exit $(if ($count.FAIL) { 1 } else { 0 })
