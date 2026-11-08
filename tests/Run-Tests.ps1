param([string]$Suite = '*', [switch]$SkipLive, [switch]$NoAttack)

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
