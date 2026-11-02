# Parity check on the live data (C:\Program Files\FreeEDR): the PowerShell tray dumps the inputs it read and its model (EDR_SELFTEST_DUMP),
# then the C# tray builds its model from exactly those inputs and lists any difference. Exit code 0 = same model.
#   powershell -File src\parity.ps1 [-Exe <EDR-Tray.exe>] [-Keep <fixture name>]
# -Keep copies the dump into Edr.Core.Tests\Fixtures\<name> so it becomes a unit test.
param([string]$Exe = (Join-Path $PSScriptRoot '..\obj\publish\tray\FreeEDR-Tray.exe'), [string]$Keep)
$ErrorActionPreference = 'Stop'
$work = Join-Path $PSScriptRoot "..\obj\parity-$(Get-Date -Format yyyyMMdd-HHmmss)"   # inside the dev folder, not %TEMP%
$env:EDR_SELFTEST_DUMP = $work
# Let the self-test run to the end (Select-Object -First would stop it before the dump is written)
try { $ps = @(powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File (Join-Path $PSScriptRoot '..\EDR-Tray.ps1') -SelfTest) }
finally { Remove-Item Env:EDR_SELFTEST_DUMP }
Write-Host "PowerShell tray: $($ps[0])"
if (-not (Test-Path "$work\model.json")) { Write-Host 'The PowerShell self-test wrote no dump:'; $ps | Out-Host; exit 1 }
& $Exe --selftest --compare $work | Out-Host
$rc = $LASTEXITCODE
if ($Keep) { Copy-Item $work (Join-Path $PSScriptRoot "Edr.Core.Tests\Fixtures\$Keep") -Recurse -Force; Write-Host "Kept as fixture '$Keep'" }
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
exit $rc
