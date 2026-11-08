$ErrorActionPreference = 'Stop'
$vsInstaller = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer"
if ((Test-Path "$vsInstaller\vswhere.exe") -and ($env:PATH -notlike "*$vsInstaller*")) { $env:PATH += ";$vsInstaller" }
$out = Join-Path $PSScriptRoot '..\obj\publish\tray'
& dotnet test --project "$PSScriptRoot\Edr.Core.Tests" -c Release
if ($LASTEXITCODE -ne 0) { throw "Tests failed (exit $LASTEXITCODE)" }
& dotnet publish "$PSScriptRoot\Edr.Tray" -c Release -o $out
if ($LASTEXITCODE -ne 0) { throw "Publish failed (exit $LASTEXITCODE)" }
Get-ChildItem $out -File | Where-Object Extension -ne '.pdb' | Format-Table Name, @{ n = 'MB'; e = { [math]::Round($_.Length / 1MB, 1) } } -AutoSize
