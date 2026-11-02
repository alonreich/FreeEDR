# Builds the NativeAOT tray into ..\obj\publish\tray (FreeEDR-Tray.exe + Avalonia's native DLLs; .pdb symbols stay beside it).
# Normally dev_build.cmd / build.cmd do this; this script is for working on the tray alone.
# Needs the .NET 10 SDK and the VS 2022 C++ build tools. Run from any folder: powershell -File src\publish.ps1
$ErrorActionPreference = 'Stop'
# The AOT linker finds the C++ tools through vswhere.exe, which the VS installer does not put on PATH
$vsInstaller = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer"
if ((Test-Path "$vsInstaller\vswhere.exe") -and ($env:PATH -notlike "*$vsInstaller*")) { $env:PATH += ";$vsInstaller" }
$out = Join-Path $PSScriptRoot '..\obj\publish\tray'
& dotnet test --project "$PSScriptRoot\Edr.Core.Tests" -c Release
if ($LASTEXITCODE -ne 0) { throw "Tests failed (exit $LASTEXITCODE)" }
& dotnet publish "$PSScriptRoot\Edr.Tray" -c Release -o $out
if ($LASTEXITCODE -ne 0) { throw "Publish failed (exit $LASTEXITCODE)" }
Get-ChildItem $out -File | Where-Object Extension -ne '.pdb' | Format-Table Name, @{ n = 'MB'; e = { [math]::Round($_.Length / 1MB, 1) } } -AutoSize
