param(
    [switch]$SelfTest,
    [switch]$BuildOnly,
    [switch]$Clean,
    [switch]$Show,
    [switch]$Dev,
    [switch]$Aot
)

$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$DevAppDir = Join-Path $RepoRoot '.dev-run\app'

Write-Host "=== FreeEDR -- Developer Runner ===" -ForegroundColor Cyan

$NormalizedDevDir = [System.IO.Path]::GetFullPath($DevAppDir)
Get-Process -Name 'FreeEDR-Tray', 'Edr.Tray' -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        $procPath = $_.MainModule.FileName
        if ($procPath -and $procPath.StartsWith($NormalizedDevDir, [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Host "Stopping running dev instance PID=$($_.Id)..." -ForegroundColor Yellow
            $_.Kill()
            $_.WaitForExit(5000) | Out-Null
        }
    } catch { }
}

if ($Clean -and (Test-Path $DevAppDir)) {
    Write-Host "Cleaning .dev-run\app..." -ForegroundColor Yellow
    Remove-Item -LiteralPath $DevAppDir -Recurse -Force
}

New-Item -ItemType Directory -Path $DevAppDir -Force | Out-Null
$TrayProj = Join-Path $RepoRoot 'src\Edr.Tray\Edr.Tray.csproj'

$trayArgs = @()
if ($SelfTest) { $trayArgs += '--selftest' }
if ($Show -or -not $SelfTest) { $trayArgs += '--show' }
if ($Dev) { $trayArgs += '--dev' }

if ($Aot) {
    $vsInstaller = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer"
    if ((Test-Path "$vsInstaller\vswhere.exe") -and ($env:PATH -notlike "*$vsInstaller*")) { $env:PATH += ";$vsInstaller" }

    Write-Host "Publishing NativeAOT dev tray to $DevAppDir..." -ForegroundColor Cyan
    & dotnet publish $TrayProj -c Release -o $DevAppDir --nologo
    if ($LASTEXITCODE -ne 0) {
        Write-Error "dotnet publish (AOT) for dev runner failed."
        exit $LASTEXITCODE
    }

    if ($BuildOnly) {
        Write-Host "Dev build succeeded (-BuildOnly specified; skipping launch)." -ForegroundColor Green
        exit 0
    }

    $ExePath = Join-Path $DevAppDir 'FreeEDR-Tray.exe'
    if ($SelfTest) {
        Write-Host "Running NativeAOT tray self-test..." -ForegroundColor Cyan
        & $ExePath @trayArgs
        exit $LASTEXITCODE
    }

    Write-Host "Launching $ExePath ($($trayArgs -join ' '))..." -ForegroundColor Green
    Start-Process -FilePath $ExePath -ArgumentList ($trayArgs -join ' ') -WorkingDirectory $DevAppDir
} else {
    Write-Host "Building dev tray (fast JIT) to $DevAppDir..." -ForegroundColor Cyan
    & dotnet build $TrayProj -c Release -p:PublishAot=false -o $DevAppDir --nologo
    if ($LASTEXITCODE -ne 0) {
        Write-Error "dotnet build for dev runner failed."
        exit $LASTEXITCODE
    }

    if ($BuildOnly) {
        Write-Host "Dev build succeeded (-BuildOnly specified; skipping launch)." -ForegroundColor Green
        exit 0
    }

    $DllPath = Join-Path $DevAppDir 'FreeEDR-Tray.dll'
    if ($SelfTest) {
        Write-Host "Running C# tray self-test..." -ForegroundColor Cyan
        & dotnet $DllPath @trayArgs
        exit $LASTEXITCODE
    }

    Write-Host "Launching $DllPath ($($trayArgs -join ' '))..." -ForegroundColor Green
    Start-Process -FilePath "dotnet" -ArgumentList "`"$DllPath`" $($trayArgs -join ' ')" -WorkingDirectory $DevAppDir
}
