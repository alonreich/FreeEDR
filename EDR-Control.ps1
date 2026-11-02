# EDR-Control.ps1 - elevated helper launched by the tray through UAC.
# Validates one command and drops it into control\ (admin-only) for the engine to execute.
param([Parameter(Mandatory = $true)][string]$Payload)

. "$PSScriptRoot\EDR-Common.ps1"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { exit 5 }

$cmd = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Payload)) | ConvertFrom-Json
$allowed = @('pause', 'resume', 'scan-now', 'unban', 'exclude', 'unexclude', 'block', 'unblock', 'batch', 'restart-engine')
if ($cmd.action -notin $allowed) { exit 2 }
if ($cmd.action -eq 'batch' -and @($cmd.ops | Where-Object { $_.action -notin @('unban', 'exclude', 'unexclude', 'block', 'unblock') }).Count) { exit 2 }

if ($cmd.action -eq 'restart-engine') {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Start-ScheduledTask -TaskName $TaskName
    exit 0
}

$tmp = Join-Path $ControlDir ("{0}-{1}.tmp" -f (Get-Date -Format 'yyyyMMddHHmmssfff'), [guid]::NewGuid().ToString('N').Substring(0, 6))
$final = [IO.Path]::ChangeExtension($tmp, '.json')
[IO.File]::WriteAllText($tmp, ($cmd | ConvertTo-Json -Depth 6 -Compress), $Utf8NoBom)
[IO.File]::Move($tmp, $final)
exit 0
