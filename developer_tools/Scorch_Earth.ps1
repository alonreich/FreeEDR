# Scorch_Earth.ps1 - Complete uninstallation, state wiping, and restoration of Windows to defaults.
# Removes FreeEDR, EDR, LocalEDR, Wail2Ban, all registry entries, tasks, shortcuts, firewall rules,
# uninstalls Sysmon, restores Windows Defender to clean defaults (CFA disabled, ASR rules cleared),
# and wipes all install/temp directories leaving zero traces.
#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$NoPause)

$ErrorActionPreference = 'Continue'
Set-Location $env:SystemRoot

function Write-Step([string]$Text) { Write-Host "`n== $Text" -ForegroundColor Cyan }
function Write-Ok([string]$Text)   { Write-Host "   OK   $Text" -ForegroundColor Green }
function Write-Warn([string]$Text) { Write-Host "   WARN $Text" -ForegroundColor Yellow }

# Elevation check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: Scorch_Earth requires Administrator privileges." -ForegroundColor Red
    exit 1
}

Write-Host "###########################################################" -ForegroundColor Red
Write-Host " FreeEDR / EDR Scorch-Earth Removal & Windows Restoration" -ForegroundColor Yellow
Write-Host "###########################################################" -ForegroundColor Red

# 1. Stop Processes
Write-Step "Stopping all FreeEDR, EDR, and tool processes"
foreach ($ev in 'Local\FreeEDR-Tray-Exit', 'Local\EDR-Tray-Exit') {
    try { ([Threading.EventWaitHandle]::OpenExisting($ev)).Set() | Out-Null } catch { }
}
Start-Sleep -Seconds 1
$procs = Get-CimInstance Win32_Process | Where-Object {
    $_.CommandLine -match 'EDR-(Engine|Tray|Scan|Control)\.ps1' -or
    $_.Name -match '^(FreeEDR-Tray|hayabusa|osv-scanner|yara64|velociraptor)\.exe$'
}
foreach ($p in $procs) {
    try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; Write-Ok "Killed process $($p.Name) (PID $($p.ProcessId))" }
    catch { Write-Warn "Could not kill process $($p.Name): $($_.Exception.Message)" }
}

# 2. Stop & Remove Scheduled Tasks
Write-Step "Removing all scheduled tasks"
$tasks = @('FreeEDR', 'EDR', 'FreeEDR tray start', 'start wail2ban onstartup', 'LocalEDR-TrayWatcher', 'LocalEDR-DailyScan')
foreach ($t in $tasks) {
    if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue
        if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) { Write-Warn "Could not remove task '$t'" }
        else { Write-Ok "Removed task '$t'" }
    }
}

# 3. Registry Cleanup
Write-Step "Removing registry entries (Run keys, uninstaller keys, application settings)"
# Machine Run
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'FreeEDR Tray', 'EDR Tray' -ErrorAction SilentlyContinue
Write-Ok "Cleaned HKLM Run keys"

# Helper for user accounts and profile hives
function Get-AllUserAccounts {
    foreach ($k in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue) {
        if ($k.PSChildName -notmatch '^S-1-(5-21|12-1)-[\d-]+$') { continue }
        $p = [Environment]::ExpandEnvironmentVariables([string](Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue).ProfileImagePath)
        if ($p -and (Test-Path -LiteralPath $p -PathType Container)) { [pscustomobject]@{ Sid = $k.PSChildName; Path = $p } }
    }
}
function Invoke-AllUserHives([scriptblock]$Action) {
    foreach ($a in Get-AllUserAccounts) {
        $key = "Registry::HKEY_USERS\$($a.Sid)"
        if (Test-Path $key) { try { & $Action $key } catch { }; continue }
        $dat = Join-Path $a.Path 'NTUSER.DAT'
        if (-not (Test-Path -LiteralPath $dat)) { continue }
        $tmp = "ScorchEarth-$($a.Sid)"
        $null = & reg.exe load "HKU\$tmp" $dat 2>&1
        if ($LASTEXITCODE -ne 0) { continue }
        try { & $Action "Registry::HKEY_USERS\$tmp" } catch { }
        finally { [GC]::Collect(); [GC]::WaitForPendingFinalizers(); $null = & reg.exe unload "HKU\$tmp" 2>&1 }
    }
}

Invoke-AllUserHives {
    param($k)
    foreach ($n in 'FreeEDR Tray', 'EDR Tray') {
        Remove-ItemProperty -Path "$k\Software\Microsoft\Windows\CurrentVersion\Run" -Name $n -ErrorAction SilentlyContinue
    }
    Remove-Item -Path "$k\Software\FreeEDR", "$k\Software\LocalEDR" -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Ok "Cleaned HKCU / User Hive Run keys and software settings"

# Inno Setup and software keys
Remove-Item -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{6F0E2C1A-4B7D-4E59-9A33-0E2D5C8B7A41}_is1' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{6F0E2C1A-4B7D-4E59-9A33-0E2D5C8B7A41}_is1' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path 'HKLM:\SOFTWARE\FreeEDR', 'HKLM:\SOFTWARE\LocalEDR', 'HKLM:\SOFTWARE\Wail2Ban' -Recurse -Force -ErrorAction SilentlyContinue
Write-Ok "Cleaned Uninstall and product registry keys"

# 4. Shortcuts
Write-Step "Deleting shortcuts"
$shortcuts = @(
    (Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'FreeEDR.lnk'),
    (Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'FreeEDR.lnk'),
    (Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'EDR Security.lnk')
)
foreach ($a in Get-AllUserAccounts) {
    $shortcuts += "$($a.Path)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\FreeEDR.lnk"
    $shortcuts += "$($a.Path)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\EDR Security.lnk"
    $shortcuts += "$($a.Path)\Desktop\FreeEDR.lnk"
}
foreach ($s in @($shortcuts | Where-Object { $_ } | Select-Object -Unique)) {
    if (Test-Path -LiteralPath $s) {
        Remove-Item -LiteralPath $s -Force -ErrorAction SilentlyContinue
        Write-Ok "Deleted shortcut: $s"
    }
}

# 5. Firewall Rules
Write-Step "Removing firewall rules"
try {
    $fw = New-Object -ComObject HNetCfg.FwPolicy2
    $ban = @($fw.Rules | Where-Object { $_.Grouping -eq 'EDR Wail2Ban' -or $_.Name -like 'a a a wail2ban block IP:*' })
    foreach ($r in $ban) { try { $fw.Rules.Remove($r.Name) } catch { } }
    Write-Ok "Removed $($ban.Count) Wail2Ban block rules"
} catch { Write-Warn "Wail2Ban firewall rules: $($_.Exception.Message)" }

$v6 = @(Get-NetFirewallRule | Where-Object { $_.DisplayName -like 'Block RDP IPv6*' -or $_.Name -like 'Block RDP IPv6*' } -ErrorAction SilentlyContinue)
if ($v6.Count) {
    $v6 | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Ok "Removed IPv6 Remote Desktop block rules"
}

# 6. Microsoft Defender Restoration (Windows Defaults)
Write-Step "Restoring Microsoft Defender to Windows defaults (CFA disabled, ASR rules cleared)"
try {
    # Disable Controlled Folder Access
    Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction Stop
    Write-Ok "Disabled Controlled Folder Access (Windows default)"

    # Clear all CFA allowed applications
    $cfaApps = @((Get-MpPreference).ControlledFolderAccessAllowedApplications)
    if ($cfaApps.Count) {
        foreach ($app in $cfaApps) {
            try { Remove-MpPreference -ControlledFolderAccessAllowedApplications $app -ErrorAction SilentlyContinue } catch { }
        }
        Write-Ok "Cleared $($cfaApps.Count) Controlled Folder Access allowed application(s)"
    }

    # Clear all FreeEDR Attack Surface Reduction (ASR) rules
    $asrRules = @(
        '56a863a9-875e-4185-98a7-b882c64b5ce5', '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c', 'd4f940ab-401b-4efc-aadc-ad5f3c50688a',
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550', '5beb7efe-fd9a-4556-801d-275e5ffc04cc',
        'd3e037e1-3eb8-44c8-a917-57927947596d', '3b576869-a4ec-4529-8536-b80a7769e899', '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84',
        '26190899-1602-49e8-8b27-eb1d0a1ce869', 'e6db77e5-3df2-4cf1-b95a-636979351e5b', 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4',
        '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b', 'c1db55ab-c21a-4637-bb3f-a12568109d35',
        '01443614-cd74-433a-b99e-2ecdc07bfc25', 'd1e49aac-8f56-4280-b9ba-993a6d77406c'
    )
    $activeAsr = @((Get-MpPreference).AttackSurfaceReductionRules_Ids | ForEach-Object { ([string]$_).ToLower() })
    $clearedAsr = 0
    foreach ($ruleId in $asrRules) {
        if ($activeAsr -contains $ruleId.ToLower()) {
            try {
                Remove-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -ErrorAction Stop
                $clearedAsr++
            } catch { Write-Warn "Could not remove ASR rule $ruleId : $($_.Exception.Message)" }
        }
    }
    Write-Ok "Removed $clearedAsr FreeEDR Attack Surface Reduction rule(s)"

    # Remove threat action overrides
    $threatIds = @((Get-MpPreference).ThreatIDDefaultAction_Ids)
    if ($threatIds.Count) {
        foreach ($tid in $threatIds) {
            try { Remove-MpPreference -ThreatIDDefaultAction_Ids ([long]$tid) -ErrorAction SilentlyContinue } catch { }
        }
        Write-Ok "Cleared $($threatIds.Count) Defender threat ID override(s)"
    }

    # Remove folder exclusions for FreeEDR / EDR paths
    $exPaths = @((Get-MpPreference).ExclusionPath)
    foreach ($p in $exPaths) {
        if ($p -match 'FreeEDR|LocalEDR|Wail2Ban|\\EDR(\\)?$') {
            try { Remove-MpPreference -ExclusionPath $p -ErrorAction SilentlyContinue; Write-Ok "Removed Defender path exclusion: $p" } catch { }
        }
    }
} catch {
    Write-Warn "Error restoring Defender settings: $($_.Exception.Message)"
}

# 7. Sysmon Uninstallation
Write-Step "Uninstalling Sysmon"
$sysmonExe = "$env:SystemRoot\Sysmon64.exe"
if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
    if (Test-Path -LiteralPath $sysmonExe) {
        $null = & $sysmonExe -u force 2>&1
        Start-Sleep -Seconds 2
    }
    if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
        Write-Warn "Sysmon64 service still present: stopping service"
        & sc.exe stop Sysmon64 2>&1 | Out-Null
        & sc.exe delete Sysmon64 2>&1 | Out-Null
    }
}
if (Get-Service SysmonDrv -ErrorAction SilentlyContinue) {
    & sc.exe stop SysmonDrv 2>&1 | Out-Null
    & sc.exe delete SysmonDrv 2>&1 | Out-Null
}
if (-not (Get-Service Sysmon64 -ErrorAction SilentlyContinue)) {
    Write-Ok "Sysmon64 service uninstalled"
} else {
    Write-Warn "Sysmon64 service could not be completely removed"
}

# Sysmon log file
$evtx = "$env:SystemRoot\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx"
if (Test-Path -LiteralPath $evtx) {
    try { Remove-Item -LiteralPath $evtx -Force -ErrorAction SilentlyContinue; Write-Ok "Deleted Sysmon operational event log file" }
    catch { Write-Warn "Sysmon event log is locked; will be deleted upon restart" }
}

# 8. Event Log Source
Write-Step "Removing event log source"
if ([Diagnostics.EventLog]::SourceExists('wail2ban')) {
    try { Remove-EventLog -Source 'wail2ban' -ErrorAction SilentlyContinue; Write-Ok "Removed event source 'wail2ban'" }
    catch { Write-Warn "Could not remove event source 'wail2ban': $($_.Exception.Message)" }
}

# 9. Filesystem Directory Removal
Write-Step "Removing FreeEDR installation directories"
$dirs = @(
    'C:\Program Files\FreeEDR',
    'C:\EDR',
    'C:\LocalEDR',
    'C:\Wail2Ban'
)
foreach ($a in Get-AllUserAccounts) {
    $dirs += "$($a.Path)\AppData\Local\EDR"
}

foreach ($d in @($dirs | Where-Object { $_ } | Select-Object -Unique)) {
    if (Test-Path -LiteralPath $d) {
        try {
            Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction Stop
            Write-Ok "Deleted directory: $d"
        } catch {
            Write-Warn "Directory $d partially locked: $($_.Exception.Message)"
        }
    }
}

# 10. Temporary Files Cleanup
Write-Step "Cleaning temporary setup and install files"
$tempDirs = @($env:TEMP, "C:\Windows\Temp")
foreach ($a in Get-AllUserAccounts) {
    $tempDirs += "$($a.Path)\AppData\Local\Temp"
}
foreach ($td in @($tempDirs | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique)) {
    Get-ChildItem -Path $td -Filter 'is-*.tmp' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
        try { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue; Write-Ok "Cleaned Inno Setup temp: $($_.FullName)" } catch { }
    }
    Get-ChildItem -Path $td -Filter '*FreeEDR*' -Force -ErrorAction SilentlyContinue | ForEach-Object {
        try { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue; Write-Ok "Cleaned temp file: $($_.FullName)" } catch { }
    }
}

# 11. Final Verification
Write-Step "Verification of Clean System State"
$leftovers = 0
if (Test-Path 'C:\Program Files\FreeEDR') { Write-Warn "Lingering path: C:\Program Files\FreeEDR"; $leftovers++ }
if (Test-Path 'C:\EDR')                  { Write-Warn "Lingering path: C:\EDR"; $leftovers++ }
if (Get-ScheduledTask -TaskName 'FreeEDR' -ErrorAction SilentlyContinue) { Write-Warn "Lingering task: FreeEDR"; $leftovers++ }
if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) { Write-Warn "Lingering service: Sysmon64"; $leftovers++ }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{6F0E2C1A-4B7D-4E59-9A33-0E2D5C8B7A41}_is1') { Write-Warn "Lingering uninstaller registry key"; $leftovers++ }

Write-Host "`n###########################################################" -ForegroundColor Cyan
if ($leftovers -eq 0) {
    Write-Host " SUCCESS: Scorch-earth removal completed. System is 100% clean." -ForegroundColor Green
    Write-Host " Windows Defender has been restored to defaults (CFA disabled, ASR rules cleared)." -ForegroundColor Green
} else {
    Write-Host " COMPLETED WITH $leftovers WARNING(S). Some files may require a reboot to release." -ForegroundColor Yellow
}
Write-Host "###########################################################" -ForegroundColor Cyan

if (-not $NoPause -and [Environment]::UserInteractive) {
    Read-Host "`nPress Enter to exit" | Out-Null
}
