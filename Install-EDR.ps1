# Install-EDR.ps1 - installs, upgrades or repairs FreeEDR in C:\Program Files\FreeEDR. Run elevated from the project folder:
#     powershell -ExecutionPolicy Bypass -File .\Install-EDR.ps1 [-AllowNewerTools] [-NoPause]
#     (or run compiled\FreeEDR-Setup.exe, which unpacks these files and runs this script; exit 0 / 3 / 1 = success / rolled back / failed)
# Idempotent: safe to run again. Never deletes data\ (events, bans, state) or your exclusions.
#   * fresh PC        : downloads Sysmon + pinned tool versions (hash-verified), installs everything
#   * upgrade         : backs up the current scripts, installs the new ones, rolls back if the engine fails
#   * move from C:\EDR: the install before 2026-11-02 (task "EDR", %LOCALAPPDATA%\EDR) is moved into the new folder
#                       with all its data, and removed only after the new install is verified
#   * legacy migration: imports C:\Wail2Ban + C:\LocalEDR (history, bans, tools) and removes them after success
#Requires -RunAsAdministrator
param([switch]$AllowNewerTools, [switch]$NoPause)

$ErrorActionPreference = 'Stop'
$Src    = $PSScriptRoot
$Root   = "$(if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles })\FreeEDR"   # = $Root of EDR-Common.ps1
$OldRoot  = 'C:\EDR'                          # install folder before 2026-11-02
$OldLocal = "$env:LOCALAPPDATA\EDR"            # the tray's per-user files before 2026-11-02 (now $Root\user)
$OldEdr = 'C:\LocalEDR'
$OldW2b = 'C:\Wail2Ban'
$DlDir     = "$Root\data\download"               # downloads in progress (not %TEMP%: FreeEDR keeps its files in its own folder)
New-Item -ItemType Directory -Path $Root, $DlDir -Force | Out-Null
Start-Transcript -Path "$Root\install.log" -Force | Out-Null

function Step([string]$Text) { Write-Host "`n== $Text" -ForegroundColor Cyan }
function Ok([string]$Text)   { Write-Host "   OK   $Text" -ForegroundColor Green }
function Warn([string]$Text) { Write-Host "   WARN $Text" -ForegroundColor Yellow }

# Pinned tool versions (SHA256 of the executable after extraction)
$Tools = @(
    @{ Name = 'Hayabusa';     Repo = 'Yamato-Security/hayabusa'; Tag = 'v4.3.1';  Asset = '-win-x64\.zip$';          Exe = 'hayabusa\hayabusa.exe'; Sha = '411CE8749115C85B359ADE15B9824B38650B06274DC816D1D4B9035859C8C573' }
    @{ Name = 'YARA';         Repo = 'VirusTotal/yara';          Tag = 'v4.6.0';  Asset = 'win64\.zip$';             Exe = 'yara64.exe';            Sha = '6B4897B945F408080645EC06E2D2540F067A57A68D5E5830781CDC1D88FC41E2' }
    @{ Name = 'OSV-Scanner';  Repo = 'google/osv-scanner';       Tag = 'v2.7.0';  Asset = 'windows_amd64\.exe$';     Exe = 'osv-scanner.exe';       Sha = '9964ED64EC9A387391EB4CC006AD5C531154821AEF29B793E02C448DE4686438' }
    # Velociraptor ships gzipped since 0.77.3 (.exe.gz, GitHub digest of the .gz checked 2026-11-01; Sha is of the extracted exe, signed Rapid7 LLC).
    # Upgrade = replace an existing copy whose hash differs (single exe, so it can be swapped back on failure)
    @{ Name = 'Velociraptor'; Repo = 'Velocidex/velociraptor';   Tag = 'v0.77.3'; Asset = 'windows-amd64\.exe(\.gz)?$'; Exe = 'velociraptor.exe';  Sha = '3D20A5A2D272E3EB2BCCAE4A80EBE469FC1A6F63EB4A8F8A586DBAE356437D32'; Upgrade = $true }
)
$ProjectFiles = @('EDR-Common.ps1', 'EDR-Engine.ps1', 'EDR-Scan.ps1', 'EDR-Control.ps1', 'EDR-Tray.ps1', 'Install-EDR.ps1', 'README.md', 'Installation_Process.md',
                  'config\sysmonconfig.template.xml', 'rules\custom_edr.yar', 'rules\ransomware.yar')
$oldTasks = @('start wail2ban onstartup', 'LocalEDR-TrayWatcher', 'LocalEDR-DailyScan')
$result = 'FAILED'
$backup = $null
$legacy = (Test-Path $OldEdr) -or (Test-Path $OldW2b)
$moveOld = (Test-Path "$OldRoot\EDR-Engine.ps1") -and ($OldRoot -ne $Root)
$runKey  = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$oldLnk  = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\EDR Security.lnk"

function Get-Download([string]$Url, [string]$OutFile) {
    & curl.exe -sSL --fail --max-time 600 -H 'User-Agent: FreeEDR-installer' -o $OutFile $Url
    if ($LASTEXITCODE -ne 0) { throw "Download failed: $Url" }
}

function Install-Tool($T) {
    $target = "$BinDir\$($T.Exe)"
    if (Test-Path $target) {
        if (-not $T.Upgrade -or (Get-FileHash $target -Algorithm SHA256).Hash -eq $T.Sha) { Ok "$($T.Name) present"; return }
        $old = "$target.old"
        try { Move-Item $target $old -Force -ErrorAction Stop } catch { Warn "$($T.Name): cannot update to $($T.Tag) (file in use?) - kept the installed version"; return }
        try { Install-ToolFiles $T $target; Remove-Item $old -Force -ErrorAction SilentlyContinue }
        catch { Remove-Item $target -Force -ErrorAction SilentlyContinue; Move-Item $old $target -Force; Warn "$($T.Name) update to $($T.Tag) failed, kept the installed version: $_" }
        return
    }
    Install-ToolFiles $T $target
}

function Install-ToolFiles($T, [string]$target) {
    $tag = $T.Tag
    $api = (& curl.exe -sSL -H 'User-Agent: FreeEDR-installer' "https://api.github.com/repos/$($T.Repo)/releases/tags/$tag") -join "`n" | ConvertFrom-Json
    if (-not $api.assets -and $AllowNewerTools) {
        $api = (& curl.exe -sSL -H 'User-Agent: FreeEDR-installer' "https://api.github.com/repos/$($T.Repo)/releases/latest") -join "`n" | ConvertFrom-Json
        $tag = $api.tag_name
    }
    $asset = @($api.assets | Where-Object { $_.name -match $T.Asset -and $_.name -notmatch 'live-response|debug|msi' }) | Select-Object -First 1
    if (-not $asset) { throw "$($T.Name) $tag : no matching release asset" }
    $dl = Join-Path $DlDir $asset.name
    Get-Download $asset.browser_download_url $dl
    if ($dl -like '*.gz') {
        $in = [IO.File]::OpenRead($dl)
        try {
            $gz = New-Object IO.Compression.GZipStream($in, [IO.Compression.CompressionMode]::Decompress)
            $out = [IO.File]::Create($target)
            try { $gz.CopyTo($out) } finally { $out.Dispose(); $gz.Dispose() }
        } finally { $in.Dispose() }
    } elseif ($dl -like '*.zip') {
        $x = Join-Path $DlDir "x-$($T.Name)"
        Remove-Item $x -Recurse -Force -ErrorAction SilentlyContinue
        Expand-Archive $dl $x -Force
        if ($T.Name -eq 'Hayabusa') {
            New-Item -ItemType Directory -Path "$BinDir\hayabusa" -Force | Out-Null
            Copy-Item "$x\*" "$BinDir\hayabusa\" -Recurse -Force
            $exe = Get-ChildItem "$BinDir\hayabusa\hayabusa-*-win-x64.exe" | Select-Object -First 1
            Move-Item $exe.FullName $target -Force
        } else {
            Get-ChildItem $x -Recurse -Include 'yara64.exe', 'yarac64.exe' | ForEach-Object { Copy-Item $_.FullName $BinDir -Force }
        }
        Remove-Item $x -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Copy-Item $dl $target -Force
    }
    Remove-Item $dl -Force -ErrorAction SilentlyContinue
    $h = (Get-FileHash $target -Algorithm SHA256).Hash
    if ($h -ne $T.Sha) {
        if ($AllowNewerTools -and $tag -ne $T.Tag) { Warn "$($T.Name) $tag installed (newer than the pinned $($T.Tag); hash not pinned: $h)" }
        else { Remove-Item $target -Force; throw "$($T.Name): SHA256 mismatch ($h) - refusing to install" }
    } else { Ok "$($T.Name) $tag downloaded and verified" }
}

try {
    Step 'Pre-flight'
    $me = [Security.Principal.WindowsIdentity]::GetCurrent()
    $userSid = $me.User.Value   # used only for the folder permissions below, never stored
    Ok 'Running elevated'
    foreach ($f in $ProjectFiles) { if (-not (Test-Path "$Src\$f")) { throw "Missing project file $Src\$f" } }

    if ($moveOld) {
        Step "Moving the previous install from $OldRoot to $Root"
        # Stop the old engine and tray; the old task stays registered (disabled) until the new install is verified
        if (Get-ScheduledTask -TaskName 'EDR' -ErrorAction SilentlyContinue) { Stop-ScheduledTask -TaskName 'EDR' -ErrorAction SilentlyContinue; Disable-ScheduledTask -TaskName 'EDR' -ErrorAction SilentlyContinue | Out-Null }
        foreach ($ev in 'Local\EDR-Tray-Exit', 'Local\FreeEDR-Tray-Exit') { try { ([Threading.EventWaitHandle]::OpenExisting($ev)).Set() | Out-Null } catch { } }
        Start-Sleep -Seconds 2
        Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'EDR-(Engine|Tray|Scan)\.ps1' -and $_.ProcessId -ne $PID } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        Get-Process hayabusa, osv-scanner, yara64, velociraptor -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$OldRoot\*" } | Stop-Process -Force -ErrorAction SilentlyContinue
        # Every sub-folder (config, data incl. events/bans/state/backups, quarantine, bin, rules, ...); not the old top-level
        # scripts and docs, the new ones come from $Src. (robocopy /XF would also skip the scripts inside data\backup-*.)
        foreach ($d in Get-ChildItem $OldRoot -Directory) {
            $null = robocopy $d.FullName (Join-Path $Root $d.Name) /E /COPY:DAT /R:1 /W:1 /NFL /NDL /NJH /NJS /NP
            if ($LASTEXITCODE -ge 8) { throw "Copying $($d.FullName) failed (robocopy exit $LASTEXITCODE)" }
        }
        Ok "Data, settings, allow/block lists, quarantine and tools copied from $OldRoot"
        if (Test-Path $OldLocal) {
            $null = robocopy $OldLocal "$Root\user" /E /COPY:DAT /R:1 /W:1 /NFL /NDL /NJH /NJS /NP
            if ($LASTEXITCODE -ge 8) { throw "Copying $OldLocal failed (robocopy exit $LASTEXITCODE)" }
            Ok "Tray files (reviewed alerts, hidden apps, history) copied from $OldLocal"
        }
    }

    Step 'Installing project files'
    if ((Resolve-Path $Src).Path.TrimEnd('\') -ne $Root) {
        if (Test-Path "$Root\EDR-Engine.ps1") {
            $backup = "$Root\data\backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            New-Item -ItemType Directory -Path "$backup\config", "$backup\rules" -Force | Out-Null
            Copy-Item "$Root\*.ps1" $backup -Force
            Copy-Item "$Root\config\sysmonconfig.xml" "$backup\config\" -Force -ErrorAction SilentlyContinue
            Copy-Item "$Root\rules\*.yar" "$backup\rules\" -Force -ErrorAction SilentlyContinue
            Ok "Previous version backed up to $backup"
        }
        foreach ($f in $ProjectFiles) {
            New-Item -ItemType Directory -Path (Split-Path "$Root\$f") -Force | Out-Null
            Copy-Item "$Src\$f" "$Root\$f" -Force
        }
        Ok "$($ProjectFiles.Count) files copied from $Src"
    } else { Ok "Running from $Root itself - files already in place" }
    . "$Root\EDR-Common.ps1"
    foreach ($d in $ConfigDir, $DataDir, "$DataDir\legacy", $RulesDir, $BinDir, $ControlDir, $InboxDir, $UserDir) { New-Item -ItemType Directory -Path $d -Force | Out-Null }

    if ($legacy) {
        Step 'Stopping legacy Wail2Ban / LocalEDR'
        foreach ($t in $oldTasks) {
            if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
                Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
                Disable-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue | Out-Null
                Ok "Stopped + disabled '$t'"
            }
        }
        Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'LocalEDR\\(Watcher|UpdateAndScan)\.ps1|Wail2Ban\\wail2ban\.ps1' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        if (Test-Path "$OldEdr\bin") { robocopy "$OldEdr\bin" $BinDir /E /R:1 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null; Ok 'Legacy tools copied' }
        if ((Test-Path "$OldEdr\rules\ioc_sha256.txt") -and -not (Test-Path "$RulesDir\ioc_sha256.txt")) { Copy-Item "$OldEdr\rules\ioc_sha256.txt" $RulesDir }
        if ((Test-Path "$OldW2b\bannedIPLog.ini") -and -not (Test-Path $StrikesFile)) { Copy-Item "$OldW2b\bannedIPLog.ini" $StrikesFile; Ok 'Wail2Ban strike history imported' }
        foreach ($f in "$OldEdr\Detections.log", "$OldW2b\wail2ban_log.log") { if (Test-Path $f) { Copy-Item $f "$DataDir\legacy\" -Force } }
    }

    Step 'Tools (Sysmon, Hayabusa, YARA, OSV-Scanner, Velociraptor)'
    # Stop running tool processes so files can be replaced/removed
    Get-Process hayabusa, osv-scanner, yara64 -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$BinDir\*" } | Stop-Process -Force -ErrorAction SilentlyContinue
    foreach ($t in $Tools) { Install-Tool $t }
    # E9: remove download leftovers and the duplicate Hayabusa binary
    foreach ($z in Get-ChildItem "$BinDir\*.zip" -ErrorAction SilentlyContinue) { Remove-Item $z.FullName -Force; Ok "Removed leftover $($z.Name)" }
    foreach ($d in Get-ChildItem "$BinDir\hayabusa\hayabusa-*-win-x64.exe" -ErrorAction SilentlyContinue) {
        if ((Get-FileHash $d.FullName).Hash -eq (Get-FileHash "$BinDir\hayabusa\hayabusa.exe").Hash) { Remove-Item $d.FullName -Force; Ok "Removed duplicate $($d.Name)" }
    }
    $sysmonExe = "$env:SystemRoot\Sysmon64.exe"
    $sysmonSvc = Get-Service Sysmon64 -ErrorAction SilentlyContinue
    if (-not $sysmonSvc) {
        $zip = Join-Path $DlDir 'Sysmon.zip'; $x = Join-Path $DlDir 'x-sysmon'
        Get-Download 'https://download.sysinternals.com/files/Sysmon.zip' $zip
        Expand-Archive $zip $x -Force
        $sig = Get-AuthenticodeSignature "$x\Sysmon64.exe"
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft') { throw 'Sysmon64.exe signature is not a valid Microsoft signature' }
        $sysmonExe = "$x\Sysmon64.exe"
        Ok 'Sysmon downloaded (Microsoft signature verified)'
    } else { Ok "Sysmon installed ($((Get-Item "$env:SystemRoot\Sysmon64.exe").VersionInfo.FileVersion))" }

    Step 'Sysmon configuration'
    $rendered = (Get-Content "$ConfigDir\sysmonconfig.template.xml" -Raw).Replace('{ROOT}', $Root)   # user-independent: no profile path is written
    $prev = if (Test-Path $SysmonConfig) { Get-Content $SysmonConfig -Raw } else { $null }
    [IO.File]::WriteAllText($SysmonConfig, $rendered, (New-Object Text.UTF8Encoding($false)))
    $ErrorActionPreference = 'Continue'
    if (-not $sysmonSvc) { $out = & $sysmonExe -accepteula -i $SysmonConfig 2>&1 | Out-String } else { $out = & $sysmonExe -accepteula -c $SysmonConfig 2>&1 | Out-String }
    $sysmonExit = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($sysmonExit -eq 0) { Ok 'Sysmon config applied (include-only rules, games/anti-cheat excluded)' }
    else {
        Warn "Sysmon rejected the new config (exit $sysmonExit): $($out.Trim() -split "`n" | Select-Object -Last 3)"
        if ($prev) { [IO.File]::WriteAllText($SysmonConfig, $prev); $ErrorActionPreference = 'Continue'; & $sysmonExe -c $SysmonConfig 2>&1 | Out-Null; $ErrorActionPreference = 'Stop'; Warn 'Previous Sysmon config restored' }
    }
    $drv = Get-Service SysmonDrv -ErrorAction SilentlyContinue
    if ($drv -and $drv.Status -ne 'Running') { Warn "Sysmon driver is $($drv.Status) - restart the PC" }

    Step 'Settings, exclusions and history'
    $cfg = Get-EdrConfig
    # Older versions stored the installing user's profile path; the scan now finds every user's profile by itself
    if ($cfg.PSObject.Properties.Name -contains 'userProfile') { $cfg.PSObject.Properties.Remove('userProfile'); Ok 'Removed the stored user profile path (profiles are found automatically)' }
    if ($cfg.PSObject.Properties.Name -contains 'scanTime') { $cfg.PSObject.Properties.Remove('scanTime'); Ok 'Removed the obsolete scanTime setting (scanTimes is used)' }
    Write-JsonAtomic $ConfigFile $cfg
    Ok "edr-config.json (IOC feed: $($cfg.iocFeedUrl))"
    $x = Get-Exclusions
    # Game/anti-cheat/EDR folders now live in the Sysmon config; older whole-folder exclusions of them are removed
    $builtin = @('C:\Program Files\Epic Games\', 'C:\Program Files (x86)\Epic Games\', 'C:\ProgramData\Epic\', "$Root\", "$OldRoot\")
    $before = @($x.realtimePath).Count
    $x.realtimePath = @($x.realtimePath | Where-Object { $_ -and $builtin -notcontains $_.prefix -and [string]$_.prefix -notmatch '\\AppData\\Local\\(EpicGamesLauncher|FortniteGame)\\$' })
    # A version-pinned "all rules" OneDrive allow is replaced by the OneDrive profile below: it broke on every update.
    $n = @($x.realtime).Count
    $x.realtime = @($x.realtime | Where-Object { $_ -and -not ($_.rule -eq '*' -and $_.image -like 'C:\Program Files\Microsoft OneDrive\*\OneDrive*.exe' -and $_.image -notmatch '\*' -and (-not $_.parent -or $_.parent -eq $_.image)) })
    if ($n -ne @($x.realtime).Count) { Ok 'Replaced the version-pinned OneDrive allow with a Run-key-only allow' }
    # E15: "allow PowerShell itself, all rules" hid every PowerShell attack (credential theft, Defender tampering, ...); Allow Claude Code replaces it.
    # Any copy counts (also bundled ones such as Codex's under %USERPROFILE%\.cache, where any program running as the user can replace the file).
    $n = @($x.realtime).Count
    $x.realtime = @($x.realtime | Where-Object { $_ -and -not (($_.rule -eq '*' -or -not $_.rule) -and -not $_.parent -and -not $_.signer -and
                                                              (Split-Path ([string]$_.image) -Leaf) -match '^(pwsh|powershell|powershell_ise)\.exe$') })
    if ($n -ne @($x.realtime).Count) { Warn "Removed $($n - @($x.realtime).Count) allow(s) of PowerShell itself for all rules - use Overview > Allow Claude Code instead" }
    # Trusted-app profiles (README §3 "Trusted apps"): the recommended ones are switched on once, for the apps found on
    # this PC. After that only the user changes them (tray > Trusted apps), so a later upgrade never re-adds what they removed.
    # The older Run-key-only allows of OneDrive / Google Drive / Razer are covered by those profiles.
    $oldRunKey = @('C:\Program Files\Microsoft OneDrive\*\OneDrive*.exe', 'C:\Program Files\Google\Drive File Stream\*\GoogleDriveFS.exe', 'C:\Program Files\Razer\RazerAppEngine\*\RazerAppEngine.exe')
    if (-not $cfg.allowProfilesInitialized) {
        $x.realtime = @($x.realtime | Where-Object { $_ -and -not ($_.rule -eq 'Startup entry added or changed (Run key)' -and $oldRunKey -contains $_.image -and -not $_.profile) })
        foreach ($p in $AllowProfiles) {
            if (-not $p.default -or -not (Test-ProfileInstalled $p)) { continue }
            foreach ($op in Get-ProfileOps $p) {
                $list = $op.blade
                $entry = [ordered]@{ id = [guid]::NewGuid().ToString('N'); added = (Get-Date).ToString('yyyy-MM-dd HH:mm') }
                foreach ($k in $op.Keys) { if ($k -notin 'action', 'blade') { $entry[$k] = $op[$k] } }
                $x.$list = @($x.$list) + [pscustomobject]$entry
            }
            Ok "Trusted app: $($p.name)"
        }
        # Claude Code allows made with the older "Allow Claude Code" button belong to its profile now
        foreach ($e in @($x.realtime) + @($x.sigma)) {
            if ($e -and -not $e.profile -and $e.parent -like '*\claude.exe' -and $e.parentSigner -eq $ClaudeSigner) { $e | Add-Member -NotePropertyName profile -NotePropertyValue 'claude-code' -Force }
        }
        $cfg.allowProfilesInitialized = $true
        Write-JsonAtomic $ConfigFile $cfg
    } else { Ok 'Trusted-app profiles kept as you set them (tray > Trusted apps)' }
    if ($legacy -and -not @($x.wail2ban).Count -and (Test-Path "$OldW2b\wail2ban_config.ini")) {
        $section = ''
        foreach ($l in Get-Content "$OldW2b\wail2ban_config.ini") {
            if ($l -match '^\[(.+)\]$') { $section = $matches[1].Trim(); continue }
            if ($section -eq 'Whitelist' -and $l -match '^\s*([^#].+?)\s*=\s*(.*)') {
                $x.wail2ban = @($x.wail2ban) + [pscustomobject]@{ id = [guid]::NewGuid().ToString('N'); added = (Get-Date).ToString('yyyy-MM-dd HH:mm'); cidr = $matches[1].Trim(); note = $matches[2].Trim() }
            }
        }
    }
    Write-JsonAtomic $ExclFile $x
    Ok "exclusions.json ($($before - @($x.realtimePath).Count) old path exclusions moved into the Sysmon config / removed)"
    if ($legacy -and -not (Test-Path $EventsFile) -and (Test-Path "$OldEdr\Detections.log")) {
        $lines = @()
        foreach ($l in Get-Content "$OldEdr\Detections.log" -Encoding UTF8) {
            $e = $null
            if ($l -match '^\[([^\]]+)\] \[REALTIME ALERT\] (.*?) \| Process: (.*?) \| Detail: (.*?) \| SHA256: (.*)$') {
                $e = [ordered]@{ time = $matches[1]; blade = 'realtime'; severity = 'Medium'; title = $matches[2]; process = $matches[3]; detail = $matches[4].Trim(); rule = $matches[2]; sha256 = $matches[5] }
            } elseif ($l -match '^\[([^\]]+)\] \[VULNERABILITY CVE\] ID: (\S+) \| Package: (.+?) \(([^)]*)\)$') {
                $e = [ordered]@{ time = $matches[1]; blade = 'cve'; severity = 'Medium'; title = "$($matches[2]) in $($matches[3]) $($matches[4])"; process = $matches[3]; detail = ''; cve = $matches[2]; vulnId = $matches[2]; package = $matches[3]; version = $matches[4] }
            } elseif ($l -match '^\[([^\]]+)\] \[STATUS\] (.*)$') {
                $e = [ordered]@{ time = $matches[1]; blade = 'system'; severity = 'Info'; title = $matches[2]; process = ''; detail = 'Imported from the old LocalEDR log'; kind = 'status' }
            }
            if ($e) { $e.id = [guid]::NewGuid().ToString('N'); $e.legacy = $true; $lines += ([pscustomobject]$e | ConvertTo-Json -Compress) }
        }
        if ($lines.Count) { [IO.File]::WriteAllText($EventsFile, (($lines -join "`n") + "`n"), $Utf8NoBom) }
        Ok "$($lines.Count) legacy detections imported (marked reviewed)"
    }
    if (-not [Diagnostics.EventLog]::SourceExists('wail2ban')) { New-EventLog -LogName Application -Source wail2ban }

    Step "Locking down $Root permissions"
    $null = icacls $Root /setowner '*S-1-5-32-544' /T /C /Q
    $null = icacls $Root /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' "*${userSid}:(OI)(CI)RX"
    if ($LASTEXITCODE -ne 0) { throw "icacls on $Root failed" }
    $null = icacls "$Root\*" /reset /T /C /Q
    # W to create a request, D so the tray can rename its .tmp to .json (a rename needs delete access on the file)
    $null = icacls $InboxDir /grant "*${userSid}:(OI)(CI)(W,D)"
    $null = icacls $UserDir /grant "*${userSid}:(OI)(CI)M"
    # The reset above made quarantine\ inherit your read access again: quarantined files stay SYSTEM + Administrators only
    if (Test-Path $QuarantineDir) { $null = icacls $QuarantineDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' }
    Ok 'Admins + SYSTEM: full | you (unelevated): read-only | inbox\: you may drop resume/scan requests | user\: your tray files | quarantine\: admins only | everyone else: no access'

    $enforce = ($cfg.enforce -eq $true)
    Step "Microsoft Defender: ASR rules, Controlled folder access, game allow-list ($(if ($enforce) { 'block mode' } else { 'detect-only: audit mode' }))"
    # Detect-only (config enforce = false, the default): Defender only reports what these rules would block, so they never
    # interrupt work; FreeEDR lists those reports. Defender's own antivirus is not changed.
    $asrMode = if ($enforce) { 'Enabled' } else { 'AuditMode' }
    $asrBlock = @('56a863a9-875e-4185-98a7-b882c64b5ce5', '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c', 'd4f940ab-401b-4efc-aadc-ad5f3c50688a',
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550', '5beb7efe-fd9a-4556-801d-275e5ffc04cc',
        'd3e037e1-3eb8-44c8-a917-57927947596d', '3b576869-a4ec-4529-8536-b80a7769e899', '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84',
        '26190899-1602-49e8-8b27-eb1d0a1ce869', 'e6db77e5-3df2-4cf1-b95a-636979351e5b', 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4',
        '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b', 'c1db55ab-c21a-4637-bb3f-a12568109d35')
    $asrAudit = @('01443614-cd74-433a-b99e-2ecdc07bfc25', 'd1e49aac-8f56-4280-b9ba-993a6d77406c')   # too disruptive for dev work to block
    try {
        foreach ($id in $asrBlock) { Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions $asrMode -ErrorAction Stop }
        foreach ($id in $asrAudit) { Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions AuditMode -ErrorAction Stop }
        if ($enforce) { Ok "$($asrBlock.Count) ASR rules blocking, $($asrAudit.Count) audit-only" } else { Ok "$($asrBlock.Count + $asrAudit.Count) ASR rules in audit mode (reported, never blocked)" }
    } catch { Warn "ASR rules: $($_.Exception.Message)" }
    try {
        if ($enforce) { Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction Stop; Ok 'Controlled folder access ON' }
        else { Set-MpPreference -EnableControlledFolderAccess AuditMode -ErrorAction Stop; Ok 'Controlled folder access in audit mode (reported, never blocked)' }
    } catch { Warn "Controlled folder access: $($_.Exception.Message)" }
    $gameExes = @(Get-ChildItem 'C:\Program Files\Epic Games\*\*\Binaries\Win64\*.exe', 'C:\Program Files (x86)\Epic Games\Launcher\Portal\Binaries\Win64\*.exe', 'C:\Program Files (x86)\EasyAntiCheat_EOS\*.exe' -ErrorAction SilentlyContinue)
    foreach ($g in $gameExes) { try { Add-MpPreference -ControlledFolderAccessAllowedApplications $g.FullName -ErrorAction Stop } catch { } }
    Ok "$($gameExes.Count) Epic/Fortnite/Easy Anti-Cheat programs allowed through Controlled folder access"
    # Remote Desktop shadowing (watching/controlling another session) is not used here, and its rule allowed any address
    try {
        $shadow = @(Get-NetFirewallRule -Name 'RemoteDesktop-Shadow-In-TCP' -ErrorAction Stop | Where-Object { $_.Enabled -eq 'True' })
        if ($shadow.Count) { $shadow | Disable-NetFirewallRule -ErrorAction Stop; Ok 'Firewall: "Remote Desktop - Shadow (TCP-In)" disabled' } else { Ok 'Firewall: Remote Desktop shadowing already closed' }
    } catch { Warn "Remote Desktop shadow firewall rule: $($_.Exception.Message)" }

    Step "Scheduled task `"$TaskName`" (SYSTEM, at boot + 5-minute watchdog)"
    $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>FreeEDR engine: Wail2Ban + Sysmon real-time detection + YARA/IOC + twice-daily Sigma/CVE scan + user block/quarantine + health. Tray: $Root\EDR-Tray.ps1. Docs: $Root\README.md</Description></RegistrationInfo>
  <Triggers>
    <BootTrigger><Enabled>true</Enabled></BootTrigger>
    <TimeTrigger><Repetition><Interval>PT5M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>2026-01-01T00:00:00</StartBoundary><Enabled>true</Enabled></TimeTrigger>
  </Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>5</Priority>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "$Root\EDR-Engine.ps1"</Arguments>
      <WorkingDirectory>$Root</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@
    Register-ScheduledTask -TaskName $TaskName -Xml $xml -Force | Out-Null
    Ok "Task '$TaskName' registered"

    Step 'Tray auto-start and Start menu shortcut'
    $trayCmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$Root\EDR-Tray.ps1`""
    Set-ItemProperty -Path $runKey -Name 'FreeEDR Tray' -Value $trayCmd
    $lnk = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\FreeEDR.lnk"
    $sc = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
    $sc.TargetPath = 'powershell.exe'
    $sc.Arguments = "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$Root\EDR-Tray.ps1`" -Show"
    $sc.WindowStyle = 7
    $sc.IconLocation = "$env:SystemRoot\System32\imageres.dll,73"
    $sc.Description = 'FreeEDR dashboard'
    $sc.Save()
    # Close the running tray so the new version starts (new trays listen for this signal; older ones are stopped)
    foreach ($ev in 'Local\FreeEDR-Tray-Exit', 'Local\EDR-Tray-Exit') { try { ([Threading.EventWaitHandle]::OpenExisting($ev)).Set() | Out-Null; Start-Sleep -Seconds 2 } catch { } }
    Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'EDR-Tray\.ps1' -and $_.ProcessId -ne $PID } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Ok 'Tray starts at sign-in; "FreeEDR" is in the Start menu'

    Step 'Starting the engine and verifying'
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'EDR-Engine\.ps1' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 2
    $stamp = Get-Date
    Start-ScheduledTask -TaskName $TaskName
    $st = $null
    for ($i = 0; $i -lt 45; $i++) {
        Start-Sleep -Seconds 2
        $st = Read-Json $StatusFile $null
        if ($st -and [datetime]$st.engineStarted -ge $stamp.AddSeconds(-5) -and ((Get-Date) - [datetime]$st.heartbeat).TotalSeconds -lt 30) { break }
        $st = $null
    }
    $checks = [ordered]@{
        'Engine running (fresh heartbeat)' = [bool]$st
        'Wail2Ban watching failed logons'  = [bool]($st -and $st.wail2ban.state -ne 'error')
        'EDR watching Sysmon'              = [bool]($st -and $st.edr.state -ne 'error')
        'YARA rules compiled'              = [bool]($st -and @($st.edr.yaraRules).Count -ge 2)
        'All tools present'                = -not @($Tools | Where-Object { -not (Test-Path "$BinDir\$($_.Exe)") }).Count
    }
    foreach ($k in $checks.Keys) { if ($checks[$k]) { Ok $k } else { Warn "$k - FAILED" } }
    $verified = $checks['Engine running (fresh heartbeat)'] -and $checks['Wail2Ban watching failed logons'] -and $checks['All tools present']

    if ($verified) {
        if ($moveOld) {
            Step "Removing the previous install ($OldRoot)"
            if (Get-ScheduledTask -TaskName 'EDR' -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName 'EDR' -Confirm:$false; Ok "Deleted task 'EDR'" }
            Remove-ItemProperty -Path $runKey -Name 'EDR Tray' -ErrorAction SilentlyContinue
            if (Test-Path $oldLnk) { Remove-Item $oldLnk -Force }
            Ok 'Removed the old tray auto-start and the "EDR Security" Start-menu entry'
            foreach ($d in $OldRoot, $OldLocal) {
                if (-not (Test-Path $d)) { continue }
                try { Remove-Item $d -Recurse -Force -ErrorAction Stop; Ok "Deleted $d" } catch { Warn "Could not delete all of $d ($($_.Exception.Message)) - delete it after a restart" }
            }
        }
        if ($legacy) {
            Step 'Removing the legacy setup'
            foreach ($t in $oldTasks) { if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $t -Confirm:$false; Ok "Deleted task '$t'" } }
            foreach ($d in $OldEdr, $OldW2b) { if (Test-Path $d) { Remove-Item $d -Recurse -Force; Ok "Deleted $d" } }
        }
        $result = 'SUCCESS'
    } elseif ($backup) {
        Step 'Verification failed - rolling back to the previous version'
        Copy-Item "$backup\*.ps1" $Root -Force
        Copy-Item "$backup\rules\*.yar" $RulesDir -Force -ErrorAction SilentlyContinue
        if (Test-Path "$backup\config\sysmonconfig.xml") { Copy-Item "$backup\config\sysmonconfig.xml" $SysmonConfig -Force; $ErrorActionPreference = 'Continue'; & "$env:SystemRoot\Sysmon64.exe" -c $SysmonConfig 2>&1 | Out-Null; $ErrorActionPreference = 'Stop' }
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue; Start-ScheduledTask -TaskName $TaskName
        $result = 'ROLLED BACK'
    } elseif ($moveOld) {
        Step "Verification failed - starting the previous install in $OldRoot again"
        Disable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $runKey -Name 'FreeEDR Tray' -ErrorAction SilentlyContinue
        Enable-ScheduledTask -TaskName 'EDR' -ErrorAction SilentlyContinue | Out-Null; Start-ScheduledTask -TaskName 'EDR' -ErrorAction SilentlyContinue
        $lnk = $oldLnk
        $result = 'ROLLED BACK'
    } elseif ($legacy) {
        Step 'Verification failed - re-enabling the legacy setup'
        Disable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null
        foreach ($t in $oldTasks) { if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) { Enable-ScheduledTask -TaskName $t | Out-Null; Start-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue } }
        $result = 'ROLLED BACK'
    }

    Step 'Starting the tray'
    Start-Process explorer.exe "`"$lnk`""
    Ok 'Tray started (unelevated)'
} catch {
    Write-Host "`nERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace
    if ($legacy) { foreach ($t in $oldTasks) { if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) { Enable-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue | Out-Null; Start-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue } } }
    if ($backup) { Copy-Item "$backup\*.ps1" $Root -Force -ErrorAction SilentlyContinue; Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue }
    elseif ($moveOld -and (Get-ScheduledTask -TaskName 'EDR' -ErrorAction SilentlyContinue)) {
        # The move failed half-way: the old install in C:\EDR is untouched, so run it again
        Enable-ScheduledTask -TaskName 'EDR' -ErrorAction SilentlyContinue | Out-Null; Start-ScheduledTask -TaskName 'EDR' -ErrorAction SilentlyContinue
        if (Test-Path $oldLnk) { Start-Process explorer.exe "`"$oldLnk`"" }
    }
    $result = 'FAILED (previous state restored where possible)'
} finally {
    Write-Host "`nINSTALL RESULT: $result" -ForegroundColor $(if ($result -eq 'SUCCESS') { 'Green' } else { 'Red' })
    Stop-Transcript | Out-Null
    Remove-Item $DlDir -Recurse -Force -ErrorAction SilentlyContinue
    if ([Environment]::UserInteractive -and -not $env:EDR_NO_PAUSE -and -not $NoPause) { Read-Host 'Press Enter to close' }
}
# Exit code for FreeEDR-Setup.exe and scripts: 0 = SUCCESS, 3 = ROLLED BACK, 1 = FAILED
exit $(if ($result -eq 'SUCCESS') { 0 } elseif ($result -like 'ROLLED BACK*') { 3 } else { 1 })
