# Live: health and configuration of the FreeEDR installed on this PC (read-only; skipped with -SkipLive or when not installed).
# These describe the INSTALLED version: after a code change they only reflect it once FreeEDR-Setup.exe was run.
param([string]$Repo, [switch]$Live, [switch]$Attack, [switch]$Elevated, [string]$Work)

$Root = Join-Path $(if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }) 'FreeEDR'
$installed = Test-Path "$Root\data\status.json"
$csharp = Test-Path "$Root\bin\FreeEDR-Engine.exe"
function Need-Install { if (-not $Live) { Skip 'live checks off (-SkipLive)' }; if (-not $installed) { Skip "FreeEDR is not installed ($Root)" } }
function Need-CSharp { Need-Install; if (-not $csharp) { Known 'the installed FreeEDR is the PowerShell version - run compiled\FreeEDR-Setup.exe (with the owner''s approval) to test the C# version live' } }
function Read-Status { Read-Text "$Root\data\status.json" | ConvertFrom-Json }

Test 'Installed programs match the latest build (otherwise live results describe an older version)' {
    Need-CSharp
    $pub = Join-Path $Repo 'obj\EdrBuild\publish'
    if (-not (Test-Path $pub)) { Skip 'no build output yet (run dev_build.cmd)' }
    $diff = @(foreach ($p in @(@('Edr.Engine', 'FreeEDR-Engine.exe', ''), @('Edr.Control', 'FreeEDR-Control.exe', ''), @('Edr.Setup', 'FreeEDR-Installer.exe', ''), @('Edr.Tray', 'FreeEDR-Tray.exe', 'tray'))) {
        $built = Join-Path $pub "$($p[0])\$($p[1])"
        $inst = Join-Path $Root "bin\$($p[2])\$($p[1])"
        if (-not (Test-Path $built)) { continue }
        if (-not (Test-Path $inst) -or (Get-FileHash $built).Hash -ne (Get-FileHash $inst).Hash) { $p[1] }
    })
    if ($diff.Count) { Known "not installed yet: $($diff -join ', ') - run compiled\FreeEDR-Setup.exe (with the owner's approval) to test them live" }
}

Test 'Engine service "FreeEDR" is running' {
    Need-CSharp
    $s = Get-Service FreeEDR -ErrorAction SilentlyContinue
    Assert-True $s 'service FreeEDR is missing'
    Assert-Equal 'Running' "$($s.Status)" 'service state'
}

Test 'Engine service keeps only the privileges it needs (least privilege)' {
    Need-CSharp
    $out = @(& sc.exe qprivs FreeEDR 2>&1) -join "`n"
    if ($out -notmatch 'SeChangeNotifyPrivilege') { Known 'the installed version does not restrict the engine''s privileges yet - run compiled\FreeEDR-Setup.exe (with the owner''s approval)' }
    foreach ($bad in 'SeDebugPrivilege', 'SeTcbPrivilege', 'SeLoadDriverPrivilege', 'SeTakeOwnershipPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege') {
        Assert-True ($out -notmatch $bad) "the engine keeps $bad"
    }
}

Test 'Engine pipe and event archive are working' {
    Need-CSharp
    $st = Read-Status
    if ($null -eq $st.pipe -or $null -eq $st.archive) { Known 'the installed version has no pipe / event archive yet - run compiled\FreeEDR-Setup.exe (with the owner''s approval)' }
    Assert-True (-not $st.pipe.error) "pipe: $($st.pipe.error)"
    Assert-True ([int]$st.archive.logs -gt 0) "event archive copies no log ($($st.archive.error))"
    Assert-True (-not $st.archive.error) "event archive: $($st.archive.error)"
}

Test 'Engine heartbeat is fresh (under 60 s)' {
    Need-Install
    $st = Read-Status
    $age = ((Get-Date) - [datetime]$st.heartbeat).TotalSeconds
    Assert-True ($age -lt 60) "heartbeat is $([int]$age) s old - engine down? see $Root\data\engine.log"
}

Test 'Detect-only and Wail2Ban mode are reported' {
    Need-CSharp
    $st = Read-Status
    Assert-Equal 'detect-only' $st.mode 'status.mode'
    Assert-True ($null -ne $st.wail2ban.block) 'status.wail2ban.block missing'
}

Test 'Sensors healthy: Sysmon service + driver running, Wail2Ban and EDR not in error' {
    Need-Install
    $st = Read-Status
    Assert-True ($st.sysmon.ok) "Sysmon: $($st.sysmon.message)"
    Assert-True ($st.wail2ban.state -ne 'error') 'Wail2Ban in error'
    Assert-True ($st.edr.state -ne 'error') 'EDR in error'
    Assert-True (@($st.edr.yaraRules).Count -ge 2) "YARA rules compiled: $(@($st.edr.yaraRules) -join ', ')"
}

Test 'No engine errors in the last hour' {
    Need-Install
    $log = "$Root\data\engine.log"
    if (-not (Test-Path $log)) { Skip 'no engine.log' }
    $since = (Get-Date).AddHours(-1)
    $err = @(Get-Content $log -Tail 3000 | Where-Object { $_ -match '^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) \[E\] ' -and [datetime]$matches[1] -ge $since })
    if ($err.Count) { Known "$($err.Count) error lines, last: $($err[-1])" }
}

Test 'Last scan had no failed steps' {
    Need-Install
    $f = "$Root\data\scan-result.json"
    if (-not (Test-Path $f)) { Skip 'no scan result yet' }
    $sr = Read-Text $f | ConvertFrom-Json
    $bad = @($sr.steps | Where-Object { $_ -and $_.ok -eq $false } | ForEach-Object { "$($_.name): $($_.message)" })
    if ($bad.Count) { Known "failed steps: $($bad -join ' | ')" }
}

Test 'Folder permissions: no write access for Users / Everyone / Authenticated Users on the folder or its programs' {
    Need-Install
    $weak = 'S-1-5-32-545', 'S-1-1-0', 'S-1-5-11'
    # Rights that let an account change files (ReadAndExecute / Synchronize are fine: every account may run the tray)
    $write = [Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData -bor
             [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
             [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
             [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    $targets = @($Root) + @(Get-ChildItem "$Root\bin", "$Root\config", "$Root\rules", "$Root\control" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }) +
               @(Get-ChildItem "$Root\bin" -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    foreach ($p in $targets | Select-Object -Unique) {
        # control\ holds short-lived command files the engine consumes: skip one that disappears between listing and reading
        $acl = try { Get-Acl -LiteralPath $p -ErrorAction Stop } catch [System.Management.Automation.ItemNotFoundException] { $null }
        if (-not $acl) { continue }
        foreach ($a in $acl.Access) {
            $sid = try { $a.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { '' }
            if ("$($a.AccessControlType)" -eq 'Allow' -and $weak -contains $sid -and ([int]$a.FileSystemRights -band [int]$write)) { throw "$p grants $($a.IdentityReference) $($a.FileSystemRights)" }
        }
    }
}

Test 'Folder owner is Administrators' {
    Need-Install
    Assert-Equal 'S-1-5-32-544' ((Get-Acl -LiteralPath $Root).GetOwner([Security.Principal.SecurityIdentifier]).Value) 'owner of the install folder'
}

Test 'Tray start and shortcuts point at the admin-only install folder' {
    Need-CSharp
    $run = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue).'FreeEDR Tray'
    Assert-True $run 'no HKLM Run value'
    Assert-Match $run ([regex]::Escape("$Root\bin\tray\FreeEDR-Tray.exe")) 'HKLM Run value'
}

Test 'Tray is running for this account' {
    Need-CSharp
    $mine = @(Get-Process FreeEDR-Tray -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq [Diagnostics.Process]::GetCurrentProcess().SessionId })
    if (-not $mine.Count) { Known 'no tray in this session (hidden by the user, or not started yet)' }
}

Test 'Listed in Settings > Apps with a version' {
    Need-Install
    $k = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{6F0E2C1A-4B7D-4E59-9A33-0E2D5C8B7A41}_is1' -ErrorAction SilentlyContinue
    if (-not $k) { Known 'no Settings > Apps entry yet (installed by script)' }
    Assert-True $k.DisplayVersion 'no DisplayVersion'
}

Test 'Noise check: no alert repeats more than 50 times in 7 days (possible false positive)' {
    Need-Install
    $ev = "$Root\data\events.jsonl"
    if (-not (Test-Path $ev)) { Skip 'no events' }
    $since = (Get-Date).AddDays(-7)
    $groups = @(Get-Content $ev -Tail 20000 | ForEach-Object { try { $_ | ConvertFrom-Json } catch { } } |
        Where-Object { $_ -and $_.blade -in 'realtime', 'sigma' -and $_.time -and [datetime]$_.time -ge $since } |
        Group-Object { "$($_.title) | $(Split-Path ([string]$_.process) -Leaf)" } | Where-Object { $_.Count -gt 50 } | Sort-Object Count -Descending)
    if ($groups.Count) { Known ("noisy: " + (($groups | Select-Object -First 5 | ForEach-Object { "$($_.Name) (x$($_.Count))" }) -join '; ') + ' - review: add a narrow allow or a corpus sample') }
}
