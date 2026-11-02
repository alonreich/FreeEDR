# EDR-Engine.ps1 - FreeEDR's single background engine, run as SYSTEM by the "FreeEDR" scheduled task.
#   * Wail2Ban : bans IPs after repeated failed logons (Security 4625 + RDP 140)
#   * Real-time: Sysmon detections (+ IOC hash and YARA enrichment)
#   * Defender : surfaces Defender / ASR / Controlled Folder Access blocks
#   * Scanner  : Sigma/CVE/feed scan twice a day (config scanTimes) with catch-up if the PC was off
#   * Blocking : user verdicts from the dashboard - stop/quarantine programs, permanent IP blocks
#   * Health   : heartbeat + Sysmon self-check, written to data\status.json for the tray
# Commands arrive as JSON files in control\ (admin-only) and inbox\ (user, safe verbs only).

$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\EDR-Common.ps1"

# Defined before the single-instance check, which logs through it
function Write-EngineLog([string]$Level, [string]$Text) {
    # W2/W3: every level goes to the file; the file is trimmed instead of growing forever
    try {
        if ((Test-Path $EngineLog) -and ((Get-Item $EngineLog).Length -gt 5MB)) {
            $keep = Get-Content $EngineLog -Tail 10000
            [IO.File]::WriteAllLines($EngineLog, [string[]]$keep, $Utf8NoBom)
        }
    } catch { }
    Add-TextLine $EngineLog ("{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Text)
}

$mutex = $null
$created = $false
try {
    $mSec = New-Object System.Security.AccessControl.MutexSecurity
    $mSec.AddAccessRule((New-Object System.Security.AccessControl.MutexAccessRule(
        (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')),
        [System.Security.AccessControl.MutexRights]::FullControl,
        [System.Security.AccessControl.AccessControlType]::Allow)))
    $mSec.AddAccessRule((New-Object System.Security.AccessControl.MutexAccessRule(
        (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')),
        [System.Security.AccessControl.MutexRights]::FullControl,
        [System.Security.AccessControl.AccessControlType]::Allow)))
    $mutex = New-Object Threading.Mutex($true, $EngineMutex, [ref]$created, $mSec)
} catch {
    Write-EngineLog E "Failed to acquire secure mutex '$EngineMutex': $($_.Exception.Message)"
}

if (-not $created) {
    $otherEngine = @(Get-CimInstance Win32_Process -Filter "ProcessId != $PID" -ErrorAction SilentlyContinue | Where-Object {
        $_.CommandLine -match 'EDR-Engine\.ps1'
    })
    if ($otherEngine.Count -gt 0) {
        exit 0
    }
    Write-EngineLog W "Mutex '$EngineMutex' was squatted or unowned without an active engine process; continuing execution."
}

foreach ($d in $DataDir, $ControlDir, $InboxDir) { if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null } }

################################################################################
# Events

function New-EdrEvent {
    param([string]$Blade, [string]$Severity, [string]$Title, [string]$Process = '', [string]$Detail = '', [hashtable]$Extra = @{})
    $e = [ordered]@{
        id       = [guid]::NewGuid().ToString('N')
        time     = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        blade    = $Blade
        severity = $Severity
        title    = $Title
        process  = $Process
        detail   = $Detail
    }
    foreach ($k in $Extra.Keys) { $e[$k] = $Extra[$k] }
    try {
        if ((Test-Path $EventsFile) -and ((Get-Item $EventsFile).Length -gt 20MB)) {
            Move-Item $EventsFile ("$DataDir\events-{0}.jsonl" -f (Get-Date -Format 'yyyyMMdd-HHmmss')) -Force
            $archives = @(Get-ChildItem -Path "$DataDir\events-*.jsonl" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime)
            if ($archives.Count -gt 5) {
                $archives | Select-Object -First ($archives.Count - 5) | Remove-Item -Force -ErrorAction SilentlyContinue
            }
        }
    } catch { }
    Add-TextLine $EventsFile (([pscustomobject]$e) | ConvertTo-Json -Compress -Depth 5)
}

function Write-AppEventLog([string]$Text, [int]$Id, [string]$Type = 'Information') {
    try { [Diagnostics.EventLog]::WriteEntry('wail2ban', $Text, [Diagnostics.EventLogEntryType]$Type, $Id) } catch { }
}

################################################################################
# Config / state / exclusions

$script:Cfg   = Get-EdrConfig
# Detect-only (config enforce = false, the default): nothing is stopped, quarantined or firewall-blocked.
# Wail2Ban reports password guessing instead of banning, and Block verdicts only flag the item as a threat.
function Test-Enforcing { return ($script:Cfg.enforce -eq $true) }
$script:Excl  = Get-Exclusions
$script:ExclStamp = if (Test-Path $ExclFile) { (Get-Item $ExclFile).LastWriteTimeUtc } else { [datetime]::MinValue }

$script:State = Read-Json $StateFile $null
if (-not $script:State) { $script:State = [pscustomobject]@{} }
foreach ($p in 'edrPausedUntil', 'realtimePausedUntil', 'malwarePausedUntil', 'sigmaPausedUntil', 'cvePausedUntil', 'wail2banPausedUntil', 'lastScanStart', 'lastScanEnd', 'lastScanOk', 'lastScanSummary', 'lastToolCheck') {
    if (-not ($script:State.PSObject.Properties.Name -contains $p)) { $script:State | Add-Member -NotePropertyName $p -NotePropertyValue $null }
}
foreach ($p in 'sigmaSeen', 'cveSeen', 'toolSeen', 'defSeen') {
    if (-not ($script:State.PSObject.Properties.Name -contains $p)) { $script:State | Add-Member -NotePropertyName $p -NotePropertyValue @() }
}
function Save-State { Write-JsonAtomic $StateFile $script:State }
function Save-Exclusions {
    Write-JsonAtomic $ExclFile $script:Excl
    $script:ExclStamp = (Get-Item $ExclFile).LastWriteTimeUtc
}

function Test-Paused([string]$Blade) {
    # Master EDR pause pauses all detection blades
    if ($Blade -in @('realtime', 'malware', 'ioc', 'yara', 'sigma', 'cve')) {
        if ($script:State.edrPausedUntil) {
            if ([datetime]$script:State.edrPausedUntil -gt (Get-Date)) { return $true }
            $script:State.edrPausedUntil = $null; Save-State
            Write-EngineLog A "Master EDR pause expired - resumed automatically"
            New-EdrEvent system Info "$($BladeNames['edr']) resumed automatically" -Detail 'The timed pause ended.' -Extra @{ kind = 'status' }
        }
    }
    $prop = "${Blade}PausedUntil"
    $u = $script:State.$prop
    if (-not $u) { return $false }
    if ([datetime]$u -gt (Get-Date)) { return $true }
    $script:State.$prop = $null; Save-State
    $bName = if ($BladeNames.ContainsKey($Blade)) { $BladeNames[$Blade] } else { $Blade }
    Write-EngineLog A "$Blade pause expired - resumed automatically"
    New-EdrEvent system Info "$bName resumed automatically" -Detail 'The timed pause ended.' -Extra @{ kind = 'status' }
    return $false
}

################################################################################
# Wail2Ban

$script:Attempts  = New-Object System.Collections.ArrayList
$script:Strikes   = @{}   # ip -> @{ Count; Epoch }
$script:SelfIps   = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

function Get-Epoch { [double]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000) }

function Update-SelfIps {
    $script:SelfIps.Clear()
    try {
        foreach ($a in Get-NetIPAddress -ErrorAction Stop) {
            $n = ConvertTo-NormalIp $a.IPAddress
            if ($n) { [void]$script:SelfIps.Add($n) }
        }
    } catch { Write-EngineLog W "Could not read local IPs: $_" }
}

function Read-Strikes {
    if (-not (Test-Path $StrikesFile)) { return }
    foreach ($line in Get-Content $StrikesFile) {
        $p = $line.Trim().Split(' ')
        if ($p.Length -ge 2 -and $p[0]) {
            $epoch = if ($p.Length -ge 3) { [double]::Parse($p[2], [Globalization.CultureInfo]::InvariantCulture) } else { Get-Epoch }
            $script:Strikes[$p[0]] = @{ Count = [int]$p[1]; Epoch = $epoch }
        }
    }
}

function Save-Strikes {
    $lines = foreach ($k in $script:Strikes.Keys) {
        "{0} {1} {2}" -f $k, $script:Strikes[$k].Count, $script:Strikes[$k].Epoch.ToString([Globalization.CultureInfo]::InvariantCulture)
    }
    [IO.File]::WriteAllLines($StrikesFile, [string[]]@($lines), $Utf8NoBom)
}

# Escalating ban: 5^strike minutes. One strike decays per clean 24h. Capped lower for private IPs (W7).
function Get-BanDuration([string]$Ip) {
    $now = Get-Epoch
    $count = 0
    if ($script:Strikes.ContainsKey($Ip)) {
        $count = $script:Strikes[$Ip].Count
        $decay = [math]::Floor(($now - $script:Strikes[$Ip].Epoch) / 86400)
        if ($decay -gt 0) { $count = [math]::Max(0, $count - [int]$decay) }
    }
    $count++
    $script:Strikes[$Ip] = @{ Count = $count; Epoch = $now }
    Save-Strikes
    $cap = if (Test-PrivateIp $Ip) { $script:Cfg.wail2ban.maxBanPrivateSec } else { $script:Cfg.wail2ban.maxBanPublicSec }
    return @{ Seconds = [math]::Min([math]::Pow(5, $count) * 60, $cap); Strike = $count }
}

function Test-Whitelisted([string]$Ip) {
    foreach ($w in $script:Excl.wail2ban) { if (Test-IpInCidr $Ip $w.cidr) { return $w.cidr } }
    return $null
}

function Get-BanRules {
    $fw = New-Object -ComObject HNetCfg.FwPolicy2
    @($fw.Rules | Where-Object { $_.Name -like "$FwRulePrefix *" })
}

function Test-BanRule([string]$Ip) {
    $name = "$FwRulePrefix $Ip"
    return [bool](@(Get-BanRules | Where-Object { $_.Name -eq $name }).Count)
}

function Remove-BanRule([string]$Ip) {
    $fw = New-Object -ComObject HNetCfg.FwPolicy2
    $name = "$FwRulePrefix $Ip"
    $removed = $false
    for ($i = 0; $i -lt 10; $i++) {
        if (-not @($fw.Rules | Where-Object { $_.Name -eq $name }).Count) { break }
        $fw.Rules.Remove($name); $removed = $true
    }
    return $removed
}

function New-BanRule([string]$Ip, [string]$ExpireText) {
    $r = New-Object -ComObject HNetCfg.FWRule
    $r.Name            = "$FwRulePrefix $Ip"
    $r.Description     = "Expire: $ExpireText"
    $r.Grouping        = 'EDR Wail2Ban'
    $r.Protocol        = 256
    $r.RemoteAddresses = $Ip
    $r.Direction       = 1
    $r.Action          = 0
    $r.Profiles        = 0x7FFFFFFF
    $r.Enabled         = $true
    (New-Object -ComObject HNetCfg.FwPolicy2).Rules.Add($r)
}

function Invoke-Ban([string]$Ip, [int]$Count) {
    $why = Test-Whitelisted $Ip
    if ($why) { Write-EngineLog W "$Ip reached $Count failed logons but is whitelisted ($why)"; return }
    if (Test-BanRule $Ip) { Write-EngineLog W "$Ip already blocked"; return }
    $ban = Get-BanDuration $Ip
    $expire = (Get-Date).AddSeconds($ban.Seconds)
    $expireText = $expire.ToString('yyyy-MM-dd HH:mm:ss')
    try {
        New-BanRule $Ip $expireText
        $msg = "Blocked $Ip until $expireText ($Count failed logons, strike $($ban.Strike))"
        Write-EngineLog A $msg
        Write-AppEventLog $msg 1000
        $scope = if (Test-PrivateIp $Ip) { 'private/LAN address' } else { 'public internet address' }
        New-EdrEvent wail2ban Medium "Blocked $Ip after $Count failed logons" -Detail "Blocked for $(Format-Duration $ban.Seconds) (strike $($ban.Strike)), until $expireText. Source is a $scope." -Extra @{ ip = $Ip; expires = $expireText; strike = $ban.Strike }
    } catch {
        $msg = "Could not add firewall block for $Ip : $_"
        Write-EngineLog E $msg
        Write-AppEventLog $msg 1001 'Error'
        New-EdrEvent wail2ban High "Failed to block $Ip" -Detail $msg -Extra @{ ip = $Ip }
    }
}

# $Replay: failures read back from the log at engine start. They were already reported before the restart, so they
# only refill the 30-minute counter (no new events), and failures older than the IP's last ban/report are skipped.
function Add-LogonFailure([string]$RawIp, [string]$Source, [datetime]$When, [switch]$Replay) {
    if (Test-Paused 'wail2ban') { return }
    $ip = ConvertTo-NormalIp $RawIp
    if (-not $ip -or $ip -in @('0.0.0.0', '255.255.255.255', '::')) { return }
    if ($script:SelfIps.Contains($ip)) { return }   # W1: exact match, not a regex
    if ($Replay -and $script:Strikes.ContainsKey($ip)) {
        $last = [DateTimeOffset]::FromUnixTimeMilliseconds([long]($script:Strikes[$ip].Epoch * 1000)).LocalDateTime
        if ($When -le $last) { return }
    }
    # One RDP failure can be logged by both 4625 and RdpCoreTS 140 - count it once
    foreach ($a in $script:Attempts) {
        if ($a.Ip -eq $ip -and $a.Source -ne $Source -and [math]::Abs(($a.Time - $When).TotalSeconds) -le 3) { return }
    }
    [void]$script:Attempts.Add(@{ Ip = $ip; Time = $When; Source = $Source })
    $cutoff = (Get-Date).AddSeconds(-$script:Cfg.wail2ban.windowSeconds)
    $count = @($script:Attempts | Where-Object { $_.Ip -eq $ip -and $_.Time -ge $cutoff }).Count
    $limit = $script:Cfg.wail2ban.failCount
    $window = "$([int]($script:Cfg.wail2ban.windowSeconds / 60)) minutes"
    if ($count -ge $limit) {
        if (Test-Enforcing) {
            if (-not $Replay) { New-EdrEvent wail2ban Low "Failed network logon from $ip" -Detail "Failure $count of $limit within $window (source: $Source)." -Extra @{ ip = $ip; kind = 'fail'; source = $Source } }
            Invoke-Ban $ip $count
        } else {
            # Detect-only: the threshold is reported (Medium, notified) instead of banning
            $why = Test-Whitelisted $ip
            if (-not $why) {
                $script:Strikes[$ip] = @{ Count = 0; Epoch = (Get-Epoch) }; Save-Strikes   # remembered so a restart does not report it again
                $scope = if (Test-PrivateIp $ip) { 'private/LAN address' } else { 'public internet address' }
                Write-EngineLog A "Password guessing from $ip ($count failed logons in $window) - detect-only, not blocked"
                New-EdrEvent wail2ban Medium "Password guessing from $ip ($count failed logons)" -Detail "$count failed logons within $window (source: $Source). Source is a $scope. Detect-only mode: the address was not blocked. Flag it, or Always allow it if it is your own device." -Extra @{ ip = $ip; kind = 'fail'; source = $Source; threshold = $true }
            }
        }
        foreach ($a in @($script:Attempts | Where-Object { $_.Ip -eq $ip })) { $script:Attempts.Remove($a) }
    } elseif (-not $Replay) {
        # Shown in the dashboard's Wail2Ban > Detected list, so the user can flag or allow the source early
        New-EdrEvent wail2ban Low "Failed network logon from $ip" -Detail "Failure $count of $limit within $window (source: $Source)." -Extra @{ ip = $ip; kind = 'fail'; source = $Source }
    }
}

# W8: a successful network/RDP logon from a public address means someone outside the LAN has a valid password
$script:LoginSeen = @{}
function Invoke-LogonSuccess($Record) {
    $d = Get-EventData $Record
    $ip = Get-IpFromEventData $d $false
    if (-not $ip -or $script:SelfIps.Contains($ip) -or (Test-PrivateIp $ip) -or (Test-Whitelisted $ip)) { return }
    $user = ("$($d['TargetDomainName'])\$($d['TargetUserName'])").Trim('\')
    $key = "$ip|$user"
    if ($script:LoginSeen.ContainsKey($key) -and ((Get-Date) - $script:LoginSeen[$key]).TotalMinutes -lt 30) { return }   # one SMB session logs many 4624s
    $script:LoginSeen[$key] = Get-Date
    $how = if ($d['LogonType'] -eq '10') { 'Remote Desktop' } else { 'network logon (file sharing, or Remote Desktop with NLA)' }
    $proc = if ($d['ProcessName'] -and $d['ProcessName'] -ne '-') { [string]$d['ProcessName'] } else { '' }
    Write-EngineLog A "Successful $how as $user from public IP $ip"
    New-EdrEvent wail2ban High "Successful login as $user from $ip (public internet)" -Process $proc -Detail "$how. Workstation: $($d['WorkstationName']). Authentication: $($d['AuthenticationPackageName'])." -Extra @{ ip = $ip; kind = 'login'; user = $user; logonType = [string]$d['LogonType'] }
}

function Clear-OldAttempts {
    $cutoff = (Get-Date).AddSeconds(-$script:Cfg.wail2ban.windowSeconds)
    foreach ($a in @($script:Attempts | Where-Object { $_.Time -lt $cutoff })) { $script:Attempts.Remove($a) }
}

# W4: runs on a 60s timer, not after every event
function Remove-ExpiredBans {
    $list = @()
    try {
        foreach ($r in Get-BanRules) {
            $ip = $r.Name.Substring($FwRulePrefix.Length).Trim()
            $exp = $null; $permanent = $false
            if ($r.Description -match '^Expire:\s*(.+)$') {
                $d = [datetime]::MinValue
                if ($matches[1].Trim() -eq 'never') { $permanent = $true }
                elseif ([datetime]::TryParse($matches[1].Trim(), [ref]$d)) { $exp = $d }
            }
            if ($exp -and $exp -lt (Get-Date)) {
                if (Remove-BanRule $ip) {
                    Write-EngineLog A "Ban expired, unblocked $ip"
                    Write-AppEventLog "Removed IP $ip from firewall rules" 2000
                }
                continue
            }
            $strike = if ($script:Strikes.ContainsKey($ip)) { $script:Strikes[$ip].Count } else { 0 }
            $list += [pscustomobject]@{ ip = $ip; expires = $(if ($permanent) { 'Permanent' } elseif ($exp) { $exp.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }); strikes = $strike; private = (Test-PrivateIp $ip); permanent = $permanent }
        }
    } catch { Write-EngineLog E "Expired-ban cleanup failed: $_" }
    $script:Banned = $list
}

function Get-IpFromEventData([hashtable]$Data, [bool]$Fallback = $true) {
    foreach ($k in 'IpAddress', 'IPString', 'ClientIP', 'ClientAddress', 'Address') {
        if ($Data.ContainsKey($k)) { $n = ConvertTo-NormalIp $Data[$k]; if ($n) { return $n } }
    }
    if (-not $Fallback) { return $null }   # 4625 without a source address is a local logon - never guess
    foreach ($v in $Data.Values) {
        if ("$v" -match '(\d{1,3}(\.\d{1,3}){3})') { $n = ConvertTo-NormalIp $matches[1]; if ($n) { return $n } }
    }
    return $null
}

function Sync-RecentFailures {
    try {
        $recent = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddSeconds(-$script:Cfg.wail2ban.windowSeconds) } -ErrorAction Stop
        foreach ($ev in ($recent | Sort-Object TimeCreated)) {
            $ip = Get-IpFromEventData (Get-EventData $ev) $false
            if ($ip) { Add-LogonFailure $ip 'Security' $ev.TimeCreated -Replay }
        }
    } catch { if ("$_" -notmatch 'No events were found') { Write-EngineLog W "Startup sync of 4625 failed: $_" } }
}

function Set-Ipv6RdpBlocks {
    # Kept from Wail2Ban: block inbound RDP from all IPv6 sources (failures there were never counted)
    if (-not (Test-Enforcing)) { return }   # detect-only: no firewall rules are added (existing ones are left as they are)
    try {
        foreach ($proto in 'TCP', 'UDP') {
            $name = "Block RDP IPv6 ($proto 3389)"
            if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Block -Protocol $proto -LocalPort 3389 -RemoteAddress @('::/1', '8000::/1') -ErrorAction Stop | Out-Null
                Write-EngineLog A "Firewall rule created: $name"
            }
        }
    } catch { Write-EngineLog E "IPv6 RDP block rules: $_" }
}

################################################################################
# Real-time (Sysmon) + IOC + YARA

# Rule names come from config\sysmonconfig.xml; anything unknown defaults to Medium
$RuleSeverity = @{
    'Credential dumping tool'                         = 'Critical'
    'LSASS memory dump'                               = 'Critical'
    'Code injected into LSASS'                        = 'Critical'
    'LSASS memory read (credential theft)'            = 'High'
    'Shadow copy or recovery tampering'               = 'Critical'
    'Defender tampering'                              = 'High'
    'Defender exclusion added'                        = 'High'
    'Event log cleared'                               = 'High'
    'Encoded PowerShell command'                      = 'High'
    'PowerShell download or in-memory execution'      = 'High'
    'Office app started a shell'                      = 'High'
    'Winlogon hijack'                                 = 'High'
    'Debugger hijack (IFEO)'                          = 'High'
    'Unsigned driver loaded'                          = 'High'
    'mshta script execution'                          = 'High'
    'certutil download or decode'                     = 'High'
    'regsvr32/rundll32 script abuse'                  = 'High'
    'bitsadmin download'                              = 'Medium'
    'Script run from Downloads or Temp'               = 'Medium'
    'New user or admin group change'                  = 'High'
    'Windows script/LOLBin made a network connection' = 'Medium'
    'Startup entry added or changed (Run key)'        = 'Medium'
    'File added to a Startup folder'                  = 'Medium'
    'Scheduled task created from command line'        = 'Medium'
    'Executable launched from Downloads'              = 'Low'
}

$script:IocMap   = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
$script:IocStamp = [datetime]::MinValue

# Accepts "sha256" or "sha256;comment" lines (signature-base format); md5/sha1 lines are skipped
function Update-IocSet {
    $f = "$RulesDir\ioc_sha256.txt"
    if (-not (Test-Path $f)) { return }
    $t = (Get-Item $f).LastWriteTimeUtc
    if ($t -eq $script:IocStamp) { return }
    $script:IocStamp = $t
    $script:IocMap.Clear()
    foreach ($l in [IO.File]::ReadLines($f)) {
        if ($l -match '^\s*([0-9a-fA-F]{64})\s*(?:;(.*))?$') { $script:IocMap[$matches[1]] = [string]$matches[2] }
    }
    Write-EngineLog I "IOC hash list loaded: $($script:IocMap.Count) SHA256 hashes"
}

function Get-EventData($Record) {
    $h = @{}
    try {
        [xml]$x = $Record.ToXml()
        foreach ($d in $x.Event.EventData.Data) { if ($d.Name) { $h[$d.Name] = [string]$d.'#text' } }
    } catch { }
    return $h
}

# Parent, grandparent, ... of a Sysmon process-create event (up to $Depth), read from the live process list.
# Each step checks that the process really is the logged one (same path, started earlier), so a reused PID is never trusted.
$script:ProcCache = @{}
function Get-CachedProcess([int]$ProcId) {
    # Not named $Pid: that is PowerShell's read-only $PID, and binding it throws
    if ($ProcId -le 4) { return $null }
    if ($script:ProcCache.ContainsKey($ProcId)) {
        $entry = $script:ProcCache[$ProcId]
        if ((Get-Date) - $entry.Time -lt [TimeSpan]::FromMinutes(2)) { return $entry.Proc }
    }
    if ($script:ProcCache.Count -gt 500) { $script:ProcCache.Clear() }
    try {
        $p = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcId" -ErrorAction Stop
        if (-not $p) { return $null }
        $script:ProcCache[$ProcId] = @{ Proc = $p; Time = (Get-Date) }
        return $p
    } catch { return $null }
}

function Get-Ancestors([hashtable]$D, [int]$Depth = $MaxAncestors) {
    if (-not $D.ContainsKey('_anc')) {
        $list = New-Object Collections.ArrayList
        $par = [string]$D['ParentImage']
        if ($par) { [void]$list.Add($par) }
        $procId = 0
        [void][int]::TryParse([string]$D['ParentProcessId'], [ref]$procId)
        try {
            $p = if ($procId -gt 4) { Get-CachedProcess $procId } else { $null }
            if ($p -and $p.ExecutablePath -ine $par) { $p = $null }
            while ($p -and $list.Count -lt $MaxAncestors -and $p.ParentProcessId -gt 4) {
                $q = Get-CachedProcess ([int]$p.ParentProcessId)
                if (-not $q -or -not $q.ExecutablePath -or $q.CreationDate -gt $p.CreationDate) { break }
                [void]$list.Add([string]$q.ExecutablePath)
                $p = $q
            }
        } catch { }
        $D['_anc'] = @($list)
    }
    return @($D['_anc'] | Select-Object -First ([Math]::Max(1, $Depth)))
}

# A parent pattern matches one of the first N ancestors; with parentSigner that file must also carry a valid signature of it
function Test-ParentMatch($X, [string]$Parent, [hashtable]$D) {
    $n = [int]$X.ancestors
    $cands = if ($n -gt 1 -and $D) { Get-Ancestors $D $n } else { @($Parent) }
    foreach ($c in $cands) {
        if (-not $c -or -not ($c -like $X.parent)) { continue }
        if ($X.parentSigner -and (Get-CachedSigner $c) -ne $X.parentSigner) { continue }
        return $true
    }
    return $false
}

# Exclusion entries: rule ('*' = any), image, parent and detail (command line / registry value) are wildcard patterns ('' = any)
function Test-RealtimeExcluded([string]$Rule, [string]$Image, [string]$Parent, [hashtable]$D = $null, [string]$Detail = '') {
    foreach ($p in $script:Excl.realtimePath) { if ($Image -and $p.prefix -and $Image.StartsWith([string]$p.prefix, [StringComparison]::OrdinalIgnoreCase)) { return $true } }
    foreach ($x in $script:Excl.realtime) {
        if (-not $x) { continue }
        if ($x.rule -and $x.rule -ne '*' -and $x.rule -ne $Rule) { continue }
        if ($x.image -and -not ($Image -like $x.image)) { continue }
        if ($x.detail -and -not ($Detail -like $x.detail)) { continue }
        if ($x.parent -and -not (Test-ParentMatch $x $Parent $D)) { continue }
        if ($x.signer -and (Get-CachedSigner $Image) -ne $x.signer) { continue }
        if (-not $x.image -and -not $x.parent -and -not $x.signer -and -not $x.detail) { continue }   # never a blanket "ignore everything"
        return $true
    }
    return $false
}

# Publisher lookups are slow (~50 ms), so they are cached per file version and only made for signer exclusions
$script:SignerCache = @{}
function Get-CachedSigner([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $k = "$Path|$((Get-Item -LiteralPath $Path).LastWriteTimeUtc.Ticks)"
    if (-not $script:SignerCache.ContainsKey($k)) {
        if ($script:SignerCache.Count -gt 2000) { $script:SignerCache.Clear() }
        $script:SignerCache[$k] = Get-FileSigner $Path
    }
    return $script:SignerCache[$k]
}

# Rule names of the applied Sysmon config. An alert with any other name means the driver still runs an older
# rule set (Sysmon64 -c on a stuck driver only takes effect after a reboot) - reported as a health problem.
$script:RuleNames = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$script:StaleRule = $null
$script:StaleRuleTime = [datetime]::MinValue
function Update-RuleNames {
    $script:RuleNames.Clear()
    try {
        [xml]$x = Get-Content $SysmonConfig -Raw
        foreach ($n in $x.SelectNodes('//EventFiltering//*[@name]')) { if ($n.LocalName -ne 'RuleGroup') { [void]$script:RuleNames.Add($n.GetAttribute('name')) } }
    } catch { Write-EngineLog W "Could not read the Sysmon rule names: $_" }
}

# The engine's own children (scan, control helper, tray) - identified by the admin-only script path
$OwnScriptRx = [regex]::Escape("$Root\") + 'EDR-(Engine|Scan|Tray|Control)\.ps1'
function Test-OwnProcess([hashtable]$D) {
    # The installer (re)writes the tray's own start-up entry at every install
    if ([string]$D['TargetObject'] -match '\\CurrentVersion\\Run\\(FreeEDR Tray|EDR Tray)$' -and [string]$D['Image'] -match '\\(powershell|pwsh)\.exe$') { return $true }
    return ([string]$D['ParentCommandLine'] -match $OwnScriptRx) -or ([string]$D['CommandLine'] -match ('^"?[^"]*\\(powershell|pwsh)\.exe"?\s.*-File\s+"?' + $OwnScriptRx))
}

$script:YaraRules = @()
function Update-YaraRules {
    $yara = "$BinDir\yara64.exe"
    $script:YaraRules = @()
    if (-not (Test-Path $yara)) { return }
    foreach ($r in Get-ChildItem "$RulesDir\*.yar" -ErrorAction SilentlyContinue) {
        & $yara $r.FullName "$env:SystemRoot\System32\notepad.exe" 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { $script:YaraRules += $r.FullName } else { Write-EngineLog W "YARA rule file skipped (does not compile): $($r.Name)" }
    }
    Write-EngineLog I "YARA rule files loaded: $(($script:YaraRules | ForEach-Object { Split-Path $_ -Leaf }) -join ', ')"
}

$script:YaraCache = @{}
function Invoke-Yara([string]$Image) {
    $yara = "$BinDir\yara64.exe"
    if (-not $script:YaraRules.Count -or -not $Image -or -not (Test-Path -LiteralPath $Image)) { return $null }
    if ($Image.StartsWith("$env:SystemRoot\", [StringComparison]::OrdinalIgnoreCase)) { return $null }   # Windows binaries contain these strings legitimately
    foreach ($x in $script:Excl.yara) { if ($Image -like $x.image) { return $null } }
    try {
        $item = Get-Item -LiteralPath $Image -ErrorAction Stop
        if ($item.Length -gt 50MB) { return $null }
        $k = "$Image|$($item.LastWriteTimeUtc.Ticks)"
        if ($script:YaraCache.ContainsKey($k)) { return $script:YaraCache[$k] }
    } catch { return $null }
    $args2 = @($script:YaraRules) + @($Image)
    $hit = & $yara @args2 2>$null
    $res = if ($hit) { (($hit | Select-Object -First 1) -split ' ')[0] } else { $null }
    if ($script:YaraCache.Count -gt 1000) { $script:YaraCache.Clear() }
    $script:YaraCache[$k] = $res
    return $res
}

function Invoke-SysmonRecord($Record) {
    if (Test-Paused 'realtime') { return }
    $d = Get-EventData $Record
    $rule = ([string]$d['RuleName']).Trim()
    if ($rule -eq '-') { $rule = '' }
    if (-not $rule -and $Record.Id -in 19, 20, 21) { $rule = 'WMI persistence' }   # WMI is logged without a rule name
    if (-not $rule) { return }
    if (Test-OwnProcess $d) { return }
    $oldRule = $script:RuleNames.Count -and $rule -ne 'WMI persistence' -and -not $script:RuleNames.Contains($rule)
    if ($oldRule) { $script:StaleRule = $rule; $script:StaleRuleTime = Get-Date }
    $image = if ($d['Image']) { $d['Image'] } elseif ($d['SourceImage']) { $d['SourceImage'] } else { [string]$d['ImageLoaded'] }
    $parent = [string]$d['ParentImage']
    switch ($Record.Id) {
        3       { $detail = "Connected to $($d['DestinationIp']):$($d['DestinationPort']) $($d['DestinationHostname'])" }
        6       { $detail = "Driver: $($d['ImageLoaded'])  Signature: $($d['Signature']) ($($d['SignatureStatus']))" }
        8       { $detail = "Injected into: $($d['TargetImage'])" }
        10      { $detail = "Opened $($d['TargetImage']) with access $($d['GrantedAccess'])" }
        11      { $detail = "Created: $($d['TargetFilename'])" }
        { $_ -in 12, 13, 14 } { $detail = "$($d['TargetObject'])$(if ($d['Details']) { ' = ' + $d['Details'] })" }
        { $_ -in 19, 20, 21 } { $detail = "WMI $($d['Operation']) $($d['EventType']): $($d['Name']) $($d['Query']) $($d['Destination'])".Trim(); if (-not $image) { $image = '' } }
        default { $detail = [string]$d['CommandLine'] }
    }
    if (Test-RealtimeExcluded $rule $image $parent $d $detail) { return }
    if ((Test-Enforcing) -and $image -and $Record.Id -eq 1 -and @($script:Blocks | Where-Object { $_.enforce -and $_.image -ieq $image }).Count) { Invoke-BlockEnforcement; return }

    $hash = if ($d['Hashes']) { ($d['Hashes'] -replace '^.*SHA256=', '') -replace ',.*$', '' } else { '' }
    $blade = 'realtime'
    $sev = if ($RuleSeverity.ContainsKey($rule)) { $RuleSeverity[$rule] } elseif ($Record.Id -in 19, 20, 21) { 'High' } else { 'Medium' }
    $title = $rule
    $extra = @{ rule = $rule; sha256 = $hash; parent = $parent; user = [string]$d['User']; sysmonId = $Record.Id }
    if ($oldRule) { $extra.oldRule = $true }
    if ($Record.Id -eq 1) { $anc = @(Get-Ancestors $d | Select-Object -Skip 1); if ($anc.Count) { $extra.ancestors = $anc } }   # grandparent and up, for "allowed by" in the tray

    if (-not (Test-Paused 'malware')) {
        if ($hash -and $script:IocMap.ContainsKey($hash) -and -not @($script:Excl.ioc | Where-Object { $_.sha256 -ieq $hash }).Count) {
            $blade = 'ioc'; $sev = 'Critical'
            $name = $script:IocMap[$hash]
            $title = if ($name) { "Known malware: $name" } else { "Known malware hash ($rule)" }
            $extra.threat = $name
        }
        $yaraHit = Invoke-Yara $image
        if ($yaraHit) { $blade = 'yara'; $sev = 'Critical'; $title = "YARA match: $yaraHit"; $extra.yaraRule = $yaraHit }
    }

    New-EdrEvent $blade $sev $title -Process $image -Detail $detail -Extra $extra
}

################################################################################
# Microsoft Defender events (S1 visibility)

$AsrNames = @{
    '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block Office apps from creating child processes'
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email'
    '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block untrusted executables (prevalence/age)'
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block obfuscated scripts'
    'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JS/VBS launching downloaded executables'
    '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office apps creating executable content'
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office apps injecting into other processes'
    '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication apps creating child processes'
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
    'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creation from PSExec/WMI'
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted/unsigned processes from USB'
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
    'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Advanced protection against ransomware'
}

$AsrAlwaysAudit = @('01443614-cd74-433a-b99e-2ecdc07bfc25', 'd1e49aac-8f56-4280-b9ba-993a6d77406c')

function Invoke-DefenderRecord($Record) {
    $d = Get-EventData $Record
    $proc = [string]$d['Process Name']
    $path = [string]$d['Path']
    switch ($Record.Id) {
        1116 {
            $sevName = [string]$d['Severity Name']
            $sev = if ($sevName -match 'Severe') { 'Critical' } elseif ($sevName -match 'High') { 'High' } else { 'Medium' }
            New-EdrEvent defender $sev "Defender detected malware: $($d['Threat Name'])" -Process $proc -Detail $path -Extra @{ kind = 'malware'; threat = [string]$d['Threat Name']; threatId = [string]$d['Threat ID'] }
            # Remembered so the Sigma scan does not report the same detection again
            $script:State.defSeen = @(@($script:State.defSeen) + "$($d['Threat Name'])|$($Record.TimeCreated.ToString('yyyy-MM-dd HH:mm'))" | Select-Object -Last 2000)
            Save-State
        }
        1121 {
            $id = ([string]$d['ID']).ToLower()
            $name = if ($AsrNames.ContainsKey($id)) { $AsrNames[$id] } else { $id }
            New-EdrEvent defender Medium "Defender ASR blocked: $name" -Process $proc -Detail $path -Extra @{ kind = 'asr'; asrId = $id; path = $path }
        }
        1123 {
            New-EdrEvent defender Medium "Controlled folder access blocked a write" -Process $proc -Detail "Tried to change: $path" -Extra @{ kind = 'cfa'; path = $path }
        }
        # Audit mode (detect-only install): what Defender would have blocked. Low = listed, never a notification.
        1122 {
            $id = ([string]$d['ID']).ToLower()
            if ($id -in $AsrAlwaysAudit) { return }   # audit-only by design (they would flag every new or dev-built program)
            $name = if ($AsrNames.ContainsKey($id)) { $AsrNames[$id] } else { $id }
            New-EdrEvent defender Low "Defender ASR would have blocked: $name" -Process $proc -Detail $path -Extra @{ kind = 'asr-audit'; asrId = $id; path = $path }
        }
        1124 {
            New-EdrEvent defender Low "Controlled folder access would have blocked a write" -Process $proc -Detail "Tried to change: $path" -Extra @{ kind = 'cfa-audit'; path = $path }
        }
    }
}

################################################################################
# Watchers

$script:Watchers = @{}
$script:WatchErrors = @{}
$WatchDefs = @(
    @{ Sid = 'w2b-4625';   Log = 'Security';                                                    XPath = '*[System[(EventID=4625)]]' }
    @{ Sid = 'w2b-rdp140'; Log = 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'; XPath = '*[System[(EventID=140)]]' }
    @{ Sid = 'rt-sysmon';  Log = 'Microsoft-Windows-Sysmon/Operational';                        XPath = '*[System[(EventID=1 or EventID=3 or EventID=6 or EventID=8 or EventID=10 or EventID=11 or EventID=12 or EventID=13 or EventID=14 or EventID=19 or EventID=20 or EventID=21)]]' }
    @{ Sid = 'def';        Log = 'Microsoft-Windows-Windows Defender/Operational';              XPath = '*[System[(EventID=1116 or EventID=1121 or EventID=1122 or EventID=1123 or EventID=1124)]]' }
    @{ Sid = 'logon-ok';   Log = 'Security';                                                    XPath = "*[System[(EventID=4624)] and EventData[Data[@Name='LogonType']='3' or Data[@Name='LogonType']='10']]" }
)

function Start-Watcher($Def) {
    try {
        if ($script:Watchers.ContainsKey($Def.Sid)) {
            Unregister-Event -SourceIdentifier $Def.Sid -ErrorAction SilentlyContinue
            try { $script:Watchers[$Def.Sid].Enabled = $false; $script:Watchers[$Def.Sid].Dispose() } catch { }
            $script:Watchers.Remove($Def.Sid)
        }
        $q = New-Object Diagnostics.Eventing.Reader.EventLogQuery($Def.Log, [Diagnostics.Eventing.Reader.PathType]::LogName, $Def.XPath)
        $w = New-Object Diagnostics.Eventing.Reader.EventLogWatcher($q)
        Register-ObjectEvent -InputObject $w -EventName EventRecordWritten -SourceIdentifier $Def.Sid | Out-Null
        $w.Enabled = $true
        $script:Watchers[$Def.Sid] = $w
        $script:WatchErrors.Remove($Def.Sid)
        Write-EngineLog I "Watching $($Def.Log)"
    } catch {
        Unregister-Event -SourceIdentifier $Def.Sid -ErrorAction SilentlyContinue
        $script:WatchErrors[$Def.Sid] = "$($_.Exception.Message)"
        Write-EngineLog E "Cannot watch $($Def.Log): $($_.Exception.Message)"
    }
}

################################################################################
# Sysmon health (T3)

$script:SysmonOk = $script:State.sysmonOk -ne $false   # remembered, so a problem fixed by a reboot still gets its "healthy again"
$script:SysmonMsg = ''
$script:LastSysmonRestart = [datetime]::MinValue

function Test-SysmonHealth {
    $svc = Get-Service Sysmon64 -ErrorAction SilentlyContinue
    $drv = Get-Service SysmonDrv -ErrorAction SilentlyContinue
    $msg = ''
    if (-not $svc) { $msg = 'Sysmon is not installed' }
    elseif ($svc.Status -ne 'Running') {
        if ((Get-Date) - $script:LastSysmonRestart -gt [TimeSpan]::FromMinutes(5)) {
            $script:LastSysmonRestart = Get-Date
            try { Start-Service Sysmon64 -ErrorAction Stop; Write-EngineLog A 'Sysmon service was stopped - restarted it' } catch { }
            $svc = Get-Service Sysmon64 -ErrorAction SilentlyContinue
        }
        if ($svc.Status -ne 'Running') { $msg = "Sysmon service is $($svc.Status)" }
    }
    if (-not $msg -and $drv -and $drv.Status -ne 'Running') { $msg = "Sysmon driver is $($drv.Status) - restart the PC" }
    if (-not $msg -and $script:WatchErrors.ContainsKey('rt-sysmon')) { $msg = 'Sysmon event log not readable' }
    if (-not $msg -and $script:StaleRule -and ((Get-Date) - $script:StaleRuleTime).TotalMinutes -lt 60) {
        $msg = "Sysmon still runs an old rule set (alert `"$($script:StaleRule)`" is not in config\sysmonconfig.xml) - restart the PC"
    }
    $ok = -not $msg
    if ($ok -ne $script:SysmonOk) {
        if ($ok) { New-EdrEvent system Info 'Sysmon sensor is healthy again' -Extra @{ kind = 'health' } }
        else     { New-EdrEvent system High 'Sysmon sensor is not working' -Detail "$msg. Real-time detection is blind until this is fixed." -Extra @{ kind = 'health' } }
    }
    if ($script:State.sysmonOk -ne $ok) { $script:State | Add-Member -NotePropertyName sysmonOk -NotePropertyValue $ok -Force; Save-State }
    $script:SysmonOk = $ok
    $script:SysmonMsg = if ($ok) { 'Running' } else { $msg }
    $script:SysmonSvc = if ($svc) { "$($svc.Status)" } else { 'Missing' }
    $script:SysmonDrv = if ($drv) { "$($drv.Status)" } else { 'Missing' }
}

$script:Defender = $null
function Update-DefenderStatus {
    try {
        $s = Get-MpComputerStatus -ErrorAction Stop
        $p = Get-MpPreference -ErrorAction Stop
        $blockCount = 0; $auditCount = 0
        if ($p.AttackSurfaceReductionRules_Actions) {
            $blockCount = @($p.AttackSurfaceReductionRules_Actions | Where-Object { $_ -eq 1 }).Count
            $auditCount = @($p.AttackSurfaceReductionRules_Actions | Where-Object { $_ -eq 2 }).Count
        }
        $script:Defender = [pscustomobject]@{
            realtime        = [bool]$s.RealTimeProtectionEnabled
            tamper          = [bool]$s.IsTamperProtected
            signatureAgeDays= $s.AntivirusSignatureAge
            asrBlockRules   = $blockCount
            asrAuditRules   = $auditCount
            controlledFolders = switch ([int]$p.EnableControlledFolderAccess) { 1 { 'On' } 2 { 'Audit' } default { 'Off' } }
        }
    } catch { $script:Defender = $null }
}

################################################################################
# Scanner (T2: catch-up if the scheduled time was missed)

$script:ScanProc = $null
$script:ScanTrigger = 'schedule'
$script:EngineStart = Get-Date

function Get-NextScanDue {
    $s = Get-ScanSlots $script:Cfg.scanTimes (Get-Date)
    $last = if ($script:State.lastScanStart) { [datetime]$script:State.lastScanStart } else { [datetime]::MinValue }
    if ($last -lt $s.Prev) {
        if ($s.Prev -lt $script:EngineStart) { return $script:EngineStart.AddMinutes(5) }   # missed while the PC was off
        return $s.Prev
    }
    return $s.Next
}

function Start-Scan([string]$Trigger) {
    if ($script:ScanProc -and -not $script:ScanProc.HasExited) { return $false }
    if (Test-Paused 'edr') { return $false }
    $script:ScanTrigger = $Trigger
    $script:State.lastScanStart = (Get-Date).ToString('s'); Save-State
    # scan-result.json is kept (the dashboard shows feed times from it); Complete-Scan ignores a stale one
    $script:ScanProc = Start-Process powershell.exe -PassThru -WindowStyle Hidden -ArgumentList @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', "`"$Root\EDR-Scan.ps1`"")
    Write-EngineLog A "Scan started ($Trigger)"
    return $true
}

function Stop-Scan([string]$Why) {
    if (-not $script:ScanProc -or $script:ScanProc.HasExited) { return }
    try { Stop-Process -Id $script:ScanProc.Id -Force } catch { }
    Get-Process hayabusa, osv-scanner -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$BinDir\*" } | Stop-Process -Force -ErrorAction SilentlyContinue
    $script:ScanProc = $null
    Write-EngineLog A "Scan stopped: $Why"
}

# Sigma exclusions: a rule title ('*' = any rule), optionally only when started by a parent (wildcard)
function Test-SigmaExcluded([string]$Title, [string]$Parent) {
    foreach ($x in @($script:Excl.sigma)) {
        if (-not $x) { continue }
        $anyRule = -not $x.title -or $x.title -eq '*'
        if (-not $anyRule -and $x.title -ne $Title) { continue }
        if ($x.parent -and -not (Test-ParentMatch $x $Parent $null)) { continue }
        if ($anyRule -and -not $x.parent) { continue }   # never a blanket "ignore everything"
        return $true
    }
    return $false
}

function New-StringSet($Items) {
    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($i in @($Items)) { if ($i) { [void]$set.Add([string]$i) } }
    return ,$set
}

function Complete-Scan {
    $res = Read-Json $ScanResult $null
    if ($res -and $script:State.lastScanStart -and (-not $res.started -or [datetime]$res.started -lt ([datetime]$script:State.lastScanStart).AddSeconds(-5))) { $res = $null }   # left over from the previous scan
    $script:State.lastScanEnd = (Get-Date).ToString('s')
    $newSigma = 0; $newCve = 0; $problems = @()
    if (-not $res) {
        $problems += 'scan produced no result file'
    } else {
        foreach ($s in @($res.steps)) { if (-not $s.ok) { $problems += "$($s.name): $($s.message)" } }
        # E6: one alert per detected event (rule + record), not one per rule title forever
        $seen = New-StringSet $script:State.sigmaSeen
        $defSeen = New-StringSet $script:State.defSeen
        foreach ($hit in @($res.sigma)) {
            if (-not $hit.title) { continue }
            if ($hit.title -match '\(Sysmon Alert\)$') { continue }   # Hayabusa re-reporting our own Sysmon rules - the real-time blade already alerted
            $key = "$($hit.title)|$($hit.computer)|$($hit.channel)|$($hit.recordId)"
            if ($seen.Contains($key)) { continue }
            [void]$seen.Add($key)
            $sp = Get-SigmaProcess ([string]$hit.details)
            $sev = if ($hit.level -match '^crit' -or $hit.title -match 'Severe') { 'Critical' } else { 'High' }
            if ($hit.title -match $DefenderSigmaTitles) {
                # Defender's own detection: listed once in Anti-Malware, not again under Sigma
                $threat = if ([string]$hit.details -match 'Threat: ([^\xA6]+)') { $matches[1].Trim() } else { $hit.title }
                $dkey = "$threat|$(([string]$hit.timestamp).Substring(0, [Math]::Min(16, ([string]$hit.timestamp).Length)))"
                if ($defSeen.Contains($dkey)) { continue }
                [void]$defSeen.Add($dkey)
                New-EdrEvent defender $sev "Defender detected malware: $threat" -Process $sp.Image -Detail $hit.details -Extra @{ kind = 'malware'; threat = $threat; eventTime = $hit.timestamp; source = 'Sigma scan of the Defender log' }
                continue
            }
            if (Test-SigmaExcluded $hit.title $sp.Parent) { continue }
            $newSigma++
            $proc = if ($sp.Image) { $sp.Image } else { $hit.computer }
            New-EdrEvent sigma $sev $hit.title -Process $proc -Detail $hit.details -Extra @{ level = $hit.level; eventTime = $hit.timestamp; channel = $hit.channel; eventId = $hit.eventId; recordId = $hit.recordId; ruleId = $hit.ruleId; parent = $sp.Parent; computer = $hit.computer }
        }
        $script:State.sigmaSeen = @($seen | Select-Object -Last 20000)
        $script:State.defSeen = @($defSeen | Select-Object -Last 2000)
        # The CVE tab lists the latest scan only (patched packages disappear); events are just for history
        if (@($res.steps | Where-Object { $_.name -like '*OSV*' -and $_.ok }).Count) {
            Write-JsonAtomic $CveFile ([pscustomobject]@{ scanned = (Get-Date).ToString('s'); items = @($res.vulns) })
        }
        $cveSeen = New-StringSet $script:State.cveSeen
        foreach ($v in @($res.vulns)) {
            if (-not $v.id -or $cveSeen.Contains($v.id)) { continue }
            [void]$cveSeen.Add($v.id)
            if (@($script:Excl.cve | Where-Object { $_.cve -eq $v.id -or $_.cve -eq $v.cve }).Count) { continue }
            $newCve++
            $sev = if ($v.severity) { [string]$v.severity } else { 'Medium' }
            New-EdrEvent cve $sev "$($v.cve) in $($v.package) $($v.version) (fixed in $($v.fixed))" -Process $v.package -Detail $v.summary -Extra @{ cve = $v.cve; vulnId = $v.id; package = $v.package; version = $v.version; fixed = $v.fixed; path = $v.path }
        }
        $script:State.cveSeen = @($cveSeen)
        # E9: tool update notices, once per new version
        $toolSeen = New-StringSet $script:State.toolSeen
        foreach ($t in @($res.tools)) {
            if (-not $t.latest -or -not $t.outdated) { continue }
            $key = "$($t.name)|$($t.latest)"
            if ($toolSeen.Contains($key)) { continue }
            [void]$toolSeen.Add($key)
            New-EdrEvent patch Info "EDR tool update: $($t.name) $($t.current) -> $($t.latest)" -Process $t.name -Detail "Download: $($t.url)" -Extra @{ kind = 'tool'; url = $t.url; version = $t.current; latest = $t.latest }
        }
        $script:State.toolSeen = @($toolSeen)
        if ($res.toolCheck) { $script:State.lastToolCheck = $res.toolCheck }
    }
    $script:State.lastScanOk = ($problems.Count -eq 0)
    $script:State.lastScanSummary = "$newSigma new Sigma alerts, $newCve new vulnerabilities to patch" + $(if ($problems.Count) { "; problems: " + ($problems -join '; ') } else { '' })
    Save-State
    $sev = if ($problems.Count) { 'Medium' } else { 'Info' }
    New-EdrEvent system $sev "Scan finished: $newSigma new Sigma alerts, $newCve new vulnerabilities" -Detail $(if ($problems.Count) { "Problems: " + ($problems -join "`n") } else { 'All scan steps completed.' }) -Extra @{ kind = 'scan'; trigger = $script:ScanTrigger; newSigma = $newSigma; newCve = $newCve; ok = ($problems.Count -eq 0) }
    Write-EngineLog A "Scan finished: $($script:State.lastScanSummary)"
}

function Watch-Scan {
    if ($script:ScanProc) {
        if ($script:ScanProc.HasExited) { $script:ScanProc = $null; Complete-Scan }
        elseif ((Get-Date) - $script:ScanProc.StartTime -gt [TimeSpan]::FromHours(2)) {
            Stop-Scan 'exceeded 2 hours'
            Complete-Scan
        }
    } elseif (-not (Test-Paused 'edr') -and (Get-Date) -ge (Get-NextScanDue)) {
        [void](Start-Scan 'schedule')
    }
}

################################################################################
# Block / quarantine (user verdicts from the dashboard; config\blocklist.json)
#   realtime      : stop the program now and every time it starts
#   ioc / yara    : the same, and the file is moved to quarantine\
#   sigma         : a confirmed-threat record (Sigma findings are past log entries; nothing to stop)
#   wail2ban      : permanent firewall block of one IP
# Windows and security components are never moved or blocked permanently - only stopped once.

$script:Blocks = @(Get-Blocklist)
function Save-Blocks { Write-JsonAtomic $BlockFile ([pscustomobject]@{ items = @($script:Blocks) }) }

function Test-ProtectedPath([string]$Path) {
    foreach ($p in @($env:SystemRoot, "$env:ProgramFiles\Windows Defender", "${env:ProgramFiles(x86)}\Windows Defender", "$env:ProgramData\Microsoft\Windows Defender", $Root)) {
        if ($p -and $Path.StartsWith("$p\", [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Stop-ImageProcesses([string]$Image) {
    $n = 0
    foreach ($p in [Diagnostics.Process]::GetProcessesByName([IO.Path]::GetFileNameWithoutExtension($Image))) {
        try { if ($p.Path -and $p.Path -ieq $Image) { $p.Kill(); $n++ } } catch { }
    }
    return $n
}

function Initialize-QuarantineDir {
    if (Test-Path $QuarantineDir) { return }
    New-Item -ItemType Directory -Path $QuarantineDir -Force | Out-Null
    & icacls.exe $QuarantineDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
}

function Move-ToQuarantine([string]$Path, [string]$Id) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    Initialize-QuarantineDir
    $dest = Join-Path $QuarantineDir "$Id.quarantine"
    for ($i = 0; $i -lt 5; $i++) {
        try { Move-Item -LiteralPath $Path -Destination $dest -Force -ErrorAction Stop; return $dest } catch { Start-Sleep -Milliseconds 400 }
    }
    return $null
}

function Add-Block($Cmd) {
    $blade = [string]$Cmd.blade
    $entry = [ordered]@{
        id = [guid]::NewGuid().ToString('N'); added = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); blade = $blade
        title = [string]$Cmd.title; image = ''; sha256 = ''; ip = ''; enforce = $false; quarantine = ''; note = ''; hits = 0
    }
    $enforcing = Test-Enforcing
    switch ($blade) {
        { $_ -in 'realtime', 'ioc', 'yara' } {
            $img = [string]$Cmd.image
            if (-not $img -or -not [IO.Path]::IsPathRooted($img)) { return }
            if (@($script:Blocks | Where-Object { $_.image -ieq $img }).Count) { return }
            $entry.image = $img; $entry.sha256 = [string]$Cmd.sha256
            if (-not $enforcing) {
                $entry.note = 'Flagged as a threat by you. Detect-only mode: the program was not stopped or moved - remove it yourself, or let Microsoft Defender handle it.'
                break
            }
            $n = Stop-ImageProcesses $img
            if (Test-ProtectedPath $img) {
                $entry.note = "Windows/security component: stopped $n running copies, not blocked permanently (that would break Windows)."
            } else {
                $entry.enforce = $true
                $entry.note = "Stopped $n running copies; stopped again whenever it starts."
                if ($blade -in 'ioc', 'yara') {
                    $q = Move-ToQuarantine $img $entry.id
                    if ($q) { $entry.quarantine = $q; $entry.note = "Moved to quarantine; stopped $n running copies." }
                    else { $entry.note = "File not found or locked, so not moved; stopped $n running copies and stopped again whenever it starts." }
                }
            }
        }
        'sigma' {
            if (-not $entry.title -or @($script:Blocks | Where-Object { $_.blade -eq 'sigma' -and $_.title -eq $entry.title }).Count) { return }
            $entry.note = 'Confirmed as a threat by you.'
        }
        'wail2ban' {
            $ip = ConvertTo-NormalIp $Cmd.ip
            if (-not $ip -or $script:SelfIps.Contains($ip) -or @($script:Blocks | Where-Object { $_.ip -eq $ip }).Count) { return }
            $entry.ip = $ip
            if (-not $enforcing) { $entry.note = 'Flagged as hostile by you. Detect-only mode: not blocked in Windows Firewall.'; break }
            [void](Remove-BanRule $ip)
            try { New-BanRule $ip 'never' } catch { New-EdrEvent wail2ban High "Failed to block $ip" -Detail "$_" -Extra @{ ip = $ip }; return }
            $entry.note = 'Blocked permanently in Windows Firewall by you.'
            Write-AppEventLog "Blocked $ip permanently (by user)" 1000
            Remove-ExpiredBans
        }
        default { return }
    }
    $script:Blocks = @($script:Blocks) + [pscustomobject]$entry
    Save-Blocks
    $what = if ($entry.image) { $entry.image } elseif ($entry.ip) { $entry.ip } else { $entry.title }
    $verb = if ($enforcing) { 'Blocked' } else { 'Flagged' }
    Write-EngineLog A "$verb ($blade) by user: $what - $($entry.note)"
    New-EdrEvent system Info "$verb by you: $(if ($entry.image) { Split-Path $entry.image -Leaf } else { $what })" -Detail $entry.note -Extra @{ kind = 'verdict' }
}

function Remove-Block([string]$Id) {
    $hit = @($script:Blocks | Where-Object { $_.id -eq $Id }) | Select-Object -First 1
    if (-not $hit) { return }
    $note = 'Unblocked.'
    if ($hit.quarantine -and (Test-Path -LiteralPath $hit.quarantine)) {
        $dest = $hit.image
        if (Test-Path -LiteralPath $dest) { $dest = "$dest.restored-$(Get-Date -Format 'yyyyMMddHHmmss')" }
        try {
            $dir = Split-Path $dest
            if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            Move-Item -LiteralPath $hit.quarantine -Destination $dest -Force -ErrorAction Stop
            $note = "Restored from quarantine to $dest."
        } catch {
            Write-EngineLog E "Restore from quarantine failed: $_"
            New-EdrEvent system Medium "Could not restore $(Split-Path $hit.image -Leaf) from quarantine" -Detail "$_" -Extra @{ kind = 'status' }
            return
        }
    }
    if ($hit.blade -eq 'wail2ban' -and $hit.ip) { [void](Remove-BanRule $hit.ip); Write-AppEventLog "Removed IP $($hit.ip) from firewall rules" 2000; Remove-ExpiredBans }
    $script:Blocks = @($script:Blocks | Where-Object { $_.id -ne $Id })
    Save-Blocks
    $what = if ($hit.image) { $hit.image } elseif ($hit.ip) { $hit.ip } else { $hit.title }
    Write-EngineLog A "Unblocked ($($hit.blade)) by user: $what - $note"
    New-EdrEvent system Info "Unblocked by you: $(if ($hit.image) { Split-Path $hit.image -Leaf } else { $what })" -Detail $note -Extra @{ kind = 'verdict' }
}

# Stops blocked programs that were started again (polled every loop and on Sysmon process starts)
function Invoke-BlockEnforcement {
    if (-not (Test-Enforcing) -or (Test-Paused 'realtime')) { return }   # realtime pause includes live enforcement (and the master pause)
    $changed = $false
    foreach ($b in @($script:Blocks | Where-Object { $_.enforce -and $_.image })) {
        $n = Stop-ImageProcesses $b.image
        if (-not $n) { continue }
        $b.hits = [int]$b.hits + $n; $changed = $true
        Write-EngineLog A "Blocked program started and was stopped: $($b.image)"
        New-EdrEvent $b.blade Medium "Blocked program was started and stopped: $(Split-Path $b.image -Leaf)" -Process $b.image -Detail "Blocked by you on $($b.added)." -Extra @{ kind = 'blocked-start'; blockId = $b.id; sha256 = $b.sha256 }
    }
    if ($changed) { Save-Blocks }
}

# Permanent IP blocks survive manual firewall edits
function Repair-PermanentBans {
    if (-not (Test-Enforcing)) { return }
    foreach ($b in @($script:Blocks | Where-Object { $_.blade -eq 'wail2ban' -and $_.ip })) {
        if (-not (Test-BanRule $b.ip)) { try { New-BanRule $b.ip 'never'; Write-EngineLog A "Re-applied permanent block for $($b.ip)" } catch { } }
    }
}

################################################################################
# Commands

$script:LastManualScan = [datetime]::MinValue

function Add-Exclusion([string]$List, [hashtable]$Fields) {
    $entry = [ordered]@{ id = [guid]::NewGuid().ToString('N'); added = (Get-Date).ToString('yyyy-MM-dd HH:mm') }
    foreach ($k in $Fields.Keys) { $entry[$k] = $Fields[$k] }
    $script:Excl.$List = @($script:Excl.$List) + [pscustomobject]$entry
    Save-Exclusions
    Write-EngineLog A "Exclusion added to ${List}: $(($Fields.Values | Where-Object { $_ }) -join ' | ')"
}

# Same entry already allowed (e.g. a trusted-app profile switched on twice): adding it again would only duplicate it
function Test-ExclusionExists([string]$List, [hashtable]$Fields, [string[]]$Keys) {
    foreach ($x in @($script:Excl.$List)) {
        if (-not $x) { continue }
        $same = $true
        foreach ($k in $Keys) { if ([string]$x.$k -ne [string]$Fields[$k]) { $same = $false; break } }
        if ($same) {
            if ($Fields.profile -and -not $x.profile) { $x | Add-Member -NotePropertyName profile -NotePropertyValue $Fields.profile -Force; Save-Exclusions }
            return $true
        }
    }
    return $false
}

function Get-PauseBlade($Cmd) {
    $b = [string]$Cmd.blade
    if ($b -in @('edr', 'realtime', 'malware', 'sigma', 'cve', 'wail2ban')) { return $b }
    return $null
}

function Invoke-EdrCommand($Cmd, [bool]$Trusted) {
    $action = [string]$Cmd.action
    if (-not $Trusted -and $action -notin @('resume', 'scan-now')) { Write-EngineLog W "Ignored '$action' from inbox (needs admin)"; return }
    switch ($action) {
        'pause' {
            $b = Get-PauseBlade $Cmd; if (-not $b) { return }
            $m = [int]$Cmd.minutes
            $until = if ($m -gt 0) { (Get-Date).AddMinutes($m).ToString('s') } else { $UntilResumed }
            $script:State."${b}PausedUntil" = $until; Save-State
            if ($b -in @('edr', 'sigma', 'cve')) { Stop-Scan "$b paused" }
            $txt = if ($m -gt 0) { "for $m minutes" } else { 'until you resume it' }
            $dur = if ($m -gt 0) { "${m}m" } else { 'indefinite' }
            $user = if ($Cmd.user) { [string]$Cmd.user } else { $env:USERNAME }
            $nowIso = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            $bTitle = if ($BladeNames.ContainsKey($b)) { $BladeNames[$b] } else { $b }
            $auditMsg = "[FORENSIC-AUDIT] [$nowIso] [USER: $user] [RUBRIC: $b] [ACTION: PAUSE] [DURATION: $dur] [UNTIL: $until]"
            Write-EngineLog A $auditMsg
            Write-AppEventLog "Forensic Audit: Rubric '$b' paused for $dur by '$user'. Until: $until" 3000
            New-EdrEvent system Medium "$bTitle paused $txt" -Detail "Forensic Audit: Rubric $b paused for $dur by $user until $until" -Extra @{ kind = 'audit'; rubric = $b; action = 'pause'; user = $user; duration = $dur; until = $until }
        }
        'resume' {
            $b = Get-PauseBlade $Cmd; if (-not $b) { return }
            if (-not $script:State."${b}PausedUntil") { return }
            $script:State."${b}PausedUntil" = $null; Save-State
            $user = if ($Cmd.user) { [string]$Cmd.user } else { $env:USERNAME }
            $nowIso = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            $bTitle = if ($BladeNames.ContainsKey($b)) { $BladeNames[$b] } else { $b }
            $auditMsg = "[FORENSIC-AUDIT] [$nowIso] [USER: $user] [RUBRIC: $b] [ACTION: RESUME] [DURATION: 0] [UNTIL: NOW]"
            Write-EngineLog A $auditMsg
            Write-AppEventLog "Forensic Audit: Rubric '$b' resumed by '$user'" 3000
            New-EdrEvent system Info "$bTitle resumed" -Detail "Forensic Audit: Rubric $b resumed by $user" -Extra @{ kind = 'audit'; rubric = $b; action = 'resume'; user = $user }
        }
        'scan-now' {
            if ((Get-Date) - $script:LastManualScan -lt [TimeSpan]::FromMinutes(2)) { return }
            $script:LastManualScan = Get-Date
            if (Test-Paused 'edr') { New-EdrEvent system Info 'Scan not started: EDR is paused' -Extra @{ kind = 'status' }; return }
            if (-not (Start-Scan 'manual')) { New-EdrEvent system Info 'A scan is already running' -Extra @{ kind = 'status' } }
        }
        'block'   { Add-Block $Cmd }
        'unblock' { Remove-Block ([string]$Cmd.id) }
        'batch' {
            # Several verdict steps behind one UAC prompt, e.g. unblock + exclude ("move to Allowed")
            foreach ($op in @($Cmd.ops)) {
                if ($op -and [string]$op.action -in @('unban', 'exclude', 'unexclude', 'block', 'unblock')) { Invoke-EdrCommand $op $Trusted }
            }
        }
        'unban' {
            $ip = ConvertTo-NormalIp $Cmd.ip; if (-not $ip) { return }
            foreach ($b in @($script:Blocks | Where-Object { $_.ip -eq $ip })) { Remove-Block $b.id }
            [void](Remove-BanRule $ip)
            $script:Strikes.Remove($ip); Save-Strikes
            Write-EngineLog A "Unbanned $ip by user"
            Write-AppEventLog "Removed IP $ip from firewall rules" 2000
            New-EdrEvent wail2ban Info "Unblocked $ip (by you)" -Extra @{ ip = $ip; kind = 'unban' }
            Remove-ExpiredBans
        }
        'exclude' {
            switch ([string]$Cmd.blade) {
                'realtime' {
                    if (-not $Cmd.image -and -not $Cmd.parent -and -not $Cmd.signer -and -not $Cmd.detail) { return }
                    # A Windows/Microsoft signature alone would hide Windows' own tools; together with a program path it only narrows that path
                    if ($Cmd.signer -and [string]$Cmd.signer -in $UnsafeSigners -and -not $Cmd.image) { Write-EngineLog W "Refused to allow every program signed by $($Cmd.signer)"; return }
                    if ($Cmd.parentSigner -and [string]$Cmd.parentSigner -in $UnsafeSigners) { Write-EngineLog W "Refused to allow everything started by programs signed by $($Cmd.parentSigner)"; return }
                    $anc = if ($Cmd.parent) { [Math]::Min($MaxAncestors, [Math]::Max(1, [int]$Cmd.ancestors)) } else { 0 }
                    $f = @{ rule = $(if ($Cmd.rule) { [string]$Cmd.rule } else { '*' }); image = [string]$Cmd.image; parent = [string]$Cmd.parent; raw = [string]$Cmd.raw; signer = [string]$Cmd.signer
                            parentSigner = [string]$Cmd.parentSigner; ancestors = $anc; detail = [string]$Cmd.detail; profile = [string]$Cmd.profile }
                    if (Test-ExclusionExists realtime $f @('rule', 'image', 'parent', 'signer', 'parentSigner', 'detail')) { return }
                    Add-Exclusion realtime $f
                }
                'ioc'      { if (-not $Cmd.sha256) { return }; Add-Exclusion ioc @{ sha256 = [string]$Cmd.sha256; image = [string]$Cmd.image } }
                'yara'     { if (-not $Cmd.image) { return }; Add-Exclusion yara @{ image = [string]$Cmd.image; raw = [string]$Cmd.raw } }
                'sigma'    {
                    if (-not $Cmd.title -and -not $Cmd.parent) { return }
                    if ($Cmd.parentSigner -and [string]$Cmd.parentSigner -in $UnsafeSigners) { Write-EngineLog W "Refused to allow everything started by programs signed by $($Cmd.parentSigner)"; return }
                    $f = @{ title = $(if ($Cmd.title) { [string]$Cmd.title } else { '*' }); parent = [string]$Cmd.parent; parentSigner = [string]$Cmd.parentSigner; profile = [string]$Cmd.profile }
                    if (Test-ExclusionExists sigma $f @('title', 'parent', 'parentSigner')) { return }
                    Add-Exclusion sigma $f
                }
                'cve'      { Add-Exclusion cve @{ cve = [string]$Cmd.cve; package = [string]$Cmd.package } }
                'wail2ban' {
                    $c = [string]$Cmd.cidr
                    $base = ConvertTo-NormalIp ($c.Split('/')[0]); if (-not $base) { return }
                    if ($c -match '/' -and $c -notmatch '/\d{1,3}$') { Write-EngineLog W "Refused an invalid network '$c'"; return }
                    Add-Exclusion wail2ban @{ cidr = $c; note = [string]$Cmd.note }
                    foreach ($b in @($script:Blocks | Where-Object { $_.ip -and (Test-IpInCidr $_.ip $c) })) { Remove-Block $b.id }
                    foreach ($b in @($script:Banned)) { if (Test-IpInCidr $b.ip $c) { [void](Remove-BanRule $b.ip); $script:Strikes.Remove($b.ip) } }
                    Save-Strikes; Remove-ExpiredBans
                }
                'defender' {
                    $path = [string]$Cmd.path; if (-not $path) { return }
                    try {
                        if ($Cmd.kind -eq 'cfa') { Add-MpPreference -ControlledFolderAccessAllowedApplications $path -ErrorAction Stop }
                        elseif ($Cmd.kind -eq 'threat') {
                            # "Allow" for one Defender threat ID (path holds the numeric ID)
                            if ($path -notmatch '^\d+$') { return }
                            Add-MpPreference -ThreatIDDefaultAction_Ids ([long]$path) -ThreatIDDefaultAction_Actions 6 -ErrorAction Stop
                        }
                        else { Add-MpPreference -AttackSurfaceReductionOnlyExclusions $path -ErrorAction Stop }
                        Add-Exclusion defender @{ kind = [string]$Cmd.kind; path = $path; note = [string]$Cmd.note }
                    } catch { New-EdrEvent system Medium 'Could not add Defender exclusion' -Detail "$path : $_" -Extra @{ kind = 'status' } }
                }
            }
        }
        'unexclude' {
            foreach ($list in @($script:Excl.PSObject.Properties.Name)) {
                $hit = @($script:Excl.$list | Where-Object { $_.id -eq $Cmd.id })
                if (-not $hit.Count) { continue }
                if ($list -eq 'defender') {
                    try {
                        if ($hit[0].kind -eq 'cfa') { Remove-MpPreference -ControlledFolderAccessAllowedApplications $hit[0].path -ErrorAction Stop }
                        elseif ($hit[0].kind -eq 'threat') { Remove-MpPreference -ThreatIDDefaultAction_Ids ([long]$hit[0].path) -ErrorAction Stop }
                        else { Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $hit[0].path -ErrorAction Stop }
                    } catch { Write-EngineLog E "Remove Defender exclusion failed: $_" }
                }
                $script:Excl.$list = @($script:Excl.$list | Where-Object { $_.id -ne $Cmd.id })
                Save-Exclusions
                Write-EngineLog A "Exclusion removed from $list ($($Cmd.id))"
            }
        }
        default { Write-EngineLog W "Unknown command '$action'" }
    }
}

$script:FailedCmdFiles = @{}
function Read-Commands {
    foreach ($dir in @($ControlDir, $InboxDir)) {
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        $files = @([System.IO.Directory]::EnumerateFiles($dir, '*.json') | Select-Object -First 25)
        foreach ($f in $files) {
            if ($script:FailedCmdFiles.ContainsKey($f)) {
                if ((Get-Date) - $script:FailedCmdFiles[$f] -lt [TimeSpan]::FromMinutes(5)) { continue }
            }
            try {
                $fi = New-Object System.IO.FileInfo($f)
                if ($fi.Length -gt 64KB) {
                    Write-EngineLog W "Command file '$f' exceeds 64KB limit ($($fi.Length) bytes); discarded"
                    [System.IO.File]::Delete($f)
                    continue
                }
            } catch { continue }

            $cmd = Read-Json $f $null
            $deleted = $false
            for ($retry = 0; $retry -lt 3; $retry++) {
                try {
                    [System.IO.File]::Delete($f)
                    $deleted = $true
                    $script:FailedCmdFiles.Remove($f)
                    break
                } catch { Start-Sleep -Milliseconds 50 }
            }
            if (-not $deleted) {
                $script:FailedCmdFiles[$f] = Get-Date
                Write-EngineLog W "Could not delete command file '$f'; locked by another process"
                continue
            }
            if ($cmd) {
                try { Invoke-EdrCommand $cmd ($dir -eq $ControlDir) } catch { Write-EngineLog E "Command failed: $_" }
            }
        }
    }
    # Half-written requests (a .tmp the tray could not rename) are never read: remove them after 2 minutes
    foreach ($t in @(Get-ChildItem -LiteralPath $InboxDir -Filter '*.tmp' -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt (Get-Date).AddMinutes(-2) })) {
        Remove-Item -LiteralPath $t.FullName -Force -ErrorAction SilentlyContinue
    }
}

################################################################################
# Status for the tray

function Write-Status {
    $edrState = if ($script:WatchErrors.ContainsKey('rt-sysmon')) { 'error' } elseif (Test-Paused 'edr') { 'paused' } else { 'on' }
    $w2State = if ($script:WatchErrors.ContainsKey('w2b-4625')) { 'error' } elseif (Test-Paused 'wail2ban') { 'paused' } else { 'on' }
    $malState = if (Test-Paused 'malware') { 'paused' } else { 'on' }
    $rtState = if (Test-Paused 'realtime') { 'paused' } else { 'on' }
    $sigState = if (Test-Paused 'sigma') { 'paused' } else { 'on' }
    $cveState = if (Test-Paused 'cve') { 'paused' } else { 'on' }
    $status = [ordered]@{
        heartbeat     = (Get-Date).ToString('s')
        engineStarted = $script:EngineStart.ToString('s')
        edr           = [ordered]@{ state = $edrState; pausedUntil = $script:State.edrPausedUntil; error = $script:WatchErrors['rt-sysmon']; iocHashes = $script:IocMap.Count; yaraRules = @($script:YaraRules | ForEach-Object { Split-Path $_ -Leaf }) }
        realtime      = [ordered]@{ state = $rtState; pausedUntil = $script:State.realtimePausedUntil }
        malware       = [ordered]@{ state = $malState; pausedUntil = $script:State.malwarePausedUntil }
        sigma         = [ordered]@{ state = $sigState; pausedUntil = $script:State.sigmaPausedUntil }
        cve           = [ordered]@{ state = $cveState; pausedUntil = $script:State.cvePausedUntil }
        wail2ban      = [ordered]@{ state = $w2State; pausedUntil = $script:State.wail2banPausedUntil; error = $script:WatchErrors['w2b-4625']; banned = @($script:Banned); rdp140 = -not $script:WatchErrors.ContainsKey('w2b-rdp140') }
        sysmon        = [ordered]@{ ok = $script:SysmonOk; message = $script:SysmonMsg; service = $script:SysmonSvc; driver = $script:SysmonDrv }
        defender      = $script:Defender
        scan          = [ordered]@{
            running = [bool]($script:ScanProc -and -not $script:ScanProc.HasExited)
            lastStart = $script:State.lastScanStart; lastEnd = $script:State.lastScanEnd
            ok = $script:State.lastScanOk; summary = $script:State.lastScanSummary
            nextDue = (Get-NextScanDue).ToString('s')
            times = @($script:Cfg.scanTimes)
        }
        blocks        = @($script:Blocks).Count
        enforce       = (Test-Enforcing)
    }
    Write-JsonAtomic $StatusFile $status
}

################################################################################
# Main - every step is guarded so one bad event or command can never stop the engine

function Invoke-Safely([string]$Name, [scriptblock]$Block) {
    try { & $Block } catch { Write-EngineLog E "$Name failed: $($_.Exception.Message) $($_.InvocationInfo.PositionMessage)" }
}

Write-EngineLog A "Engine started (PID $PID)"
$script:Banned = @()
Invoke-Safely 'Local IPs'      { Update-SelfIps }
Invoke-Safely 'Strikes'        { Read-Strikes }
Invoke-Safely 'IOC list'       { Update-IocSet }
Invoke-Safely 'YARA rules'     { Update-YaraRules }
Invoke-Safely 'Sysmon rules'   { Update-RuleNames }
Invoke-Safely 'IPv6 RDP block' { Set-Ipv6RdpBlocks }
Invoke-Safely 'Startup sync'   { Sync-RecentFailures }
foreach ($w in $WatchDefs) { Invoke-Safely "Watcher $($w.Sid)" { Start-Watcher $w } }
Invoke-Safely 'Sysmon health'  { Test-SysmonHealth }
Invoke-Safely 'Defender'       { Update-DefenderStatus }
Invoke-Safely 'Bans'           { Remove-ExpiredBans }
Invoke-Safely 'Status'         { Write-Status }

$next = @{ status = (Get-Date); minute = (Get-Date).AddSeconds(60); five = (Get-Date).AddMinutes(5); ten = (Get-Date).AddMinutes(10) }

while ($true) {
    $batchCount = 0
    $maxBatch = 50
    while ($batchCount -lt $maxBatch) {
        $ev = $null
        try {
            $ev = if ($batchCount -eq 0) { Wait-Event -Timeout 5 } else { Wait-Event -Timeout 0 }
        } catch { break }
        if (-not $ev) { break }
        $batchCount++
        try {
            $args2 = $ev.SourceEventArgs
            if ($args2.EventException) {
                Write-EngineLog E "Watcher $($ev.SourceIdentifier) error: $($args2.EventException.Message) - restarting it"
                $def = $WatchDefs | Where-Object { $_.Sid -eq $ev.SourceIdentifier }
                if ($def) { Start-Watcher $def }
            } elseif ($args2.EventRecord) {
                $rec = $args2.EventRecord
                switch ($ev.SourceIdentifier) {
                    'w2b-4625'   { $ip = Get-IpFromEventData (Get-EventData $rec) $false; if ($ip) { Add-LogonFailure $ip 'Security' $rec.TimeCreated } }
                    'w2b-rdp140' { $ip = Get-IpFromEventData (Get-EventData $rec); if ($ip) { Add-LogonFailure $ip 'RdpCoreTS' $rec.TimeCreated } }
                    'rt-sysmon'  { Invoke-SysmonRecord $rec }
                    'def'        { Invoke-DefenderRecord $rec }
                    'logon-ok'   { Invoke-LogonSuccess $rec }
                }
            }
        } catch { Write-EngineLog E "Event handling failed: $($_.Exception.Message) $($_.InvocationInfo.PositionMessage)" }
        Remove-Event -EventIdentifier $ev.EventIdentifier -ErrorAction SilentlyContinue
    }

    $now = Get-Date
    Invoke-Safely 'Commands' { Read-Commands }
    Invoke-Safely 'Block enforcement' { Invoke-BlockEnforcement }
    Invoke-Safely 'Exclusions reload' {
        if ((Test-Path $ExclFile) -and (Get-Item $ExclFile).LastWriteTimeUtc -ne $script:ExclStamp) {
            $script:Excl = Get-Exclusions; $script:ExclStamp = (Get-Item $ExclFile).LastWriteTimeUtc
        }
    }
    if ($now -ge $next.minute) {
        $next.minute = $now.AddSeconds(60)
        Invoke-Safely 'Attempts cleanup' { Clear-OldAttempts }
        Invoke-Safely 'Permanent bans'   { Repair-PermanentBans }
        Invoke-Safely 'Ban expiry'       { Remove-ExpiredBans }
        Invoke-Safely 'Sysmon health'    { Test-SysmonHealth }
        Invoke-Safely 'Scan'             { Watch-Scan }
    }
    if ($now -ge $next.five) {
        $next.five = $now.AddMinutes(5)
        Invoke-Safely 'Local IPs' { Update-SelfIps }
        Invoke-Safely 'IOC list'  { Update-IocSet }
        foreach ($w in $WatchDefs) { if ($script:WatchErrors.ContainsKey($w.Sid)) { Invoke-Safely "Watcher $($w.Sid)" { Start-Watcher $w } } }
    }
    if ($now -ge $next.ten) { $next.ten = $now.AddMinutes(10); Invoke-Safely 'Defender' { Update-DefenderStatus } }
    if ($now -ge $next.status) { $next.status = $now.AddSeconds(15); Invoke-Safely 'Status' { Write-Status } }
}
