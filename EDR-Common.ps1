# EDR-Common.ps1 - shared paths and helpers of FreeEDR. Dot-sourced by every FreeEDR script.
# Windows PowerShell 5.1 compatible.

$ProductName  = 'FreeEDR'
# C:\Program Files\FreeEDR (the 64-bit folder, also from a 32-bit host). Everything FreeEDR keeps lives under it.
$Root         = "$(if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles })\FreeEDR"
$OldRoot      = 'C:\EDR'                       # install folder before 2026-11-02; Install-EDR.ps1 moves it here
$ConfigDir    = "$Root\config"
$DataDir      = "$Root\data"
$RulesDir     = "$Root\rules"
$BinDir       = "$Root\bin"
$ControlDir   = "$Root\control"   # admin-only command drop (pause, exclude, unban)
$InboxDir     = "$Root\inbox"     # user-writable drop for safe commands (resume, scan-now)
$UserDir      = "$Root\user"      # the tray's own files (reviewed alerts, hidden apps, history, tray.log): writable by the installing user
$DownloadDir  = "$DataDir\download"   # installer/tool downloads in progress (removed after use)
$ConfigFile   = "$ConfigDir\edr-config.json"
$ExclFile     = "$ConfigDir\exclusions.json"
$EventsFile   = "$DataDir\events.jsonl"
$StatusFile   = "$DataDir\status.json"
$StateFile    = "$DataDir\state.json"
$StrikesFile  = "$DataDir\wail2ban_strikes.txt"
$EngineLog    = "$DataDir\engine.log"
$ScanLog      = "$DataDir\scan.log"
$ScanResult   = "$DataDir\scan-result.json"
$CveFile      = "$DataDir\cve-current.json"   # latest vulnerability scan: only packages with a released fix
$BlockFile    = "$ConfigDir\blocklist.json"   # everything the user blocked/quarantined (managed by the engine)
$QuarantineDir = "$Root\quarantine"          # quarantined files (SYSTEM + Administrators only)
$SysmonConfig = "$ConfigDir\sysmonconfig.xml"
$TaskName     = 'FreeEDR'
$OldTaskName  = 'EDR'             # task name before 2026-11-02
$EngineMutex  = 'Global\FreeEDR-Engine'
$TrayMutex    = 'Local\FreeEDR-Tray'; $TrayShowEvent = 'Local\FreeEDR-Tray-Show'; $TrayExitEvent = 'Local\FreeEDR-Tray-Exit'
$FwRulePrefix = 'a a a wail2ban block IP:'   # kept from Wail2Ban so existing bans stay managed
$Utf8NoBom    = New-Object System.Text.UTF8Encoding($false)

$UntilResumed = '9999-12-31T00:00:00'

$BladeNames = [ordered]@{
    edr      = 'EDR (real-time, YARA, IOC, Sigma, CVE)'
    realtime = 'Real-time (Sysmon)'
    malware  = 'Anti-Malware (IOC & YARA)'
    ioc      = 'Malware hash (IOC)'
    yara     = 'YARA file scan'
    sigma    = 'Event-log scan (Sigma)'
    defender = 'Microsoft Defender'
    wail2ban = 'Wail2Ban (password guessing)'
    cve      = 'Vulnerability (CVE)'
    patch    = 'App updates (winget)'
    system   = 'EDR health'
}

$BladeScopeDescriptions = @{
    malware  = 'Pauses IOC malware hashes and YARA rules file inspections. Real-time Sysmon process tracking, firewall bans, and Defender remain active.'
    realtime = 'Pauses real-time Sysmon process tracking and live blocklist enforcement. Scans, firewall rules, and Defender remain active.'
    edr      = 'Master switch: Pauses all real-time EDR detection, blocking, YARA, IOC, Sigma, and CVE scans. Defender remains active.'
    sigma    = 'Pauses scheduled and manual Hayabusa event-log scans. Real-time EDR, Anti-Malware, and Wail2Ban remain active.'
    cve      = 'Pauses OSV vulnerability checks of Python packages. All other protections remain active.'
    wail2ban = 'Pauses tracking failed logons and new firewall bans. Existing bans stay until expiration.'
}

function Test-Paused([string]$Blade) {
    if (-not (Test-Path $StateFile)) { return $false }
    $s = Read-Json $StateFile $null
    if (-not $s) { return $false }
    if ($Blade -in @('realtime', 'malware', 'ioc', 'yara', 'sigma', 'cve')) {
        if ($s.edrPausedUntil) {
            try { if ([datetime]$s.edrPausedUntil -gt (Get-Date)) { return $true } } catch { }
        }
    }
    $prop = "${Blade}PausedUntil"
    $u = $s.$prop
    if (-not $u) { return $false }
    try { if ([datetime]$u -gt (Get-Date)) { return $true } } catch { }
    return $false
}

$SeverityRank = @{ Critical = 4; High = 3; Medium = 2; Low = 1; Info = 0 }

function Get-DefaultConfig {
    [pscustomobject]@{
        scanTimes      = @('06:00', '18:00')   # feeds, Sigma, CVE and tool checks run at each of these times
        quietProcesses = @('FortniteClient*', 'FortniteLauncher*')
        iocFeedUrl     = 'https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/hash-iocs.txt'
        sigmaLookback  = '2d'        # Hayabusa --time-offset: only scan recent events each day
        enforce        = $false      # $false = detect-only: nothing is stopped, quarantined or firewall-blocked; verdicts only flag
        allowProfilesInitialized = $false   # set by the installer once the recommended trusted-app profiles were applied
        wail2ban       = [pscustomobject]@{
            windowSeconds     = 1800      # count failures within the last 30 min
            failCount         = 5         # ban after this many failures
            maxBanPublicSec   = 7776000   # 90 days cap for public IPs
            maxBanPrivateSec  = 604800    # 7 days cap for private/LAN/loopback IPs (W7)
        }
    }
}

function Read-Json([string]$Path, $Default = $null) {
    for ($i = 0; $i -lt 5; $i++) {
        try {
            if (-not (Test-Path -LiteralPath $Path)) { return $Default }
            $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite,Delete')
            try { $text = (New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)).ReadToEnd() } finally { $fs.Dispose() }
            if ([string]::IsNullOrWhiteSpace($text)) { return $Default }
            return ($text | ConvertFrom-Json)
        } catch { Start-Sleep -Milliseconds 150 }
    }
    return $Default
}

function Write-JsonAtomic([string]$Path, $Object) {
    $tmp = "$Path.$PID.tmp"
    [IO.File]::WriteAllText($tmp, ($Object | ConvertTo-Json -Depth 8), $Utf8NoBom)
    for ($i = 0; $i -lt 5; $i++) {
        try {
            if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($tmp, $Path, [NullString]::Value) } else { [IO.File]::Move($tmp, $Path) }
            return
        } catch { Start-Sleep -Milliseconds 150 }
    }
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
}

function Add-TextLine([string]$Path, [string]$Line) {
    for ($i = 0; $i -lt 10; $i++) {
        try { [IO.File]::AppendAllText($Path, $Line + "`n", $Utf8NoBom); return } catch { Start-Sleep -Milliseconds 100 }
    }
}

function Get-EdrConfig {
    $cfg = Read-Json $ConfigFile $null
    $def = Get-DefaultConfig
    if (-not $cfg) { return $def }
    foreach ($p in $def.PSObject.Properties) {
        if (-not ($cfg.PSObject.Properties.Name -contains $p.Name)) { $cfg | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value }
    }
    foreach ($p in $def.wail2ban.PSObject.Properties) {
        if (-not ($cfg.wail2ban.PSObject.Properties.Name -contains $p.Name)) { $cfg.wail2ban | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value }
    }
    if ($cfg.iocFeedUrl -like '*bazaar.abuse.ch*') { $cfg.iocFeedUrl = $def.iocFeedUrl }   # abuse.ch exports return 410 since 2026
    return $cfg
}

# Every real user profile folder on this PC (any user, any name; works as SYSTEM too). Nothing user-specific is
# stored anywhere: the list is read from Windows each time.
function Get-UserProfiles {
    $dirs = @()
    try {
        foreach ($k in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction Stop) {
            if ($k.PSChildName -notmatch '^S-1-5-21-') { continue }   # local and domain accounts, not SYSTEM / services
            $p = [Environment]::ExpandEnvironmentVariables([string](Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue).ProfileImagePath)
            if ($p -and (Test-Path -LiteralPath $p -PathType Container)) { $dirs += $p }
        }
    } catch { }
    if (-not $dirs.Count) {
        $base = Split-Path ([Environment]::GetFolderPath('UserProfile'))
        if (-not $base -or $base -like "$env:SystemRoot*") { $base = "$env:SystemDrive\Users" }
        $dirs = @(Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin 'Public', 'Default', 'Default User', 'All Users' } | ForEach-Object { $_.FullName })
    }
    return @($dirs | Select-Object -Unique)
}

# The scheduled update slot before and after $Now (config scanTimes, e.g. 06:00 and 18:00)
function Get-ScanSlots($Times, [datetime]$Now) {
    $spans = @(@($Times) | ForEach-Object { $t = [TimeSpan]::Zero; if ([TimeSpan]::TryParse([string]$_, [ref]$t)) { $t } })
    if (-not $spans.Count) { $spans = @([TimeSpan]::FromHours(6), [TimeSpan]::FromHours(18)) }
    $all = @(foreach ($d in -1, 0, 1) { foreach ($t in $spans) { $Now.Date.AddDays($d).Add($t) } }) | Sort-Object
    return @{
        Prev = @($all | Where-Object { $_ -le $Now }) | Select-Object -Last 1
        Next = @($all | Where-Object { $_ -gt $Now }) | Select-Object -First 1
    }
}

# Program and parent from Hayabusa's details text ("Proc: C:\x.exe ¦ ParentCmdline: "C:\y\claude.exe" --flags ¦ ...")
function Get-SigmaProcess([string]$Details) {
    $f = @{}
    foreach ($part in ($Details -split [regex]::Escape([string][char]0xA6))) {
        $kv = $part -split ':\s', 2
        if ($kv.Count -eq 2 -and -not $f.ContainsKey($kv[0].Trim())) { $f[$kv[0].Trim()] = $kv[1].Trim().TrimEnd([char]0xC2).Trim() }   # 0xC2: UTF-8 "¦" read as ANSI
    }
    $img = @('Proc', 'Image', 'SrcProc', 'Process') | ForEach-Object { $f[$_] } | Where-Object { $_ -match '\.exe$' } | Select-Object -First 1
    $par = $f['ParentImage']
    if (-not $par -and $f['ParentCmdline']) {
        $pc = $f['ParentCmdline']
        if ($pc -match '^"([^"]+\.exe)"') { $par = $matches[1] } elseif ($pc -match '^(.+?\.exe)(\s|$)') { $par = $matches[1] }
    }
    return @{ Image = [string]$img; Parent = [string]$par }
}

# Publisher of a validly signed file (e.g. "Google LLC"), or $null
function Get-FileSigner([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try {
        $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        if ($s.Status -eq 'Valid' -and $s.SignerCertificate) { return $s.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) }
    } catch { }
    return $null
}

# Allowing these publishers would hide Windows' own tools (PowerShell, mshta, rundll32, Office), which attackers abuse
$UnsafeSigners = @('Microsoft Windows', 'Microsoft Windows Publisher', 'Microsoft Corporation')

# "Allow Claude Code": only the rules its own shell launcher trips, and only under a validly signed claude.exe.
# Its PowerShell tool runs claude.exe -> pwsh -EncodedCommand (syntax check) and claude.exe -> cmd.exe -> pwsh
# -Command "... Invoke-Expression ..." (the command itself), so the parent may be up to 3 levels above.
$ClaudeSigner         = 'Anthropic, PBC'
$ClaudeRealtimeRules  = @('Encoded PowerShell command', 'PowerShell download or in-memory execution')
$ClaudeSigmaTitles    = @('PowerShell Base64 Encoded FromBase64String Cmdlet', 'Script Interpreter Execution From Suspicious Folder')
$MaxAncestors         = 3

# Hayabusa rules that only repeat Microsoft Defender's own detections
$DefenderSigmaTitles = '^(Antivirus - |Defender Alert)'

# ---- Trusted-app profiles ("Trusted apps" wizard) ------------------------------
# One profile = a set of exclusions that lets one app run without alerts. Every entry is stored in
# exclusions.json with profile = <id>, so the wizard can switch the whole app on or off again at any time.
# Installed by default (when the app is found on the PC) where Default is $true. Entry fields as in exclusions.json:
#   realtime: rule ('*' = any), image, parent (+ parentSigner, ancestors = levels up), signer, detail (wildcard on
#             the command line / registry value). sigma: title ('*' = any), parent (+ parentSigner).
# A detail pattern matches what the app's own command line looks like; a program imitating it exactly is hidden too.
$PsLauncherRules = @('Encoded PowerShell command', 'PowerShell download or in-memory execution')
$PsLauncherSigma = @('PowerShell Base64 Encoded FromBase64String Cmdlet', 'Script Interpreter Execution From Suspicious Folder')
function New-AiProfileEntries([string]$Parent, [string]$Signer) {
    foreach ($r in $PsLauncherRules) { @{ list = 'realtime'; rule = $r; image = ''; parent = $Parent; parentSigner = $Signer; ancestors = $MaxAncestors } }
    foreach ($t in $PsLauncherSigma) { @{ list = 'sigma'; title = $t; parent = $Parent; parentSigner = $Signer } }
}
$AllowProfiles = @(
    [pscustomobject]@{
        id = 'claude-code'; name = 'Claude Code (Anthropic)'; default = $true
        what = "Claude Code's PowerShell tool: encoded syntax checks and its shell launcher. Only these PowerShell rules, only under claude.exe signed by Anthropic, PBC (or its exact launcher command line)."
        detect = @('C:\Users\*\AppData\Local\Claude-Data\*\claude-code', 'C:\Program Files\WindowsApps\AnthropicPBC.Claude_*', 'C:\Users\*\.local\bin\claude.exe')
        entries = @(@(New-AiProfileEntries '*\claude.exe' $ClaudeSigner) + @(
            @{ list = 'realtime'; rule = 'PowerShell download or in-memory execution'; image = '*\pwsh.exe'; detail = '*$__claudeCodeScript = $env:CLAUDE_CODE_SHELL_LAUNCHER_SCRIPT*' }
            @{ list = 'realtime'; rule = 'Encoded PowerShell command'; image = '*\pwsh.exe'; detail = '*-EncodedCommand CgBmAHUAbgBjAHQAaQBvAG4AIABXAHIAaQB0AGUALQBSAGUAcwB1AGwAdAAoACQASgBz*' }))
    }
    [pscustomobject]@{
        id = 'openai-codex'; name = 'ChatGPT / Codex (OpenAI)'; default = $true
        what = 'PowerShell started by the ChatGPT desktop app and the Codex agent (signed by OpenAI OpCo, LLC): commands, notification sounds, git helpers.'
        detect = @('C:\Program Files\WindowsApps\OpenAI.Codex_*', 'C:\Users\*\AppData\Local\OpenAI\Codex')
        entries = @(@(New-AiProfileEntries '*\ChatGPT.exe' 'OpenAI OpCo, LLC') + @(New-AiProfileEntries '*\codex.exe' 'OpenAI OpCo, LLC'))
    }
    [pscustomobject]@{
        id = 'antigravity'; name = 'Antigravity (Google AI IDE)'; default = $true
        what = 'PowerShell started by the Antigravity agent. Note: Antigravity is not digitally signed, so this allow is tied to its install folder only.'
        detect = @('C:\Users\*\AppData\Local\Programs\antigravity\Antigravity.exe')
        entries = @(New-AiProfileEntries 'C:\Users\*\AppData\Local\Programs\antigravity\*' '')
    }
    [pscustomobject]@{
        id = 'vcpkg'; name = 'Visual Studio Build Tools (vcpkg shell)'; default = $true
        what = 'The vcpkg environment script that Visual Studio developer shells load with "iex (get-content vcpkg-init.cmd)".'
        detect = @('C:\Program Files*\Microsoft Visual Studio\*\*\VC\vcpkg\vcpkg-init.cmd')
        entries = @(@{ list = 'realtime'; rule = 'PowerShell download or in-memory execution'; image = '*\pwsh.exe'; detail = '*iex (get-content \"C:\Program Files*\Microsoft Visual Studio\*\VC\vcpkg\vcpkg-init.cmd\" -raw)*' })
    }
    [pscustomobject]@{
        id = 'onedrive'; name = 'Microsoft OneDrive'; default = $true
        what = 'Everything OneDrive does: start-up entries, sync service, updates and its setup program (any version; per-user copies only when signed by Microsoft).'
        detect = @('C:\Program Files\Microsoft OneDrive', 'C:\Users\*\AppData\Local\Microsoft\OneDrive\OneDrive.exe')
        entries = @(
            @{ list = 'realtime'; rule = '*'; image = 'C:\Program Files\Microsoft OneDrive\*' }
            @{ list = 'realtime'; rule = '*'; image = 'C:\Users\*\AppData\Local\Microsoft\OneDrive\*'; signer = 'Microsoft Corporation' }
            @{ list = 'realtime'; rule = '*'; image = 'C:\Users\*\Downloads\OneDriveSetup*.exe'; signer = 'Microsoft Corporation' })
    }
    [pscustomobject]@{
        id = 'office'; name = 'Microsoft Office updates (Click-to-Run)'; default = $true
        what = 'Office Click-to-Run: its update service and the scheduled tasks it creates.'
        detect = @('C:\Program Files\Common Files\microsoft shared\ClickToRun')
        entries = @(
            @{ list = 'realtime'; rule = '*'; image = 'C:\Program Files\Common Files\microsoft shared\ClickToRun\*' }
            @{ list = 'realtime'; rule = 'Scheduled task created from command line'; image = ''; parent = 'C:\Program Files\Common Files\microsoft shared\ClickToRun\*'; ancestors = 1 })
    }
    [pscustomobject]@{
        id = 'google-drive'; name = 'Google Drive'; default = $true
        what = 'Google Drive for desktop (any version): its start-up entry and everything it runs from its install folder.'
        detect = @('C:\Program Files\Google\Drive File Stream')
        entries = @(@{ list = 'realtime'; rule = '*'; image = 'C:\Program Files\Google\Drive File Stream\*' })
    }
    [pscustomobject]@{
        id = 'razer'; name = 'Razer (Synapse / Cortex / App Engine)'; default = $true
        what = 'Razer software from its install folders (start-up entries, updates).'
        detect = @('C:\Program Files\Razer', 'C:\Program Files (x86)\Razer')
        entries = @(
            @{ list = 'realtime'; rule = '*'; image = 'C:\Program Files\Razer\*' }
            @{ list = 'realtime'; rule = '*'; image = 'C:\Program Files (x86)\Razer\*' })
    }
    [pscustomobject]@{
        id = 'installers'; name = 'Software installers (one-time RunOnce entries)'; default = $false
        what = 'Installers (Visual C++, .NET, Python, ...) add a one-time "RunOnce" start-up entry to finish setup. Off by default: malware can use RunOnce too.'
        detect = @()
        entries = @(@{ list = 'realtime'; rule = 'Startup entry added or changed (Run key)'; image = ''; detail = '*\CurrentVersion\RunOnce\*' })
    }
)

function Get-AllowProfile([string]$Id) { $AllowProfiles | Where-Object { $_.id -eq $Id } | Select-Object -First 1 }

# Is the app of a profile on this PC? (profiles without detect paths count as present)
function Test-ProfileInstalled($P) {
    if (-not @($P.detect).Count) { return $true }
    foreach ($d in $P.detect) { if (Get-Item -Path $d -ErrorAction SilentlyContinue) { return $true } }
    return $false
}

# Engine "exclude" commands for one profile (the same fields the engine stores)
function Get-ProfileOps($P) {
    foreach ($e in $P.entries) {
        $op = @{ action = 'exclude'; blade = $e.list; profile = $P.id }
        foreach ($k in $e.Keys) { if ($k -ne 'list') { $op[$k] = $e[$k] } }
        if ($e.list -eq 'realtime' -and -not $op.ContainsKey('rule')) { $op.rule = '*' }
        $op
    }
}

function Get-Blocklist {
    $b = Read-Json $BlockFile $null
    if ($b -and $b.items) { return @($b.items | Where-Object { $_ }) }
    return @()
}

function Get-EmptyExclusions {
    [pscustomobject]@{ realtimePath = @(); realtime = @(); ioc = @(); yara = @(); sigma = @(); wail2ban = @(); cve = @(); defender = @() }
}

function Get-Exclusions {
    $x = Read-Json $ExclFile $null
    $e = Get-EmptyExclusions
    if (-not $x) { return $e }
    foreach ($p in $e.PSObject.Properties) {
        if ($x.PSObject.Properties.Name -contains $p.Name -and $null -ne $x.($p.Name)) { $e.($p.Name) = @($x.($p.Name)) }
    }
    return $e
}

# ---- IP helpers -------------------------------------------------------------

function ConvertTo-NormalIp([string]$Text) {
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $s = $Text.Trim().Trim('[', ']')
    if ($s -match '^::ffff:(\d{1,3}(\.\d{1,3}){3})$') { $s = $matches[1] }
    $s = ($s -split '%')[0]
    if (-not ($s -match '^\d{1,3}(\.\d{1,3}){3}$' -or $s -match ':')) { return $null }
    $ip = $null
    if ([Net.IPAddress]::TryParse($s, [ref]$ip)) { return $ip.ToString() }
    return $null
}

function Test-IpInCidr([string]$Ip, [string]$Cidr) {
    $parts = $Cidr.Trim().Split('/')
    $a = $null; $n = $null
    if (-not [Net.IPAddress]::TryParse($Ip, [ref]$a)) { return $false }
    if (-not [Net.IPAddress]::TryParse($parts[0], [ref]$n)) { return $false }
    if ($a.AddressFamily -ne $n.AddressFamily) { return $false }
    if ($parts.Count -lt 2) { return $a.Equals($n) }
    $bits = [int]$parts[1]
    $ab = $a.GetAddressBytes(); $nb = $n.GetAddressBytes()
    for ($i = 0; $i -lt $ab.Length; $i++) {
        $take = [Math]::Min(8, [Math]::Max(0, $bits - 8 * $i))
        if ($take -eq 0) { break }
        $mask = [byte]((0xFF -shl (8 - $take)) -band 0xFF)
        if (($ab[$i] -band $mask) -ne ($nb[$i] -band $mask)) { return $false }
    }
    return $true
}

$PrivateRanges = @('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '100.64.0.0/10', '127.0.0.0/8', 'fc00::/7', 'fe80::/10', '::1/128')

function Test-PrivateIp([string]$Ip) {
    foreach ($r in $PrivateRanges) { if (Test-IpInCidr $Ip $r) { return $true } }
    return $false
}

function Format-Duration([double]$Seconds) {
    $t = [TimeSpan]::FromSeconds($Seconds)
    if ($t.TotalDays -ge 1) { return ('{0:0.#} days' -f $t.TotalDays) }
    if ($t.TotalHours -ge 1) { return ('{0:0.#} hours' -f $t.TotalHours) }
    return ('{0:0} minutes' -f $t.TotalMinutes)
}
