# EDR-Tray.ps1 - tray icon + dashboard for the EDR engine. Runs in the user's session, NOT elevated.
# Reads data\status.json, data\events.jsonl, config\blocklist.json, data\cve-current.json.
# Dashboard: one tab per section (Anti-Malware, EDR, Sigma, CVE, App Updates, Wail2Ban), each with
# three sub-tabs: Detected -> Blocked -> Allowed. Block/allow/unban/exclude go through EDR-Control.ps1
# with a UAC prompt; resume and scan-now go through inbox\.
# -SelfTest builds the model and the dashboard from the live data, prints a summary and exits (no UI).
param([switch]$Show, [switch]$SelfTest)

Add-Type -AssemblyName System.Windows.Forms, System.Drawing
. "$PSScriptRoot\EDR-Common.ps1"

# Single instance: a second launch (Start menu shortcut) asks the running tray to open the dashboard
$created = $false
$script:Mutex = New-Object Threading.Mutex($true, $TrayMutex, [ref]$created)
$script:ShowSignal = New-Object Threading.EventWaitHandle($false, [Threading.EventResetMode]::AutoReset, $TrayShowEvent)
$script:ExitSignal = New-Object Threading.EventWaitHandle($false, [Threading.EventResetMode]::AutoReset, $TrayExitEvent)
if (-not $created -and -not $SelfTest) { [void]$script:ShowSignal.Set(); exit 0 }

Add-Type -Namespace EdrNative -Name Win -MemberDefinition '[DllImport("user32.dll")] public static extern bool SetProcessDPIAware(); [DllImport("user32.dll")] public static extern bool DestroyIcon(System.IntPtr h);'
[void][EdrNative.Win]::SetProcessDPIAware()
[Windows.Forms.Application]::EnableVisualStyles()

$LocalDir     = $UserDir   # writable by the installing user; everything else under $Root is read-only
if ($SelfTest -and $env:EDR_SELFTEST_ROOT) {
    # Self-test on a fixture folder (data\, config\, local\) instead of $Root - used for the C# tray's parity tests
    $r = $env:EDR_SELFTEST_ROOT
    $StatusFile = "$r\data\status.json"; $EventsFile = "$r\data\events.jsonl"; $CveFile = "$r\data\cve-current.json"; $ScanResult = "$r\data\scan-result.json"
    $ExclFile = "$r\config\exclusions.json"; $BlockFile = "$r\config\blocklist.json"; $SysmonConfig = "$r\config\sysmonconfig.xml"; $ConfigFile = "$r\config\edr-config.json"
    $LocalDir = "$r\local"
}
$ReviewedFile = "$LocalDir\reviewed.txt"
$IgnoredApps  = "$LocalDir\ignored-apps.txt"
$HistoryFile  = "$LocalDir\history.json"    # CVE fixes and app updates started from the dashboard
$TrayLog      = "$LocalDir\tray.log"
if (-not (Test-Path $LocalDir)) { New-Item -ItemType Directory -Path $LocalDir -Force | Out-Null }

function Write-TrayLog([string]$Text) { Add-TextLine $TrayLog ("{0} {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Text) }

################################################################################
# Plain-language explanations (shown in the details pane): what happened / what to do

$RuleHints = @{
    'Encoded PowerShell command' = @(
        'PowerShell was started with a hidden (base64-encoded) command. Malware uses this to hide what it runs. Some legitimate tools also do it, for example AI coding assistants and installers.',
        'Look at "Started by". If it is a program you trust (for example claude.exe or an installer), click "Allow everything started by ...". Otherwise click Block program.')
    'PowerShell download or in-memory execution' = @(
        'PowerShell downloaded something or ran code straight from memory (DownloadString, Invoke-Expression, IEX, FromBase64String). This is the classic first step of a malware infection.',
        'If you did not just run a script yourself, check "Started by" and the command line. Exclude only if the parent program is one you trust.')
    'Shadow copy or recovery tampering' = @(
        'Something tried to delete Windows backup snapshots or disable recovery. Ransomware does this right before encrypting files.',
        'URGENT unless you did this yourself: disconnect from the network, run a full Microsoft Defender scan, check the program and what started it.')
    'Credential dumping tool' = @(
        'A command line contained commands of a well-known Windows password-stealing tool.',
        'URGENT: disconnect, run a Defender offline scan, change your passwords from another device.')
    'LSASS memory dump' = @(
        'Something tried to dump the memory of LSASS, the Windows process that holds your passwords.',
        'URGENT unless you ran it yourself for debugging: disconnect, run a Defender offline scan, change passwords.')
    'Code injected into LSASS' = @(
        'A program injected code into LSASS, the Windows process that holds your credentials.',
        'URGENT unless it is security software: disconnect and run a Defender offline scan.')
    'LSASS memory read (credential theft)' = @(
        'A program opened LSASS (where Windows keeps credentials) with rights that allow reading passwords. Security and anti-cheat software sometimes do this too.',
        'If the program is antivirus, anti-cheat or a known Windows component, exclude it. Otherwise treat as urgent.')
    'Defender tampering' = @(
        'A command tried to switch off or weaken Microsoft Defender.',
        'Unless you did this on purpose, treat as urgent: check Windows Security settings and run a full scan.')
    'Defender exclusion added' = @(
        'A new Microsoft Defender exclusion was added. Malware adds exclusions so Defender will not scan it.',
        'If you did not add it, open Windows Security > Virus & threat protection > Exclusions and remove it.')
    'Event log cleared' = @(
        'Windows event logs were cleared. Attackers do this to hide their tracks.',
        'Unless you cleared them yourself, investigate: check other alerts around the same time.')
    'Office app started a shell' = @(
        'Word/Excel/PowerPoint/Outlook started a command prompt or script engine. This is how malicious documents infect PCs.',
        'Close the document you just opened, do not enable macros, run a Defender scan.')
    'Winlogon hijack' = @(
        'The Windows sign-in program settings (Winlogon) were changed. Malware uses this to run at every sign-in.',
        'Unless you just installed system software, investigate the value shown below.')
    'Debugger hijack (IFEO)' = @(
        'A "debugger" was attached to a program through Image File Execution Options. Malware uses this to run instead of the real program.',
        'Check the registry path below. Legit only for developer tools.')
    'Unsigned driver loaded' = @(
        'A kernel driver without a valid signature was loaded. Rootkits and some cheats/hacking tools do this.',
        'If you did not just install hardware or development drivers, investigate the driver path.')
    'mshta script execution' = @(
        'mshta.exe ran. It is a built-in Windows program that malware abuses to run scripts from web pages or files.',
        'Legitimate use is rare on a home PC. Check the command line and the program that started it.')
    'certutil download or decode' = @(
        'certutil.exe (a certificate tool) was used to download or decode a file - a well-known malware trick.',
        'Investigate unless you ran it yourself.')
    'regsvr32/rundll32 script abuse' = @(
        'regsvr32/rundll32 was used to run a script or load something from the internet - a well-known malware trick.',
        'Investigate unless you recognise the command.')
    'bitsadmin download' = @(
        'bitsadmin.exe downloaded a file. Some installers do this, malware does too.',
        'Check the command line for the download address.')
    'Script run from Downloads or Temp' = @(
        'A .js/.vbs script was run from Downloads or a temp folder. Email/web malware often arrives this way.',
        'If you did not open a script on purpose, delete it and run a Defender scan.')
    'New user or admin group change' = @(
        'A user account was created or someone was added to the Administrators group.',
        'Unless you did this, treat as urgent: check Settings > Accounts > Other users.')
    'Windows script/LOLBin made a network connection' = @(
        'A Windows tool that normally never goes online (mshta, rundll32, certutil, ...) made a network connection. Malware uses these to download payloads.',
        'Check the destination address. Exclude only if you know the program.')
    'Startup entry added or changed (Run key)' = @(
        'A program added or changed something that starts automatically when you sign in.',
        'Fine if you just installed or configured an app. Otherwise check the value - it shows what will start with Windows.')
    'File added to a Startup folder' = @(
        'A file was placed in a Startup folder, so it will run every time you sign in.',
        'Fine if you just installed an app. Otherwise check the file name.')
    'Scheduled task created from command line' = @(
        'A scheduled task was created with schtasks.exe. Installers do this; so does malware, to survive reboots.',
        'Check the command line for what the task runs.')
    'Executable launched from Downloads' = @(
        'A program was started directly from your Downloads folder.',
        'Usually this is you running an installer. Only worry if you did not open it yourself.')
    'WMI persistence' = @(
        'A permanent WMI event subscription was created. This is a stealthy way for malware to run automatically.',
        'Rare on a home PC - investigate unless you know the software that did it.')
}
$BladeHints = @{
    ioc      = @('This program''s file fingerprint (SHA256) is on a public list of known malware (Neo23x0 signature-base).', 'Click Quarantine: the program is stopped and its file is moved to the EDR quarantine. Then run a full Microsoft Defender scan.')
    yara     = @('The program file matched a YARA pattern of known hacking tools or ransomware.', 'Click Quarantine unless it is a security tool you installed on purpose (then click Allow).')
    sigma    = @('The scheduled scan of the Windows event logs matched a Sigma rule rated high or critical. It describes something that was already logged, possibly hours ago.', 'If it was you (installing software, admin work), click Allow - this rule is then ignored. If not, click Confirm as threat and block the program involved in the EDR or Anti-Malware tab.')
    wail2ban = @('A computer failed to sign in to this PC over the network (Remote Desktop / file sharing). After 5 failures in 30 minutes it is reported as password guessing (and blocked for a while only if blocking is switched on).', 'If you do not know this address, flag it. If it is one of your own devices, click Always allow.')
    cve      = @('A Python package on this PC has a known security hole (CVE) that is fixed in a newer version.', 'Click Update now: a window opens and installs the fixed version. "Ask Gemini" explains the issue in plain words.')
    patch    = @('A newer version is available. Updates often contain security fixes.', 'Click Update now.')
    system   = @('Status message from the EDR itself.', '')
}
$DefenderHints = @{
    malware = @('Microsoft Defender detected malware and handled it (usually quarantined).', 'Nothing to do. Windows Security > Protection history shows the details. Only if you are sure it is a false alarm: Allow.')
    asr     = @('Microsoft Defender attack surface reduction blocked a risky action.', 'If this is a program you trust and need, click Allow.')
    cfa     = @('Controlled folder access (ransomware protection) blocked an app from changing files in your protected folders.', 'If you trust the app, click Allow.')
    'asr-audit' = @('Microsoft Defender attack surface reduction would have blocked this action. It is in audit mode (detect-only), so nothing was stopped.', 'If this is a program you trust, click Allow so it is no longer listed. Otherwise investigate the program.')
    'cfa-audit' = @('Controlled folder access (ransomware protection) would have stopped this app from changing files in your protected folders. It is in audit mode (detect-only), so the change went through.', 'If you trust the app, click Allow. If you do not know it, investigate - ransomware changes many files quickly.')
}

$GeminiTemplate = 'I found this cve {0} on my windows os pc. 1. please explain to me in a short condensed and oversimplified way what that CVE actually is. 2. How can this CVE be taken advantage by an attacker? what prerequisites conditions must be met first for the attacker to even be able to access it and invoke this cve. 3. Please provide me the commands to resolve it in cmd as admin or powershell as admin.'

################################################################################
# State

$script:Events      = New-Object System.Collections.ArrayList
$script:Offset      = 0
$script:Reviewed    = New-Object 'System.Collections.Generic.HashSet[string]'
$script:Ignored     = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$script:Status      = $null
$script:BannedKey   = ''
$script:Excl        = Get-Exclusions
$script:Blocks      = @()
$script:Cve         = $null
$script:ScanRes     = $null
$script:History     = @()
$script:Stamps      = @{}
$script:Cfg         = Get-EdrConfig
$script:Model       = $null
$script:ModelDirty  = $true
$script:ViewDirty   = $true
$script:Initial     = $true
$script:Exiting     = $false
$script:ToastTarget = $null
$script:Queued      = New-Object System.Collections.ArrayList
$script:LastQuietCheck = [datetime]::MinValue
$script:EngineDownToasted = $false
$script:PatchEvents = @()
$script:PatchProc   = $null
$script:PatchNext   = (Get-Date).AddMinutes(2)
$script:PatchChecked = $null
$script:Form        = $null
$script:Search      = ''
$script:ShowReviewed = $false
$script:BuiltIn     = @()

if (Test-Path $ReviewedFile) { foreach ($l in [IO.File]::ReadAllLines($ReviewedFile)) { if ($l) { [void]$script:Reviewed.Add($l.Trim()) } } }
if (Test-Path $IgnoredApps)  { foreach ($l in [IO.File]::ReadAllLines($IgnoredApps))  { if ($l) { [void]$script:Ignored.Add($l.Trim()) } } }
$h = Read-Json $HistoryFile $null
if ($h -and $h.items) { $script:History = @($h.items | Where-Object { $_ }) }

# Built-in Sysmon exclusions (games, anti-cheat, EDR) - shown read-only in EDR > Allowed
# Rule names of the current Sysmon config - real-time alerts from any other (retired) rule are hidden as reviewed
$script:RuleNames = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
try {
    [xml]$sx = Get-Content $SysmonConfig -Raw
    $script:BuiltIn = @($sx.Sysmon.EventFiltering.RuleGroup | Where-Object { $_.name -eq 'BuiltInExclusions' } |
        ForEach-Object { $_.ProcessCreate.Image } | ForEach-Object { $_.'#text' } | Where-Object { $_ } | Select-Object -Unique)
    foreach ($n in $sx.SelectNodes('//EventFiltering//*[@name]')) { if ($n.LocalName -ne 'RuleGroup') { [void]$script:RuleNames.Add($n.GetAttribute('name')) } }
} catch { }

# Alerts that only you can judge: pinned on top of Detected with "Was this you?"
$ConfirmPattern = 'Successful login as|External Remote .* from Public IP|Log File Cleared|^Log Cleared|Event log cleared|New user or admin group change|Defender tampering|Defender exclusion added'

function Get-Rank($e) { $r = $SeverityRank[[string]$e.severity]; if ($null -eq $r) { 0 } else { $r } }

# Alerts from a rule that is no longer in the Sysmon config (old LocalEDR rules) or Hayabusa re-reporting Sysmon
function Test-Retired($e) {
    if ($e.oldRule) { return $true }
    if ($e.blade -eq 'sigma' -and [string]$e.title -match '\(Sysmon Alert\)$') { return $true }
    if ($e.blade -eq 'realtime' -and $e.rule -and $script:RuleNames.Count -and $e.rule -ne 'WMI persistence' -and -not $script:RuleNames.Contains([string]$e.rule)) { return $true }
    return $false
}

function Test-Reviewed($e) { return [bool]($e.legacy -or $script:Reviewed.Contains([string]$e.id) -or (Test-Retired $e)) }

# Program and parent of a Sigma hit (new events carry them; older ones are parsed from the details text)
function Get-SigmaInfo($e) {
    if ($null -eq $e.PSObject.Properties['_sp']) {
        $sp = Get-SigmaProcess ([string]$e.detail)
        if (-not $sp.Image -and $e.process -match '\.exe$') { $sp.Image = [string]$e.process }
        if ($e.parent) { $sp.Parent = [string]$e.parent }
        $e | Add-Member -NotePropertyName _sp -NotePropertyValue $sp -Force
    }
    return $e._sp
}

$script:SignerCache = @{}
function Get-TraySigner([string]$Path) {
    if (-not $Path) { return $null }
    if (-not $script:SignerCache.ContainsKey($Path)) { $script:SignerCache[$Path] = Get-FileSigner $Path }
    return $script:SignerCache[$Path]
}

# Same rule as the engine: the parent pattern matches one of the first N ancestors (parent, grandparent, ...), signed by parentSigner if set
function Test-TrayParentMatch($R, $Chain) {
    $n = [Math]::Max(1, [int]$R.ancestors)
    foreach ($c in @($Chain | Where-Object { $_ } | Select-Object -First $n)) {
        if (-not ([string]$c -like $R.parent)) { continue }
        if ($R.parentSigner -and (Get-TraySigner ([string]$c)) -ne $R.parentSigner) { continue }
        return $true
    }
    return $false
}

# Signature of a parent program, used to tie a "started by" allow to its publisher (not for Windows' own tools)
function Get-ParentSigner([string]$Path) {
    $sg = Get-TraySigner $Path
    if ($sg -and $sg -notin $UnsafeSigners) { return $sg }
    return ''
}

function Set-Reviewed($Events) {
    $new = @()
    foreach ($e in @($Events)) { if ($e -and $e.id -and $script:Reviewed.Add([string]$e.id)) { $new += [string]$e.id } }
    if ($new.Count) { [IO.File]::AppendAllLines($ReviewedFile, [string[]]$new); $script:ModelDirty = $true }
}

function Clear-Reviewed($Events) {
    $n = 0
    foreach ($e in @($Events)) { if ($e -and $e.id -and $script:Reviewed.Remove([string]$e.id)) { $n++ } }
    if ($n) { [IO.File]::WriteAllLines($ReviewedFile, [string[]]@($script:Reviewed)); $script:ModelDirty = $true }
}

function Save-History { Write-JsonAtomic $HistoryFile ([pscustomobject]@{ items = @($script:History) }) }

function Add-History([string]$Sec, [string]$Key, $Obj) {
    $h = [ordered]@{ id = [guid]::NewGuid().ToString('N'); sec = $Sec; key = $Key; time = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }
    foreach ($n in 'cve', 'package', 'version', 'fixed', 'python', 'fixPackage', 'path', 'name', 'latest') { if ($Obj.PSObject.Properties[$n]) { $h[$n] = $Obj.$n } }
    if (-not $h.name -and $Obj.PSObject.Properties['process']) { $h.name = $Obj.process }
    $keep = @($script:History | Where-Object { -not ($_.sec -eq $Sec -and $_.key -eq $Key) })
    $script:History = @(($keep + @([pscustomobject]$h)) | Select-Object -Last 500)
    Save-History; $script:ModelDirty = $true
}

function Remove-History([string]$Id) {
    $script:History = @($script:History | Where-Object { $_.id -ne $Id })
    Save-History; $script:ModelDirty = $true
}

function Test-UpdatedSince([string]$Sec, [string]$Key, [datetime]$Since) {
    foreach ($h in @($script:History)) {
        if ($h.sec -eq $Sec -and $h.key -eq $Key) { try { if ([datetime]$h.time -gt $Since) { return $true } } catch { } }
    }
    return $false
}

function Get-PauseState([string]$Blade) {
    if (-not $script:Status) { return $null }
    if ($Blade -in @('realtime', 'malware', 'sigma', 'cve')) {
        if ($script:Status.$Blade -and $script:Status.$Blade.state -eq 'paused') { return $script:Status.$Blade }
        if ($script:Status.edr -and $script:Status.edr.state -eq 'paused') { return $script:Status.edr }
    }
    if ($script:Status.$Blade) { return $script:Status.$Blade }
    if ($Blade -eq 'edr' -and -not $script:Status.edr) { return $script:Status.realtime }
    return $null
}

################################################################################
# Data loading

function Read-NewEvents {
    if (-not (Test-Path $EventsFile)) { return }
    $len = (Get-Item $EventsFile).Length
    if ($len -lt $script:Offset) {
        $script:Offset = 0
        if ($script:Events.Count -gt 5000) {
            $script:Events = [System.Collections.ArrayList]@($script:Events | Select-Object -Last 5000)
        }
    }
    if ($len -eq $script:Offset) { return }
    $fs = [IO.File]::Open($EventsFile, 'Open', 'Read', 'ReadWrite,Delete')
    try {
        [void]$fs.Seek($script:Offset, 'Begin')
        $bytes = New-Object byte[] ($len - $script:Offset)
        $read = $fs.Read($bytes, 0, $bytes.Length)
    } finally { $fs.Dispose() }
    if ($read -le 0) { return }
    $lastNl = [Array]::LastIndexOf($bytes, [byte]10, $read - 1)
    if ($lastNl -lt 0) { return }
    $script:Offset += $lastNl + 1
    $text = [Text.Encoding]::UTF8.GetString($bytes, 0, $lastNl + 1)
    $lines = $text.Split("`n")
    $lineIdx = 0
    foreach ($line in $lines) {
        $lineIdx++
        if ($lineIdx % 500 -eq 0 -and $script:Form -and $script:Form.Visible) {
            [Windows.Forms.Application]::DoEvents()
        }
        if (-not $line.Trim()) { continue }
        try { $e = $line | ConvertFrom-Json } catch { continue }
        [void]$script:Events.Add($e)
        if (-not $script:Initial) { Invoke-Notify $e }
    }
    $script:ModelDirty = $true
}

function Test-FileChanged([string]$Path, [string]$Name) {
    $t = if (Test-Path $Path) { (Get-Item $Path).LastWriteTimeUtc } else { [datetime]::MinValue }
    if ($script:Stamps.ContainsKey($Name) -and $script:Stamps[$Name] -eq $t) { return $false }
    $script:Stamps[$Name] = $t
    return $true
}

function Update-Status {
    if (Test-FileChanged $StatusFile 'status') {
        $s = Read-Json $StatusFile $null
        if ($s) {
            $script:Status = $s; $script:ViewDirty = $true
            if ((Test-TrayEnforcing) -ne $script:LabelMode) { Set-ModeLabels }
            $k = (@($s.wail2ban.banned) | ConvertTo-Json -Compress)
            if ($k -ne $script:BannedKey) { $script:BannedKey = $k; $script:ModelDirty = $true }
        }
    }
    if (Test-FileChanged $ExclFile 'excl')    { $script:Excl = Get-Exclusions; $script:ModelDirty = $true }
    if (Test-FileChanged $BlockFile 'blocks') { $script:Blocks = @(Get-Blocklist); $script:ModelDirty = $true }
    if (Test-FileChanged $CveFile 'cve')      { $script:Cve = Read-Json $CveFile $null; $script:ModelDirty = $true }
    if (Test-FileChanged $ScanResult 'scan')  { $script:ScanRes = Read-Json $ScanResult $null; $script:ViewDirty = $true }
}

function Test-EngineAlive {
    if (-not $script:Status -or -not $script:Status.heartbeat) { return $false }
    return ((Get-Date) - [datetime]$script:Status.heartbeat).TotalSeconds -lt 90
}

function Format-Until($St) {
    if ($St.pausedUntil -eq $UntilResumed) { return 'until you resume it' }
    return 'until ' + ([datetime]$St.pausedUntil).ToString('HH:mm')
}

function Format-When($Value, [string]$Fmt = 'ddd dd/MM HH:mm') {
    if (-not $Value) { return 'never' }
    try { return ([datetime]$Value).ToString($Fmt) } catch { return [string]$Value }
}

################################################################################
# Sections: every dashboard tab holds three lists - 0 Detected, 1 Blocked, 2 Allowed (named per section)

$SectionOrder = @('malware', 'edr', 'sigma', 'cve', 'apps', 'wail2ban')
$Sections = @{
    malware  = @{ Name = 'Anti-Malware'; Subs = @('Detected', 'Blocked', 'Allowed'); Block = 'Quarantine'; Allow = 'Allow'; Security = $true }
    edr      = @{ Name = 'EDR'; Subs = @('Detected', 'Blocked', 'Allowed'); Block = 'Block program'; Allow = 'Allow'; Security = $true }
    sigma    = @{ Name = 'Sigma'; Subs = @('Detected', 'Blocked', 'Allowed'); Block = 'Confirm as threat'; Allow = 'Allow this rule (ignore it)'; Security = $true }
    cve      = @{ Name = 'CVE'; Subs = @('Detected', 'Updated', 'Ignored'); Block = 'Update now'; Allow = 'Ignore'; Security = $true }
    apps     = @{ Name = 'App Updates'; Subs = @('Available', 'Updated', 'Hidden'); Block = 'Update now'; Allow = 'Hide'; Security = $false }
    wail2ban = @{ Name = 'Wail2Ban'; Subs = @('Detected', 'Blocked', 'Allowed'); Block = 'Block IP'; Allow = 'Always allow'; Security = $true }
}
# Detect-only mode (config enforce = false, the default): "Blocked" lists hold what you flagged; nothing is stopped
$ModeLabels = @{
    $true  = @{ malware = @('Blocked', 'Quarantine'); edr = @('Blocked', 'Block program'); sigma = @('Blocked', 'Confirm as threat'); wail2ban = @('Blocked', 'Block IP') }
    $false = @{ malware = @('Flagged', 'Flag as threat'); edr = @('Flagged', 'Flag as threat'); sigma = @('Flagged', 'Confirm as threat'); wail2ban = @('Flagged', 'Flag as hostile') }
}
function Test-TrayEnforcing {
    if ($script:Status -and $null -ne $script:Status.enforce) { return [bool]$script:Status.enforce }
    return ($script:Cfg.enforce -eq $true)
}
function Set-ModeLabels {
    $mode = Test-TrayEnforcing
    foreach ($k in $ModeLabels[$mode].Keys) { $Sections[$k].Subs[1] = $ModeLabels[$mode][$k][0]; $Sections[$k].Block = $ModeLabels[$mode][$k][1] }
    $script:LabelMode = $mode
}
Set-ModeLabels
$BladeSection = @{ ioc = 'malware'; yara = 'malware'; defender = 'malware'; realtime = 'edr'; sigma = 'sigma'; cve = 'cve'; patch = 'apps'; wail2ban = 'wail2ban' }
$ExclSection  = @{ realtimePath = 'edr'; realtime = 'edr'; ioc = 'malware'; yara = 'malware'; defender = 'malware'; sigma = 'sigma'; cve = 'cve'; wail2ban = 'wail2ban' }

$ListCols = @{
    'malware|0'  = @(@('Severity', 95), @('When', 135), @('Caught by', 150), @('Threat', 320), @('Program', 170), @('Details', 420))
    'malware|1'  = @(@('Since', 135), @('Threat', 320), @('Program', 170), @('Status', 380), @('Location', 380))
    'malware|2'  = @(@('Added', 135), @('Allowed item', 620), @('Type', 240))
    'edr|0'      = @(@('Severity', 95), @('When', 135), @('What happened', 300), @('Program', 160), @('Started by', 160), @('Details', 440))
    'edr|1'      = @(@('Since', 135), @('Program', 200), @('Reason', 280), @('Status', 380), @('Location', 380))
    'edr|2'      = @(@('Added', 135), @('Allowed item', 700), @('Type', 220))
    'sigma|0'    = @(@('Severity', 95), @('When', 135), @('Rule', 360), @('Program', 150), @('Started by', 150), @('Details', 560))
    'sigma|1'    = @(@('Confirmed', 135), @('Rule', 450), @('Matches', 80), @('Note', 300))
    'sigma|2'    = @(@('Added', 135), @('Allowed item', 700))
    'cve|0'      = @(@('Severity', 95), @('CVE', 170), @('Package', 150), @('Installed', 100), @('Update to', 100), @('Summary', 620))
    'cve|1'      = @(@('Update started', 135), @('CVE', 170), @('Package', 150), @('From', 100), @('To', 100))
    'cve|2'      = @(@('Added', 135), @('CVE', 250), @('Package', 200))
    'apps|0'     = @(@('App', 320), @('Installed', 150), @('Update to', 150), @('winget ID', 320))
    'apps|1'     = @(@('Update started', 135), @('App', 320), @('From', 150), @('To', 150))
    'apps|2'     = @(, @('Hidden app (winget ID)', 500))
    'wail2ban|0' = @(@('Last attempt', 135), @('IP address', 220), @('What', 280), @('Network', 150))
    'wail2ban|1' = @(@('Since', 135), @('IP address', 220), @('Blocked until', 160), @('Strikes', 70), @('Network', 130), @('How', 220))
    'wail2ban|2' = @(@('Added', 135), @('IP / network', 260), @('Note', 320))
    'overview'   = @(@('When', 135), @('Message', 420), @('Details', 700))
}

$EmptyText = @{
    'malware|0' = 'Nothing detected.'; 'malware|1' = 'Nothing flagged, quarantined or blocked.'; 'malware|2' = 'Nothing allowed.'
    'edr|0' = 'Nothing detected.'; 'edr|1' = 'No program is flagged or blocked.'; 'edr|2' = 'Nothing allowed.'
    'sigma|0' = 'Nothing detected.'; 'sigma|1' = 'No confirmed threats.'; 'sigma|2' = 'No rule is ignored.'
    'cve|0' = 'No package needs a security update.'; 'cve|1' = 'Nothing updated from here yet.'; 'cve|2' = 'Nothing ignored.'
    'apps|0' = 'All apps are up to date.'; 'apps|1' = 'Nothing updated from here yet.'; 'apps|2' = 'No hidden apps.'
    'wail2ban|0' = 'No failed or unexpected logons.'; 'wail2ban|1' = 'No IP address is flagged or blocked.'; 'wail2ban|2' = 'No address is always allowed.'
    'overview' = 'No messages.'
}

function Get-Leaf($Path) { if ($Path) { Split-Path ([string]$Path) -Leaf } else { '' } }
function Get-Short($Text, [int]$Max = 220) { $t = ([string]$Text) -replace '\s+', ' '; if ($t.Length -gt $Max) { $t.Substring(0, $Max - 3) + '...' } else { $t } }
function Format-Sev([string]$Sev) { if ($Sev) { [string][char]0x25CF + ' ' + $Sev } else { '' } }
function Get-NetLabel([string]$Ip) { if (Test-PrivateIp $Ip) { 'Private / LAN' } else { 'Public internet' } }

function ConvertTo-VersionParts([string]$V) { @([regex]::Matches($V, '\d+') | ForEach-Object { [long]$_.Value }) }
function Compare-PyVersion([string]$A, [string]$B) {
    $x = @(ConvertTo-VersionParts $A); $y = @(ConvertTo-VersionParts $B)
    for ($i = 0; $i -lt [Math]::Max($x.Count, $y.Count); $i++) {
        $p = if ($i -lt $x.Count) { $x[$i] } else { 0 }
        $q = if ($i -lt $y.Count) { $y[$i] } else { 0 }
        if ($p -ne $q) { return $(if ($p -gt $q) { 1 } else { -1 }) }
    }
    return 0
}

function New-Row([string]$Kind, [string]$Time, [string]$Sev, [object[]]$Cols) {
    [pscustomobject]@{
        Kind = $Kind; Sec = ''; List = 0; Time = $Time; Sev = $Sev; Cols = @($Cols | ForEach-Object { [string]$_ })
        Key = ''; Ev = $null; Group = @(); Entry = $null; ExclList = ''; Ban = $null; Muted = $false; Note = ''; Pinned = $false
    }
}

# Mirrors the engine's exclusion logic; returns the matching exclusion entry
function Find-Exclusion($e) {
    $x = $script:Excl
    switch ([string]$e.blade) {
        'realtime' {
            $img = [string]$e.process; $par = [string]$e.parent; $rule = [string]$e.rule
            foreach ($p in @($x.realtimePath)) { if ($p -and $p.prefix -and $img -and $img.StartsWith([string]$p.prefix, [StringComparison]::OrdinalIgnoreCase)) { return $p } }
            foreach ($r in @($x.realtime)) {
                if (-not $r) { continue }
                if ($r.rule -and $r.rule -ne '*' -and $r.rule -ne $rule) { continue }
                if ($r.image -and -not ($img -like $r.image)) { continue }
                if ($r.detail -and -not ([string]$e.detail -like $r.detail)) { continue }
                if ($r.parent -and -not (Test-TrayParentMatch $r (@($par) + @($e.ancestors)))) { continue }
                if ($r.signer -and (Get-TraySigner $img) -ne $r.signer) { continue }
                if (-not $r.image -and -not $r.parent -and -not $r.signer -and -not $r.detail) { continue }
                return $r
            }
        }
        'ioc'      { foreach ($r in @($x.ioc)) { if ($r -and $e.sha256 -and $r.sha256 -ieq [string]$e.sha256) { return $r } } }
        'yara'     { foreach ($r in @($x.yara)) { if ($r -and $e.process -and ([string]$e.process -like $r.image)) { return $r } } }
        'sigma' {
            $par = (Get-SigmaInfo $e).Parent
            foreach ($r in @($x.sigma)) {
                if (-not $r) { continue }
                $anyRule = -not $r.title -or $r.title -eq '*'
                if (-not $anyRule -and $r.title -ne $e.title) { continue }
                if ($r.parent -and -not (Test-TrayParentMatch $r @($par))) { continue }
                if ($anyRule -and -not $r.parent) { continue }
                return $r
            }
        }
        'wail2ban' { if ($e.ip) { foreach ($r in @($x.wail2ban)) { if ($r -and (Test-IpInCidr ([string]$e.ip) ([string]$r.cidr))) { return $r } } } }
        'defender' {
            foreach ($r in @($x.defender)) {
                if (-not $r) { continue }
                if ($r.kind -eq 'threat') { if ($e.threatId -and $r.path -eq [string]$e.threatId) { return $r } }
                elseif ($r.kind -eq ([string]$e.kind -replace '-audit$') -and ($r.path -ieq [string]$e.path -or $r.path -ieq [string]$e.process)) { return $r }
            }
        }
    }
    return $null
}

function Find-Block($e) {
    $b = [string]$e.blade
    foreach ($k in @($script:Blocks)) {
        if (-not $k) { continue }
        if ($b -in 'realtime', 'ioc', 'yara') {
            if ($k.blade -notin 'realtime', 'ioc', 'yara') { continue }
            if (($e.process -and $k.image -and $k.image -ieq [string]$e.process) -or ($k.sha256 -and $e.sha256 -and $k.sha256 -ieq [string]$e.sha256)) { return $k }
        } elseif ($b -eq 'sigma') {
            if ($k.blade -eq 'sigma' -and $k.title -eq $e.title) { return $k }
        } elseif ($b -eq 'wail2ban') {
            if ($k.blade -eq 'wail2ban' -and $e.ip -and $k.ip -eq [string]$e.ip) { return $k }
        }
    }
    return $null
}

function Find-CveExclusion($v) {
    $ids = @(@($v.id, $v.cve) + @($v.aliases)) | Where-Object { $_ }
    foreach ($x in @($script:Excl.cve)) { if ($x -and $ids -contains [string]$x.cve) { return $x } }
    return $null
}

function Get-ExclText([string]$List, $x) {
    switch ($List) {
        'realtimePath' { return "Any program under $($x.prefix)" }
        'realtime' {
            $what = @()
            if ($x.image)  { $what += "program $(if ($x.raw) { $x.raw } else { $x.image })" }
            if ($x.parent) { $what += "started by $($x.parent)$(if ([int]$x.ancestors -gt 1) { " (up to $($x.ancestors) levels up)" })$(if ($x.parentSigner) { " signed by $($x.parentSigner)" })" }
            if ($x.signer) { $what += $(if ($x.image) { "signed by $($x.signer)" } else { "every program signed by $($x.signer)" }) }
            if ($x.detail) { $what += "command line like $($x.detail)" }
            $r = if ($x.rule -eq '*' -or -not $x.rule) { 'all rules' } else { 'rule "' + $x.rule + '"' }
            return (($what -join ', ') + "  -  $r")
        }
        'ioc'      { return "$($x.image)  (SHA256 $($x.sha256))" }
        'yara'     { return $(if ($x.raw) { [string]$x.raw } else { [string]$x.image }) }
        'sigma'    {
            $rule = if (-not $x.title -or $x.title -eq '*') { 'Any Sigma rule' } else { 'Rule "' + $x.title + '"' }
            return $(if ($x.parent) { "$rule, when started by $($x.parent)$(if ($x.parentSigner) { " signed by $($x.parentSigner)" })" } else { $rule })
        }
        'wail2ban' { return "Never block $($x.cidr)$(if ($x.note) { "  ($($x.note))" })" }
        'cve'      { return "$($x.cve)$(if ($x.package) { " in $($x.package)" })" }
        'defender' {
            if ($x.kind -eq 'threat') { return "Defender threat ID $($x.path)$(if ($x.note) { " ($($x.note))" })" }
            return [string]$x.path
        }
    }
    return ''
}

function Get-ExclType([string]$List, $x) {
    if ($x.profile) { $p = Get-AllowProfile ([string]$x.profile); return "Trusted app: $(if ($p) { $p.name } else { $x.profile })" }
    switch ($List) {
        'realtimePath' { return 'Folder' }
        'realtime'     { if ($x.signer -and -not $x.image) { return 'Publisher (digital signature)' } elseif ($x.parent) { return 'Everything it starts (any version)' } elseif ($x.rule -and $x.rule -ne '*') { return 'Program, one rule' } else { return 'Program, all rules' } }
        'ioc'          { return 'File fingerprint (not malware)' }
        'yara'         { return 'File skipped by YARA' }
        'defender'     { switch ([string]$x.kind) { 'cfa' { return 'Defender: Controlled folder access' } 'threat' { return 'Defender: threat allowed' } default { return 'Defender: ASR rules' } } }
    }
    return ''
}

function Get-Minute($Text) { $s = [string]$Text; return $s.Substring(0, [Math]::Min(16, $s.Length)) }

function Add-ToMap($Map, [string]$Key, $Value) {
    if (-not $Map.ContainsKey($Key)) { $Map[$Key] = New-Object Collections.ArrayList }
    [void]$Map[$Key].Add($Value)
}

function Add-Row($M, [string]$Sec, [int]$List, $Row) {
    $Row.Sec = $Sec; $Row.List = $List
    [void]$M[$Sec].Rows[$List].Add($Row)
}

function New-EventRow([string]$Sec, $Rep, $Members) {
    $n = @($Members).Count
    $pinned = [string]$Rep.title -match $ConfirmPattern
    $title = [string]$Rep.title
    if ($pinned) { $title = "Was this you?   $title" }
    if ($n -gt 1) { $title += "   (x$n)" }
    $detail = Get-Short $Rep.detail
    if ($Sec -eq 'malware') { $cols = @((Format-Sev $Rep.severity), $Rep.time, $BladeNames[[string]$Rep.blade], $title, (Get-Leaf $Rep.process), $detail) }
    elseif ($Sec -eq 'edr') { $cols = @((Format-Sev $Rep.severity), $Rep.time, $title, (Get-Leaf $Rep.process), (Get-Leaf $Rep.parent), $detail) }
    elseif ($Sec -eq 'wail2ban') { $cols = @($Rep.time, $Rep.ip, $title, (Get-NetLabel ([string]$Rep.ip))) }
    else { $sp = Get-SigmaInfo $Rep; $cols = @((Format-Sev $Rep.severity), $Rep.time, $title, (Get-Leaf $sp.Image), (Get-Leaf $sp.Parent), $detail) }
    $r = New-Row 'event' ([string]$Rep.time) ([string]$Rep.severity) $cols
    $r.Ev = $Rep; $r.Group = @($Members); $r.Key = [string]$Rep.id; $r.Pinned = $pinned
    $r.Muted = -not @($Members | Where-Object { -not (Test-Reviewed $_) }).Count
    return $r
}

# Sorts every event, verdict and scan result into its section and list
function Update-Model {
    $m = @{}
    foreach ($s in $SectionOrder) {
        $m[$s] = @{ Rows = @{ 0 = (New-Object Collections.ArrayList); 1 = (New-Object Collections.ArrayList); 2 = (New-Object Collections.ArrayList) }; Count = 0; Alert = $false; Attention = 0 }
    }
    $sys = New-Object Collections.ArrayList
    $det = @{ malware = (New-Object Collections.ArrayList); edr = (New-Object Collections.ArrayList); sigma = (New-Object Collections.ArrayList) }
    $defBlocked = New-Object Collections.ArrayList
    $fails = New-Object Collections.ArrayList
    $banHist = New-Object Collections.ArrayList
    $blockEv = @{}; $exclEv = @{}
    $logins = New-Object Collections.ArrayList
    $avSeen = New-Object 'System.Collections.Generic.HashSet[string]'
    $claude = $null

    foreach ($e in $script:Events) {
        $b = [string]$e.blade
        if ($b -eq 'system' -or ($b -eq 'patch' -and $e.kind -eq 'tool')) { [void]$sys.Add($e); continue }
        if ($b -eq 'wail2ban') {
            if ($e.kind -eq 'fail') { [void]$fails.Add($e) } elseif ($e.kind -eq 'login') { [void]$logins.Add($e) } elseif ($e.ip -and $e.expires) { [void]$banHist.Add($e) }
            continue
        }
        if ($b -notin 'realtime', 'ioc', 'yara', 'sigma', 'defender') { continue }   # cve: the CVE tab shows the latest scan instead
        if (-not $claude) {
            $par = if ($b -eq 'sigma') { (Get-SigmaInfo $e).Parent } else { [string]$e.parent }
            $claude = @(@($par) + @($e.ancestors) | Where-Object { [string]$_ -match '\\claude\.exe$' }) | Select-Object -First 1
        }
        if ($b -eq 'defender' -and $e.threat) { [void]$avSeen.Add("$($e.threat)|$(Get-Minute $(if ($e.eventTime) { $e.eventTime } else { $e.time }))") }
        if ($b -eq 'sigma' -and [string]$e.title -match $DefenderSigmaTitles) {
            # Hayabusa repeating a Defender detection: shown once, in Anti-Malware, as blocked by Defender
            $threat = if ([string]$e.detail -match 'Threat: ([^\xA6]+)') { $matches[1].Trim() } else { [string]$e.title }
            $t16 = Get-Minute $(if ($e.eventTime) { $e.eventTime } else { $e.time })
            if (-not $avSeen.Add("$threat|$t16")) { continue }
            $e = [pscustomobject]@{ id = $e.id; time = $e.time; blade = 'defender'; kind = 'malware'; severity = $e.severity; title = "Defender detected malware: $threat"
                                    threat = $threat; process = (Get-SigmaInfo $e).Image; detail = $e.detail; eventTime = $e.eventTime }
            $b = 'defender'
        }
        $bk = Find-Block $e
        if ($bk) { Add-ToMap $blockEv $bk.id $e; continue }
        $x = Find-Exclusion $e
        if ($x) { Add-ToMap $exclEv $x.id $e; continue }
        if ($b -eq 'defender' -and $e.kind -notin 'asr-audit', 'cfa-audit') { [void]$defBlocked.Add($e); continue }   # Defender already blocked it (audit = only reported: Detected)
        if ($e.kind -eq 'blocked-start') { continue }
        [void]$det[$BladeSection[$b]].Add($e)
    }

    # Detected: identical alerts collapsed into one row (x N)
    foreach ($sec in 'malware', 'edr', 'sigma') {
        foreach ($g in @($det[$sec] | Group-Object { if ($_.blade -eq 'sigma') { $sp = Get-SigmaInfo $_; "sigma|$($_.title)|$($sp.Image)|$($sp.Parent)" } else { "$($_.blade)|$($_.title)|$($_.process)|$($_.parent)" } })) {
            $members = @($g.Group | Sort-Object { [string]$_.time })
            Add-Row $m $sec 0 (New-EventRow $sec $members[-1] $members)
        }
    }

    # Blocked by the user
    foreach ($bk in @($script:Blocks)) {
        if (-not $bk) { continue }
        $hits = @(if ($blockEv.ContainsKey($bk.id)) { $blockEv[$bk.id] | Sort-Object { [string]$_.time } })   # @(): one hit must stay an array (.Count)
        $state = [string]$bk.note
        if ([int]$bk.hits) { $state += " Stopped $($bk.hits) time(s) since." }
        $r = $null
        switch ([string]$bk.blade) {
            'realtime' { $r = New-Row 'block' $bk.added '' @($bk.added, (Get-Leaf $bk.image), $bk.title, $state, $bk.image); $sec = 'edr' }
            'ioc'      { $r = New-Row 'block' $bk.added '' @($bk.added, $bk.title, (Get-Leaf $bk.image), $state, $bk.image); $sec = 'malware' }
            'yara'     { $r = New-Row 'block' $bk.added '' @($bk.added, $bk.title, (Get-Leaf $bk.image), $state, $bk.image); $sec = 'malware' }
            'sigma'    { $r = New-Row 'block' $bk.added '' @($bk.added, $bk.title, $hits.Count, $state); $sec = 'sigma' }
        }
        if (-not $r) { continue }
        $r.Entry = $bk; $r.Key = [string]$bk.id; $r.Group = $hits
        if ($hits.Count) { $r.Ev = $hits[-1] }
        Add-Row $m $sec 1 $r
    }

    # Blocked by Microsoft Defender (already handled; listed so it can be allowed)
    foreach ($g in @($defBlocked | Group-Object { "$($_.kind)|$($_.path)|$($_.process)|$($_.threat)" })) {
        $members = @($g.Group | Sort-Object { [string]$_.time })
        $rep = $members[-1]
        $title = [string]$rep.title
        if ($members.Count -gt 1) { $title += "   (x$($members.Count))" }
        $r = New-Row 'defender' $rep.time $rep.severity @($rep.time, $title, (Get-Leaf $rep.process), 'Blocked by Microsoft Defender', $(if ($rep.path) { $rep.path } else { $rep.detail }))
        $r.Ev = $rep; $r.Group = $members; $r.Key = [string]$rep.id
        Add-Row $m 'malware' 1 $r
    }

    # Allowed (exclusions)
    foreach ($p in $script:Excl.PSObject.Properties) {
        $sec = $ExclSection[$p.Name]
        if (-not $sec) { continue }
        foreach ($x in @($p.Value)) {
            if (-not $x) { continue }
            $text = Get-ExclText $p.Name $x
            if ($sec -eq 'cve') { $cols = @($x.added, $x.cve, $x.package) }
            elseif ($sec -eq 'wail2ban') { $cols = @($x.added, $x.cidr, $x.note) }
            elseif ($sec -eq 'sigma') { $cols = @($x.added, $x.title) }
            else { $cols = @($x.added, $text, (Get-ExclType $p.Name $x)) }
            $r = New-Row 'excl' $x.added '' $cols
            $r.Entry = $x; $r.ExclList = $p.Name; $r.Key = [string]$x.id; $r.Note = $text
            if ($exclEv.ContainsKey([string]$x.id)) { $r.Group = @($exclEv[[string]$x.id]) }
            Add-Row $m $sec 2 $r
        }
    }
    foreach ($bi in $script:BuiltIn) {
        $r = New-Row 'builtin' '' '' @('built-in', "Any program under $bi", 'Games / anti-cheat / EDR (Sysmon config)')
        $r.Key = "builtin-$bi"; $r.Note = "Any program under $bi"
        Add-Row $m 'edr' 2 $r
    }

    # Wail2Ban
    $bannedIp = @{}
    foreach ($b in @(@($(if ($script:Status) { $script:Status.wail2ban.banned })) | Where-Object { $_ })) { $bannedIp[[string]$b.ip] = $b }
    $perm = @{}
    foreach ($bk in @($script:Blocks | Where-Object { $_ -and $_.blade -eq 'wail2ban' -and $_.ip })) { $perm[[string]$bk.ip] = $bk }
    $lastBan = @{}
    foreach ($e in $banHist) { $k = [string]$e.ip; if (-not $lastBan.ContainsKey($k) -or [string]$e.time -gt [string]$lastBan[$k].time) { $lastBan[$k] = $e } }
    foreach ($g in @($fails | Group-Object { [string]$_.ip })) {
        $ip = $g.Name
        if ($bannedIp.ContainsKey($ip) -or $perm.ContainsKey($ip)) { continue }
        if (Find-Exclusion $g.Group[0]) { continue }
        $since = if ($lastBan.ContainsKey($ip)) { [string]$lastBan[$ip].time } else { '' }
        $members = @($g.Group | Where-Object { [string]$_.time -gt $since } | Sort-Object { [string]$_.time })
        if (-not $members.Count) { continue }
        $rep = $members[-1]
        $r = New-Row 'fail' $rep.time 'Low' @($rep.time, $ip, "$($members.Count) failed logon$(if ($members.Count -ne 1) { 's' })", (Get-NetLabel $ip))
        $r.Ev = $rep; $r.Group = $members; $r.Key = "fail-$ip"
        $r.Muted = -not @($members | Where-Object { -not (Test-Reviewed $_) }).Count
        Add-Row $m 'wail2ban' 0 $r
    }
    # Successful logins from the internet (one row per address and user)
    foreach ($g in @($logins | Group-Object { "$($_.ip)|$($_.user)" })) {
        $members = @($g.Group | Sort-Object { [string]$_.time })
        $rep = $members[-1]
        if ($perm.ContainsKey([string]$rep.ip) -or (Find-Exclusion $rep)) { continue }
        Add-Row $m 'wail2ban' 0 (New-EventRow 'wail2ban' $rep $members)
    }
    foreach ($ip in @(@($bannedIp.Keys) + @($perm.Keys) | Select-Object -Unique)) {
        $b = $bannedIp[$ip]; $bk = $perm[$ip]; $ev = $lastBan[$ip]
        $since = if ($bk) { [string]$bk.added } elseif ($ev) { [string]$ev.time } else { '' }
        $until = if ($bk) { 'Permanent' } elseif ($b) { [string]$b.expires } else { '' }
        $how = if ($bk) { 'By you (permanent)' } else { 'Automatic (failed logons)' }
        $r = New-Row 'ban' $since '' @($since, $ip, $until, $(if ($b) { $b.strikes } else { '' }), (Get-NetLabel $ip), $how)
        $r.Entry = $bk; $r.Ban = $b; $r.Key = "ban-$ip"
        $r.Ev = if ($ev) { $ev } else { [pscustomobject]@{ blade = 'wail2ban'; ip = $ip; title = "Blocked $ip"; time = $since } }
        Add-Row $m 'wail2ban' 1 $r
    }
    foreach ($ip in @($lastBan.Keys)) {
        if ($bannedIp.ContainsKey($ip) -or $perm.ContainsKey($ip)) { continue }
        $ev = $lastBan[$ip]
        if (Find-Exclusion $ev) { continue }
        $r = New-Row 'banhist' $ev.time '' @($ev.time, $ip, "Expired ($($ev.expires))", $ev.strike, (Get-NetLabel $ip), 'Automatic - expired')
        $r.Ev = $ev; $r.Muted = $true; $r.Key = "hist-$ip"
        Add-Row $m 'wail2ban' 1 $r
    }

    # CVE: the latest scan, only packages with a released fix (the scan drops the rest)
    $scanned = [datetime]::MinValue
    if ($script:Cve -and $script:Cve.scanned) { try { $scanned = [datetime]$script:Cve.scanned } catch { } }
    foreach ($v in @($(if ($script:Cve) { $script:Cve.items }) | Where-Object { $_ })) {
        if (Find-CveExclusion $v) { continue }
        if (Test-UpdatedSince 'cve' ([string]$v.id) $scanned) { continue }
        $r = New-Row 'cve' (Format-When $script:Cve.scanned 'yyyy-MM-dd HH:mm:ss') $v.severity @((Format-Sev $v.severity), $v.cve, $v.package, $v.version, $v.fixed, (Get-Short $v.summary 200))
        $r.Entry = $v; $r.Key = "cve-$($v.id)-$($v.path)"
        Add-Row $m 'cve' 0 $r
    }

    # App updates (winget)
    $checked = if ($script:PatchChecked) { $script:PatchChecked } else { [datetime]::MinValue }
    foreach ($p in @($script:PatchEvents)) {
        if ($script:Ignored.Contains([string]$p.appId)) { continue }
        if (Test-UpdatedSince 'apps' ([string]$p.appId) $checked) { continue }
        $r = New-Row 'app' $p.time 'Info' @($p.process, $p.version, $p.latest, $p.appId)
        $r.Entry = $p; $r.Ev = $p; $r.Key = "app-$($p.appId)"
        Add-Row $m 'apps' 0 $r
    }
    foreach ($id in @($script:Ignored)) {
        $r = New-Row 'hidden' '' '' @($id)
        $r.Entry = [string]$id; $r.Key = "hidden-$id"
        Add-Row $m 'apps' 2 $r
    }

    # Updates started from the dashboard (CVE + apps)
    foreach ($hx in @($script:History)) {
        if (-not $hx) { continue }
        if ($hx.sec -eq 'cve') { $r = New-Row 'hist' $hx.time '' @($hx.time, $hx.cve, $hx.package, $hx.version, $hx.fixed) }
        elseif ($hx.sec -eq 'apps') { $r = New-Row 'hist' $hx.time '' @($hx.time, $hx.name, $hx.version, $hx.latest) }
        else { continue }
        $r.Entry = $hx; $r.Key = [string]$hx.id
        Add-Row $m ([string]$hx.sec) 1 $r
    }

    # Newest first; the CVE list worst first
    foreach ($s in $SectionOrder) {
        for ($i = 0; $i -lt 3; $i++) {
            if ($s -eq 'cve' -and $i -eq 0) {
                $m[$s].Rows[$i] = @($m[$s].Rows[$i] | Sort-Object @{ e = { $SeverityRank[[string]$_.Sev] }; Descending = $true }, @{ e = { [string]$_.Entry.package } })
            } else {
                $m[$s].Rows[$i] = @($m[$s].Rows[$i] | Sort-Object @{ e = { $_.Pinned -and -not $_.Muted }; Descending = $true }, @{ e = { [string]$_.Time }; Descending = $true })
            }
        }
    }

    # Counts: the tab shows how many open items; red only for security items that need a decision
    $att = 0; $pin = 0
    foreach ($s in $SectionOrder) {
        $open = @($m[$s].Rows[0] | Where-Object { -not $_.Muted })
        $serious = @($open | Where-Object { $s -eq 'cve' -or $SeverityRank[[string]$_.Sev] -ge 2 }).Count
        $m[$s].Count = $open.Count
        $m[$s].Alert = $Sections[$s].Security -and $serious -gt 0
        if ($s -in 'malware', 'edr', 'sigma', 'wail2ban') { $m[$s].Attention = $serious; $att += $serious }
        $pin += @($open | Where-Object { $_.Pinned }).Count
    }

    $msgs = @($sys | Sort-Object { [string]$_.time } -Descending | Select-Object -First 300 | ForEach-Object {
        $r = New-Row 'sys' $_.time $_.severity @($_.time, $_.title, (Get-Short $_.detail 200))
        $r.Ev = $_; $r.Key = [string]$_.id; $r.Sec = 'overview'
        $r
    })
    $script:Model = @{ Sec = $m; Messages = $msgs; Attention = $att; Pinned = $pin; Claude = $claude }
    $script:ModelDirty = $false
    $script:ViewDirty = $true
}

# One sentence that tells the user what matters right now
function Get-Overall {
    $st = $script:Status
    if (-not (Test-EngineAlive)) {
        return @{ Key = 'down'; Text = 'Protection is OFF - EDR engine is not running'; Sub = 'Right-click the tray shield > Advanced > Restart engine, or restart the PC.' }
    }
    $edr = Get-PauseState 'edr'
    $problems = @()
    if (-not $st.sysmon.ok)            { $problems += "Sysmon sensor: $($st.sysmon.message)" }
    if ($edr.state -eq 'error')        { $problems += "EDR: $($edr.error)" }
    if ($st.wail2ban.state -eq 'error') { $problems += "Wail2Ban: $($st.wail2ban.error)" }
    if ($problems.Count) { return @{ Key = 'down'; Text = 'Protection has a problem'; Sub = ($problems -join '  |  ') } }

    $model = $script:Model
    $att = if ($model) { $model.Attention } else { 0 }
    if ($model -and $model.Pinned) {
        return @{ Key = 'attention'; Text = "Please confirm $($model.Pinned) item$(if ($model.Pinned -ne 1) { 's' }): was this you?"; Sub = 'Logins from the internet, cleared logs or account changes - shown on top of the Detected lists. Answer Yes (it was me) or No (it was not me).' }
    }
    $cve = if ($model) { $model.Sec.cve.Count } else { 0 }
    $paused = @()
    if ($edr.state -eq 'paused')         { $paused += "EDR is paused $(Format-Until $edr)" }
    else {
        # One part paused on its own also shows as paused (grey shield), not as "You're protected"
        foreach ($b in 'realtime', 'malware', 'sigma', 'cve') {
            $bs = $st.$b
            if ($bs -and $bs.state -eq 'paused') { $paused += "$($PauseLabels[$b]) is paused $(Format-Until $bs)" }
        }
    }
    if ($st.wail2ban.state -eq 'paused') { $paused += "Wail2Ban is paused $(Format-Until $st.wail2ban)" }
    if ($att -gt 0) {
        $parts = @(foreach ($s in 'malware', 'edr', 'sigma') { $n = $model.Sec[$s].Attention; if ($n) { "$($Sections[$s].Name): $n" } })
        $sub = ($parts -join ',  ') + '.  Open the tab, click an item, then Allow it or flag it.'
        if ($paused.Count) { $sub = ($paused -join '; ') + '. ' + $sub }
        return @{ Key = 'attention'; Text = "$att item$(if ($att -ne 1) { 's' }) need$(if ($att -eq 1) { 's' }) your review"; Sub = $sub }
    }
    if ($paused.Count) { return @{ Key = 'paused'; Text = 'Protection partly paused'; Sub = ($paused -join '; ') + '.' } }
    if ($st.scan.ok -eq $false) { return @{ Key = 'attention'; Text = 'Last scan had problems'; Sub = [string]$st.scan.summary } }
    $sub = "Nothing needs your attention. Last update: $(Format-When $st.scan.lastEnd 'ddd HH:mm'). Next: $(Format-When $st.scan.nextDue 'ddd HH:mm')."
    if ($cve) { $sub += "  $cve security update$(if ($cve -ne 1) { 's' }) waiting in the CVE tab." }
    return @{ Key = 'ok'; Text = "You're protected"; Sub = $sub }
}

################################################################################
# Icons

$Palette = @{
    ok        = [Drawing.Color]::FromArgb(46, 125, 50)
    attention = [Drawing.Color]::FromArgb(230, 145, 0)
    paused    = [Drawing.Color]::FromArgb(110, 110, 110)
    down      = [Drawing.Color]::FromArgb(198, 40, 40)
}
$PaletteLight = @{
    ok        = [Drawing.Color]::FromArgb(232, 245, 233)
    attention = [Drawing.Color]::FromArgb(255, 243, 224)
    paused    = [Drawing.Color]::FromArgb(238, 238, 238)
    down      = [Drawing.Color]::FromArgb(255, 235, 238)
}
$RowColors = @{
    blockedBack = [Drawing.Color]::FromArgb(253, 236, 234); blockedFore = [Drawing.Color]::FromArgb(140, 30, 30)
    allowedBack = [Drawing.Color]::FromArgb(237, 247, 238); allowedFore = [Drawing.Color]::FromArgb(30, 90, 40)
    doneBack    = [Drawing.Color]::FromArgb(240, 246, 252); doneFore    = [Drawing.Color]::FromArgb(30, 60, 110)
    muted       = [Drawing.Color]::FromArgb(130, 130, 130)
}

function New-ShieldIcon([Drawing.Color]$Color, [string]$Glyph) {
    $bmp = New-Object Drawing.Bitmap 32, 32
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'; $g.TextRenderingHint = 'AntiAliasGridFit'
    $pts = [Drawing.Point[]]@(
        (New-Object Drawing.Point 16, 1), (New-Object Drawing.Point 30, 5), (New-Object Drawing.Point 29, 17),
        (New-Object Drawing.Point 16, 31), (New-Object Drawing.Point 3, 17), (New-Object Drawing.Point 2, 5))
    $g.FillPolygon((New-Object Drawing.SolidBrush $Color), $pts)
    $g.DrawPolygon((New-Object Drawing.Pen ([Drawing.Color]::FromArgb(160, 0, 0, 0)), 1), $pts)
    $f = New-Object Drawing.Font('Segoe UI', 13, [Drawing.FontStyle]::Bold, [Drawing.GraphicsUnit]::Pixel)
    $sf = New-Object Drawing.StringFormat; $sf.Alignment = 'Center'; $sf.LineAlignment = 'Center'
    $g.DrawString($Glyph, $f, [Drawing.Brushes]::White, (New-Object Drawing.RectangleF 0, 0, 32, 30), $sf)
    $g.Dispose()
    $h = $bmp.GetHicon()
    $icon = [Drawing.Icon]::FromHandle($h).Clone()
    [void][EdrNative.Win]::DestroyIcon($h)
    return $icon
}

$Icons = @{
    ok        = New-ShieldIcon $Palette.ok ([string][char]0x2713)
    attention = New-ShieldIcon $Palette.attention '!'
    paused    = New-ShieldIcon $Palette.paused 'II'
    down      = New-ShieldIcon $Palette.down 'X'
}

################################################################################
# Notifications (held back while a "quiet" app such as Fortnite runs)

function Test-QuietApp {
    foreach ($n in @($script:Cfg.quietProcesses)) { if (Get-Process -Name $n -ErrorAction SilentlyContinue) { return $true } }
    return $false
}

function Show-Toast([string]$Title, [string]$Text, [string]$Level = 'Info', [string]$TargetId = $null) {
    if ($SelfTest) { return }
    $script:ToastTarget = $TargetId
    if ($Title.Length -gt 63) { $Title = $Title.Substring(0, 60) + '...' }
    if ($Text.Length -gt 250) { $Text = $Text.Substring(0, 247) + '...' }
    $icon = switch ($Level) { 'Error' { [Windows.Forms.ToolTipIcon]::Error } 'Warning' { [Windows.Forms.ToolTipIcon]::Warning } default { [Windows.Forms.ToolTipIcon]::Info } }
    $script:Tray.ShowBalloonTip(10000, $Title, $Text, $icon)
}

function Invoke-Notify($e) {
    $rank = Get-Rank $e
    $toast = $false
    if ($e.blade -in @('realtime', 'ioc', 'yara', 'sigma', 'defender') -and $rank -ge 3) { $toast = $true }
    if ($e.kind -eq 'blocked-start') { $toast = $true }
    if ($e.blade -eq 'wail2ban' -and $rank -ge 2) { $toast = $true }
    if ($e.blade -eq 'system' -and ($e.kind -eq 'health' -or ($e.kind -eq 'scan' -and ($e.trigger -eq 'manual' -or $rank -ge 2 -or $e.newSigma -gt 0)))) { $toast = $true }
    if (-not $toast) { return }
    if (Test-QuietApp) { [void]$script:Queued.Add($e); return }
    $proc = Get-Leaf $e.process
    $body = if ($proc) { "$proc`n" } else { '' }
    $body += if ($e.blade -eq 'system') { [string]$e.detail } else { 'Click to see what it means and what to do.' }
    $lvl = if ($rank -ge 3) { 'Warning' } else { 'Info' }
    if ($e.severity -eq 'Critical' -or ($e.blade -eq 'system' -and $rank -ge 3)) { $lvl = 'Error' }
    Show-Toast ([string]$e.title) $body $lvl ([string]$e.id)
}

function Send-QueuedToasts {
    if (-not $script:Queued.Count) { return }
    if ((Get-Date) - $script:LastQuietCheck -lt [TimeSpan]::FromSeconds(10)) { return }
    $script:LastQuietCheck = Get-Date
    if (Test-QuietApp) { return }
    $n = $script:Queued.Count
    $crit = @($script:Queued | Where-Object { (Get-Rank $_) -ge 3 }).Count
    $script:Queued.Clear()
    Show-Toast "While you were gaming: $n alert$(if ($n -ne 1) { 's' })" "$crit high/critical. Click to review." $(if ($crit) { 'Warning' } else { 'Info' })
}

################################################################################
# Commands

function Send-AdminCommand([hashtable]$Cmd) {
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($Cmd | ConvertTo-Json -Compress -Depth 6)))
    # The request travels on the command line (Windows limit about 32,000 characters)
    if ($b64.Length -gt 30000) {
        [void][Windows.Forms.MessageBox]::Show('Too many items selected for one change. Select fewer items (for example 50) and try again. Nothing was changed.', $ProductName, 'OK', 'Warning')
        return $false
    }
    try {
        $p = Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -PassThru -ArgumentList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', "`"$Root\EDR-Control.ps1`"", '-Payload', $b64)
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while (-not $p.HasExited -and $sw.ElapsedMilliseconds -lt 15000) {
            [Windows.Forms.Application]::DoEvents()
            [Threading.Thread]::Sleep(50)
        }
        if (-not $p.HasExited) {
            try { $p.Kill() } catch { }
            [void][Windows.Forms.MessageBox]::Show('Timed out waiting for administrator approval. Nothing was changed.', $ProductName, 'OK', 'Warning')
            return $false
        }
        if ($p.ExitCode -ne 0) {
            return $false
        }
        return $true
    } catch {
        [void][Windows.Forms.MessageBox]::Show('Cancelled - Windows administrator approval was not given. Nothing was changed.', $ProductName, 'OK', 'Information')
        return $false
    }
}

function Send-UserCommand([hashtable]$Cmd) {
    $tmp = Join-Path $InboxDir ("{0}-{1}.tmp" -f (Get-Date -Format 'yyyyMMddHHmmssfff'), [guid]::NewGuid().ToString('N').Substring(0, 6))
    try {
        $final = [IO.Path]::ChangeExtension($tmp, '.json')
        [IO.File]::WriteAllText($tmp, ($Cmd | ConvertTo-Json -Compress), $Utf8NoBom)
        [IO.File]::Move($tmp, $final)
        return $true
    } catch {
        Write-TrayLog "inbox request failed ($($_.Exception.Message)) - asking for administrator approval instead"
        try { [IO.File]::Delete($tmp) } catch { }   # the engine also removes leftovers after 2 minutes
        return (Send-AdminCommand $Cmd)
    }
}

function Confirm-Action([string]$Text) {
    return ([Windows.Forms.MessageBox]::Show($Text, 'EDR - confirm', 'YesNo', 'Question') -eq 'Yes')
}

function Show-Info([string]$Text) { [void][Windows.Forms.MessageBox]::Show($Text, $ProductName, 'OK', 'Information') }

# Several engine steps (e.g. unblock + allow) behind one confirmation and one UAC prompt
function Send-Ops($Ops, [string]$Question) {
    $seen = @{}; $list = @()
    foreach ($o in @($Ops)) {
        if (-not $o) { continue }
        $k = (($o.Keys | Sort-Object | ForEach-Object { "$_=$($o[$_])" }) -join ';')
        if (-not $seen.ContainsKey($k)) { $seen[$k] = 1; $list += , $o }
    }
    if (-not $list.Count) { return $false }
    if (-not (Confirm-Action ($Question + "`n`nWindows will ask for administrator approval."))) { return $false }
    $cmd = if ($list.Count -eq 1) { $list[0] } else { @{ action = 'batch'; ops = $list } }
    if (Send-AdminCommand $cmd) { Show-Toast 'Done' 'The lists update within a few seconds.'; return $true }
    return $false
}

$PauseLabels = @{
    edr      = 'EDR Master Protection'
    realtime = 'Real-Time EDR'
    malware  = 'Anti-Malware'
    sigma    = 'Sigma Event-Log Scan'
    cve      = 'CVE Vulnerability Scan'
    wail2ban = 'Wail2Ban'
}

$PauseScopeDescriptions = @{
    malware  = 'Pauses IOC malware hashes and YARA rules file inspections. Real-time Sysmon process tracking, firewall bans, and Defender remain active.'
    realtime = 'Pauses real-time Sysmon process tracking and live blocklist enforcement. Scans, firewall rules, and Defender remain active.'
    edr      = 'Master switch: Pauses all real-time EDR detection, blocking, YARA, IOC, Sigma, and CVE scans. Defender remains active.'
    sigma    = 'Pauses scheduled and manual Hayabusa event-log scans. Real-time EDR, Anti-Malware, and Wail2Ban remain active.'
    cve      = 'Pauses OSV vulnerability checks of Python packages. All other protections remain active.'
    wail2ban = 'Pauses tracking failed logons and new firewall bans. Existing bans stay until expiration.'
}

function Invoke-Pause([string]$Blade, [int]$Minutes) {
    $what = if ($PauseLabels.ContainsKey($Blade)) { $PauseLabels[$Blade] } else { $Blade }
    $scope = if ($PauseScopeDescriptions.ContainsKey($Blade)) { $PauseScopeDescriptions[$Blade] } else { '' }
    $how = if ($Minutes -gt 0) { "for $Minutes minutes" } else { 'until you resume it' }
    if ($Minutes -eq 0 -and -not (Confirm-Action "Pause $what $how?`n`nScope: $scope`n`nMicrosoft Defender keeps protecting you either way.")) { return }
    if (Send-AdminCommand @{ action = 'pause'; blade = $Blade; minutes = $Minutes; user = $env:USERNAME }) {
        Show-Toast "$what paused" "Paused $how. Right-click the tray shield to resume."
    }
}

function Invoke-Resume([string]$Blade) {
    # Paused only through the master switch: resuming this one part alone would change nothing
    $own = if ($script:Status) { $script:Status.$Blade } else { $null }
    $masterPaused = $script:Status -and $script:Status.edr -and $script:Status.edr.state -eq 'paused'
    if ($Blade -ne 'edr' -and $Blade -in @('realtime', 'malware', 'sigma', 'cve') -and $masterPaused -and -not ($own -and $own.state -eq 'paused')) {
        if (-not (Confirm-Action "$($PauseLabels[$Blade]) is paused by the master switch (all EDR).`n`nResume all EDR protections now?")) { return }
        $Blade = 'edr'
    }
    $what = if ($PauseLabels.ContainsKey($Blade)) { $PauseLabels[$Blade] } else { $Blade }
    if (Send-UserCommand @{ action = 'resume'; blade = $Blade; user = $env:USERNAME }) {
        Show-Toast "$what resumed" "$what is active again within a few seconds."
    }
}

function Invoke-ScanNow {
    if ($script:Status -and $script:Status.scan.running) { Show-Toast 'Update already running' 'You will get a notification when it finishes.'; return }
    if ((Get-PauseState 'edr').state -eq 'paused') { Show-Toast 'EDR is paused' 'Resume EDR protection first.'; return }
    if (Send-UserCommand @{ action = 'scan-now' }) { Show-Toast 'Update started' 'Malware hashes, Sigma rules + event logs and the CVE check run in the background. You will be notified when it finishes.' }
}

# claude-code\2.1.309\9078b9c1d466\claude.exe -> claude-code\*\*\claude.exe (survives app updates)
function Get-VersionlessPattern([string]$Path) {
    $parts = foreach ($p in $Path.Split('\')) {
        if ($p -match '^v?\d+(\.\d+)+$' -or $p -match '^[0-9a-fA-F]{8,}$' -or $p -match '^app-\d') { '*' } else { [Management.Automation.WildcardPattern]::Escape($p) }
    }
    return ($parts -join '\')
}
function Get-ExactPattern([string]$Path) { [Management.Automation.WildcardPattern]::Escape($Path) }

function Get-GeminiPrompt([string]$Id) { return ($GeminiTemplate -f $Id) }

function Invoke-GeminiCli([string]$Id) {
    if (-not (Get-Command gemini -ErrorAction SilentlyContinue)) { Invoke-GeminiWeb $Id; return }
    $safeId = $Id -replace '[^a-zA-Z0-9_\-\.:]', ''
    $p = (Get-GeminiPrompt $safeId).Replace("'", "''")
    # Plain -Command, not -EncodedCommand: an encoded command line would trip the "Encoded PowerShell" rule
    $cmdText = "Set-Location `$env:USERPROFILE; `$host.UI.RawUI.WindowTitle = 'Gemini - $safeId'; gemini -i '$p'"
    $shell = if (Get-Command pwsh -ErrorAction SilentlyContinue) { 'pwsh.exe' } else { 'powershell.exe' }
    Start-Process $shell -ArgumentList @('-NoExit', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $cmdText)
}

function Invoke-GeminiWeb([string]$Id) {
    [Windows.Forms.Clipboard]::SetText((Get-GeminiPrompt $Id))
    Start-Process 'https://gemini.google.com/app'
    Show-Toast 'Prompt copied' "Paste it into Gemini with Ctrl+V ($Id)."
}

function Start-Terminal([string]$Command) {
    $shell = if (Get-Command pwsh -ErrorAction SilentlyContinue) { 'pwsh.exe' } else { 'powershell.exe' }
    Start-Process $shell -ArgumentList @('-NoExit', '-NoProfile', '-Command', $Command)
}

################################################################################
# Verdicts: Detected -> Blocked -> Allowed, and back

function Get-RowEvents($Rows) {
    foreach ($r in @($Rows)) { if (@($r.Group).Count) { $r.Group } elseif ($r.Ev -and $r.Ev.id) { $r.Ev } }
}

function Get-RowName($Row) {
    switch ($Row.Kind) {
        'excl'    { return $Row.Note }
        'builtin' { return $Row.Note }
        'block'   { if ($Row.Entry.image) { return [string]$Row.Entry.image } elseif ($Row.Entry.ip) { return [string]$Row.Entry.ip } else { return [string]$Row.Entry.title } }
        'cve'     { return "$($Row.Entry.cve) in $($Row.Entry.package) $($Row.Entry.version)" }
        'hist'    { if ($Row.Entry.cve) { return "$($Row.Entry.cve) in $($Row.Entry.package)" } else { return [string]$Row.Entry.name } }
        'hidden'  { return [string]$Row.Entry }
        'app'     { return [string]$Row.Entry.process }
    }
    $e = $Row.Ev
    if ($e.ip) { return [string]$e.ip }
    if ($e.process -and $e.blade -ne 'sigma') { return "$($e.process)  ($($e.title))" }
    return [string]$e.title
}

function Format-NameList($Names) {
    $u = @($Names | Where-Object { $_ } | Select-Object -Unique)
    $txt = ($u | Select-Object -First 8 | ForEach-Object { "  - $_" }) -join "`n"
    if ($u.Count -gt 8) { $txt += "`n  ... and $($u.Count - 8) more" }
    return $txt
}

function Get-BlockOp($e) {
    if (-not $e) { return $null }
    $b = [string]$e.blade
    if ($b -in 'realtime', 'ioc', 'yara') {
        if ($e.process -and [IO.Path]::IsPathRooted([string]$e.process)) { return @{ action = 'block'; blade = $b; image = [string]$e.process; sha256 = [string]$e.sha256; title = [string]$e.title } }
        return $null
    }
    if ($b -eq 'sigma') { return @{ action = 'block'; blade = 'sigma'; title = [string]$e.title } }
    if ($b -eq 'wail2ban' -and $e.ip) { return @{ action = 'block'; blade = 'wail2ban'; ip = [string]$e.ip } }
    return $null
}

function Get-AllowOp($e, [string]$Variant = 'default') {
    if (-not $e) { return $null }
    $p = [string]$e.process
    switch ([string]$e.blade) {
        'realtime' {
            if ($Variant -eq 'parent' -and $e.parent) { return @{ action = 'exclude'; blade = 'realtime'; rule = '*'; image = ''; parent = (Get-VersionlessPattern ([string]$e.parent)); parentSigner = (Get-ParentSigner ([string]$e.parent)) } }
            if ($Variant -eq 'signer') {
                $sg = Get-TraySigner $p
                if ($sg -and $sg -notin $UnsafeSigners) { return @{ action = 'exclude'; blade = 'realtime'; rule = '*'; image = ''; parent = ''; signer = $sg } }
                return $null
            }
            if (-not $p) { return $null }
            $rule = if ($Variant -eq 'rule' -and $e.rule) { [string]$e.rule } else { '*' }
            return @{ action = 'exclude'; blade = 'realtime'; rule = $rule; image = (Get-ExactPattern $p); raw = $p }
        }
        'ioc'   { if ($e.sha256) { return @{ action = 'exclude'; blade = 'ioc'; sha256 = [string]$e.sha256; image = $p } } }
        'yara'  { if ($p) { return @{ action = 'exclude'; blade = 'yara'; image = (Get-ExactPattern $p); raw = $p } } }
        'sigma' {
            $par = (Get-SigmaInfo $e).Parent
            if ($Variant -eq 'parent' -and $par) { return @{ action = 'exclude'; blade = 'sigma'; title = '*'; parent = (Get-VersionlessPattern $par); parentSigner = (Get-ParentSigner $par) } }
            return @{ action = 'exclude'; blade = 'sigma'; title = [string]$e.title }
        }
        'wail2ban' {
            if (-not $e.ip) { return $null }
            $c = [string]$e.ip
            if ($Variant -eq 'net' -and $c -match '^(\d+\.\d+\.\d+)\.\d+$') { $c = "$($matches[1]).0/24" }
            return @{ action = 'exclude'; blade = 'wail2ban'; cidr = $c; note = 'added from dashboard' }
        }
        'defender' {
            switch ([string]$e.kind -replace '-audit$') {
                'asr'     { return @{ action = 'exclude'; blade = 'defender'; kind = 'asr'; path = $(if ($e.path) { [string]$e.path } else { $p }) } }
                'cfa'     { if ($p) { return @{ action = 'exclude'; blade = 'defender'; kind = 'cfa'; path = $p } } }
                'malware' { if ($e.threatId) { return @{ action = 'exclude'; blade = 'defender'; kind = 'threat'; path = [string]$e.threatId; note = [string]$e.threat } } }
            }
        }
    }
    return $null
}

function Get-AllowOpFromBlock($b) {
    switch ([string]$b.blade) {
        'realtime' { return @{ action = 'exclude'; blade = 'realtime'; rule = '*'; image = (Get-ExactPattern ([string]$b.image)); raw = [string]$b.image } }
        'ioc' {
            if ($b.sha256) { return @{ action = 'exclude'; blade = 'ioc'; sha256 = [string]$b.sha256; image = [string]$b.image } }
            return @{ action = 'exclude'; blade = 'yara'; image = (Get-ExactPattern ([string]$b.image)); raw = [string]$b.image }
        }
        'yara'     { return @{ action = 'exclude'; blade = 'yara'; image = (Get-ExactPattern ([string]$b.image)); raw = [string]$b.image } }
        'sigma'    { return @{ action = 'exclude'; blade = 'sigma'; title = [string]$b.title } }
        'wail2ban' { return @{ action = 'exclude'; blade = 'wail2ban'; cidr = [string]$b.ip; note = 'added from dashboard' } }
    }
    return $null
}

# Allowed -> Blocked needs a concrete program path or address (a wildcard or folder cannot be blocked)
function Get-BlockOpFromExcl($Row) {
    $x = $Row.Entry
    switch ($Row.ExclList) {
        { $_ -in 'realtime', 'yara' } {
            $raw = if ($x.raw) { [string]$x.raw } elseif ($x.image -and $x.image -notmatch '(?<!`)[*?\[]') { [Management.Automation.WildcardPattern]::Unescape([string]$x.image) } else { $null }
            if ($raw) { return @{ action = 'block'; blade = $Row.ExclList; image = $raw; title = 'Blocked from the Allowed list' } }
        }
        'ioc'      { if ($x.image) { return @{ action = 'block'; blade = 'ioc'; image = [string]$x.image; sha256 = [string]$x.sha256; title = 'Known malware hash' } } }
        'sigma'    { if ($x.title -and $x.title -ne '*') { return @{ action = 'block'; blade = 'sigma'; title = [string]$x.title } } }
        'wail2ban' { if ([string]$x.cidr -notmatch '/') { return @{ action = 'block'; blade = 'wail2ban'; ip = [string]$x.cidr } } }
    }
    return $null
}

# The parent's exclusions in both EDR and Sigma ("Allow everything started by claude.exe, everywhere")
function Get-ParentAllowOps([string]$Parent) {
    $pat = Get-VersionlessPattern $Parent
    return @(
        @{ action = 'exclude'; blade = 'realtime'; rule = '*'; image = ''; parent = $pat; parentSigner = (Get-ParentSigner $Parent) },
        @{ action = 'exclude'; blade = 'sigma'; title = '*'; parent = $pat; parentSigner = (Get-ParentSigner $Parent) }
    )
}

# ---- Trusted apps (profiles from EDR-Common.ps1) -----------------------------
# A profile is on while exclusions tagged with its id exist; switching it off removes exactly those, so every app can
# be trusted and distrusted again at any time (tray > Trusted apps, or Overview > Trusted apps).
function Test-ProfileOn([string]$Id) {
    foreach ($l in 'realtime', 'sigma') { if (@($script:Excl.$l | Where-Object { $_ -and $_.profile -eq $Id }).Count) { return $true } }
    return $false
}

# Would this one profile entry hide the event? (the same matching as Find-Exclusion)
function Test-ProfileEntryMatch($Entry, $e) {
    $x = [pscustomobject]$Entry
    if ($Entry.list -eq 'realtime' -and $e.blade -eq 'realtime') {
        if ($x.rule -and $x.rule -ne '*' -and $x.rule -ne [string]$e.rule) { return $false }
        if ($x.image -and -not ([string]$e.process -like $x.image)) { return $false }
        if ($x.detail -and -not ([string]$e.detail -like $x.detail)) { return $false }
        if ($x.parent -and -not (Test-TrayParentMatch $x (@([string]$e.parent) + @($e.ancestors)))) { return $false }
        if ($x.signer -and (Get-TraySigner ([string]$e.process)) -ne $x.signer) { return $false }
        return [bool]($x.image -or $x.parent -or $x.signer -or $x.detail)
    }
    if ($Entry.list -eq 'sigma' -and $e.blade -eq 'sigma') {
        if ($x.title -and $x.title -ne '*' -and $x.title -ne [string]$e.title) { return $false }
        if ($x.parent -and -not (Test-TrayParentMatch $x @((Get-SigmaInfo $e).Parent))) { return $false }
        return [bool]($x.parent -or ($x.title -and $x.title -ne '*'))
    }
    return $false
}

# The first profile that is off and would hide this alert ("Trust the whole app" action)
function Find-ProfileFor($e) {
    if (-not $e) { return $null }
    foreach ($p in $AllowProfiles) {
        if (Test-ProfileOn $p.id) { continue }
        foreach ($en in $p.entries) { if (Test-ProfileEntryMatch $en $e) { return $p } }
    }
    return $null
}

# Switch profiles on/off (@{ id = $true/$false }) behind one confirmation and one UAC prompt
function Set-ProfileStates([hashtable]$Want) {
    $ops = @(); $on = @(); $off = @()
    foreach ($id in $Want.Keys) {
        $p = Get-AllowProfile $id; if (-not $p) { continue }
        $isOn = Test-ProfileOn $id
        if ($Want[$id] -and -not $isOn) { $ops += @(Get-ProfileOps $p); $on += $p.name }
        elseif (-not $Want[$id] -and $isOn) {
            foreach ($l in 'realtime', 'sigma') { foreach ($x in @($script:Excl.$l | Where-Object { $_ -and $_.profile -eq $id })) { $ops += @{ action = 'unexclude'; id = [string]$x.id } } }
            $off += $p.name
        }
    }
    if (-not $ops.Count) { return $false }
    $q = ''
    if ($on.Count)  { $q += "Trust (no more alerts from their normal work):`n$(Format-NameList $on)`n`n" }
    if ($off.Count) { $q += "Stop trusting (alerts are shown again):`n$(Format-NameList $off)`n`n" }
    $q += 'You can change this again at any time: tray > Trusted apps.'
    $ok = Send-Ops $ops $q.Trim()
    if ($ok) { Request-Refresh }
    return $ok
}

function Show-TrustedApps {
    $f = New-Object Windows.Forms.Form
    $f.Text = "$ProductName - Trusted apps"; $f.Size = New-Object Drawing.Size 720, 640; $f.MinimumSize = New-Object Drawing.Size 560, 420
    $f.StartPosition = 'CenterScreen'; $f.Font = $Fonts.Base; $f.BackColor = [Drawing.Color]::White; $f.Icon = $Icons.ok
    $top = New-Object Windows.Forms.Label; $top.Dock = 'Top'; $top.Height = 74; $top.Padding = New-Object Windows.Forms.Padding 14, 12, 14, 0
    $top.Text = "Apps you trust run without alerts for their normal work. Everything else they do is still checked.`nTick an app to trust it, untick it to see its alerts again. You can come back here at any time (tray > Trusted apps)."
    $list = New-Object Windows.Forms.FlowLayoutPanel; $list.Dock = 'Fill'; $list.FlowDirection = 'TopDown'; $list.WrapContents = $false; $list.AutoScroll = $true
    $list.Padding = New-Object Windows.Forms.Padding 14, 0, 14, 0
    $boxes = @{}
    foreach ($p in $AllowProfiles) {
        $found = Test-ProfileInstalled $p
        $cb = New-Object Windows.Forms.CheckBox; $cb.AutoSize = $true; $cb.Font = $Fonts.Bold; $cb.UseMnemonic = $false
        $cb.Text = "$($p.name)$(if (-not $found) { '   (not found on this PC)' } elseif ($p.default) { '   (recommended)' })"
        $cb.Checked = Test-ProfileOn $p.id; $cb.Margin = New-Object Windows.Forms.Padding 0, 10, 0, 0
        $d = New-Object Windows.Forms.Label; $d.Text = $p.what; $d.MaximumSize = New-Object Drawing.Size 640, 0; $d.AutoSize = $true
        $d.ForeColor = [Drawing.Color]::FromArgb(90, 90, 90); $d.Margin = New-Object Windows.Forms.Padding 20, 0, 0, 0; $d.UseMnemonic = $false
        [void]$list.Controls.Add($cb); [void]$list.Controls.Add($d)
        $boxes[$p.id] = $cb
    }
    $bar = New-Object Windows.Forms.FlowLayoutPanel; $bar.Dock = 'Bottom'; $bar.Height = 52; $bar.FlowDirection = 'RightToLeft'; $bar.Padding = New-Object Windows.Forms.Padding 0, 10, 12, 0
    $ok = New-Object Windows.Forms.Button; $ok.Text = 'Apply'; $ok.Size = New-Object Drawing.Size 110, 32; $ok.Font = $Fonts.Bold
    $cancel = New-Object Windows.Forms.Button; $cancel.Text = 'Close'; $cancel.Size = New-Object Drawing.Size 110, 32; $cancel.DialogResult = 'Cancel'
    $rec = New-Object Windows.Forms.Button; $rec.Text = 'Select recommended'; $rec.Size = New-Object Drawing.Size 160, 32
    $rec.Add_Click({ foreach ($p in $AllowProfiles) { $boxes[$p.id].Checked = [bool]($p.default -and (Test-ProfileInstalled $p)) } }.GetNewClosure())
    $ok.Add_Click({
        $want = @{}; foreach ($k in $boxes.Keys) { $want[$k] = $boxes[$k].Checked }
        $changes = @($want.Keys | Where-Object { $want[$_] -ne (Test-ProfileOn $_) })
        if (-not $changes.Count) { $f.Close(); return }
        if (Set-ProfileStates $want) { $f.Close() }
    }.GetNewClosure())
    $bar.Controls.AddRange(@($cancel, $ok, $rec))
    $f.Controls.Add($list); $f.Controls.Add($bar); $f.Controls.Add($top)
    $f.CancelButton = $cancel
    [void]$f.ShowDialog()
    $f.Dispose()
}

function Get-EventParent($e) { if ($e.blade -eq 'sigma') { [string](Get-SigmaInfo $e).Parent } else { [string]$e.parent } }

function Test-ParentAllowed([string]$Parent) {
    $pat = Get-VersionlessPattern $Parent
    return [bool](@($script:Excl.realtime | Where-Object { $_ -and $_.parent -eq $pat }).Count -and @($script:Excl.sigma | Where-Object { $_ -and $_.parent -eq $pat }).Count)
}

function Invoke-AllowParent([string]$Parent) {
    $pat = Get-VersionlessPattern $Parent
    [void](Send-Ops (Get-ParentAllowOps $Parent) "Allow everything started by $(Get-Leaf $Parent), in EDR and Sigma?`n`n$pat`n(* = any version, so it keeps working after updates)`n`nPrograms it starts are no longer reported by the real-time rules or the Sigma scan. Anti-Malware (malware hashes, YARA, Defender) still checks them.")
}

function Invoke-BlockRows($Rows) {
    $Rows = @($Rows); $sec = $Rows[0].Sec
    if ($sec -eq 'cve') { Invoke-CveUpdate $Rows; return }
    if ($sec -eq 'apps') { Invoke-AppUpdate $Rows; return }
    $ops = New-Object Collections.ArrayList; $names = @()
    foreach ($r in $Rows) {
        if ($r.Kind -eq 'excl') {
            $op = Get-BlockOpFromExcl $r
            if ($op) { [void]$ops.Add(@{ action = 'unexclude'; id = [string]$r.Entry.id }); [void]$ops.Add($op); $names += $r.Note }
            continue
        }
        if ($r.Kind -eq 'ban' -and $r.Entry) { continue }   # already permanent
        $op = Get-BlockOp $r.Ev
        if ($op) { [void]$ops.Add($op); $names += (Get-RowName $r) }
    }
    if (-not $ops.Count) { Show-Info 'There is nothing to block for this item (no program file or address is known).'; return }
    $list = Format-NameList $names
    if (-not (Test-TrayEnforcing)) {
        # Detect-only: a verdict is recorded, nothing is stopped, moved or firewall-blocked
        $q = switch ($sec) {
            'sigma'    { "Confirm as threat:`n$list`n`nThe finding moves to Flagged. Nothing is stopped (FreeEDR only detects)." }
            'wail2ban' { "Flag as hostile:`n$list`n`nThe address moves to Flagged and stays reported. It is not blocked in the firewall (FreeEDR only detects)." }
            default    { "Flag as a threat:`n$list`n`nIt moves to Flagged. FreeEDR only detects: the program is not stopped or moved. Remove it yourself or run a Microsoft Defender scan." }
        }
        return (Send-Ops $ops $q)
    }
    $q = switch ($sec) {
        'malware'  { "Quarantine:`n$list`n`nThe program is stopped and its file is moved to the FreeEDR quarantine ($QuarantineDir). You can restore it from the Quarantined list. Windows and security components are only stopped, never moved." }
        'edr'      { "Block:`n$list`n`nThe program is stopped now and every time it starts again. You can undo this from the Blocked list. Windows components are only stopped once - blocking them would break Windows." }
        'sigma'    { "Confirm as threat:`n$list`n`nThe finding moves to Confirmed threats. Sigma reports past log entries, so nothing is stopped - block the program in the EDR or Anti-Malware tab if needed." }
        'wail2ban' { "Block permanently:`n$list`n`nAll inbound traffic from it is blocked in Windows Firewall until you unblock it." }
    }
    return (Send-Ops $ops $q)
}

function Invoke-AllowRows($Rows, [string]$Variant = 'default') {
    $Rows = @($Rows); $sec = $Rows[0].Sec
    if ($sec -eq 'apps') { Hide-Apps $Rows; return }
    $ops = New-Object Collections.ArrayList; $names = @(); $hist = @()
    foreach ($r in $Rows) {
        $op = $null
        switch ($r.Kind) {
            'block' { [void]$ops.Add(@{ action = 'unblock'; id = [string]$r.Entry.id }); $op = Get-AllowOpFromBlock $r.Entry }
            'cve'   { $op = @{ action = 'exclude'; blade = 'cve'; cve = [string]$r.Entry.id; package = [string]$r.Entry.package } }
            'hist'  { $op = @{ action = 'exclude'; blade = 'cve'; cve = [string]$r.Entry.key; package = [string]$r.Entry.package }; $hist += $r.Entry }
            default { $op = Get-AllowOp $r.Ev $Variant }
        }
        if ($op) { [void]$ops.Add($op); $names += (Get-RowName $r) }
    }
    if (-not @($ops | Where-Object { $_.action -eq 'exclude' }).Count) { Show-Info 'This item cannot be allowed from here (for a Defender malware detection without a threat ID, use Windows Security).'; return }
    $list = Format-NameList $names
    $q = switch ($sec) {
        'malware'  { "Allow:`n$list`n`nIt is no longer reported or blocked. A quarantined file is restored. Defender allows are applied in Microsoft Defender." }
        'edr'      { "Allow:`n$list`n`n$(switch ($Variant) { 'rule' { 'Only this rule is ignored for the program.' } 'parent' { 'Everything started by this program (any version) is ignored.' } 'signer' { "Every program signed by $(Get-TraySigner ([string]$Rows[0].Ev.process)) is ignored by the real-time rules (checked against the file's digital signature, so it survives updates)." } default { 'All real-time alerts for the program are ignored, and a block is removed.' } })" }
        'sigma'    { if ($Variant -eq 'parent') { "Ignore every Sigma rule for programs started by:`n$list`n`n(any version of the parent)" } else { "Ignore this Sigma rule:`n$list`n`nIts findings are no longer reported." } }
        'cve'      { "Ignore:`n$list`n`nIt is no longer listed as needing an update." }
        'wail2ban' { "Always allow:`n$list`n`nWail2Ban never blocks it; a current block is removed." }
    }
    if (Send-Ops $ops $q) { foreach ($h in $hist) { Remove-History $h.id } }
}

function Invoke-BackRows($Rows) {
    $Rows = @($Rows); $sec = $Rows[0].Sec; $S = $Sections[$sec]
    $ops = New-Object Collections.ArrayList; $names = @(); $local = @()
    foreach ($r in $Rows) {
        switch ($r.Kind) {
            'block' { [void]$ops.Add(@{ action = 'unblock'; id = [string]$r.Entry.id }) }
            'ban'   { if ($r.Entry) { [void]$ops.Add(@{ action = 'unblock'; id = [string]$r.Entry.id }) } else { [void]$ops.Add(@{ action = 'unban'; ip = [string]$r.Ban.ip }) } }
            'excl'  { [void]$ops.Add(@{ action = 'unexclude'; id = [string]$r.Entry.id }) }
            'hist'   { $local += $r }
            'hidden' { $local += $r }
        }
        $names += (Get-RowName $r)
    }
    if ($ops.Count) {
        $extra = if (@($Rows | Where-Object { $_.Kind -eq 'block' -and $_.Entry.quarantine }).Count) { "`nQuarantined files are restored to where they were." } else { '' }
        if (-not (Send-Ops $ops "Move back to $($S.Subs[0]):`n$(Format-NameList $names)`n`nIt is detected and reported again.$extra")) { return }
    }
    foreach ($r in $local) { if ($r.Kind -eq 'hist') { Remove-History $r.Entry.id } else { Show-App ([string]$r.Entry) } }
    Clear-Reviewed @(Get-RowEvents $Rows)
    Request-Refresh
}

function Invoke-CveUpdate($Rows) {
    $targets = [ordered]@{}
    foreach ($r in @($Rows)) {
        $v = $r.Entry
        $pkg = if ($v.fixPackage) { [string]$v.fixPackage } else { [string]$v.package }
        $py = if ($v.python) { [string]$v.python } else { 'py' }
        $min = if ($pkg -ieq [string]$v.package) { [string]$v.fixed } else { '' }
        $k = "$py|$pkg"
        if (-not $targets.Contains($k)) { $targets[$k] = @{ Py = $py; Pkg = $pkg; Min = $min } }
        elseif ($min -and (Compare-PyVersion $min $targets[$k].Min) -gt 0) { $targets[$k].Min = $min }
    }
    $cmds = @(foreach ($t in $targets.Values) {
        $safePkg = [string]$t.Pkg -replace '[^a-zA-Z0-9_\-\.]', ''
        $safeMin = [string]$t.Min -replace '[^a-zA-Z0-9_\-\.]', ''
        $safePy  = [string]$t.Py
        if (-not (Test-Path -LiteralPath $safePy) -and $safePy -notmatch '^[a-zA-Z0-9_\-\.]+$') { $safePy = 'py' }
        $spec = if ($safeMin) { "$safePkg>=$safeMin" } else { $safePkg }
        "& '$safePy' -m pip install --upgrade '$spec'"
    })
    if (-not $cmds.Count) { return }
    $why = if (@($Rows | Where-Object { $_.Entry.fixPackage -and $_.Entry.fixPackage -ine $_.Entry.package }).Count) { "`n(Some packages are bundled inside pip, so pip itself is updated.)" } else { '' }
    if (-not (Confirm-Action "Install the fixed versions?`n`n$($cmds -join "`n")$why`n`nA PowerShell window opens and runs this. The CVE list refreshes after the next update (CVE tab > Update now).")) { return }
    Start-Terminal (($cmds + @("Write-Host ''; Write-Host 'Done - you can close this window. The CVE tab refreshes after the next update.' -ForegroundColor Green")) -join '; ')
    foreach ($r in @($Rows)) { if ($r.Kind -eq 'cve') { Add-History 'cve' ([string]$r.Entry.id) $r.Entry } elseif ($r.Kind -eq 'hist') { Add-History 'cve' ([string]$r.Entry.key) $r.Entry } }
    Request-Refresh
}

function Invoke-AppUpdate($Rows) {
    $Rows = @($Rows)
    $ids = @(foreach ($r in $Rows) { if ($r.Kind -eq 'hidden') { [string]$r.Entry } elseif ($r.Kind -eq 'hist') { [string]$r.Entry.key } else { [string]$r.Entry.appId } }) | Where-Object { $_ } | Select-Object -Unique
    $validIds = @($ids | Where-Object { $_ -match '^[a-zA-Z0-9_\-\.]+$' })
    if (-not @($validIds).Count) { return }
    foreach ($r in $Rows) { if ($r.Kind -eq 'hidden') { Show-App ([string]$r.Entry) } }
    Start-Terminal ((@($validIds) | ForEach-Object { "winget upgrade --id '$_' -e --accept-source-agreements --accept-package-agreements" }) -join '; ')
    foreach ($r in $Rows) {
        if ($r.Kind -eq 'app') { Add-History 'apps' ([string]$r.Entry.appId) $r.Entry }
        elseif ($r.Kind -eq 'hist') { Add-History 'apps' ([string]$r.Entry.key) $r.Entry }
    }
    $script:PatchNext = (Get-Date).AddMinutes(10)   # re-check, so anything that failed comes back to Available
    Request-Refresh
}

function Hide-Apps($Rows) {
    foreach ($r in @($Rows)) {
        $id = if ($r.Kind -eq 'hist') { [string]$r.Entry.key } else { [string]$r.Entry.appId }
        if ($r.Kind -eq 'hist') { Remove-History $r.Entry.id }
        if ($id -and $script:Ignored.Add($id)) { [IO.File]::AppendAllLines($IgnoredApps, [string[]]@($id)) }
    }
    Request-Refresh
}

function Show-App([string]$Id) {
    if ($script:Ignored.Remove($Id)) { [IO.File]::WriteAllLines($IgnoredApps, [string[]]@($script:Ignored)) }
    $script:ModelDirty = $true
}

function Request-Refresh { $script:ModelDirty = $true; Update-Dashboard }

function New-Act([string]$Text, [scriptblock]$Run, $Arg = $null, [switch]$Bold, [switch]$Disabled) {
    [pscustomobject]@{ Text = $Text; Run = $Run; Arg = $Arg; Bold = [bool]$Bold; Disabled = [bool]$Disabled }
}

# The actions for the selected rows: the first one is the main (bold) action; the same list feeds the right-click menu and the buttons
function Get-Actions($Rows) {
    $Rows = @($Rows); $r = $Rows[0]
    $same = @($Rows | Where-Object { $_.Kind -eq $r.Kind })
    $n = $same.Count
    $sfx = if ($n -gt 1) { " ($n items)" } else { '' }
    $S = $Sections[$r.Sec]
    $acts = New-Object Collections.ArrayList
    switch ($r.Kind) {
        { $_ -in 'event', 'fail' } {
            if ($r.Pinned) {
                # Only you can judge these: "yes" keeps future detection on (mark reviewed), "no" blocks / confirms
                [void]$acts.Add((New-Act "No, it wasn't me - $($S.Block)$sfx" { Invoke-BlockRows $args[0] } $same -Bold))
                [void]$acts.Add((New-Act "Yes, this was me - Trust & Review$sfx" { Set-Reviewed @(Get-RowEvents $args[0]); Request-Refresh } $same -Bold))
            } else {
                [void]$acts.Add((New-Act "$($S.Block)$sfx" { Invoke-BlockRows $args[0] } $same -Bold))
            }
            [void]$acts.Add((New-Act "$($S.Allow)$sfx" { Invoke-AllowRows $args[0] 'default' } $same))
            $par = Get-EventParent $r.Ev
            if ($r.Sec -eq 'edr' -and $n -eq 1) {
                if ($r.Ev.rule -and $r.Ev.process) { [void]$acts.Add((New-Act "Allow only for rule `"$($r.Ev.rule)`"" { Invoke-AllowRows $args[0] 'rule' } $same)) }
                if ($par) { [void]$acts.Add((New-Act "Allow everything started by $(Get-Leaf $par) (any version)" { Invoke-AllowRows $args[0] 'parent' } $same)) }
                $sg = Get-TraySigner ([string]$r.Ev.process)
                if ($sg -and $sg -notin $UnsafeSigners) { [void]$acts.Add((New-Act "Allow everything signed by $sg" { Invoke-AllowRows $args[0] 'signer' } $same)) }
            }
            if ($r.Sec -eq 'sigma' -and $n -eq 1 -and $par) {
                [void]$acts.Add((New-Act "Allow everything started by $(Get-Leaf $par) (any version)" { Invoke-AllowRows $args[0] 'parent' } $same))
            }
            # A trusted-app profile (Claude Code, OneDrive, ...) that is off and covers this alert: one click trusts the whole app
            $prof = if ($r.Sec -in 'edr', 'sigma') { Find-ProfileFor $r.Ev } else { $null }
            if ($prof) { [void]$acts.Insert(0, (New-Act "Trust the whole app: $($prof.name)" { Set-ProfileStates @{ $args[0] = $true } } $prof.id -Bold)) }
            if ($r.Sec -in 'edr', 'sigma' -and $n -eq 1 -and $par -and -not (Test-ParentAllowed $par)) {
                [void]$acts.Add((New-Act "Allow everything started by $(Get-Leaf $par) in EDR and Sigma" { Invoke-AllowParent $args[0] } $par))
            }
            if ($r.Sec -eq 'wail2ban' -and $n -eq 1 -and [string]$r.Ev.ip -match '^(\d+\.\d+\.\d+)\.\d+$') {
                [void]$acts.Add((New-Act "Always allow the whole $($matches[1]).0/24 network" { Invoke-AllowRows $args[0] 'net' } $same))
            }
            if ($r.Pinned -and -not $r.Muted) { }   # "Yes, this was me" already marks it reviewed
            elseif (@(Get-RowEvents $same | Where-Object { -not (Test-Reviewed $_) }).Count) {
                [void]$acts.Add((New-Act "Mark Reviewed$sfx" { Set-Reviewed @(Get-RowEvents $args[0]); Request-Refresh } $same))
            } else {
                [void]$acts.Add((New-Act "Mark Unreviewed$sfx" { Clear-Reviewed @(Get-RowEvents $args[0]); Request-Refresh } $same))
            }
        }
        'block' {
            [void]$acts.Add((New-Act "Move back to $($S.Subs[0]) ($(if (Test-TrayEnforcing) { 'unblock' } else { 'remove flag' }))$sfx" { Invoke-BackRows $args[0] } $same -Bold))
            [void]$acts.Add((New-Act "Move to $($S.Subs[2]) (allow)$sfx" { Invoke-AllowRows $args[0] 'default' } $same))
        }
        'defender' {
            [void]$acts.Add((New-Act "Move to Allowed (allow in Defender)$sfx" { Invoke-AllowRows $args[0] 'default' } $same -Bold))
            [void]$acts.Add((New-Act 'Open Windows Security' { Start-Process 'windowsdefender://threat' } $null))
        }
        'ban' {
            if (-not $r.Entry) { [void]$acts.Add((New-Act "$(if (Test-TrayEnforcing) { 'Block permanently' } else { $S.Block })$sfx" { Invoke-BlockRows $args[0] } $same -Bold)) }
            [void]$acts.Add((New-Act "$(if (Test-TrayEnforcing) { 'Unblock' } else { 'Remove flag' }) - move back to $($S.Subs[0])$sfx" { Invoke-BackRows $args[0] } $same))
            [void]$acts.Add((New-Act "Move to Allowed (always allow)$sfx" { Invoke-AllowRows $args[0] 'default' } $same))
        }
        'banhist' {
            [void]$acts.Add((New-Act "$(if (Test-TrayEnforcing) { 'Block permanently' } else { $S.Block })$sfx" { Invoke-BlockRows $args[0] } $same -Bold))
            [void]$acts.Add((New-Act "Move to Allowed (always allow)$sfx" { Invoke-AllowRows $args[0] 'default' } $same))
        }
        'excl' {
            if ($r.Sec -eq 'cve') {
                [void]$acts.Add((New-Act "Move back to $($S.Subs[0]) (stop ignoring)$sfx" { Invoke-BackRows $args[0] } $same -Bold))
            } elseif ($r.ExclList -eq 'defender') {
                [void]$acts.Add((New-Act "Remove allow - Defender blocks it again$sfx" { Invoke-BackRows $args[0] } $same -Bold))
            } else {
                $can = @($same | Where-Object { Get-BlockOpFromExcl $_ }).Count -gt 0
                $label = if ($can) { "Move to $($S.Subs[1]) ($($S.Block.ToLower()))$sfx" } else { "Move to $($S.Subs[1]) - not possible for a wildcard or folder" }
                [void]$acts.Add((New-Act $label { Invoke-BlockRows $args[0] } $same -Bold -Disabled:(-not $can)))
                [void]$acts.Add((New-Act "Move back to $($S.Subs[0]) (remove allow)$sfx" { Invoke-BackRows $args[0] } $same))
            }
        }
        'builtin' { [void]$acts.Add((New-Act 'Built-in exclusion - edit config\sysmonconfig.template.xml to change' { } $null -Disabled)) }
        'cve' {
            [void]$acts.Add((New-Act "Update now$sfx" { Invoke-CveUpdate $args[0] } $same -Bold))
            if ($n -eq 1) {
                $id = [string]$r.Entry.cve
                [void]$acts.Add((New-Act "Ask Gemini about $id" { Invoke-GeminiCli $args[0] } $id))
                [void]$acts.Add((New-Act 'Ask Gemini in the browser' { Invoke-GeminiWeb $args[0] } $id))
            }
            [void]$acts.Add((New-Act "Move to Ignored$sfx" { Invoke-AllowRows $args[0] 'default' } $same))
        }
        'hist' {
            if ($r.Sec -eq 'cve') { [void]$acts.Add((New-Act "Update again$sfx" { Invoke-CveUpdate $args[0] } $same)) }
            else { [void]$acts.Add((New-Act "Update again$sfx" { Invoke-AppUpdate $args[0] } $same)) }
            [void]$acts.Add((New-Act "Move back to $($S.Subs[0])$sfx" { Invoke-BackRows $args[0] } $same))
            [void]$acts.Add((New-Act "Move to $($S.Subs[2])$sfx" { Invoke-AllowRows $args[0] 'default' } $same))
        }
        'app' {
            [void]$acts.Add((New-Act "Update now$sfx" { Invoke-AppUpdate $args[0] } $same -Bold))
            [void]$acts.Add((New-Act 'Update all apps' { Invoke-AppUpdate @($script:Model.Sec.apps.Rows[0]) } $null))
            [void]$acts.Add((New-Act "Move to Hidden$sfx" { Hide-Apps $args[0] } $same))
        }
        'hidden' {
            [void]$acts.Add((New-Act "Move back to Available$sfx" { Invoke-BackRows $args[0] } $same -Bold))
            [void]$acts.Add((New-Act "Update now$sfx" { Invoke-AppUpdate $args[0] } $same))
        }
        'sys' {
            if ($r.Ev.kind -eq 'tool' -and $r.Ev.url) { [void]$acts.Add((New-Act 'Open download page' { Start-Process $args[0] } ([string]$r.Ev.url) -Bold)) }
        }
    }
    $e = $r.Ev
    if ($e -and $n -eq 1 -and $e.process -and [string]$e.blade -in 'realtime', 'ioc', 'yara', 'defender' -and (Test-Path -LiteralPath ([string]$e.process) -ErrorAction SilentlyContinue)) {
        [void]$acts.Add((New-Act 'Open file location' { Start-Process explorer.exe "/select,`"$($args[0])`"" } ([string]$e.process)))
    }
    [void]$acts.Add((New-Act 'Copy details' { Copy-RowDetails $args[0] } $r))
    return $acts.ToArray()
}

function Copy-RowDetails($Row) {
    $o = if ($Row.Ev -and $Row.Kind -notin 'block', 'excl', 'cve', 'hist') { $Row.Ev } elseif ($Row.Entry -is [string]) { [pscustomobject]@{ item = $Row.Entry } } elseif ($Row.Entry) { $Row.Entry } else { $Row.Ev }
    $lines = @($o.PSObject.Properties | Where-Object { $_.Value -and -not $_.Name.StartsWith('_') } | ForEach-Object { "$($_.Name): $(@($_.Value) -join ', ')" })
    if ($lines.Count) { [Windows.Forms.Clipboard]::SetText(($lines -join "`r`n")) }
}

################################################################################
# Winget app updates (E8: one row per app, user context; checked at the same times as the scan)

function ConvertFrom-WingetTable([string[]]$Lines) {
    $clean = @($Lines | ForEach-Object { ($_ -split "`r")[-1] })
    $h = -1
    for ($i = 0; $i -lt $clean.Count; $i++) { if ($clean[$i] -match '^Name\s+Id\s+Version\s+Available') { $h = $i; break } }
    if ($h -lt 0) { return @() }
    $hdr = $clean[$h]
    $cId = $hdr.IndexOf('Id'); $cVer = $hdr.IndexOf('Version'); $cAv = $hdr.IndexOf('Available'); $cSrc = $hdr.IndexOf('Source')
    $apps = @()
    for ($i = $h + 2; $i -lt $clean.Count; $i++) {
        $l = $clean[$i]
        if (-not $l.Trim() -or $l -match '^\d+ upgrades? available' -or $l.Length -le $cAv) { break }
        $get = { param($a, $b) if ($b -lt 0 -or $b -gt $l.Length) { $b = $l.Length }; if ($a -ge $l.Length) { '' } else { $l.Substring($a, $b - $a).Trim() } }
        $app = [pscustomobject]@{ name = (& $get 0 $cId); appId = (& $get $cId $cVer); version = (& $get $cVer $cAv); latest = (& $get $cAv $cSrc) }
        if ($app.appId -and $app.latest) { $apps += $app }
    }
    return $apps
}

function Update-PatchCheck {
    if ($script:PatchProc) {
        if (-not $script:PatchProc.HasExited) { return }
        $script:PatchProc = $null
        $out = "$LocalDir\winget.txt"
        if (Test-Path $out) {
            $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            $script:PatchEvents = @(ConvertFrom-WingetTable (Get-Content $out -Encoding UTF8) | ForEach-Object {
                [pscustomobject]@{
                    id = "app-$($_.appId)"; time = $stamp; blade = 'patch'; kind = 'app'; severity = 'Info'
                    title = "$($_.name): $($_.version) -> $($_.latest)"; process = $_.name; appId = $_.appId; version = $_.version; latest = $_.latest
                    detail = "winget id: $($_.appId)"
                }
            })
            $script:PatchChecked = Get-Date
            $script:ModelDirty = $true
        }
        return
    }
    if ((Get-Date) -ge $script:PatchNext) {
        $script:PatchNext = (Get-ScanSlots $script:Cfg.scanTimes (Get-Date)).Next
        $wg = Get-Command winget -ErrorAction SilentlyContinue
        if ($wg) {
            try {
                $script:PatchProc = Start-Process $wg.Source -ArgumentList @('upgrade', '--accept-source-agreements', '--disable-interactivity') -RedirectStandardOutput "$LocalDir\winget.txt" -WindowStyle Hidden -PassThru
            } catch { Write-TrayLog "winget check failed: $_" }
        }
        $script:ViewDirty = $true
    }
}

################################################################################
# Tray

$script:Tray = New-Object Windows.Forms.NotifyIcon
$script:Tray.Icon = $Icons.ok
$script:Tray.Text = $ProductName
$script:Tray.Visible = -not $SelfTest
$script:TrayMenu = New-Object Windows.Forms.ContextMenuStrip
$script:Tray.ContextMenuStrip = $script:TrayMenu
$script:BoldFont = New-Object Drawing.Font('Segoe UI', 9, [Drawing.FontStyle]::Bold)

function New-MenuItem([string]$Text, $Tag, [scriptblock]$OnClick) {
    $mi = New-Object Windows.Forms.ToolStripMenuItem($Text)
    $mi.Tag = $Tag
    if ($OnClick) { $mi.Add_Click($OnClick) }
    return $mi
}

function Add-PauseItems($Target, [string]$Blade) {
    [void]$Target.Add((New-MenuItem 'Pause for 15 minutes' @($Blade, 15) { Invoke-Pause $this.Tag[0] $this.Tag[1] }))
    [void]$Target.Add((New-MenuItem 'Pause for 1 hour' @($Blade, 60) { Invoke-Pause $this.Tag[0] $this.Tag[1] }))
    [void]$Target.Add((New-MenuItem 'Stop until I resume' @($Blade, 0) { Invoke-Pause $this.Tag[0] $this.Tag[1] }))
}

function Add-BladeMenu([string]$Blade, [string]$Label) {
    $st = Get-PauseState $Blade
    if (-not (Test-EngineAlive)) {
        $mi = New-MenuItem "${Label}: unknown (engine not running)" $null $null; $mi.Enabled = $false
        [void]$script:TrayMenu.Items.Add($mi); return
    }
    switch ($st.state) {
        'paused' {
            $mi = New-MenuItem ("Resume $Label   (paused " + (Format-Until $st) + ')') $Blade { Invoke-Resume $this.Tag }
            $mi.ForeColor = $Palette.ok; $mi.Font = $script:BoldFont
            [void]$script:TrayMenu.Items.Add($mi)
        }
        'error' {
            $mi = New-MenuItem "${Label}: NOT WORKING - open dashboard" $null { Show-Dashboard }
            $mi.ForeColor = $Palette.down
            [void]$script:TrayMenu.Items.Add($mi)
        }
        default {
            $mi = New-MenuItem "${Label}: On" $null $null
            Add-PauseItems $mi.DropDownItems $Blade
            [void]$script:TrayMenu.Items.Add($mi)
        }
    }
}

function Build-TrayMenu {
    $m = $script:TrayMenu
    $m.Items.Clear()
    $ov = Get-Overall
    $h = New-MenuItem $ov.Text $null { Show-Dashboard }
    $h.Font = $script:BoldFont; $h.ForeColor = $Palette[$ov.Key]
    [void]$m.Items.Add($h)
    [void]$m.Items.Add((New-MenuItem 'Open dashboard' $null { Show-Dashboard }))
    $open = New-MenuItem 'Open' $null $null
    foreach ($s in $SectionOrder) {
        $c = if ($script:Model) { $script:Model.Sec[$s].Count } else { 0 }
        $mi = New-MenuItem "$($Sections[$s].Name)$(if ($c) { "   ($c)" })" $s { Show-Dashboard -Section $this.Tag }
        if ($script:Model -and $script:Model.Sec[$s].Alert) { $mi.ForeColor = $Palette.down; $mi.Font = $script:BoldFont }
        [void]$open.DropDownItems.Add($mi)
    }
    [void]$m.Items.Add($open)
    [void]$m.Items.Add('-')
    Add-BladeMenu 'realtime' 'Real-time EDR'
    Add-BladeMenu 'malware' 'Anti-Malware'
    Add-BladeMenu 'sigma' 'Sigma scan'
    Add-BladeMenu 'cve' 'CVE scan'
    Add-BladeMenu 'wail2ban' 'Wail2Ban'
    Add-BladeMenu 'edr' 'Master switch (all EDR)'
    [void]$m.Items.Add('-')
    $scanning = $script:Status -and $script:Status.scan.running
    $si = New-MenuItem $(if ($scanning) { 'Updating...' } else { 'Update and scan now' }) $null { Invoke-ScanNow }
    $si.Enabled = -not $scanning -and (Test-EngineAlive)
    [void]$m.Items.Add($si)
    [void]$m.Items.Add((New-MenuItem 'Trusted apps (no alerts for apps you trust)...' $null { Show-TrustedApps }))
    $adv = New-MenuItem 'Advanced' $null $null
    [void]$adv.DropDownItems.Add((New-MenuItem 'Send a harmless test detection' $null {
        # Started through cmd so its parent is not the tray (tray children are treated as the EDR's own)
        Start-Process cmd.exe -ArgumentList '/c start "" /min powershell.exe -NoProfile -Command "Invoke-Expression ''Write-Output EDR-test-detection''"' -WindowStyle Hidden
        Show-Toast 'Test sent' 'A "PowerShell download or in-memory execution" alert should appear in the EDR tab within a few seconds.'
    }))
    [void]$adv.DropDownItems.Add((New-MenuItem 'Velociraptor forensics GUI (admin)' $null {
        try { Start-Process "$BinDir\velociraptor.exe" -ArgumentList @('gui', '--datastore', "`"$DataDir\velociraptor`"") -Verb RunAs -WorkingDirectory $DataDir } catch { }
    }))
    [void]$adv.DropDownItems.Add((New-MenuItem 'Open documentation' $null { Start-Process notepad.exe "`"$Root\README.md`"" }))
    [void]$adv.DropDownItems.Add((New-MenuItem 'Open engine log' $null { Start-Process notepad.exe "`"$EngineLog`"" }))
    [void]$adv.DropDownItems.Add((New-MenuItem 'Restart engine (admin)' $null { [void](Send-AdminCommand @{ action = 'restart-engine' }) }))
    [void]$m.Items.Add($adv)
    [void]$m.Items.Add('-')
    [void]$m.Items.Add((New-MenuItem 'Hide tray icon (protection keeps running)' $null {
        $script:Exiting = $true; $script:Tray.Visible = $false; [Windows.Forms.Application]::Exit()
    }))
}

$script:TrayMenu.Add_Opening({ Build-TrayMenu })
$script:Tray.Add_MouseClick({ param($s, $a) if ($a.Button -eq 'Left') { Show-Dashboard } })
$script:Tray.Add_BalloonTipClicked({ Show-Dashboard $script:ToastTarget })

function Update-TrayIcon {
    $ov = Get-Overall
    if ($script:Tray.Icon -ne $Icons[$ov.Key]) { $script:Tray.Icon = $Icons[$ov.Key] }
    $t = "EDR: $($ov.Text)"
    if ($t.Length -gt 63) { $t = $t.Substring(0, 60) + '...' }
    $script:Tray.Text = $t
    if ($ov.Key -eq 'down' -and -not (Test-EngineAlive)) {
        if (-not $script:EngineDownToasted -and -not $script:Initial) { Show-Toast 'EDR protection is OFF' 'The EDR engine stopped. Right-click the tray shield > Advanced > Restart engine.' 'Error'; $script:EngineDownToasted = $true }
    } else { $script:EngineDownToasted = $false }
}

################################################################################
# Dashboard

$Fonts = @{
    Base   = New-Object Drawing.Font('Segoe UI', 9)
    Bold   = New-Object Drawing.Font('Segoe UI', 9, [Drawing.FontStyle]::Bold)
    Title  = New-Object Drawing.Font('Segoe UI Semibold', 16)
    Sub    = New-Object Drawing.Font('Segoe UI', 10)
    CardH  = New-Object Drawing.Font('Segoe UI Semibold', 10)
    Value  = New-Object Drawing.Font('Segoe UI Semibold', 13)
    H2     = New-Object Drawing.Font('Segoe UI Semibold', 12)
    Label  = New-Object Drawing.Font('Segoe UI', 8.5, [Drawing.FontStyle]::Bold)
    Small  = New-Object Drawing.Font('Segoe UI', 8.5)
    Mono   = New-Object Drawing.Font('Consolas', 9)
}

function New-List([string]$Key) {
    $lv = New-Object Windows.Forms.ListView
    $lv.View = 'Details'; $lv.FullRowSelect = $true; $lv.HideSelection = $false; $lv.MultiSelect = $true
    $lv.Dock = 'Fill'; $lv.BorderStyle = 'None'; $lv.Font = $Fonts.Base; $lv.Tag = $Key
    foreach ($c in $ListCols[$Key]) { [void]$lv.Columns.Add([string]$c[0], [int]$c[1]) }
    $cm = New-Object Windows.Forms.ContextMenuStrip
    $cm.Tag = $lv
    $cm.Add_Opening({ param($s, $a) Build-ListMenu $s.Tag $s; if (-not $s.Items.Count) { $a.Cancel = $true } })
    $lv.ContextMenuStrip = $cm
    $lv.Add_SelectedIndexChanged({ param($s, $a) if (@(Get-SelectedRows $s).Count) { Show-Details $s } })
    $script:Lv[$Key] = $lv
    return $lv
}

function Get-SelectedRows($Lv) { @($Lv.SelectedItems | ForEach-Object { $_.Tag } | Where-Object { $_ }) }

function New-RowItem($Row) {
    $it = New-Object Windows.Forms.ListViewItem([string]$Row.Cols[0])
    for ($i = 1; $i -lt $Row.Cols.Count; $i++) { [void]$it.SubItems.Add([string]$Row.Cols[$i]) }
    $it.Tag = $Row; $it.UseItemStyleForSubItems = $true
    if ($Row.List -eq 1 -and $Row.Sec -in 'cve', 'apps') { $it.BackColor = $RowColors.doneBack; $it.ForeColor = $RowColors.doneFore }
    elseif ($Row.List -eq 1) { $it.BackColor = $RowColors.blockedBack; $it.ForeColor = $RowColors.blockedFore }
    elseif ($Row.List -eq 2) { $it.BackColor = $RowColors.allowedBack; $it.ForeColor = $RowColors.allowedFore }
    else {
        switch ($Row.Sev) {
            'Critical' { $it.BackColor = [Drawing.Color]::FromArgb(253, 236, 234); $it.ForeColor = [Drawing.Color]::FromArgb(183, 28, 28); $it.Font = $Fonts.Bold }
            'High'     { $it.BackColor = [Drawing.Color]::FromArgb(255, 243, 224); $it.ForeColor = [Drawing.Color]::FromArgb(191, 54, 12); $it.Font = $Fonts.Bold }
            'Medium'   { $it.ForeColor = [Drawing.Color]::FromArgb(130, 90, 0) }
            default    { $it.ForeColor = [Drawing.Color]::FromArgb(70, 70, 70) }
        }
    }
    if ($Row.Muted) { $it.Font = $Fonts.Base; $it.ForeColor = $RowColors.muted; if ($Row.List -eq 0) { $it.BackColor = [Drawing.Color]::White } }
    return $it
}

function New-PlaceholderItem([string]$Key, [string]$Text) {
    $cols = $ListCols[$Key]
    $wide = 0
    for ($i = 1; $i -lt $cols.Count; $i++) { if ([int]$cols[$i][1] -gt [int]$cols[$wide][1]) { $wide = $i } }
    $it = New-Object Windows.Forms.ListViewItem($(if ($wide -eq 0) { $Text } else { '' }))
    for ($i = 1; $i -lt $cols.Count; $i++) { [void]$it.SubItems.Add($(if ($i -eq $wide) { $Text } else { '' })) }
    $it.ForeColor = [Drawing.Color]::FromArgb(120, 120, 120); $it.Tag = $null
    return $it
}

function Set-ListItems($Lv, $Items) {
    $selKeys = @($Lv.SelectedItems | Where-Object { $_.Tag } | ForEach-Object { $_.Tag.Key })
    $top = if ($Lv.TopItem) { $Lv.TopItem.Index } else { 0 }
    $Lv.BeginUpdate()
    $Lv.Items.Clear()
    if ($Items) { $Lv.Items.AddRange([Windows.Forms.ListViewItem[]]@($Items)) }
    foreach ($it in $Lv.Items) { if ($it.Tag -and $selKeys -contains $it.Tag.Key) { $it.Selected = $true } }
    if ($Lv.Items.Count -gt $top) { try { $Lv.TopItem = $Lv.Items[$top] } catch { } }
    $Lv.EndUpdate()
}

function Test-RowMatch($Row) {
    if (-not $script:Search) { return $true }
    $s = $script:Search
    $vals = @($Row.Cols) + @($Row.Note)
    if ($Row.Ev) { $vals += @($Row.Ev.process, $Row.Ev.parent, $Row.Ev.detail, $Row.Ev.ip, $Row.Ev.title) }
    foreach ($v in $vals) { if ($v -and ([string]$v).IndexOf($s, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true } }
    return $false
}

function New-Tile([string]$Key, [string]$Name) {
    $p = New-Object Windows.Forms.Panel
    $p.Dock = 'Fill'; $p.Margin = New-Object Windows.Forms.Padding 6; $p.BackColor = [Drawing.Color]::FromArgb(247, 247, 247); $p.Cursor = 'Hand'
    $bar = New-Object Windows.Forms.Panel; $bar.Dock = 'Left'; $bar.Width = 6
    $h = New-Object Windows.Forms.Label; $h.Text = $Name; $h.Font = $Fonts.CardH; $h.Location = New-Object Drawing.Point 16, 8; $h.AutoSize = $true
    $v = New-Object Windows.Forms.Label; $v.Font = $Fonts.Value; $v.Location = New-Object Drawing.Point 16, 30; $v.Size = New-Object Drawing.Size 260, 28; $v.AutoEllipsis = $true; $v.Tag = 'fit'
    $s = New-Object Windows.Forms.Label; $s.Font = $Fonts.Base; $s.ForeColor = [Drawing.Color]::FromArgb(100, 100, 100); $s.Location = New-Object Drawing.Point 16, 60; $s.Size = New-Object Drawing.Size 260, 34; $s.AutoEllipsis = $true; $s.Tag = 'fit'
    $l = New-Object Windows.Forms.LinkLabel; $l.Font = $Fonts.Base; $l.Location = New-Object Drawing.Point 16, 96; $l.AutoSize = $true; $l.Tag = $Key
    $l.Add_LinkClicked({ param($sender, $a) Invoke-TileLink $sender.Tag $sender })
    $p.Controls.AddRange(@($bar, $h, $v, $s, $l))
    foreach ($c in @($p, $h, $v, $s)) { $c.Name = $Key; $c.Add_Click({ Open-Section $this.Name }) }
    $p.Add_Resize({ param($sender, $a) foreach ($c in $sender.Controls) { if ($c.Tag -eq 'fit') { $c.Width = [Math]::Max(80, $sender.Width - 26) } } })
    return @{ Panel = $p; Bar = $bar; Value = $v; Sub = $s; Link = $l }
}

function Show-PauseMenu($Control, [string]$Blade) {
    $cm = New-Object Windows.Forms.ContextMenuStrip
    Add-PauseItems $cm.Items $Blade
    $cm.Show($Control, (New-Object Drawing.Point 0, $Control.Height))
}

function Invoke-PauseLink([string]$Blade, $Control) {
    if ((Get-PauseState $Blade).state -eq 'paused') { Invoke-Resume $Blade } else { Show-PauseMenu $Control $Blade }
}

function Invoke-TileLink([string]$Key, $Control) {
    switch ($Key) {
        'malware'  { Invoke-PauseLink 'malware' $Control }
        'edr'      { Invoke-PauseLink 'realtime' $Control }
        'sigma'    { Invoke-PauseLink 'sigma' $Control }
        'cve'      { Invoke-PauseLink 'cve' $Control }
        'wail2ban' { Invoke-PauseLink 'wail2ban' $Control }
        'sensors'  { Start-Process notepad.exe "`"$EngineLog`"" }
        'scans'    { if (Test-Path $ScanLog) { Start-Process notepad.exe "`"$ScanLog`"" } }
        default    { Open-Section $Key }
    }
}

function Open-Section([string]$Key, [int]$Sub = -1) {
    if (-not $script:Tabs.TabPages.ContainsKey($Key)) { return }
    $script:Tabs.SelectedTab = $script:Tabs.TabPages[$Key]
    if ($Sub -ge 0 -and $script:SubTabs[$Key]) { $script:SubTabs[$Key].SelectedIndex = $Sub }
}

function Invoke-StatusExtraLink([string]$Sec, $Control) {
    switch ($Sec) {
        'malware'  { Invoke-ScanNow }
        'sigma'    { Invoke-ScanNow }
        'cve'      { Invoke-ScanNow }
        'apps'     { $script:PatchNext = Get-Date; Show-Toast 'Checking for app updates' 'The App Updates list refreshes in a minute or two.' }
    }
}

function New-Dashboard {
    $script:Lv = @{}; $script:SubTabs = @{}; $script:StatusLbl = @{}; $script:StatusLink = @{}; $script:StatusExtraLink = @{}; $script:StatusBadge = @{}; $script:Tiles = @{}
    $script:TabInfo = @{ overview = @{ Text = 'Overview'; Alert = $false } }
    foreach ($s in $SectionOrder) { $script:TabInfo[$s] = @{ Text = $Sections[$s].Name; Alert = $false } }

    $f = New-Object Windows.Forms.Form
    $f.AutoScaleDimensions = New-Object Drawing.SizeF 96, 96
    $f.AutoScaleMode = 'Dpi'
    $f.Text = $ProductName
    $f.Size = New-Object Drawing.Size 1240, 820
    $f.MinimumSize = New-Object Drawing.Size 980, 620
    $f.StartPosition = 'CenterScreen'
    $f.Font = $Fonts.Base
    $f.BackColor = [Drawing.Color]::White
    $f.Icon = $Icons.ok

    # Toolbar: search + show reviewed (applies to every list)
    $tb = New-Object Windows.Forms.Panel; $tb.Dock = 'Top'; $tb.Height = 38
    $lbl = New-Object Windows.Forms.Label; $lbl.Text = 'Search:'; $lbl.AutoSize = $true; $lbl.Location = New-Object Drawing.Point 12, 11
    $script:SearchBox = New-Object Windows.Forms.TextBox; $script:SearchBox.Location = New-Object Drawing.Point 66, 8; $script:SearchBox.Width = 300
    $script:SearchBox.Add_TextChanged({ $script:Search = $script:SearchBox.Text.Trim(); $script:ViewDirty = $true; Update-Dashboard })
    $chk = New-Object Windows.Forms.CheckBox; $chk.Text = 'Show reviewed items'; $chk.AutoSize = $true; $chk.Location = New-Object Drawing.Point 384, 10
    $chk.Add_CheckedChanged({ $script:ShowReviewed = $this.Checked; $script:ViewDirty = $true; Update-Dashboard })
    $hint = New-Object Windows.Forms.Label; $hint.AutoSize = $true; $hint.Location = New-Object Drawing.Point 548, 11; $hint.ForeColor = [Drawing.Color]::Gray
    $hint.Text = 'Click an item to see what it means. Buttons or right-click: block, allow, or move it between the lists.'
    $tb.Controls.AddRange(@($lbl, $script:SearchBox, $chk, $hint))

    # Main tabs (owner-drawn so a tab with security items to review shows in red)
    $script:Tabs = New-Object Windows.Forms.TabControl; $script:Tabs.Dock = 'Fill'
    $script:Tabs.DrawMode = 'OwnerDrawFixed'; $script:Tabs.SizeMode = 'Fixed'; $script:Tabs.ItemSize = New-Object Drawing.Size 138, 30
    $script:Tabs.Add_DrawItem({
        param($s, $a)
        $page = $s.TabPages[$a.Index]
        $info = $script:TabInfo[$page.Name]
        $sel = $a.Index -eq $s.SelectedIndex
        $bg = if ($sel) { [Drawing.Color]::White } else { [Drawing.Color]::FromArgb(238, 238, 238) }
        $a.Graphics.FillRectangle((New-Object Drawing.SolidBrush $bg), $a.Bounds)
        $fg = if ($info.Alert) { $Palette.down } else { [Drawing.Color]::FromArgb(33, 33, 33) }
        $font = if ($sel -or $info.Alert) { $Fonts.Bold } else { $Fonts.Base }
        [Windows.Forms.TextRenderer]::DrawText($a.Graphics, [string]$info.Text, $font, $a.Bounds, $fg, [Windows.Forms.TextFormatFlags]'HorizontalCenter, VerticalCenter, SingleLine')
    })

    # Overview: header, triage card, tiles, forensics log
    $ovp = New-Object Windows.Forms.TabPage; $ovp.Name = 'overview'; $ovp.BackColor = [Drawing.Color]::White
    $hdr = New-Object Windows.Forms.Panel; $hdr.Dock = 'Top'; $hdr.Height = 84
    $script:HdrTitle = New-Object Windows.Forms.Label; $script:HdrTitle.Font = $Fonts.Title; $script:HdrTitle.AutoSize = $true; $script:HdrTitle.Location = New-Object Drawing.Point 18, 10
    $script:HdrSub = New-Object Windows.Forms.Label; $script:HdrSub.Font = $Fonts.Sub; $script:HdrSub.Location = New-Object Drawing.Point 20, 50; $script:HdrSub.Size = New-Object Drawing.Size 820, 24
    $script:HdrSub.AutoEllipsis = $true
    $hdr.Add_Resize({ param($s, $a) $script:HdrSub.Width = [Math]::Max(200, $s.Width - 500) })
    $btnBox = New-Object Windows.Forms.FlowLayoutPanel; $btnBox.Dock = 'Right'; $btnBox.Width = 330; $btnBox.FlowDirection = 'RightToLeft'
    $btnBox.Padding = New-Object Windows.Forms.Padding 0, 24, 12, 0; $btnBox.BackColor = [Drawing.Color]::Transparent
    $btnScan = New-Object Windows.Forms.Button; $btnScan.Text = 'Update and scan now'; $btnScan.Size = New-Object Drawing.Size 160, 32; $btnScan.BackColor = [Drawing.Color]::White
    $btnScan.Add_Click({ Invoke-ScanNow })
    $btnAll = New-Object Windows.Forms.Button; $btnAll.Text = 'Mark all reviewed'; $btnAll.Size = New-Object Drawing.Size 140, 32; $btnAll.BackColor = [Drawing.Color]::White
    $btnAll.Add_Click({
        $rows = @(foreach ($s in 'malware', 'edr', 'sigma', 'wail2ban') { $script:Model.Sec[$s].Rows[0] | Where-Object { -not $_.Muted } })
        $evs = @(Get-RowEvents $rows)
        if ($evs.Count -and (Confirm-Action "Mark all $($rows.Count) detected items as reviewed?`nThey are hidden from the Detected lists (tick 'Show reviewed items' to see them).")) { Set-Reviewed $evs; Request-Refresh }
    })
    $script:BtnTrusted = New-Object Windows.Forms.Button; $script:BtnTrusted.Text = 'Trusted apps...'; $script:BtnTrusted.Size = New-Object Drawing.Size 140, 32; $script:BtnTrusted.BackColor = [Drawing.Color]::White
    $script:BtnTrusted.Add_Click({ Show-TrustedApps })
    $btnBox.Width = 480
    $btnBox.Controls.AddRange(@($btnScan, $btnAll, $script:BtnTrusted))
    $hdr.Controls.AddRange(@($btnBox, $script:HdrTitle, $script:HdrSub))
    $script:Hdr = $hdr

    # Suggestion 3: Interactive Triage Card ("Was This You?")
    $tc = New-Object Windows.Forms.Panel; $tc.Dock = 'Top'; $tc.Height = 84; $tc.Padding = New-Object Windows.Forms.Padding 12, 8, 12, 8
    $tc.BackColor = [Drawing.Color]::FromArgb(255, 248, 225); $tc.Visible = $false
    $tcAccent = New-Object Windows.Forms.Panel; $tcAccent.Dock = 'Left'; $tcAccent.Width = 6; $tcAccent.BackColor = [Drawing.Color]::FromArgb(239, 108, 0)
    $tcBtnBox = New-Object Windows.Forms.FlowLayoutPanel; $tcBtnBox.Dock = 'Right'; $tcBtnBox.Width = 350; $tcBtnBox.FlowDirection = 'RightToLeft'; $tcBtnBox.Padding = New-Object Windows.Forms.Padding 0, 16, 8, 0
    $btnTriageNo = New-Object Windows.Forms.Button; $btnTriageNo.UseMnemonic = $false; $btnTriageNo.Text = 'X  No, it was not me'; $btnTriageNo.Size = New-Object Drawing.Size 165, 34
    $btnTriageNo.BackColor = [Drawing.Color]::FromArgb(198, 40, 40); $btnTriageNo.ForeColor = [Drawing.Color]::White; $btnTriageNo.Font = $Fonts.Bold
    $btnTriageNo.Add_Click({
        if ($script:CurrentTriageRow) {
            $r = $script:CurrentTriageRow
            if (Invoke-BlockRows @($r)) {
                Request-Refresh
                Show-Toast "Flagged" $(if (Test-TrayEnforcing) { 'Unauthorized activity blocked and logged.' } else { 'Flagged as a threat and logged (detect-only: nothing was stopped).' })
            }
        }
    })
    $btnTriageYes = New-Object Windows.Forms.Button; $btnTriageYes.UseMnemonic = $false; $btnTriageYes.Text = 'Yes, this was me'; $btnTriageYes.Size = New-Object Drawing.Size 155, 34
    $btnTriageYes.BackColor = [Drawing.Color]::FromArgb(46, 125, 50); $btnTriageYes.ForeColor = [Drawing.Color]::White; $btnTriageYes.Font = $Fonts.Bold
    $btnTriageYes.Add_Click({
        if ($script:CurrentTriageRow) {
            Set-Reviewed @(Get-RowEvents $script:CurrentTriageRow)
            Request-Refresh
            Show-Toast "Triage Completed" "Activity marked as authorized and reviewed."
        }
    })
    $tcBtnBox.Controls.AddRange(@($btnTriageNo, $btnTriageYes))
    $tcContent = New-Object Windows.Forms.Panel; $tcContent.Dock = 'Fill'; $tcContent.Padding = New-Object Windows.Forms.Padding 12, 4, 0, 0
    $tcTitle = New-Object Windows.Forms.Label; $tcTitle.Dock = 'Top'; $tcTitle.Height = 22; $tcTitle.Font = $Fonts.CardH; $tcTitle.ForeColor = [Drawing.Color]::FromArgb(191, 54, 12)
    $tcDetail = New-Object Windows.Forms.Label; $tcDetail.Dock = 'Top'; $tcDetail.Height = 22; $tcDetail.Font = $Fonts.Base; $tcDetail.ForeColor = [Drawing.Color]::FromArgb(40, 40, 40)
    $tcHelp = New-Object Windows.Forms.Label; $tcHelp.Dock = 'Top'; $tcHelp.Height = 20; $tcHelp.Font = $Fonts.Small; $tcHelp.ForeColor = [Drawing.Color]::FromArgb(100, 100, 100)
    $tcHelp.Text = "Only you can verify this. If you or your team performed this, click 'Yes, this was me'. If unexpected, click 'No, it was not me' to flag it as a threat."
    $tcContent.Controls.AddRange(@($tcHelp, $tcDetail, $tcTitle))
    $tc.Controls.AddRange(@($tcContent, $tcBtnBox, $tcAccent))
    $script:TriagePanel = $tc; $script:TriageTitle = $tcTitle; $script:TriageDetail = $tcDetail

    $tiles = New-Object Windows.Forms.TableLayoutPanel; $tiles.Dock = 'Top'; $tiles.Height = 270; $tiles.ColumnCount = 4; $tiles.RowCount = 2
    $tiles.Padding = New-Object Windows.Forms.Padding 10, 4, 10, 4
    for ($i = 0; $i -lt 4; $i++) { [void]$tiles.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle 'Percent', 25)) }
    for ($i = 0; $i -lt 2; $i++) { [void]$tiles.RowStyles.Add((New-Object Windows.Forms.RowStyle 'Percent', 50)) }
    $n = 0
    foreach ($k in @($SectionOrder) + @('sensors', 'scans')) {
        $name = if ($Sections[$k]) { $Sections[$k].Name } elseif ($k -eq 'sensors') { 'Sensors' } else { 'Updates and scans' }
        $script:Tiles[$k] = New-Tile $k $name
        $tiles.Controls.Add($script:Tiles[$k].Panel, ($n % 4), [Math]::Floor($n / 4)); $n++
    }

    # Suggestion 4: Forensics & Action History Header with Export
    $auditBar = New-Object Windows.Forms.Panel; $auditBar.Dock = 'Top'; $auditBar.Height = 36; $auditBar.Padding = New-Object Windows.Forms.Padding 14, 4, 14, 4
    $auditLbl = New-Object Windows.Forms.Label; $auditLbl.UseMnemonic = $false; $auditLbl.Dock = 'Left'; $auditLbl.Width = 500; $auditLbl.Font = $Fonts.CardH; $auditLbl.TextAlign = 'MiddleLeft'
    $auditLbl.Text = 'Forensics, Audit Ledger & System Messages'
    $btnExport = New-Object Windows.Forms.Button; $btnExport.Dock = 'Right'; $btnExport.Width = 160; $btnExport.Text = 'Export Audit Log (CSV)'; $btnExport.BackColor = [Drawing.Color]::White
    $btnExport.Add_Click({ Export-AuditLog })
    $auditBar.Controls.AddRange(@($btnExport, $auditLbl))

    $msgList = New-List 'overview'
    $ovp.Controls.Add($msgList); $ovp.Controls.Add($auditBar); $ovp.Controls.Add($tiles); $ovp.Controls.Add($tc); $ovp.Controls.Add($hdr)
    [void]$script:Tabs.TabPages.Add($ovp)

    # One tab per section: status bar with play/pause + 3 lifecycle sub-tabs (Detected / Blocked / Allowed)
    foreach ($s in $SectionOrder) {
        $tp = New-Object Windows.Forms.TabPage; $tp.Name = $s; $tp.BackColor = [Drawing.Color]::White
        $bar = New-Object Windows.Forms.Panel; $bar.Dock = 'Top'; $bar.Height = 34; $bar.BackColor = [Drawing.Color]::FromArgb(247, 247, 247)
        
        $badge = New-Object Windows.Forms.Label; $badge.Dock = 'Left'; $badge.Width = 130; $badge.TextAlign = 'MiddleLeft'
        $badge.Font = $Fonts.Bold; $badge.Padding = New-Object Windows.Forms.Padding 8, 0, 0, 0
        $badge.Text = '● ACTIVE'; $badge.ForeColor = [Drawing.Color]::FromArgb(46, 125, 50)
        
        $sl = New-Object Windows.Forms.Label; $sl.Dock = 'Fill'; $sl.TextAlign = 'MiddleLeft'; $sl.AutoEllipsis = $true; $sl.Padding = New-Object Windows.Forms.Padding 4, 0, 0, 0
        $sl.ForeColor = [Drawing.Color]::FromArgb(80, 80, 80)
        
        $rBox = New-Object Windows.Forms.FlowLayoutPanel; $rBox.Dock = 'Right'; $rBox.AutoSize = $true; $rBox.FlowDirection = 'RightToLeft'; $rBox.Padding = New-Object Windows.Forms.Padding 0, 6, 8, 0
        
        $lk = New-Object Windows.Forms.LinkLabel; $lk.AutoSize = $true; $lk.Tag = $s; $lk.Text = 'Pause...'
        $lk.Margin = New-Object Windows.Forms.Padding 6, 2, 6, 0
        $lk.Add_LinkClicked({ param($sender, $a) Invoke-StatusLink $sender.Tag $sender })
        
        $extraLk = New-Object Windows.Forms.LinkLabel; $extraLk.AutoSize = $true; $extraLk.Tag = $s; $extraLk.Text = ''
        $extraLk.Margin = New-Object Windows.Forms.Padding 6, 2, 6, 0; $extraLk.Visible = $false
        $extraLk.Add_LinkClicked({ param($sender, $a) Invoke-StatusExtraLink $sender.Tag $sender })
        
        $rBox.Controls.AddRange(@($lk, $extraLk))
        $bar.Controls.AddRange(@($sl, $rBox, $badge))
        $script:StatusBadge[$s] = $badge; $script:StatusLbl[$s] = $sl; $script:StatusLink[$s] = $lk; $script:StatusExtraLink[$s] = $extraLk

        $sub = New-Object Windows.Forms.TabControl; $sub.Dock = 'Fill'; $sub.Padding = New-Object Drawing.Point 14, 5
        for ($i = 0; $i -lt 3; $i++) {
            $sp = New-Object Windows.Forms.TabPage; $sp.Name = "$s|$i"; $sp.Text = $Sections[$s].Subs[$i]; $sp.BackColor = [Drawing.Color]::White
            $sp.Controls.Add((New-List "$s|$i"))
            [void]$sub.TabPages.Add($sp)
        }
        $sub.Add_SelectedIndexChanged({ Hide-Details })
        $script:SubTabs[$s] = $sub
        $tp.Controls.Add($sub); $tp.Controls.Add($bar)
        [void]$script:Tabs.TabPages.Add($tp)
    }
    $script:Tabs.Add_SelectedIndexChanged({ Hide-Details })

    # Details pane: hidden until an item is clicked
    $split = New-Object Windows.Forms.SplitContainer; $script:Split = $split; $split.Dock = 'Fill'; $split.Orientation = 'Horizontal'
    $split.Panel1.Controls.Add($script:Tabs)
    $split.Panel2.Padding = New-Object Windows.Forms.Padding 16, 6, 16, 8
    $split.Panel2.BackColor = [Drawing.Color]::FromArgb(250, 250, 250)
    $script:ActionBar = New-Object Windows.Forms.FlowLayoutPanel; $script:ActionBar.Dock = 'Top'; $script:ActionBar.WrapContents = $true
    $script:ActionBar.AutoSize = $true; $script:ActionBar.AutoSizeMode = 'GrowAndShrink'; $script:ActionBar.Padding = New-Object Windows.Forms.Padding 0, 0, 0, 6
    $script:Details = New-Object Windows.Forms.RichTextBox
    $script:Details.Dock = 'Fill'; $script:Details.ReadOnly = $true; $script:Details.BorderStyle = 'None'
    $script:Details.BackColor = [Drawing.Color]::FromArgb(250, 250, 250); $script:Details.DetectUrls = $false
    $split.Panel2.Controls.Add($script:Details)
    $split.Panel2.Controls.Add($script:ActionBar)
    $split.Panel2Collapsed = $true

    $f.Controls.Add($split)
    $f.Controls.Add($tb)
    $f.Add_FormClosing({ param($s, $a) if (-not $script:Exiting) { $a.Cancel = $true; $s.Hide() } })
    $script:Form = $f
    $script:ViewDirty = $true
}

function Add-Rtf([string]$Text, $Font = $Fonts.Base, $Color = [Drawing.Color]::FromArgb(33, 33, 33)) {
    $d = $script:Details
    $d.SelectionStart = $d.TextLength; $d.SelectionLength = 0
    $d.SelectionFont = $Font; $d.SelectionColor = $Color
    $d.AppendText($Text)
}

function Add-RtfRows($Rows) {
    $gray = [Drawing.Color]::FromArgb(100, 100, 100)
    foreach ($k in $Rows.Keys) { if ($Rows[$k]) { Add-Rtf ("{0,-14}" -f $k) $Fonts.Bold $gray; Add-Rtf "$($Rows[$k])`n" $Fonts.Mono } }
}

function Hide-Details {
    if (-not $script:Split) { return }
    $script:Split.Panel2Collapsed = $true
    $script:ActionBar.Controls.Clear()
}

function Show-DetailsPane {
    if ($script:Split.Panel2Collapsed) {
        $script:Split.Panel2Collapsed = $false
        try { $script:Split.SplitterDistance = [int]($script:Split.Height * 0.58) } catch { }
    }
}

$LoginHint = @('Someone signed in to this PC with a valid password from a public internet address (not your home network). With Remote Desktop reachable from the internet, this is either you (for example your phone on mobile data) or someone who knows the password.',
               'If it was you: Yes, it was me (or Always allow the address). If not: No, it wasn''t me - this blocks the address; then change your Windows password and limit Remote Desktop / file sharing to your home network.')

function Get-Hint($e) {
    if ($e.kind -eq 'login') { return $LoginHint }
    if ($e.blade -eq 'realtime' -and $RuleHints.ContainsKey([string]$e.rule)) { return $RuleHints[[string]$e.rule] }
    if ($e.blade -eq 'defender' -and $DefenderHints.ContainsKey([string]$e.kind)) { return $DefenderHints[[string]$e.kind] }
    if ($BladeHints.ContainsKey([string]$e.blade)) { return $BladeHints[[string]$e.blade] }
    return @('', '')
}

function Update-ActionBar($Rows) {
    $script:ActionBar.Controls.Clear()
    foreach ($a in @(Get-Actions $Rows)) {
        if ($a.Disabled) { continue }
        $b = New-Object Windows.Forms.Button
        $b.UseMnemonic = $false; $b.Text = $a.Text; $b.AutoSize = $true; $b.Height = 30; $b.BackColor = [Drawing.Color]::White; $b.Tag = $a
        $b.Margin = New-Object Windows.Forms.Padding 0, 2, 8, 2
        if ($a.Bold) { $b.Font = $Fonts.Bold }
        $b.Add_Click({ & $this.Tag.Run $this.Tag.Arg })
        $script:ActionBar.Controls.Add($b)
    }
    $c = New-Object Windows.Forms.Button; $c.Text = 'Close details'; $c.AutoSize = $true; $c.Height = 30; $c.FlatStyle = 'Flat'
    $c.Margin = New-Object Windows.Forms.Padding 16, 2, 0, 2; $c.Add_Click({ Hide-Details })
    $script:ActionBar.Controls.Add($c)
}

function Build-ListMenu($Lv, $Menu) {
    $Menu.Items.Clear()
    $rows = @(Get-SelectedRows $Lv)
    if (-not $rows.Count) { return }
    foreach ($a in @(Get-Actions $rows)) {
        $mi = New-MenuItem ($a.Text -replace '&', '&&') $a { & $this.Tag.Run $this.Tag.Arg }
        if ($a.Bold) { $mi.Font = $script:BoldFont }
        if ($a.Disabled) { $mi.Enabled = $false }
        [void]$Menu.Items.Add($mi)
    }
}

function Export-AuditLog {
    # Saved where the user chooses (default Documents): the tray runs unelevated and cannot write under Program Files
    $dlg = New-Object Windows.Forms.SaveFileDialog
    $dlg.Title = 'Export audit log'; $dlg.Filter = 'CSV file (*.csv)|*.csv'; $dlg.DefaultExt = 'csv'
    $dlg.InitialDirectory = [Environment]::GetFolderPath('MyDocuments')
    $dlg.FileName = "FreeEDR-Audit-Export-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    if ($dlg.ShowDialog() -ne 'OK') { $dlg.Dispose(); return }
    $exportPath = $dlg.FileName; $dlg.Dispose()
    try {
        $csvLines = New-Object System.Collections.ArrayList
        [void]$csvLines.Add('"Timestamp","Severity","Category","ActionOrMessage","DetailsOrTarget","Initiator"')
        foreach ($m in @($script:Model.Messages)) {
            $ev = $m.Ev
            $time = if ($ev.time) { [string]$ev.time } else { [string]$m.Time }
            $sev = if ($ev.severity) { [string]$ev.severity } else { [string]$m.Sev }
            # The engine stores the audit fields (rubric, action, user, ...) on the event itself
            $rubric = if ($ev.rubric) { [string]$ev.rubric } elseif ($ev.blade) { [string]$ev.blade } else { 'system' }
            $title = ([string]$m.Cols[1] -replace '"', '""')
            $detail = ([string]$m.Cols[2] -replace '"', '""')
            $user = if ($ev.user) { [string]$ev.user } else { 'Engine' }
            [void]$csvLines.Add(('"{0}","{1}","{2}","{3}","{4}","{5}"' -f $time, $sev, $rubric, $title, $detail, $user))
        }
        foreach ($b in @($script:Blocks)) {
            $bTime = if ($b.added) { [string]$b.added } else { '' }
            $bTarget = if ($b.image) { [string]$b.image } elseif ($b.ip) { [string]$b.ip } else { '' }
            $bTargetEsc = ($bTarget -replace '"', '""')
            [void]$csvLines.Add(('"{0}","High","blocklist","{2}","{1}","User"' -f $bTime, $bTargetEsc, $(if ($b.enforce) { 'Blocked' } else { 'Flagged' })))
        }
        [IO.File]::WriteAllLines($exportPath, [string[]]$csvLines, [System.Text.Encoding]::UTF8)
        Show-Toast "Audit Log Exported" "Forensic ledger saved to: $exportPath"
        Start-Process notepad.exe "`"$exportPath`""
    } catch {
        Show-Toast "Export Failed" $_.Exception.Message
    }
}

function Write-EventDetails($e, $Row, [string]$Where) {
    $gray = [Drawing.Color]::FromArgb(100, 100, 100)
    $hint = Get-Hint $e
    $sevColor = switch ([string]$e.severity) { 'Critical' { $Palette.down } 'High' { [Drawing.Color]::FromArgb(191, 54, 12) } 'Medium' { [Drawing.Color]::FromArgb(130, 90, 0) } default { $gray } }
    $sep = '   ' + [char]0xB7 + '   '
    $count = @($Row.Group).Count
    Add-Rtf "$($e.title)`n" $Fonts.H2
    Add-Rtf "$($e.severity)" $Fonts.Bold $sevColor
    Add-Rtf "${sep}$Where${sep}caught by $($BladeNames[[string]$e.blade])${sep}$($e.time)$(if ($count -gt 1) { "${sep}$count times" })$(if (Test-Retired $e) { "${sep}from a retired rule (old Sysmon rule set)" } elseif (Test-Reviewed $e) { "${sep}reviewed" })`n`n" $Fonts.Base $gray
    if ($Row.Pinned -and $Row.List -eq 0) { Add-Rtf "WAS THIS YOU?`n" $Fonts.Label $Palette.down; Add-Rtf "Only you can tell. Yes = mark it reviewed (future ones are still reported). No = block it / keep it as a confirmed threat.`n`n" }
    $sp = if ($e.blade -eq 'sigma') { Get-SigmaInfo $e } else { @{ Image = $e.process; Parent = $e.parent } }
    if ($hint[0]) { Add-Rtf "WHAT HAPPENED`n" $Fonts.Label $gray; Add-Rtf "$($hint[0])`n`n" }
    if ($hint[1] -and $Row.List -eq 0) { Add-Rtf "WHAT TO DO`n" $Fonts.Label $gray; Add-Rtf "$($hint[1])`n`n" }
    if ($e.kind -eq 'audit') {
        Add-Rtf "FORENSIC AUDIT RECORD (Event ID 3000)`n" $Fonts.Label $Palette.ok
        Add-Rtf "Administrative action logged in tamper-evident engine log and Windows Event Log.`n`n" $Fonts.Base $gray
    }
    Add-Rtf "DETAILS`n" $Fonts.Label $gray
    $detailsMap = [ordered]@{
        'Program' = $sp.Image; 'Started by' = $sp.Parent; 'User' = $e.user; 'Rule' = $e.rule; 'Threat' = $e.threat
        'IP address' = $e.ip; 'Location' = $e.path; 'SHA256' = $e.sha256; 'Latest' = $e.latest; 'Download' = $e.url; 'Detail' = $e.detail
    }
    if ($e.kind -eq 'audit') {
        if ($e.rubric) { $detailsMap['Rubric'] = $e.rubric }
        if ($e.action) { $detailsMap['Action'] = $e.action }
        if ($e.user) { $detailsMap['Initiator'] = $e.user; $detailsMap['User'] = $null }
        if ($e.until) { $detailsMap['Expires / Until'] = $e.until }
        if ($e.duration) { $detailsMap['Duration'] = $e.duration }
    }
    Add-RtfRows $detailsMap
}

function Show-Details($Lv) {
    $rows = @(Get-SelectedRows $Lv)
    if (-not $rows.Count) { return }
    $row = $rows[0]
    Show-DetailsPane
    Update-ActionBar $rows
    $d = $script:Details; $d.Clear()
    $gray = [Drawing.Color]::FromArgb(100, 100, 100)
    $S = $Sections[$row.Sec]
    $where = if ($S) { "$($S.Name) > $($S.Subs[$row.List])" } else { 'EDR messages' }
    switch ($row.Kind) {
        'block' {
            $b = $row.Entry
            Add-Rtf "$(if ($b.image) { Get-Leaf $b.image } elseif ($b.ip) { $b.ip } else { $b.title })`n" $Fonts.H2
            Add-Rtf "$where`n`n" $Fonts.Base $gray
            Add-Rtf "$($b.note)`n`n"
            Add-RtfRows ([ordered]@{ 'Since' = $b.added; 'Program' = $b.image; 'Reason' = $b.title; 'SHA256' = $b.sha256; 'Quarantine' = $b.quarantine; 'Stopped' = $(if ([int]$b.hits) { "$($b.hits) time(s) after blocking" }); 'Detections' = $(if (@($row.Group).Count) { @($row.Group).Count }) })
            if ($row.Ev) { Add-Rtf "`nLAST DETECTION`n" $Fonts.Label $gray; Add-RtfRows ([ordered]@{ 'When' = $row.Ev.time; 'What' = $row.Ev.title; 'Detail' = $row.Ev.detail }) }
        }
        'excl' {
            Add-Rtf "Allowed: $($row.Note)`n" $Fonts.H2
            Add-Rtf "$where   $([char]0xB7)   added $($row.Entry.added)`n`n" $Fonts.Base $gray
            Add-Rtf "Matching activity is not reported$(if ($row.ExclList -eq 'wail2ban') { ' and never blocked' }). Use the buttons to move it back to $($S.Subs[0]) or to $($S.Subs[1]).`n"
            if (@($row.Group).Count) { Add-Rtf "`n$(@($row.Group).Count) past detection(s) match this.`n" $Fonts.Base $gray }
        }
        'builtin' {
            Add-Rtf "$($row.Note)`n" $Fonts.H2
            Add-Rtf "Built into the Sysmon configuration so games and anti-cheat run untouched. To change it, edit config\sysmonconfig.template.xml and re-run Install-EDR.ps1." $Fonts.Base $gray
        }
        'cve' {
            $v = $row.Entry
            Add-Rtf "$($v.cve) in $($v.package)`n" $Fonts.H2
            Add-Rtf "$($v.severity)$(if ($v.score) { " (CVSS $($v.score))" })   $([char]0xB7)   $where`n`n" $Fonts.Bold $gray
            Add-Rtf "WHAT HAPPENED`n" $Fonts.Label $gray; Add-Rtf "$($BladeHints.cve[0])`n$($v.summary)`n`n"
            Add-Rtf "WHAT TO DO`n" $Fonts.Label $gray; Add-Rtf "$($BladeHints.cve[1])`n`n"
            $fix = if ($v.fixPackage -and $v.fixPackage -ine $v.package) { "Update $($v.fixPackage) (it bundles $($v.package))" } else { "pip install --upgrade `"$($v.package)>=$($v.fixed)`"" }
            Add-Rtf "DETAILS`n" $Fonts.Label $gray
            Add-RtfRows ([ordered]@{ 'Package' = $v.package; 'Installed' = $v.version; 'Fixed in' = $v.fixed; 'Fix' = $fix; 'Python' = $v.python; 'IDs' = (@($v.aliases) -join ', '); 'Location' = $v.path; 'Checked' = (Format-When $script:Cve.scanned) })
        }
        'hist' {
            $h = $row.Entry
            Add-Rtf "$(if ($h.cve) { "$($h.cve) in $($h.package)" } else { $h.name })`n" $Fonts.H2
            Add-Rtf "$where`n`n" $Fonts.Base $gray
            Add-Rtf "Update started $($h.time). If it is still needed at the next check, it returns to $($S.Subs[0]).`n`n"
            Add-RtfRows ([ordered]@{ 'From' = $h.version; 'To' = $(if ($h.fixed) { $h.fixed } else { $h.latest }); 'ID' = $h.key })
        }
        'app' {
            $p = $row.Entry
            Add-Rtf "$($p.process)`n" $Fonts.H2
            Add-Rtf "$where`n`n" $Fonts.Base $gray
            Add-Rtf "$($BladeHints.patch[0])`n`n"
            Add-RtfRows ([ordered]@{ 'Installed' = $p.version; 'Update to' = $p.latest; 'winget ID' = $p.appId })
        }
        'hidden' {
            Add-Rtf "$($row.Entry)`n" $Fonts.H2
            Add-Rtf "$where`n`nUpdates for this app are not listed. Move it back to Available to see them again." $Fonts.Base $gray
        }
        { $_ -in 'ban', 'banhist' } {
            $ip = [string]$row.Ev.ip
            Add-Rtf "$ip`n" $Fonts.H2
            Add-Rtf "$where`n`n" $Fonts.Base $gray
            Add-RtfRows ([ordered]@{ 'Blocked until' = $row.Cols[2]; 'Strikes' = $row.Cols[3]; 'Network' = $row.Cols[4]; 'How' = $row.Cols[5]; 'Detail' = $row.Ev.detail })
            Add-Rtf "`nAutomatic blocks last 5x longer with each strike (one strike is forgiven per clean day). Block permanently to keep it out for good." $Fonts.Base $gray
        }
        default { Write-EventDetails $row.Ev $row $where }
    }
    $d.SelectionStart = 0; $d.ScrollToCaret()
}

function Get-ScanTimesText {
    $t = if ($script:Status -and $script:Status.scan.times) { @($script:Status.scan.times) } else { @($script:Cfg.scanTimes) }
    return ($t -join ' and ')
}

function Get-StepTime([string]$Pattern) {
    $r = $script:ScanRes
    if (-not $r) { return 'not yet' }
    $s = @($r.steps | Where-Object { $_.name -like "*$Pattern*" }) | Select-Object -Last 1
    if (-not $s) { return 'not yet' }
    $t = if ($s.time) { $s.time } else { $r.finished }
    return "$(Format-When $t 'ddd HH:mm')$(if (-not $s.ok) { ' (FAILED - see scan log)' })"
}

function Get-SectionStatus([string]$Sec) {
    $st = $script:Status
    if (-not (Test-EngineAlive)) { return @{ Badge = '❚❚ OFF'; BadgeColor = 'down'; Text = 'The EDR engine is not running. Right-click tray shield > Advanced > Restart engine.'; Link = ''; Act = '' } }
    $next = Format-When $st.scan.nextDue 'ddd HH:mm'
    $times = Get-ScanTimesText
    $sep = '   |   '
    $bladeKey = if ($Sec -eq 'edr') { 'realtime' } else { $Sec }
    $pState = Get-PauseState $bladeKey
    $isPaused = ($pState -and $pState.state -eq 'paused')
    $badge = if ($isPaused) { '❚❚ ON HOLD' } else { '● ACTIVE' }
    $badgeColor = if ($isPaused) { 'attention' } else { 'ok' }
    $pLink = if ($isPaused) { 'Resume' } else { 'Pause...' }
    $untilTxt = if ($isPaused) { " ($(Format-Until $pState))" } else { '' }

    switch ($Sec) {
        'malware' {
            return @{
                Badge = "$badge$untilTxt"; BadgeColor = $badgeColor
                Text = "IOC hashes ($($st.edr.iocHashes)) & YARA rules ($(@($st.edr.yaraRules).Count)).${sep}Next scan: $next"
                Link = $pLink; Act = 'pause-malware'; ExtraLink = 'Update now'; ExtraAct = 'scan'
            }
        }
        'edr' {
            $sysmonTxt = if ($st.sysmon.ok) { 'running' } else { $st.sysmon.message }
            return @{
                Badge = "$badge$untilTxt"; BadgeColor = $badgeColor
                Text = "Real-time process tracking (Sysmon: $sysmonTxt).$(if (Test-TrayEnforcing) { ' Live blocking: blocked programs are stopped when they start.' } else { ' Detect-only: nothing is stopped.' })"
                Link = $pLink; Act = 'pause-realtime'
            }
        }
        'sigma' {
            return @{
                Badge = "$badge$untilTxt"; BadgeColor = $badgeColor
                Text = "Hayabusa event-log scan (last $($script:Cfg.sigmaLookback)). Scanned $(Get-StepTime 'Sigma event').${sep}Runs at $times"
                Link = $pLink; Act = 'pause-sigma'; ExtraLink = 'Scan now'; ExtraAct = 'scan'
            }
        }
        'cve' {
            return @{
                Badge = "$badge$untilTxt"; BadgeColor = $badgeColor
                Text = "OSV vulnerability checks for Python packages. Scanned $(Get-StepTime 'OSV').${sep}Runs at $times"
                Link = $pLink; Act = 'pause-cve'; ExtraLink = 'Check now'; ExtraAct = 'scan'
            }
        }
        'apps' {
            $l = if ($script:PatchProc) { 'Checking...' } else { 'Check now' }
            return @{
                Badge = '● ACTIVE'; BadgeColor = 'ok'
                Text = "App update checks via winget. Checked $(Format-When $script:PatchChecked 'ddd HH:mm'). Next: $(Format-When $script:PatchNext 'ddd HH:mm')"
                Link = $l; Act = 'winget'
            }
        }
        'wail2ban' {
            $w = $st.wail2ban
            $wt = if ($w.state -eq 'error') { "NOT WORKING: $($w.error)" } elseif (Test-TrayEnforcing) { "$(@($w.banned).Count) IP(s) currently blocked" } else { 'Detect-only: password guessing is reported, never blocked' }
            return @{
                Badge = "$badge$untilTxt"; BadgeColor = $badgeColor
                Text = "Brute-force logon defense. $wt (bans after $($script:Cfg.wail2ban.failCount) failures in $([int]($script:Cfg.wail2ban.windowSeconds / 60))m)."
                Link = $pLink; Act = 'pause-wail2ban'
            }
        }
    }
}

function Invoke-StatusLink([string]$Sec, $Control) {
    switch ((Get-SectionStatus $Sec).Act) {
        'scan'           { Invoke-ScanNow }
        'winget'         { $script:PatchNext = Get-Date; Show-Toast 'Checking for app updates' 'The App Updates list refreshes in a minute or two.' }
        'pause-malware'  { Invoke-PauseLink 'malware' $Control }
        'pause-realtime' { Invoke-PauseLink 'realtime' $Control }
        'pause-edr'      { Invoke-PauseLink 'edr' $Control }
        'pause-sigma'    { Invoke-PauseLink 'sigma' $Control }
        'pause-cve'      { Invoke-PauseLink 'cve' $Control }
        'pause-wail2ban' { Invoke-PauseLink 'wail2ban' $Control }
    }
}

function Update-SectionStatus {
    foreach ($s in $SectionOrder) {
        $x = Get-SectionStatus $s
        if ($script:StatusBadge[$s] -and $script:StatusBadge[$s].Text -ne $x.Badge) {
            $script:StatusBadge[$s].Text = $x.Badge
            $script:StatusBadge[$s].ForeColor = if ($x.BadgeColor -eq 'ok') { [Drawing.Color]::FromArgb(46, 125, 50) } elseif ($x.BadgeColor -eq 'down') { $Palette.down } else { [Drawing.Color]::FromArgb(239, 108, 0) }
        }
        if ($script:StatusLbl[$s].Text -ne $x.Text) { $script:StatusLbl[$s].Text = $x.Text }
        if ($script:StatusLink[$s].Text -ne $x.Link) { $script:StatusLink[$s].Text = $x.Link }
        if ($script:StatusExtraLink[$s]) {
            if ($x.ExtraLink) {
                if ($script:StatusExtraLink[$s].Text -ne $x.ExtraLink) { $script:StatusExtraLink[$s].Text = $x.ExtraLink }
                if (-not $script:StatusExtraLink[$s].Visible) { $script:StatusExtraLink[$s].Visible = $true }
            } else {
                if ($script:StatusExtraLink[$s].Visible) { $script:StatusExtraLink[$s].Visible = $false }
            }
        }
    }
}

function Set-Tile([string]$Key, [string]$Color, [string]$Value, [string]$Sub, [string]$Link) {
    $t = $script:Tiles[$Key]
    $t.Bar.BackColor = $Palette[$Color]; $t.Value.ForeColor = $(if ($Color -eq 'ok') { [Drawing.Color]::FromArgb(33, 33, 33) } else { $Palette[$Color] })
    if ($t.Value.Text -ne $Value) { $t.Value.Text = $Value }
    if ($t.Sub.Text -ne $Sub) { $t.Sub.Text = $Sub }
    if ($t.Link.Text -ne $Link) { $t.Link.Text = $Link }
}

function Update-Overview {
    $ov = Get-Overall
    $script:Hdr.BackColor = $PaletteLight[$ov.Key]
    $script:HdrTitle.Text = $ov.Text; $script:HdrTitle.ForeColor = $Palette[$ov.Key]
    $script:HdrSub.Text = $ov.Sub
    $script:Form.Icon = $Icons[$ov.Key]
    $st = $script:Status; $alive = Test-EngineAlive

    # Suggestion 3: Update "Was This You?" Interactive Triage Banner
    $allPinned = @()
    foreach ($s in $SectionOrder) {
        $allPinned += @($script:Model.Sec[$s].Rows[0] | Where-Object { $_.Pinned -and -not $_.Muted })
    }
    if ($allPinned.Count -gt 0) {
        $p = $allPinned[0]
        $script:CurrentTriageRow = $p
        $pendingTxt = if ($allPinned.Count -gt 1) { " (1 of $($allPinned.Count) alerts needing decision)" } else { "" }
        $script:TriageTitle.Text = "[!] CRITICAL ALERT TRIAGE: Was this you?$pendingTxt"
        $script:TriageDetail.Text = "$($p.Ev.title)$(if ($p.Ev.time) { " [Time: $($p.Ev.time)]" })$(if ($p.Ev.user) { " [User: $($p.Ev.user)]" })$(if ($p.Ev.ip) { " [IP: $($p.Ev.ip)]" })"
        if (-not $script:TriagePanel.Visible) { $script:TriagePanel.Visible = $true }
    } else {
        $script:CurrentTriageRow = $null
        if ($script:TriagePanel.Visible) { $script:TriagePanel.Visible = $false }
    }

    foreach ($s in $SectionOrder) {
        $c = $script:Model.Sec[$s]; $n0 = $c.Count; $def = $Sections[$s]
        $n1 = @($c.Rows[1] | Where-Object { -not $_.Muted }).Count; $n2 = @($c.Rows[2]).Count
        if (-not $n0) { $value = 'All clear' }
        elseif ($s -eq 'cve') { $value = "$n0 need$(if ($n0 -eq 1) { 's' }) an update" }
        elseif ($s -eq 'apps') { $value = "$n0 update$(if ($n0 -ne 1) { 's' }) available" }
        elseif ($s -eq 'wail2ban') { $value = "$n0 address$(if ($n0 -ne 1) { 'es' }) failing to log in" }
        else { $value = "$n0 to review" }
        $pBlade = if ($s -eq 'edr') { 'realtime' } else { $s }
        $bState = Get-PauseState $pBlade
        $paused = ($bState -and $bState.state -eq 'paused')
        $color = if (-not $alive -and $s -ne 'apps') { 'down' } elseif ($c.Alert) { 'down' } elseif ($n0) { 'attention' } elseif ($paused) { 'paused' } else { 'ok' }
        if ($paused) { $value += '  (paused)' }
        $link = if ($s -eq 'apps') { 'Open' } elseif ($paused) { 'Resume' } else { 'Pause...' }
        Set-Tile $s $color $value "$n1 $($def.Subs[1].ToLower())   |   $n2 $($def.Subs[2].ToLower())" $link
    }
    if (-not $alive) { Set-Tile 'sensors' 'down' 'Unknown' 'The EDR engine is not running.' 'Open engine log' }
    else {
        $def = if ($st.defender) { "Defender $(if ($st.defender.realtime) { 'on' } else { 'OFF' }) | $($st.defender.asrBlockRules) ASR rules | folders $($st.defender.controlledFolders)" } else { 'Defender status unknown' }
        Set-Tile 'sensors' $(if ($st.sysmon.ok) { 'ok' } else { 'down' }) $(if ($st.sysmon.ok) { 'Sysmon running' } else { "Sysmon: $($st.sysmon.message)" }) $def 'Open engine log'
    }
    if (-not $alive) { Set-Tile 'scans' 'down' 'Unknown' '' 'Open scan log' }
    elseif ($st.scan.running) { Set-Tile 'scans' 'attention' 'Updating now...' "Runs at $(Get-ScanTimesText)" 'Open scan log' }
    else {
        $ok = $st.scan.ok -ne $false
        Set-Tile 'scans' $(if ($ok) { 'ok' } else { 'attention' }) "Next: $(Format-When $st.scan.nextDue 'ddd HH:mm')" "Last: $(Format-When $st.scan.lastEnd 'ddd HH:mm') $(if ($ok) { '(OK)' } else { '(problems - see log)' })   |   runs at $(Get-ScanTimesText)" 'Open scan log'
    }
}

function Update-Lists {
    $m = $script:Model.Sec
    foreach ($s in $SectionOrder) {
        for ($i = 0; $i -lt 3; $i++) {
            $key = "$s|$i"
            $rows = @($m[$s].Rows[$i] | Where-Object { $_ -and ($i -ne 0 -or $script:ShowReviewed -or -not $_.Muted) -and (Test-RowMatch $_) })
            $items = @($rows | ForEach-Object { New-RowItem $_ })
            if (-not $items.Count) { $items = @(New-PlaceholderItem $key $(if ($script:Search) { 'Nothing matches the search.' } else { $EmptyText[$key] })) }
            Set-ListItems $script:Lv[$key] $items
            $name = $Sections[$s].Subs[$i]
            $script:SubTabs[$s].TabPages[$i].Text = if ($rows.Count) { "$name ($($rows.Count))" } else { $name }
        }
        $cnt = $m[$s].Count
        $script:TabInfo[$s] = @{ Text = $(if ($cnt) { "$($Sections[$s].Name) ($cnt)" } else { $Sections[$s].Name }); Alert = $m[$s].Alert }
    }
    $rows = @($script:Model.Messages | Where-Object { Test-RowMatch $_ })
    $items = @($rows | ForEach-Object { New-RowItem $_ })
    if (-not $items.Count) { $items = @(New-PlaceholderItem 'overview' $EmptyText['overview']) }
    Set-ListItems $script:Lv['overview'] $items
    $script:Tabs.Invalidate()
}

function Update-Dashboard {
    if ($script:ModelDirty) {
        Update-Model
        if ($script:Form -and $script:Form.Visible) { [Windows.Forms.Application]::DoEvents() }
    }
    if (-not $script:Form -or -not $script:Form.Visible) { return }
    Update-Overview
    Update-SectionStatus
    if (-not $script:ViewDirty) { return }
    $script:ViewDirty = $false
    Update-Lists
}

function Select-ById([string]$Id) {
    foreach ($key in @($script:Lv.Keys)) {
        $lv = $script:Lv[$key]
        foreach ($it in $lv.Items) {
            $row = $it.Tag
            if (-not $row) { continue }
            if ($row.Key -eq $Id -or ($row.Ev -and $row.Ev.id -eq $Id) -or @($row.Group | Where-Object { $_.id -eq $Id }).Count) {
                $parts = $key.Split('|')
                $script:Tabs.SelectedTab = $script:Tabs.TabPages[$parts[0]]
                if ($parts.Count -gt 1) { $script:SubTabs[$parts[0]].SelectedIndex = [int]$parts[1] }
                $lv.SelectedItems.Clear(); $it.Selected = $true; $it.Focused = $true; $it.EnsureVisible()
                return
            }
        }
    }
}

function Show-Dashboard([string]$SelectId = $null, [string]$Section = $null) {
    if (-not $script:Form) { New-Dashboard }
    $script:ViewDirty = $true
    if (-not $script:Form.Visible) { $script:Form.Show() }
    if ($script:Form.WindowState -eq 'Minimized') { $script:Form.WindowState = 'Normal' }
    $script:Form.Activate()
    Update-Dashboard
    if ($Section) { Open-Section $Section 0 }
    if ($SelectId) { Select-ById $SelectId }
}

################################################################################
# Self-test: build everything from the live data without showing UI

if ($SelfTest) {
    Update-Status
    $script:Initial = $true
    Read-NewEvents
    # Optional test data (EDR_SELFTEST_CVE / EDR_SELFTEST_BLOCKS = paths to a cve-current.json / blocklist.json)
    if ($env:EDR_SELFTEST_CVE) { $script:Cve = Read-Json $env:EDR_SELFTEST_CVE $null }
    if ($env:EDR_SELFTEST_BLOCKS) { $b = Read-Json $env:EDR_SELFTEST_BLOCKS $null; if ($b) { $script:Blocks = @($b.items) } }
    Update-Model
    New-Dashboard
    Update-Overview; Update-SectionStatus; Update-Lists
    "Overall : $((Get-Overall).Text) - $((Get-Overall).Sub)"
    foreach ($s in $SectionOrder) {
        $c = $script:Model.Sec[$s]
        "{0,-9} open={1,-3} alert={2,-5} | {3}={4}  {5}={6}  {7}={8}" -f $s, $c.Count, $c.Alert, $Sections[$s].Subs[0], @($c.Rows[0]).Count, $Sections[$s].Subs[1], @($c.Rows[1]).Count, $Sections[$s].Subs[2], @($c.Rows[2]).Count
        "          status: $((Get-SectionStatus $s).Text)"
    }
    "Messages: $(@($script:Model.Messages).Count)"
    if ($env:EDR_SELFTEST_DUMP) {
        # Parity fixture for the C# tray: the exact inputs read above plus the model built from them
        $dir = $env:EDR_SELFTEST_DUMP
        foreach ($d in 'data', 'config', 'local') { New-Item -ItemType Directory -Path "$dir\inputs\$d" -Force | Out-Null }
        $cveSrc = if ($env:EDR_SELFTEST_CVE) { $env:EDR_SELFTEST_CVE } else { $CveFile }
        foreach ($f in @(@($StatusFile, 'data\status.json'), @($cveSrc, 'data\cve-current.json'), @($ScanResult, 'data\scan-result.json'), @($ExclFile, 'config\exclusions.json'),
                         @($BlockFile, 'config\blocklist.json'), @($SysmonConfig, 'config\sysmonconfig.xml'), @($ReviewedFile, 'local\reviewed.txt'),
                         @($IgnoredApps, 'local\ignored-apps.txt'), @($HistoryFile, 'local\history.json'))) {
            $to = [IO.Path]::GetFullPath("$dir\inputs\$($f[1])")
            if ((Test-Path $f[0]) -and [IO.Path]::GetFullPath($f[0]) -ne $to) { Copy-Item $f[0] $to -Force }
        }
        if ($env:EDR_SELFTEST_BLOCKS) { Copy-Item $env:EDR_SELFTEST_BLOCKS "$dir\inputs\config\blocklist.json" -Force }
        if ([IO.Path]::GetFullPath($EventsFile) -ne [IO.Path]::GetFullPath("$dir\inputs\data\events.jsonl")) {
            $fs = [IO.File]::Open($EventsFile, 'Open', 'Read', 'ReadWrite,Delete')
            try { $buf = New-Object byte[] $script:Offset; [void]$fs.Read($buf, 0, $buf.Length) } finally { $fs.Dispose() }
            [IO.File]::WriteAllBytes("$dir\inputs\data\events.jsonl", $buf)
        }
        $ov = Get-Overall
        $rowOut = { param($r) [ordered]@{ kind = $r.Kind; key = $r.Key; time = [string]$r.Time; sev = [string]$r.Sev; cols = @($r.Cols); muted = [bool]$r.Muted; pinned = [bool]$r.Pinned; group = @($r.Group).Count } }
        $secs = [ordered]@{}
        foreach ($s in $SectionOrder) {
            $c = $script:Model.Sec[$s]
            $secs[$s] = [ordered]@{ count = $c.Count; alert = [bool]$c.Alert; attention = $c.Attention
                                   lists = @(foreach ($i in 0..2) { , @(@($c.Rows[$i]) | Where-Object { $_ } | ForEach-Object { & $rowOut $_ }) }) }
        }
        $dump = [ordered]@{ now = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss'); overall = [ordered]@{ key = $ov.Key; text = $ov.Text; sub = $ov.Sub }
                            attention = $script:Model.Attention; pinned = $script:Model.Pinned; claude = [string]$script:Model.Claude
                            sections = $secs; messages = @(@($script:Model.Messages) | ForEach-Object { & $rowOut $_ }) }
        [IO.File]::WriteAllText("$dir\model.json", ($dump | ConvertTo-Json -Depth 10), $Utf8NoBom)
        "Dump  : $dir"
    }
    foreach ($key in @($script:Lv.Keys | Sort-Object)) {
        $it = @($script:Lv[$key].Items | Where-Object { $_.Tag }) | Select-Object -First 1
        if (-not $it) { continue }
        $it.Selected = $true
        Show-Details $script:Lv[$key]
        "{0,-11} [{1}] {2}  ->  {3}" -f $key, $it.Tag.Kind, (Get-Short (($it.Tag.Cols | Where-Object { $_ }) -join ' / ') 70), ((@(Get-Actions @($it.Tag)) | ForEach-Object { $_.Text }) -join ' | ')
    }
    if ($env:EDR_SELFTEST_PNG) {
        # Screenshots of the Overview and each section tab (first sub-tab), for checking the layout
        $script:Form.StartPosition = 'Manual'; $script:Form.Location = New-Object Drawing.Point -3000, 0
        $script:Form.Show(); Update-Dashboard
        foreach ($k in @('overview') + $SectionOrder) {
            Open-Section $k 0; Hide-Details
            $it = if ($k -ne 'overview') { @($script:Lv["$k|0"].Items | Where-Object { $_.Tag }) | Select-Object -First 1 }
            if ($it) { $it.Selected = $true; Show-Details $script:Lv["$k|0"] }
            [Windows.Forms.Application]::DoEvents()
            $bmp = New-Object Drawing.Bitmap $script:Form.Width, $script:Form.Height
            $script:Form.DrawToBitmap($bmp, (New-Object Drawing.Rectangle 0, 0, $script:Form.Width, $script:Form.Height))
            $bmp.Save((Join-Path $env:EDR_SELFTEST_PNG "$k.png")); $bmp.Dispose()
        }
        $script:Exiting = $true; $script:Form.Close()
    }
    $script:Tray.Dispose()
    exit 0
}

################################################################################
# Main loop

function Invoke-Tick {
    if ($script:ExitSignal.WaitOne(0)) { $script:Exiting = $true; $script:Tray.Visible = $false; [Windows.Forms.Application]::Exit(); return }
    if ($script:ShowSignal.WaitOne(0)) { Show-Dashboard }
    Update-Status
    Read-NewEvents
    Update-PatchCheck
    Send-QueuedToasts
    Update-Dashboard
    Update-TrayIcon
    if ($script:WizardPending -and (Test-EngineAlive)) {
        # First start after install: review the trusted apps once (the installer already switched on the recommended ones)
        $script:WizardPending = $false
        try { [IO.File]::WriteAllText($WizardFlag, (Get-Date).ToString('s')) } catch { }
        Show-TrustedApps
    }
}

$WizardFlag = "$LocalDir\trusted-apps-reviewed.txt"
$script:WizardPending = -not (Test-Path $WizardFlag)

try {
    Update-Status
    Read-NewEvents
    Update-Model
    Update-TrayIcon
    $script:Initial = $false
} catch { Write-TrayLog "Startup: $_ $($_.ScriptStackTrace)" }

$timer = New-Object Windows.Forms.Timer
$timer.Interval = 2000
$timer.Add_Tick({ try { Invoke-Tick } catch { Write-TrayLog "Tick: $_ $($_.ScriptStackTrace)" } })
$timer.Start()

if ($Show) { Show-Dashboard }
else {
    $ov = Get-Overall
    Show-Toast "EDR: $($ov.Text)" 'Left-click the shield for the dashboard, right-click for controls.' $(if ($ov.Key -eq 'down') { 'Error' } else { 'Info' })
}

[Windows.Forms.Application]::Run()
$timer.Stop()
$script:Tray.Visible = $false
$script:Tray.Dispose()
