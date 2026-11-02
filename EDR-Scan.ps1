# EDR-Scan.ps1 - scheduled scan (twice a day), started by EDR-Engine.ps1 (as SYSTEM). Writes data\scan-result.json.
#   A. IOC hash feed update (kept on failure)   B. Sigma rules update + Hayabusa scan of recent event logs
#   C. OSV vulnerability scan of Python (only packages with a released fix are reported)
#   D. check for newer versions of the EDR tools
# The winget app-update check runs in the tray instead (it needs the user's context).

$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\EDR-Common.ps1"
$cfg   = Get-EdrConfig
$state = Read-Json $StateFile $null

$result = [ordered]@{ started = (Get-Date).ToString('s'); finished = $null; steps = @(); sigma = @(); vulns = @(); tools = @(); toolCheck = $null }
function Add-Step([string]$Name, [bool]$Ok, [string]$Message) {
    $script:result.steps += [pscustomobject]@{ name = $Name; ok = $Ok; message = $Message; time = (Get-Date).ToString('s') }
    Add-TextLine $ScanLog ("{0} [{1}] {2}: {3}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $(if ($Ok) { 'OK' } else { 'FAIL' }), $Name, $Message)
}
function Invoke-Native([string]$Exe, [string[]]$Arguments) {
    $out = & $Exe @Arguments 2>&1 | ForEach-Object { "$_" }
    return @{ Exit = $LASTEXITCODE; Output = ($out -join "`n") }
}
if ((Test-Path $ScanLog) -and (Get-Item $ScanLog).Length -gt 2MB) { Remove-Item $ScanLog -Force }
Add-TextLine $ScanLog "=== Scan started $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

# A. IOC feed (E4): download to a temp file, only replace the list if it looks valid
if (Test-Paused 'malware') {
    Add-Step 'IOC hash feed update' $true 'Skipped: Anti-Malware is paused'
} else {
    $iocFile = "$RulesDir\ioc_sha256.txt"
    $tmp = "$iocFile.download"
    $code = & curl.exe -sL --max-time 120 -w '%{http_code}' -o $tmp $cfg.iocFeedUrl 2>$null
    $valid = 0
    if ($code -eq '200' -and (Test-Path $tmp)) { $valid = @(Select-String -Path $tmp -Pattern '^\s*[0-9a-fA-F]{64}\s*(;|$)').Count }
    if ($valid -ge 100) {
        Move-Item $tmp $iocFile -Force
        Add-Step 'IOC hash feed update' $true "$valid SHA256 malware hashes from $($cfg.iocFeedUrl)"
    } else {
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        $have = if (Test-Path $iocFile) { @(Select-String -Path $iocFile -Pattern '^\s*[0-9a-fA-F]{64}\s*(;|$)').Count } else { 0 }
        Add-Step 'IOC hash feed update' $false "HTTP $code, $valid usable hashes - kept the previous list ($have hashes)"
    }
}

# B. Sigma (Hayabusa 4.x: the command is dfir-timeline; csv-timeline no longer exists)
if (Test-Paused 'sigma') {
    Add-Step 'Sigma rules update' $true 'Skipped: Sigma scanning is paused'
    Add-Step 'Sigma event-log scan' $true 'Skipped: Sigma scanning is paused'
} else {
    $hayaDir = "$BinDir\hayabusa"
    $haya    = "$hayaDir\hayabusa.exe"
    if (Test-Path $haya) {
        Push-Location $hayaDir   # hayabusa resolves rules\ and config\ relative to the working directory
        $r = Invoke-Native $haya @('update-rules', '-q')
        Add-TextLine $ScanLog $r.Output
        Add-Step 'Sigma rules update' ($r.Exit -eq 0) "exit code $($r.Exit)"

        $csv = "$DataDir\hayabusa_last_scan.csv"
        Remove-Item $csv -Force -ErrorAction SilentlyContinue
        $r = Invoke-Native $haya @('dfir-timeline', '-l', '-w', '-q', '-Q', '-K', '-C', '-m', 'high', '--time-offset', [string]$cfg.sigmaLookback, '-o', $csv)
        Pop-Location
        if (Test-Path $csv) {
            $header = $null
            $maxSigmaRows = 2000   # newest hits kept (bounded memory); more than this in one scan is reported below
            $queue = New-Object 'System.Collections.Generic.Queue[string]'
            $totalRows = 0
            foreach ($line in [IO.File]::ReadLines($csv, [Text.Encoding]::UTF8)) {
                if ($null -eq $header) { $header = $line; continue }
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                $totalRows++
                if ($queue.Count -ge $maxSigmaRows) { [void]$queue.Dequeue() }
                $queue.Enqueue($line)
            }
            if ($header -and $queue.Count -gt 0) {
                $csvChunk = @($header) + @($queue.ToArray())
                $lastRows = @($csvChunk | ConvertFrom-Csv)
                foreach ($hit in $lastRows) {
                    $result.sigma += [pscustomobject]@{
                        title = $hit.RuleTitle; level = $hit.Level; details = $hit.Details; timestamp = $hit.Timestamp
                        computer = $hit.Computer; channel = $hit.Channel; eventId = $hit.EventID; recordId = $hit.RecordID; ruleId = $hit.RuleID
                    }
                }
            }
            if ($totalRows -gt $maxSigmaRows) {
                Add-Step 'Sigma event-log scan' $false "$totalRows high/critical hits in the last $($cfg.sigmaLookback); only the newest $maxSigmaRows were checked - see data\hayabusa_last_scan.csv for the rest"
            } else {
                Add-Step 'Sigma event-log scan' $true "$totalRows high/critical hits in the last $($cfg.sigmaLookback)"
            }
        } else {
            Add-TextLine $ScanLog $r.Output
            Add-Step 'Sigma event-log scan' $false "no output (exit code $($r.Exit)) - see data\scan.log"
        }
    } else {
        Add-Step 'Sigma event-log scan' $false "hayabusa.exe not found in $hayaDir"
    }
}

# C. OSV vulnerability scan of Python environments
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

# Lowest released version above the installed one that fixes this vulnerability (commit hashes are skipped)
function Get-FixVersion($Vuln, [string]$Package, [string]$Installed) {
    $norm = ($Package -replace '[-_.]+', '-').ToLower()
    $best = $null
    foreach ($a in @($Vuln.affected)) {
        if ($a.package.name -and (([string]$a.package.name -replace '[-_.]+', '-').ToLower()) -ne $norm) { continue }
        foreach ($r in @($a.ranges)) {
            foreach ($ev in @($r.events)) {
                $f = [string]$ev.fixed
                if (-not $f -or $f -notmatch '^\d+(\.\d+)*([a-z]+\d*)?(\.post\d+)?$') { continue }
                if ((Compare-PyVersion $f $Installed) -le 0) { continue }
                if (-not $best -or (Compare-PyVersion $f $best) -lt 0) { $best = $f }
            }
        }
    }
    return $best
}

function Get-SeverityName([string]$Score) {
    $s = 0.0
    if (-not [double]::TryParse($Score, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$s)) { return 'Medium' }
    if ($s -ge 9) { 'Critical' } elseif ($s -ge 7) { 'High' } elseif ($s -ge 4) { 'Medium' } else { 'Low' }
}

# Which python.exe owns the package, and which package to upgrade (a library bundled inside pip is fixed by upgrading pip)
function Get-PipTarget([string]$Path, [string]$Package) {
    $p = $Path -replace '/', '\'
    $python = $null
    if ($p -match '^(.*?)\\Lib\\site-packages\\') { $exe = Join-Path $matches[1] 'python.exe'; if (Test-Path -LiteralPath $exe) { $python = $exe } }
    elseif ($p -match '\\Packages\\PythonSoftwareFoundation\.Python\.(\d+\.\d+)_') { $python = "python$($matches[1])" }
    $fixPkg = $Package
    if ($p -match '\\site-packages\\([^\\]+)\\_vendor\\') { $fixPkg = $matches[1] }
    return @{ Python = $python; Package = $fixPkg }
}

# One row per vulnerability group (aliases merged) that has a released fix newer than the installed version
function ConvertFrom-OsvResult($O) {
    $script:osvNoFix = 0
    foreach ($res in @($O.results)) {
        foreach ($pkg in @($res.packages)) {
            $name = [string]$pkg.package.name; $ver = [string]$pkg.package.version
            $byId = @{}
            foreach ($v in @($pkg.vulnerabilities)) { if ($v) { $byId[[string]$v.id] = $v } }
            $groups = @($pkg.groups | Where-Object { $_ })
            if (-not $groups.Count) { $groups = @($byId.Values | ForEach-Object { [pscustomobject]@{ ids = @($_.id); aliases = @($_.aliases); max_severity = '' } }) }
            foreach ($g in $groups) {
                $vs = @(@($g.ids) | ForEach-Object { $byId[[string]$_] } | Where-Object { $_ })
                if (-not $vs.Count) { continue }
                $fix = $null
                foreach ($v in $vs) { $f = Get-FixVersion $v $name $ver; if ($f -and (-not $fix -or (Compare-PyVersion $f $fix) -gt 0)) { $fix = $f } }
                if (-not $fix) { $script:osvNoFix++; continue }   # no fixed release yet: nothing to update to, so not shown
                $ids = @(@($g.ids) + @($g.aliases) + @($vs | ForEach-Object { $_.aliases }) | Where-Object { $_ } | Select-Object -Unique)
                $cve = @($ids | Where-Object { $_ -match '^CVE-' }) | Select-Object -First 1
                $t = Get-PipTarget ([string]$res.source.path) $name
                [pscustomobject]@{
                    id = [string]$vs[0].id; cve = $(if ($cve) { $cve } else { [string]$vs[0].id }); aliases = $ids
                    package = $name; version = $ver; fixed = $fix; score = [string]$g.max_severity; severity = (Get-SeverityName ([string]$g.max_severity))
                    summary = [string](@($vs | ForEach-Object { $_.summary } | Where-Object { $_ }) | Select-Object -First 1)
                    path = [string]$res.source.path; python = $t.Python; fixPackage = $t.Package
                }
            }
        }
    }
}

if (Test-Paused 'cve') {
    Add-Step 'Python vulnerability scan (OSV)' $true 'Skipped: CVE vulnerability scanning is paused'
} else {
    $osv = "$BinDir\osv-scanner.exe"
    # Python of every user on this PC (found automatically, nothing user-specific is configured)
    $pyDirs = @(foreach ($u in Get-UserProfiles) { "$u\AppData\Local\Programs\Python"; "$u\AppData\Local\Packages" }) | Where-Object { Test-Path -LiteralPath $_ }
    if (Test-Path $osv) {
        $noFix = 0; $failed = @()
        # data\download is removed at the end of every install, so it is created here when needed
        New-Item -ItemType Directory -Path $DownloadDir -Force -ErrorAction SilentlyContinue | Out-Null
        foreach ($dir in $pyDirs) {
            $tmpOsv = Join-Path $DownloadDir "osv-$([guid]::NewGuid().ToString('N').Substring(0,6)).json"
            $o = $null
            try {
                & $osv scan source -r $dir --format json 1>$tmpOsv 2>$null
                if (Test-Path $tmpOsv) { $o = Read-Json $tmpOsv $null }
            } catch {
                Add-TextLine $ScanLog "OSV scan of $dir failed: $($_.Exception.Message)"
            } finally {
                Remove-Item -LiteralPath $tmpOsv -Force -ErrorAction SilentlyContinue
            }
            if ($o) { $result.vulns += @(ConvertFrom-OsvResult $o); $noFix += $script:osvNoFix } else { $failed += $dir }
        }
        # A folder that produced no readable result fails the step, so the CVE tab keeps the previous list instead of
        # being replaced by an empty one
        if ($failed.Count) { Add-Step 'Python vulnerability scan (OSV)' $false "no result for $($failed -join ', ') - kept the previous list (see data\scan.log)" }
        else { Add-Step 'Python vulnerability scan (OSV)' $true "$(@($result.vulns).Count) vulnerabilities with an available update in $($pyDirs.Count) folders ($noFix without a fix yet are not shown)" }
    } else {
        Add-Step 'Python vulnerability scan (OSV)' $false 'osv-scanner.exe not found'
    }
}

# D. Are the EDR's own tools out of date? (E9) - read-only GitHub API calls, nothing is downloaded. Every scan (twice a day).
function Get-Ver([string]$Text) { if ($Text -match '(\d+\.\d+(\.\d+)?)') { return $matches[1] } return $null }
$haya = "$BinDir\hayabusa\hayabusa.exe"; $osv = "$BinDir\osv-scanner.exe"   # also set when the Sigma / CVE steps were skipped (paused)
$tools = @(
    @{ name = 'Hayabusa';      repo = 'Yamato-Security/hayabusa'; current = Get-Ver ((Invoke-Native $haya @('help')).Output -split "`n" | Select-Object -First 1) }
    @{ name = 'YARA';          repo = 'VirusTotal/yara';          current = Get-Ver (Invoke-Native "$BinDir\yara64.exe" @('-v')).Output }
    @{ name = 'OSV-Scanner';   repo = 'google/osv-scanner';       current = Get-Ver ((Invoke-Native $osv @('--version')).Output -split "`n" | Select-Object -First 1) }
    @{ name = 'Velociraptor';  repo = 'Velocidex/velociraptor';   current = Get-Ver ((Invoke-Native "$BinDir\velociraptor.exe" @('version')).Output -split "`n" | Where-Object { $_ -match '^version:' } | Select-Object -First 1) }
)
$ok = 0
foreach ($t in $tools) {
    $api = (& curl.exe -sL --max-time 30 -H 'User-Agent: EDR-tool-check' "https://api.github.com/repos/$($t.repo)/releases/latest" 2>$null) -join "`n"
    $latest = $null; $url = "https://github.com/$($t.repo)/releases"
    try { $j = $api | ConvertFrom-Json; $latest = Get-Ver $j.tag_name; if ($j.html_url) { $url = $j.html_url } } catch { }
    $outdated = $false
    if ($latest -and $t.current) { try { $outdated = ([version]$latest -gt [version]$t.current) } catch { } ; $ok++ }
    $result.tools += [pscustomobject]@{ name = $t.name; current = $t.current; latest = $latest; outdated = $outdated; url = $url }
}
if ($ok) { $result.toolCheck = (Get-Date).ToString('s') }
Add-Step 'EDR tool version check' ($ok -gt 0) (($result.tools | ForEach-Object { "$($_.name) $($_.current)$(if ($_.outdated) { " -> $($_.latest) available" })" }) -join ', ')

$result.finished = (Get-Date).ToString('s')
Write-JsonAtomic $ScanResult ([pscustomobject]$result)
Add-TextLine $ScanLog "=== Scan finished $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
