param([string]$Repo, [switch]$Live, [switch]$Attack, [switch]$Elevated, [string]$Work)

$DataFiles = @('config\sysmonconfig.template.xml', 'rules\custom_edr.yar', 'rules\ransomware.yar', 'README.md',
               'docs\user\USER_GUIDE.md', 'docs\install\INSTALLATION.md', 'docs\install\UNINSTALL.md', 'docs\CHANGELOG.md')
$Projects = @('Edr.Core', 'Edr.Engine', 'Edr.Control', 'Edr.Setup', 'Edr.Tray', 'Edr.Core.Tests')

Test 'Every installed data file and every C# project exists' {
    $missing = @($DataFiles | Where-Object { -not (Test-Path (Join-Path $Repo $_)) }) + @($Projects | Where-Object { -not (Test-Path (Join-Path $Repo "src\$_\$_.csproj")) })
    Assert-True (-not $missing.Count) "missing: $($missing -join ', ')"
}

Test 'The build installs exactly the data files the installer expects (build\EdrBuild\Gates.cs)' {
    $gates = Read-Text "$Repo\build\EdrBuild\Gates.cs"
    foreach ($f in $DataFiles) { Assert-True ($gates.Contains('@"' + $f + '"') -or $gates.Contains('"' + $f + '"')) "Gates.DataFiles lacks $f" }
    foreach ($exe in 'FreeEDR-Engine.exe', 'FreeEDR-Control.exe', 'FreeEDR-Installer.exe', 'FreeEDR-Tray.exe') { Assert-Match $gates ([regex]::Escape($exe)) "Gates.Programs lacks $exe" }
}

Test 'No PowerShell product scripts are installed any more (the app is C# / NativeAOT)' {
    $gates = Read-Text "$Repo\build\EdrBuild\Gates.cs"
    Assert-NoMatch $gates 'EDR-(Engine|Tray|Scan|Control|Common)\.ps1' 'build stages a PowerShell script'
    $iss = Read-Text "$Repo\build\installer\FreeEDR-Setup.iss"
    Assert-NoMatch $iss 'powershell\.exe|\.ps1' 'Setup still runs PowerShell'
}

Test '*.yar are ASCII without BOM (YARA skips the file otherwise)' {
    foreach ($f in Get-ChildItem "$Repo\rules\*.yar") {
        $b = [IO.File]::ReadAllBytes($f.FullName)
        Assert-False ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) "$($f.Name) has a BOM"
        Assert-False (@($b | Where-Object { $_ -gt 0x7F }).Count) "$($f.Name) has non-ASCII bytes"
    }
}

Test 'Sysmon template: valid XML, {ROOT} placeholder, no "end with any" (Sysmon 15.22 crashes on it)' {
    $t = Read-Text "$Repo\config\sysmonconfig.template.xml"
    [xml]$x = $t
    Assert-True ($t.Contains('{ROOT}')) 'no {ROOT} placeholder'
    Assert-True (-not $x.SelectNodes("//*[@condition='end with any']").Count) 'a rule uses condition="end with any"'
    Assert-True ($x.Sysmon.EventFiltering) 'no EventFiltering'
}

Test 'No credential-theft tool strings in plain text in the sources (antivirus / AMSI would flag the files)' {
    $words = @('73656b75726c73613a3a', ('6c7361647' + '56d703a3a'), '496e766f6b652d4d696d696b61747a') | ForEach-Object {
        $h = $_; -join (0..($h.Length / 2 - 1) | ForEach-Object { [char][Convert]::ToInt32($h.Substring($_ * 2, 2), 16) }) }
    $bad = @(Get-ChildItem "$Repo\src" -Recurse -Include *.cs, *.axaml -File | Where-Object { $_.FullName -notmatch '\\(bin|obj)\\' } |
        Select-String -Pattern (($words | ForEach-Object { [regex]::Escape($_) }) -join '|') -List | ForEach-Object { $_.Path })
    Assert-True (-not $bad.Count) "found in: $($bad -join ', ')"
}

Test 'Detect-only: no code path stops processes or quarantines files outside the installer' {
    $hits = @(Get-ChildItem "$Repo\src\Edr.Engine", "$Repo\src\Edr.Control", "$Repo\src\Edr.Tray" -Recurse -Include *.cs -File | Where-Object { $_.FullName -notmatch '\\(bin|obj)\\' } |
        Select-String -Pattern '\.Kill\(true\)|Move-ToQuarantine|Stop-ImageProcesses|TerminateProcess' | Where-Object { $_.Line -notmatch 'p\.Kill\(|try \{ p\.Kill' })
    Assert-True (-not $hits.Count) "process kill found: $(($hits | ForEach-Object { "$(Split-Path $_.Path -Leaf):$($_.LineNumber)" }) -join ', ')"
}

Test 'Installer and uninstaller are symmetric (everything set up outside the folder is undone)' {
    $i = Read-Text "$Repo\src\Edr.Setup\Installer.cs"
    $u = Read-Text "$Repo\src\Edr.Setup\Uninstaller.cs"
    foreach ($pair in @(
        @('Services.CreateOrUpdate', 'Services.Delete'),
        @('EdrPaths.RunValue', 'EdrPaths.RunValue'),
        @('Shortcut(', 'FreeEDR.lnk'),
        @('Defender.ApplyAudit', 'Defender.Restore'),
        @('CreateEventSource', 'DeleteEventSource'),
        @('Disable-NetFirewallRule', 'Enable-NetFirewallRule'),
        @('SaveBaseline', 'BaselineFile'))) {
        Assert-True ($i.Contains($pair[0])) "installer lacks $($pair[0])"
        Assert-True ($u.Contains($pair[1])) "uninstaller does not undo it ($($pair[1]))"
    }
    Assert-True ($u.Contains('RemoveAllBans')) 'uninstaller leaves Wail2Ban firewall rules'
}

Test 'Setup: listed in Settings > Apps with version, uninstaller wired, x64 only, admin-only unpack folder' {
    $iss = Read-Text "$Repo\build\installer\FreeEDR-Setup.iss"
    foreach ($p in 'AppVersion=\{#AppVersionText\}', 'Uninstallable=yes', 'ArchitecturesAllowed=x64os', 'setup-src', 'bin\\FreeEDR-Installer\.exe', "'uninstall --from-setup'", 'PrivilegesRequired=admin') {
        Assert-Match $iss $p
    }
}

Test 'Setup: no downgrade without asking, uninstall keeps the settings record unless the restore worked, Settings > Apps version stays true' {
    $iss = Read-Text "$Repo\build\installer\FreeEDR-Setup.iss"
    foreach ($p in 'function InitializeSetup', 'AllowDowngrade', '--allow-downgrade', 'procedure CurUninstallStepChanged', 'usPostUninstall', 'UninstallResult = 0', 'SyncDisplayVersion', 'FreeEDR \(finish removal\)') { Assert-Match $iss $p }
    Assert-NoMatch $iss '\[UninstallDelete\]' 'Setup deletes the folder even when the restore failed'
    Assert-NoMatch $iss 'UninstallDisplaySize' 'a fixed size is shown in Settings > Apps'
}

Test 'Release automation: changelog, release workflow with verification and five-release retention' {
    $c = Read-Text "$Repo\docs\CHANGELOG.md"
    Assert-Match $c '(?m)^## Unreleased' 'docs\CHANGELOG.md has no "## Unreleased"'
    Assert-Match $c "(?m)^### What's new for you" 'docs\CHANGELOG.md has no user-facing part'
    foreach ($f in "$Repo\AGENTS.md", "$Repo\project_structure.txt") { Assert-Match (Read-Text $f) 'CHANGELOG\.md' "$(Split-Path $f -Leaf) does not require the changelog" }
    $wf = "$Repo\.github\workflows\release.yml"
    Assert-True (Test-Path $wf) 'no release workflow'
    $w = Read-Text $wf
    foreach ($p in '--promote-changelog', 'build\.cmd', 'Run-Tests\.ps1', '--draft', 'sha256', 'KEEP', 'delete-asset', 'dry_run', 'failure\(\) \|\| cancelled\(\)', 'release-staging/', 'FreeEDR-Update\.exe', 'SkipLive', '\$env:MARKER', 'git revert') { Assert-Match $w $p "release.yml lacks $p" }
    Assert-NoMatch $w "if: failure\(\)\s*`n" 'the clean-up must also run when a release is cancelled'
}

Test 'Elevated programs request administrator, the tray never does' {
    foreach ($p in 'Edr.Control', 'Edr.Setup') { Assert-Match (Read-Text "$Repo\src\$p\app.manifest") 'requireAdministrator' "$p manifest" }
    Assert-Match (Read-Text "$Repo\src\Edr.Tray\app.manifest") 'asInvoker' 'tray manifest'
}

Test 'Documentation: agent rule to run the tests, uninstall documented' {
    foreach ($f in 'AGENTS.md', 'CLAUDE.md') { Assert-Match (Read-Text "$Repo\$f") 'Run-Tests\.ps1' "$f lacks the test rule" }
    Assert-Match (Read-Text "$Repo\docs\install\UNINSTALL.md") 'FreeEDR-Installer' 'UNINSTALL.md'
}

Test 'Documentation routing: project_structure.txt names only existing docs, every doc is routed and says what it is for' {
    $ps = Read-Text "$Repo\project_structure.txt"
    $named = @([regex]::Matches($ps, '(?<![\w\\])((?:agents|architecture|engine|tray|install|user|reference|history)\\[A-Z_]+\.md)') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
    foreach ($n in $named) { Assert-True (Test-Path "$Repo\docs\$n") "project_structure.txt names docs\$n, which does not exist" }
    foreach ($d in Get-ChildItem "$Repo\docs" -Recurse -Filter *.md) {
        $rel = $d.FullName.Substring("$Repo\docs\".Length)
        Assert-True ($ps.Contains($rel)) "docs\$rel is not routed in project_structure.txt"
        Assert-Match (Get-Content $d.FullName -TotalCount 4 | Out-String) 'Read for:' "docs\$rel has no 'Read for:' line"
    }
}

Test '.gitignore keeps test results and build output out of git (they hold paths and user names)' {
    $g = Read-Text "$Repo\.gitignore"
    Assert-Match $g 'tests/results|tests\\results'
    Assert-Match $g 'obj'
}
