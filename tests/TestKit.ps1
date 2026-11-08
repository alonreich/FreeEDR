
$global:FreeEdrTestResults = New-Object Collections.ArrayList
$global:FreeEdrTestSuite = ''

function Test([string]$Name, [scriptblock]$Body) {
    $r = [pscustomobject]@{ Suite = $global:FreeEdrTestSuite; Name = $Name; Result = 'PASS'; Detail = '' }
    try { $null = & $Body }
    catch {
        $m = [string]$_.Exception.Message
        if ($m.StartsWith('[SKIP] ')) { $r.Result = 'SKIP'; $r.Detail = $m.Substring(7) }
        elseif ($m.StartsWith('[WARN] ')) { $r.Result = 'WARN'; $r.Detail = $m.Substring(7) }
        else { $r.Result = 'FAIL'; $r.Detail = "$m$(if ($_.InvocationInfo.ScriptName -and $_.InvocationInfo.ScriptLineNumber) { " ($(Split-Path -Leaf $_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber))" })" }
    }
    [void]$global:FreeEdrTestResults.Add($r)
    $color = @{ PASS = 'Green'; FAIL = 'Red'; WARN = 'Yellow'; SKIP = 'DarkGray' }[$r.Result]
    Write-Host ("  {0,-4} {1}" -f $r.Result, $Name) -ForegroundColor $color
    if ($r.Detail -and $r.Result -ne 'PASS') { Write-Host "       $($r.Detail)" -ForegroundColor $color }
}

function Skip([string]$Why) { throw "[SKIP] $Why" }
function Known([string]$Why) { throw "[WARN] $Why" }
function Assert-True($Value, [string]$Message = 'expected true') { if (-not $Value) { throw $Message } }
function Assert-False($Value, [string]$Message = 'expected false') { if ($Value) { throw $Message } }
function Assert-Equal($Expected, $Actual, [string]$Message = '') {
    if ("$Expected" -cne "$Actual") { throw "expected '$Expected', got '$Actual'$(if ($Message) { " - $Message" })" }
}
function Assert-Match([string]$Text, [string]$Pattern, [string]$Message = '') {
    if ($Text -notmatch $Pattern) { throw "'$Pattern' not found$(if ($Message) { " - $Message" })" }
}
function Assert-NoMatch([string]$Text, [string]$Pattern, [string]$Message = '') {
    if ($Text -match $Pattern) { throw "'$Pattern' found: '$($matches[0])'$(if ($Message) { " - $Message" })" }
}

function Get-ScriptParts([string]$Path, [string[]]$Functions = @(), [string[]]$Variables = @()) {
    $ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
    $parts = @()
    foreach ($v in $Variables) {
        $a = $ast.FindAll({ param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Parent -eq $ast.EndBlock -and
                                       $n.Left.Extent.Text -match ('^\$(script:)?' + [regex]::Escape($v) + '$') }, $true) | Select-Object -First 1
        if (-not $a) { throw "$Path : no script-level assignment of `$$v" }
        $parts += $a.Extent.Text
    }
    foreach ($f in $Functions) {
        $d = $ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $f }, $true) | Select-Object -First 1
        if (-not $d) { throw "$Path : function $f not found" }
        $parts += $d.Extent.Text
    }
    return ($parts -join "`n")
}

function Read-Text([string]$Path) { [IO.File]::ReadAllText($Path) }

$global:FreeEdrCSharp = $null
function Invoke-CSharpTests([string]$Repo, [string]$Work) {
    if ($null -ne $global:FreeEdrCSharp) { return $global:FreeEdrCSharp }
    $global:FreeEdrCSharp = @()
    $src = Join-Path $Repo 'src'
    $env:TEMP = Join-Path $Repo 'obj\tmp'; $env:TMP = $env:TEMP; $env:NUGET_PACKAGES = Join-Path $Repo 'obj\nuget\packages'
    $env:DOTNET_CLI_HOME = Join-Path $Repo 'obj\dotnet-home'; $env:DOTNET_NOLOGO = '1'; $env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
    New-Item -ItemType Directory -Path $env:TEMP -Force | Out-Null
    $out = & dotnet build (Join-Path $src 'Edr.Core.Tests') -c Release --nologo -v q -tl:off 2>&1
    if ($LASTEXITCODE -ne 0) { throw "C# tests do not build: $(($out | Select-Object -Last 5) -join ' ')" }
    $exe = Join-Path $src 'Edr.Core.Tests\bin\Release\net10.0-windows\Edr.Core.Tests.exe'
    $xmlFile = Join-Path $Work 'csharp-tests.xml'
    Remove-Item -LiteralPath $xmlFile -Force -ErrorAction SilentlyContinue
    Push-Location (Split-Path $exe)
    try { $null = & $exe -noColor -noLogo -result-xml $xmlFile 2>&1 } finally { Pop-Location }
    if (-not (Test-Path $xmlFile)) { throw 'C# tests produced no result file' }
    [xml]$x = [IO.File]::ReadAllText($xmlFile)
    $global:FreeEdrCSharp = @(foreach ($t in $x.SelectNodes('//test')) {
        [pscustomobject]@{
            Class = ([string]$t.type).Split('.')[-1]; Name = [string]$t.name; Result = [string]$t.result
            Message = if ($t.failure) { [string]$t.failure.message.InnerText } elseif ($t.reason) { [string]$t.reason.InnerText } else { '' }
        }
    })
    return $global:FreeEdrCSharp
}

function Add-CSharpResults([string]$Repo, [string]$Work, [string[]]$Classes) {
    $all = @(Invoke-CSharpTests $Repo $Work)
    $mine = @($all | Where-Object { $Classes -contains $_.Class })
    if (-not $mine.Count) { Test "C# tests of $($Classes -join ', ')" { throw 'no C# test of these classes ran' }; return }
    foreach ($t in $mine) {
        $global:FreeEdrCurrentCSharp = $t
        Test "[C#] $($t.Name -replace '^Edr\.Core\.Tests\.', '')" {
            $r = $global:FreeEdrCurrentCSharp
            if ($r.Result -eq 'Skip') { Skip $r.Message }
            if ($r.Result -ne 'Pass') { throw (($r.Message -split "`n" | Select-Object -First 3) -join ' ') }
        }
    }
}
