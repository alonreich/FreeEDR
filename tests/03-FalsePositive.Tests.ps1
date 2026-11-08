param([string]$Repo, [switch]$Live, [switch]$Attack, [switch]$Elevated, [string]$Work)

Add-CSharpResults $Repo $Work @('SysmonRuleTests', 'EngineDecisionTests')

Test 'Corpus file is valid and holds both kinds of samples' {
    $c = Read-Text "$PSScriptRoot\data\process-corpus.json" | ConvertFrom-Json
    Assert-True (@($c.malicious).Count -ge 10) 'too few attack samples'
    Assert-True (@($c.benign).Count -ge 10) 'too few everyday samples'
}
