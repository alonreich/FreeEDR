# False positives / false negatives: the Sysmon process rules (config\sysmonconfig.template.xml) against everyday
# command lines (must stay quiet) and attack command lines (must alert) from tests\data\process-corpus.json, and the
# engine's allow decisions (trusted-app parents, exact launcher lines, blanket allows). The checks run in C#
# (SysmonRuleTests, EngineDecisionTests). Add every false positive found on a real PC to the corpus.
param([string]$Repo, [switch]$Live, [switch]$Attack, [switch]$Elevated, [string]$Work)

Add-CSharpResults $Repo $Work @('SysmonRuleTests', 'EngineDecisionTests')

Test 'Corpus file is valid and holds both kinds of samples' {
    $c = Read-Text "$PSScriptRoot\data\process-corpus.json" | ConvertFrom-Json
    Assert-True (@($c.malicious).Count -ge 10) 'too few attack samples'
    Assert-True (@($c.benign).Count -ge 10) 'too few everyday samples'
}
