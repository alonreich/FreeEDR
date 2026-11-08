param([string]$Repo, [switch]$Live, [switch]$Attack, [switch]$Elevated, [string]$Work)

Add-CSharpResults $Repo $Work @('PatternRulesTests', 'IpTests', 'ConfigTests', 'JsonFileTests', 'ActionTests', 'SummaryTests',
                                'ProfileTests', 'GoldenModelTests', 'EngineInternalsTests', 'SignerTests', 'SingleInstanceTests', 'ReleaseTests')
