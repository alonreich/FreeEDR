# Unit: the C# core (src\Edr.Core.Tests): validation rules, IP helpers, settings, durable JSON files, actions,
# summaries, trusted-app profiles, the golden dashboard models, engine internals (scan parsing, Wail2Ban counting).
param([string]$Repo, [switch]$Live, [switch]$Attack, [switch]$Elevated, [string]$Work)

Add-CSharpResults $Repo $Work @('PatternRulesTests', 'IpTests', 'ConfigTests', 'JsonFileTests', 'ActionTests', 'SummaryTests',
                                'ProfileTests', 'GoldenModelTests', 'EngineInternalsTests', 'SignerTests', 'SingleInstanceTests')
