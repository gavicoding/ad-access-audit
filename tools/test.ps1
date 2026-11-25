<#
.SYNOPSIS
    Runs PSScriptAnalyzer and Pester, the same way the CI does.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

Import-Module PSScriptAnalyzer
$issues = @(Invoke-ScriptAnalyzer -Path $root -Recurse -Settings (Join-Path $root 'PSScriptAnalyzerSettings.psd1'))
if ($issues.Count -gt 0) {
    $issues | Format-Table -AutoSize RuleName, Severity, ScriptName, Line, Message | Out-String -Width 200 | Write-Output
}
$errors = @($issues | Where-Object Severity -EQ 'Error')
if ($errors.Count -gt 0) { throw "PSScriptAnalyzer found $($errors.Count) error(s)." }
Write-Output "PSScriptAnalyzer: $($issues.Count) issue(s), 0 errors."

Import-Module Pester -MinimumVersion 5.0.0 -MaximumVersion 5.99.99
$config = New-PesterConfiguration
$config.Run.Path = Join-Path $root 'tests'
$config.Run.Exit = $false
$config.Run.PassThru = $true
$config.Output.Verbosity = 'Detailed'
$run = Invoke-Pester -Configuration $config
if ($run.FailedCount -gt 0) { throw "$($run.FailedCount) test(s) failed." }
Write-Output "Pester: $($run.PassedCount) passed, $($run.SkippedCount) skipped."
